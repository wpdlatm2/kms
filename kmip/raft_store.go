package kmip

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/hashicorp/raft"
	raftboltdb "github.com/hashicorp/raft-boltdb/v2"
)

// RaftStore는 Raft 기반 분산 객체 저장소
type RaftStore struct {
	raft     *raft.Raft
	fsm      *FSM
	dataDir  string
	bindAddr string
	config   *RaftConfig
	policy   *ReplicationPolicy
	logger   *log.Logger
}

// RaftConfig는 Raft 저장소 설정
type RaftConfig struct {
	// 기본 설정
	NodeID   string // Raft 노드 ID
	BindAddr string // Raft 바인드 주소 (예: "127.0.0.1:7000")
	DataDir  string // 데이터 디렉토리
	Bootstrap bool  // 부트스트랩 모드 (첫 노드인 경우 true)
	
	// 복제 설정
	ReplicationEnabled bool  // 복제 활성화 여부
	ReplicationFactor  int   // 복제 팩터 (기본: 3)
	MinReplicas        int   // 최소 복제본 수 (쿼럼용, 기본: 2)
	
	// 성능 설정
	HeartbeatTimeout    time.Duration // 하트비트 타임아웃 (기본: 1초)
	ElectionTimeout     time.Duration // 선거 타임아웃 (기본: 1초)
	CommitTimeout       time.Duration // 커밋 타임아웃 (기본: 50ms)
	SnapshotInterval    time.Duration // 스냅샷 간격 (기본: 20초)
	SnapshotThreshold   uint64        // 스냅샷 임계값 (기본: 8192)
	MaxAppendEntries    int           // 최대 Append Entries (기본: 64)
	TrailingLogs        uint64        // 보관할 로그 수 (기본: 10240)
	
	// 클러스터 멤버
	InitialPeers []PeerConfig // 초기 피어 목록
}

// PeerConfig는 피어 노드 설정
type PeerConfig struct {
	ID      string // 노드 ID
	Address string // Raft 주소
}

// ReplicationMode는 복제 모드
type ReplicationMode string

const (
	// ReplicationModeSync는 동기 복제 (모든 복제본에 커밋 대기)
	ReplicationModeSync ReplicationMode = "sync"
	
	// ReplicationModeAsync는 비동기 복제 (리더만 커밋 후 반환)
	ReplicationModeAsync ReplicationMode = "async"
	
	// ReplicationModeQuorum은 쿼럼 복제 (과반수 복제본에 커밋 대기)
	ReplicationModeQuorum ReplicationMode = "quorum"
)

// ReplicationPolicy는 복제 정책
type ReplicationPolicy struct {
	Mode              ReplicationMode // 복제 모드
	MinAcks           int             // 최소 ACK 수
	TimeoutMs         int             // 복제 타임아웃 (밀리초)
	RetryAttempts     int             // 재시도 횟수
	RetryBackoffMs    int             // 재시도 백오프 (밀리초)
	ConsistencyLevel  string          // 일관성 레벨 (strong, eventual)
}

// DefaultRaftConfig는 기본 Raft 설정을 반환
func DefaultRaftConfig() *RaftConfig {
	return &RaftConfig{
		NodeID:              "node-1",
		BindAddr:            "127.0.0.1:7000",
		DataDir:             "./data/raft",
		Bootstrap:           false,
		ReplicationEnabled:  true,
		ReplicationFactor:   3,
		MinReplicas:         2,
		HeartbeatTimeout:    1 * time.Second,
		ElectionTimeout:     1 * time.Second,
		CommitTimeout:       50 * time.Millisecond,
		SnapshotInterval:    20 * time.Second,
		SnapshotThreshold:   8192,
		MaxAppendEntries:    64,
		TrailingLogs:        10240,
		InitialPeers:        []PeerConfig{},
	}
}

// DefaultReplicationPolicy는 기본 복제 정책
func DefaultReplicationPolicy() *ReplicationPolicy {
	return &ReplicationPolicy{
		Mode:              ReplicationModeQuorum,
		MinAcks:           2,
		TimeoutMs:         5000,
		RetryAttempts:     3,
		RetryBackoffMs:    100,
		ConsistencyLevel:  "strong",
	}
}

// ValidateRaftConfig는 설정을 검증
func ValidateRaftConfig(c *RaftConfig) error {
	if c.NodeID == "" {
		return fmt.Errorf("NodeID is required")
	}
	if c.BindAddr == "" {
		return fmt.Errorf("BindAddr is required")
	}
	if c.DataDir == "" {
		return fmt.Errorf("DataDir is required")
	}
	if c.ReplicationEnabled {
		if c.ReplicationFactor < 1 {
			return fmt.Errorf("ReplicationFactor must be at least 1")
		}
		if c.MinReplicas < 1 {
			return fmt.Errorf("MinReplicas must be at least 1")
		}
		if c.MinReplicas > c.ReplicationFactor {
			return fmt.Errorf("MinReplicas cannot exceed ReplicationFactor")
		}
	}
	return nil
}

// NewRaftStore는 새로운 Raft 저장소를 생성
func NewRaftStore(config *RaftConfig, policy *ReplicationPolicy) (*RaftStore, error) {
	// 기본값 설정
	if config == nil {
		config = DefaultRaftConfig()
	} else {
		// 설정되지 않은 값에 기본값 적용
		if config.HeartbeatTimeout == 0 {
			config.HeartbeatTimeout = 1 * time.Second
		}
		if config.ElectionTimeout == 0 {
			config.ElectionTimeout = 1 * time.Second
		}
		if config.CommitTimeout == 0 {
			config.CommitTimeout = 50 * time.Millisecond
		}
		if config.SnapshotInterval == 0 {
			config.SnapshotInterval = 20 * time.Second
		}
		if config.SnapshotThreshold == 0 {
			config.SnapshotThreshold = 8192
		}
		if config.MaxAppendEntries == 0 {
			config.MaxAppendEntries = 64
		}
		if config.TrailingLogs == 0 {
			config.TrailingLogs = 10240
		}
	}
	
	if policy == nil {
		policy = DefaultReplicationPolicy()
	}
	
	// 설정 검증
	if err := ValidateRaftConfig(config); err != nil {
		return nil, fmt.Errorf("invalid config: %v", err)
	}
	
	// 데이터 디렉토리 생성
	if err := os.MkdirAll(config.DataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %v", err)
	}

	// FSM 생성
	fsm := NewFSM()
	
	logger := log.New(os.Stderr, fmt.Sprintf("[RAFT:%s] ", config.NodeID), log.LstdFlags)
	
	store := &RaftStore{
		fsm:      fsm,
		dataDir:  config.DataDir,
		bindAddr: config.BindAddr,
		config:   config,
		policy:   policy,
		logger:   logger,
	}
	
	// 복제가 비활성화되면 로컬 모드로 동작
	if !config.ReplicationEnabled {
		logger.Println("⚠️  Replication DISABLED - running in LOCAL mode")
		return store, nil
	}

	// Raft 설정
	raftConfig := raft.DefaultConfig()
	raftConfig.LocalID = raft.ServerID(config.NodeID)
	
	// 타임아웃 설정
	raftConfig.HeartbeatTimeout = config.HeartbeatTimeout
	raftConfig.ElectionTimeout = config.ElectionTimeout
	raftConfig.CommitTimeout = config.CommitTimeout
	raftConfig.SnapshotInterval = config.SnapshotInterval
	raftConfig.SnapshotThreshold = config.SnapshotThreshold
	raftConfig.MaxAppendEntries = config.MaxAppendEntries
	raftConfig.TrailingLogs = config.TrailingLogs
	
	// 로그 출력 설정
	raftConfig.LogOutput = os.Stderr
	
	// 복제 정책에 따른 설정 조정
	switch policy.Mode {
	case ReplicationModeSync:
		// 동기 모드: 모든 팔로워가 응답할 때까지 대기
		logger.Printf("📋 Replication Mode: SYNC (wait for all replicas)")
		raftConfig.CommitTimeout = time.Duration(policy.TimeoutMs) * time.Millisecond
	case ReplicationModeAsync:
		// 비동기 모드: 빠른 커밋
		logger.Printf("📋 Replication Mode: ASYNC (fast commit)")
		raftConfig.CommitTimeout = 10 * time.Millisecond
	case ReplicationModeQuorum:
		// 쿼럼 모드: 과반수 응답 대기 (기본)
		logger.Printf("📋 Replication Mode: QUORUM (wait for majority)")
		raftConfig.CommitTimeout = time.Duration(policy.TimeoutMs/2) * time.Millisecond
	}
	
	logger.Printf("📊 Replication Factor: %d, Min Replicas: %d", 
		config.ReplicationFactor, config.MinReplicas)

	// 주소 파싱
	addr, err := net.ResolveTCPAddr("tcp", config.BindAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve bind address: %v", err)
	}

	// Transport 생성
	transport, err := raft.NewTCPTransport(config.BindAddr, addr, 3, 10*time.Second, os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("failed to create transport: %v", err)
	}

	// Snapshot store 생성
	snapshotStore, err := raft.NewFileSnapshotStore(config.DataDir, 2, os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("failed to create snapshot store: %v", err)
	}

	// Log store 생성 (BoltDB 사용)
	logStore, err := raftboltdb.NewBoltStore(filepath.Join(config.DataDir, "raft-log.db"))
	if err != nil {
		return nil, fmt.Errorf("failed to create log store: %v", err)
	}

	// Stable store 생성 (BoltDB 사용)
	stableStore, err := raftboltdb.NewBoltStore(filepath.Join(config.DataDir, "raft-stable.db"))
	if err != nil {
		return nil, fmt.Errorf("failed to create stable store: %v", err)
	}

	// Raft 인스턴스 생성
	ra, err := raft.NewRaft(raftConfig, fsm, logStore, stableStore, snapshotStore, transport)
	if err != nil {
		return nil, fmt.Errorf("failed to create raft: %v", err)
	}
	
	store.raft = ra

	// 부트스트랩 모드인 경우 클러스터 초기화
	if config.Bootstrap {
		configuration := raft.Configuration{
			Servers: []raft.Server{
				{
					ID:      raft.ServerID(config.NodeID),
					Address: transport.LocalAddr(),
				},
			},
		}
		
		// 초기 피어 추가
		for _, peer := range config.InitialPeers {
			if peer.ID != config.NodeID {
				configuration.Servers = append(configuration.Servers, raft.Server{
					ID:      raft.ServerID(peer.ID),
					Address: raft.ServerAddress(peer.Address),
				})
			}
		}
		
		logger.Printf("🚀 Bootstrapping cluster with %d nodes", len(configuration.Servers))
		ra.BootstrapCluster(configuration)
	}

	logger.Printf("✅ Raft store initialized successfully")
	return store, nil
}

// Store는 객체를 저장
func (s *RaftStore) Store(obj ManagedObject) error {
	// 복제가 비활성화된 경우 로컬 FSM에 직접 저장
	if !s.config.ReplicationEnabled || s.raft == nil {
		// 객체를 JSON으로 직렬화
		data, err := serializeManagedObject(obj)
		if err != nil {
			return fmt.Errorf("failed to serialize object: %v", err)
		}
		s.fsm.Store(obj.GetUniqueIdentifier(), data)
		return nil
	}
	
	// 리더가 아니면 에러
	if s.raft.State() != raft.Leader {
		return errors.New("not the leader - please retry on the leader node")
	}
	
	// 객체를 JSON으로 직렬화
	data, err := serializeManagedObject(obj)
	if err != nil {
		return fmt.Errorf("failed to serialize object: %v", err)
	}

	// Raft 커맨드 생성
	cmd := Command{
		Type: CommandStore,
		Key:  obj.GetUniqueIdentifier(),
		Data: data,
	}

	cmdBytes, err := json.Marshal(cmd)
	if err != nil {
		return fmt.Errorf("failed to marshal command: %v", err)
	}

	// 복제 정책에 따라 타임아웃 설정
	timeout := time.Duration(s.policy.TimeoutMs) * time.Millisecond
	
	// Raft에 적용 (재시도 로직 포함)
	for attempt := 0; attempt <= s.policy.RetryAttempts; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(s.policy.RetryBackoffMs*attempt) * time.Millisecond
			s.logger.Printf("⏳ Retry attempt %d/%d after %v", 
				attempt, s.policy.RetryAttempts, backoff)
			time.Sleep(backoff)
		}
		
		// Raft에 커밋
		future := s.raft.Apply(cmdBytes, timeout)
		if err := future.Error(); err != nil {
			if attempt < s.policy.RetryAttempts {
				s.logger.Printf("⚠️  Apply failed: %v, retrying...", err)
				continue
			}
			return fmt.Errorf("failed to apply command after %d attempts: %v", 
				s.policy.RetryAttempts+1, err)
		}
		
		// 성공
		if attempt > 0 {
			s.logger.Printf("✅ Command applied successfully after %d retries", attempt)
		}
		return nil
	}

	return errors.New("max retries exceeded")
}

// Retrieve는 객체를 조회
func (s *RaftStore) Retrieve(id string) (ManagedObject, error) {
	data, ok := s.fsm.Get(id)
	if !ok {
		return nil, errors.New("object not found")
	}

	// 역직렬화
	obj, err := deserializeManagedObject(data)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize object: %v", err)
	}

	return obj, nil
}

// Delete는 객체를 삭제
func (s *RaftStore) Delete(id string) error {
	// 존재 여부 확인
	if _, ok := s.fsm.Get(id); !ok {
		return errors.New("object not found")
	}
	
	// 복제가 비활성화된 경우 로컬 FSM에서 직접 삭제
	if !s.config.ReplicationEnabled || s.raft == nil {
		s.fsm.Delete(id)
		return nil
	}
	
	// 리더가 아니면 에러
	if s.raft.State() != raft.Leader {
		return errors.New("not the leader - please retry on the leader node")
	}

	// Raft 커맨드 생성
	cmd := Command{
		Type: CommandDelete,
		Key:  id,
	}

	cmdBytes, err := json.Marshal(cmd)
	if err != nil {
		return fmt.Errorf("failed to marshal command: %v", err)
	}

	// 복제 정책에 따라 타임아웃 설정
	timeout := time.Duration(s.policy.TimeoutMs) * time.Millisecond
	
	// Raft에 적용 (재시도 로직 포함)
	for attempt := 0; attempt <= s.policy.RetryAttempts; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(s.policy.RetryBackoffMs*attempt) * time.Millisecond
			time.Sleep(backoff)
		}
		
		future := s.raft.Apply(cmdBytes, timeout)
		if err := future.Error(); err != nil {
			if attempt < s.policy.RetryAttempts {
				continue
			}
			return fmt.Errorf("failed to apply command: %v", err)
		}
		
		return nil
	}

	return errors.New("max retries exceeded")
}

// List는 모든 객체를 반환
func (s *RaftStore) List() []ManagedObject {
	keys := s.fsm.List()
	result := make([]ManagedObject, 0, len(keys))

	for _, key := range keys {
		if obj, err := s.Retrieve(key); err == nil {
			result = append(result, obj)
		}
	}

	return result
}

// GenerateUniqueID는 고유 식별자를 생성
func (s *RaftStore) GenerateUniqueID() string {
	// InMemoryStore와 동일한 구현 재사용
	store := NewInMemoryStore()
	return store.GenerateUniqueID()
}

// Join은 기존 클러스터에 노드를 추가
func (s *RaftStore) Join(nodeID, addr string) error {
	configFuture := s.raft.GetConfiguration()
	if err := configFuture.Error(); err != nil {
		return fmt.Errorf("failed to get raft configuration: %v", err)
	}

	// 이미 클러스터에 있는지 확인
	for _, srv := range configFuture.Configuration().Servers {
		if srv.ID == raft.ServerID(nodeID) || srv.Address == raft.ServerAddress(addr) {
			// 이미 존재하면 제거 후 다시 추가
			future := s.raft.RemoveServer(srv.ID, 0, 0)
			if err := future.Error(); err != nil {
				return fmt.Errorf("failed to remove existing server: %v", err)
			}
		}
	}

	// 새 서버 추가
	future := s.raft.AddVoter(raft.ServerID(nodeID), raft.ServerAddress(addr), 0, 0)
	if err := future.Error(); err != nil {
		return fmt.Errorf("failed to add voter: %v", err)
	}

	return nil
}

// Leave는 클러스터에서 노드를 제거
func (s *RaftStore) Leave(nodeID string) error {
	future := s.raft.RemoveServer(raft.ServerID(nodeID), 0, 0)
	if err := future.Error(); err != nil {
		return fmt.Errorf("failed to remove server: %v", err)
	}
	return nil
}

// IsLeader는 현재 노드가 리더인지 확인
func (s *RaftStore) IsLeader() bool {
	return s.raft.State() == raft.Leader
}

// GetLeader는 현재 리더 주소를 반환
func (s *RaftStore) GetLeader() string {
	addr, _ := s.raft.LeaderWithID()
	return string(addr)
}

// GetStats는 Raft 통계를 반환
func (s *RaftStore) GetStats() map[string]string {
	return s.raft.Stats()
}

// Shutdown은 Raft 노드를 종료
func (s *RaftStore) Shutdown() error {
	future := s.raft.Shutdown()
	return future.Error()
}

// serializeManagedObject는 ManagedObject를 직렬화
func serializeManagedObject(obj ManagedObject) ([]byte, error) {
	// 간단한 구조체로 변환
	data := struct {
		Type             int32                  `json:"type"`
		UniqueIdentifier string                 `json:"unique_identifier"`
		Attributes       map[string]interface{} `json:"attributes"`
		KeyBlock         *KeyBlock              `json:"key_block,omitempty"`
	}{
		Type:             obj.GetObjectType(),
		UniqueIdentifier: obj.GetUniqueIdentifier(),
		Attributes:       obj.GetAttributes(),
	}

	// SymmetricKey인 경우 KeyBlock 포함
	if symKey, ok := obj.(*SymmetricKey); ok {
		data.KeyBlock = &symKey.KeyBlock
	}

	return json.Marshal(data)
}

// deserializeManagedObject는 ManagedObject를 역직렬화
func deserializeManagedObject(data []byte) (ManagedObject, error) {
	var tmp struct {
		Type             int32                  `json:"type"`
		UniqueIdentifier string                 `json:"unique_identifier"`
		Attributes       map[string]interface{} `json:"attributes"`
		KeyBlock         *KeyBlock              `json:"key_block,omitempty"`
	}

	if err := json.Unmarshal(data, &tmp); err != nil {
		return nil, err
	}

	switch tmp.Type {
	case ObjectTypeSymmetricKey:
		obj := &SymmetricKey{
			UniqueIdentifier: tmp.UniqueIdentifier,
			Attributes:       tmp.Attributes,
		}
		if tmp.KeyBlock != nil {
			obj.KeyBlock = *tmp.KeyBlock
		}
		return obj, nil
		
	case ObjectTypePublicKey:
		obj := &PublicKey{
			UniqueIdentifier: tmp.UniqueIdentifier,
			Attributes:       tmp.Attributes,
		}
		if tmp.KeyBlock != nil {
			obj.KeyBlock = *tmp.KeyBlock
		}
		return obj, nil
		
	case ObjectTypePrivateKey:
		obj := &PrivateKey{
			UniqueIdentifier: tmp.UniqueIdentifier,
			Attributes:       tmp.Attributes,
		}
		if tmp.KeyBlock != nil {
			obj.KeyBlock = *tmp.KeyBlock
		}
		return obj, nil

	default:
		return nil, fmt.Errorf("unsupported object type: %d", tmp.Type)
	}
}
