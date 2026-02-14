package kmip

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"
)

// CrossClusterReplication은 클러스터 간 복제를 관리
type CrossClusterReplication struct {
	localClusterID   string
	remoteCluster    []RemoteCluster
	store            ObjectStore
	config           *CrossClusterConfig
	client           *http.Client
	mu               sync.RWMutex
	logger           *log.Logger
	replicationQueue chan ReplicationEvent
	stopCh           chan struct{}
}

// RemoteCluster는 원격 클러스터 정보
type RemoteCluster struct {
	ID          string   // 클러스터 ID
	Name        string   // 클러스터 이름
	Endpoints   []string // REST API 엔드포인트 (여러 노드)
	Enabled     bool     // 복제 활성화 여부
	Priority    int      // 우선순위 (1=최고)
	Bidirectional bool   // 양방향 복제 여부
	
	// 인증
	APIKey      string   // API 키
	TLSEnabled  bool     // TLS 사용 여부
	
	// 상태
	LastSync    time.Time
	Status      string   // active, failed, paused
	ErrorCount  int
}

// CrossClusterConfig는 클러스터 간 복제 설정
type CrossClusterConfig struct {
	// 기본 설정
	LocalClusterID   string
	LocalClusterName string
	
	// 복제 정책
	ReplicationMode  CrossReplicationMode  // push, pull, bidirectional
	ConflictStrategy ConflictStrategy      // last-write-wins, source-wins, manual
	
	// 성능 설정
	BatchSize        int           // 배치 크기
	BatchInterval    time.Duration // 배치 간격
	RetryAttempts    int           // 재시도 횟수
	RetryBackoff     time.Duration // 재시도 백오프
	Timeout          time.Duration // 요청 타임아웃
	
	// 필터
	IncludePatterns  []string      // 복제할 키 패턴
	ExcludePatterns  []string      // 제외할 키 패턴
	
	// 보안
	EnableEncryption bool          // 전송 중 암호화
	EnableCompression bool         // 압축
}

// CrossReplicationMode는 클러스터 간 복제 모드
type CrossReplicationMode string

const (
	// CrossReplicationModePush는 로컬 -> 원격 단방향 복제
	CrossReplicationModePush CrossReplicationMode = "push"
	
	// CrossReplicationModePull은 원격 -> 로컬 단방향 복제
	CrossReplicationModePull CrossReplicationMode = "pull"
	
	// CrossReplicationModeBidirectional은 양방향 복제
	CrossReplicationModeBidirectional CrossReplicationMode = "bidirectional"
)

// ConflictStrategy는 충돌 해결 전략
type ConflictStrategy string

const (
	// ConflictStrategyLastWriteWins는 최근 쓰기 승리
	ConflictStrategyLastWriteWins ConflictStrategy = "last-write-wins"
	
	// ConflictStrategySourceWins는 소스 클러스터 우선
	ConflictStrategySourceWins ConflictStrategy = "source-wins"
	
	// ConflictStrategyTargetWins는 대상 클러스터 우선
	ConflictStrategyTargetWins ConflictStrategy = "target-wins"
	
	// ConflictStrategyManual은 수동 해결
	ConflictStrategyManual ConflictStrategy = "manual"
)

// ReplicationEvent는 복제 이벤트
type ReplicationEvent struct {
	Type      string    // create, update, delete
	ObjectID  string
	Object    ManagedObject
	Timestamp time.Time
	SourceCluster string
}

// NewCrossClusterReplication은 새로운 클러스터 간 복제를 생성
func NewCrossClusterReplication(store ObjectStore, config *CrossClusterConfig) *CrossClusterReplication {
	if config == nil {
		config = DefaultCrossClusterConfig()
	}
	
	ccr := &CrossClusterReplication{
		localClusterID:   config.LocalClusterID,
		remoteCluster:    make([]RemoteCluster, 0),
		store:            store,
		config:           config,
		client:           &http.Client{Timeout: config.Timeout},
		logger:           log.New(log.Writer(), fmt.Sprintf("[CCR:%s] ", config.LocalClusterID), log.LstdFlags),
		replicationQueue: make(chan ReplicationEvent, 1000),
		stopCh:           make(chan struct{}),
	}
	
	// 복제 워커 시작
	go ccr.replicationWorker()
	
	return ccr
}

// DefaultCrossClusterConfig는 기본 설정을 반환
func DefaultCrossClusterConfig() *CrossClusterConfig {
	return &CrossClusterConfig{
		LocalClusterID:    "cluster-1",
		LocalClusterName:  "Primary Cluster",
		ReplicationMode:   CrossReplicationModePush,
		ConflictStrategy:  ConflictStrategyLastWriteWins,
		BatchSize:         100,
		BatchInterval:     5 * time.Second,
		RetryAttempts:     3,
		RetryBackoff:      1 * time.Second,
		Timeout:           10 * time.Second,
		EnableEncryption:  true,
		EnableCompression: true,
	}
}

// AddRemoteCluster는 원격 클러스터를 추가
func (ccr *CrossClusterReplication) AddRemoteCluster(cluster RemoteCluster) error {
	ccr.mu.Lock()
	defer ccr.mu.Unlock()
	
	// 중복 확인
	for _, rc := range ccr.remoteCluster {
		if rc.ID == cluster.ID {
			return fmt.Errorf("cluster %s already exists", cluster.ID)
		}
	}
	
	cluster.Status = "active"
	cluster.LastSync = time.Now()
	ccr.remoteCluster = append(ccr.remoteCluster, cluster)
	
	ccr.logger.Printf("✅ Added remote cluster: %s (%s)", cluster.Name, cluster.ID)
	return nil
}

// RemoveRemoteCluster는 원격 클러스터를 제거
func (ccr *CrossClusterReplication) RemoveRemoteCluster(clusterID string) error {
	ccr.mu.Lock()
	defer ccr.mu.Unlock()
	
	for i, rc := range ccr.remoteCluster {
		if rc.ID == clusterID {
			ccr.remoteCluster = append(ccr.remoteCluster[:i], ccr.remoteCluster[i+1:]...)
			ccr.logger.Printf("🗑️  Removed remote cluster: %s", clusterID)
			return nil
		}
	}
	
	return fmt.Errorf("cluster %s not found", clusterID)
}

// ReplicateObject는 객체를 원격 클러스터에 복제
func (ccr *CrossClusterReplication) ReplicateObject(event ReplicationEvent) {
	// 큐에 추가
	select {
	case ccr.replicationQueue <- event:
	default:
		ccr.logger.Printf("⚠️  Replication queue full, dropping event")
	}
}

// replicationWorker는 복제 이벤트를 처리
func (ccr *CrossClusterReplication) replicationWorker() {
	batchTicker := time.NewTicker(ccr.config.BatchInterval)
	defer batchTicker.Stop()
	
	batch := make([]ReplicationEvent, 0, ccr.config.BatchSize)
	
	for {
		select {
		case event := <-ccr.replicationQueue:
			batch = append(batch, event)
			
			// 배치 크기에 도달하면 즉시 복제
			if len(batch) >= ccr.config.BatchSize {
				ccr.processBatch(batch)
				batch = batch[:0]
			}
			
		case <-batchTicker.C:
			// 주기적으로 배치 처리
			if len(batch) > 0 {
				ccr.processBatch(batch)
				batch = batch[:0]
			}
			
		case <-ccr.stopCh:
			// 종료 전 남은 배치 처리
			if len(batch) > 0 {
				ccr.processBatch(batch)
			}
			return
		}
	}
}

// processBatch는 배치를 처리
func (ccr *CrossClusterReplication) processBatch(batch []ReplicationEvent) {
	ccr.mu.RLock()
	clusters := make([]RemoteCluster, len(ccr.remoteCluster))
	copy(clusters, ccr.remoteCluster)
	ccr.mu.RUnlock()
	
	for _, cluster := range clusters {
		if !cluster.Enabled {
			continue
		}
		
		ccr.logger.Printf("📤 Replicating %d events to %s", len(batch), cluster.Name)
		
		// 비동기로 각 클러스터에 복제
		go ccr.replicateBatchToCluster(cluster, batch)
	}
}

// replicateBatchToCluster는 배치를 특정 클러스터에 복제
func (ccr *CrossClusterReplication) replicateBatchToCluster(cluster RemoteCluster, batch []ReplicationEvent) {
	for attempt := 0; attempt <= ccr.config.RetryAttempts; attempt++ {
		if attempt > 0 {
			backoff := ccr.config.RetryBackoff * time.Duration(attempt)
			time.Sleep(backoff)
			ccr.logger.Printf("⏳ Retry %d/%d to %s", attempt, ccr.config.RetryAttempts, cluster.Name)
		}
		
		err := ccr.sendBatchToCluster(cluster, batch)
		if err == nil {
			// 성공
			ccr.updateClusterStatus(cluster.ID, "active", 0, time.Now())
			if attempt > 0 {
				ccr.logger.Printf("✅ Replication to %s succeeded after %d retries", cluster.Name, attempt)
			}
			return
		}
		
		ccr.logger.Printf("❌ Replication to %s failed: %v", cluster.Name, err)
	}
	
	// 모든 재시도 실패
	ccr.updateClusterStatus(cluster.ID, "failed", 1, time.Time{})
}

// sendBatchToCluster는 배치를 클러스터로 전송
func (ccr *CrossClusterReplication) sendBatchToCluster(cluster RemoteCluster, batch []ReplicationEvent) error {
	// 엔드포인트 선택 (라운드 로빈 또는 랜덤)
	endpoint := cluster.Endpoints[0]
	if len(cluster.Endpoints) > 1 {
		endpoint = cluster.Endpoints[time.Now().Unix()%int64(len(cluster.Endpoints))]
	}
	
	url := fmt.Sprintf("%s/api/v1/replication/batch", endpoint)
	
	payload := map[string]interface{}{
		"source_cluster": ccr.localClusterID,
		"target_cluster": cluster.ID,
		"events":         batch,
		"timestamp":      time.Now(),
	}
	
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %v", err)
	}
	
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}
	
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Cluster-ID", ccr.localClusterID)
	
	// API 키 인증
	if cluster.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+cluster.APIKey)
	}
	
	resp, err := ccr.client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}
	
	return nil
}

// updateClusterStatus는 클러스터 상태를 업데이트
func (ccr *CrossClusterReplication) updateClusterStatus(clusterID string, status string, errorDelta int, lastSync time.Time) {
	ccr.mu.Lock()
	defer ccr.mu.Unlock()
	
	for i := range ccr.remoteCluster {
		if ccr.remoteCluster[i].ID == clusterID {
			ccr.remoteCluster[i].Status = status
			ccr.remoteCluster[i].ErrorCount += errorDelta
			if !lastSync.IsZero() {
				ccr.remoteCluster[i].LastSync = lastSync
			}
			break
		}
	}
}

// GetClusterStatus는 모든 원격 클러스터의 상태를 반환
func (ccr *CrossClusterReplication) GetClusterStatus() []RemoteCluster {
	ccr.mu.RLock()
	defer ccr.mu.RUnlock()
	
	status := make([]RemoteCluster, len(ccr.remoteCluster))
	copy(status, ccr.remoteCluster)
	return status
}

// Stop은 복제를 중지
func (ccr *CrossClusterReplication) Stop() {
	close(ccr.stopCh)
	ccr.logger.Println("🛑 Cross-cluster replication stopped")
}

// SyncFromRemote는 원격 클러스터에서 데이터를 가져옴 (Pull)
func (ccr *CrossClusterReplication) SyncFromRemote(clusterID string) error {
	ccr.mu.RLock()
	var cluster *RemoteCluster
	for i := range ccr.remoteCluster {
		if ccr.remoteCluster[i].ID == clusterID {
			cluster = &ccr.remoteCluster[i]
			break
		}
	}
	ccr.mu.RUnlock()
	
	if cluster == nil {
		return fmt.Errorf("cluster %s not found", clusterID)
	}
	
	ccr.logger.Printf("📥 Pulling data from %s", cluster.Name)
	
	// 원격 클러스터에서 키 목록 가져오기
	endpoint := cluster.Endpoints[0]
	url := fmt.Sprintf("%s/api/v1/keys", endpoint)
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	
	if cluster.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+cluster.APIKey)
	}
	
	resp, err := ccr.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	var result struct {
		Keys []map[string]interface{} `json:"keys"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}
	
	ccr.logger.Printf("✅ Pulled %d keys from %s", len(result.Keys), cluster.Name)
	
	// TODO: 각 키를 로컬 저장소에 저장
	// 충돌 해결 전략 적용
	
	return nil
}
