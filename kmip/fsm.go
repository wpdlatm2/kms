package kmip

import (
	"encoding/json"
	"fmt"
	"io"
	"sync"

	"github.com/hashicorp/raft"
)

// CommandType은 Raft 커맨드 타입
type CommandType uint8

const (
	CommandStore CommandType = iota
	CommandDelete
)

// Command는 Raft 로그에 저장되는 커맨드
type Command struct {
	Type CommandType `json:"type"`
	Key  string      `json:"key"`
	Data []byte      `json:"data,omitempty"`
}

// FSM은 Raft Finite State Machine 구현
type FSM struct {
	mu      sync.RWMutex
	objects map[string][]byte // Serialized ManagedObject
}

// NewFSM은 새로운 FSM을 생성
func NewFSM() *FSM {
	return &FSM{
		objects: make(map[string][]byte),
	}
}

// Apply는 Raft 로그 엔트리를 적용
func (f *FSM) Apply(log *raft.Log) interface{} {
	var cmd Command
	if err := json.Unmarshal(log.Data, &cmd); err != nil {
		return fmt.Errorf("failed to unmarshal command: %v", err)
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	switch cmd.Type {
	case CommandStore:
		f.objects[cmd.Key] = cmd.Data
		return nil
	case CommandDelete:
		delete(f.objects, cmd.Key)
		return nil
	default:
		return fmt.Errorf("unknown command type: %d", cmd.Type)
	}
}

// Snapshot은 현재 상태의 스냅샷을 반환
func (f *FSM) Snapshot() (raft.FSMSnapshot, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	// 현재 상태를 복사
	objects := make(map[string][]byte)
	for k, v := range f.objects {
		objects[k] = v
	}

	return &fsmSnapshot{objects: objects}, nil
}

// Restore는 스냅샷에서 상태를 복원
func (f *FSM) Restore(rc io.ReadCloser) error {
	defer rc.Close()

	var objects map[string][]byte
	if err := json.NewDecoder(rc).Decode(&objects); err != nil {
		return err
	}

	f.mu.Lock()
	f.objects = objects
	f.mu.Unlock()

	return nil
}

// Get은 키로 객체를 조회 (읽기 전용, Raft 로그 불필요)
func (f *FSM) Get(key string) ([]byte, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	data, ok := f.objects[key]
	return data, ok
}

// List는 모든 키를 반환 (읽기 전용)
func (f *FSM) List() []string {
	f.mu.RLock()
	defer f.mu.RUnlock()

	keys := make([]string, 0, len(f.objects))
	for k := range f.objects {
		keys = append(keys, k)
	}
	return keys
}

// fsmSnapshot은 FSM 스냅샷 구현
type fsmSnapshot struct {
	objects map[string][]byte
}

// Persist는 스냅샷을 영구 저장
func (s *fsmSnapshot) Persist(sink raft.SnapshotSink) error {
	err := func() error {
		// 스냅샷을 JSON으로 인코딩
		if err := json.NewEncoder(sink).Encode(s.objects); err != nil {
			return err
		}
		return sink.Close()
	}()

	if err != nil {
		sink.Cancel()
		return err
	}

	return nil
}

// Release는 스냅샷 리소스를 해제
func (s *fsmSnapshot) Release() {}
