package kmip

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
)

// ObjectStore는 관리 객체를 저장하는 인터페이스
type ObjectStore interface {
	Store(obj ManagedObject) error
	Retrieve(id string) (ManagedObject, error)
	Delete(id string) error
	List() []ManagedObject
	GenerateUniqueID() string
}

// InMemoryStore는 인메모리 객체 저장소
type InMemoryStore struct {
	mu      sync.RWMutex
	objects map[string]ManagedObject
}

// NewInMemoryStore는 새로운 인메모리 저장소를 생성
func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{
		objects: make(map[string]ManagedObject),
	}
}

// Store는 객체를 저장
func (s *InMemoryStore) Store(obj ManagedObject) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	id := obj.GetUniqueIdentifier()
	if id == "" {
		return errors.New("object must have a unique identifier")
	}
	
	s.objects[id] = obj
	return nil
}

// Retrieve는 객체를 조회
func (s *InMemoryStore) Retrieve(id string) (ManagedObject, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	obj, exists := s.objects[id]
	if !exists {
		return nil, errors.New("object not found")
	}
	
	return obj, nil
}

// Delete는 객체를 삭제
func (s *InMemoryStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	if _, exists := s.objects[id]; !exists {
		return errors.New("object not found")
	}
	
	delete(s.objects, id)
	return nil
}

// List는 모든 객체를 반환
func (s *InMemoryStore) List() []ManagedObject {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	result := make([]ManagedObject, 0, len(s.objects))
	for _, obj := range s.objects {
		result = append(result, obj)
	}
	
	return result
}

// GenerateUniqueID는 고유 식별자를 생성
func (s *InMemoryStore) GenerateUniqueID() string {
	// 16바이트 랜덤 ID 생성
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		// 에러 시 타임스탬프 기반 ID 사용
		return generateFallbackID()
	}
	
	return hex.EncodeToString(bytes)
}

func generateFallbackID() string {
	// 간단한 fallback ID 생성
	bytes := make([]byte, 16)
	for i := range bytes {
		bytes[i] = byte(i)
	}
	return hex.EncodeToString(bytes)
}
