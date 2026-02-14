package kmip

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
)

// ClusterManager는 Raft 클러스터 관리를 위한 HTTP API
type ClusterManager struct {
	store *RaftStore
	mu    sync.RWMutex
}

// NewClusterManager는 새로운 ClusterManager를 생성
func NewClusterManager(store *RaftStore) *ClusterManager {
	return &ClusterManager{
		store: store,
	}
}

// ServeHTTP는 HTTP 관리 API 서버를 시작
func (cm *ClusterManager) ServeHTTP(addr string) error {
	mux := http.NewServeMux()
	
	// 클러스터 상태 조회
	mux.HandleFunc("/cluster/status", cm.handleStatus)
	
	// 노드 추가
	mux.HandleFunc("/cluster/join", cm.handleJoin)
	
	// 노드 제거
	mux.HandleFunc("/cluster/leave", cm.handleLeave)
	
	// 통계 조회
	mux.HandleFunc("/cluster/stats", cm.handleStats)
	
	return http.ListenAndServe(addr, mux)
}

// handleStatus는 클러스터 상태를 반환
func (cm *ClusterManager) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	status := map[string]interface{}{
		"is_leader": cm.store.IsLeader(),
		"leader":    cm.store.GetLeader(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

// handleJoin은 새 노드를 클러스터에 추가
func (cm *ClusterManager) handleJoin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		NodeID string `json:"node_id"`
		Addr   string `json:"addr"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
		return
	}

	if req.NodeID == "" || req.Addr == "" {
		http.Error(w, "node_id and addr are required", http.StatusBadRequest)
		return
	}

	if err := cm.store.Join(req.NodeID, req.Addr); err != nil {
		http.Error(w, fmt.Sprintf("Failed to join node: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

// handleLeave는 노드를 클러스터에서 제거
func (cm *ClusterManager) handleLeave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		NodeID string `json:"node_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
		return
	}

	if req.NodeID == "" {
		http.Error(w, "node_id is required", http.StatusBadRequest)
		return
	}

	if err := cm.store.Leave(req.NodeID); err != nil {
		http.Error(w, fmt.Sprintf("Failed to remove node: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

// handleStats는 Raft 통계를 반환
func (cm *ClusterManager) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	stats := cm.store.GetStats()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}
