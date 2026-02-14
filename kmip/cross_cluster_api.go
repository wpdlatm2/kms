package kmip

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// HandleCrossClusterReplication은 클러스터 간 복제 API를 처리
func (api *RESTAPIServer) HandleCrossClusterReplication(ccr *CrossClusterReplication) {
	// 복제 배치 수신
	http.HandleFunc("/api/v1/replication/batch", func(w http.ResponseWriter, r *http.Request) {
		api.handleReplicationBatch(w, r, ccr)
	})
	
	// 원격 클러스터 관리
	http.HandleFunc("/api/v1/replication/clusters", func(w http.ResponseWriter, r *http.Request) {
		api.handleRemoteClusters(w, r, ccr)
	})
	
	// 클러스터 상태
	http.HandleFunc("/api/v1/replication/status", func(w http.ResponseWriter, r *http.Request) {
		api.handleReplicationStatus(w, r, ccr)
	})
	
	// 수동 동기화
	http.HandleFunc("/api/v1/replication/sync", func(w http.ResponseWriter, r *http.Request) {
		api.handleManualSync(w, r, ccr)
	})
}

// handleReplicationBatch는 복제 배치를 처리
func (api *RESTAPIServer) handleReplicationBatch(w http.ResponseWriter, r *http.Request, ccr *CrossClusterReplication) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	// 인증 확인
	authHeader := r.Header.Get("Authorization")
	sourceClusterID := r.Header.Get("X-Cluster-ID")
	
	// TODO: API 키 검증
	
	var req struct {
		SourceCluster string              `json:"source_cluster"`
		TargetCluster string              `json:"target_cluster"`
		Events        []ReplicationEvent  `json:"events"`
		Timestamp     string              `json:"timestamp"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request", err)
		return
	}
	
	ccr.logger.Printf("📥 Received %d replication events from %s", len(req.Events), req.SourceCluster)
	
	// 각 이벤트 처리
	processed := 0
	failed := 0
	
	for _, event := range req.Events {
		err := api.processReplicationEvent(event, req.SourceCluster)
		if err != nil {
			ccr.logger.Printf("⚠️  Failed to process event %s: %v", event.ObjectID, err)
			failed++
		} else {
			processed++
		}
	}
	
	response := map[string]interface{}{
		"status":    "success",
		"processed": processed,
		"failed":    failed,
		"cluster":   sourceClusterID,
	}
	
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// processReplicationEvent는 복제 이벤트를 처리
func (api *RESTAPIServer) processReplicationEvent(event ReplicationEvent, sourceCluster string) error {
	switch event.Type {
	case "create", "update":
		// 객체 저장
		if event.Object != nil {
			return api.server.GetStore().Store(event.Object)
		}
		return fmt.Errorf("no object in event")
		
	case "delete":
		// 객체 삭제
		return api.server.GetStore().Delete(event.ObjectID)
		
	default:
		return fmt.Errorf("unknown event type: %s", event.Type)
	}
}

// handleRemoteClusters는 원격 클러스터 관리
func (api *RESTAPIServer) handleRemoteClusters(w http.ResponseWriter, r *http.Request, ccr *CrossClusterReplication) {
	switch r.Method {
	case http.MethodGet:
		// 클러스터 목록
		clusters := ccr.GetClusterStatus()
		response := map[string]interface{}{
			"clusters": clusters,
			"total":    len(clusters),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		
	case http.MethodPost:
		// 클러스터 추가
		var cluster RemoteCluster
		if err := json.NewDecoder(r.Body).Decode(&cluster); err != nil {
			respondError(w, http.StatusBadRequest, "Invalid request", err)
			return
		}
		
		if err := ccr.AddRemoteCluster(cluster); err != nil {
			respondError(w, http.StatusBadRequest, "Failed to add cluster", err)
			return
		}
		
		response := map[string]interface{}{
			"status":     "success",
			"cluster_id": cluster.ID,
			"message":    fmt.Sprintf("Added remote cluster: %s", cluster.Name),
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(response)
		
	case http.MethodDelete:
		// 클러스터 제거
		var req struct {
			ClusterID string `json:"cluster_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, "Invalid request", err)
			return
		}
		
		if err := ccr.RemoveRemoteCluster(req.ClusterID); err != nil {
			respondError(w, http.StatusNotFound, "Cluster not found", err)
			return
		}
		
		response := map[string]interface{}{
			"status":  "success",
			"message": fmt.Sprintf("Removed cluster: %s", req.ClusterID),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleReplicationStatus는 복제 상태를 반환
func (api *RESTAPIServer) handleReplicationStatus(w http.ResponseWriter, r *http.Request, ccr *CrossClusterReplication) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	clusters := ccr.GetClusterStatus()
	
	// 통계 계산
	activeCount := 0
	failedCount := 0
	totalErrors := 0
	
	for _, cluster := range clusters {
		if cluster.Status == "active" {
			activeCount++
		} else if cluster.Status == "failed" {
			failedCount++
		}
		totalErrors += cluster.ErrorCount
	}
	
	response := map[string]interface{}{
		"local_cluster": ccr.localClusterID,
		"clusters":      clusters,
		"summary": map[string]interface{}{
			"total":   len(clusters),
			"active":  activeCount,
			"failed":  failedCount,
			"errors":  totalErrors,
		},
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleManualSync는 수동 동기화를 처리
func (api *RESTAPIServer) handleManualSync(w http.ResponseWriter, r *http.Request, ccr *CrossClusterReplication) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	var req struct {
		ClusterID string `json:"cluster_id"`
		Direction string `json:"direction"` // push, pull
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request", err)
		return
	}
	
	ccr.logger.Printf("🔄 Manual sync requested: %s (%s)", req.ClusterID, req.Direction)
	
	var err error
	if req.Direction == "pull" {
		err = ccr.SyncFromRemote(req.ClusterID)
	} else if req.Direction == "push" {
		// Push: 로컬의 모든 키를 원격으로 복제
		// TODO: 구현
		err = fmt.Errorf("push not implemented yet")
	} else {
		respondError(w, http.StatusBadRequest, "Invalid direction", nil)
		return
	}
	
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Sync failed", err)
		return
	}
	
	response := map[string]interface{}{
		"status":     "success",
		"cluster_id": req.ClusterID,
		"direction":  req.Direction,
		"message":    "Synchronization completed",
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// GetStore는 서버의 저장소를 반환
func (s *Server) GetStore() ObjectStore {
	return s.store
}
