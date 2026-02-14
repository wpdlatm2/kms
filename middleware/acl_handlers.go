package kmip

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// SetupACLRoutes는 ACL 관련 라우트를 설정
func (api *RESTAPIServer) SetupACLRoutes(mux *http.ServeMux, aclManager *ACLManager) {
	// 그룹 관리
	mux.HandleFunc("/api/v1/groups", func(w http.ResponseWriter, r *http.Request) {
		api.handleGroups(w, r, aclManager)
	})
	mux.HandleFunc("/api/v1/groups/", func(w http.ResponseWriter, r *http.Request) {
		api.handleGroupByID(w, r, aclManager)
	})
	
	// 클라이언트 관리
	mux.HandleFunc("/api/v1/clients", func(w http.ResponseWriter, r *http.Request) {
		api.handleClients(w, r, aclManager)
	})
	mux.HandleFunc("/api/v1/clients/", func(w http.ResponseWriter, r *http.Request) {
		api.handleClientByID(w, r, aclManager)
	})
	
	// ACL 관리
	mux.HandleFunc("/api/v1/acls", func(w http.ResponseWriter, r *http.Request) {
		api.handleACLs(w, r, aclManager)
	})
	mux.HandleFunc("/api/v1/acls/", func(w http.ResponseWriter, r *http.Request) {
		api.handleACLByID(w, r, aclManager)
	})
	
	// 권한 확인
	mux.HandleFunc("/api/v1/acls/check", func(w http.ResponseWriter, r *http.Request) {
		api.handleCheckPermission(w, r, aclManager)
	})
	
	// 자기 권한 조회 (Owner, Guest가 자신의 ACL 조회)
	mux.HandleFunc("/api/v1/acls/my-permissions", func(w http.ResponseWriter, r *http.Request) {
		api.handleMyPermissions(w, r, aclManager)
	})
}

// handleGroups는 그룹 목록 조회 및 생성
func (api *RESTAPIServer) handleGroups(w http.ResponseWriter, r *http.Request, aclManager *ACLManager) {
	// Admin 권한 확인
	clientID := api.getClientIDFromRequest(r)
	if !aclManager.CheckPermission(clientID, "", "", PermissionManage) {
		respondError(w, http.StatusForbidden, "Admin permission required", nil)
		return
	}
	
	switch r.Method {
	case http.MethodGet:
		groups := aclManager.ListGroups()
		
		response := map[string]interface{}{
			"groups": groups,
			"total":  len(groups),
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		
	case http.MethodPost:
		var req struct {
			ID          string                 `json:"id"`
			Name        string                 `json:"name"`
			Description string                 `json:"description"`
			Metadata    map[string]interface{} `json:"metadata"`
		}
		
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, "Invalid request", err)
			return
		}
		
		group := &Group{
			ID:          req.ID,
			Name:        req.Name,
			Description: req.Description,
			Metadata:    req.Metadata,
		}
		
		if err := aclManager.CreateGroup(group); err != nil {
			respondError(w, http.StatusBadRequest, "Failed to create group", err)
			return
		}
		
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(group)
		
	default:
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
	}
}

// handleGroupByID는 특정 그룹 조회/수정/삭제
func (api *RESTAPIServer) handleGroupByID(w http.ResponseWriter, r *http.Request, aclManager *ACLManager) {
	// Admin 권한 확인
	clientID := api.getClientIDFromRequest(r)
	if !aclManager.CheckPermission(clientID, "", "", PermissionManage) {
		respondError(w, http.StatusForbidden, "Admin permission required", nil)
		return
	}
	
	groupID := strings.TrimPrefix(r.URL.Path, "/api/v1/groups/")
	
	switch r.Method {
	case http.MethodGet:
		group, err := aclManager.GetGroup(groupID)
		if err != nil {
			respondError(w, http.StatusNotFound, "Group not found", err)
			return
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(group)
		
	case http.MethodPut:
		var req struct {
			Name        string                 `json:"name"`
			Description string                 `json:"description"`
			Metadata    map[string]interface{} `json:"metadata"`
		}
		
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, "Invalid request", err)
			return
		}
		
		group, err := aclManager.GetGroup(groupID)
		if err != nil {
			respondError(w, http.StatusNotFound, "Group not found", err)
			return
		}
		
		group.Name = req.Name
		group.Description = req.Description
		group.Metadata = req.Metadata
		
		if err := aclManager.UpdateGroup(group); err != nil {
			respondError(w, http.StatusBadRequest, "Failed to update group", err)
			return
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(group)
		
	case http.MethodDelete:
		if err := aclManager.DeleteGroup(groupID); err != nil {
			respondError(w, http.StatusBadRequest, "Failed to delete group", err)
			return
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message": "Group deleted successfully",
		})
		
	default:
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
	}
}

// handleClients는 클라이언트 목록 조회 및 생성
func (api *RESTAPIServer) handleClients(w http.ResponseWriter, r *http.Request, aclManager *ACLManager) {
	// Admin 권한 확인
	clientID := api.getClientIDFromRequest(r)
	if !aclManager.CheckPermission(clientID, "", "", PermissionManage) {
		respondError(w, http.StatusForbidden, "Admin permission required", nil)
		return
	}
	
	switch r.Method {
	case http.MethodGet:
		clients := aclManager.ListClients()
		
		// API 키는 응답에서 제거
		for _, client := range clients {
			client.APIKey = ""
		}
		
		response := map[string]interface{}{
			"clients": clients,
			"total":   len(clients),
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		
	case http.MethodPost:
		var req struct {
			ID          string                 `json:"id"`
			Name        string                 `json:"name"`
			Description string                 `json:"description"`
			Groups      []string               `json:"groups"`
			Metadata    map[string]interface{} `json:"metadata"`
		}
		
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, "Invalid request", err)
			return
		}
		
		// API 키 생성 (실제로는 안전한 랜덤 생성 사용)
		apiKey := fmt.Sprintf("api_%s_%d", req.ID, time.Now().Unix())
		
		client := &Client{
			ID:          req.ID,
			Name:        req.Name,
			APIKey:      apiKey,
			Description: req.Description,
			Groups:      req.Groups,
			Metadata:    req.Metadata,
		}
		
		if err := aclManager.CreateClient(client); err != nil {
			respondError(w, http.StatusBadRequest, "Failed to create client", err)
			return
		}
		
		response := map[string]interface{}{
			"id":      client.ID,
			"api_key": apiKey, // 최초 생성 시에만 반환
			"message": "Client created successfully. Save the API key - it won't be shown again.",
		}
		
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(response)
		
	default:
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
	}
}

// handleClientByID는 특정 클라이언트 조회/수정/삭제
func (api *RESTAPIServer) handleClientByID(w http.ResponseWriter, r *http.Request, aclManager *ACLManager) {
	// Admin 권한 확인
	clientID := api.getClientIDFromRequest(r)
	if !aclManager.CheckPermission(clientID, "", "", PermissionManage) {
		respondError(w, http.StatusForbidden, "Admin permission required", nil)
		return
	}
	
	targetClientID := strings.TrimPrefix(r.URL.Path, "/api/v1/clients/")
	
	switch r.Method {
	case http.MethodGet:
		client, err := aclManager.GetClient(targetClientID)
		if err != nil {
			respondError(w, http.StatusNotFound, "Client not found", err)
			return
		}
		
		client.APIKey = "" // API 키는 반환하지 않음
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(client)
		
	case http.MethodPut:
		var req struct {
			Name        string                 `json:"name"`
			Description string                 `json:"description"`
			Groups      []string               `json:"groups"`
			Enabled     *bool                  `json:"enabled"`
			Metadata    map[string]interface{} `json:"metadata"`
		}
		
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, "Invalid request", err)
			return
		}
		
		client, err := aclManager.GetClient(targetClientID)
		if err != nil {
			respondError(w, http.StatusNotFound, "Client not found", err)
			return
		}
		
		client.Name = req.Name
		client.Description = req.Description
		client.Groups = req.Groups
		if req.Enabled != nil {
			client.Enabled = *req.Enabled
		}
		client.Metadata = req.Metadata
		
		if err := aclManager.UpdateClient(client); err != nil {
			respondError(w, http.StatusBadRequest, "Failed to update client", err)
			return
		}
		
		client.APIKey = ""
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(client)
		
	case http.MethodDelete:
		if err := aclManager.DeleteClient(targetClientID); err != nil {
			respondError(w, http.StatusBadRequest, "Failed to delete client", err)
			return
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message": "Client deleted successfully",
		})
		
	default:
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
	}
}

// handleACLs는 ACL 목록 조회 및 생성
func (api *RESTAPIServer) handleACLs(w http.ResponseWriter, r *http.Request, aclManager *ACLManager) {
	// Admin 권한 확인
	clientID := api.getClientIDFromRequest(r)
	if !aclManager.CheckPermission(clientID, "", "", PermissionManage) {
		respondError(w, http.StatusForbidden, "Admin permission required", nil)
		return
	}
	
	switch r.Method {
	case http.MethodGet:
		// 쿼리 파라미터로 필터링
		clientIDFilter := r.URL.Query().Get("client_id")
		
		var acls []*ACLEntry
		if clientIDFilter != "" {
			acls = aclManager.ListACLsByClient(clientIDFilter)
		} else {
			acls = aclManager.ListACLs()
		}
		
		response := map[string]interface{}{
			"acls":  acls,
			"total": len(acls),
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		
	case http.MethodPost:
		var req struct {
			ID         string  `json:"id"`
			ClientID   string  `json:"client_id"`
			GroupID    string  `json:"group_id"`
			Role       Role    `json:"role"`
			ResourceID string  `json:"resource_id"`
			ExpiresAt  *string `json:"expires_at"` // ISO 8601 형식
		}
		
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, "Invalid request", err)
			return
		}
		
		acl := &ACLEntry{
			ID:         req.ID,
			ClientID:   req.ClientID,
			GroupID:    req.GroupID,
			Role:       req.Role,
			ResourceID: req.ResourceID,
		}
		
		// 만료 시간 파싱
		if req.ExpiresAt != nil && *req.ExpiresAt != "" {
			expiresAt, err := time.Parse(time.RFC3339, *req.ExpiresAt)
			if err != nil {
				respondError(w, http.StatusBadRequest, "Invalid expires_at format", err)
				return
			}
			acl.ExpiresAt = &expiresAt
		}
		
		if err := aclManager.CreateACL(acl); err != nil {
			respondError(w, http.StatusBadRequest, "Failed to create ACL", err)
			return
		}
		
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(acl)
		
	default:
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
	}
}

// handleACLByID는 특정 ACL 조회/삭제
func (api *RESTAPIServer) handleACLByID(w http.ResponseWriter, r *http.Request, aclManager *ACLManager) {
	// Admin 권한 확인
	clientID := api.getClientIDFromRequest(r)
	if !aclManager.CheckPermission(clientID, "", "", PermissionManage) {
		respondError(w, http.StatusForbidden, "Admin permission required", nil)
		return
	}
	
	aclID := strings.TrimPrefix(r.URL.Path, "/api/v1/acls/")
	
	switch r.Method {
	case http.MethodGet:
		acl, err := aclManager.GetACL(aclID)
		if err != nil {
			respondError(w, http.StatusNotFound, "ACL not found", err)
			return
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(acl)
		
	case http.MethodDelete:
		if err := aclManager.DeleteACL(aclID); err != nil {
			respondError(w, http.StatusBadRequest, "Failed to delete ACL", err)
			return
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message": "ACL deleted successfully",
		})
		
	default:
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
	}
}

// handleCheckPermission은 권한 확인
func (api *RESTAPIServer) handleCheckPermission(w http.ResponseWriter, r *http.Request, aclManager *ACLManager) {
	if r.Method != http.MethodPost {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
		return
	}
	
	var req struct {
		ClientID   string     `json:"client_id"`
		GroupID    string     `json:"group_id"`
		ResourceID string     `json:"resource_id"`
		Permission Permission `json:"permission"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request", err)
		return
	}
	
	allowed := aclManager.CheckPermission(req.ClientID, req.GroupID, req.ResourceID, req.Permission)
	
	response := map[string]interface{}{
		"allowed":     allowed,
		"client_id":   req.ClientID,
		"group_id":    req.GroupID,
		"resource_id": req.ResourceID,
		"permission":  req.Permission,
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleMyPermissions는 자기 권한 조회 (Owner, Guest)
func (api *RESTAPIServer) handleMyPermissions(w http.ResponseWriter, r *http.Request, aclManager *ACLManager) {
	if r.Method != http.MethodGet {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
		return
	}
	
	// 요청한 클라이언트 ID
	clientID := api.getClientIDFromRequest(r)
	if clientID == "" {
		respondError(w, http.StatusUnauthorized, "Client ID required (use X-Client-ID or X-API-Key header)", nil)
		return
	}
	
	// 클라이언트 존재 확인
	client, err := aclManager.GetClient(clientID)
	if err != nil {
		respondError(w, http.StatusNotFound, "Client not found", err)
		return
	}
	
	// 클라이언트의 모든 ACL 조회
	acls := aclManager.ListACLsByClient(clientID)
	
	// 그룹별로 정리
	type GroupPermission struct {
		GroupID     string       `json:"group_id"`
		GroupName   string       `json:"group_name,omitempty"`
		Role        Role         `json:"role"`
		Permissions []Permission `json:"permissions"`
		ResourceID  string       `json:"resource_id,omitempty"`
		ExpiresAt   *time.Time   `json:"expires_at,omitempty"`
	}
	
	groupPermissions := make([]GroupPermission, 0)
	
	for _, acl := range acls {
		gp := GroupPermission{
			GroupID:     acl.GroupID,
			Role:        acl.Role,
			Permissions: acl.Permissions,
			ResourceID:  acl.ResourceID,
			ExpiresAt:   acl.ExpiresAt,
		}
		
		// 그룹 이름 조회 (Admin/Audit은 그룹이 없을 수 있음)
		if acl.GroupID != "" && acl.GroupID != "*" {
			if group, err := aclManager.GetGroup(acl.GroupID); err == nil {
				gp.GroupName = group.Name
			}
		}
		
		groupPermissions = append(groupPermissions, gp)
	}
	
	// 요약 생성
	summary := map[string]interface{}{
		"is_admin":       false,
		"is_owner":       false,
		"is_guest":       false,
		"is_audit":       false,
		"owner_groups":   make([]string, 0),
		"guest_groups":   make([]string, 0),
	}
	
	ownerGroups := make([]string, 0)
	guestGroups := make([]string, 0)
	
	for _, acl := range acls {
		switch acl.Role {
		case RoleAdmin:
			summary["is_admin"] = true
		case RoleOwner:
			summary["is_owner"] = true
			if acl.GroupID != "" && acl.GroupID != "*" {
				ownerGroups = append(ownerGroups, acl.GroupID)
			}
		case RoleGuest:
			summary["is_guest"] = true
			if acl.GroupID != "" && acl.GroupID != "*" {
				guestGroups = append(guestGroups, acl.GroupID)
			}
		case RoleAudit:
			summary["is_audit"] = true
		}
	}
	
	summary["owner_groups"] = ownerGroups
	summary["guest_groups"] = guestGroups
	
	response := map[string]interface{}{
		"client_id":          client.ID,
		"client_name":        client.Name,
		"total_permissions":  len(groupPermissions),
		"permissions":        groupPermissions,
		"summary":            summary,
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// getClientIDFromRequest는 요청에서 클라이언트 ID를 추출
func (api *RESTAPIServer) getClientIDFromRequest(r *http.Request) string {
	// X-Client-ID 헤더에서 추출
	if clientID := r.Header.Get("X-Client-ID"); clientID != "" {
		return clientID
	}
	
	// API 키로부터 추출 (실제로는 API 키 검증 필요)
	if apiKey := r.Header.Get("X-API-Key"); apiKey != "" {
		// API 키로 클라이언트 조회 로직
		// 여기서는 간단히 API 키에서 클라이언트 ID 추출
		return extractClientIDFromAPIKey(apiKey)
	}
	
	return ""
}

// extractClientIDFromAPIKey는 API 키에서 클라이언트 ID를 추출 (예제)
func extractClientIDFromAPIKey(apiKey string) string {
	// 실제로는 데이터베이스에서 조회해야 함
	// 예: api_client123_1234567890 -> client123
	parts := strings.Split(apiKey, "_")
	if len(parts) >= 2 {
		return parts[1]
	}
	return ""
}
