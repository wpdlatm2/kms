package kmip

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// AuditLog는 감사 로그 항목
type AuditLog struct {
	ID         string                 `json:"id"`
	Timestamp  time.Time              `json:"timestamp"`
	ClientID   string                 `json:"client_id"`
	Action     string                 `json:"action"`       // CREATE_KEY, DELETE_KEY, etc.
	Resource   string                 `json:"resource"`     // keys, groups, clients, acls
	ResourceID string                 `json:"resource_id"`  // 대상 리소스 ID
	GroupID    string                 `json:"group_id"`     // 대상 그룹 ID
	Result     string                 `json:"result"`       // success, denied, error
	Method     string                 `json:"method"`       // HTTP 메소드
	Path       string                 `json:"path"`         // 요청 경로
	StatusCode int                    `json:"status_code"`  // 응답 상태 코드
	IPAddress  string                 `json:"ip_address"`   // 클라이언트 IP
	UserAgent  string                 `json:"user_agent"`   // User-Agent
	Details    map[string]interface{} `json:"details,omitempty"` // 추가 정보
}

// AuditLogger는 감사 로그 관리자
type AuditLogger struct {
	logs      []*AuditLog
	mu        sync.RWMutex
	maxLogs   int // 최대 로그 개수
	retention time.Duration // 보관 기간
}

// NewAuditLogger는 새로운 감사 로거를 생성
func NewAuditLogger(maxLogs int, retention time.Duration) *AuditLogger {
	return &AuditLogger{
		logs:      make([]*AuditLog, 0),
		maxLogs:   maxLogs,
		retention: retention,
	}
}

// Log는 감사 로그를 기록
func (al *AuditLogger) Log(log *AuditLog) {
	al.mu.Lock()
	defer al.mu.Unlock()
	
	log.ID = fmt.Sprintf("audit_%d", time.Now().UnixNano())
	log.Timestamp = time.Now()
	
	al.logs = append(al.logs, log)
	
	// 오래된 로그 정리
	al.cleanupOldLogs()
	
	// 최대 개수 제한
	if len(al.logs) > al.maxLogs {
		al.logs = al.logs[len(al.logs)-al.maxLogs:]
	}
}

// cleanupOldLogs는 보관 기간이 지난 로그를 삭제
func (al *AuditLogger) cleanupOldLogs() {
	cutoff := time.Now().Add(-al.retention)
	
	validLogs := make([]*AuditLog, 0)
	for _, log := range al.logs {
		if log.Timestamp.After(cutoff) {
			validLogs = append(validLogs, log)
		}
	}
	
	al.logs = validLogs
}

// GetLogs는 감사 로그를 조회
func (al *AuditLogger) GetLogs(filter *AuditLogFilter) []*AuditLog {
	al.mu.RLock()
	defer al.mu.RUnlock()
	
	result := make([]*AuditLog, 0)
	
	for _, log := range al.logs {
		if filter != nil && !filter.Match(log) {
			continue
		}
		result = append(result, log)
	}
	
	return result
}

// AuditLogFilter는 감사 로그 필터
type AuditLogFilter struct {
	ClientID   string
	Action     string
	Resource   string
	ResourceID string
	GroupID    string
	Result     string
	StartTime  *time.Time
	EndTime    *time.Time
}

// Match는 로그가 필터 조건에 맞는지 확인
func (f *AuditLogFilter) Match(log *AuditLog) bool {
	if f.ClientID != "" && log.ClientID != f.ClientID {
		return false
	}
	if f.Action != "" && log.Action != f.Action {
		return false
	}
	if f.Resource != "" && log.Resource != f.Resource {
		return false
	}
	if f.ResourceID != "" && log.ResourceID != f.ResourceID {
		return false
	}
	if f.GroupID != "" && log.GroupID != f.GroupID {
		return false
	}
	if f.Result != "" && log.Result != f.Result {
		return false
	}
	if f.StartTime != nil && log.Timestamp.Before(*f.StartTime) {
		return false
	}
	if f.EndTime != nil && log.Timestamp.After(*f.EndTime) {
		return false
	}
	
	return true
}

// ACLMiddleware는 ACL 확인 미들웨어
type ACLMiddleware struct {
	aclManager  *ACLManager
	auditLogger *AuditLogger
}

// NewACLMiddleware는 새로운 ACL 미들웨어를 생성
func NewACLMiddleware(aclManager *ACLManager, auditLogger *AuditLogger) *ACLMiddleware {
	return &ACLMiddleware{
		aclManager:  aclManager,
		auditLogger: auditLogger,
	}
}

// Wrap은 핸들러를 ACL 체크로 감싸기
func (m *ACLMiddleware) Wrap(next http.Handler, resource string, permission Permission) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientID := m.getClientID(r)
		groupID := m.getGroupID(r)
		resourceID := m.getResourceID(r)
		
		// 권한 확인
		allowed := m.aclManager.CheckPermission(clientID, groupID, resourceID, permission)
		
		if !allowed {
			// 감사 로그 기록
			m.auditLogger.Log(&AuditLog{
				ClientID:   clientID,
				Action:     fmt.Sprintf("%s_%s", r.Method, resource),
				Resource:   resource,
				ResourceID: resourceID,
				GroupID:    groupID,
				Result:     "denied",
				Method:     r.Method,
				Path:       r.URL.Path,
				StatusCode: http.StatusForbidden,
				IPAddress:  getClientIP(r),
				UserAgent:  r.UserAgent(),
			})
			
			http.Error(w, "Permission denied", http.StatusForbidden)
			return
		}
		
		// 권한이 있으면 다음 핸들러 실행
		next.ServeHTTP(w, r)
		
		// 성공 로그 기록
		m.auditLogger.Log(&AuditLog{
			ClientID:   clientID,
			Action:     fmt.Sprintf("%s_%s", r.Method, resource),
			Resource:   resource,
			ResourceID: resourceID,
			GroupID:    groupID,
			Result:     "success",
			Method:     r.Method,
			Path:       r.URL.Path,
			StatusCode: http.StatusOK,
			IPAddress:  getClientIP(r),
			UserAgent:  r.UserAgent(),
		})
	})
}

// getClientID는 요청에서 클라이언트 ID 추출
func (m *ACLMiddleware) getClientID(r *http.Request) string {
	if clientID := r.Header.Get("X-Client-ID"); clientID != "" {
		return clientID
	}
	if apiKey := r.Header.Get("X-API-Key"); apiKey != "" {
		return extractClientIDFromAPIKey(apiKey)
	}
	return ""
}

// getGroupID는 요청에서 그룹 ID 추출
func (m *ACLMiddleware) getGroupID(r *http.Request) string {
	// 쿼리 파라미터 또는 헤더에서 추출
	if groupID := r.URL.Query().Get("group_id"); groupID != "" {
		return groupID
	}
	if groupID := r.Header.Get("X-Group-ID"); groupID != "" {
		return groupID
	}
	return ""
}

// getResourceID는 요청에서 리소스 ID 추출
func (m *ACLMiddleware) getResourceID(r *http.Request) string {
	// URL 경로에서 추출 (예: /api/v1/keys/{id})
	// 간단히 마지막 경로 세그먼트를 반환
	parts := splitPath(r.URL.Path)
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return ""
}

// getClientIP는 클라이언트 IP 주소를 추출
func getClientIP(r *http.Request) string {
	// X-Forwarded-For 헤더 확인
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}
	// X-Real-IP 헤더 확인
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	// RemoteAddr 사용
	return r.RemoteAddr
}

// splitPath는 경로를 세그먼트로 분할
func splitPath(path string) []string {
	parts := make([]string, 0)
	for _, part := range splitString(path, "/") {
		if part != "" {
			parts = append(parts, part)
		}
	}
	return parts
}

func splitString(s, sep string) []string {
	result := make([]string, 0)
	current := ""
	
	for _, char := range s {
		if string(char) == sep {
			result = append(result, current)
			current = ""
		} else {
			current += string(char)
		}
	}
	if current != "" {
		result = append(result, current)
	}
	
	return result
}

// SetupAuditRoutes는 감사 로그 관련 라우트를 설정
func (api *RESTAPIServer) SetupAuditRoutes(mux *http.ServeMux, aclManager *ACLManager, auditLogger *AuditLogger) {
	// 감사 로그 조회
	mux.HandleFunc("/api/v1/audit/logs", func(w http.ResponseWriter, r *http.Request) {
		api.handleAuditLogs(w, r, aclManager, auditLogger)
	})
	
	// 감사 리포트 생성
	mux.HandleFunc("/api/v1/audit/reports", func(w http.ResponseWriter, r *http.Request) {
		api.handleAuditReports(w, r, aclManager, auditLogger)
	})
}

// handleAuditLogs는 감사 로그 조회
func (api *RESTAPIServer) handleAuditLogs(w http.ResponseWriter, r *http.Request, aclManager *ACLManager, auditLogger *AuditLogger) {
	if r.Method != http.MethodGet {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
		return
	}
	
	clientID := api.getClientIDFromRequest(r)
	requestedGroupID := r.URL.Query().Get("group_id")
	
	// 권한 확인
	// 1. Audit 역할: 모든 로그 조회 가능
	hasAuditRole := aclManager.CheckPermission(clientID, "", "", PermissionAudit)
	
	// 2. Owner 역할: 해당 그룹의 로그만 조회 가능
	hasOwnerRole := false
	allowedGroups := make([]string, 0)
	
	if !hasAuditRole {
		// Owner 권한을 가진 그룹 목록 조회
		acls := aclManager.ListACLsByClient(clientID)
		for _, acl := range acls {
			if acl.Role == RoleOwner {
				allowedGroups = append(allowedGroups, acl.GroupID)
				hasOwnerRole = true
			}
		}
		
		// Owner 역할도 없으면 거부
		if !hasOwnerRole {
			respondError(w, http.StatusForbidden, "Audit or Owner permission required", nil)
			return
		}
		
		// Owner인 경우 group_id 파라미터 필수
		if requestedGroupID == "" {
			respondError(w, http.StatusBadRequest, "group_id parameter required for Owner role", nil)
			return
		}
		
		// Owner인 그룹만 조회 가능
		groupAllowed := false
		for _, g := range allowedGroups {
			if g == requestedGroupID {
				groupAllowed = true
				break
			}
		}
		
		if !groupAllowed {
			respondError(w, http.StatusForbidden, "No permission to view logs for this group", nil)
			return
		}
	}
	
	// 필터 파싱
	filter := &AuditLogFilter{
		ClientID:   r.URL.Query().Get("client_id"),
		Action:     r.URL.Query().Get("action"),
		Resource:   r.URL.Query().Get("resource"),
		ResourceID: r.URL.Query().Get("resource_id"),
		Result:     r.URL.Query().Get("result"),
	}
	
	// Owner인 경우 해당 그룹으로 필터링
	if !hasAuditRole && hasOwnerRole {
		filter.GroupID = requestedGroupID
	} else if requestedGroupID != "" {
		// Audit 역할이지만 특정 그룹을 요청한 경우
		filter.GroupID = requestedGroupID
	}
	
	// 시간 범위 파싱
	if startTimeStr := r.URL.Query().Get("start_time"); startTimeStr != "" {
		if startTime, err := time.Parse(time.RFC3339, startTimeStr); err == nil {
			filter.StartTime = &startTime
		}
	}
	if endTimeStr := r.URL.Query().Get("end_time"); endTimeStr != "" {
		if endTime, err := time.Parse(time.RFC3339, endTimeStr); err == nil {
			filter.EndTime = &endTime
		}
	}
	
	logs := auditLogger.GetLogs(filter)
	
	response := map[string]interface{}{
		"logs":  logs,
		"total": len(logs),
	}
	
	// Owner인 경우 필터링된 그룹 정보 포함
	if !hasAuditRole && hasOwnerRole {
		response["filtered_by_group"] = requestedGroupID
		response["role"] = "Owner"
	} else {
		response["role"] = "Audit"
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleAuditReports는 감사 리포트 생성
func (api *RESTAPIServer) handleAuditReports(w http.ResponseWriter, r *http.Request, aclManager *ACLManager, auditLogger *AuditLogger) {
	if r.Method != http.MethodGet {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
		return
	}
	
	// Audit 권한 확인
	clientID := api.getClientIDFromRequest(r)
	if !aclManager.CheckPermission(clientID, "", "", PermissionAudit) {
		respondError(w, http.StatusForbidden, "Audit permission required", nil)
		return
	}
	
	// 전체 로그 가져오기
	logs := auditLogger.GetLogs(nil)
	
	// 통계 생성
	report := generateAuditReport(logs)
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(report)
}

// generateAuditReport는 감사 리포트를 생성
func generateAuditReport(logs []*AuditLog) map[string]interface{} {
	totalLogs := len(logs)
	
	// 결과별 집계
	resultCounts := make(map[string]int)
	actionCounts := make(map[string]int)
	clientCounts := make(map[string]int)
	resourceCounts := make(map[string]int)
	
	for _, log := range logs {
		resultCounts[log.Result]++
		actionCounts[log.Action]++
		clientCounts[log.ClientID]++
		resourceCounts[log.Resource]++
	}
	
	return map[string]interface{}{
		"total_logs": totalLogs,
		"summary": map[string]interface{}{
			"by_result":   resultCounts,
			"by_action":   actionCounts,
			"by_client":   clientCounts,
			"by_resource": resourceCounts,
		},
		"generated_at": time.Now(),
	}
}
