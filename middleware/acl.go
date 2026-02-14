package middleware

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ACLMiddleware는 ACL 확인을 위한 미들웨어
type ACLMiddleware struct {
	aclChecker  ACLChecker
	auditLogger AuditLogger
}

// ACLChecker는 ACL 확인 인터페이스
type ACLChecker interface {
	CheckPermission(clientID, groupID, resourceID string, permission string) bool
}

// AuditLogger는 감사 로깅 인터페이스
type AuditLogger interface {
	Log(log *AuditLog)
}

// AuditLog는 감사 로그 구조체
type AuditLog struct {
	ID         string                 `json:"id"`
	Timestamp  time.Time              `json:"timestamp"`
	ClientID   string                 `json:"client_id"`
	Action     string                 `json:"action"`
	Resource   string                 `json:"resource"`
	ResourceID string                 `json:"resource_id"`
	GroupID    string                 `json:"group_id"`
	Result     string                 `json:"result"`
	Method     string                 `json:"method"`
	Path       string                 `json:"path"`
	StatusCode int                    `json:"status_code"`
	IPAddress  string                 `json:"ip_address"`
	UserAgent  string                 `json:"user_agent"`
	Details    map[string]interface{} `json:"details,omitempty"`
}

// NewACLMiddleware는 새로운 ACL 미들웨어를 생성
func NewACLMiddleware(checker ACLChecker, logger AuditLogger) *ACLMiddleware {
	return &ACLMiddleware{
		aclChecker:  checker,
		auditLogger: logger,
	}
}

// RequirePermission은 특정 권한을 요구하는 미들웨어를 반환
func (m *ACLMiddleware) RequirePermission(resource string, permission string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 클라이언트 식별
			clientID := extractClientID(r)
			if clientID == "" {
				m.logDenied(r, "", resource, "", "no_client_id")
				respondError(w, http.StatusUnauthorized, "Client ID required", nil)
				return
			}
			
			// 그룹 및 리소스 ID 추출
			groupID := extractGroupID(r)
			resourceID := extractResourceID(r)
			
			// 권한 확인
			allowed := m.aclChecker.CheckPermission(clientID, groupID, resourceID, permission)
			
			if !allowed {
				m.logDenied(r, clientID, resource, resourceID, "permission_denied")
				respondError(w, http.StatusForbidden, "Permission denied", nil)
				return
			}
			
			// 성공 로그
			m.logSuccess(r, clientID, resource, resourceID)
			
			// 다음 핸들러 실행
			next.ServeHTTP(w, r)
		})
	}
}

// RequireRole은 특정 역할을 요구하는 미들웨어를 반환
func (m *ACLMiddleware) RequireRole(roles ...string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clientID := extractClientID(r)
			if clientID == "" {
				respondError(w, http.StatusUnauthorized, "Client ID required", nil)
				return
			}
			
			// 역할 확인 (실제로는 ACLChecker에서 확인)
			hasRole := false
			for _, role := range roles {
				if m.aclChecker.CheckPermission(clientID, "", "", role) {
					hasRole = true
					break
				}
			}
			
			if !hasRole {
				respondError(w, http.StatusForbidden, "Required role not found", nil)
				return
			}
			
			next.ServeHTTP(w, r)
		})
	}
}

// RequireAdmin은 Admin 권한을 요구하는 미들웨어
func (m *ACLMiddleware) RequireAdmin() Middleware {
	return m.RequirePermission("admin", "MANAGE")
}

// RequireOwner는 Owner 권한을 요구하는 미들웨어
func (m *ACLMiddleware) RequireOwner(resource string) Middleware {
	return m.RequirePermission(resource, "UPDATE")
}

// RequireGuest는 최소 Guest 권한(READ)을 요구하는 미들웨어
func (m *ACLMiddleware) RequireGuest(resource string) Middleware {
	return m.RequirePermission(resource, "READ")
}

// RequireAudit은 Audit 권한을 요구하는 미들웨어
func (m *ACLMiddleware) RequireAudit() Middleware {
	return m.RequirePermission("audit", "AUDIT")
}

// logDenied는 거부된 요청을 로그에 기록
func (m *ACLMiddleware) logDenied(r *http.Request, clientID, resource, resourceID, reason string) {
	if m.auditLogger == nil {
		return
	}
	
	m.auditLogger.Log(&AuditLog{
		Timestamp:  time.Now(),
		ClientID:   clientID,
		Action:     fmt.Sprintf("%s_%s", r.Method, resource),
		Resource:   resource,
		ResourceID: resourceID,
		GroupID:    extractGroupID(r),
		Result:     "denied",
		Method:     r.Method,
		Path:       r.URL.Path,
		StatusCode: http.StatusForbidden,
		IPAddress:  getClientIP(r),
		UserAgent:  r.UserAgent(),
		Details: map[string]interface{}{
			"reason": reason,
		},
	})
}

// logSuccess는 성공한 요청을 로그에 기록
func (m *ACLMiddleware) logSuccess(r *http.Request, clientID, resource, resourceID string) {
	if m.auditLogger == nil {
		return
	}
	
	m.auditLogger.Log(&AuditLog{
		Timestamp:  time.Now(),
		ClientID:   clientID,
		Action:     fmt.Sprintf("%s_%s", r.Method, resource),
		Resource:   resource,
		ResourceID: resourceID,
		GroupID:    extractGroupID(r),
		Result:     "success",
		Method:     r.Method,
		Path:       r.URL.Path,
		StatusCode: http.StatusOK,
		IPAddress:  getClientIP(r),
		UserAgent:  r.UserAgent(),
	})
}

// extractClientID는 요청에서 클라이언트 ID를 추출
func extractClientID(r *http.Request) string {
	// X-Client-ID 헤더
	if clientID := r.Header.Get("X-Client-ID"); clientID != "" {
		return clientID
	}
	
	// X-API-Key 헤더에서 추출
	if apiKey := r.Header.Get("X-API-Key"); apiKey != "" {
		return extractClientIDFromAPIKey(apiKey)
	}
	
	// Authorization 헤더 (Bearer 토큰)
	if auth := r.Header.Get("Authorization"); auth != "" {
		if strings.HasPrefix(auth, "Bearer ") {
			token := strings.TrimPrefix(auth, "Bearer ")
			return extractClientIDFromToken(token)
		}
	}
	
	return ""
}

// extractGroupID는 요청에서 그룹 ID를 추출
func extractGroupID(r *http.Request) string {
	// X-Group-ID 헤더
	if groupID := r.Header.Get("X-Group-ID"); groupID != "" {
		return groupID
	}
	
	// 쿼리 파라미터
	if groupID := r.URL.Query().Get("group_id"); groupID != "" {
		return groupID
	}
	
	return ""
}

// extractResourceID는 요청에서 리소스 ID를 추출
func extractResourceID(r *http.Request) string {
	// URL 경로에서 추출
	path := r.URL.Path
	parts := strings.Split(path, "/")
	
	// 마지막 세그먼트가 리소스 ID인 경우가 많음
	if len(parts) > 0 {
		lastPart := parts[len(parts)-1]
		if lastPart != "" && !isAPIEndpoint(lastPart) {
			return lastPart
		}
	}
	
	// 쿼리 파라미터
	if resourceID := r.URL.Query().Get("resource_id"); resourceID != "" {
		return resourceID
	}
	if id := r.URL.Query().Get("id"); id != "" {
		return id
	}
	
	return ""
}

// extractClientIDFromAPIKey는 API 키에서 클라이언트 ID를 추출
func extractClientIDFromAPIKey(apiKey string) string {
	// 예: api_client123_1234567890 -> client123
	parts := strings.Split(apiKey, "_")
	if len(parts) >= 2 {
		return parts[1]
	}
	return ""
}

// extractClientIDFromToken은 토큰에서 클라이언트 ID를 추출
func extractClientIDFromToken(token string) string {
	// JWT 디코딩 등 (실제 구현 필요)
	return ""
}

// isAPIEndpoint는 문자열이 API 엔드포인트인지 확인
func isAPIEndpoint(s string) bool {
	endpoints := []string{
		"keys", "groups", "clients", "acls",
		"search", "attributes", "rekey",
		"audit", "logs", "reports",
		"health", "info", "versions",
	}
	
	for _, endpoint := range endpoints {
		if s == endpoint {
			return true
		}
	}
	
	return false
}

// respondError는 에러 응답을 반환
func respondError(w http.ResponseWriter, statusCode int, message string, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	
	response := map[string]interface{}{
		"error":   message,
		"code":    statusCode,
	}
	
	if err != nil {
		response["details"] = err.Error()
	}
	
	json.NewEncoder(w).Encode(response)
}
