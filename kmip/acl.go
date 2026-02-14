package kmip

import (
	"fmt"
	"sync"
	"time"
)

// Role은 사용자 역할
type Role string

const (
	// RoleAdmin은 모든 키와 클라이언트 관리 권한
	RoleAdmin Role = "Admin"
	
	// RoleOwner는 해당 그룹의 키에 대한 CRUD 권한
	RoleOwner Role = "Owner"
	
	// RoleGuest는 해당 그룹의 키에 대한 R(읽기) 권한
	RoleGuest Role = "Guest"
	
	// RoleAudit은 감사 로그 및 리포트 조회 권한
	RoleAudit Role = "Audit"
)

// Permission은 작업 권한
type Permission string

const (
	PermissionCreate Permission = "CREATE"
	PermissionRead   Permission = "READ"
	PermissionUpdate Permission = "UPDATE"
	PermissionDelete Permission = "DELETE"
	PermissionManage Permission = "MANAGE" // Admin용
	PermissionAudit  Permission = "AUDIT"  // Audit용
)

// Group은 키와 클라이언트를 그룹화
type Group struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// Client는 API 클라이언트 (사용자 또는 애플리케이션)
type Client struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	APIKey      string                 `json:"api_key,omitempty"` // 해시된 API 키
	Description string                 `json:"description,omitempty"`
	Groups      []string               `json:"groups"` // 소속 그룹 ID 목록
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	Enabled     bool                   `json:"enabled"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// ACLEntry는 접근 제어 목록 항목
type ACLEntry struct {
	ID          string       `json:"id"`
	ClientID    string       `json:"client_id"`    // 클라이언트 ID
	GroupID     string       `json:"group_id"`     // 그룹 ID (Admin/Audit은 "*" 가능)
	Role        Role         `json:"role"`         // Admin, Owner, Guest, Audit
	Permissions []Permission `json:"permissions"`  // 허용된 작업 목록
	ResourceID  string       `json:"resource_id"`  // 특정 리소스 (선택적, "*"는 전체)
	CreatedAt   time.Time    `json:"created_at"`
	UpdatedAt   time.Time    `json:"updated_at"`
	ExpiresAt   *time.Time   `json:"expires_at,omitempty"` // 만료 시간 (선택적)
}

// ACLManager는 ACL 관리자
type ACLManager struct {
	groups  map[string]*Group     // group_id -> Group
	clients map[string]*Client    // client_id -> Client
	acls    map[string]*ACLEntry  // acl_id -> ACLEntry
	
	// 빠른 조회를 위한 인덱스
	clientACLs map[string][]string // client_id -> []acl_id
	groupACLs  map[string][]string // group_id -> []acl_id
	
	mu sync.RWMutex
}

// NewACLManager는 새로운 ACL 관리자를 생성
func NewACLManager() *ACLManager {
	return &ACLManager{
		groups:     make(map[string]*Group),
		clients:    make(map[string]*Client),
		acls:       make(map[string]*ACLEntry),
		clientACLs: make(map[string][]string),
		groupACLs:  make(map[string][]string),
	}
}

// CreateGroup은 새로운 그룹을 생성
func (m *ACLManager) CreateGroup(group *Group) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if group.ID == "" {
		return fmt.Errorf("group ID is required")
	}
	
	if _, exists := m.groups[group.ID]; exists {
		return fmt.Errorf("group already exists: %s", group.ID)
	}
	
	group.CreatedAt = time.Now()
	group.UpdatedAt = time.Now()
	
	m.groups[group.ID] = group
	return nil
}

// GetGroup은 그룹을 조회
func (m *ACLManager) GetGroup(groupID string) (*Group, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	group, exists := m.groups[groupID]
	if !exists {
		return nil, fmt.Errorf("group not found: %s", groupID)
	}
	
	return group, nil
}

// ListGroups는 모든 그룹을 조회
func (m *ACLManager) ListGroups() []*Group {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	groups := make([]*Group, 0, len(m.groups))
	for _, group := range m.groups {
		groups = append(groups, group)
	}
	
	return groups
}

// UpdateGroup은 그룹을 수정
func (m *ACLManager) UpdateGroup(group *Group) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if _, exists := m.groups[group.ID]; !exists {
		return fmt.Errorf("group not found: %s", group.ID)
	}
	
	group.UpdatedAt = time.Now()
	m.groups[group.ID] = group
	
	return nil
}

// DeleteGroup은 그룹을 삭제
func (m *ACLManager) DeleteGroup(groupID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	// 그룹에 연결된 ACL 확인
	if aclIDs, exists := m.groupACLs[groupID]; exists && len(aclIDs) > 0 {
		return fmt.Errorf("group has associated ACLs, delete them first")
	}
	
	delete(m.groups, groupID)
	delete(m.groupACLs, groupID)
	
	return nil
}

// CreateClient는 새로운 클라이언트를 생성
func (m *ACLManager) CreateClient(client *Client) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if client.ID == "" {
		return fmt.Errorf("client ID is required")
	}
	
	if _, exists := m.clients[client.ID]; exists {
		return fmt.Errorf("client already exists: %s", client.ID)
	}
	
	client.CreatedAt = time.Now()
	client.UpdatedAt = time.Now()
	client.Enabled = true
	
	m.clients[client.ID] = client
	return nil
}

// GetClient는 클라이언트를 조회
func (m *ACLManager) GetClient(clientID string) (*Client, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	client, exists := m.clients[clientID]
	if !exists {
		return nil, fmt.Errorf("client not found: %s", clientID)
	}
	
	return client, nil
}

// ListClients는 모든 클라이언트를 조회
func (m *ACLManager) ListClients() []*Client {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	clients := make([]*Client, 0, len(m.clients))
	for _, client := range m.clients {
		clients = append(clients, client)
	}
	
	return clients
}

// UpdateClient는 클라이언트를 수정
func (m *ACLManager) UpdateClient(client *Client) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if _, exists := m.clients[client.ID]; !exists {
		return fmt.Errorf("client not found: %s", client.ID)
	}
	
	client.UpdatedAt = time.Now()
	m.clients[client.ID] = client
	
	return nil
}

// DeleteClient는 클라이언트를 삭제
func (m *ACLManager) DeleteClient(clientID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	// 클라이언트에 연결된 ACL 모두 삭제
	if aclIDs, exists := m.clientACLs[clientID]; exists {
		for _, aclID := range aclIDs {
			delete(m.acls, aclID)
		}
		delete(m.clientACLs, clientID)
	}
	
	delete(m.clients, clientID)
	
	return nil
}

// CreateACL은 새로운 ACL 항목을 생성
func (m *ACLManager) CreateACL(acl *ACLEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if acl.ID == "" {
		return fmt.Errorf("ACL ID is required")
	}
	
	// 클라이언트 존재 확인
	if _, exists := m.clients[acl.ClientID]; !exists {
		return fmt.Errorf("client not found: %s", acl.ClientID)
	}
	
	// Admin과 Audit을 제외하고는 그룹 필수
	if acl.Role != RoleAdmin && acl.Role != RoleAudit {
		if acl.GroupID == "" || acl.GroupID == "*" {
			return fmt.Errorf("group ID is required for %s role", acl.Role)
		}
		
		// 그룹 존재 확인
		if _, exists := m.groups[acl.GroupID]; !exists {
			return fmt.Errorf("group not found: %s", acl.GroupID)
		}
	}
	
	// 역할에 따른 권한 설정
	acl.Permissions = m.getPermissionsForRole(acl.Role)
	
	acl.CreatedAt = time.Now()
	acl.UpdatedAt = time.Now()
	
	m.acls[acl.ID] = acl
	
	// 인덱스 업데이트
	m.clientACLs[acl.ClientID] = append(m.clientACLs[acl.ClientID], acl.ID)
	if acl.GroupID != "" && acl.GroupID != "*" {
		m.groupACLs[acl.GroupID] = append(m.groupACLs[acl.GroupID], acl.ID)
	}
	
	return nil
}

// getPermissionsForRole은 역할에 따른 권한을 반환
func (m *ACLManager) getPermissionsForRole(role Role) []Permission {
	switch role {
	case RoleAdmin:
		return []Permission{
			PermissionCreate,
			PermissionRead,
			PermissionUpdate,
			PermissionDelete,
			PermissionManage,
		}
	case RoleOwner:
		return []Permission{
			PermissionCreate,
			PermissionRead,
			PermissionUpdate,
			PermissionDelete,
		}
	case RoleGuest:
		return []Permission{
			PermissionRead,
		}
	case RoleAudit:
		return []Permission{
			PermissionRead,
			PermissionAudit,
		}
	default:
		return []Permission{}
	}
}

// GetACL은 ACL 항목을 조회
func (m *ACLManager) GetACL(aclID string) (*ACLEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	acl, exists := m.acls[aclID]
	if !exists {
		return nil, fmt.Errorf("ACL not found: %s", aclID)
	}
	
	return acl, nil
}

// ListACLs는 모든 ACL을 조회
func (m *ACLManager) ListACLs() []*ACLEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	acls := make([]*ACLEntry, 0, len(m.acls))
	for _, acl := range m.acls {
		acls = append(acls, acl)
	}
	
	return acls
}

// ListACLsByClient는 클라이언트의 모든 ACL을 조회
func (m *ACLManager) ListACLsByClient(clientID string) []*ACLEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	aclIDs, exists := m.clientACLs[clientID]
	if !exists {
		return []*ACLEntry{}
	}
	
	acls := make([]*ACLEntry, 0, len(aclIDs))
	for _, aclID := range aclIDs {
		if acl, ok := m.acls[aclID]; ok {
			acls = append(acls, acl)
		}
	}
	
	return acls
}

// DeleteACL은 ACL 항목을 삭제
func (m *ACLManager) DeleteACL(aclID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	acl, exists := m.acls[aclID]
	if !exists {
		return fmt.Errorf("ACL not found: %s", aclID)
	}
	
	// 인덱스에서 제거
	m.removeFromIndex(m.clientACLs[acl.ClientID], aclID)
	if acl.GroupID != "" && acl.GroupID != "*" {
		m.removeFromIndex(m.groupACLs[acl.GroupID], aclID)
	}
	
	delete(m.acls, aclID)
	
	return nil
}

// removeFromIndex는 인덱스에서 항목을 제거
func (m *ACLManager) removeFromIndex(slice []string, item string) []string {
	for i, v := range slice {
		if v == item {
			return append(slice[:i], slice[i+1:]...)
		}
	}
	return slice
}

// CheckPermission은 클라이언트가 특정 작업을 수행할 권한이 있는지 확인
func (m *ACLManager) CheckPermission(clientID, groupID, resourceID string, permission Permission) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	// 클라이언트 존재 및 활성화 확인
	client, exists := m.clients[clientID]
	if !exists || !client.Enabled {
		return false
	}
	
	// 클라이언트의 ACL 확인
	aclIDs, exists := m.clientACLs[clientID]
	if !exists {
		return false
	}
	
	for _, aclID := range aclIDs {
		acl, ok := m.acls[aclID]
		if !ok {
			continue
		}
		
		// 만료 확인
		if acl.ExpiresAt != nil && acl.ExpiresAt.Before(time.Now()) {
			continue
		}
		
		// Admin은 모든 권한
		if acl.Role == RoleAdmin {
			return m.hasPermission(acl.Permissions, permission)
		}
		
		// Audit은 감사 관련 권한만
		if acl.Role == RoleAudit && permission == PermissionAudit {
			return true
		}
		
		// 그룹 일치 확인
		if acl.GroupID != groupID && acl.GroupID != "*" {
			continue
		}
		
		// 리소스 일치 확인
		if acl.ResourceID != "" && acl.ResourceID != "*" && acl.ResourceID != resourceID {
			continue
		}
		
		// 권한 확인
		if m.hasPermission(acl.Permissions, permission) {
			return true
		}
	}
	
	return false
}

// hasPermission은 권한 목록에 특정 권한이 있는지 확인
func (m *ACLManager) hasPermission(permissions []Permission, permission Permission) bool {
	for _, p := range permissions {
		if p == permission {
			return true
		}
	}
	return false
}
