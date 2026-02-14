// 전역 변수
let currentUser = null;
let currentRole = null;
let apiKey = null;
let clientId = null;

// API 기본 URL
const API_BASE = 'http://localhost:9090';

// 역할별 권한 매핑
const PERMISSIONS = {
    'Admin': {
        dashboard: true,
        keys: { view: true, create: true, edit: true, delete: true },
        groups: { view: true, create: true, edit: true, delete: true },
        clients: { view: true, create: true, edit: true, delete: true },
        acls: { view: true, create: true, edit: true, delete: true },
        audit: { view: true }
    },
    'Owner': {
        dashboard: true,
        keys: { view: true, create: true, edit: true, delete: true },
        groups: { view: true, create: false, edit: false, delete: false },
        clients: { view: false, create: false, edit: false, delete: false },
        acls: { view: false, create: false, edit: false, delete: false },
        audit: { view: true } // 자신의 그룹만
    },
    'Guest': {
        dashboard: true,
        keys: { view: true, create: false, edit: false, delete: false },
        groups: { view: true, create: false, edit: false, delete: false },
        clients: { view: false, create: false, edit: false, delete: false },
        acls: { view: false, create: false, edit: false, delete: false },
        audit: { view: false }
    },
    'Audit': {
        dashboard: true,
        keys: { view: false, create: false, edit: false, delete: false },
        groups: { view: false, create: false, edit: false, delete: false },
        clients: { view: false, create: false, edit: false, delete: false },
        acls: { view: false, create: false, edit: false, delete: false },
        audit: { view: true }
    }
};

// 페이지 로드 시
document.addEventListener('DOMContentLoaded', function() {
    // 로그인 폼 제출
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', handleLogin);
    }
    
    // 세션 확인
    checkSession();
});

// 로그인 처리
async function handleLogin(e) {
    e.preventDefault();
    
    const inputClientId = document.getElementById('clientId').value;
    const inputApiKey = document.getElementById('apiKey').value;
    
    try {
        // API로 권한 확인
        const response = await fetch(`${API_BASE}/api/v1/acls/my-permissions`, {
            headers: {
                'X-API-Key': inputApiKey,
                'X-Client-ID': inputClientId
            }
        });
        
        if (!response.ok) {
            throw new Error('인증 실패');
        }
        
        const data = await response.json();
        
        // 세션 저장
        clientId = inputClientId;
        apiKey = inputApiKey;
        currentUser = data.client_name || inputClientId;
        
        // 역할 결정
        if (data.summary.is_admin) {
            currentRole = 'Admin';
        } else if (data.summary.is_owner) {
            currentRole = 'Owner';
        } else if (data.summary.is_audit) {
            currentRole = 'Audit';
        } else {
            currentRole = 'Guest';
        }
        
        // 로컬 스토리지에 저장
        localStorage.setItem('clientId', clientId);
        localStorage.setItem('apiKey', apiKey);
        localStorage.setItem('currentUser', currentUser);
        localStorage.setItem('currentRole', currentRole);
        
        // 대시보드로 이동
        showDashboard();
        
    } catch (error) {
        showLoginError('로그인 실패: ' + error.message);
    }
}

// 로그인 에러 표시
function showLoginError(message) {
    const errorDiv = document.getElementById('loginError');
    errorDiv.textContent = message;
    errorDiv.classList.add('show');
    
    setTimeout(() => {
        errorDiv.classList.remove('show');
    }, 3000);
}

// 세션 확인
function checkSession() {
    const savedClientId = localStorage.getItem('clientId');
    const savedApiKey = localStorage.getItem('apiKey');
    
    if (savedClientId && savedApiKey) {
        clientId = savedClientId;
        apiKey = savedApiKey;
        currentUser = localStorage.getItem('currentUser');
        currentRole = localStorage.getItem('currentRole');
        
        showDashboard();
    }
}

// 대시보드 표시
function showDashboard() {
    document.getElementById('loginScreen').style.display = 'none';
    document.getElementById('dashboard').classList.add('active');
    
    // 사용자 정보 표시
    document.getElementById('userName').textContent = currentUser;
    const roleElement = document.getElementById('userRole');
    roleElement.textContent = currentRole.toUpperCase();
    roleElement.className = `user-role role-${currentRole.toLowerCase()}`;
    
    // 메뉴 권한 적용
    applyPermissions();
    
    // 대시보드 데이터 로드
    loadDashboard();
    
    // 사이드바 메뉴 클릭 이벤트
    setupSidebarMenu();
}

// 권한 적용
function applyPermissions() {
    const permissions = PERMISSIONS[currentRole];
    const menuItems = document.querySelectorAll('.sidebar-menu li');
    
    menuItems.forEach(item => {
        const section = item.dataset.section;
        
        // 대시보드는 항상 접근 가능
        if (section === 'overview') return;
        
        // 섹션별 권한 확인
        let hasAccess = false;
        
        switch(section) {
            case 'keys':
                hasAccess = permissions.keys.view;
                break;
            case 'groups':
                hasAccess = permissions.groups.view;
                break;
            case 'clients':
                hasAccess = permissions.clients.view;
                break;
            case 'acls':
                hasAccess = permissions.acls.view;
                break;
            case 'audit':
                hasAccess = permissions.audit.view;
                break;
        }
        
        if (!hasAccess) {
            item.classList.add('disabled');
            item.onclick = (e) => {
                e.preventDefault();
                showAlert('접근 권한이 없습니다.', 'error');
            };
        }
    });
}

// 사이드바 메뉴 설정
function setupSidebarMenu() {
    const menuItems = document.querySelectorAll('.sidebar-menu li:not(.disabled)');
    
    menuItems.forEach(item => {
        item.addEventListener('click', function() {
            // 활성 메뉴 변경
            menuItems.forEach(i => i.classList.remove('active'));
            this.classList.add('active');
            
            // 섹션 변경
            const section = this.dataset.section;
            showSection(section);
        });
    });
}

// 섹션 표시
function showSection(section) {
    // 모든 섹션 숨기기
    document.querySelectorAll('.content-section').forEach(s => {
        s.style.display = 'none';
    });
    
    // 선택된 섹션 표시
    const sectionElement = document.getElementById(`section-${section}`);
    if (sectionElement) {
        sectionElement.style.display = 'block';
        
        // 섹션별 데이터 로드
        switch(section) {
            case 'overview':
                loadDashboard();
                break;
            case 'keys':
                loadKeys();
                break;
            case 'groups':
                loadGroups();
                break;
            case 'clients':
                loadClients();
                break;
            case 'acls':
                loadACLs();
                break;
            case 'audit':
                loadAuditLogs();
                break;
        }
    }
}

// 대시보드 로드
async function loadDashboard() {
    try {
        // 통계 데이터 로드
        const [keysData, groupsData, clientsData, permissionsData] = await Promise.all([
            apiRequest('/api/v1/keys'),
            currentRole === 'Admin' ? apiRequest('/api/v1/groups') : Promise.resolve({ total: '-' }),
            currentRole === 'Admin' ? apiRequest('/api/v1/clients') : Promise.resolve({ total: '-' }),
            apiRequest('/api/v1/acls/my-permissions')
        ]);
        
        // 통계 업데이트
        document.getElementById('totalKeys').textContent = keysData.total || keysData.keys?.length || 0;
        document.getElementById('totalGroups').textContent = groupsData.total || '-';
        document.getElementById('totalClients').textContent = clientsData.total || '-';
        document.getElementById('myPermissions').textContent = permissionsData.total_permissions || 0;
        
    } catch (error) {
        console.error('대시보드 로드 실패:', error);
    }
}

// 암호키 로드
async function loadKeys() {
    try {
        const data = await apiRequest('/api/v1/keys');
        const tbody = document.getElementById('keysTableBody');
        
        if (!data.keys || data.keys.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="6" class="empty-state">
                        <div class="empty-state-icon">🔑</div>
                        <div>등록된 암호키가 없습니다.</div>
                    </td>
                </tr>
            `;
            return;
        }
        
        tbody.innerHTML = data.keys.map(key => `
            <tr>
                <td>${escapeHtml(key.key_id || key.id)}</td>
                <td>${escapeHtml(key.algorithm)}</td>
                <td>${key.length} bits</td>
                <td><span class="badge badge-success">${escapeHtml(key.state || 'active')}</span></td>
                <td>${formatDate(key.created_at)}</td>
                <td>
                    <div class="action-buttons">
                        ${hasPermission('keys', 'view') ? `<button class="btn-sm btn-view" onclick="viewKey('${key.key_id || key.id}')">조회</button>` : ''}
                        ${hasPermission('keys', 'edit') ? `<button class="btn-sm btn-edit" onclick="editKey('${key.key_id || key.id}')">수정</button>` : ''}
                        ${hasPermission('keys', 'delete') ? `<button class="btn-sm btn-delete" onclick="deleteKey('${key.key_id || key.id}')">삭제</button>` : ''}
                    </div>
                </td>
            </tr>
        `).join('');
        
    } catch (error) {
        console.error('암호키 로드 실패:', error);
        showAlert('암호키 로드 실패: ' + error.message, 'error');
    }
}

// 그룹 로드
async function loadGroups() {
    try {
        const data = await apiRequest('/api/v1/groups');
        const tbody = document.getElementById('groupsTableBody');
        
        if (!data.groups || data.groups.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="5" class="empty-state">
                        <div class="empty-state-icon">👥</div>
                        <div>등록된 그룹이 없습니다.</div>
                    </td>
                </tr>
            `;
            return;
        }
        
        tbody.innerHTML = data.groups.map(group => `
            <tr>
                <td>${escapeHtml(group.id)}</td>
                <td>${escapeHtml(group.name)}</td>
                <td>${escapeHtml(group.description || '-')}</td>
                <td>${formatDate(group.created_at)}</td>
                <td>
                    <div class="action-buttons">
                        ${hasPermission('groups', 'edit') ? `<button class="btn-sm btn-edit" onclick="editGroup('${group.id}')">수정</button>` : ''}
                        ${hasPermission('groups', 'delete') ? `<button class="btn-sm btn-delete" onclick="deleteGroup('${group.id}')">삭제</button>` : ''}
                    </div>
                </td>
            </tr>
        `).join('');
        
    } catch (error) {
        console.error('그룹 로드 실패:', error);
        showAlert('그룹 로드 실패: ' + error.message, 'error');
    }
}

// 클라이언트 로드
async function loadClients() {
    try {
        const data = await apiRequest('/api/v1/clients');
        const tbody = document.getElementById('clientsTableBody');
        
        if (!data.clients || data.clients.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="6" class="empty-state">
                        <div class="empty-state-icon">💻</div>
                        <div>등록된 클라이언트가 없습니다.</div>
                    </td>
                </tr>
            `;
            return;
        }
        
        tbody.innerHTML = data.clients.map(client => `
            <tr>
                <td>${escapeHtml(client.id)}</td>
                <td>${escapeHtml(client.name)}</td>
                <td><span class="badge ${client.enabled ? 'badge-success' : 'badge-danger'}">${client.enabled ? '활성' : '비활성'}</span></td>
                <td>${client.groups ? client.groups.join(', ') : '-'}</td>
                <td>${formatDate(client.created_at)}</td>
                <td>
                    <div class="action-buttons">
                        ${hasPermission('clients', 'edit') ? `<button class="btn-sm btn-edit" onclick="editClient('${client.id}')">수정</button>` : ''}
                        ${hasPermission('clients', 'delete') ? `<button class="btn-sm btn-delete" onclick="deleteClient('${client.id}')">삭제</button>` : ''}
                    </div>
                </td>
            </tr>
        `).join('');
        
    } catch (error) {
        console.error('클라이언트 로드 실패:', error);
        showAlert('클라이언트 로드 실패: ' + error.message, 'error');
    }
}

// ACL 로드
async function loadACLs() {
    try {
        const data = await apiRequest('/api/v1/acls');
        const tbody = document.getElementById('aclsTableBody');
        
        if (!data.acls || data.acls.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="6" class="empty-state">
                        <div class="empty-state-icon">🔒</div>
                        <div>등록된 ACL이 없습니다.</div>
                    </td>
                </tr>
            `;
            return;
        }
        
        tbody.innerHTML = data.acls.map(acl => `
            <tr>
                <td>${escapeHtml(acl.id)}</td>
                <td>${escapeHtml(acl.client_id)}</td>
                <td>${escapeHtml(acl.group_id || '*')}</td>
                <td><span class="badge badge-info">${escapeHtml(acl.role)}</span></td>
                <td>${formatDate(acl.created_at)}</td>
                <td>
                    <div class="action-buttons">
                        ${hasPermission('acls', 'delete') ? `<button class="btn-sm btn-delete" onclick="deleteACL('${acl.id}')">삭제</button>` : ''}
                    </div>
                </td>
            </tr>
        `).join('');
        
    } catch (error) {
        console.error('ACL 로드 실패:', error);
        showAlert('ACL 로드 실패: ' + error.message, 'error');
    }
}

// 감사 로그 로드
async function loadAuditLogs() {
    try {
        let url = '/api/v1/audit/logs';
        
        // Owner인 경우 그룹 ID 필요
        if (currentRole === 'Owner') {
            const perms = await apiRequest('/api/v1/acls/my-permissions');
            if (perms.summary.owner_groups && perms.summary.owner_groups.length > 0) {
                url += `?group_id=${perms.summary.owner_groups[0]}`;
            }
        }
        
        const data = await apiRequest(url);
        const tbody = document.getElementById('auditTableBody');
        
        if (!data.logs || data.logs.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="6" class="empty-state">
                        <div class="empty-state-icon">📝</div>
                        <div>감사 로그가 없습니다.</div>
                    </td>
                </tr>
            `;
            return;
        }
        
        tbody.innerHTML = data.logs.map(log => `
            <tr>
                <td>${formatDateTime(log.timestamp)}</td>
                <td>${escapeHtml(log.client_id)}</td>
                <td>${escapeHtml(log.action)}</td>
                <td>${escapeHtml(log.resource)}</td>
                <td><span class="badge ${log.result === 'success' ? 'badge-success' : 'badge-danger'}">${escapeHtml(log.result)}</span></td>
                <td>${escapeHtml(log.ip_address)}</td>
            </tr>
        `).join('');
        
    } catch (error) {
        console.error('감사 로그 로드 실패:', error);
        showAlert('감사 로그 로드 실패: ' + error.message, 'error');
    }
}

// API 요청 헬퍼
async function apiRequest(url, options = {}) {
    const headers = {
        'Content-Type': 'application/json',
        'X-API-Key': apiKey,
        'X-Client-ID': clientId,
        ...options.headers
    };
    
    const response = await fetch(API_BASE + url, {
        ...options,
        headers
    });
    
    if (!response.ok) {
        const error = await response.json().catch(() => ({}));
        throw new Error(error.message || `HTTP ${response.status}`);
    }
    
    return response.json();
}

// 권한 확인
function hasPermission(resource, action) {
    const permissions = PERMISSIONS[currentRole];
    return permissions[resource] && permissions[resource][action];
}

// 알림 표시
function showAlert(message, type = 'success') {
    const container = document.getElementById('alertContainer');
    const alert = document.createElement('div');
    alert.className = `alert alert-${type} show`;
    alert.textContent = message;
    
    container.appendChild(alert);
    
    setTimeout(() => {
        alert.classList.remove('show');
        setTimeout(() => alert.remove(), 300);
    }, 3000);
}

// 로그아웃
function logout() {
    localStorage.clear();
    location.reload();
}

// 유틸리티 함수
function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return String(text).replace(/[&<>"']/g, m => map[m]);
}

function formatDate(dateString) {
    if (!dateString) return '-';
    const date = new Date(dateString);
    return date.toLocaleDateString('ko-KR');
}

function formatDateTime(dateString) {
    if (!dateString) return '-';
    const date = new Date(dateString);
    return date.toLocaleString('ko-KR');
}

function searchTable(tableId, searchText) {
    const table = document.getElementById(tableId);
    const rows = table.getElementsByTagName('tr');
    
    for (let i = 1; i < rows.length; i++) {
        const row = rows[i];
        const text = row.textContent || row.innerText;
        
        if (text.toLowerCase().indexOf(searchText.toLowerCase()) > -1) {
            row.style.display = '';
        } else {
            row.style.display = 'none';
        }
    }
}

// 모달 함수들 (다음 파일에서 구현)
function showCreateKeyModal() {
    if (!hasPermission('keys', 'create')) {
        showAlert('생성 권한이 없습니다.', 'error');
        return;
    }
    // 모달 표시 로직
    showAlert('암호키 생성 모달 (구현 예정)', 'info');
}

function showCreateGroupModal() {
    if (!hasPermission('groups', 'create')) {
        showAlert('생성 권한이 없습니다.', 'error');
        return;
    }
    showAlert('그룹 생성 모달 (구현 예정)', 'info');
}

function showCreateClientModal() {
    if (!hasPermission('clients', 'create')) {
        showAlert('생성 권한이 없습니다.', 'error');
        return;
    }
    showAlert('클라이언트 생성 모달 (구현 예정)', 'info');
}

function showCreateACLModal() {
    if (!hasPermission('acls', 'create')) {
        showAlert('생성 권한이 없습니다.', 'error');
        return;
    }
    showAlert('ACL 생성 모달 (구현 예정)', 'info');
}

function viewKey(keyId) {
    showAlert(`키 조회: ${keyId} (구현 예정)`, 'info');
}

function editKey(keyId) {
    if (!hasPermission('keys', 'edit')) {
        showAlert('수정 권한이 없습니다.', 'error');
        return;
    }
    showAlert(`키 수정: ${keyId} (구현 예정)`, 'info');
}

async function deleteKey(keyId) {
    if (!hasPermission('keys', 'delete')) {
        showAlert('삭제 권한이 없습니다.', 'error');
        return;
    }
    
    if (!confirm('정말 삭제하시겠습니까?')) return;
    
    try {
        await apiRequest(`/api/v1/keys/${keyId}`, { method: 'DELETE' });
        showAlert('암호키가 삭제되었습니다.', 'success');
        loadKeys();
    } catch (error) {
        showAlert('삭제 실패: ' + error.message, 'error');
    }
}

function editGroup(groupId) {
    showAlert(`그룹 수정: ${groupId} (구현 예정)`, 'info');
}

async function deleteGroup(groupId) {
    if (!hasPermission('groups', 'delete')) {
        showAlert('삭제 권한이 없습니다.', 'error');
        return;
    }
    
    if (!confirm('정말 삭제하시겠습니까?')) return;
    
    try {
        await apiRequest(`/api/v1/groups/${groupId}`, { method: 'DELETE' });
        showAlert('그룹이 삭제되었습니다.', 'success');
        loadGroups();
    } catch (error) {
        showAlert('삭제 실패: ' + error.message, 'error');
    }
}

function editClient(clientId) {
    showAlert(`클라이언트 수정: ${clientId} (구현 예정)`, 'info');
}

async function deleteClient(clientId) {
    if (!hasPermission('clients', 'delete')) {
        showAlert('삭제 권한이 없습니다.', 'error');
        return;
    }
    
    if (!confirm('정말 삭제하시겠습니까?')) return;
    
    try {
        await apiRequest(`/api/v1/clients/${clientId}`, { method: 'DELETE' });
        showAlert('클라이언트가 삭제되었습니다.', 'success');
        loadClients();
    } catch (error) {
        showAlert('삭제 실패: ' + error.message, 'error');
    }
}

async function deleteACL(aclId) {
    if (!hasPermission('acls', 'delete')) {
        showAlert('삭제 권한이 없습니다.', 'error');
        return;
    }
    
    if (!confirm('정말 삭제하시겠습니까?')) return;
    
    try {
        await apiRequest(`/api/v1/acls/${aclId}`, { method: 'DELETE' });
        showAlert('ACL이 삭제되었습니다.', 'success');
        loadACLs();
    } catch (error) {
        showAlert('삭제 실패: ' + error.message, 'error');
    }
}
