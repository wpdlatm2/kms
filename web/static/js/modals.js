// 모달 관리
function showModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.classList.add('active');
    }
}

function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.classList.remove('active');
    }
}

// 암호키 생성 모달
function showCreateKeyModal() {
    if (!hasPermission('keys', 'create')) {
        showAlert('생성 권한이 없습니다.', 'error');
        return;
    }
    
    const modalHTML = `
        <div id="createKeyModal" class="modal active">
            <div class="modal-content">
                <div class="modal-header">
                    <h3 class="modal-title">새 암호키 생성</h3>
                    <button class="btn-close" onclick="closeModal('createKeyModal')">&times;</button>
                </div>
                <div class="modal-body">
                    <form id="createKeyForm">
                        <div class="form-group">
                            <label>알고리즘 *</label>
                            <select id="keyAlgorithm" required>
                                <option value="">선택하세요</option>
                                <option value="AES">AES</option>
                                <option value="RSA">RSA</option>
                                <option value="3DES">3DES</option>
                                <option value="SEED">SEED</option>
                                <option value="ARIA">ARIA</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label>키 길이 (bits) *</label>
                            <select id="keyLength" required>
                                <option value="">선택하세요</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label>그룹 ID *</label>
                            <select id="keyGroup" required>
                                <option value="">선택하세요</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label>설명</label>
                            <input type="text" id="keyDescription" placeholder="선택사항">
                        </div>
                    </form>
                </div>
                <div class="modal-footer">
                    <button class="btn-secondary" onclick="closeModal('createKeyModal')">취소</button>
                    <button class="btn-primary" onclick="createKey()">생성</button>
                </div>
            </div>
        </div>
    `;
    
    document.getElementById('modalContainer').innerHTML = modalHTML;
    
    // 알고리즘 선택 시 키 길이 옵션 변경
    document.getElementById('keyAlgorithm').addEventListener('change', function() {
        updateKeyLengthOptions(this.value);
    });
    
    // 그룹 목록 로드
    loadGroupsForSelect();
}

// 알고리즘별 키 길이 옵션
function updateKeyLengthOptions(algorithm) {
    const lengthSelect = document.getElementById('keyLength');
    const lengths = {
        'AES': [128, 192, 256],
        'RSA': [1024, 2048, 3072, 4096],
        '3DES': [112, 168, 192],
        'SEED': [128],
        'ARIA': [128, 192, 256]
    };
    
    lengthSelect.innerHTML = '<option value="">선택하세요</option>';
    
    if (lengths[algorithm]) {
        lengths[algorithm].forEach(len => {
            const option = document.createElement('option');
            option.value = len;
            option.textContent = len + ' bits';
            lengthSelect.appendChild(option);
        });
    }
}

// 셀렉트박스용 그룹 로드
async function loadGroupsForSelect() {
    try {
        const data = await apiRequest('/api/v1/groups');
        const select = document.getElementById('keyGroup');
        
        if (data.groups) {
            data.groups.forEach(group => {
                const option = document.createElement('option');
                option.value = group.id;
                option.textContent = group.name;
                select.appendChild(option);
            });
        }
    } catch (error) {
        console.error('그룹 로드 실패:', error);
    }
}

// 암호키 생성 실행
async function createKey() {
    const algorithm = document.getElementById('keyAlgorithm').value;
    const length = parseInt(document.getElementById('keyLength').value);
    const groupId = document.getElementById('keyGroup').value;
    const description = document.getElementById('keyDescription').value;
    
    if (!algorithm || !length || !groupId) {
        showAlert('필수 항목을 모두 입력하세요.', 'error');
        return;
    }
    
    try {
        const body = {
            algorithm: algorithm,
            length: length,
            attributes: {
                description: description || '',
                group_id: groupId
            }
        };
        
        await apiRequest('/api/v1/keys', {
            method: 'POST',
            body: JSON.stringify(body),
            headers: {
                'X-Group-ID': groupId
            }
        });
        
        showAlert('암호키가 생성되었습니다.', 'success');
        closeModal('createKeyModal');
        loadKeys();
        loadDashboard();
        
    } catch (error) {
        showAlert('생성 실패: ' + error.message, 'error');
    }
}

// 그룹 생성 모달
function showCreateGroupModal() {
    if (!hasPermission('groups', 'create')) {
        showAlert('생성 권한이 없습니다.', 'error');
        return;
    }
    
    const modalHTML = `
        <div id="createGroupModal" class="modal active">
            <div class="modal-content">
                <div class="modal-header">
                    <h3 class="modal-title">새 그룹 생성</h3>
                    <button class="btn-close" onclick="closeModal('createGroupModal')">&times;</button>
                </div>
                <div class="modal-body">
                    <form id="createGroupForm">
                        <div class="form-group">
                            <label>그룹 ID *</label>
                            <input type="text" id="groupId" placeholder="group-prod" required>
                        </div>
                        <div class="form-group">
                            <label>그룹명 *</label>
                            <input type="text" id="groupName" placeholder="Production Team" required>
                        </div>
                        <div class="form-group">
                            <label>설명</label>
                            <input type="text" id="groupDescription" placeholder="선택사항">
                        </div>
                    </form>
                </div>
                <div class="modal-footer">
                    <button class="btn-secondary" onclick="closeModal('createGroupModal')">취소</button>
                    <button class="btn-primary" onclick="createGroup()">생성</button>
                </div>
            </div>
        </div>
    `;
    
    document.getElementById('modalContainer').innerHTML = modalHTML;
}

// 그룹 생성 실행
async function createGroup() {
    const id = document.getElementById('groupId').value;
    const name = document.getElementById('groupName').value;
    const description = document.getElementById('groupDescription').value;
    
    if (!id || !name) {
        showAlert('필수 항목을 모두 입력하세요.', 'error');
        return;
    }
    
    try {
        const body = {
            id: id,
            name: name,
            description: description
        };
        
        await apiRequest('/api/v1/groups', {
            method: 'POST',
            body: JSON.stringify(body)
        });
        
        showAlert('그룹이 생성되었습니다.', 'success');
        closeModal('createGroupModal');
        loadGroups();
        loadDashboard();
        
    } catch (error) {
        showAlert('생성 실패: ' + error.message, 'error');
    }
}

// 클라이언트 생성 모달
function showCreateClientModal() {
    if (!hasPermission('clients', 'create')) {
        showAlert('생성 권한이 없습니다.', 'error');
        return;
    }
    
    const modalHTML = `
        <div id="createClientModal" class="modal active">
            <div class="modal-content">
                <div class="modal-header">
                    <h3 class="modal-title">새 클라이언트 생성</h3>
                    <button class="btn-close" onclick="closeModal('createClientModal')">&times;</button>
                </div>
                <div class="modal-body">
                    <form id="createClientForm">
                        <div class="form-group">
                            <label>클라이언트 ID *</label>
                            <input type="text" id="clientIdInput" placeholder="client-web-app" required>
                        </div>
                        <div class="form-group">
                            <label>클라이언트명 *</label>
                            <input type="text" id="clientName" placeholder="Web Application" required>
                        </div>
                        <div class="form-group">
                            <label>설명</label>
                            <input type="text" id="clientDescription" placeholder="선택사항">
                        </div>
                        <div class="form-group">
                            <label>그룹 (복수 선택 가능)</label>
                            <div id="clientGroupsContainer" style="max-height: 150px; overflow-y: auto; border: 1px solid #ddd; padding: 10px; border-radius: 5px;">
                                <div class="loading"><div class="spinner"></div></div>
                            </div>
                        </div>
                    </form>
                </div>
                <div class="modal-footer">
                    <button class="btn-secondary" onclick="closeModal('createClientModal')">취소</button>
                    <button class="btn-primary" onclick="createClient()">생성</button>
                </div>
            </div>
        </div>
    `;
    
    document.getElementById('modalContainer').innerHTML = modalHTML;
    loadGroupsForClientSelect();
}

// 클라이언트용 그룹 체크박스 로드
async function loadGroupsForClientSelect() {
    try {
        const data = await apiRequest('/api/v1/groups');
        const container = document.getElementById('clientGroupsContainer');
        
        if (!data.groups || data.groups.length === 0) {
            container.innerHTML = '<div style="color: #999;">등록된 그룹이 없습니다.</div>';
            return;
        }
        
        container.innerHTML = data.groups.map(group => `
            <label style="display: block; margin-bottom: 8px; cursor: pointer;">
                <input type="checkbox" name="clientGroups" value="${group.id}" style="margin-right: 8px;">
                ${escapeHtml(group.name)} (${escapeHtml(group.id)})
            </label>
        `).join('');
        
    } catch (error) {
        console.error('그룹 로드 실패:', error);
    }
}

// 클라이언트 생성 실행
async function createClient() {
    const id = document.getElementById('clientIdInput').value;
    const name = document.getElementById('clientName').value;
    const description = document.getElementById('clientDescription').value;
    
    // 선택된 그룹
    const selectedGroups = Array.from(document.querySelectorAll('input[name="clientGroups"]:checked'))
        .map(cb => cb.value);
    
    if (!id || !name) {
        showAlert('필수 항목을 모두 입력하세요.', 'error');
        return;
    }
    
    try {
        const body = {
            id: id,
            name: name,
            description: description,
            groups: selectedGroups
        };
        
        const result = await apiRequest('/api/v1/clients', {
            method: 'POST',
            body: JSON.stringify(body)
        });
        
        // API 키 표시
        if (result.api_key) {
            showAPIKeyModal(result.api_key);
        }
        
        showAlert('클라이언트가 생성되었습니다.', 'success');
        closeModal('createClientModal');
        loadClients();
        loadDashboard();
        
    } catch (error) {
        showAlert('생성 실패: ' + error.message, 'error');
    }
}

// API 키 표시 모달
function showAPIKeyModal(apiKey) {
    const modalHTML = `
        <div id="apiKeyModal" class="modal active">
            <div class="modal-content">
                <div class="modal-header">
                    <h3 class="modal-title">⚠️ API 키 저장</h3>
                </div>
                <div class="modal-body">
                    <div style="background: #fff3cd; padding: 15px; border-radius: 5px; margin-bottom: 15px;">
                        <strong>중요:</strong> 이 API 키는 다시 표시되지 않습니다. 안전한 곳에 저장하세요!
                    </div>
                    <div class="form-group">
                        <label>API Key</label>
                        <input type="text" value="${apiKey}" readonly 
                               style="font-family: monospace; background: #f8f9fa;"
                               onclick="this.select()">
                    </div>
                </div>
                <div class="modal-footer">
                    <button class="btn-primary" onclick="copyAPIKey('${apiKey}'); closeModal('apiKeyModal');">
                        복사 후 닫기
                    </button>
                </div>
            </div>
        </div>
    `;
    
    document.getElementById('modalContainer').innerHTML += modalHTML;
}

// API 키 복사
function copyAPIKey(apiKey) {
    navigator.clipboard.writeText(apiKey).then(() => {
        showAlert('API 키가 클립보드에 복사되었습니다.', 'success');
    }).catch(() => {
        showAlert('복사 실패. 수동으로 복사하세요.', 'error');
    });
}

// ACL 생성 모달
function showCreateACLModal() {
    if (!hasPermission('acls', 'create')) {
        showAlert('생성 권한이 없습니다.', 'error');
        return;
    }
    
    const modalHTML = `
        <div id="createACLModal" class="modal active">
            <div class="modal-content">
                <div class="modal-header">
                    <h3 class="modal-title">새 ACL 생성</h3>
                    <button class="btn-close" onclick="closeModal('createACLModal')">&times;</button>
                </div>
                <div class="modal-body">
                    <form id="createACLForm">
                        <div class="form-group">
                            <label>ACL ID *</label>
                            <input type="text" id="aclId" placeholder="acl-001" required>
                        </div>
                        <div class="form-group">
                            <label>클라이언트 *</label>
                            <select id="aclClient" required>
                                <option value="">선택하세요</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label>역할 *</label>
                            <select id="aclRole" required>
                                <option value="">선택하세요</option>
                                <option value="Admin">Admin (전체 관리)</option>
                                <option value="Owner">Owner (그룹 CRUD)</option>
                                <option value="Guest">Guest (읽기 전용)</option>
                                <option value="Audit">Audit (감사 로그)</option>
                            </select>
                        </div>
                        <div class="form-group" id="aclGroupField">
                            <label>그룹 *</label>
                            <select id="aclGroup">
                                <option value="">선택하세요</option>
                            </select>
                            <small style="color: #999;">Admin과 Audit은 그룹 불필요</small>
                        </div>
                        <div class="form-group">
                            <label>만료일 (선택)</label>
                            <input type="datetime-local" id="aclExpires">
                        </div>
                    </form>
                </div>
                <div class="modal-footer">
                    <button class="btn-secondary" onclick="closeModal('createACLModal')">취소</button>
                    <button class="btn-primary" onclick="createACL()">생성</button>
                </div>
            </div>
        </div>
    `;
    
    document.getElementById('modalContainer').innerHTML = modalHTML;
    
    // 역할 선택 시 그룹 필드 표시/숨김
    document.getElementById('aclRole').addEventListener('change', function() {
        const groupField = document.getElementById('aclGroupField');
        if (this.value === 'Admin' || this.value === 'Audit') {
            groupField.style.display = 'none';
        } else {
            groupField.style.display = 'block';
        }
    });
    
    // 클라이언트 및 그룹 목록 로드
    loadClientsForACL();
    loadGroupsForACL();
}

// ACL용 클라이언트 로드
async function loadClientsForACL() {
    try {
        const data = await apiRequest('/api/v1/clients');
        const select = document.getElementById('aclClient');
        
        if (data.clients) {
            data.clients.forEach(client => {
                const option = document.createElement('option');
                option.value = client.id;
                option.textContent = client.name + ' (' + client.id + ')';
                select.appendChild(option);
            });
        }
    } catch (error) {
        console.error('클라이언트 로드 실패:', error);
    }
}

// ACL용 그룹 로드
async function loadGroupsForACL() {
    try {
        const data = await apiRequest('/api/v1/groups');
        const select = document.getElementById('aclGroup');
        
        if (data.groups) {
            data.groups.forEach(group => {
                const option = document.createElement('option');
                option.value = group.id;
                option.textContent = group.name + ' (' + group.id + ')';
                select.appendChild(option);
            });
        }
    } catch (error) {
        console.error('그룹 로드 실패:', error);
    }
}

// ACL 생성 실행
async function createACL() {
    const id = document.getElementById('aclId').value;
    const clientId = document.getElementById('aclClient').value;
    const role = document.getElementById('aclRole').value;
    const groupId = document.getElementById('aclGroup').value;
    const expiresAt = document.getElementById('aclExpires').value;
    
    if (!id || !clientId || !role) {
        showAlert('필수 항목을 모두 입력하세요.', 'error');
        return;
    }
    
    // Owner와 Guest는 그룹 필수
    if ((role === 'Owner' || role === 'Guest') && !groupId) {
        showAlert('Owner와 Guest는 그룹을 선택해야 합니다.', 'error');
        return;
    }
    
    try {
        const body = {
            id: id,
            client_id: clientId,
            group_id: groupId || '',
            role: role
        };
        
        if (expiresAt) {
            body.expires_at = new Date(expiresAt).toISOString();
        }
        
        await apiRequest('/api/v1/acls', {
            method: 'POST',
            body: JSON.stringify(body)
        });
        
        showAlert('ACL이 생성되었습니다.', 'success');
        closeModal('createACLModal');
        loadACLs();
        
    } catch (error) {
        showAlert('생성 실패: ' + error.message, 'error');
    }
}
