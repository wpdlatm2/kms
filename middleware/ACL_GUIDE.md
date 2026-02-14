# 🔐 KMIP ACL 및 권한 관리 가이드

## 개요

**그룹 기반 역할 및 ACL(Access Control List)** 시스템으로 세밀한 권한 관리를 제공합니다.

### 핵심 개념

```
클라이언트 (Client/API Key)
    ↓ 소속
그룹 (Group)
    ↓ 포함
암호키 (Cryptographic Keys)

권한 (Permissions)
    ↓ 정의
ACL (Access Control List)
    ↓ 제어
접근 (Access)
```

## 🎭 역할 (Roles)

### Admin (관리자)

```
권한: 모든 키와 클라이언트 관리
범위: 전체 시스템
그룹: 불필요 (모든 그룹에 접근)
작업: CREATE, READ, UPDATE, DELETE, MANAGE
```

**사용 예:**
- 시스템 관리자
- DevOps 팀
- 보안 관리자

### Owner (소유자)

```
권한: 해당 그룹의 키에 대한 CRUD + 해당 그룹의 감사로그 조회
범위: 특정 그룹
그룹: 필수
작업: CREATE, READ, UPDATE, DELETE (+ 해당 그룹 감사로그)
```

**사용 예:**
- 팀 리더
- 프로젝트 소유자
- 애플리케이션 관리자

**추가 권한:**
- ✅ 해당 그룹의 감사 로그 조회
- ✅ 자신의 권한 목록 조회

### Guest (게스트)

```
권한: 해당 그룹의 키에 대한 읽기만
범위: 특정 그룹
그룹: 필수
작업: READ
```

**사용 예:**
- 읽기 전용 사용자
- 모니터링 시스템
- 보고서 생성기

**추가 권한:**
- ✅ 자신의 권한 목록 조회

### Audit (감사)

```
권한: 감사 로그 및 리포트 조회
범위: 전체 시스템
그룹: 불필요
작업: READ, AUDIT
```

**사용 예:**
- 보안 감사자
- 컴플라이언스 팀
- 내부 감사

## 📊 권한 매트릭스

| 역할 | 그룹 | 키 생성 | 키 조회 | 키 수정 | 키 삭제 | 그룹 관리 | 클라이언트 관리 | ACL 관리 | 감사 로그 | 자기 권한 조회 |
|------|------|---------|---------|---------|---------|-----------|-----------------|----------|-----------|----------------|
| **Admin** | - | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ (전체) | ✅ |
| **Owner** | 필수 | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ✅ (해당 그룹) | ✅ |
| **Guest** | 필수 | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| **Audit** | - | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ (전체) | ✅ |

## 🏗️ 구조

### Group (그룹)

```json
{
  "id": "group-prod",
  "name": "Production Team",
  "description": "Production environment keys",
  "created_at": "2024-02-13T10:00:00Z",
  "updated_at": "2024-02-13T10:00:00Z",
  "metadata": {
    "department": "Engineering",
    "environment": "production"
  }
}
```

### Client (클라이언트)

```json
{
  "id": "client-web-app",
  "name": "Web Application",
  "api_key": "api_client-web-app_1707818400",
  "description": "Main web application",
  "groups": ["group-prod", "group-staging"],
  "enabled": true,
  "created_at": "2024-02-13T10:00:00Z",
  "metadata": {
    "application": "web-frontend",
    "owner": "john.doe@example.com"
  }
}
```

### ACL Entry (ACL 항목)

```json
{
  "id": "acl-001",
  "client_id": "client-web-app",
  "group_id": "group-prod",
  "role": "Owner",
  "permissions": ["CREATE", "READ", "UPDATE", "DELETE"],
  "resource_id": "*",
  "created_at": "2024-02-13T10:00:00Z",
  "expires_at": "2025-02-13T10:00:00Z"
}
```

## 🚀 빠른 시작

### 1단계: 그룹 생성

```bash
# Production 그룹 생성
curl -X POST http://localhost:9090/api/v1/groups \
  -H "X-Client-ID: admin" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "group-prod",
    "name": "Production Team",
    "description": "Production environment keys"
  }'
```

### 2단계: 클라이언트 생성

```bash
# 웹 애플리케이션 클라이언트 생성
curl -X POST http://localhost:9090/api/v1/clients \
  -H "X-Client-ID: admin" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "client-web-app",
    "name": "Web Application",
    "description": "Main web application",
    "groups": ["group-prod"]
  }'

# 응답에서 API 키 저장!
# {
#   "id": "client-web-app",
#   "api_key": "api_client-web-app_1707818400",
#   "message": "Client created successfully. Save the API key - it won't be shown again."
# }
```

### 3단계: ACL 부여

```bash
# Owner 권한 부여
curl -X POST http://localhost:9090/api/v1/acls \
  -H "X-Client-ID: admin" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "acl-web-app-owner",
    "client_id": "client-web-app",
    "group_id": "group-prod",
    "role": "Owner",
    "resource_id": "*"
  }'
```

### 4단계: 권한 테스트

```bash
# 클라이언트로 키 생성 (성공)
curl -X POST http://localhost:9090/api/v1/keys \
  -H "X-API-Key: api_client-web-app_1707818400" \
  -H "X-Group-ID: group-prod" \
  -H "Content-Type: application/json" \
  -d '{
    "algorithm": "AES",
    "length": 256
  }'

# 다른 그룹의 키 생성 시도 (실패 - 권한 없음)
curl -X POST http://localhost:9090/api/v1/keys \
  -H "X-API-Key: api_client-web-app_1707818400" \
  -H "X-Group-ID: group-dev" \
  -H "Content-Type: application/json" \
  -d '{
    "algorithm": "AES",
    "length": 256
  }'
# 응답: 403 Permission denied
```

## 📋 API 엔드포인트

### 그룹 관리

#### 그룹 생성

```http
POST /api/v1/groups
X-Client-ID: admin

{
  "id": "group-dev",
  "name": "Development Team",
  "description": "Development environment"
}
```

#### 그룹 목록

```http
GET /api/v1/groups
X-Client-ID: admin
```

#### 그룹 조회

```http
GET /api/v1/groups/{group_id}
X-Client-ID: admin
```

#### 그룹 수정

```http
PUT /api/v1/groups/{group_id}
X-Client-ID: admin

{
  "name": "Development Team (Updated)",
  "description": "Updated description"
}
```

#### 그룹 삭제

```http
DELETE /api/v1/groups/{group_id}
X-Client-ID: admin
```

### 클라이언트 관리

#### 클라이언트 생성

```http
POST /api/v1/clients
X-Client-ID: admin

{
  "id": "client-mobile-app",
  "name": "Mobile Application",
  "description": "iOS and Android app",
  "groups": ["group-prod", "group-staging"]
}
```

**응답:**
```json
{
  "id": "client-mobile-app",
  "api_key": "api_client-mobile-app_1707818500",
  "message": "Client created successfully. Save the API key - it won't be shown again."
}
```

#### 클라이언트 목록

```http
GET /api/v1/clients
X-Client-ID: admin
```

#### 클라이언트 조회

```http
GET /api/v1/clients/{client_id}
X-Client-ID: admin
```

#### 클라이언트 수정

```http
PUT /api/v1/clients/{client_id}
X-Client-ID: admin

{
  "name": "Mobile App (Updated)",
  "enabled": true,
  "groups": ["group-prod"]
}
```

#### 클라이언트 비활성화

```http
PUT /api/v1/clients/{client_id}
X-Client-ID: admin

{
  "enabled": false
}
```

#### 클라이언트 삭제

```http
DELETE /api/v1/clients/{client_id}
X-Client-ID: admin
```

### ACL 관리

#### ACL 생성

```http
POST /api/v1/acls
X-Client-ID: admin

{
  "id": "acl-002",
  "client_id": "client-mobile-app",
  "group_id": "group-prod",
  "role": "Guest",
  "resource_id": "*",
  "expires_at": "2025-12-31T23:59:59Z"
}
```

#### ACL 목록 (전체)

```http
GET /api/v1/acls
X-Client-ID: admin
```

#### ACL 목록 (클라이언트별)

```http
GET /api/v1/acls?client_id=client-web-app
X-Client-ID: admin
```

#### ACL 조회

```http
GET /api/v1/acls/{acl_id}
X-Client-ID: admin
```

#### ACL 삭제

```http
DELETE /api/v1/acls/{acl_id}
X-Client-ID: admin
```

#### 권한 확인

```http
POST /api/v1/acls/check
Content-Type: application/json

{
  "client_id": "client-web-app",
  "group_id": "group-prod",
  "resource_id": "key-123",
  "permission": "DELETE"
}
```

**응답:**
```json
{
  "allowed": true,
  "client_id": "client-web-app",
  "group_id": "group-prod",
  "resource_id": "key-123",
  "permission": "DELETE"
}
```

#### 자기 권한 조회 (Owner, Guest)

**모든 클라이언트는 자신의 권한 목록을 조회할 수 있습니다:**

```http
GET /api/v1/acls/my-permissions
X-API-Key: api_client-web-app_1707858720
```

**응답:**
```json
{
  "client_id": "client-web-app",
  "client_name": "Web Application",
  "total_permissions": 3,
  "permissions": [
    {
      "group_id": "group-prod",
      "group_name": "Production",
      "role": "Owner",
      "permissions": ["CREATE", "READ", "UPDATE", "DELETE"],
      "resource_id": "*"
    },
    {
      "group_id": "group-staging",
      "group_name": "Staging",
      "role": "Owner",
      "permissions": ["CREATE", "READ", "UPDATE", "DELETE"],
      "resource_id": "*"
    },
    {
      "group_id": "group-dev",
      "group_name": "Development",
      "role": "Guest",
      "permissions": ["READ"],
      "resource_id": "*"
    }
  ],
  "summary": {
    "is_admin": false,
    "is_owner": true,
    "is_guest": true,
    "is_audit": false,
    "owner_groups": ["group-prod", "group-staging"],
    "guest_groups": ["group-dev"]
  }
}
```

**특징:**
- ✅ 모든 역할 (Admin, Owner, Guest, Audit)이 사용 가능
- ✅ 자신의 모든 ACL 목록 반환
- ✅ 그룹별로 정리된 권한 정보
- ✅ 역할 요약 (어떤 그룹에서 Owner/Guest인지)
- ✅ 만료 시간 정보 포함

### 감사 로그

#### 감사 로그 조회 (Audit 역할)

**전체 감사 로그:**
```http
GET /api/v1/audit/logs
X-Client-ID: auditor
```

**특정 그룹 필터링:**
```http
GET /api/v1/audit/logs?group_id=group-prod
X-Client-ID: auditor
```

#### 감사 로그 조회 (Owner 역할)

**Owner는 자신이 관리하는 그룹의 로그만 조회 가능:**

```http
GET /api/v1/audit/logs?group_id=group-prod
X-API-Key: api_client-web-app_1707858720
```

**응답:**
```json
{
  "logs": [
    {
      "id": "audit_1707858600000",
      "timestamp": "2024-02-13T10:10:00Z",
      "client_id": "client-web-app",
      "action": "POST_keys",
      "resource": "keys",
      "resource_id": "key-123",
      "group_id": "group-prod",
      "result": "success"
    }
  ],
  "total": 1,
  "filtered_by_group": "group-prod",
  "role": "Owner"
}
```

**쿼리 파라미터:**
- `group_id`: 그룹 ID (Owner는 필수, Audit은 선택)
- `client_id`: 클라이언트 ID
- `action`: 작업 (CREATE_KEY, DELETE_KEY 등)
- `resource`: 리소스 (keys, groups, clients)
- `resource_id`: 리소스 ID
- `result`: 결과 (success, denied, error)
- `start_time`: 시작 시간 (ISO 8601)
- `end_time`: 종료 시간 (ISO 8601)

**Owner 역할 제한사항:**
- ✅ 자신이 Owner인 그룹의 로그만 조회 가능
- ✅ `group_id` 파라미터 필수
- ❌ 다른 그룹의 로그 조회 불가
- ❌ 전체 감사 리포트 조회 불가

**응답:**
```json
{
  "logs": [
    {
      "id": "audit_1707818600000",
      "timestamp": "2024-02-13T10:10:00Z",
      "client_id": "client-web-app",
      "action": "POST_keys",
      "resource": "keys",
      "resource_id": "key-123",
      "group_id": "group-prod",
      "result": "success",
      "method": "POST",
      "path": "/api/v1/keys",
      "status_code": 201,
      "ip_address": "192.168.1.100",
      "user_agent": "curl/7.68.0"
    }
  ],
  "total": 1
}
```

#### 감사 리포트

```http
GET /api/v1/audit/reports
X-Client-ID: auditor
```

**응답:**
```json
{
  "total_logs": 150,
  "summary": {
    "by_result": {
      "success": 120,
      "denied": 25,
      "error": 5
    },
    "by_action": {
      "POST_keys": 50,
      "GET_keys": 70,
      "DELETE_keys": 30
    },
    "by_client": {
      "client-web-app": 100,
      "client-mobile-app": 50
    },
    "by_resource": {
      "keys": 120,
      "groups": 20,
      "clients": 10
    }
  },
  "generated_at": "2024-02-13T10:30:00Z"
}
```

## 🎯 사용 시나리오

### 시나리오 1: 다중 환경 관리

```
조직 구조:
- Production 그룹
- Staging 그룹
- Development 그룹

클라이언트:
- Web App (Owner: Prod, Staging / Guest: Dev)
- Mobile App (Owner: Prod / Guest: Staging, Dev)
- CI/CD (Owner: Dev, Staging)
```

**설정:**

```bash
# 그룹 생성
curl -X POST /api/v1/groups -d '{"id":"group-prod","name":"Production"}'
curl -X POST /api/v1/groups -d '{"id":"group-staging","name":"Staging"}'
curl -X POST /api/v1/groups -d '{"id":"group-dev","name":"Development"}'

# 클라이언트 생성
curl -X POST /api/v1/clients -d '{
  "id":"client-web",
  "name":"Web App",
  "groups":["group-prod","group-staging","group-dev"]
}'

# ACL 설정
# Web App: Owner (Prod, Staging), Guest (Dev)
curl -X POST /api/v1/acls -d '{
  "id":"acl-web-prod","client_id":"client-web",
  "group_id":"group-prod","role":"Owner"
}'
curl -X POST /api/v1/acls -d '{
  "id":"acl-web-staging","client_id":"client-web",
  "group_id":"group-staging","role":"Owner"
}'
curl -X POST /api/v1/acls -d '{
  "id":"acl-web-dev","client_id":"client-web",
  "group_id":"group-dev","role":"Guest"
}'
```

### 시나리오 2: 시간 제한 권한

```
요구사항:
- 외부 컨설턴트에게 30일간 Guest 권한
- 만료 후 자동 차단
```

**설정:**

```bash
# 30일 후 만료되는 ACL
curl -X POST /api/v1/acls \
  -H "Content-Type: application/json" \
  -d '{
    "id": "acl-consultant",
    "client_id": "client-consultant",
    "group_id": "group-prod",
    "role": "Guest",
    "expires_at": "2024-03-15T00:00:00Z"
  }'
```

### 시나리오 3: 리소스별 권한

```
요구사항:
- 특정 키만 접근 가능
- 나머지 키는 차단
```

**설정:**

```bash
# 특정 키에 대한 Owner 권한
curl -X POST /api/v1/acls -d '{
  "id":"acl-specific",
  "client_id":"client-app",
  "group_id":"group-prod",
  "role":"Owner",
  "resource_id":"key-important-001"
}'
```

### 시나리오 4: Owner의 감사로그 조회

```
요구사항:
- 팀 리더가 자신의 그룹 활동 모니터링
- Production 그룹의 모든 작업 추적
```

**설정:**

```bash
# 1. Owner 권한 부여
curl -X POST /api/v1/acls \
  -H "X-Client-ID: admin" \
  -d '{
    "id":"acl-team-leader",
    "client_id":"client-team-leader",
    "group_id":"group-prod",
    "role":"Owner"
  }'

# 2. Owner가 자신의 그룹 감사로그 조회
curl -X GET "http://localhost:9090/api/v1/audit/logs?group_id=group-prod" \
  -H "X-API-Key: api_client-team-leader_xxx"

# 응답: group-prod 그룹의 모든 활동 로그
{
  "logs": [
    {
      "client_id": "client-web-app",
      "action": "POST_keys",
      "group_id": "group-prod",
      "result": "success",
      "timestamp": "2024-02-13T10:00:00Z"
    },
    {
      "client_id": "client-mobile-app",
      "action": "DELETE_keys",
      "group_id": "group-prod",
      "result": "success",
      "timestamp": "2024-02-13T11:00:00Z"
    }
  ],
  "total": 2,
  "filtered_by_group": "group-prod",
  "role": "Owner"
}

# 3. Owner가 자신의 권한 확인
curl -X GET http://localhost:9090/api/v1/acls/my-permissions \
  -H "X-API-Key: api_client-team-leader_xxx"

# 응답: 자신이 가진 모든 권한
{
  "client_id": "client-team-leader",
  "total_permissions": 2,
  "permissions": [
    {
      "group_id": "group-prod",
      "group_name": "Production",
      "role": "Owner",
      "permissions": ["CREATE", "READ", "UPDATE", "DELETE"]
    },
    {
      "group_id": "group-staging",
      "group_name": "Staging",
      "role": "Guest",
      "permissions": ["READ"]
    }
  ],
  "summary": {
    "is_owner": true,
    "is_guest": true,
    "owner_groups": ["group-prod"],
    "guest_groups": ["group-staging"]
  }
}
```

### 시나리오 5: Guest의 권한 확인

```
요구사항:
- 읽기 전용 사용자가 자신의 접근 범위 확인
```

**사용:**

```bash
# Guest가 자신의 권한 조회
curl -X GET http://localhost:9090/api/v1/acls/my-permissions \
  -H "X-API-Key: api_client-readonly_xxx"

# 응답
{
  "client_id": "client-readonly",
  "client_name": "Read-Only User",
  "total_permissions": 3,
  "permissions": [
    {
      "group_id": "group-prod",
      "role": "Guest",
      "permissions": ["READ"]
    },
    {
      "group_id": "group-staging",
      "role": "Guest",
      "permissions": ["READ"]
    },
    {
      "group_id": "group-dev",
      "role": "Guest",
      "permissions": ["READ"]
    }
  ],
  "summary": {
    "is_guest": true,
    "guest_groups": ["group-prod", "group-staging", "group-dev"]
  }
}

# Guest가 감사로그 조회 시도 (실패)
curl -X GET "http://localhost:9090/api/v1/audit/logs?group_id=group-prod" \
  -H "X-API-Key: api_client-readonly_xxx"

# 응답: 403 Forbidden
{
  "error": "Audit or Owner permission required"
}
```

## 🔍 권한 확인 흐름

```
1. API 요청 수신
   ↓
2. X-API-Key에서 Client ID 추출
   ↓
3. Client 활성화 여부 확인
   ↓
4. 요청에서 Group ID, Resource ID 추출
   ↓
5. Client의 ACL 목록 조회
   ↓
6. 각 ACL 확인:
   - 만료 여부
   - Role이 Admin? → 허용
   - Role이 Audit + Permission이 AUDIT? → 허용
   - Group ID 일치?
   - Resource ID 일치? (또는 "*")
   - Permission 포함?
   ↓
7. 하나라도 통과 → 허용
   모두 실패 → 거부
   ↓
8. 감사 로그 기록
```

## 📊 감사 로그 분석

### 로그 항목 구조

```json
{
  "id": "audit_1707818700000",
  "timestamp": "2024-02-13T10:15:00Z",
  "client_id": "client-web-app",
  "action": "DELETE_keys",
  "resource": "keys",
  "resource_id": "key-old-001",
  "group_id": "group-prod",
  "result": "success",
  "method": "DELETE",
  "path": "/api/v1/keys/key-old-001",
  "status_code": 200,
  "ip_address": "192.168.1.100",
  "user_agent": "Python/3.9 requests/2.28.0",
  "details": {
    "key_algorithm": "AES",
    "key_length": 256
  }
}
```

### 주요 분석 패턴

**비정상 접근 탐지:**
```bash
# 거부된 요청 조회
GET /api/v1/audit/logs?result=denied

# 특정 클라이언트의 실패한 요청
GET /api/v1/audit/logs?client_id=client-suspicious&result=denied
```

**활동 패턴 분석:**
```bash
# 시간대별 활동
GET /api/v1/audit/logs?start_time=2024-02-13T00:00:00Z&end_time=2024-02-13T23:59:59Z

# 특정 리소스에 대한 모든 작업
GET /api/v1/audit/logs?resource_id=key-critical-001
```

**컴플라이언스 리포트:**
```bash
# 전체 통계 리포트
GET /api/v1/audit/reports
```

## 🛡️ 보안 모범 사례

### 1. 최소 권한 원칙

```
❌ 나쁜 예: 모든 클라이언트에게 Admin 권한
✅ 좋은 예: 필요한 그룹과 역할만 부여
```

### 2. 권한 분리

```
✅ Production: Owner 권한 (소수)
✅ Staging: Owner 권한 (개발팀)
✅ Development: Guest 권한 (전체)
```

### 3. 만료 시간 설정

```
✅ 임시 권한: expires_at 설정
✅ 정기 검토: 분기별 ACL 검토
```

### 4. 감사 로그 모니터링

```
✅ 실시간 알림: denied 결과 모니터링
✅ 주간 리포트: 활동 패턴 분석
✅ 이상 탐지: 비정상 접근 패턴
```

### 5. API 키 관리

```
✅ 안전한 저장: 환경 변수 또는 비밀 관리 도구
✅ 정기 갱신: 6개월마다 API 키 갱신
✅ 즉시 폐기: 유출 시 클라이언트 비활성화
```

## 🎉 요약

```
✅ 4가지 역할: Admin, Owner, Guest, Audit
✅ 그룹 기반 권한 관리
✅ 유연한 ACL 시스템
✅ 리소스별 세밀한 제어
✅ 시간 제한 권한
✅ 완전한 감사 로깅
✅ 실시간 권한 확인
✅ Admin API로 모든 관리 가능
✅ Owner의 그룹별 감사로그 조회 (NEW!)
✅ 클라이언트의 자기 권한 조회 (NEW!)
```

**세밀한 권한 관리로 시스템을 보호하세요!** 🔐
