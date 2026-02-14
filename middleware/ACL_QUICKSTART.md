# 🚀 ACL 및 권한 관리 빠른 시작

## ✅ 새로운 기능!

### Owner의 감사로그 조회
- ✅ Owner는 자신이 관리하는 그룹의 감사로그를 조회할 수 있습니다
- ✅ 팀 리더가 팀 활동을 모니터링할 수 있습니다

### 자기 권한 조회
- ✅ Owner와 Guest는 자신에게 부여된 권한 목록을 조회할 수 있습니다
- ✅ 어떤 그룹에 어떤 권한이 있는지 즉시 확인 가능합니다

## 🎯 1분 안에 시작하기

### 1단계: 그룹 생성 (Admin)

```bash
curl -X POST http://localhost:9090/api/v1/groups \
  -H "X-Client-ID: admin" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "group-prod",
    "name": "Production Team",
    "description": "Production environment keys"
  }'
```

### 2단계: 클라이언트 생성 (Admin)

```bash
curl -X POST http://localhost:9090/api/v1/clients \
  -H "X-Client-ID: admin" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "client-team-leader",
    "name": "Team Leader",
    "description": "Production team leader"
  }'

# 응답에서 API 키 저장!
# {
#   "id": "client-team-leader",
#   "api_key": "api_client-team-leader_1707860000",
#   "message": "Save the API key - it won't be shown again."
# }
```

### 3단계: Owner 권한 부여 (Admin)

```bash
curl -X POST http://localhost:9090/api/v1/acls \
  -H "X-Client-ID: admin" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "acl-team-leader-prod",
    "client_id": "client-team-leader",
    "group_id": "group-prod",
    "role": "Owner"
  }'
```

### 4단계: Owner가 자신의 권한 확인

```bash
curl -X GET http://localhost:9090/api/v1/acls/my-permissions \
  -H "X-API-Key: api_client-team-leader_1707860000"
```

**응답:**
```json
{
  "client_id": "client-team-leader",
  "client_name": "Team Leader",
  "total_permissions": 1,
  "permissions": [
    {
      "group_id": "group-prod",
      "group_name": "Production Team",
      "role": "Owner",
      "permissions": ["CREATE", "READ", "UPDATE", "DELETE"]
    }
  ],
  "summary": {
    "is_owner": true,
    "owner_groups": ["group-prod"]
  }
}
```

### 5단계: Owner가 키 생성

```bash
curl -X POST http://localhost:9090/api/v1/keys \
  -H "X-API-Key: api_client-team-leader_1707860000" \
  -H "X-Group-ID: group-prod" \
  -H "Content-Type: application/json" \
  -d '{
    "algorithm": "AES",
    "length": 256
  }'
```

### 6단계: Owner가 감사로그 확인

```bash
curl -X GET "http://localhost:9090/api/v1/audit/logs?group_id=group-prod" \
  -H "X-API-Key: api_client-team-leader_1707860000"
```

**응답:**
```json
{
  "logs": [
    {
      "id": "audit_1707860100000",
      "timestamp": "2024-02-13T23:15:00Z",
      "client_id": "client-team-leader",
      "action": "POST_keys",
      "resource": "keys",
      "resource_id": "key-001",
      "group_id": "group-prod",
      "result": "success",
      "method": "POST",
      "path": "/api/v1/keys"
    }
  ],
  "total": 1,
  "filtered_by_group": "group-prod",
  "role": "Owner"
}
```

## 📊 역할별 가이드

### Admin (관리자)

**할 수 있는 것:**
- ✅ 모든 그룹 생성/수정/삭제
- ✅ 모든 클라이언트 생성/수정/삭제
- ✅ 모든 ACL 생성/삭제
- ✅ 모든 키 CRUD
- ✅ 전체 감사로그 조회
- ✅ 자신의 권한 조회

**예제:**
```bash
# 그룹 생성
curl -X POST /api/v1/groups -H "X-Client-ID: admin" \
  -d '{"id":"new-group","name":"New Team"}'

# 모든 감사로그 조회
curl -X GET /api/v1/audit/logs -H "X-Client-ID: admin"

# 감사 리포트 생성
curl -X GET /api/v1/audit/reports -H "X-Client-ID: admin"
```

### Owner (소유자)

**할 수 있는 것:**
- ✅ 해당 그룹의 키 CRUD
- ✅ 해당 그룹의 감사로그 조회 (NEW!)
- ✅ 자신의 권한 조회 (NEW!)

**할 수 없는 것:**
- ❌ 그룹 관리
- ❌ 클라이언트 관리
- ❌ ACL 관리
- ❌ 다른 그룹의 키 접근
- ❌ 다른 그룹의 감사로그 조회

**예제:**
```bash
# 키 생성
curl -X POST /api/v1/keys \
  -H "X-API-Key: owner_api_key" \
  -H "X-Group-ID: my-group" \
  -d '{"algorithm":"AES","length":256}'

# 내 그룹의 감사로그 조회 (필수: group_id)
curl -X GET "/api/v1/audit/logs?group_id=my-group" \
  -H "X-API-Key: owner_api_key"

# 내 권한 확인
curl -X GET /api/v1/acls/my-permissions \
  -H "X-API-Key: owner_api_key"
```

### Guest (게스트)

**할 수 있는 것:**
- ✅ 해당 그룹의 키 조회 (READ만)
- ✅ 자신의 권한 조회 (NEW!)

**할 수 없는 것:**
- ❌ 키 생성/수정/삭제
- ❌ 감사로그 조회
- ❌ 그룹/클라이언트/ACL 관리

**예제:**
```bash
# 키 조회
curl -X GET /api/v1/keys \
  -H "X-API-Key: guest_api_key" \
  -H "X-Group-ID: my-group"

# 내 권한 확인
curl -X GET /api/v1/acls/my-permissions \
  -H "X-API-Key: guest_api_key"

# 키 생성 시도 (실패)
curl -X POST /api/v1/keys \
  -H "X-API-Key: guest_api_key" \
  -d '{"algorithm":"AES","length":256}'
# 응답: 403 Permission denied
```

### Audit (감사)

**할 수 있는 것:**
- ✅ 전체 감사로그 조회
- ✅ 감사 리포트 생성
- ✅ 자신의 권한 조회

**할 수 없는 것:**
- ❌ 키 CRUD
- ❌ 그룹/클라이언트/ACL 관리

**예제:**
```bash
# 전체 감사로그 조회
curl -X GET /api/v1/audit/logs \
  -H "X-Client-ID: auditor"

# 특정 기간의 로그
curl -X GET "/api/v1/audit/logs?start_time=2024-02-13T00:00:00Z&end_time=2024-02-13T23:59:59Z" \
  -H "X-Client-ID: auditor"

# 거부된 요청만 조회
curl -X GET "/api/v1/audit/logs?result=denied" \
  -H "X-Client-ID: auditor"

# 감사 리포트
curl -X GET /api/v1/audit/reports \
  -H "X-Client-ID: auditor"
```

## 🔍 자기 권한 조회 상세

### API 엔드포인트

```
GET /api/v1/acls/my-permissions
```

### 헤더

```
X-API-Key: your_api_key
또는
X-Client-ID: your_client_id
```

### 응답 구조

```json
{
  "client_id": "클라이언트 ID",
  "client_name": "클라이언트 이름",
  "total_permissions": 권한 개수,
  "permissions": [
    {
      "group_id": "그룹 ID",
      "group_name": "그룹 이름",
      "role": "역할 (Admin/Owner/Guest/Audit)",
      "permissions": ["권한 목록"],
      "resource_id": "리소스 ID (옵션)",
      "expires_at": "만료 시간 (옵션)"
    }
  ],
  "summary": {
    "is_admin": boolean,
    "is_owner": boolean,
    "is_guest": boolean,
    "is_audit": boolean,
    "owner_groups": ["Owner 권한이 있는 그룹 목록"],
    "guest_groups": ["Guest 권한이 있는 그룹 목록"]
  }
}
```

### 예제 응답

**다중 역할 클라이언트:**
```json
{
  "client_id": "client-multi",
  "client_name": "Multi-Role User",
  "total_permissions": 4,
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
    },
    {
      "group_id": "group-test",
      "group_name": "Testing",
      "role": "Guest",
      "permissions": ["READ"],
      "resource_id": "*",
      "expires_at": "2024-12-31T23:59:59Z"
    }
  ],
  "summary": {
    "is_admin": false,
    "is_owner": true,
    "is_guest": true,
    "is_audit": false,
    "owner_groups": ["group-prod", "group-staging"],
    "guest_groups": ["group-dev", "group-test"]
  }
}
```

## 📝 Owner의 감사로그 조회 상세

### API 엔드포인트

```
GET /api/v1/audit/logs?group_id={group_id}
```

### 헤더

```
X-API-Key: owner_api_key
```

### 필수 파라미터

- `group_id`: Owner인 그룹 ID (필수!)

### 선택 파라미터

- `client_id`: 특정 클라이언트 필터링
- `action`: 작업 필터링
- `resource`: 리소스 필터링
- `result`: 결과 필터링 (success/denied/error)
- `start_time`: 시작 시간 (ISO 8601)
- `end_time`: 종료 시간 (ISO 8601)

### Owner 제한사항

**허용:**
- ✅ 자신이 Owner인 그룹의 로그만 조회
- ✅ 시간대별, 작업별 필터링
- ✅ 성공/실패 필터링

**거부:**
- ❌ 다른 그룹의 로그 조회
- ❌ `group_id` 파라미터 없이 조회
- ❌ 전체 감사 리포트 생성

### 예제

**성공 케이스:**
```bash
# Owner가 자신의 그룹 로그 조회
curl -X GET "http://localhost:9090/api/v1/audit/logs?group_id=group-prod" \
  -H "X-API-Key: owner_api_key"

# 특정 시간대 필터링
curl -X GET "http://localhost:9090/api/v1/audit/logs?group_id=group-prod&start_time=2024-02-13T10:00:00Z" \
  -H "X-API-Key: owner_api_key"

# 실패한 요청만 조회
curl -X GET "http://localhost:9090/api/v1/audit/logs?group_id=group-prod&result=denied" \
  -H "X-API-Key: owner_api_key"
```

**실패 케이스:**
```bash
# group_id 없이 조회 시도
curl -X GET "http://localhost:9090/api/v1/audit/logs" \
  -H "X-API-Key: owner_api_key"
# 응답: 400 Bad Request
# "group_id parameter required for Owner role"

# 다른 그룹의 로그 조회 시도
curl -X GET "http://localhost:9090/api/v1/audit/logs?group_id=other-group" \
  -H "X-API-Key: owner_api_key"
# 응답: 403 Forbidden
# "No permission to view logs for this group"
```

## 🎯 실전 시나리오

### 시나리오: 팀 리더의 일일 모니터링

```bash
# 1. 아침: 자신의 권한 확인
curl -X GET /api/v1/acls/my-permissions \
  -H "X-API-Key: team_leader_key"

# 2. 오전: 어제 생성된 키 확인
curl -X GET "/api/v1/audit/logs?group_id=my-team&action=POST_keys&start_time=2024-02-12T00:00:00Z" \
  -H "X-API-Key: team_leader_key"

# 3. 오후: 실패한 요청 조사
curl -X GET "/api/v1/audit/logs?group_id=my-team&result=denied" \
  -H "X-API-Key: team_leader_key"

# 4. 저녁: 오늘 하루 활동 요약
curl -X GET "/api/v1/audit/logs?group_id=my-team&start_time=2024-02-13T00:00:00Z&end_time=2024-02-13T23:59:59Z" \
  -H "X-API-Key: team_leader_key"
```

### 시나리오: Guest의 접근 범위 확인

```bash
# 1. 내가 어떤 그룹에 접근할 수 있는지 확인
curl -X GET /api/v1/acls/my-permissions \
  -H "X-API-Key: guest_key"

# 응답:
# {
#   "summary": {
#     "is_guest": true,
#     "guest_groups": ["group-prod", "group-staging", "group-dev"]
#   }
# }

# 2. 각 그룹의 키 조회
curl -X GET /api/v1/keys?group_id=group-prod \
  -H "X-API-Key: guest_key"

curl -X GET /api/v1/keys?group_id=group-staging \
  -H "X-API-Key: guest_key"
```

## 📚 참고

### API 엔드포인트 요약

```
# 자기 권한 조회 (모든 역할)
GET /api/v1/acls/my-permissions

# 감사로그 조회
GET /api/v1/audit/logs
  - Audit: 모든 로그 (group_id 선택)
  - Owner: 해당 그룹만 (group_id 필수)
  - Guest: 불가

# 감사 리포트 (Audit만)
GET /api/v1/audit/reports
```

### 권한 체크리스트

**Owner 확인사항:**
- [ ] 어떤 그룹에 Owner 권한이 있는가?
- [ ] 해당 그룹의 활동을 모니터링하고 있는가?
- [ ] 의심스러운 활동이 있는가?
- [ ] 권한 만료일이 다가오는가?

**Guest 확인사항:**
- [ ] 어떤 그룹에 접근할 수 있는가?
- [ ] 필요한 키를 조회할 수 있는가?
- [ ] 추가 권한이 필요한가? (Admin에게 요청)

## 🎉 완료!

```
✅ Owner의 그룹별 감사로그 조회
✅ 모든 클라이언트의 자기 권한 조회
✅ 역할별 접근 제어
✅ 실시간 모니터링
✅ 완전한 추적성
```

**이제 팀 리더도 자신의 그룹을 모니터링할 수 있습니다!** 🔐✨
