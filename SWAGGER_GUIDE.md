# 📚 KMIP REST API Swagger 문서 가이드

## 개요

**Swagger/OpenAPI 3.0** 기반의 완전한 대화형 API 문서를 제공합니다.

### 특징

- ✅ **Swagger UI**: 대화형 API 테스트 인터페이스
- ✅ **ReDoc**: 깔끔한 읽기 전용 문서
- ✅ **OpenAPI 3.0**: 표준 스펙 지원
- ✅ **Try it out**: 브라우저에서 직접 API 테스트
- ✅ **실시간 예제**: 요청/응답 예제 제공
- ✅ **완전한 스키마**: 모든 데이터 모델 정의

## 🌐 접속 방법

### Swagger UI (추천)

```
http://localhost:9090/docs
```

**특징:**
- 대화형 인터페이스
- API 직접 테스트 가능
- 요청/응답 실시간 확인
- 인증 토큰 설정 가능

### ReDoc (읽기 전용)

```
http://localhost:9090/redoc
```

**특징:**
- 깔끔한 3단 레이아웃
- 읽기에 최적화
- 검색 기능
- 인쇄 친화적

### OpenAPI 스펙

**YAML:**
```
http://localhost:9090/api/v1/swagger.yaml
```

**JSON:**
```
http://localhost:9090/api/v1/swagger.json
```

## 🎨 Swagger UI 사용법

### 1. 접속

브라우저에서 접속:
```
http://localhost:9090/docs
```

### 2. API 탐색

**헤더 정보:**
- 서비스 이름: KMIP REST API
- 버전: 1.0.0
- 설명: 전체 기능 설명

**통계 카드:**
- 🔑 Key Operations: 15+ 작업
- 🔐 Security: 보안 기능
- 🌐 Replication: 클러스터 복제
- 📊 KMIP Versions: 지원 버전

**태그별 그룹:**
- Keys: 키 관리
- KeyPairs: 키 쌍 관리
- Attributes: 속성 관리
- Search: 검색
- Server: 서버 정보
- Replication: 복제 관리

### 3. API 테스트

#### 예제 1: 키 생성

**단계:**

1. **Keys** 태그 클릭
2. **POST /api/v1/keys** 선택
3. **Try it out** 버튼 클릭
4. Request body 수정:

```json
{
  "algorithm": "AES",
  "length": 256,
  "attributes": {
    "environment": "production",
    "owner": "john.doe"
  }
}
```

5. **Execute** 버튼 클릭
6. 응답 확인:

```json
{
  "key_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "created"
}
```

#### 예제 2: 키 조회

**단계:**

1. **GET /api/v1/keys/{keyId}** 선택
2. **Try it out** 클릭
3. **keyId** 입력: `550e8400-e29b-41d4-a716-446655440000`
4. **Execute** 클릭
5. 응답 확인:

```json
{
  "key_id": "550e8400-e29b-41d4-a716-446655440000",
  "algorithm": "AES",
  "length": 256,
  "created_at": "2024-02-13T10:00:00Z",
  "state": "active",
  "key_material": "0123456789ABCDEF...",
  "attributes": {
    "environment": "production",
    "owner": "john.doe"
  }
}
```

#### 예제 3: 키 검색

**단계:**

1. **POST /api/v1/keys/search** 선택
2. **Try it out** 클릭
3. Request body:

```json
{
  "attributes": {
    "environment": "production"
  },
  "max_results": 10
}
```

4. **Execute** 클릭
5. 검색 결과 확인

### 4. 인증 설정

**API Key 인증:**

1. 우측 상단 **Authorize** 버튼 클릭
2. **ApiKeyAuth** 섹션에서:
   - Header Name: `X-API-Key`
   - Value: `your-api-key-here`
3. **Authorize** 클릭
4. **Close** 클릭

**이후 모든 요청에 자동으로 포함됩니다.**

## 📖 OpenAPI 스펙 구조

### 기본 정보

```yaml
openapi: 3.0.3
info:
  title: KMIP REST API
  version: 1.0.0
  description: |
    KMIP REST API Server with:
    - Symmetric/Asymmetric key management
    - Cross-cluster replication
    - Raft consensus
```

### 서버 정보

```yaml
servers:
  - url: http://localhost:9090
    description: Development server
  - url: https://api.example.com
    description: Production server
```

### 태그

```yaml
tags:
  - name: Keys
    description: Key management operations
  - name: KeyPairs
    description: Asymmetric key pair operations
  - name: Attributes
    description: Key attribute management
  - name: Search
    description: Key search and discovery
  - name: Server
    description: Server information
  - name: Replication
    description: Cross-cluster replication
```

### 경로 (Paths)

#### GET /health

```yaml
/health:
  get:
    summary: Health check
    tags:
      - Server
    responses:
      '200':
        description: Server is healthy
```

#### POST /api/v1/keys

```yaml
/api/v1/keys:
  post:
    summary: Create a new key
    tags:
      - Keys
    requestBody:
      required: true
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/CreateKeyRequest'
    responses:
      '201':
        description: Key created
      '400':
        description: Invalid request
```

### 스키마 (Schemas)

#### CreateKeyRequest

```yaml
CreateKeyRequest:
  type: object
  required:
    - algorithm
    - length
  properties:
    algorithm:
      type: string
      enum: [AES, DES, 3DES, RSA, DSA, ECDSA, SEED, ARIA]
    length:
      type: integer
      minimum: 8
      maximum: 4096
    attributes:
      type: object
      additionalProperties: true
      maxProperties: 100
```

#### Key

```yaml
Key:
  type: object
  properties:
    key_id:
      type: string
    algorithm:
      type: string
    length:
      type: integer
    created_at:
      type: string
      format: date-time
    state:
      type: string
      enum: [active, compromised, destroyed]
    key_material:
      type: string
    attributes:
      type: object
```

### 보안 스키마

```yaml
securitySchemes:
  ApiKeyAuth:
    type: apiKey
    in: header
    name: X-API-Key
  BearerAuth:
    type: http
    scheme: bearer
```

## 🎯 주요 엔드포인트

### 키 관리

| 메소드 | 경로 | 설명 |
|--------|------|------|
| **POST** | `/api/v1/keys` | 대칭 키 생성 |
| **POST** | `/api/v1/keypairs` | 비대칭 키 쌍 생성 |
| **POST** | `/api/v1/keys/register` | 기존 키 등록 |
| **GET** | `/api/v1/keys` | 모든 키 목록 |
| **GET** | `/api/v1/keys/{id}` | 키 조회 |
| **DELETE** | `/api/v1/keys/{id}` | 키 삭제 |

### 속성 관리

| 메소드 | 경로 | 설명 |
|--------|------|------|
| **GET** | `/api/v1/keys/attributes/{id}` | 속성 조회 |
| **POST** | `/api/v1/keys/attributes/{id}` | 속성 추가/수정 |
| **DELETE** | `/api/v1/keys/attributes/{id}` | 속성 삭제 |

### 검색

| 메소드 | 경로 | 설명 |
|--------|------|------|
| **POST** | `/api/v1/keys/search` | 키 검색 |

### 서버

| 메소드 | 경로 | 설명 |
|--------|------|------|
| **GET** | `/health` | 헬스체크 |
| **GET** | `/api/v1/server/info` | 서버 정보 |
| **GET** | `/api/v1/server/versions` | 지원 버전 |

### 복제

| 메소드 | 경로 | 설명 |
|--------|------|------|
| **GET** | `/api/v1/replication/clusters` | 클러스터 목록 |
| **POST** | `/api/v1/replication/clusters` | 클러스터 추가 |
| **DELETE** | `/api/v1/replication/clusters` | 클러스터 제거 |
| **GET** | `/api/v1/replication/status` | 복제 상태 |

## 📝 요청/응답 예제

### 키 생성 (AES-256)

**요청:**
```http
POST /api/v1/keys HTTP/1.1
Host: localhost:9090
Content-Type: application/json

{
  "algorithm": "AES",
  "length": 256,
  "attributes": {
    "environment": "production",
    "owner": "john.doe",
    "purpose": "encryption"
  }
}
```

**응답:**
```http
HTTP/1.1 201 Created
Content-Type: application/json

{
  "key_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "created"
}
```

### 키 쌍 생성 (RSA-2048)

**요청:**
```http
POST /api/v1/keypairs HTTP/1.1
Host: localhost:9090
Content-Type: application/json

{
  "algorithm": "RSA",
  "length": 2048,
  "attributes": {
    "purpose": "signing",
    "owner": "security-team"
  }
}
```

**응답:**
```http
HTTP/1.1 201 Created
Content-Type: application/json

{
  "public_key_id": "pub-550e8400-e29b-41d4-a716-446655440000",
  "private_key_id": "priv-550e8400-e29b-41d4-a716-446655440001",
  "status": "created"
}
```

### 키 검색

**요청:**
```http
POST /api/v1/keys/search HTTP/1.1
Host: localhost:9090
Content-Type: application/json

{
  "attributes": {
    "environment": "production",
    "purpose": "encryption"
  },
  "max_results": 10
}
```

**응답:**
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "keys": [
    {
      "key_id": "550e8400-e29b-41d4-a716-446655440000",
      "algorithm": "AES",
      "length": 256,
      "created_at": "2024-02-13T10:00:00Z",
      "state": "active"
    }
  ],
  "total": 1,
  "matched": 1
}
```

## 🔍 검증 규칙

Swagger UI에서 각 필드의 검증 규칙을 확인할 수 있습니다:

### 알고리즘
- **Type:** `string`
- **Enum:** `AES`, `DES`, `3DES`, `RSA`, `DSA`, `ECDSA`, `SEED`, `ARIA`
- **Required:** ✅

### 키 길이
- **Type:** `integer`
- **Minimum:** `8`
- **Maximum:** `4096`
- **Required:** ✅

### 키 자료
- **Type:** `string`
- **Pattern:** `^[0-9a-fA-F]+$`
- **Description:** Hex-encoded

### 속성
- **Type:** `object`
- **Max Properties:** `100`
- **Additional Properties:** `true`

## 🛠️ 커스터마이징

### 서버 URL 변경

OpenAPI 스펙에서 서버 URL을 수정:

```yaml
servers:
  - url: https://your-domain.com
    description: Your production server
```

### 보안 스키마 추가

JWT 인증 추가:

```yaml
securitySchemes:
  JWTAuth:
    type: http
    scheme: bearer
    bearerFormat: JWT

security:
  - JWTAuth: []
```

### 예제 추가

더 많은 예제 추가:

```yaml
examples:
  SEED-128:
    summary: Create SEED-128 key
    value:
      algorithm: SEED
      length: 128
  ARIA-256:
    summary: Create ARIA-256 key
    value:
      algorithm: ARIA
      length: 256
```

## 📊 통계 및 정보

### API 엔드포인트 수

```
총 엔드포인트: 20+
- Keys: 7
- KeyPairs: 1
- Attributes: 3
- Search: 1
- Server: 3
- Replication: 4
- Health: 1
```

### 지원 알고리즘

```
대칭 키:
- AES (128, 192, 256)
- DES (56)
- 3DES (112, 168, 192)
- SEED (128)
- ARIA (128, 192, 256)

비대칭 키:
- RSA (1024, 2048, 3072, 4096)
- DSA (1024, 2048, 3072)
- ECDSA (256, 384, 521)
```

### KMIP 버전 지원

```
- KMIP 1.0
- KMIP 1.1
- KMIP 1.2
- KMIP 1.3
- KMIP 1.4
- KMIP 2.0
- KMIP 2.1
- KMIP 3.0
```

## 🎓 학습 자료

### Swagger UI 기능

1. **Try it out**: API 직접 테스트
2. **Models**: 데이터 모델 확인
3. **Authorize**: 인증 설정
4. **Schemas**: 스키마 상세 정보
5. **Responses**: 응답 코드 및 예제

### OpenAPI 3.0 문서

- [OpenAPI Specification](https://swagger.io/specification/)
- [Swagger UI Documentation](https://swagger.io/tools/swagger-ui/)
- [ReDoc Documentation](https://redocly.com/redoc/)

## 🔗 유용한 링크

### 문서 접속

```
Swagger UI:     http://localhost:9090/docs
ReDoc:          http://localhost:9090/redoc
OpenAPI YAML:   http://localhost:9090/api/v1/swagger.yaml
OpenAPI JSON:   http://localhost:9090/api/v1/swagger.json
API Root:       http://localhost:9090/
Health Check:   http://localhost:9090/health
```

### 외부 도구

**Swagger Editor:**
```
https://editor.swagger.io/
```
OpenAPI 스펙을 복사하여 편집 및 검증

**Postman:**
```
Import → Link → http://localhost:9090/api/v1/swagger.json
```
Postman에서 컬렉션으로 가져오기

## 🎉 요약

```
✅ Swagger UI: http://localhost:9090/docs
✅ ReDoc: http://localhost:9090/redoc
✅ OpenAPI 3.0 스펙 제공
✅ 대화형 API 테스트
✅ 20+ 엔드포인트 문서화
✅ 완전한 요청/응답 예제
✅ 검증 규칙 명시
✅ 인증 지원
✅ 프로덕션 준비 완료
```

**브라우저에서 바로 API를 탐색하고 테스트하세요!** 📚✨
