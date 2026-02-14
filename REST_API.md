# KMIP REST API Documentation

## Overview

KMIP REST API는 KMIP 프로토콜을 RESTful HTTP API로 래핑하여 더 쉽게 사용할 수 있도록 합니다.

## Base URL

```
http://localhost:9090
```

## API Endpoints

### 1. Health Check

헬스체크 엔드포인트

```http
GET /health
```

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-01T00:00:00Z"
}
```

---

### 2. API Root

API 정보 및 사용 가능한 엔드포인트 목록

```http
GET /
```

**Response:**
```json
{
  "service": "KMIP REST API Server",
  "version": "1.0.0",
  "endpoints": {
    "POST   /api/v1/keys": "Create a new key",
    "GET    /api/v1/keys": "List all keys",
    "GET    /api/v1/keys/{id}": "Get a key by ID",
    "DELETE /api/v1/keys/{id}": "Delete a key by ID",
    "GET    /api/v1/server/info": "Get server information",
    "GET    /api/v1/server/versions": "Get supported KMIP versions"
  },
  "timestamp": "2024-01-01T00:00:00Z"
}
```

---

### 3. Create Key

새로운 암호화 키 생성

```http
POST /api/v1/keys
Content-Type: application/json
```

**Request Body:**
```json
{
  "key_type": "symmetric",
  "algorithm": "AES",
  "length": 256,
  "name": "my-encryption-key",
  "usage_mask": ["encrypt", "decrypt"],
  "attributes": {
    "custom_attribute": "value"
  }
}
```

**Parameters:**
- `key_type` (string, optional): 키 타입 - "symmetric", "public", "private" (기본값: "symmetric")
- `algorithm` (string, optional): 알고리즘 - "AES", "RSA" 등 (기본값: "AES")
- `length` (integer, optional): 키 길이 (비트) (기본값: 256)
- `name` (string, optional): 키 이름
- `usage_mask` (array, optional): 키 사용 용도
- `attributes` (object, optional): 추가 속성

**Response (201 Created):**
```json
{
  "key_id": "a1b2c3d4e5f6",
  "key_type": "symmetric",
  "status": "created",
  "created_at": "2024-01-01T00:00:00Z",
  "attributes": {
    "custom_attribute": "value"
  }
}
```

**Example:**
```bash
curl -X POST http://localhost:9090/api/v1/keys \
  -H "Content-Type: application/json" \
  -d '{
    "key_type": "symmetric",
    "algorithm": "AES",
    "length": 256
  }'
```

---

### 4. List Keys

모든 키 목록 조회

```http
GET /api/v1/keys
```

**Response (200 OK):**
```json
{
  "keys": [
    {
      "key_id": "a1b2c3d4e5f6",
      "key_type": "symmetric",
      "algorithm": "AES",
      "length": 256,
      "name": "my-key",
      "created_at": "2024-01-01T00:00:00Z"
    }
  ],
  "total": 1
}
```

**Example:**
```bash
curl http://localhost:9090/api/v1/keys
```

---

### 5. Get Key

특정 키 조회

```http
GET /api/v1/keys/{id}
```

**Path Parameters:**
- `id` (string, required): 키 ID

**Response (200 OK):**
```json
{
  "key_id": "a1b2c3d4e5f6",
  "key_type": "symmetric",
  "algorithm": "AES",
  "length": 256,
  "key_material": "0123456789abcdef...",
  "attributes": {},
  "created_at": "2024-01-01T00:00:00Z"
}
```

**Response (404 Not Found):**
```json
{
  "error": "Key not found",
  "status": 404
}
```

**Example:**
```bash
curl http://localhost:9090/api/v1/keys/a1b2c3d4e5f6
```

---

### 6. Delete Key

키 삭제

```http
DELETE /api/v1/keys/{id}
```

**Path Parameters:**
- `id` (string, required): 키 ID

**Response (200 OK):**
```json
{
  "key_id": "a1b2c3d4e5f6",
  "status": "deleted",
  "deleted_at": "2024-01-01T00:00:00Z"
}
```

**Response (404 Not Found):**
```json
{
  "error": "Key not found",
  "status": 404
}
```

**Example:**
```bash
curl -X DELETE http://localhost:9090/api/v1/keys/a1b2c3d4e5f6
```

---

### 7. Server Information

서버 정보 및 기능 조회

```http
GET /api/v1/server/info
```

**Response (200 OK):**
```json
{
  "vendor": "KMIP Go Server",
  "server_info": "KMIP 1.0-3.0 Compatible Server",
  "supported_versions": ["1.0", "1.1", "1.2", "1.3", "1.4", "2.0", "2.1", "3.0"],
  "operations": ["Create", "Get", "Destroy", "Query", "DiscoverVersions"],
  "object_types": ["symmetric", "public", "private"]
}
```

**Example:**
```bash
curl http://localhost:9090/api/v1/server/info
```

---

### 8. Supported Versions

지원하는 KMIP 버전 목록

```http
GET /api/v1/server/versions
```

**Response (200 OK):**
```json
{
  "supported_versions": ["1.0", "1.1", "1.2", "1.3", "1.4", "2.0", "2.1", "3.0"]
}
```

**Example:**
```bash
curl http://localhost:9090/api/v1/server/versions
```

---

## Error Responses

모든 API는 에러 발생 시 다음 형식의 응답을 반환합니다:

```json
{
  "error": "Error message",
  "status": 400,
  "details": "Detailed error information"
}
```

**Common Status Codes:**
- `200 OK` - 요청 성공
- `201 Created` - 리소스 생성 성공
- `400 Bad Request` - 잘못된 요청
- `404 Not Found` - 리소스를 찾을 수 없음
- `405 Method Not Allowed` - 허용되지 않은 HTTP 메서드
- `500 Internal Server Error` - 서버 내부 오류

---

## CORS Support

모든 엔드포인트는 CORS를 지원합니다:
- `Access-Control-Allow-Origin: *`
- `Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS`
- `Access-Control-Allow-Headers: Content-Type, Authorization`

---

## Usage Examples

### Python Example

```python
import requests
import json

# Base URL
base_url = "http://localhost:9090"

# 1. Create a key
response = requests.post(
    f"{base_url}/api/v1/keys",
    json={
        "key_type": "symmetric",
        "algorithm": "AES",
        "length": 256,
        "name": "my-test-key"
    }
)
key_data = response.json()
key_id = key_data["key_id"]
print(f"Created key: {key_id}")

# 2. List all keys
response = requests.get(f"{base_url}/api/v1/keys")
keys = response.json()
print(f"Total keys: {keys['total']}")

# 3. Get specific key
response = requests.get(f"{base_url}/api/v1/keys/{key_id}")
key = response.json()
print(f"Key details: {json.dumps(key, indent=2)}")

# 4. Delete key
response = requests.delete(f"{base_url}/api/v1/keys/{key_id}")
result = response.json()
print(f"Deleted: {result['status']}")

# 5. Server info
response = requests.get(f"{base_url}/api/v1/server/info")
info = response.json()
print(f"Server: {info['vendor']}")
print(f"Versions: {', '.join(info['supported_versions'])}")
```

### JavaScript Example

```javascript
const baseUrl = "http://localhost:9090";

// 1. Create a key
async function createKey() {
  const response = await fetch(`${baseUrl}/api/v1/keys`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      key_type: 'symmetric',
      algorithm: 'AES',
      length: 256,
      name: 'my-test-key'
    }),
  });
  const data = await response.json();
  console.log('Created key:', data.key_id);
  return data.key_id;
}

// 2. List all keys
async function listKeys() {
  const response = await fetch(`${baseUrl}/api/v1/keys`);
  const data = await response.json();
  console.log('Total keys:', data.total);
  console.log('Keys:', data.keys);
}

// 3. Get specific key
async function getKey(keyId) {
  const response = await fetch(`${baseUrl}/api/v1/keys/${keyId}`);
  const data = await response.json();
  console.log('Key details:', data);
}

// 4. Delete key
async function deleteKey(keyId) {
  const response = await fetch(`${baseUrl}/api/v1/keys/${keyId}`, {
    method: 'DELETE',
  });
  const data = await response.json();
  console.log('Deleted:', data.status);
}

// 5. Server info
async function serverInfo() {
  const response = await fetch(`${baseUrl}/api/v1/server/info`);
  const data = await response.json();
  console.log('Server:', data.vendor);
  console.log('Versions:', data.supported_versions);
}

// Example usage
(async () => {
  const keyId = await createKey();
  await listKeys();
  await getKey(keyId);
  await deleteKey(keyId);
  await serverInfo();
})();
```

### cURL Examples

```bash
# Health check
curl http://localhost:9090/health

# Create key
curl -X POST http://localhost:9090/api/v1/keys \
  -H "Content-Type: application/json" \
  -d '{"key_type":"symmetric","algorithm":"AES","length":256}'

# List keys
curl http://localhost:9090/api/v1/keys

# Get key
curl http://localhost:9090/api/v1/keys/{key-id}

# Delete key
curl -X DELETE http://localhost:9090/api/v1/keys/{key-id}

# Server info
curl http://localhost:9090/api/v1/server/info

# Supported versions
curl http://localhost:9090/api/v1/server/versions
```

---

## Security Considerations

### Production Deployment

1. **HTTPS**: 프로덕션에서는 반드시 HTTPS 사용
2. **Authentication**: API 키 또는 JWT 토큰 인증 추가
3. **Authorization**: 역할 기반 접근 제어 (RBAC)
4. **Rate Limiting**: API 요청 속도 제한
5. **Key Material**: 키 자료는 권한이 있는 경우에만 반환
6. **Audit Logging**: 모든 API 요청/응답 로깅

### Example with Authentication (Future)

```bash
# API 키를 사용한 인증 예제
curl -X POST http://localhost:9090/api/v1/keys \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d '{"key_type":"symmetric","algorithm":"AES","length":256}'
```

---

## Rate Limiting

현재 구현에는 rate limiting이 없습니다. 프로덕션 환경에서는 다음과 같은 제한을 권장합니다:
- 인증된 사용자: 100 requests/minute
- 미인증 사용자: 10 requests/minute

---

## Monitoring

REST API는 각 요청에 대해 로그를 남깁니다:

```
[2024-01-01 12:00:00] POST /api/v1/keys - 125ms
[2024-01-01 12:00:01] GET /api/v1/keys - 15ms
[2024-01-01 12:00:02] DELETE /api/v1/keys/a1b2c3d4e5f6 - 45ms
```

---

## WebSocket Support (Future)

향후 버전에서는 WebSocket을 통한 실시간 이벤트 스트리밍을 지원할 예정입니다:
- 키 생성 이벤트
- 키 삭제 이벤트
- 키 만료 알림

---

## API Versioning

현재 API 버전: `v1`

URL에 버전이 포함되어 있어 향후 하위 호환성을 유지하면서 새로운 버전을 추가할 수 있습니다.

---

## OpenAPI Specification

OpenAPI (Swagger) 스펙은 향후 제공될 예정입니다.
