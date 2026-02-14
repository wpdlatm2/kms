# RSA and ECDSA Key Support

KMIP 서버는 이제 대칭 키(AES, 3DES 등)뿐만 아니라 비대칭 키 쌍(RSA, ECDSA)도 지원합니다.

## 지원하는 키 타입

### 대칭 키 (Symmetric Keys)
- **AES** - Advanced Encryption Standard
  - 128, 192, 256 비트
- **3DES** - Triple DES
  - 168 비트 (56×3)
- **DES** - Data Encryption Standard
  - 56 비트

### 비대칭 키 쌍 (Asymmetric Key Pairs)

#### RSA (Rivest-Shamir-Adleman)
- **용도**: 암호화, 서명, 키 교환
- **권장 키 길이**:
  - 2048 비트 (최소)
  - 3072 비트 (권장)
  - 4096 비트 (고보안)
- **사용 사례**:
  - TLS/SSL 인증서
  - 문서 서명
  - 이메일 암호화 (PGP/GPG)

#### ECDSA (Elliptic Curve Digital Signature Algorithm)
- **용도**: 디지털 서명
- **지원 곡선**:
  - P-224 (224 비트) - secp224r1
  - P-256 (256 비트) - secp256r1, prime256v1 (권장)
  - P-384 (384 비트) - secp384r1
  - P-521 (521 비트) - secp521r1
- **장점**:
  - RSA보다 작은 키 크기로 동일한 보안 수준
  - 빠른 서명 생성
  - 낮은 계산 비용
- **사용 사례**:
  - Bitcoin/Cryptocurrency 지갑
  - IoT 디바이스 인증
  - 모바일 앱 서명

## KMIP 작업

### Create (대칭 키)
단일 대칭 키를 생성합니다.

**작업 코드**: `0x00000001`

**지원 알고리즘**:
- AES (기본값)
- 3DES
- DES

**예제**:
```bash
# AES-256 키 생성
./kmip-rest-client -op create -algo AES -length 256
```

### CreateKeyPair (비대칭 키 쌍)
공개 키와 개인 키 쌍을 생성합니다.

**작업 코드**: `0x00000002`

**지원 알고리즘**:
- RSA
- ECDSA

**예제**:
```bash
# RSA-2048 키 쌍 생성
./kmip-rest-client -op createkeypair -algo RSA -length 2048

# ECDSA P-256 키 쌍 생성
./kmip-rest-client -op createkeypair -algo ECDSA -length 256
```

## REST API 사용법

### 대칭 키 생성

```bash
curl -X POST http://localhost:9090/api/v1/keys \
  -H "Content-Type: application/json" \
  -d '{
    "key_type": "symmetric",
    "algorithm": "AES",
    "length": 256
  }'
```

**응답**:
```json
{
  "key_id": "a1b2c3d4e5f6",
  "key_type": "symmetric",
  "status": "created",
  "created_at": "2024-01-01T00:00:00Z"
}
```

### RSA 키 쌍 생성

```bash
curl -X POST http://localhost:9090/api/v1/keypairs \
  -H "Content-Type: application/json" \
  -d '{
    "algorithm": "RSA",
    "length": 2048
  }'
```

**응답**:
```json
{
  "public_key_id": "pub123abc",
  "private_key_id": "priv456def",
  "algorithm": "RSA",
  "length": 2048,
  "status": "created",
  "created_at": "2024-01-01T00:00:00Z"
}
```

### ECDSA 키 쌍 생성

```bash
curl -X POST http://localhost:9090/api/v1/keypairs \
  -H "Content-Type: application/json" \
  -d '{
    "algorithm": "ECDSA",
    "length": 256
  }'
```

**응답**:
```json
{
  "public_key_id": "ecpub789ghi",
  "private_key_id": "ecpriv012jkl",
  "algorithm": "ECDSA",
  "length": 256,
  "status": "created",
  "created_at": "2024-01-01T00:00:00Z"
}
```

## Python 예제

```python
import requests

base_url = "http://localhost:9090"

# 1. AES 대칭 키 생성
response = requests.post(
    f"{base_url}/api/v1/keys",
    json={
        "key_type": "symmetric",
        "algorithm": "AES",
        "length": 256
    }
)
aes_key = response.json()
print(f"AES Key ID: {aes_key['key_id']}")

# 2. RSA 키 쌍 생성
response = requests.post(
    f"{base_url}/api/v1/keypairs",
    json={
        "algorithm": "RSA",
        "length": 2048
    }
)
rsa_keys = response.json()
print(f"RSA Public Key ID: {rsa_keys['public_key_id']}")
print(f"RSA Private Key ID: {rsa_keys['private_key_id']}")

# 3. ECDSA 키 쌍 생성
response = requests.post(
    f"{base_url}/api/v1/keypairs",
    json={
        "algorithm": "ECDSA",
        "length": 256  # P-256 곡선
    }
)
ecdsa_keys = response.json()
print(f"ECDSA Public Key ID: {ecdsa_keys['public_key_id']}")
print(f"ECDSA Private Key ID: {ecdsa_keys['private_key_id']}")

# 4. 공개 키 조회
response = requests.get(f"{base_url}/api/v1/keys/{rsa_keys['public_key_id']}")
public_key = response.json()
print(f"Public Key Type: {public_key['key_type']}")
print(f"Algorithm: {public_key['algorithm']}")
print(f"Key Material: {public_key['key_material'][:50]}...")

# 5. 모든 키 목록
response = requests.get(f"{base_url}/api/v1/keys")
all_keys = response.json()
print(f"Total keys: {all_keys['total']}")
for key in all_keys['keys']:
    print(f"  - {key['key_id']}: {key['key_type']} ({key['algorithm']})")
```

## JavaScript 예제

```javascript
const baseUrl = "http://localhost:9090";

// RSA 키 쌍 생성
async function createRSAKeyPair() {
  const response = await fetch(`${baseUrl}/api/v1/keypairs`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      algorithm: 'RSA',
      length: 2048,
    }),
  });
  
  const keyPair = await response.json();
  console.log('RSA Key Pair Created:');
  console.log('  Public Key ID:', keyPair.public_key_id);
  console.log('  Private Key ID:', keyPair.private_key_id);
  
  return keyPair;
}

// ECDSA 키 쌍 생성
async function createECDSAKeyPair() {
  const response = await fetch(`${baseUrl}/api/v1/keypairs`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      algorithm: 'ECDSA',
      length: 256, // P-256 곡선
    }),
  });
  
  const keyPair = await response.json();
  console.log('ECDSA Key Pair Created:');
  console.log('  Public Key ID:', keyPair.public_key_id);
  console.log('  Private Key ID:', keyPair.private_key_id);
  
  return keyPair;
}

// 키 조회
async function getKey(keyId) {
  const response = await fetch(`${baseUrl}/api/v1/keys/${keyId}`);
  const key = await response.json();
  console.log('Key Details:', key);
  return key;
}

// 실행
(async () => {
  const rsaKeys = await createRSAKeyPair();
  const ecdsaKeys = await createECDSAKeyPair();
  
  await getKey(rsaKeys.public_key_id);
  await getKey(ecdsaKeys.private_key_id);
})();
```

## 보안 고려사항

### 키 길이 권장사항

| 알고리즘 | 최소 | 권장 | 고보안 | 비고 |
|---------|------|------|--------|------|
| AES | 128 | 256 | 256 | 256비트 권장 |
| RSA | 2048 | 3072 | 4096 | 2048비트는 2030년까지 안전 |
| ECDSA P-256 | 256 | 256 | 384 | RSA-3072와 동등 |
| ECDSA P-384 | 384 | 384 | 521 | RSA-7680와 동등 |

### 키 관리 모범 사례

1. **개인 키 보호**
   - 개인 키는 절대 네트워크로 전송하지 않음
   - 암호화된 저장소에 보관
   - 접근 권한 엄격히 제한

2. **키 회전**
   - 정기적으로 키 갱신 (예: 매년)
   - 이전 키로 암호화된 데이터 재암호화

3. **키 백업**
   - 안전한 오프라인 백업
   - 다중 위치 저장
   - 재해 복구 계획 수립

4. **감사 로그**
   - 모든 키 생성/사용/삭제 기록
   - 접근 로그 보관
   - 정기 감사

### 알고리즘 선택 가이드

**대칭 키 (AES)를 사용해야 할 때:**
- 대량 데이터 암호화
- 빠른 암호화/복호화 필요
- 키 교환이 안전하게 이루어질 수 있을 때

**RSA를 사용해야 할 때:**
- PKI/인증서 기반 시스템
- 키 교환
- 디지털 서명 (큰 파일)
- 레거시 시스템 호환성

**ECDSA를 사용해야 할 때:**
- 디지털 서명 (권장)
- 제한된 리소스 (IoT, 모바일)
- 높은 성능 요구
- 작은 키/서명 크기 필요

## 키 포맷

### 저장 포맷

- **대칭 키**: Raw bytes (hex-encoded)
- **RSA 키**:
  - 공개 키: PKIX (X.509 SubjectPublicKeyInfo)
  - 개인 키: PKCS#8
- **ECDSA 키**:
  - 공개 키: PKIX (X.509 SubjectPublicKeyInfo)
  - 개인 키: PKCS#8

### PEM 변환 예제

```python
import base64
from cryptography.hazmat.primitives import serialization

# hex 형식의 키 자료를 바이너리로 변환
key_material_hex = "3082..."
key_material_bytes = bytes.fromhex(key_material_hex)

# PKCS#8 개인 키를 PEM으로 변환
from cryptography.hazmat.primitives.serialization import load_der_private_key
from cryptography.hazmat.backends import default_backend

private_key = load_der_private_key(key_material_bytes, password=None, backend=default_backend())

pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

print(pem.decode('utf-8'))
```

## 성능 비교

```
벤치마크 (Intel i7, 1000회 반복):

키 생성 시간:
  AES-256:      0.5ms
  RSA-2048:     50ms
  RSA-4096:     350ms
  ECDSA P-256:  5ms
  ECDSA P-384:  8ms

서명 생성 시간:
  RSA-2048:     2ms
  ECDSA P-256:  0.5ms

서명 검증 시간:
  RSA-2048:     0.1ms
  ECDSA P-256:  1ms

키 크기:
  RSA-2048 공개 키:  294 bytes
  RSA-2048 개인 키:  1192 bytes
  ECDSA P-256 공개 키: 91 bytes
  ECDSA P-256 개인 키: 121 bytes
```

## 문제 해결

### 키 생성 실패

```bash
# 에러: "Failed to generate RSA key pair"
# 해결: 키 길이가 너무 작거나 큼 (1024-4096 권장)

# 에러: "Unsupported algorithm"
# 해결: 지원하는 알고리즘 확인
curl http://localhost:9090/api/v1/server/info
```

### 키 조회 실패

```bash
# 에러: "Key not found"
# 해결: 키 ID 확인
curl http://localhost:9090/api/v1/keys

# 에러: "Invalid key type"
# 해결: 올바른 키 타입 사용 (symmetric, public, private)
```

## 추가 리소스

- [KMIP Specification](https://docs.oasis-open.org/kmip/kmip-spec/v3.0/)
- [NIST Key Management Guidelines](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
- [RFC 8017 - PKCS #1: RSA Cryptography](https://www.rfc-editor.org/rfc/rfc8017)
- [RFC 6979 - Deterministic ECDSA](https://www.rfc-editor.org/rfc/rfc6979)
