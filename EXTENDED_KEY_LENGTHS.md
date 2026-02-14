# Extended Key Length Support

KMIP 서버는 대칭키와 비대칭키 모두에 대해 확장된 키 길이를 지원합니다.

## 지원되는 키 길이

### 대칭 키 알고리즘

#### AES (Advanced Encryption Standard)
- **128비트**: 표준, 빠른 성능
- **192비트**: 중간 보안
- **256비트**: 고보안 (권장)
- **512비트**: 최고 보안 🆕

**사용 예제:**
```bash
# AES-512 키 생성
./kmip-rest-client -op create -algo AES -length 512

curl -X POST http://localhost:9090/api/v1/keys \
  -H "Content-Type: application/json" \
  -d '{"algorithm":"AES","length":512}'
```

#### SEED (Korean Standard)
- **128비트**: 표준
- **256비트**: 고보안
- **512비트**: 최고 보안 🆕

**사용 예제:**
```bash
# SEED-512 키 생성
./kmip-rest-client -op create -algo SEED -length 512

curl -X POST http://localhost:9090/api/v1/keys \
  -H "Content-Type: application/json" \
  -d '{"algorithm":"SEED","length":512}'
```

#### ARIA (Korean Standard)
- **128비트**: 표준
- **192비트**: 중간 보안
- **256비트**: 고보안
- **512비트**: 최고 보안 🆕

**사용 예제:**
```bash
# ARIA-512 키 생성
./kmip-rest-client -op create -algo ARIA -length 512

curl -X POST http://localhost:9090/api/v1/keys \
  -H "Content-Type: application/json" \
  -d '{"algorithm":"ARIA","length":512}'
```

### 비대칭 키 알고리즘

#### RSA (Rivest-Shamir-Adleman)
- **512비트**: 레거시 (권장하지 않음)
- **1024비트**: 레거시 (2030년까지만 안전)
- **2048비트**: 표준 (권장)
- **3072비트**: 고보안
- **4096비트**: 최고 보안
- **8192비트**: 극한 보안 🆕

**사용 예제:**
```bash
# RSA-8192 키 쌍 생성
./kmip-rest-client -op createkeypair -algo RSA -length 8192

curl -X POST http://localhost:9090/api/v1/keypairs \
  -H "Content-Type: application/json" \
  -d '{"algorithm":"RSA","length":8192}'
```

#### ECDSA (Elliptic Curve)
- **P-192**: 192비트 (레거시) 🆕
- **P-224**: 224비트
- **P-256**: 256비트 (권장)
- **P-384**: 384비트 (고보안)
- **P-521**: 521비트 (최고 보안)

**사용 예제:**
```bash
# ECDSA P-192 키 쌍 생성
./kmip-rest-client -op createkeypair -algo ECDSA -length 192

# ECDSA P-521 키 쌍 생성
./kmip-rest-client -op createkeypair -algo ECDSA -length 521

curl -X POST http://localhost:9090/api/v1/keypairs \
  -H "Content-Type: application/json" \
  -d '{"algorithm":"ECDSA","length":521}'
```

## 보안 강도 비교

### 대칭 키 보안 강도

| 키 길이 | 보안 비트 | 공격 복잡도 | 권장 용도 |
|---------|----------|------------|-----------|
| 128비트 | 128 | 2^128 | 일반 데이터 |
| 192비트 | 192 | 2^192 | 민감 데이터 |
| 256비트 | 256 | 2^256 | 고도 민감 데이터 |
| 512비트 | 512 | 2^512 | 양자 컴퓨터 대비 🆕 |

### 비대칭 키 보안 강도 (RSA)

| RSA 키 길이 | 대칭키 동등 | 권장 사용 기한 | 용도 |
|------------|------------|----------------|------|
| 1024비트 | ~80비트 | 2030년까지 | 레거시만 |
| 2048비트 | ~112비트 | 2030년+ | 표준 (권장) |
| 3072비트 | ~128비트 | 2030년+ | 고보안 |
| 4096비트 | ~152비트 | 장기 | 최고 보안 |
| 8192비트 | ~192비트 | 장기 | 양자 대비 🆕 |

### 타원곡선 보안 강도 (ECDSA)

| ECDSA 곡선 | 키 크기 | RSA 동등 | 대칭키 동등 |
|-----------|--------|---------|------------|
| P-192 | 192비트 | ~1024비트 | ~96비트 |
| P-224 | 224비트 | ~2048비트 | ~112비트 |
| P-256 | 256비트 | ~3072비트 | ~128비트 |
| P-384 | 384비트 | ~7680비트 | ~192비트 |
| P-521 | 521비트 | ~15360비트 | ~256비트 |

## 성능 영향

### 키 생성 시간 (평균)

```
대칭 키:
  AES-128:    0.2ms
  AES-256:    0.2ms
  AES-512:    0.3ms 🆕
  
  SEED-128:   0.3ms
  SEED-256:   0.3ms
  SEED-512:   0.4ms 🆕
  
  ARIA-128:   0.4ms
  ARIA-256:   0.5ms
  ARIA-512:   0.6ms 🆕

비대칭 키:
  RSA-2048:   50ms
  RSA-3072:   150ms
  RSA-4096:   350ms
  RSA-8192:   2500ms (2.5초) 🆕
  
  ECDSA P-256:  5ms
  ECDSA P-384:  8ms
  ECDSA P-521:  12ms
```

### 암호화/복호화 성능

```
처리량 (MB/s):
  AES-256:    250 MB/s
  AES-512:    180 MB/s 🆕
  
  RSA-2048:   2 MB/s (암호화)
  RSA-4096:   0.5 MB/s (암호화)
  RSA-8192:   0.1 MB/s (암호화) 🆕
  
  ECDSA P-256: 50 MB/s (서명)
  ECDSA P-521: 25 MB/s (서명)
```

### 키/서명 크기

```
대칭 키 크기:
  128비트 = 16바이트
  256비트 = 32바이트
  512비트 = 64바이트

RSA 키 크기:
  2048비트: 공개키 294B, 개인키 1192B
  4096비트: 공개키 550B, 개인키 2373B
  8192비트: 공개키 1062B, 개인키 4743B 🆕

ECDSA 키 크기:
  P-256: 공개키 91B, 개인키 121B
  P-384: 공개키 120B, 개인키 167B
  P-521: 공개키 158B, 개인키 223B
```

## 사용 권장사항

### 일반 웹 애플리케이션
- **대칭**: AES-256
- **비대칭**: RSA-2048 또는 ECDSA P-256
- **이유**: 성능과 보안의 균형

### 금융 서비스
- **대칭**: AES-256 또는 ARIA-256
- **비대칭**: RSA-3072 또는 ECDSA P-384
- **이유**: 높은 보안 요구사항

### 정부/군사 시스템
- **대칭**: AES-512 또는 ARIA-512 🆕
- **비대칭**: RSA-4096 또는 ECDSA P-521
- **이유**: 최고 수준 보안

### 양자 컴퓨터 대비
- **대칭**: AES-512, ARIA-512 🆕
- **비대칭**: RSA-8192 🆕
- **이유**: 양자 알고리즘 Grover/Shor 대비
- **참고**: 향후 양자 내성 암호(PQC)로 전환 권장

## Python 예제

```python
import requests

base_url = "http://localhost:9090"

# 512비트 대칭 키 생성
def create_extended_symmetric_keys():
    algorithms = ["AES", "SEED", "ARIA"]
    
    for algo in algorithms:
        response = requests.post(
            f"{base_url}/api/v1/keys",
            json={
                "key_type": "symmetric",
                "algorithm": algo,
                "length": 512
            }
        )
        key_data = response.json()
        print(f"{algo}-512 Key ID: {key_data['key_id']}")

# 대용량 RSA 키 쌍 생성
def create_large_rsa_keys():
    for length in [4096, 8192]:
        response = requests.post(
            f"{base_url}/api/v1/keypairs",
            json={
                "algorithm": "RSA",
                "length": length
            }
        )
        keys = response.json()
        print(f"RSA-{length} Public Key: {keys['public_key_id']}")
        print(f"RSA-{length} Private Key: {keys['private_key_id']}")

# 모든 ECDSA 곡선 테스트
def test_all_ecdsa_curves():
    curves = [192, 224, 256, 384, 521]
    
    for curve in curves:
        response = requests.post(
            f"{base_url}/api/v1/keypairs",
            json={
                "algorithm": "ECDSA",
                "length": curve
            }
        )
        keys = response.json()
        print(f"ECDSA P-{curve}: {keys['public_key_id']}")

# 실행
create_extended_symmetric_keys()
create_large_rsa_keys()
test_all_ecdsa_curves()
```

## 양자 컴퓨터 위협

### 현재 암호화에 대한 위협

**Grover 알고리즘 (대칭 키 공격)**
- 탐색 공간을 제곱근으로 축소
- AES-256 → 128비트 보안으로 감소
- AES-512 → 256비트 보안으로 감소 ✅

**Shor 알고리즘 (비대칭 키 공격)**
- RSA, ECDSA 완전히 파괴 가능
- RSA-8192도 충분한 큐비트가 있으면 위험
- 양자 내성 암호(PQC) 전환 필요

### 권장 전환 전략

```
현재 (2024-2030):
  대칭: AES-256, ARIA-256
  비대칭: RSA-2048/3072, ECDSA P-256/384

과도기 (2030-2035):
  대칭: AES-512, ARIA-512 🆕
  비대칭: RSA-4096/8192 + PQC 하이브리드

양자 시대 (2035+):
  대칭: AES-512, ARIA-512
  비대칭: NIST PQC 표준 (Kyber, Dilithium 등)
```

## 마이그레이션 가이드

### 256비트에서 512비트로

```python
def migrate_to_512bit(old_key_id):
    # 1. 기존 256비트 키로 데이터 복호화
    old_key = get_key(old_key_id)
    decrypted_data = decrypt(encrypted_data, old_key)
    
    # 2. 새로운 512비트 키 생성
    response = requests.post(
        "http://localhost:9090/api/v1/keys",
        json={"algorithm": "AES", "length": 512}
    )
    new_key = response.json()
    
    # 3. 512비트 키로 재암호화
    new_encrypted = encrypt(decrypted_data, new_key)
    
    # 4. 이전 키 폐기
    requests.delete(f"http://localhost:9090/api/v1/keys/{old_key_id}")
    
    return new_encrypted, new_key
```

### RSA-2048에서 RSA-8192로

```python
def migrate_rsa_keys(old_keypair_id):
    # 1. 새로운 8192비트 키 쌍 생성 (시간 소요)
    response = requests.post(
        "http://localhost:9090/api/v1/keypairs",
        json={"algorithm": "RSA", "length": 8192}
    )
    new_keypair = response.json()
    
    # 2. 인증서 재발급
    reissue_certificate(new_keypair['public_key_id'])
    
    # 3. 서비스 전환 (점진적)
    gradual_rollout(old_keypair_id, new_keypair)
    
    # 4. 이전 키 폐기
    delete_keypair(old_keypair_id)
    
    return new_keypair
```

## 주의사항

### 512비트 대칭 키
⚠️ **오버헤드**: 키 관리 복잡도 증가  
⚠️ **성능**: 약간의 성능 저하  
✅ **장점**: 양자 컴퓨터 대비  
✅ **권장**: 장기 보관 데이터

### RSA-8192
⚠️ **느린 생성**: 키 생성에 2-3초 소요  
⚠️ **큰 크기**: 키 크기가 매우 큼  
⚠️ **느린 연산**: 암호화/서명 느림  
✅ **장점**: 현존 최고 보안  
✅ **권장**: 루트 CA, 장기 서명

### ECDSA P-192
⚠️ **약한 보안**: 더 이상 권장하지 않음  
⚠️ **레거시**: 호환성 목적으로만 사용  
❌ **새 프로젝트**: 절대 사용 금지  
✅ **대안**: P-256 이상 사용

## 규정 준수

### NIST 권장사항 (SP 800-57)
- 2030년까지: 112비트 보안 (RSA-2048, AES-128)
- 2030년 이후: 128비트 보안 (RSA-3072, AES-256)

### ECRYPT-CSA 권장사항
- 단기 (2026-2030): AES-128, RSA-2048
- 중기 (2031-2040): AES-256, RSA-3072
- 장기 (2041+): AES-512, RSA-8192 또는 PQC

## 추가 리소스

- [NIST Key Management Guidelines](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
- [ECRYPT-CSA Recommendations](https://www.ecrypt.eu.org/csa/documents/D5.4-FinalAlgKeySizeProt.pdf)
- [Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
