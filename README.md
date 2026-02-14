# KMIP Server (Go Implementation)

KMIP (Key Management Interoperability Protocol) 1.0 ~ 3.0을 지원하는 Go 언어 기반 서버 구현입니다.

## 특징

- ✅ KMIP 프로토콜 버전 1.0 ~ 3.0 지원
- ✅ TTLV (Tag-Type-Length-Value) 인코딩/디코딩
- ✅ TLS 1.2+ 보안 통신
- ✅ **대칭 키 (AES, 3DES, DES) 및 비대칭 키 쌍 (RSA, ECDSA) 지원** 🆕
- ✅ 키 관리 (생성, 조회, 삭제)
- ✅ **Raft 합의 알고리즘 기반 분산 저장소**
- ✅ **REST API 지원**
- ✅ 인메모리 키 저장소 (개발/테스트용)
- ✅ 클라이언트 인증 지원 (선택적)
- ✅ Query 및 DiscoverVersions 작업
- ✅ 클러스터 관리 HTTP API

## 프로젝트 구조

```
kmip-server/
├── kmip/                    # KMIP 프로토콜 구현
│   ├── ttlv.go             # TTLV 인코딩/디코딩
│   ├── protocol.go         # 프로토콜 구조체 및 버전 관리
│   ├── server.go           # 서버 핸들러
│   ├── store.go            # 인메모리 저장소
│   ├── keygen.go           # 키 생성 (AES, RSA, ECDSA)
│   ├── seed.go             # SEED 알고리즘 (한국 표준) 🆕
│   ├── aria.go             # ARIA 알고리즘 (한국 표준) 🆕
│   ├── raft_store.go       # Raft 분산 저장소
│   ├── fsm.go              # Raft FSM 구현
│   ├── cluster_manager.go  # 클러스터 관리 API
│   └── rest_api.go         # REST API 핸들러
├── cmd/
│   ├── kmip-server/        # 서버 실행 파일
│   │   └── main.go
│   ├── kmip-client/        # KMIP 클라이언트 예제
│   │   └── main.go
│   └── kmip-rest-client/   # REST API 클라이언트
│       └── main.go
├── scripts/
│   ├── generate_certs.sh   # 테스트용 인증서 생성
│   ├── test_raft_cluster.sh # Raft 클러스터 테스트
│   └── rest_api_examples.sh # REST API 예제
├── go.mod
├── README.md
├── QUICKSTART.md           # 빠른 시작 가이드
├── RAFT_GUIDE.md           # Raft 클러스터 가이드
├── REST_API.md             # REST API 문서
├── ASYMMETRIC_KEYS.md      # RSA/ECDSA 키 가이드
└── KOREAN_ALGORITHMS.md    # SEED/ARIA 가이드 🆕
```

## 설치 및 빌드

### 1. 의존성 설치

```bash
go mod download
```

### 2. 서버 빌드

```bash
go build -o kmip-server ./cmd/kmip-server
```

### 3. 클라이언트 빌드 (선택)

```bash
go build -o kmip-client ./cmd/kmip-client
```

## 사용법

### 1. 테스트용 인증서 생성

```bash
chmod +x scripts/generate_certs.sh
./scripts/generate_certs.sh
```

생성되는 파일:
- `ca.crt`, `ca.key` - CA 인증서 및 키
- `server.crt`, `server.key` - 서버 인증서 및 키
- `client.crt`, `client.key` - 클라이언트 인증서 및 키

### 2. 서버 실행

#### 기본 실행 (인메모리 저장소)
```bash
./kmip-server -cert server.crt -key server.key
```

#### Raft 분산 저장소 사용 (단일 노드)
```bash
./kmip-server \
  -use-raft \
  -bootstrap \
  -cert server.crt \
  -key server.key
```

#### Raft 클러스터 구성 (3노드 예제)

**노드 1 (리더, 부트스트랩):**
```bash
./kmip-server \
  -use-raft \
  -bootstrap \
  -node-id node1 \
  -raft-addr 127.0.0.1:7000 \
  -data-dir ./data/node1 \
  -addr :5696 \
  -http-addr :8080 \
  -cert server.crt \
  -key server.key
```

**노드 2:**
```bash
./kmip-server \
  -use-raft \
  -node-id node2 \
  -raft-addr 127.0.0.1:7001 \
  -data-dir ./data/node2 \
  -addr :5697 \
  -http-addr :8081 \
  -cert server.crt \
  -key server.key
```

**노드 3:**
```bash
./kmip-server \
  -use-raft \
  -node-id node3 \
  -raft-addr 127.0.0.1:7002 \
  -data-dir ./data/node3 \
  -addr :5698 \
  -http-addr :8082 \
  -cert server.crt \
  -key server.key
```

**클러스터에 노드 추가:**
```bash
# 노드 2 추가
curl -X POST http://localhost:8080/cluster/join \
  -H "Content-Type: application/json" \
  -d '{"node_id": "node2", "addr": "127.0.0.1:7001"}'

# 노드 3 추가
curl -X POST http://localhost:8080/cluster/join \
  -H "Content-Type: application/json" \
  -d '{"node_id": "node3", "addr": "127.0.0.1:7002"}'
```

상세한 Raft 클러스터 가이드는 [RAFT_GUIDE.md](RAFT_GUIDE.md)를 참고하세요.

### 3. 클라이언트 테스트

#### KMIP 클라이언트 (TTLV 프로토콜)

**Query 요청 (서버 정보 조회)**
```bash
./kmip-client -op query
```

**DiscoverVersions 요청 (지원 버전 조회)**
```bash
./kmip-client -op discover
```

**Create 요청 (대칭 키 생성)**
```bash
./kmip-client -op create
```

**클라이언트 인증 사용**
```bash
./kmip-client -op query -cert client.crt -key client.key -ca ca.crt
```

#### REST API 클라이언트 🆕

**REST API 활성화하여 서버 실행:**
```bash
./kmip-server -cert server.crt -key server.key -enable-rest -rest-addr :9090
```

**REST API 클라이언트 사용:**
```bash
# 서버 정보 조회
./kmip-rest-client -op info

# 지원 버전 조회
./kmip-rest-client -op versions

# 대칭 키 생성 (AES)
./kmip-rest-client -op create -type symmetric -algo AES -length 256

# 512비트 대칭 키 (양자 컴퓨터 대비)
./kmip-rest-client -op create -type symmetric -algo AES -length 512

# 한국 표준 알고리즘 (SEED)
./kmip-rest-client -op create -type symmetric -algo SEED -length 128

# 한국 표준 알고리즘 (ARIA-512)
./kmip-rest-client -op create -type symmetric -algo ARIA -length 512

# RSA 키 쌍 생성 (표준)
./kmip-rest-client -op createkeypair -algo RSA -length 2048

# RSA 키 쌍 생성 (극한 보안, 8192비트)
./kmip-rest-client -op createkeypair -algo RSA -length 8192

# ECDSA 키 쌍 생성
./kmip-rest-client -op createkeypair -algo ECDSA -length 256

# ECDSA P-521 (최고 보안)
./kmip-rest-client -op createkeypair -algo ECDSA -length 521

# 키 목록 조회
./kmip-rest-client -op list

# 특정 키 조회
./kmip-rest-client -op get -id <key-id>

# 키 삭제
./kmip-rest-client -op delete -id <key-id>
```

**cURL 사용:**
```bash
# 대칭 키 생성 (AES-256)
curl -X POST http://localhost:9090/api/v1/keys \
  -H "Content-Type: application/json" \
  -d '{"key_type":"symmetric","algorithm":"AES","length":256}'

# AES-512 (양자 대비)
curl -X POST http://localhost:9090/api/v1/keys \
  -H "Content-Type: application/json" \
  -d '{"key_type":"symmetric","algorithm":"AES","length":512}'

# SEED-512 키 생성
curl -X POST http://localhost:9090/api/v1/keys \
  -H "Content-Type: application/json" \
  -d '{"key_type":"symmetric","algorithm":"SEED","length":512}'

# ARIA-512 키 생성
curl -X POST http://localhost:9090/api/v1/keys \
  -H "Content-Type: application/json" \
  -d '{"key_type":"symmetric","algorithm":"ARIA","length":512}'

# RSA-2048 키 쌍 생성
curl -X POST http://localhost:9090/api/v1/keypairs \
  -H "Content-Type: application/json" \
  -d '{"algorithm":"RSA","length":2048}'

# RSA-8192 키 쌍 생성 (극한 보안)
curl -X POST http://localhost:9090/api/v1/keypairs \
  -H "Content-Type: application/json" \
  -d '{"algorithm":"RSA","length":8192}'

# ECDSA P-256 키 쌍 생성
curl -X POST http://localhost:9090/api/v1/keypairs \
  -H "Content-Type: application/json" \
  -d '{"algorithm":"ECDSA","length":256}'

# ECDSA P-521 키 쌍 생성
curl -X POST http://localhost:9090/api/v1/keypairs \
  -H "Content-Type: application/json" \
  -d '{"algorithm":"ECDSA","length":521}'

# 키 목록 조회
curl http://localhost:9090/api/v1/keys

# 서버 정보
curl http://localhost:9090/api/v1/server/info
```

상세한 REST API 문서는 [REST_API.md](REST_API.md)를 참고하세요.

## 지원하는 KMIP 작업

현재 구현된 작업:

| 작업 | 코드 | 설명 |
|------|------|------|
| Create | 0x00000001 | 새로운 대칭 키 생성 (AES, 3DES, DES, SEED, ARIA) |
| CreateKeyPair | 0x00000002 | 비대칭 키 쌍 생성 (RSA, ECDSA) |
| **Register** | 0x00000003 | **외부 키 등록** 🆕 |
| **Rekey** | 0x00000004 | **키 재생성 (로테이션)** 🆕 |
| **Locate** | 0x00000008 | **속성/이름으로 키 검색** 🆕 |
| Get | 0x0000000A | 키 조회 |
| **GetAttributes** | 0x0000000B | **키 속성 조회** 🆕 |
| **AddAttribute** | 0x0000000D | **키 속성 추가** 🆕 |
| **ModifyAttribute** | 0x0000000E | **키 속성 수정** 🆕 |
| **DeleteAttribute** | 0x0000000F | **키 속성 삭제** 🆕 |
| Destroy | 0x00000014 | 키 삭제 |
| Query | 0x00000018 | 서버 정보 및 기능 조회 |
| DiscoverVersions | 0x0000001E | 지원되는 KMIP 버전 조회 |

**총 13개 작업 지원** (7개 신규 추가)

## 지원하는 암호화 알고리즘

### 대칭 키 알고리즘
- **AES** (128, 192, 256, **512** 비트) 🆕
- **3DES** (168 비트)
- **DES** (56 비트)
- **SEED** (128, 256, **512** 비트) - 한국 표준 🆕
- **ARIA** (128, 192, 256, **512** 비트) - 한국 표준 🆕

### 비대칭 키 알고리즘
- **RSA** (**512-8192** 비트, 권장: 2048+) 🆕
- **ECDSA** (**P-192**, P-224, P-256, P-384, P-521) 🆕

### 확장 지원
- 512비트 대칭 키: 양자 컴퓨터 대비
- RSA 8192비트: 극한 보안
- ECDSA P-192: 레거시 호환

상세한 정보:
- RSA/ECDSA: [ASYMMETRIC_KEYS.md](ASYMMETRIC_KEYS.md)
- SEED/ARIA: [KOREAN_ALGORITHMS.md](KOREAN_ALGORITHMS.md)
- 확장 키 길이: [EXTENDED_KEY_LENGTHS.md](EXTENDED_KEY_LENGTHS.md) 🆕

## Raft 클러스터 관리 API

Raft 모드로 실행 시 HTTP 관리 API 사용 가능 (기본 포트: 8080)

### 클러스터 상태 조회
```bash
curl http://localhost:8080/cluster/status
```

### Raft 통계 조회
```bash
curl http://localhost:8080/cluster/stats
```

### 노드 추가
```bash
curl -X POST http://localhost:8080/cluster/join \
  -H "Content-Type: application/json" \
  -d '{"node_id": "node2", "addr": "127.0.0.1:7001"}'
```

### 노드 제거
```bash
curl -X POST http://localhost:8080/cluster/leave \
  -H "Content-Type: application/json" \
  -d '{"node_id": "node2"}'
```

## KMIP 프로토콜 버전

지원하는 버전:
- KMIP 1.0 (2010)
- KMIP 1.1
- KMIP 1.2
- KMIP 1.3
- KMIP 1.4
- KMIP 2.0 (2016)
- KMIP 2.1 (2020)
- KMIP 3.0 (2024) - 최신

각 버전은 DiscoverVersions 작업을 통해 협상 가능합니다.

## 보안 고려사항

### TLS 설정
- 최소 TLS 1.2 사용
- 강력한 암호 스위트 사용:
  - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
  - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
  - TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
  - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256

### 프로덕션 환경
⚠️ 이 구현은 학습 및 테스트 목적입니다. 프로덕션 환경에서는 다음을 고려하세요:

1. **분산 저장소**: Raft 클러스터 사용 권장 (3-5 노드)
2. **접근 제어**: 사용자 인증 및 권한 관리 구현
3. **감사 로그**: 모든 키 작업에 대한 상세 로그
4. **HSM 통합**: 하드웨어 보안 모듈과 통합
5. **키 백업**: 자동 스냅샷 및 백업 메커니즘
6. **성능 최적화**: 동시 연결 처리 개선
7. **모니터링**: Raft 상태, 로그 지연, 디스크 사용량 모니터링

## Raft 분산 저장소 장점

### 고가용성 (High Availability)
- 노드 장애 시 자동 페일오버
- 3노드 클러스터: 1개 노드 실패 허용
- 5노드 클러스터: 2개 노드 실패 허용

### 강한 일관성 (Strong Consistency)
- 과반수 합의를 통한 데이터 일관성 보장
- 모든 노드가 동일한 순서로 명령 실행
- 네트워크 분할 시에도 데이터 무결성 유지

### 내구성 (Durability)
- 모든 쓰기 작업이 디스크에 영구 저장
- 자동 스냅샷 및 로그 관리
- 노드 재시작 시 상태 복구

### 확장성 (Scalability)
- 읽기 부하를 여러 노드로 분산 가능
- 클러스터 크기 동적 조정
- 리더 선출 및 자동 재구성

## 확장 가능한 기능

추가 구현 가능한 KMIP 기능:

### 추가 작업
- CreateKeyPair - 비대칭 키 쌍 생성
- Register - 외부 키 등록
- Activate - 키 활성화
- Revoke - 키 폐기
- Encrypt/Decrypt - 암호화/복호화
- Sign/Verify - 서명/검증
- MAC/MACVerify - MAC 생성/검증

### 추가 객체 타입
- PublicKey - 공개 키
- PrivateKey - 개인 키
- Certificate - 인증서
- SecretData - 비밀 데이터
- OpaqueObject - 불투명 객체

### KMIP 3.0 특징
- Post-Quantum Cryptography (PQC) 지원
  - ML-KEM (Module-Lattice-based Key Encapsulation)
  - ML-DSA (Module-Lattice-based Digital Signature Algorithm)
  - SLH-DSA (Stateless Hash-based Digital Signature Algorithm)
- System/User 객체 분류
- 향상된 Unique Identifier 지원

## 개발 및 테스트

### 단위 테스트 실행
```bash
go test ./kmip/...
```

### 코드 포맷팅
```bash
go fmt ./...
```

### 정적 분석
```bash
go vet ./...
```

## 참고 문서

- [OASIS KMIP Specification](https://docs.oasis-open.org/kmip/)
- [KMIP 3.0 Specification](https://docs.oasis-open.org/kmip/kmip-spec/v3.0/)
- [KMIP Wikipedia](https://en.wikipedia.org/wiki/Key_Management_Interoperability_Protocol)

## 라이선스

이 프로젝트는 MIT 라이선스 하에 배포됩니다.

## 기여

버그 리포트, 기능 제안, Pull Request를 환영합니다!

## 문의

이슈가 있으시면 GitHub Issues를 통해 문의해주세요.
