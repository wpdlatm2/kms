# KMIP Server - Complete File List

## 📦 전체 파일 다운로드

**압축 파일:** `kmip-server-complete.tar.gz` (109KB)

모든 소스 코드, 문서, 스크립트가 포함되어 있습니다.

## 📂 디렉토리 구조

```
kmip-server/
├── 📄 문서 파일 (9개)
│   ├── README.md                    - 프로젝트 메인 문서
│   ├── QUICKSTART.md               - 5분 빠른 시작 가이드
│   ├── RAFT_GUIDE.md               - Raft 클러스터 가이드
│   ├── REST_API.md                 - REST API 완전한 문서
│   ├── ASYMMETRIC_KEYS.md          - RSA/ECDSA 가이드
│   ├── KOREAN_ALGORITHMS.md        - SEED/ARIA 가이드
│   ├── EXTENDED_KEY_LENGTHS.md     - 확장 키 길이 가이드
│   ├── TESTING_GUIDE.md            - 테스트 완전 가이드
│   └── go.mod                      - Go 모듈 의존성
│
├── 🔧 빌드 및 설정 (1개)
│   └── Makefile                    - 빌드 및 실행 명령
│
├── 💻 서버 코드 - kmip/ (11개)
│   ├── protocol.go                 - KMIP 프로토콜 구조체
│   ├── ttlv.go                     - TTLV 인코딩/디코딩
│   ├── server.go                   - KMIP 서버 핸들러
│   ├── store.go                    - 인메모리 저장소
│   ├── keygen.go                   - 키 생성 (AES, RSA, ECDSA, SEED, ARIA)
│   ├── seed.go                     - SEED 알고리즘 (한국 표준)
│   ├── aria.go                     - ARIA 알고리즘 (한국 표준)
│   ├── raft_store.go               - Raft 분산 저장소
│   ├── fsm.go                      - Raft FSM 구현
│   ├── cluster_manager.go          - 클러스터 관리 API
│   └── rest_api.go                 - REST API 핸들러
│
├── 🖥️  클라이언트 코드 - cmd/ (5개)
│   ├── kmip-server/main.go         - KMIP 서버 메인
│   ├── kmip-client/main.go         - KMIP 클라이언트 (TTLV)
│   ├── kmip-rest-client/main.go    - REST API 클라이언트
│   ├── kmip-rest-test/main.go      - REST API 테스트 스위트
│   └── kmip-test-client/main.go    - KMIP 버전 테스트 클라이언트
│
└── 📜 스크립트 - scripts/ (3개)
    ├── generate_certs.sh           - 테스트 인증서 생성
    ├── test_raft_cluster.sh        - Raft 클러스터 테스트
    └── rest_api_examples.sh        - REST API 예제

총 29개 파일
```

## 📊 파일 통계

| 카테고리 | 파일 수 | 설명 |
|---------|--------|------|
| 문서 | 9개 | 가이드, 튜토리얼, API 문서 |
| 서버 코드 | 11개 | KMIP 프로토콜, 암호화, 저장소 |
| 클라이언트 | 5개 | CLI 도구, 테스트 클라이언트 |
| 스크립트 | 3개 | 자동화, 테스트, 인증서 |
| 설정 | 2개 | Makefile, go.mod |

## 🎯 주요 기능별 파일

### KMIP 프로토콜
- `kmip/protocol.go` - 메시지 구조체
- `kmip/ttlv.go` - 인코딩/디코딩
- `kmip/server.go` - 요청 처리

### 암호화 알고리즘
- `kmip/keygen.go` - 통합 키 생성
- `kmip/seed.go` - SEED (한국)
- `kmip/aria.go` - ARIA (한국)

### 저장소
- `kmip/store.go` - 인메모리
- `kmip/raft_store.go` - Raft 분산
- `kmip/fsm.go` - Raft FSM

### REST API
- `kmip/rest_api.go` - HTTP 핸들러
- `cmd/kmip-rest-client/main.go` - CLI
- `REST_API.md` - 문서

### 테스트
- `cmd/kmip-rest-test/main.go` - REST 테스트
- `cmd/kmip-test-client/main.go` - KMIP 테스트
- `TESTING_GUIDE.md` - 가이드

## 🚀 빠른 시작 (압축 해제 후)

```bash
# 1. 압축 해제
tar -xzf kmip-server-complete.tar.gz
cd kmip-server/

# 2. 빌드
make build

# 3. 인증서 생성
make certs

# 4. 서버 실행
make run-rest

# 5. 테스트 (다른 터미널)
make test-suite-rest
```

## 📝 지원 기능

### 대칭 키 알고리즘
- ✅ AES (128, 192, 256, 512비트)
- ✅ SEED (128, 256, 512비트)
- ✅ ARIA (128, 192, 256, 512비트)
- ✅ 3DES (168비트)

### 비대칭 키 알고리즘
- ✅ RSA (512-8192비트)
- ✅ ECDSA (P-192, P-224, P-256, P-384, P-521)

### KMIP 버전
- ✅ KMIP 1.0, 1.1, 1.2, 1.3, 1.4
- ✅ KMIP 2.0, 2.1
- ✅ KMIP 3.0

### KMIP 작업
- ✅ Create (대칭 키)
- ✅ CreateKeyPair (비대칭 키)
- ✅ Get (키 조회)
- ✅ Destroy (키 삭제)
- ✅ Query (서버 정보)
- ✅ DiscoverVersions

### 추가 기능
- ✅ Raft 합의 알고리즘 (분산 저장소)
- ✅ REST API (HTTP/JSON)
- ✅ TLS 1.2+ 보안
- ✅ 클러스터 관리 API
- ✅ 포괄적 테스트 도구

## 📚 주요 문서

### 시작하기
1. **README.md** - 전체 프로젝트 개요
2. **QUICKSTART.md** - 5분 빠른 시작
3. **Makefile** - 모든 명령어 리스트

### 심화 가이드
4. **RAFT_GUIDE.md** - 분산 클러스터 구성
5. **REST_API.md** - HTTP API 전체 문서
6. **TESTING_GUIDE.md** - 테스트 전략

### 알고리즘별 가이드
7. **ASYMMETRIC_KEYS.md** - RSA/ECDSA 상세
8. **KOREAN_ALGORITHMS.md** - SEED/ARIA 상세
9. **EXTENDED_KEY_LENGTHS.md** - 확장 키 길이

## 🔧 시스템 요구사항

### 필수
- Go 1.21 이상
- Linux/macOS/Windows
- OpenSSL (인증서 생성용)

### 권장
- 멀티코어 CPU
- 4GB+ RAM
- SSD 스토리지
- 네트워크 연결 (클러스터 모드)

## 📦 의존성 (go.mod)

```
github.com/hashicorp/raft v1.6.1
github.com/hashicorp/raft-boltdb/v2 v2.3.0
github.com/boltdb/bolt v1.3.1
```

## 🎓 학습 경로

1. **초급**: README.md + QUICKSTART.md
2. **중급**: REST_API.md + 클라이언트 사용
3. **고급**: RAFT_GUIDE.md + 클러스터 구성
4. **전문가**: 소스 코드 분석 + 기여

## 🤝 기여 방법

1. 코드 포크
2. 기능 브랜치 생성
3. 변경사항 커밋
4. 테스트 실행 (`make test-suite-rest`)
5. Pull Request 제출

## 📄 라이선스

각 알고리즘별:
- AES, RSA, ECDSA: 공개 표준
- SEED, ARIA: 특허 없음, 자유 사용

## 🆘 지원

### 문제 발생 시
1. `QUICKSTART.md` 문제 해결 섹션 확인
2. `TESTING_GUIDE.md` 디버깅 가이드
3. GitHub Issues 생성

### 추가 학습 자료
- KMIP Spec: https://docs.oasis-open.org/kmip/
- NIST Guidelines: https://csrc.nist.gov/
- Raft Paper: https://raft.github.io/

## 🎉 완료!

모든 파일이 준비되었습니다. 압축 파일을 다운로드하고 위의 빠른 시작 가이드를 따라하세요!
