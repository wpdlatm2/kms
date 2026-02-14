# KMIP Testing Guide

KMIP 서버의 모든 기능을 체계적으로 테스트할 수 있는 가이드입니다.

## 테스트 클라이언트

### 1. REST API 테스트 스위트 (`kmip-rest-test`)

REST API의 모든 기능을 자동으로 테스트하는 포괄적인 테스트 클라이언트입니다.

#### 특징
- ✅ 대칭 키 생성 테스트 (AES, SEED, ARIA 전체 길이)
- ✅ 비대칭 키 쌍 생성 테스트 (RSA, ECDSA 전체 범위)
- ✅ 키 관리 작업 테스트 (조회, 목록, 삭제)
- ✅ 서버 기본 기능 테스트
- ✅ 상세한 결과 리포트
- ✅ JSON 형식 결과 저장

#### 사용법

**전체 테스트 실행:**
```bash
make test-suite-rest
```

**결과 저장:**
```bash
make test-suite-rest-save
# 결과: test-results.json
```

**카테고리별 테스트:**
```bash
# 기본 기능만
./kmip-rest-test -category basic

# 대칭 키만
./kmip-rest-test -category symmetric

# 비대칭 키만
./kmip-rest-test -category asymmetric

# 관리 기능만
./kmip-rest-test -category management

# 전체
./kmip-rest-test -category all
```

**상세 모드:**
```bash
./kmip-rest-test -verbose
```

**결과 저장:**
```bash
./kmip-rest-test -verbose -output results.json
```

### 2. KMIP 버전 테스트 클라이언트 (`kmip-test-client`)

KMIP 프로토콜 버전별로 모든 기능을 테스트합니다.

#### 특징
- ✅ KMIP 1.0 ~ 3.0 모든 버전 테스트
- ✅ 버전별 호환성 확인
- ✅ 작업별 성능 측정
- ✅ 상세한 에러 리포트

#### 사용법

**모든 버전 테스트:**
```bash
make test-kmip-versions
```

**특정 버전 테스트:**
```bash
# KMIP 1.0
./kmip-test-client -version 1.0 -verbose

# KMIP 2.0
./kmip-test-client -version 2.0 -verbose

# KMIP 3.0
./kmip-test-client -version 3.0 -verbose
```

**Makefile 사용:**
```bash
make test-kmip-version VERSION=2.0
```

**결과 저장:**
```bash
./kmip-test-client -version all -output kmip-test-results.txt
```

## 테스트 시나리오

### 시나리오 1: 빠른 검증 테스트

서버가 정상 작동하는지 빠르게 확인:

```bash
# 1. 서버 시작
make run-rest

# 2. 다른 터미널에서 기본 테스트
./kmip-rest-test -category basic

# 예상 출력:
# === Basic Tests ===
# ✓ Health Check           (5.23ms)
# ✓ API Root              (3.45ms)
# ✓ Server Info           (12.34ms)
# ✓ Supported Versions    (8.76ms)
```

### 시나리오 2: 전체 기능 테스트

모든 알고리즘과 키 길이 테스트:

```bash
# 1. 서버 시작 (REST API 활성화)
make run-rest

# 2. 전체 테스트 실행
make test-suite-rest-save

# 3. 결과 확인
cat test-results.json | jq '.summary'
```

**예상 결과:**
```json
{
  "total": 45,
  "passed": 45,
  "failed": 0
}
```

### 시나리오 3: KMIP 버전 호환성 테스트

모든 KMIP 버전에서 작동 확인:

```bash
# 1. 서버 시작
make run

# 2. 버전별 테스트
make test-kmip-versions

# 예상 출력:
# Testing KMIP Version 1.0
# ✓ DiscoverVersions passed (10.23ms)
# ✓ Query passed (15.67ms)
# ✓ Create_AES_256 passed (8.34ms)
# ...
#
# Testing KMIP Version 3.0
# ✓ DiscoverVersions passed (9.87ms)
# ✓ Query passed (14.23ms)
# ...
```

### 시나리오 4: 성능 벤치마크

대량 키 생성 성능 측정:

```bash
# 커스텀 스크립트
for i in {1..100}; do
  ./kmip-rest-client -op create -algo AES -length 256
done

# 시간 측정
time for i in {1..100}; do
  curl -s -X POST http://localhost:9090/api/v1/keys \
    -H "Content-Type: application/json" \
    -d '{"algorithm":"AES","length":256}' > /dev/null
done
```

### 시나리오 5: 스트레스 테스트

동시 연결 테스트:

```bash
# 동시에 10개 클라이언트 실행
for i in {1..10}; do
  ./kmip-rest-test -category symmetric &
done
wait

echo "All concurrent tests completed"
```

### 시나리오 6: Raft 클러스터 테스트

분산 환경에서 데이터 일관성 확인:

```bash
# 1. Raft 클러스터 시작
make run-cluster

# 2. 리더 노드에 키 생성
./kmip-rest-client -op create -algo AES -length 256

# 3. 팔로워 노드에서 조회
./kmip-rest-client -addr http://localhost:9091 -op list

# 4. 데이터 일관성 확인 (모든 노드에서 동일한 키 목록)
```

## 테스트 결과 분석

### 출력 형식

**성공한 테스트:**
```
✓ Create AES-256          (12.34ms) - Create AES-256 symmetric key
```

**실패한 테스트:**
```
✗ Create RSA-8192         (2534.56ms) - Failed to generate RSA key pair
  Error: key length too large
```

### 요약 통계

```
========================================
Test Summary
========================================

Total Tests:    45
Passed:         43 (95.6%)
Failed:         2 (4.4%)
Total Duration: 5.23s

Results by Category:
  Basic          : 4/4 passed (100.0%)
  Symmetric      : 12/12 passed (100.0%)
  Asymmetric     : 7/9 passed (77.8%)
  Management     : 20/20 passed (100.0%)
```

### JSON 결과 파일

```json
{
  "timestamp": "2024-02-10T12:34:56Z",
  "summary": {
    "total": 45,
    "passed": 43,
    "failed": 2
  },
  "results": [
    {
      "Category": "Symmetric",
      "TestName": "Create AES-256",
      "Success": true,
      "Duration": 12340000,
      "Error": "",
      "Description": "Create AES-256 symmetric key"
    }
  ]
}
```

## 테스트 커버리지

### 대칭 키 알고리즘 (12개 테스트)
- ✅ AES-128, 192, 256, 512
- ✅ SEED-128, 256, 512
- ✅ ARIA-128, 192, 256, 512
- ✅ 3DES-168

### 비대칭 키 알고리즘 (9개 테스트)
- ✅ RSA-1024, 2048, 3072, 4096
- ✅ ECDSA P-192, P-224, P-256, P-384, P-521

### KMIP 작업 (6개)
- ✅ DiscoverVersions
- ✅ Query
- ✅ Create (대칭 키)
- ✅ CreateKeyPair (비대칭 키)
- ✅ Get
- ✅ Destroy

### KMIP 버전 (8개)
- ✅ KMIP 1.0, 1.1, 1.2, 1.3, 1.4
- ✅ KMIP 2.0, 2.1
- ✅ KMIP 3.0

## CI/CD 통합

### GitHub Actions 예제

```yaml
name: KMIP Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Setup Go
        uses: actions/setup-go@v2
        with:
          go-version: '1.21'
      
      - name: Build
        run: make build
      
      - name: Generate Certificates
        run: make certs
      
      - name: Start Server
        run: |
          make run-rest &
          sleep 5
      
      - name: Run Tests
        run: make test-suite-rest-save
      
      - name: Upload Results
        uses: actions/upload-artifact@v2
        with:
          name: test-results
          path: test-results.json
```

### Jenkins 예제

```groovy
pipeline {
    agent any
    
    stages {
        stage('Build') {
            steps {
                sh 'make build'
            }
        }
        
        stage('Test') {
            steps {
                sh 'make certs'
                sh 'make run-rest &'
                sh 'sleep 5'
                sh 'make test-suite-rest-save'
            }
        }
        
        stage('Publish Results') {
            steps {
                archiveArtifacts artifacts: 'test-results.json'
                junit 'test-results.json'
            }
        }
    }
}
```

## 문제 해결

### 테스트 실패 시

**1. 서버 연결 실패**
```
Error: connection refused
```
**해결:** 서버가 실행 중인지 확인
```bash
curl http://localhost:9090/health
```

**2. 인증서 오류**
```
Error: x509: certificate signed by unknown authority
```
**해결:** 인증서 재생성
```bash
make certs
```

**3. 타임아웃**
```
Error: timeout waiting for response
```
**해결:** 타임아웃 시간 증가
```bash
./kmip-rest-test -timeout 60
```

### 성능 이슈

**RSA-8192 생성이 너무 느림:**
```bash
# RSA-8192는 2-3초 소요 (정상)
# 더 빠른 테스트를 위해 RSA-4096 사용
./kmip-rest-test -category asymmetric
```

## 베스트 프랙티스

1. **정기적 테스트**: CI/CD 파이프라인에 통합
2. **버전 호환성**: 새 버전 배포 전 전체 버전 테스트
3. **성능 모니터링**: 테스트 결과 시간 추적
4. **결과 보관**: JSON 결과를 버전별로 저장
5. **자동화**: Makefile 명령 사용

## 추가 테스트 도구

### 수동 cURL 테스트

```bash
# 헬스체크
curl http://localhost:9090/health

# 키 생성
curl -X POST http://localhost:9090/api/v1/keys \
  -H "Content-Type: application/json" \
  -d '{"algorithm":"AES","length":256}'

# 키 목록
curl http://localhost:9090/api/v1/keys | jq
```

### Postman Collection

Postman 컬렉션 파일 생성:
```json
{
  "info": {
    "name": "KMIP REST API",
    "schema": "https://schema.getpostman.com/json/collection/v2.1.0/"
  },
  "item": [
    {
      "name": "Create AES-256 Key",
      "request": {
        "method": "POST",
        "url": "{{base_url}}/api/v1/keys",
        "body": {
          "mode": "raw",
          "raw": "{\"algorithm\":\"AES\",\"length\":256}"
        }
      }
    }
  ]
}
```

## 참고 자료

- [KMIP Specification](https://docs.oasis-open.org/kmip/)
- [REST API Documentation](REST_API.md)
- [Server Configuration Guide](README.md)
