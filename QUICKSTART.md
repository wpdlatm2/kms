# KMIP Server - Quick Start Guide

## 빠른 시작 (5분)

### 1️⃣ 단일 노드 서버 (개발/테스트)

```bash
# 빌드 및 실행
make all
make run

# 다른 터미널에서 테스트
make test-query
```

### 2️⃣ Raft 단일 노드 (영구 저장)

```bash
make build
make certs
make run-raft

# 테스트
make test-query
```

### 3️⃣ Raft 3노드 클러스터 (프로덕션 준비)

#### 옵션 A: 자동 스크립트 사용

```bash
chmod +x scripts/test_raft_cluster.sh
./scripts/test_raft_cluster.sh
```

#### 옵션 B: Makefile 사용

```bash
# 클러스터 시작
make run-cluster

# 상태 확인
make cluster-status

# 통계 확인
make cluster-stats

# 클러스터 중지
make stop-cluster
```

#### 옵션 C: 수동 설정

**터미널 1 - 노드1 (리더):**
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

**터미널 2 - 노드2:**
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

**터미널 3 - 노드3:**
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

**터미널 4 - 클러스터 구성:**
```bash
# 노드2 추가
curl -X POST http://localhost:8080/cluster/join \
  -H "Content-Type: application/json" \
  -d '{"node_id": "node2", "addr": "127.0.0.1:7001"}'

# 노드3 추가
curl -X POST http://localhost:8080/cluster/join \
  -H "Content-Type: application/json" \
  -d '{"node_id": "node3", "addr": "127.0.0.1:7002"}'

# 상태 확인
curl http://localhost:8080/cluster/status | jq
```

## 클라이언트 테스트

### KMIP 작업 테스트 (TTLV 프로토콜)

```bash
# Query - 서버 정보 조회
./kmip-client -op query -addr localhost:5696

# DiscoverVersions - 지원 버전 조회
./kmip-client -op discover -addr localhost:5696

# Create - 대칭 키 생성
./kmip-client -op create -addr localhost:5696
```

### REST API 테스트 🆕

**REST API 서버 실행:**
```bash
# 인메모리 모드
./kmip-server -cert server.crt -key server.key -enable-rest -rest-addr :9090

# Raft 모드
./kmip-server -use-raft -bootstrap -cert server.crt -key server.key -enable-rest -rest-addr :9090
```

**CLI 클라이언트 사용:**
```bash
# 서버 정보
./kmip-rest-client -op info

# 버전 조회
./kmip-rest-client -op versions

# 키 생성
./kmip-rest-client -op create -type symmetric -algo AES -length 256

# 키 목록
./kmip-rest-client -op list

# 키 조회
./kmip-rest-client -op get -id <key-id>

# 키 삭제
./kmip-rest-client -op delete -id <key-id>
```

**cURL 사용:**
```bash
# 키 생성
curl -X POST http://localhost:9090/api/v1/keys \
  -H "Content-Type: application/json" \
  -d '{"key_type":"symmetric","algorithm":"AES","length":256}'

# 키 목록
curl http://localhost:9090/api/v1/keys | jq

# 서버 정보
curl http://localhost:9090/api/v1/server/info | jq
```

**Python으로 사용:**
```python
import requests

# 키 생성
response = requests.post('http://localhost:9090/api/v1/keys', 
    json={'key_type': 'symmetric', 'algorithm': 'AES', 'length': 256})
key_id = response.json()['key_id']
print(f"Created key: {key_id}")

# 키 조회
response = requests.get(f'http://localhost:9090/api/v1/keys/{key_id}')
print(response.json())
```

### 클러스터 관리

```bash
# 클러스터 상태
curl http://localhost:8080/cluster/status

# Raft 통계
curl http://localhost:8080/cluster/stats | jq

# 노드 제거
curl -X POST http://localhost:8080/cluster/leave \
  -H "Content-Type: application/json" \
  -d '{"node_id": "node3"}'

# 노드 재추가
curl -X POST http://localhost:8080/cluster/join \
  -H "Content-Type: application/json" \
  -d '{"node_id": "node3", "addr": "127.0.0.1:7002"}'
```

## 시나리오별 가이드

### 🔧 개발 중
```bash
# 빠른 재시작이 필요한 경우
make run  # 인메모리, 데이터 영구 저장 안됨
```

### 🧪 로컬 테스트
```bash
# 데이터 영구 저장 필요
make run-raft  # 단일 Raft 노드
```

### 🚀 프로덕션 준비
```bash
# 고가용성 클러스터
make run-cluster  # 3노드 Raft 클러스터
```

## 문제 해결

### 포트 충돌
```bash
# 기존 프로세스 확인
lsof -i :5696
lsof -i :7000
lsof -i :8080

# 모든 kmip-server 프로세스 종료
pkill -f kmip-server
```

### 클러스터 리셋
```bash
# 모든 데이터 삭제 후 재시작
make stop-cluster
make clean
make run-cluster
```

### 로그 확인
```bash
# 실시간 로그 보기
tail -f node1.log
tail -f node2.log
tail -f node3.log

# 에러 로그 필터링
grep -i error node*.log
```

### 리더 찾기
```bash
# 모든 노드 확인
for port in 8080 8081 8082; do
  echo "Port $port:"
  curl -s http://localhost:$port/cluster/status | jq
done
```

## 성능 벤치마크 (참고)

```bash
# 단일 노드 vs Raft 성능 비교

# 인메모리 (단일 노드)
# - 쓰기: ~10,000 ops/sec
# - 읽기: ~50,000 ops/sec

# Raft (3노드 클러스터)
# - 쓰기: ~1,000 ops/sec (과반수 복제 필요)
# - 읽기: ~30,000 ops/sec (리더에서 읽기)
```

## 다음 단계

1. **프로덕션 배포**: [RAFT_GUIDE.md](RAFT_GUIDE.md) 참고
2. **상세 문서**: [README.md](README.md) 참고
3. **API 문서**: KMIP 프로토콜 스펙 참고

## 자주 묻는 질문

**Q: 언제 Raft를 사용해야 하나요?**
A: 데이터 영구 저장과 고가용성이 필요한 경우. 개발/테스트는 인메모리도 충분.

**Q: 노드를 몇 개 사용해야 하나요?**
A: 3노드(1개 실패 허용) 또는 5노드(2개 실패 허용) 권장. 홀수 개 사용.

**Q: 리더가 다운되면?**
A: 자동으로 새 리더 선출 (수 초 내). 클라이언트는 재연결.

**Q: 데이터는 어디에 저장되나요?**
A: `-data-dir` 옵션으로 지정한 디렉토리. 기본값: `./data`

**Q: 백업은 어떻게 하나요?**
A: 데이터 디렉토리를 주기적으로 백업. Raft는 자동 스냅샷 생성.
