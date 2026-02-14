# 🚀 KMIP Raft 복제 완전 가이드

## ✅ 완료된 기능

**설정 기반 Raft 복제 시스템이 완전히 구현되었습니다!**

### 주요 기능

- ✅ **3가지 복제 모드**: Quorum (과반수), Sync (동기), Async (비동기)
- ✅ **설정 파일 지원**: YAML, JSON
- ✅ **커맨드 라인 설정**: 플래그로 모든 옵션 제어
- ✅ **자동 재시도**: 실패 시 재시도 및 백오프
- ✅ **로컬 모드**: 복제 비활성화 옵션
- ✅ **완전한 자동화**: 클러스터 시작/중지/테스트 스크립트

## 📦 빠른 시작

### 1단계: 빌드

```bash
make build
make certs
```

### 2단계: 클러스터 시작

```bash
# Quorum 모드 (권장)
make cluster-start-quorum

# 또는
./scripts/start_cluster.sh quorum
```

**자동으로 3개 노드가 시작됩니다:**
- Node 1 (리더): REST :9090, KMIP :5696, Raft :7000
- Node 2 (팔로워): REST :9091, KMIP :5697, Raft :7001
- Node 3 (팔로워): REST :9092, KMIP :5698, Raft :7002

### 3단계: 복제 테스트

```bash
make cluster-test
```

**테스트 내용:**
1. Node 1에 키 생성
2. Node 2, 3에서 키 자동 복제 확인
3. 여러 키 생성 및 일관성 확인
4. 키 삭제 및 복제 확인

## 🎯 사용 방법

### 방법 1: Makefile 사용 (가장 쉬움)

```bash
# Quorum 모드로 시작
make cluster-start-quorum

# Sync 모드로 시작
make cluster-start-sync

# Async 모드로 시작
make cluster-start-async

# 클러스터 중지
make cluster-stop

# 복제 테스트
make cluster-test

# 로그 확인
make cluster-logs

# 상태 확인
make cluster-status
```

### 방법 2: 스크립트 직접 실행

```bash
# 시작
./scripts/start_cluster.sh quorum

# 중지
./scripts/stop_cluster.sh

# 테스트
./scripts/test_replication.sh
```

### 방법 3: 수동 설정

**Node 1 (리더):**
```bash
./kmip-server \
  -node-id node-1 \
  -raft-addr 127.0.0.1:7000 \
  -data-dir ./data/node-1 \
  -bootstrap \
  -use-raft \
  -replication true \
  -replication-mode quorum \
  -replication-factor 3 \
  -min-replicas 2 \
  -enable-rest \
  -rest-addr :9090
```

**Node 2, 3 (팔로워):**
```bash
./kmip-server \
  -node-id node-2 \
  -raft-addr 127.0.0.1:7001 \
  -data-dir ./data/node-2 \
  -use-raft \
  -replication true \
  -replication-mode quorum \
  -replication-factor 3 \
  -min-replicas 2 \
  -enable-rest \
  -rest-addr :9091
```

**클러스터에 추가:**
```bash
curl -X POST http://localhost:8080/join \
  -d '{"id":"node-2","address":"127.0.0.1:7001"}'
```

### 방법 4: YAML 설정 파일

**config/node1.yaml:**
```yaml
node:
  id: "node-1"
  bind_addr: "127.0.0.1:7000"
  data_dir: "./data/node-1"
  bootstrap: true

replication:
  enabled: true
  factor: 3
  min_replicas: 2
  mode: "quorum"
  consistency: "strong"

initial_peers:
  - id: "node-2"
    address: "127.0.0.1:7001"
  - id: "node-3"
    address: "127.0.0.1:7002"
```

**실행:**
```bash
./kmip-server -config config/node1.yaml -enable-rest -rest-addr :9090
```

## 🔄 복제 모드 상세

### Quorum 모드 (권장) ⭐

**설정:**
```bash
./scripts/start_cluster.sh quorum
```

**특징:**
- 과반수 노드 응답 필요 (3노드 중 2개)
- 균형잡힌 성능과 안전성
- 1개 노드 장애 허용
- **프로덕션 권장**

**로그 출력:**
```
[RAFT:node-1] 📋 Replication Mode: QUORUM (wait for majority)
[RAFT:node-1] 📊 Replication Factor: 3, Min Replicas: 2
```

### Sync 모드 (최고 안전성)

**설정:**
```bash
./scripts/start_cluster.sh sync
```

**특징:**
- 모든 노드 응답 필요
- 최고 데이터 안전성
- 가장 느린 성능
- 한 노드라도 실패하면 쓰기 실패

**사용 사례:**
- 금융 거래
- 의료 데이터
- 규제 준수 필요

### Async 모드 (최고 성능)

**설정:**
```bash
./scripts/start_cluster.sh async
```

**특징:**
- 리더만 응답 후 즉시 반환
- 최고 성능
- 리더 장애 시 데이터 손실 가능

**사용 사례:**
- 로그 수집
- 메트릭 저장
- 임시 데이터

## 📊 복제 모드 비교표

| 항목 | Quorum | Sync | Async |
|------|--------|------|-------|
| ACK 필요 | 2/3 | 3/3 | 1/3 |
| 쓰기 지연 | 중간 | 높음 | 낮음 |
| 데이터 안전성 | 높음 | 최고 | 낮음 |
| 노드 장애 허용 | 1개 | 0개 | 2개 |
| 처리량 | 중간 | 낮음 | 높음 |
| 프로덕션 적합 | ✅ | ⚠️ | ❌ |

## 🧪 테스트 시나리오

### 시나리오 1: 기본 복제 테스트

```bash
# 클러스터 시작
make cluster-start-quorum

# Node 1에 키 생성
curl -X POST http://localhost:9090/api/v1/keys \
  -H "Content-Type: application/json" \
  -d '{"algorithm":"AES","length":256}'

# 응답 예: {"key_id":"abc123...","status":"created"}

# Node 2에서 확인 (자동 복제)
curl http://localhost:9091/api/v1/keys

# Node 3에서도 확인
curl http://localhost:9092/api/v1/keys
```

### 시나리오 2: 노드 장애 테스트

```bash
# Node 3 종료
pkill -f "kmip-server.*node-3"

# 여전히 동작 (Quorum: 2/3 필요)
curl -X POST http://localhost:9090/api/v1/keys \
  -d '{"algorithm":"AES","length":256}'

# Node 3 재시작
./kmip-server -node-id node-3 ... &

# 자동으로 동기화됨
```

### 시나리오 3: 성능 벤치마크

```bash
# 100개 키 생성 (Quorum)
time for i in {1..100}; do
  curl -s -X POST http://localhost:9090/api/v1/keys \
    -d '{"algorithm":"AES","length":256}' > /dev/null
done

# Async 모드와 비교
make cluster-stop
make cluster-start-async

time for i in {1..100}; do
  curl -s -X POST http://localhost:9090/api/v1/keys \
    -d '{"algorithm":"AES","length":256}' > /dev/null
done
```

## 📈 모니터링

### 클러스터 상태 확인

```bash
# 리더 확인
curl http://localhost:8080/leader

# 멤버 목록
curl http://localhost:8080/stats

# 각 노드 상태
curl http://localhost:9090/api/v1/server/info
curl http://localhost:9091/api/v1/server/info
curl http://localhost:9092/api/v1/server/info
```

### 로그 모니터링

```bash
# 모든 노드 로그
make cluster-logs

# 개별 노드
tail -f ./data/node-1/server.log
tail -f ./data/node-2/server.log
tail -f ./data/node-3/server.log
```

### 중요 로그 메시지

```
✅ 성공 메시지:
[RAFT:node-1] ✅ Raft store initialized successfully
[RAFT:node-1] ✅ Command applied successfully

⚠️ 재시도:
[RAFT:node-1] ⏳ Retry attempt 1/3 after 100ms
[RAFT:node-1] ⚠️  Apply failed: timeout, retrying...

❌ 에러:
[RAFT:node-1] not the leader - please retry on the leader node
```

## 🔧 설정 옵션

### 커맨드 라인 플래그

```bash
./kmip-server \
  -node-id node-1                    # 노드 ID
  -raft-addr 127.0.0.1:7000         # Raft 주소
  -data-dir ./data/node-1           # 데이터 디렉토리
  -bootstrap                         # 클러스터 부트스트랩
  -use-raft                          # Raft 사용
  -replication true                  # 복제 활성화
  -replication-mode quorum          # 복제 모드
  -replication-factor 3             # 복제 팩터
  -min-replicas 2                   # 최소 복제본
  -enable-rest                      # REST API
  -rest-addr :9090                  # REST 주소
```

### YAML 설정 파일

```yaml
node:
  id: "node-1"
  bind_addr: "127.0.0.1:7000"
  data_dir: "./data/node-1"
  bootstrap: true

replication:
  enabled: true
  factor: 3
  min_replicas: 2
  mode: "quorum"              # quorum, sync, async
  consistency: "strong"       # strong, eventual
  timeout_ms: 5000
  retry_attempts: 3
  retry_backoff_ms: 100

performance:
  heartbeat_timeout: "1s"
  election_timeout: "1s"
  commit_timeout: "50ms"
  snapshot_interval: "120s"
  snapshot_threshold: 8192
  max_append_entries: 64
  trailing_logs: 10240

initial_peers:
  - id: "node-2"
    address: "127.0.0.1:7001"
  - id: "node-3"
    address: "127.0.0.1:7002"
```

## 🎓 고급 사용

### 5노드 고가용성 클러스터

```bash
# 각 노드 시작
for i in {1..5}; do
  ./kmip-server \
    -node-id node-$i \
    -raft-addr 127.0.0.1:$((7000+i-1)) \
    -data-dir ./data/node-$i \
    -replication-factor 5 \
    -min-replicas 3 \
    ... &
done
```

### 프로덕션 배포 (Docker)

```dockerfile
FROM golang:1.21 as builder
WORKDIR /build
COPY . .
RUN make build

FROM alpine:latest
RUN apk add --no-cache ca-certificates
COPY --from=builder /build/kmip-server /usr/local/bin/
COPY config/raft-config.yaml /etc/kmip/

ENTRYPOINT ["/usr/local/bin/kmip-server"]
CMD ["-config", "/etc/kmip/raft-config.yaml"]
```

### Kubernetes 배포

```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: kmip-cluster
spec:
  replicas: 3
  selector:
    matchLabels:
      app: kmip
  template:
    spec:
      containers:
      - name: kmip
        image: kmip-server:latest
        args:
        - -replication-mode=quorum
        - -replication-factor=3
        - -min-replicas=2
```

## 📚 추가 문서

- **[REPLICATION_GUIDE.md](REPLICATION_GUIDE.md)** - 상세 복제 가이드
- **[RAFT_GUIDE.md](RAFT_GUIDE.md)** - Raft 클러스터 구성
- **[config/raft-config.yaml](config/raft-config.yaml)** - 설정 예제

## 🎉 완료!

Raft 복제가 완전히 구현되고 테스트되었습니다!

```bash
# 지금 바로 시작하세요!
make cluster-start-quorum
make cluster-test
```
