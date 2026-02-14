# 🌐 클러스터 간 복제 (Cross-Cluster Replication) 가이드

## 개요

**클러스터 간 복제**는 서로 다른 지역이나 데이터센터에 있는 독립적인 KMIP 클러스터 간에 데이터를 복제하는 기능입니다.

### 단일 클러스터 vs 클러스터 간 복제

| 구분 | 단일 클러스터 (Raft) | 클러스터 간 복제 |
|------|----------------------|------------------|
| 범위 | 하나의 클러스터 내부 | 여러 클러스터 간 |
| 노드 | 같은 네트워크 | 다른 데이터센터/지역 |
| 용도 | 고가용성 (HA) | 재해 복구 (DR), 멀티 리전 |
| 지연 | 낮음 (ms) | 높음 (수십~수백 ms) |
| 일관성 | 강한 일관성 | 최종 일관성 |
| 예시 | 서울 DC 내 3노드 | 서울 ↔ 부산 클러스터 |

## 🎯 사용 시나리오

### 시나리오 1: 재해 복구 (DR)

```
┌─────────────────┐        ┌─────────────────┐
│ Production      │        │ DR Site         │
│ (서울)          │ ────>  │ (부산)          │
│ Cluster-Seoul   │  Push  │ Cluster-Busan   │
└─────────────────┘        └─────────────────┘
```

**설정:**
```yaml
# 서울 (Primary)
cross_cluster_replication:
  mode: "push"
  remote_clusters:
    - id: "cluster-busan"
      endpoints: ["https://busan.company.com:9090"]
```

### 시나리오 2: 멀티 리전 (양방향)

```
┌────────────┐           ┌────────────┐
│ US East    │  <─────>  │ EU West    │
└────────────┘           └────────────┘
      │                         │
      │  <──────────────────>   │
      │                         │
   ┌────────────────────────────┐
   │     Asia Pacific          │
   └────────────────────────────┘
```

**설정:**
```yaml
cross_cluster_replication:
  mode: "bidirectional"
  remote_clusters:
    - id: "cluster-eu"
      bidirectional: true
    - id: "cluster-ap"
      bidirectional: true
```

### 시나리오 3: Hub-and-Spoke

```
           ┌──────────┐
      ┌──> │ Spoke 1  │
      │    └──────────┘
┌──────────┐
│   Hub    │
│ (본사)   │
└──────────┘
      │    ┌──────────┐
      └──> │ Spoke 2  │
           └──────────┘
```

**용도:** 본사와 지사 간 키 배포

## 🚀 빠른 시작

### 1단계: 서울 클러스터 설정

```bash
# 서울 클러스터 시작 (Raft로 3노드)
make cluster-start-quorum

# 클러스터 간 복제 활성화
curl -X POST http://localhost:9090/api/v1/replication/clusters \
  -H "Content-Type: application/json" \
  -d '{
    "id": "cluster-busan",
    "name": "Busan Cluster",
    "endpoints": ["http://busan-server:9090"],
    "enabled": true,
    "priority": 1,
    "bidirectional": false,
    "api_key": "secret-key-123"
  }'
```

### 2단계: 부산 클러스터 설정

```bash
# 부산에서도 클러스터 시작
# (다른 서버에서)
./scripts/start_cluster.sh quorum

# 부산에서 수신 대기 (자동)
```

### 3단계: 복제 테스트

```bash
# 서울에 키 생성
curl -X POST http://seoul:9090/api/v1/keys \
  -d '{"algorithm":"AES","length":256}'

# 복제 확인 (5초 후)
sleep 5

# 부산에서 키 확인
curl http://busan:9090/api/v1/keys
# ✅ 서울에서 생성한 키가 자동으로 복제됨
```

## 📋 복제 모드

### Push 모드 (단방향 → 복제)

**특징:**
- 로컬 → 원격 단방향
- 소스 클러스터가 주도
- DR, 백업에 적합

**설정:**
```go
config := &CrossClusterConfig{
    ReplicationMode: CrossReplicationModePush,
}
ccr := NewCrossClusterReplication(store, config)

cluster := RemoteCluster{
    ID:       "cluster-dr",
    Endpoints: []string{"https://dr.company.com:9090"},
}
ccr.AddRemoteCluster(cluster)
```

### Pull 모드 (← 단방향 복제)

**특징:**
- 원격 → 로컬 단방향
- 대상 클러스터가 주도
- 중앙 집중화에 적합

**설정:**
```go
config := &CrossClusterConfig{
    ReplicationMode: CrossReplicationModePull,
}

// 주기적으로 Pull
ccr.SyncFromRemote("cluster-source")
```

### Bidirectional 모드 (양방향 ↔ 복제)

**특징:**
- 양방향 복제
- 두 클러스터가 동등
- 멀티 리전에 적합

**주의:** 충돌 해결 필요

**설정:**
```go
config := &CrossClusterConfig{
    ReplicationMode:  CrossReplicationModeBidirectional,
    ConflictStrategy: ConflictStrategyLastWriteWins,
}

cluster := RemoteCluster{
    ID:            "cluster-other",
    Bidirectional: true,
}
```

## 🔧 충돌 해결 전략

### Last-Write-Wins (권장)

가장 최근에 수정된 것이 승리

```yaml
conflict_strategy: "last-write-wins"
```

**장점:** 간단, 자동
**단점:** 데이터 손실 가능

### Source-Wins

소스 클러스터 우선

```yaml
conflict_strategy: "source-wins"
```

**용도:** DR (Production → Backup)

### Target-Wins

대상 클러스터 우선

```yaml
conflict_strategy: "target-wins"
```

**용도:** Hub-and-Spoke (Spoke → Hub)

### Manual

수동 해결 (로그에 기록)

```yaml
conflict_strategy: "manual"
```

**용도:** 중요한 데이터

## 📊 API 사용법

### 원격 클러스터 추가

```bash
curl -X POST http://localhost:9090/api/v1/replication/clusters \
  -H "Content-Type: application/json" \
  -d '{
    "id": "cluster-remote",
    "name": "Remote Cluster",
    "endpoints": [
      "https://remote-node1:9090",
      "https://remote-node2:9090",
      "https://remote-node3:9090"
    ],
    "enabled": true,
    "priority": 1,
    "bidirectional": false,
    "api_key": "your-api-key",
    "tls_enabled": true
  }'
```

### 클러스터 목록 조회

```bash
curl http://localhost:9090/api/v1/replication/clusters
```

**응답:**
```json
{
  "clusters": [
    {
      "id": "cluster-remote",
      "name": "Remote Cluster",
      "endpoints": ["https://remote:9090"],
      "enabled": true,
      "status": "active",
      "last_sync": "2024-02-10T12:00:00Z",
      "error_count": 0
    }
  ],
  "total": 1
}
```

### 복제 상태 확인

```bash
curl http://localhost:9090/api/v1/replication/status
```

**응답:**
```json
{
  "local_cluster": "cluster-seoul",
  "clusters": [...],
  "summary": {
    "total": 2,
    "active": 2,
    "failed": 0,
    "errors": 0
  }
}
```

### 수동 동기화

```bash
# Pull
curl -X POST http://localhost:9090/api/v1/replication/sync \
  -d '{"cluster_id":"cluster-remote","direction":"pull"}'

# Push
curl -X POST http://localhost:9090/api/v1/replication/sync \
  -d '{"cluster_id":"cluster-remote","direction":"push"}'
```

### 클러스터 제거

```bash
curl -X DELETE http://localhost:9090/api/v1/replication/clusters \
  -d '{"cluster_id":"cluster-remote"}'
```

## 🔐 보안

### API 키 인증

```go
cluster := RemoteCluster{
    APIKey: "secure-random-key-12345",
}
```

**요청 시:**
```
Authorization: Bearer secure-random-key-12345
```

### TLS 암호화

```yaml
remote_clusters:
  - id: "cluster-secure"
    endpoints: ["https://secure.company.com:9090"]
    tls_enabled: true
```

### 전송 암호화

```yaml
cross_cluster_replication:
  enable_encryption: true
  enable_compression: true
```

## 📈 성능 튜닝

### 배치 크기

```yaml
batch_size: 100        # 작은 배치 (지연 낮음)
batch_size: 1000       # 큰 배치 (처리량 높음)
```

### 배치 간격

```yaml
batch_interval: "1s"   # 빠른 복제 (지연 낮음)
batch_interval: "30s"  # 느린 복제 (부하 낮음)
```

### 재시도

```yaml
retry_attempts: 3
retry_backoff: "1s"    # 1s, 2s, 3s
```

## 🧪 테스트 시나리오

### 시나리오 1: 단방향 복제 테스트

```bash
# 1. 서울 클러스터 시작
cd seoul
make cluster-start-quorum

# 2. 부산 클러스터 시작
cd busan
make cluster-start-quorum

# 3. 서울에서 부산 클러스터 등록
curl -X POST http://seoul:9090/api/v1/replication/clusters \
  -d '{"id":"cluster-busan","endpoints":["http://busan:9090"]}'

# 4. 서울에 키 생성
curl -X POST http://seoul:9090/api/v1/keys \
  -d '{"algorithm":"AES","length":256}'

# 5. 부산에서 확인 (5초 후)
sleep 5
curl http://busan:9090/api/v1/keys
```

### 시나리오 2: 양방향 복제 테스트

```bash
# 1. US 클러스터에서 EU 등록
curl -X POST http://us:9090/api/v1/replication/clusters \
  -d '{
    "id":"cluster-eu",
    "endpoints":["http://eu:9090"],
    "bidirectional":true
  }'

# 2. EU 클러스터에서 US 등록
curl -X POST http://eu:9090/api/v1/replication/clusters \
  -d '{
    "id":"cluster-us",
    "endpoints":["http://us:9090"],
    "bidirectional":true
  }'

# 3. US에 키 생성
curl -X POST http://us:9090/api/v1/keys \
  -d '{"algorithm":"AES","length":256}'

# 4. EU에서 확인
curl http://eu:9090/api/v1/keys

# 5. EU에 키 생성
curl -X POST http://eu:9090/api/v1/keys \
  -d '{"algorithm":"SEED","length":128}'

# 6. US에서 확인
curl http://us:9090/api/v1/keys
```

### 시나리오 3: 장애 복구 테스트

```bash
# 1. Production에 키 100개 생성
for i in {1..100}; do
  curl -s -X POST http://prod:9090/api/v1/keys \
    -d '{"algorithm":"AES","length":256}' > /dev/null
done

# 2. DR 클러스터에서 확인
sleep 10
curl http://dr:9090/api/v1/keys | jq '.total'
# 예상: 100

# 3. Production 다운
pkill -f "kmip-server.*prod"

# 4. DR 클러스터로 전환
# 애플리케이션 설정 변경: prod -> dr

# 5. DR에서 정상 작동 확인
curl http://dr:9090/api/v1/keys
```

## 🎯 베스트 프랙티스

### 1. 토폴로지 선택

**같은 DC:** Raft만 사용 (클러스터 간 복제 불필요)
```
✅ Raft: Node1, Node2, Node3 (같은 DC)
```

**다른 DC:** 각 DC에 Raft 클러스터 + 클러스터 간 복제
```
DC1: Raft (Node1-3) ──> DC2: Raft (Node4-6)
```

### 2. 복제 모드 선택

| 용도 | 모드 | 충돌 전략 |
|------|------|-----------|
| DR | Push | source-wins |
| 멀티 리전 | Bidirectional | last-write-wins |
| Hub-Spoke | Bidirectional | manual |
| 백업 | Push | source-wins |

### 3. 성능 고려사항

**네트워크 대역폭:**
- 10Mbps: batch_size=50, interval=30s
- 100Mbps: batch_size=200, interval=10s
- 1Gbps: batch_size=1000, interval=5s

**지연시간:**
- <10ms: interval=1s (거의 실시간)
- 10-50ms: interval=5s
- >100ms: interval=30s

### 4. 모니터링

```bash
# 정기적으로 상태 확인
*/5 * * * * curl http://localhost:9090/api/v1/replication/status

# 에러 알림
if [ $failed_count -gt 0 ]; then
  send_alert "Replication failed!"
fi
```

## 🔍 트러블슈팅

### 문제 1: 복제 지연

**증상:** 키가 원격 클러스터에 늦게 도착

**해결:**
```yaml
# 배치 간격 줄이기
batch_interval: "1s"

# 배치 크기 줄이기
batch_size: 50
```

### 문제 2: 복제 실패

**증상:** status="failed"

**확인:**
```bash
# 네트워크 연결
curl https://remote:9090/health

# API 키 확인
curl https://remote:9090/api/v1/keys \
  -H "Authorization: Bearer your-api-key"
```

### 문제 3: 충돌 발생

**증상:** 양방향 복제에서 데이터 불일치

**해결:**
```yaml
# 충돌 전략 변경
conflict_strategy: "last-write-wins"

# 또는 수동 해결
conflict_strategy: "manual"
```

## 📚 참고 문서

- [단일 클러스터 복제](COMPLETE_REPLICATION_GUIDE.md)
- [Raft 가이드](RAFT_GUIDE.md)
- [REST API](REST_API.md)

## 🎉 요약

```bash
# 1. 각 지역에 Raft 클러스터 구성
make cluster-start-quorum

# 2. 원격 클러스터 등록
curl -X POST /api/v1/replication/clusters -d {...}

# 3. 자동으로 복제됨!
```

**클러스터 간 복제로 글로벌 고가용성을 달성하세요!** 🌐
