# 🚀 Raft 복제 설정 빠른 가이드

## ✅ 구현 완료

**설정 기반 Raft 복제**가 완전히 구현되었습니다!

### 주요 기능

- ✅ **3가지 복제 모드**: Quorum, Sync, Async
- ✅ **설정 파일 지원**: YAML, JSON
- ✅ **동적 설정**: 코드 또는 파일에서 로드
- ✅ **재시도 로직**: 자동 재시도 및 백오프
- ✅ **유연한 쿼럼**: 최소 복제본 수 설정 가능
- ✅ **로컬 모드**: 복제 비활성화 옵션

## 📦 복제 모드 비교

| 모드 | ACK 수 | 지연 | 안전성 | 사용 사례 |
|------|--------|------|--------|-----------|
| **Quorum** | 과반수 (2/3, 3/5) | 중간 | 높음 | **프로덕션 (권장)** |
| **Sync** | 전체 (3/3, 5/5) | 높음 | 최고 | 최고 안전성 필요 |
| **Async** | 리더만 (1) | 낮음 | 낮음 | 성능 최우선 |
| **Local** | 없음 (복제 OFF) | 최저 | 없음 | 개발/테스트 |

## 🔧 설정 방법

### 방법 1: 코드로 설정

```go
package main

import "kmip-server/kmip"

func main() {
    // Quorum 모드 (권장)
    config := &kmip.RaftConfig{
        NodeID:              "node-1",
        BindAddr:            "127.0.0.1:7000",
        DataDir:             "./data/node-1",
        Bootstrap:           true,
        ReplicationEnabled:  true,
        ReplicationFactor:   3,
        MinReplicas:         2,  // 과반수
        InitialPeers: []kmip.PeerConfig{
            {ID: "node-2", Address: "127.0.0.1:7001"},
            {ID: "node-3", Address: "127.0.0.1:7002"},
        },
    }
    
    policy := &kmip.ReplicationPolicy{
        Mode:              kmip.ReplicationModeQuorum,
        MinAcks:           2,
        TimeoutMs:         5000,
        RetryAttempts:     3,
        RetryBackoffMs:    100,
        ConsistencyLevel:  "strong",
    }
    
    store, err := kmip.NewRaftStore(config, policy)
    if err != nil {
        panic(err)
    }
    
    // 사용
    key := &kmip.SymmetricKey{...}
    store.Store(key)  // 자동으로 복제됨
}
```

### 방법 2: YAML 파일

**config/raft-config.yaml:**
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
  timeout_ms: 5000
  retry_attempts: 3
  retry_backoff_ms: 100

performance:
  heartbeat_timeout: "1s"
  election_timeout: "1s"
  commit_timeout: "50ms"
  snapshot_interval: "120s"
  snapshot_threshold: 8192

initial_peers:
  - id: "node-2"
    address: "127.0.0.1:7001"
  - id: "node-3"
    address: "127.0.0.1:7002"
```

**코드:**
```go
config, policy, err := kmip.LoadConfigFromYAML("config/raft-config.yaml")
if err != nil {
    panic(err)
}

store, err := kmip.NewRaftStore(config, policy)
```

### 방법 3: 로컬 모드 (복제 비활성화)

```go
config := &kmip.RaftConfig{
    NodeID:              "standalone",
    BindAddr:            "127.0.0.1:7000",
    DataDir:             "./data/standalone",
    ReplicationEnabled:  false,  // 복제 OFF
}

// policy는 nil 가능
store, err := kmip.NewRaftStore(config, nil)
```

## 🚀 클러스터 시작

### 3노드 클러스터 예제

**Node 1 (리더):**
```yaml
# node1-config.yaml
node:
  id: "node-1"
  bind_addr: "127.0.0.1:7000"
  data_dir: "./data/node-1"
  bootstrap: true  # 첫 노드만 true

replication:
  enabled: true
  factor: 3
  min_replicas: 2
  mode: "quorum"

initial_peers:
  - id: "node-2"
    address: "127.0.0.1:7001"
  - id: "node-3"
    address: "127.0.0.1:7002"
```

**Node 2, 3 (팔로워):**
```yaml
# node2-config.yaml, node3-config.yaml
node:
  id: "node-2"  # or "node-3"
  bind_addr: "127.0.0.1:7001"  # or 7002
  data_dir: "./data/node-2"
  bootstrap: false  # 팔로워는 false

replication:
  enabled: true
  factor: 3
  min_replicas: 2
  mode: "quorum"
```

**시작:**
```bash
# Terminal 1
./kmip-server -config node1-config.yaml -rest-port 9090

# Terminal 2
./kmip-server -config node2-config.yaml -rest-port 9091

# Terminal 3
./kmip-server -config node3-config.yaml -rest-port 9092
```

## 📊 복제 모드별 설정

### Quorum (권장)

```yaml
replication:
  enabled: true
  factor: 3
  min_replicas: 2      # 과반수
  mode: "quorum"
  consistency: "strong"
  timeout_ms: 5000
```

**특징:**
- 균형잡힌 성능과 안전성
- 1개 노드 장애 허용
- 프로덕션 권장

### Sync (최고 안전성)

```yaml
replication:
  enabled: true
  factor: 3
  min_replicas: 3      # 모든 노드
  mode: "sync"
  consistency: "strong"
  timeout_ms: 10000    # 더 긴 타임아웃
  retry_attempts: 5
```

**특징:**
- 최고 데이터 안전성
- 가장 느린 성능
- 금융, 의료 등에 적합

### Async (최고 성능)

```yaml
replication:
  enabled: true
  factor: 3
  min_replicas: 1      # 리더만
  mode: "async"
  consistency: "eventual"
  timeout_ms: 1000     # 짧은 타임아웃
```

**특징:**
- 최고 성능
- 데이터 손실 가능
- 로그, 메트릭 등에 적합

## 🔍 동작 확인

### 로그 확인

```
[RAFT:node-1] 📋 Replication Mode: QUORUM (wait for majority)
[RAFT:node-1] 📊 Replication Factor: 3, Min Replicas: 2
[RAFT:node-1] 🚀 Bootstrapping cluster with 3 nodes
[RAFT:node-1] ✅ Raft store initialized successfully
```

### 복제 테스트

```bash
# Node 1에 키 생성
curl -X POST http://localhost:9090/api/v1/keys \
  -d '{"algorithm":"AES","length":256}'

# Node 2에서 조회 (자동 복제됨)
curl http://localhost:9091/api/v1/keys

# Node 3에서도 동일한 키 확인
curl http://localhost:9092/api/v1/keys
```

### 장애 테스트

```bash
# Node 3 종료
kill <node-3-pid>

# 여전히 동작 (Quorum: 2/3 노드 필요)
curl -X POST http://localhost:9090/api/v1/keys \
  -d '{"algorithm":"AES","length":256}'

# Node 3 재시작 후 자동 동기화
./kmip-server -config node3-config.yaml
```

## 📈 성능 튜닝

### 저지연 설정

```yaml
performance:
  heartbeat_timeout: "500ms"
  election_timeout: "500ms"
  commit_timeout: "10ms"

replication:
  mode: "async"
  timeout_ms: 1000
```

### 고처리량 설정

```yaml
performance:
  max_append_entries: 128
  snapshot_threshold: 16384
  trailing_logs: 20480
```

### 안정성 우선 설정

```yaml
performance:
  snapshot_interval: "60s"
  snapshot_threshold: 4096

replication:
  mode: "sync"
  retry_attempts: 5
  timeout_ms: 10000
```

## 🎯 사용 시나리오

### 시나리오 1: 프로덕션 웹 서비스

```yaml
replication:
  enabled: true
  factor: 3
  min_replicas: 2
  mode: "quorum"
  consistency: "strong"
```

### 시나리오 2: 금융 시스템

```yaml
replication:
  enabled: true
  factor: 5
  min_replicas: 5
  mode: "sync"
  consistency: "strong"
```

### 시나리오 3: 로그 수집

```yaml
replication:
  enabled: true
  factor: 3
  min_replicas: 1
  mode: "async"
  consistency: "eventual"
```

### 시나리오 4: 로컬 개발

```yaml
replication:
  enabled: false
```

## 📚 추가 문서

- **[REPLICATION_GUIDE.md](REPLICATION_GUIDE.md)** - 상세 복제 가이드
- **[RAFT_GUIDE.md](RAFT_GUIDE.md)** - Raft 클러스터 가이드
- **[config/raft-config.yaml](config/raft-config.yaml)** - 설정 예제

## 🎉 완성!

설정 기반 Raft 복제가 완전히 구현되었습니다!
