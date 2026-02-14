# Raft Replication Configuration Guide

Raft 합의 알고리즘을 사용한 설정 기반 복제 구성 가이드입니다.

## 📋 목차

1. [복제 모드](#복제-모드)
2. [설정 옵션](#설정-옵션)
3. [클러스터 구성](#클러스터-구성)
4. [성능 튜닝](#성능-튜닝)
5. [모니터링](#모니터링)

## 🔄 복제 모드

### 1. Quorum 모드 (권장)

과반수의 노드가 응답하면 커밋합니다.

**특징:**
- ✅ 균형잡힌 성능과 안전성
- ✅ CAP 정리의 CP (일관성 + 파티션 허용)
- ✅ 프로덕션 환경 권장

**설정:**
```yaml
replication:
  mode: "quorum"
  factor: 3
  min_replicas: 2      # 과반수 (3/2 = 2)
```

**동작:**
- 3노드 클러스터: 2개 노드 응답 필요
- 5노드 클러스터: 3개 노드 응답 필요
- 쓰기 지연: 중간
- 데이터 안전성: 높음

### 2. Sync 모드 (최대 안전성)

모든 노드가 응답할 때까지 대기합니다.

**특징:**
- ✅ 최대 데이터 안전성
- ❌ 가장 느린 성능
- ⚠️ 한 노드라도 실패하면 쓰기 실패

**설정:**
```yaml
replication:
  mode: "sync"
  factor: 3
  min_replicas: 3      # 모든 노드
  timeout_ms: 10000    # 긴 타임아웃
```

**동작:**
- 모든 복제본에 데이터 기록 대기
- 쓰기 지연: 높음
- 데이터 안전성: 최고

### 3. Async 모드 (최대 성능)

리더만 커밋하고 즉시 반환합니다.

**특징:**
- ✅ 최고 성능
- ❌ 데이터 손실 가능
- ⚠️ 리더 장애 시 최근 데이터 유실 가능

**설정:**
```yaml
replication:
  mode: "async"
  factor: 3
  min_replicas: 1      # 리더만
  timeout_ms: 1000     # 짧은 타임아웃
```

**동작:**
- 리더만 기록 후 즉시 반환
- 팔로워는 비동기로 복제
- 쓰기 지연: 낮음
- 데이터 안전성: 낮음

## ⚙️ 설정 옵션

### 기본 설정

```go
config := &RaftConfig{
    NodeID:              "node-1",
    BindAddr:            "127.0.0.1:7000",
    DataDir:             "./data/node-1",
    Bootstrap:           true,
    
    ReplicationEnabled:  true,
    ReplicationFactor:   3,
    MinReplicas:         2,
    
    HeartbeatTimeout:    1 * time.Second,
    ElectionTimeout:     1 * time.Second,
    CommitTimeout:       50 * time.Millisecond,
    SnapshotInterval:    20 * time.Second,
    SnapshotThreshold:   8192,
}

policy := &ReplicationPolicy{
    Mode:              ReplicationModeQuorum,
    MinAcks:           2,
    TimeoutMs:         5000,
    RetryAttempts:     3,
    RetryBackoffMs:    100,
    ConsistencyLevel:  "strong",
}
```

### 로컬 모드 (복제 비활성화)

```go
config := &RaftConfig{
    NodeID:              "standalone",
    BindAddr:            "127.0.0.1:7000",
    DataDir:             "./data/standalone",
    ReplicationEnabled:  false,  // 복제 비활성화
}
```

## 🏗️ 클러스터 구성

### 시나리오 1: 3노드 클러스터 (권장)

**장점:**
- 최소 고가용성 구성
- 1개 노드 장애 허용
- 비용 효율적

**설정:**

**Node 1 (리더):**
```go
config := &RaftConfig{
    NodeID:    "node-1",
    BindAddr:  "10.0.1.1:7000",
    DataDir:   "./data/node-1",
    Bootstrap: true,
    
    ReplicationEnabled: true,
    ReplicationFactor:  3,
    MinReplicas:        2,
    
    InitialPeers: []PeerConfig{
        {ID: "node-2", Address: "10.0.1.2:7000"},
        {ID: "node-3", Address: "10.0.1.3:7000"},
    },
}
```

**Node 2, 3 (팔로워):**
```go
config := &RaftConfig{
    NodeID:    "node-2",  // or "node-3"
    BindAddr:  "10.0.1.2:7000",  // or 10.0.1.3:7000
    DataDir:   "./data/node-2",
    Bootstrap: false,
    
    ReplicationEnabled: true,
    ReplicationFactor:  3,
    MinReplicas:        2,
}
```

### 시나리오 2: 5노드 클러스터 (고가용성)

**장점:**
- 높은 가용성
- 2개 노드 장애 허용
- 읽기 성능 향상

**설정:**
```go
config := &RaftConfig{
    NodeID:             "node-1",
    ReplicationFactor:  5,
    MinReplicas:        3,  // 과반수
    
    InitialPeers: []PeerConfig{
        {ID: "node-2", Address: "10.0.1.2:7000"},
        {ID: "node-3", Address: "10.0.1.3:7000"},
        {ID: "node-4", Address: "10.0.1.4:7000"},
        {ID: "node-5", Address: "10.0.1.5:7000"},
    },
}
```

### 시나리오 3: 단일 노드 (개발/테스트)

```go
config := &RaftConfig{
    NodeID:             "standalone",
    ReplicationEnabled: false,  // 복제 비활성화
}
```

## 🚀 시작 가이드

### 1. 3노드 클러스터 시작

```bash
# Node 1 (리더)
./kmip-server \
  -node-id node-1 \
  -raft-addr 127.0.0.1:7000 \
  -data-dir ./data/node-1 \
  -bootstrap \
  -replication-mode quorum \
  -replication-factor 3

# Node 2
./kmip-server \
  -node-id node-2 \
  -raft-addr 127.0.0.1:7001 \
  -data-dir ./data/node-2 \
  -replication-mode quorum \
  -replication-factor 3

# Node 3
./kmip-server \
  -node-id node-3 \
  -raft-addr 127.0.0.1:7002 \
  -data-dir ./data/node-3 \
  -replication-mode quorum \
  -replication-factor 3
```

### 2. 노드 추가

```bash
# 기존 클러스터에 노드 추가
curl -X POST http://leader-node:9090/api/v1/cluster/add-server \
  -d '{"id":"node-4","address":"10.0.1.4:7000"}'
```

### 3. 노드 제거

```bash
# 클러스터에서 노드 제거
curl -X POST http://leader-node:9090/api/v1/cluster/remove-server \
  -d '{"id":"node-3"}'
```

## 📊 성능 튜닝

### 저지연 최적화

```go
config := &RaftConfig{
    HeartbeatTimeout:  500 * time.Millisecond,  // 빠른 하트비트
    ElectionTimeout:   500 * time.Millisecond,
    CommitTimeout:     10 * time.Millisecond,   // 빠른 커밋
}

policy := &ReplicationPolicy{
    Mode:              ReplicationModeAsync,    // 비동기 복제
    TimeoutMs:         1000,
    ConsistencyLevel:  "eventual",
}
```

### 고처리량 최적화

```go
config := &RaftConfig{
    MaxAppendEntries:  128,        // 더 많은 배치
    SnapshotThreshold: 16384,      // 덜 빈번한 스냅샷
    TrailingLogs:      20480,      // 더 많은 로그 보관
}
```

### 안정성 최적화

```go
config := &RaftConfig{
    SnapshotInterval:  60 * time.Second,  // 자주 스냅샷
    SnapshotThreshold: 4096,              // 낮은 임계값
}

policy := &ReplicationPolicy{
    Mode:              ReplicationModeSync,  // 동기 복제
    RetryAttempts:     5,
    TimeoutMs:         10000,
    ConsistencyLevel:  "strong",
}
```

## 📈 모니터링

### 클러스터 상태 확인

```bash
# 리더 확인
curl http://localhost:9090/api/v1/cluster/leader

# 멤버 목록
curl http://localhost:9090/api/v1/cluster/members

# 노드 상태
curl http://localhost:9090/api/v1/cluster/stats
```

### 주요 메트릭

```go
// 복제 지연
commitIndex := raft.CommitIndex()
lastApplied := fsm.LastApplied()
replicationLag := commitIndex - lastApplied

// 리더 선거 횟수
leaderChanges := stats.LeaderChanges

// 실패한 복제 시도
failedReplications := stats.FailedReplications
```

### 로그 모니터링

```
[RAFT:node-1] 📋 Replication Mode: QUORUM (wait for majority)
[RAFT:node-1] 📊 Replication Factor: 3, Min Replicas: 2
[RAFT:node-1] 🚀 Bootstrapping cluster with 3 nodes
[RAFT:node-1] ✅ Raft store initialized successfully
[RAFT:node-1] ⏳ Retry attempt 1/3 after 100ms
[RAFT:node-1] ⚠️  Apply failed: timeout, retrying...
[RAFT:node-1] ✅ Command applied successfully after 1 retries
```

## 🔧 트러블슈팅

### 문제 1: Split Brain (스플릿 브레인)

**증상:** 여러 리더가 동시에 존재

**원인:** 네트워크 파티션

**해결:**
```yaml
replication:
  min_replicas: 2    # 과반수 확인
  mode: "quorum"     # 쿼럼 모드 사용
```

### 문제 2: 느린 복제

**증상:** 쓰기 작업이 느림

**원인:** 
- 네트워크 지연
- 디스크 I/O 병목
- 너무 많은 노드

**해결:**
```go
// 타임아웃 조정
config.CommitTimeout = 100 * time.Millisecond

// 비동기 모드 고려
policy.Mode = ReplicationModeAsync

// 배치 크기 증가
config.MaxAppendEntries = 128
```

### 문제 3: 리더 선거 실패

**증상:** 리더가 선출되지 않음

**원인:** 
- 쿼럼 부족
- 네트워크 문제
- 시간 설정 불일치

**해결:**
```bash
# 클러스터 재구성
curl -X POST http://node:9090/api/v1/cluster/reconfigure

# 노드 시간 동기화 확인
ntpq -p
```

### 문제 4: 데이터 불일치

**증상:** 노드 간 데이터가 다름

**원인:**
- 비동기 모드에서 리더 장애
- 복제 실패

**해결:**
```go
// 강한 일관성 사용
policy.ConsistencyLevel = "strong"
policy.Mode = ReplicationModeQuorum

// 스냅샷으로 복구
raft.Snapshot()
```

## 📋 체크리스트

### 프로덕션 배포 전

- [ ] 복제 팩터 ≥ 3
- [ ] 쿼럼 모드 사용
- [ ] 모니터링 설정
- [ ] 백업 전략 수립
- [ ] 장애 복구 절차 문서화
- [ ] 네트워크 지연 측정
- [ ] 디스크 성능 확인
- [ ] 시간 동기화 확인

### 성능 테스트

- [ ] 쓰기 처리량 측정
- [ ] 읽기 처리량 측정
- [ ] 복제 지연 측정
- [ ] 노드 장애 시나리오
- [ ] 네트워크 파티션 시나리오
- [ ] 동시 쓰기 테스트

## 🎯 베스트 프랙티스

1. **홀수 개의 노드 사용**: 3, 5, 7 (짝수는 비효율적)
2. **쿼럼 모드 사용**: 대부분의 경우 최적
3. **정기적인 스냅샷**: 복구 시간 단축
4. **모니터링 필수**: 메트릭 수집 및 알림
5. **네트워크 품질 확보**: 저지연, 고대역폭
6. **지리적 분산 고려**: 멀티 데이터센터는 지연 증가
7. **테스트 자동화**: 장애 시나리오 정기 테스트

## 📚 참고 자료

- [Raft 논문](https://raft.github.io/raft.pdf)
- [Raft 시각화](http://thesecretlivesofdata.com/raft/)
- [Hashicorp Raft 문서](https://github.com/hashicorp/raft)
- [KMIP 서버 문서](../README.md)
