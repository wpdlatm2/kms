# KMIP Server with Raft Distributed Storage

## Raft 클러스터 구성

### 3노드 클러스터 예제

#### 1. 첫 번째 노드 (리더, 부트스트랩)

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

#### 2. 두 번째 노드

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

#### 3. 세 번째 노드

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

### 클러스터에 노드 추가

첫 번째 노드(리더)가 실행된 후, 다른 노드들을 클러스터에 추가:

```bash
# 노드 2 추가
curl -X POST http://localhost:8080/cluster/join \
  -H "Content-Type: application/json" \
  -d '{
    "node_id": "node2",
    "addr": "127.0.0.1:7001"
  }'

# 노드 3 추가
curl -X POST http://localhost:8080/cluster/join \
  -H "Content-Type: application/json" \
  -d '{
    "node_id": "node3",
    "addr": "127.0.0.1:7002"
  }'
```

## 관리 API

### 클러스터 상태 조회

```bash
curl http://localhost:8080/cluster/status
```

응답 예시:
```json
{
  "is_leader": true,
  "leader": "127.0.0.1:7000"
}
```

### Raft 통계 조회

```bash
curl http://localhost:8080/cluster/stats
```

응답 예시:
```json
{
  "applied_index": "42",
  "commit_index": "42",
  "fsm_pending": "0",
  "last_contact": "0",
  "last_log_index": "42",
  "last_log_term": "2",
  "last_snapshot_index": "0",
  "last_snapshot_term": "0",
  "latest_configuration": "[{Suffrage:Voter ID:node1 Address:127.0.0.1:7000}]",
  "latest_configuration_index": "0",
  "num_peers": "0",
  "protocol_version": "3",
  "protocol_version_max": "3",
  "protocol_version_min": "0",
  "snapshot_version_max": "1",
  "snapshot_version_min": "0",
  "state": "Leader",
  "term": "2"
}
```

### 노드 제거

```bash
curl -X POST http://localhost:8080/cluster/leave \
  -H "Content-Type: application/json" \
  -d '{
    "node_id": "node3"
  }'
```

## Raft 동작 원리

### 1. 리더 선출
- 클러스터의 노드들이 선거를 통해 리더를 선출
- 리더만 클라이언트 요청을 처리
- 리더가 실패하면 새로운 리더 선출

### 2. 로그 복제
- 모든 쓰기 작업은 리더를 통해 수행
- 리더가 로그를 팔로워들에게 복제
- 과반수가 로그를 저장하면 커밋

### 3. 데이터 일관성
- 모든 노드가 동일한 순서로 명령 실행
- 과반수 합의를 통한 강한 일관성 보장
- 네트워크 분할 시에도 데이터 무결성 유지

## 장애 시나리오

### 리더 노드 실패
1. 팔로워들이 리더 하트비트 타임아웃 감지
2. 새로운 선거 시작
3. 과반수 투표로 새 리더 선출
4. 새 리더가 클라이언트 요청 처리 계속

### 팔로워 노드 실패
1. 리더가 팔로워 실패 감지
2. 남은 노드들로 계속 작업
3. 실패한 노드 재시작 시 로그 동기화

### 네트워크 분할
1. 과반수를 가진 파티션만 작업 계속
2. 소수 파티션은 읽기 전용 모드
3. 네트워크 복구 시 로그 동기화

## 성능 고려사항

### 쓰기 성능
- 모든 쓰기는 리더를 통해 수행
- 과반수 노드에 복제 필요
- 네트워크 지연이 성능에 영향

### 읽기 성능
- 리더에서 읽기 수행 (기본)
- 팔로워 읽기도 가능하지만 약간의 지연 가능
- Stale read 옵션으로 성능 향상 가능

### 스냅샷
- 주기적으로 스냅샷 생성
- 로그 크기 제한 및 복구 시간 단축
- 설정: `SnapshotInterval`, `SnapshotThreshold`

## 프로덕션 배포 권장사항

### 클러스터 크기
- **3노드**: 1개 노드 실패 허용
- **5노드**: 2개 노드 실패 허용 (권장)
- **7노드**: 3개 노드 실패 허용

홀수 개 노드 사용 권장 (과반수 계산 최적화)

### 하드웨어
- **CPU**: 멀티코어 (2-4 코어)
- **메모리**: 최소 4GB (데이터 크기에 따라)
- **디스크**: SSD 권장 (낮은 지연시간)
- **네트워크**: 낮은 지연시간 (< 10ms)

### 배치
- 각 노드를 다른 물리 서버에 배치
- 가능하면 다른 데이터센터/가용영역에 분산
- 네트워크 안정성 중요

### 모니터링
- Raft 상태 모니터링 (리더, 팔로워)
- 로그 지연 모니터링
- 스냅샷 빈도 모니터링
- 디스크 사용량 모니터링

## 백업 및 복구

### 백업
```bash
# 데이터 디렉토리 백업
tar -czf backup-$(date +%Y%m%d).tar.gz ./data/node1/
```

### 복구
```bash
# 백업 복원
tar -xzf backup-20240101.tar.gz

# 노드 재시작
./kmip-server -use-raft -node-id node1 ...
```

## 문제 해결

### 로그 확인
```bash
# Raft 로그 레벨 설정
export RAFT_LOG_LEVEL=DEBUG

# 서버 로그 확인
tail -f kmip-server.log
```

### 클러스터 상태 확인
```bash
# 모든 노드의 상태 확인
for port in 8080 8081 8082; do
  echo "Node on :$port"
  curl -s http://localhost:$port/cluster/status | jq
  echo ""
done
```

### 리더 강제 전환
리더 노드를 종료하면 자동으로 새 리더 선출:
```bash
# 현재 리더 노드 종료
pkill -f "node-id node1"
```

## 보안 고려사항

### Raft 통신 암호화
프로덕션에서는 Raft 노드 간 통신도 TLS로 암호화 권장:
```go
// TLS Transport 사용 예제 (향후 구현 필요)
transport, err := raft.NewTCPTransportWithConfig(
    config.BindAddr,
    addr,
    3,
    10*time.Second,
    os.Stderr,
    tlsConfig,
)
```

### HTTP API 보안
관리 API에 인증/인가 추가 권장:
- API 키 인증
- JWT 토큰
- mTLS (상호 TLS 인증)

## 추가 리소스

- [HashiCorp Raft GitHub](https://github.com/hashicorp/raft)
- [Raft 논문](https://raft.github.io/raft.pdf)
- [Raft 시각화](http://thesecretlivesofdata.com/raft/)
