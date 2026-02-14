# 🐳 KMIP Docker 배포 가이드

## 개요

Docker 컨테이너 기반으로 KMIP 클러스터를 배포하고 관리하는 완전한 가이드입니다.

### 특징

- ✅ **완전 컨테이너화**: 모든 노드가 독립 컨테이너
- ✅ **영구 저장소**: 로컬 디스크 마운트
- ✅ **설정 파일 관리**: YAML 기반 설정
- ✅ **로그 관리**: 각 노드별 로그 파일
- ✅ **헬스체크**: 자동 상태 모니터링
- ✅ **자동 재시작**: 장애 시 자동 복구

## 📦 디렉토리 구조

```
kmip-server/
├── Dockerfile                          # 컨테이너 이미지 정의
├── docker-compose.yml                  # 단일 클러스터 (3노드)
├── docker-compose.multi-cluster.yml    # 멀티 클러스터 (서울+부산)
├── Makefile.docker                     # Docker 관리 명령
│
├── config/                             # 설정 파일
│   ├── node1/
│   │   └── config.yaml
│   ├── node2/
│   │   └── config.yaml
│   └── node3/
│       └── config.yaml
│
├── volumes/                            # 영구 데이터 (호스트 마운트)
│   ├── node1/
│   │   ├── data/                      # Raft 데이터
│   │   └── logs/                      # 로그 파일
│   ├── node2/
│   │   ├── data/
│   │   └── logs/
│   └── node3/
│       ├── data/
│       └── logs/
│
├── certs/                              # TLS 인증서
│   ├── ca.crt
│   ├── server.crt
│   └── server.key
│
└── scripts/
    ├── docker-setup.sh                 # 초기 설정
    └── setup-cross-cluster-replication.sh
```

## 🚀 빠른 시작

### 1단계: 환경 설정

```bash
# 설정 디렉토리 및 인증서 생성
make docker-setup-single

# 또는 멀티 클러스터
make docker-setup-multi
```

**자동으로 생성되는 것들:**
- ✅ config/ 디렉토리 및 설정 파일
- ✅ volumes/ 데이터 및 로그 디렉토리
- ✅ certs/ TLS 인증서
- ✅ .dockerignore 파일

### 2단계: 이미지 빌드

```bash
# 단일 클러스터
make docker-build

# 멀티 클러스터
make docker-build-multi
```

### 3단계: 클러스터 시작

```bash
# 단일 클러스터 (3노드)
make docker-up

# 멀티 클러스터 (서울 3노드 + 부산 3노드)
make docker-up-multi
```

### 4단계: 상태 확인

```bash
# 컨테이너 상태
make docker-ps

# 클러스터 상태
make docker-status

# 로그 확인
make docker-logs
```

## 📋 단일 클러스터 구성

### docker-compose.yml

**3노드 Raft 클러스터:**

```
┌──────────────────┐
│   Host Machine   │
│                  │
│  ┌────────────┐  │
│  │ Node 1     │  │  :9090 → REST API
│  │ (Leader)   │  │  :7000 → Raft
│  └────────────┘  │
│        ↕          │
│  ┌────────────┐  │
│  │ Node 2     │  │  :9091 → REST API
│  │ (Follower) │  │  :7001 → Raft
│  └────────────┘  │
│        ↕          │
│  │ Node 3     │  │
│  │ (Follower) │  │  :9092 → REST API
│  └────────────┘  │  :7002 → Raft
└──────────────────┘
```

**포트 매핑:**
| 노드 | KMIP | Raft | Management | REST API |
|------|------|------|------------|----------|
| Node 1 | 5696 | 7000 | 8080 | 9090 |
| Node 2 | 5697 | 7001 | 8081 | 9091 |
| Node 3 | 5698 | 7002 | 8082 | 9092 |

**볼륨 마운트:**
```yaml
volumes:
  - ./config/node1:/app/config:ro      # 설정 (읽기 전용)
  - ./volumes/node1/data:/app/data     # 데이터 (읽기/쓰기)
  - ./volumes/node1/logs:/app/logs     # 로그 (읽기/쓰기)
  - ./certs:/app/certs:ro              # 인증서 (읽기 전용)
```

## 🌐 멀티 클러스터 구성

### docker-compose.multi-cluster.yml

**서울 + 부산 2개 클러스터:**

```
┌─────────────────────┐     ┌─────────────────────┐
│  Seoul Cluster      │     │  Busan Cluster      │
│  172.21.0.0/16      │     │  172.22.0.0/16      │
│                     │     │                     │
│  Node 1-3           │◄───►│  Node 1-3           │
│  (Raft)             │     │  (Raft)             │
└─────────────────────┘     └─────────────────────┘
         │                           │
         └───────────────────────────┘
              Cross-Cluster Network
                 172.30.0.0/16
```

**포트 매핑:**

**서울 클러스터:**
| 노드 | REST API | Raft | Management |
|------|----------|------|------------|
| Seoul 1 | 19090 | 17000 | 18080 |
| Seoul 2 | 19091 | 17001 | 18081 |
| Seoul 3 | 19092 | 17002 | 18082 |

**부산 클러스터:**
| 노드 | REST API | Raft | Management |
|------|----------|------|------------|
| Busan 1 | 29090 | 27000 | 28080 |
| Busan 2 | 29091 | 27001 | 28081 |
| Busan 3 | 29092 | 27002 | 28082 |

## 🔧 설정 파일

### config/node1/config.yaml

```yaml
node:
  id: "node-1"
  bind_addr: "172.20.0.11:7000"
  data_dir: "/app/data"
  bootstrap: true

replication:
  enabled: true
  factor: 3
  min_replicas: 2
  mode: "quorum"
  consistency: "strong"

performance:
  heartbeat_timeout: "1s"
  election_timeout: "1s"
  commit_timeout: "50ms"
  snapshot_interval: "120s"

logging:
  level: "info"
  file: "/app/logs/node-1.log"
  max_size_mb: 100
  max_backups: 3
```

## 📊 Makefile 명령어

### 기본 명령

```bash
# 환경 설정
make docker-setup-single     # 단일 클러스터 설정
make docker-setup-multi      # 멀티 클러스터 설정

# 빌드
make docker-build           # 이미지 빌드
make docker-build-multi     # 멀티 클러스터 이미지 빌드

# 시작/중지
make docker-up              # 클러스터 시작
make docker-down            # 클러스터 중지
make docker-restart         # 클러스터 재시작

# 상태 확인
make docker-ps              # 컨테이너 상태
make docker-status          # 클러스터 상태
make docker-logs            # 로그 확인
```

### 고급 명령

```bash
# 개별 노드 로그
make docker-logs-node1
make docker-logs-node2
make docker-logs-node3

# 셸 접속
make docker-shell-node1     # Node 1 셸

# 네트워크 검사
make docker-inspect         # 네트워크/볼륨 정보
make docker-stats           # 리소스 사용량

# 데이터 관리
make docker-backup          # 데이터 백업
make docker-restore BACKUP_FILE=xxx.tar.gz
make docker-clean-data      # 데이터 삭제
make docker-clean-logs      # 로그 삭제
```

### 멀티 클러스터 명령

```bash
# 시작/중지
make docker-up-multi
make docker-down-multi
make docker-restart-multi

# 로그
make docker-logs-multi      # 전체 로그
make docker-logs-seoul      # 서울만
make docker-logs-busan      # 부산만

# 상태
make docker-status-multi

# 복제 설정
make docker-setup-replication
```

## 🧪 테스트

### 단일 클러스터 테스트

```bash
# 자동 테스트
make docker-test

# 수동 테스트
# 1. Node 1에 키 생성
curl -X POST http://localhost:9090/api/v1/keys \
  -d '{"algorithm":"AES","length":256}'

# 2. Node 2에서 확인 (복제됨)
curl http://localhost:9091/api/v1/keys

# 3. Node 3에서도 확인
curl http://localhost:9092/api/v1/keys
```

### 멀티 클러스터 테스트

```bash
# 1. 복제 설정
make docker-setup-replication

# 2. 서울에 키 생성
curl -X POST http://localhost:19090/api/v1/keys \
  -d '{"algorithm":"AES","length":256}'

# 3. 부산에서 확인 (5초 후)
sleep 5
curl http://localhost:29090/api/v1/keys

# 4. 복제 상태 확인
curl http://localhost:19090/api/v1/replication/status | jq
```

## 📁 데이터 관리

### 데이터 위치

```
volumes/
├── node1/
│   ├── data/
│   │   ├── raft-log.db      # Raft 로그
│   │   ├── raft-stable.db   # Raft 상태
│   │   └── snapshots/       # 스냅샷
│   └── logs/
│       └── node-1.log       # 애플리케이션 로그
```

### 백업

```bash
# 전체 백업
make docker-backup

# 생성된 파일
# backups/kmip-backup-20240210-120000.tar.gz
```

### 복원

```bash
# 1. 클러스터 중지
make docker-down

# 2. 복원
make docker-restore BACKUP_FILE=backups/kmip-backup-xxx.tar.gz

# 3. 클러스터 시작
make docker-up
```

### 로그 확인

```bash
# 실시간 로그
docker-compose logs -f kmip-node1

# 파일 로그
tail -f volumes/node1/logs/node-1.log

# 모든 로그
tail -f volumes/*/logs/*.log
```

## 🔍 트러블슈팅

### 문제 1: 컨테이너가 시작되지 않음

```bash
# 로그 확인
make docker-logs

# 상태 확인
docker-compose ps

# 헬스체크 확인
docker inspect kmip-node1 | jq '.[0].State.Health'
```

### 문제 2: Raft 클러스터 형성 실패

```bash
# 각 노드 로그 확인
make docker-logs-node1
make docker-logs-node2
make docker-logs-node3

# 네트워크 확인
docker network inspect kmip-server_kmip-network
```

### 문제 3: 데이터 손실

```bash
# 백업에서 복원
make docker-restore BACKUP_FILE=backup.tar.gz

# 스냅샷 확인
ls -la volumes/node1/data/snapshots/
```

### 문제 4: 포트 충돌

```yaml
# docker-compose.yml 편집
ports:
  - "19090:9090"  # 호스트 포트 변경
```

## 🔐 보안

### TLS 인증서 갱신

```bash
# 1. 새 인증서 생성
cd certs/
./generate-new-certs.sh

# 2. 컨테이너 재시작
make docker-restart
```

### 방화벽 설정

```bash
# 필요한 포트만 열기
# KMIP: 5696-5698
# REST: 9090-9092
# Raft: 7000-7002 (내부망만)
```

## 📈 성능 튜닝

### 리소스 제한

```yaml
# docker-compose.yml
services:
  kmip-node1:
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 2G
        reservations:
          cpus: '1'
          memory: 1G
```

### 로깅 설정

```yaml
logging:
  driver: "json-file"
  options:
    max-size: "10m"
    max-file: "3"
```

## 🎯 프로덕션 배포

### 추천 설정

```yaml
# 프로덕션용 docker-compose.yml
services:
  kmip-node1:
    restart: always           # 항상 재시작
    mem_limit: 2g            # 메모리 제한
    cpu_count: 2             # CPU 제한
    
    healthcheck:
      interval: 10s
      timeout: 5s
      retries: 3
      start_period: 30s
    
    logging:
      driver: "syslog"       # 중앙 로깅
      options:
        syslog-address: "udp://log-server:514"
```

### 모니터링

```bash
# Prometheus 메트릭 (추가 구현 필요)
curl http://localhost:9090/metrics

# 헬스체크
while true; do
  curl -s http://localhost:9090/health | jq '.status'
  sleep 5
done
```

## 📚 참고 명령

```bash
# 전체 도움말
make help

# 컨테이너 전체 정리
make docker-clean

# 시스템 정리
make docker-prune

# 완전 초기화
make docker-reset
```

## 🎉 요약

```bash
# 1. 설정
make docker-setup-single

# 2. 빌드
make docker-build

# 3. 시작
make docker-up

# 4. 테스트
make docker-test

# 5. 모니터링
make docker-logs
make docker-status
```

**Docker로 KMIP 클러스터를 쉽게 배포하고 관리하세요!** 🐳
