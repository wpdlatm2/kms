# 🚀 KMIP 백업 & 로그 관리 빠른 시작

## ✅ 구현 완료!

**자동 백업, 로그 로테이션, Syslog 원격 전송**이 모두 구현되었습니다!

## 📦 구현된 기능

### 1️⃣ 자동 백업 스케줄러
- ✅ Cron으로 주기적 백업 실행
- ✅ `/backup` 디렉토리에 저장
- ✅ 날짜 기준 자동 삭제 (기본 30일)
- ✅ 개수 기준 자동 삭제 (기본 10개)
- ✅ 자동 압축 (tar.gz)

### 2️⃣ 로그 로테이션
- ✅ 크기 기준 자동 로테이션 (기본 100MB)
- ✅ 날짜 기준 자동 삭제 (기본 7일)
- ✅ 개수 기준 자동 삭제 (기본 10개)
- ✅ 자동 압축 (gzip)

### 3️⃣ Syslog 원격 전송
- ✅ rsyslog 기반 원격 전송
- ✅ UDP/TCP 지원
- ✅ 실시간 로그 전송
- ✅ 중앙 집중식 로그 관리

## 🚀 1분 안에 시작하기

### 단계 1: Docker Compose 설정

```yaml
# docker-compose.yml
services:
  kmip-node1:
    image: kmip-server:latest
    volumes:
      - ./volumes/node1/data:/app/data
      - ./volumes/node1/logs:/app/logs
      - ./backup:/backup              # ← 백업 볼륨
    environment:
      # 백업 설정
      - BACKUP_SCHEDULE=0 2 * * *     # 매일 새벽 2시
      - BACKUP_RETENTION_DAYS=30      # 30일 보관
      - MAX_BACKUPS=10                # 최대 10개
      
      # 로그 설정
      - MAX_LOG_SIZE=100M             # 100MB마다 로테이션
      - MAX_LOG_AGE=7                 # 7일 보관
      - LOG_ROTATION_SCHEDULE=0 * * * *  # 매시간
      
      # Syslog 설정
      - SYSLOG_SERVER=syslog.example.com
      - SYSLOG_PORT=514
      - SYSLOG_PROTOCOL=udp
```

### 단계 2: 시작

```bash
docker-compose up -d
```

**완료!** 자동으로 백업, 로그 로테이션, Syslog 전송이 시작됩니다.

## 📊 디렉토리 구조

```
/
├── backup/                           # 백업 저장소
│   ├── cluster-prod-node-1-20240213-020000.tar.gz
│   ├── cluster-prod-node-1-20240212-020000.tar.gz
│   └── ... (자동으로 30일 이전 삭제)
│
└── app/
    ├── data/                        # 애플리케이션 데이터
    │   ├── raft-log.db
    │   └── raft-stable.db
    │
    └── logs/                        # 로그 파일
        ├── node-1.log               # 현재 로그
        ├── node-1.log.20240213.gz   # 로테이션 (자동 압축)
        ├── backup.log
        ├── rotation.log
        └── cron.log
```

## 🔧 환경 변수 설명

### 백업 설정

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `BACKUP_SCHEDULE` | `0 2 * * *` | Cron 형식 백업 스케줄 |
| `BACKUP_RETENTION_DAYS` | `30` | 백업 보관 기간 (일) |
| `MAX_BACKUPS` | `10` | 최대 백업 개수 |
| `CLUSTER_ID` | `cluster-default` | 클러스터 ID (백업 파일명에 사용) |
| `NODE_ID` | `node-1` | 노드 ID (백업 파일명에 사용) |

### 로그 설정

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `LOG_ROTATION_SCHEDULE` | `0 * * * *` | 로그 로테이션 스케줄 |
| `MAX_LOG_SIZE` | `100M` | 로테이션 기준 크기 |
| `MAX_LOG_AGE` | `7` | 로그 보관 기간 (일) |
| `MAX_LOG_BACKUPS` | `10` | 최대 로그 백업 개수 |
| `COMPRESS_LOGS` | `true` | 로그 압축 여부 |

### Syslog 설정

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `SYSLOG_SERVER` | (없음) | Syslog 서버 주소 |
| `SYSLOG_PORT` | `514` | Syslog 포트 |
| `SYSLOG_PROTOCOL` | `udp` | 프로토콜 (udp/tcp) |
| `SYSLOG_TAG` | `kmip` | Syslog 태그 |

## 📅 백업 스케줄 예제

### Cron 형식

```
# 분 시 일 월 요일
# * * * * *
```

### 자주 사용하는 스케줄

```yaml
# 매일 새벽 2시
BACKUP_SCHEDULE: "0 2 * * *"

# 6시간마다 (0시, 6시, 12시, 18시)
BACKUP_SCHEDULE: "0 */6 * * *"

# 매주 일요일 새벽 3시
BACKUP_SCHEDULE: "0 3 * * 0"

# 매월 1일 새벽 2시
BACKUP_SCHEDULE: "0 2 1 * *"

# 평일 오전 9시
BACKUP_SCHEDULE: "0 9 * * 1-5"
```

## 🧪 테스트

### 수동 백업 실행

```bash
# 즉시 백업 실행
docker exec kmip-node1 /app/scripts/backup-scheduler.sh backup

# 백업 목록 확인
docker exec kmip-node1 /app/scripts/backup-scheduler.sh list

# 출력 예:
# 2024-02-13 02:00:00 - cluster-prod-node-1-20240213-020000.tar.gz (45MB)
# 2024-02-12 02:00:00 - cluster-prod-node-1-20240212-020000.tar.gz (44MB)
```

### 수동 로그 로테이션

```bash
# 즉시 로그 로테이션
docker exec kmip-node1 /app/scripts/log-rotation.sh rotate

# 로그 통계 확인
docker exec kmip-node1 /app/scripts/log-rotation.sh stats

# 출력 예:
# node-1.log: 85MB (3 backups)
# backup.log: 1.2MB (0 backups)
# Total log directory size: 150MB
```

### Syslog 테스트

```bash
# 테스트 메시지 전송
docker exec kmip-node1 logger -t kmip "Test message from KMIP"

# rsyslog 상태 확인
docker exec kmip-node1 ps aux | grep rsyslog
```

## 📊 모니터링

### 백업 상태 확인

```bash
# 최근 백업 확인
ls -lht backup/ | head -5

# 백업 총 크기
du -sh backup/

# Cron 로그 확인
docker exec kmip-node1 tail -f /app/logs/cron.log
```

### 로그 상태 확인

```bash
# 로그 파일 크기
docker exec kmip-node1 du -h /app/logs/*.log

# 압축된 로그 개수
docker exec kmip-node1 ls -l /app/logs/*.gz | wc -l

# 실시간 로그 확인
docker exec kmip-node1 tail -f /app/logs/node-1.log
```

## 🎯 사용 시나리오

### 시나리오 1: 프로덕션 환경

```yaml
environment:
  # 6시간마다 백업, 90일 보관
  - BACKUP_SCHEDULE=0 */6 * * *
  - BACKUP_RETENTION_DAYS=90
  - MAX_BACKUPS=100
  
  # 50MB마다 로테이션, 30일 보관
  - MAX_LOG_SIZE=50M
  - MAX_LOG_AGE=30
  - MAX_LOG_BACKUPS=50
  
  # TCP로 Syslog 전송 (신뢰성)
  - SYSLOG_SERVER=syslog.prod.com
  - SYSLOG_PROTOCOL=tcp
```

### 시나리오 2: 개발 환경

```yaml
environment:
  # 매일 1회 백업, 7일 보관
  - BACKUP_SCHEDULE=0 4 * * *
  - BACKUP_RETENTION_DAYS=7
  - MAX_BACKUPS=5
  
  # 200MB마다 로테이션, 3일 보관
  - MAX_LOG_SIZE=200M
  - MAX_LOG_AGE=3
  - MAX_LOG_BACKUPS=3
  
  # Syslog 비활성화
  # - SYSLOG_SERVER=
```

### 시나리오 3: 고가용성 환경

```yaml
environment:
  # 2시간마다 백업, 365일 보관
  - BACKUP_SCHEDULE=0 */2 * * *
  - BACKUP_RETENTION_DAYS=365
  - MAX_BACKUPS=1000
  
  # 10MB마다 로테이션, 90일 보관
  - MAX_LOG_SIZE=10M
  - MAX_LOG_AGE=90
  - MAX_LOG_BACKUPS=100
  
  # TCP로 Syslog 전송
  - SYSLOG_SERVER=syslog1.prod.com
  - SYSLOG_PROTOCOL=tcp
```

## 📁 백업 내용

각 백업 파일에는 다음이 포함됩니다:

```
backup-file.tar.gz
├── data/                    # Raft 데이터
│   ├── raft-log.db
│   ├── raft-stable.db
│   └── snapshots/
├── config/                  # 설정 파일
│   └── config.yaml
└── backup-metadata.json     # 백업 메타데이터
```

### 백업 메타데이터 예제

```json
{
  "cluster_id": "cluster-prod",
  "node_id": "node-1",
  "timestamp": "20240213-020000",
  "backup_date": "2024-02-13T02:00:00+09:00",
  "hostname": "kmip-node1",
  "data_size": "450MB"
}
```

## 🔄 백업 복원

```bash
# 1. 컨테이너 중지
docker stop kmip-node1

# 2. 백업 파일 선택
cd backup/
ls -lht | head -5

# 3. 백업 추출
tar -xzf cluster-prod-node-1-20240213-020000.tar.gz

# 4. 데이터 복원
rm -rf ../volumes/node1/data/*
cp -r data/* ../volumes/node1/data/

# 5. 컨테이너 시작
docker start kmip-node1

# 6. 확인
docker logs -f kmip-node1
```

## 🌐 Syslog 서버 설정

### Rsyslog 서버 예제

```bash
# /etc/rsyslog.d/kmip.conf

# UDP 수신 활성화
$ModLoad imudp
$UDPServerRun 514

# KMIP 로그 필터링 및 저장
:programname, isequal, "kmip" /var/log/kmip/kmip.log
& stop
```

### Syslog-ng 서버 예제

```
# /etc/syslog-ng/conf.d/kmip.conf

source s_network {
    udp(port(514));
    tcp(port(514));
};

filter f_kmip {
    program("kmip");
};

destination d_kmip {
    file("/var/log/kmip/$HOST/$YEAR-$MONTH-$DAY.log"
         create-dirs(yes));
};

log {
    source(s_network);
    filter(f_kmip);
    destination(d_kmip);
};
```

## 🛠️ 트러블슈팅

### 백업이 생성되지 않음

```bash
# 1. Cron 확인
docker exec kmip-node1 cat /etc/crontabs/root

# 2. Cron 프로세스 확인
docker exec kmip-node1 ps aux | grep crond

# 3. Cron 로그 확인
docker exec kmip-node1 tail -50 /app/logs/cron.log

# 4. 수동 백업 테스트
docker exec kmip-node1 /app/scripts/backup-scheduler.sh backup
```

### 로그가 로테이션되지 않음

```bash
# 1. 로그 파일 크기 확인
docker exec kmip-node1 ls -lh /app/logs/*.log

# 2. 로그 로테이션 스케줄 확인
docker exec kmip-node1 cat /etc/crontabs/root | grep rotation

# 3. 수동 로테이션 테스트
docker exec kmip-node1 /app/scripts/log-rotation.sh rotate
```

### Syslog가 전송되지 않음

```bash
# 1. rsyslog 프로세스 확인
docker exec kmip-node1 ps aux | grep rsyslog

# 2. 네트워크 테스트
docker exec kmip-node1 nc -zv syslog.example.com 514

# 3. rsyslog 재시작
docker exec kmip-node1 sh -c "killall rsyslogd && rsyslogd"

# 4. 테스트 메시지 전송
docker exec kmip-node1 logger -t kmip "Test message"
```

## 📚 관련 파일

```
/app/scripts/
├── backup-scheduler.sh      # 백업 스케줄러
├── log-rotation.sh          # 로그 로테이션
├── setup-cron.sh            # Cron 설정
└── setup-syslog.sh          # Syslog 설정

/app/logs/
├── node-1.log              # 메인 로그
├── backup.log              # 백업 로그
├── rotation.log            # 로테이션 로그
└── cron.log                # Cron 로그

/backup/                     # 백업 저장소
└── cluster-*-node-*-*.tar.gz
```

## 🎉 완료!

```bash
# === 빠른 시작 ===

# 1. Docker Compose 설정 (환경 변수 추가)
vi docker-compose.yml

# 2. 시작
docker-compose up -d

# 3. 확인
docker exec kmip-node1 /app/scripts/backup-scheduler.sh stats
docker exec kmip-node1 /app/scripts/log-rotation.sh stats

# === 완료! ===
# ✅ 자동 백업: 매일 새벽 2시
# ✅ 자동 로그 로테이션: 매시간
# ✅ Syslog 원격 전송: 실시간
# ✅ 자동 정리: 날짜/개수 기준
```

**이제 백업과 로그가 완전히 자동으로 관리됩니다!** 🔄🎊
