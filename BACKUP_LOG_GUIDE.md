# 🔄 KMIP 백업 및 로그 관리 가이드

## 개요

KMIP 서버의 자동 백업, 로그 로테이션, Syslog 원격 전송을 완벽하게 지원합니다.

### 주요 기능

- ✅ **자동 백업**: Cron으로 주기적 백업
- ✅ **백업 관리**: 날짜/개수 기준 자동 삭제
- ✅ **로그 로테이션**: 크기 기준 자동 로테이션
- ✅ **로그 관리**: 날짜/개수 기준 자동 정리
- ✅ **Syslog 전송**: 원격 Syslog 서버로 실시간 전송
- ✅ **압축**: 백업 및 로그 자동 압축

## 📦 디렉토리 구조

```
/
├── backup/                     # 백업 저장소
│   ├── cluster-default-node-1-20240213-020000.tar.gz
│   ├── cluster-default-node-1-20240214-020000.tar.gz
│   └── ...
│
├── app/
│   ├── data/                  # 애플리케이션 데이터
│   │   ├── raft-log.db
│   │   ├── raft-stable.db
│   │   └── snapshots/
│   │
│   ├── logs/                  # 로그 파일
│   │   ├── node-1.log        # 현재 로그
│   │   ├── node-1.log.20240213-120000.gz  # 로테이션된 로그
│   │   ├── backup.log
│   │   ├── rotation.log
│   │   └── cron.log
│   │
│   └── scripts/
│       ├── backup-scheduler.sh
│       ├── log-rotation.sh
│       ├── setup-cron.sh
│       └── setup-syslog.sh
```

## 🔧 설정

### 환경 변수

#### 백업 설정

```yaml
environment:
  # 백업 보관 기간 (일)
  - BACKUP_RETENTION_DAYS=30
  
  # 최대 백업 개수
  - MAX_BACKUPS=10
  
  # 백업 스케줄 (Cron 형식)
  - BACKUP_SCHEDULE=0 2 * * *  # 매일 새벽 2시
  
  # 클러스터/노드 ID
  - CLUSTER_ID=cluster-seoul
  - NODE_ID=node-1
```

#### 로그 설정

```yaml
environment:
  # 최대 로그 크기 (로테이션 기준)
  - MAX_LOG_SIZE=100M
  
  # 로그 보관 기간 (일)
  - MAX_LOG_AGE=7
  
  # 최대 로그 백업 개수
  - MAX_LOG_BACKUPS=10
  
  # 로그 압축 여부
  - COMPRESS_LOGS=true
  
  # 로그 로테이션 스케줄
  - LOG_ROTATION_SCHEDULE=0 * * * *  # 매시간
```

#### Syslog 설정

```yaml
environment:
  # Syslog 서버 주소
  - SYSLOG_SERVER=syslog.example.com
  
  # Syslog 포트
  - SYSLOG_PORT=514
  
  # 프로토콜 (udp or tcp)
  - SYSLOG_PROTOCOL=udp
  
  # Syslog 태그
  - SYSLOG_TAG=kmip
```

## 📅 백업 스케줄

### Cron 스케줄 형식

```
# ┌───────────── 분 (0 - 59)
# │ ┌───────────── 시 (0 - 23)
# │ │ ┌───────────── 일 (1 - 31)
# │ │ │ ┌───────────── 월 (1 - 12)
# │ │ │ │ ┌───────────── 요일 (0 - 6, 일요일=0)
# │ │ │ │ │
# * * * * *
```

### 스케줄 예제

```yaml
# 매일 새벽 2시
BACKUP_SCHEDULE: "0 2 * * *"

# 매주 일요일 새벽 3시
BACKUP_SCHEDULE: "0 3 * * 0"

# 매월 1일 새벽 2시
BACKUP_SCHEDULE: "0 2 1 * *"

# 매시간 정각
BACKUP_SCHEDULE: "0 * * * *"

# 매일 6시간마다 (0시, 6시, 12시, 18시)
BACKUP_SCHEDULE: "0 */6 * * *"

# 평일 오전 9시
BACKUP_SCHEDULE: "0 9 * * 1-5"
```

## 🚀 사용 방법

### Docker Compose로 시작

#### docker-compose.yml 예제

```yaml
services:
  kmip-node1:
    image: kmip-server:latest
    volumes:
      - ./volumes/node1/data:/app/data
      - ./volumes/node1/logs:/app/logs
      - ./backup:/backup  # 백업 볼륨
    environment:
      - NODE_ID=node-1
      - CLUSTER_ID=cluster-prod
      
      # 백업 설정
      - BACKUP_RETENTION_DAYS=30
      - MAX_BACKUPS=10
      - BACKUP_SCHEDULE=0 2 * * *
      
      # 로그 설정
      - MAX_LOG_SIZE=100M
      - MAX_LOG_AGE=7
      - MAX_LOG_BACKUPS=10
      - COMPRESS_LOGS=true
      - LOG_ROTATION_SCHEDULE=0 * * * *
      
      # Syslog 설정
      - SYSLOG_SERVER=10.0.1.100
      - SYSLOG_PORT=514
      - SYSLOG_PROTOCOL=udp
```

#### 시작

```bash
docker-compose up -d
```

### 수동 백업

```bash
# 컨테이너 내부에서
docker exec kmip-node1 /app/scripts/backup-scheduler.sh backup

# 또는 호스트에서
docker exec kmip-node1 sh -c "/app/scripts/backup-scheduler.sh backup"
```

### 수동 로그 로테이션

```bash
# 로테이션 실행
docker exec kmip-node1 /app/scripts/log-rotation.sh rotate

# 정리만 실행
docker exec kmip-node1 /app/scripts/log-rotation.sh cleanup
```

## 📊 백업 관리

### 백업 정책

#### 날짜 기준 삭제

```
BACKUP_RETENTION_DAYS=30

30일 이전 백업 자동 삭제
├── 2024-02-10-*.tar.gz  ← 삭제 (30일 초과)
├── 2024-02-15-*.tar.gz  ← 유지
└── 2024-02-20-*.tar.gz  ← 유지
```

#### 개수 기준 삭제

```
MAX_BACKUPS=10

최신 10개만 유지, 나머지 삭제
├── backup-001.tar.gz  ← 삭제 (가장 오래됨)
├── backup-002.tar.gz  ← 삭제
├── backup-003.tar.gz  ← 유지
...
└── backup-012.tar.gz  ← 유지 (가장 최근)
```

### 백업 확인

```bash
# 백업 목록
docker exec kmip-node1 /app/scripts/backup-scheduler.sh list

# 출력 예:
# 2024-02-13 02:00:00 - cluster-default-node-1-20240213-020000.tar.gz (45MB)
# 2024-02-12 02:00:00 - cluster-default-node-1-20240212-020000.tar.gz (44MB)
# ...

# 백업 통계
docker exec kmip-node1 /app/scripts/backup-scheduler.sh stats

# 출력 예:
# Total backups: 10
# Total size: 450MB
# Oldest: cluster-default-node-1-20240203-020000.tar.gz
# Newest: cluster-default-node-1-20240213-020000.tar.gz
```

### 백업 복원

```bash
# 1. 컨테이너 중지
docker stop kmip-node1

# 2. 백업 파일 추출
cd backup/
tar -xzf cluster-default-node-1-20240213-020000.tar.gz

# 3. 데이터 복원
cp -r data/* ../volumes/node1/data/

# 4. 컨테이너 시작
docker start kmip-node1
```

## 📝 로그 관리

### 로그 로테이션 정책

#### 크기 기준

```
MAX_LOG_SIZE=100M

로그 파일이 100MB 도달 시 로테이션
node-1.log (100MB) → node-1.log.20240213-120000.gz
                   → node-1.log (새 파일)
```

#### 날짜 기준 삭제

```
MAX_LOG_AGE=7

7일 이전 로그 자동 삭제
├── node-1.log.20240206-*.gz  ← 삭제 (7일 초과)
├── node-1.log.20240208-*.gz  ← 유지
└── node-1.log.20240213-*.gz  ← 유지
```

#### 개수 기준 삭제

```
MAX_LOG_BACKUPS=10

각 로그 파일당 최신 10개 백업만 유지
├── node-1.log.20240201-*.gz  ← 삭제
├── node-1.log.20240205-*.gz  ← 유지
...
└── node-1.log.20240213-*.gz  ← 유지
```

### 로그 확인

```bash
# 실시간 로그
docker exec kmip-node1 tail -f /app/logs/node-1.log

# 압축된 로그 확인
docker exec kmip-node1 zcat /app/logs/node-1.log.*.gz | less

# 로그 검색
docker exec kmip-node1 grep "ERROR" /app/logs/node-1.log

# 로그 통계
docker exec kmip-node1 /app/scripts/log-rotation.sh stats
```

### 로그 종류

```
/app/logs/
├── node-1.log        # 메인 애플리케이션 로그
├── backup.log        # 백업 스크립트 로그
├── rotation.log      # 로그 로테이션 로그
└── cron.log          # Cron 작업 로그
```

## 📡 Syslog 원격 전송

### 설정

#### UDP 전송 (기본)

```yaml
environment:
  - SYSLOG_SERVER=syslog.company.com
  - SYSLOG_PORT=514
  - SYSLOG_PROTOCOL=udp
```

#### TCP 전송 (신뢰성 높음)

```yaml
environment:
  - SYSLOG_SERVER=syslog.company.com
  - SYSLOG_PORT=514
  - SYSLOG_PROTOCOL=tcp
```

### 테스트

```bash
# Syslog 테스트 메시지 전송
docker exec kmip-node1 logger -t kmip "Test message from KMIP"

# rsyslog 상태 확인
docker exec kmip-node1 ps aux | grep rsyslog
```

### Syslog 포맷

```
# 기본 포맷
Feb 13 12:00:00 kmip-node1 kmip: [INFO] Starting KMIP server

# 상세 포맷
<timestamp> <hostname> <tag>: <message>
```

### 중앙 Syslog 서버 설정

#### Syslog-ng 예제

```
# /etc/syslog-ng/syslog-ng.conf

source s_network {
    udp(port(514));
    tcp(port(514));
};

filter f_kmip {
    program("kmip");
};

destination d_kmip {
    file("/var/log/kmip/kmip.log");
};

log {
    source(s_network);
    filter(f_kmip);
    destination(d_kmip);
};
```

#### Rsyslog 예제

```
# /etc/rsyslog.d/kmip.conf

$ModLoad imudp
$UDPServerRun 514

:programname, isequal, "kmip" /var/log/kmip/kmip.log
& stop
```

## 🔍 모니터링

### 백업 모니터링

```bash
# 백업 스케줄 확인
docker exec kmip-node1 cat /etc/crontabs/root

# 최근 백업 확인
docker exec kmip-node1 ls -lht /backup | head -10

# 백업 로그 확인
docker exec kmip-node1 tail -f /app/logs/backup.log

# Cron 로그 확인
docker exec kmip-node1 tail -f /app/logs/cron.log
```

### 로그 모니터링

```bash
# 로그 파일 크기 확인
docker exec kmip-node1 du -h /app/logs/*.log

# 로테이션 로그 확인
docker exec kmip-node1 tail -f /app/logs/rotation.log

# 압축된 로그 개수
docker exec kmip-node1 ls -l /app/logs/*.gz | wc -l
```

### 디스크 사용량

```bash
# 백업 디렉토리 크기
docker exec kmip-node1 du -sh /backup

# 로그 디렉토리 크기
docker exec kmip-node1 du -sh /app/logs

# 데이터 디렉토리 크기
docker exec kmip-node1 du -sh /app/data
```

## 🎯 시나리오별 설정

### 시나리오 1: 프로덕션 (높은 보안)

```yaml
environment:
  # 자주 백업, 오래 보관
  - BACKUP_SCHEDULE=0 */6 * * *     # 6시간마다
  - BACKUP_RETENTION_DAYS=90        # 90일 보관
  - MAX_BACKUPS=100                 # 최대 100개
  
  # 자주 로테이션, 오래 보관
  - MAX_LOG_SIZE=50M                # 50MB마다
  - MAX_LOG_AGE=30                  # 30일 보관
  - MAX_LOG_BACKUPS=50
  
  # Syslog 전송 (TCP)
  - SYSLOG_SERVER=syslog.prod.com
  - SYSLOG_PROTOCOL=tcp
```

### 시나리오 2: 개발/테스트 (공간 절약)

```yaml
environment:
  # 덜 자주 백업, 짧게 보관
  - BACKUP_SCHEDULE=0 4 * * *       # 매일 1회
  - BACKUP_RETENTION_DAYS=7         # 7일 보관
  - MAX_BACKUPS=5
  
  # 큰 파일 허용, 짧게 보관
  - MAX_LOG_SIZE=200M
  - MAX_LOG_AGE=3
  - MAX_LOG_BACKUPS=3
  
  # Syslog 비활성화
  # - SYSLOG_SERVER=
```

### 시나리오 3: 중요 데이터 (최대 보호)

```yaml
environment:
  # 매우 자주 백업, 매우 오래 보관
  - BACKUP_SCHEDULE=0 */2 * * *     # 2시간마다
  - BACKUP_RETENTION_DAYS=365       # 1년 보관
  - MAX_BACKUPS=1000
  
  # 작은 파일, 오래 보관
  - MAX_LOG_SIZE=10M
  - MAX_LOG_AGE=90
  - MAX_LOG_BACKUPS=100
  
  # Syslog 중복 전송
  - SYSLOG_SERVER=syslog1.com,syslog2.com
  - SYSLOG_PROTOCOL=tcp
```

## 🛠️ 트러블슈팅

### 백업이 생성되지 않음

```bash
# Cron 실행 확인
docker exec kmip-node1 ps aux | grep crond

# Cron 로그 확인
docker exec kmip-node1 tail -f /app/logs/cron.log

# 수동 백업 테스트
docker exec kmip-node1 /app/scripts/backup-scheduler.sh backup
```

### 로그 로테이션 실패

```bash
# 로그 디렉토리 권한 확인
docker exec kmip-node1 ls -la /app/logs

# 수동 로테이션 테스트
docker exec kmip-node1 /app/scripts/log-rotation.sh rotate

# 로테이션 로그 확인
docker exec kmip-node1 tail -f /app/logs/rotation.log
```

### Syslog 전송 안됨

```bash
# rsyslog 프로세스 확인
docker exec kmip-node1 ps aux | grep rsyslog

# rsyslog 재시작
docker exec kmip-node1 sh -c "killall rsyslogd && rsyslogd"

# 네트워크 테스트
docker exec kmip-node1 nc -zv syslog.example.com 514
```

## 📚 참고 명령어

### 백업 관련

```bash
# 백업 실행
/app/scripts/backup-scheduler.sh backup

# 백업 정리
/app/scripts/backup-scheduler.sh cleanup

# 백업 목록
/app/scripts/backup-scheduler.sh list

# 백업 통계
/app/scripts/backup-scheduler.sh stats
```

### 로그 관련

```bash
# 로그 로테이션
/app/scripts/log-rotation.sh rotate

# 로그 정리
/app/scripts/log-rotation.sh cleanup

# 로그 통계
/app/scripts/log-rotation.sh stats
```

### Syslog 관련

```bash
# Syslog 설정
/app/scripts/setup-syslog.sh

# Syslog 테스트
logger -t kmip "Test message"

# rsyslog 재시작
killall rsyslogd && rsyslogd
```

## 🎉 요약

```
✅ 자동 백업: Cron으로 주기적 실행
✅ 백업 관리: 날짜/개수 기준 자동 삭제
✅ 로그 로테이션: 크기 기준 자동 분할
✅ 로그 관리: 날짜/개수 기준 자동 정리
✅ Syslog 전송: 원격 서버로 실시간 전송
✅ 완전 자동화: 별도 관리 불필요
```

**KMIP 서버의 백업과 로그를 완벽하게 자동 관리하세요!** 🔄
