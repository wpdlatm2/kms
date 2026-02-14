# Multi-stage build for KMIP Server
FROM golang:1.21-alpine AS builder

# 빌드 도구 설치
RUN apk add --no-cache git make

# 작업 디렉토리 설정
WORKDIR /build

# 의존성 파일 복사
COPY go.mod go.sum ./
RUN go mod download

# 소스 코드 복사
COPY . .

# 빌드
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o kmip-server ./cmd/kmip-server

# 최종 이미지
FROM alpine:latest

# 필수 패키지 설치
RUN apk --no-cache add \
    ca-certificates \
    tzdata \
    curl \
    bash \
    busybox-suid \
    rsyslog \
    logrotate \
    gzip

# 타임존 설정
ENV TZ=Asia/Seoul

# 작업 디렉토리 설정
WORKDIR /app

# 빌드된 바이너리 복사
COPY --from=builder /build/kmip-server /app/kmip-server

# 스크립트 복사
COPY scripts/backup-scheduler.sh /app/scripts/backup-scheduler.sh
COPY scripts/log-rotation.sh /app/scripts/log-rotation.sh
COPY scripts/setup-cron.sh /app/scripts/setup-cron.sh
COPY scripts/setup-syslog.sh /app/scripts/setup-syslog.sh

# 디렉토리 생성
RUN mkdir -p /app/config /app/data /app/logs /app/certs /backup

# 스크립트 실행 권한
RUN chmod +x /app/kmip-server \
    /app/scripts/backup-scheduler.sh \
    /app/scripts/log-rotation.sh \
    /app/scripts/setup-cron.sh \
    /app/scripts/setup-syslog.sh

# 환경 변수 기본값
ENV BACKUP_RETENTION_DAYS=30 \
    MAX_BACKUPS=10 \
    MAX_LOG_SIZE=100M \
    MAX_LOG_AGE=7 \
    MAX_LOG_BACKUPS=10 \
    COMPRESS_LOGS=true \
    BACKUP_SCHEDULE="0 2 * * *" \
    LOG_ROTATION_SCHEDULE="0 * * * *" \
    SYSLOG_SERVER="" \
    SYSLOG_PORT=514 \
    SYSLOG_PROTOCOL=udp

# 포트 노출
EXPOSE 5696 7000 8080 9090

# 볼륨
VOLUME ["/app/data", "/app/logs", "/app/config", "/backup"]

# 헬스체크
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:9090/health || exit 1

# 엔트리포인트 스크립트 생성
RUN echo '#!/bin/bash' > /entrypoint.sh && \
    echo 'set -e' >> /entrypoint.sh && \
    echo '' >> /entrypoint.sh && \
    echo '# Syslog 설정' >> /entrypoint.sh && \
    echo 'if [ ! -z "$SYSLOG_SERVER" ]; then' >> /entrypoint.sh && \
    echo '  /app/scripts/setup-syslog.sh' >> /entrypoint.sh && \
    echo 'fi' >> /entrypoint.sh && \
    echo '' >> /entrypoint.sh && \
    echo '# Cron 설정' >> /entrypoint.sh && \
    echo '/app/scripts/setup-cron.sh' >> /entrypoint.sh && \
    echo '' >> /entrypoint.sh && \
    echo '# KMIP 서버 시작' >> /entrypoint.sh && \
    echo 'exec /app/kmip-server "$@"' >> /entrypoint.sh && \
    chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]

# 기본 인자
CMD ["-enable-rest", "-rest-addr", ":9090"]
