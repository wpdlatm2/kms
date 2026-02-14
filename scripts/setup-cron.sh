#!/bin/bash
# KMIP Cron 스케줄러 설정

set -e

# 설정
CRON_FILE="/etc/crontabs/root"
BACKUP_SCRIPT="/app/scripts/backup-scheduler.sh"
LOG_ROTATION_SCRIPT="/app/scripts/log-rotation.sh"

# 백업 스케줄 (기본값)
BACKUP_SCHEDULE=${BACKUP_SCHEDULE:-"0 2 * * *"}      # 매일 새벽 2시
LOG_ROTATION_SCHEDULE=${LOG_ROTATION_SCHEDULE:-"0 * * * *"}  # 매시간

echo "=== Setting up KMIP Cron Scheduler ==="
echo ""

# crond 설치 확인 (Alpine)
if ! command -v crond &> /dev/null; then
    echo "Installing crond..."
    apk add --no-cache busybox-suid
fi

# cron 디렉토리 생성
mkdir -p /etc/crontabs
touch ${CRON_FILE}

# 기존 KMIP 관련 cron 제거
sed -i '/backup-scheduler.sh/d' ${CRON_FILE}
sed -i '/log-rotation.sh/d' ${CRON_FILE}

# 백업 스케줄 추가
echo "# KMIP Backup Scheduler" >> ${CRON_FILE}
echo "${BACKUP_SCHEDULE} ${BACKUP_SCRIPT} backup >> /app/logs/cron.log 2>&1" >> ${CRON_FILE}

# 로그 로테이션 스케줄 추가
echo "# KMIP Log Rotation" >> ${CRON_FILE}
echo "${LOG_ROTATION_SCHEDULE} ${LOG_ROTATION_SCRIPT} rotate >> /app/logs/cron.log 2>&1" >> ${CRON_FILE}

# 빈 줄 추가
echo "" >> ${CRON_FILE}

echo "✓ Cron schedules added:"
echo "  Backup: ${BACKUP_SCHEDULE}"
echo "  Log Rotation: ${LOG_ROTATION_SCHEDULE}"
echo ""

# cron 파일 출력
echo "Current crontab:"
cat ${CRON_FILE}
echo ""

# crond 시작
if pgrep crond > /dev/null; then
    echo "✓ crond is already running"
else
    echo "Starting crond..."
    crond -b -l 2
    echo "✓ crond started"
fi

echo ""
echo "=== Scheduler Setup Complete ==="
echo ""
echo "Monitor cron logs:"
echo "  tail -f /app/logs/cron.log"
echo ""
echo "Manual execution:"
echo "  ${BACKUP_SCRIPT} backup"
echo "  ${LOG_ROTATION_SCRIPT} rotate"
