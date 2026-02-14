#!/bin/bash
# Syslog 원격 전송 설정 스크립트

set -e

# 설정
SYSLOG_SERVER=${SYSLOG_SERVER:-""}
SYSLOG_PORT=${SYSLOG_PORT:-"514"}
SYSLOG_PROTOCOL=${SYSLOG_PROTOCOL:-"udp"}  # udp or tcp
SYSLOG_FACILITY=${SYSLOG_FACILITY:-"local0"}
SYSLOG_TAG=${SYSLOG_TAG:-"kmip"}

RSYSLOG_CONF="/etc/rsyslog.conf"
RSYSLOG_D_DIR="/etc/rsyslog.d"
KMIP_SYSLOG_CONF="${RSYSLOG_D_DIR}/10-kmip.conf"

echo "=== Setting up Syslog Remote Transmission ==="
echo ""

# Syslog 서버 확인
if [ -z "${SYSLOG_SERVER}" ]; then
    echo "⚠️  SYSLOG_SERVER not set. Remote syslog disabled."
    echo ""
    echo "To enable remote syslog, set environment variable:"
    echo "  SYSLOG_SERVER=syslog.example.com"
    echo "  SYSLOG_PORT=514"
    echo "  SYSLOG_PROTOCOL=udp"
    exit 0
fi

echo "Syslog Server: ${SYSLOG_SERVER}:${SYSLOG_PORT} (${SYSLOG_PROTOCOL})"
echo ""

# rsyslog 설치 확인
if ! command -v rsyslogd &> /dev/null; then
    echo "Installing rsyslog..."
    apk add --no-cache rsyslog
fi

# rsyslog 디렉토리 생성
mkdir -p ${RSYSLOG_D_DIR}

# KMIP syslog 설정 파일 생성
cat > ${KMIP_SYSLOG_CONF} << EOF
# KMIP Syslog Configuration
# Generated on $(date)

# 로컬 로그 파일 설정
\$template KMIPLogFormat,"%TIMESTAMP% %HOSTNAME% %syslogtag%%msg%\n"

# KMIP 애플리케이션 로그
if \$programname == '${SYSLOG_TAG}' then {
    # 로컬 파일에 저장
    /app/logs/kmip.log;KMIPLogFormat
    
    # 원격 syslog 서버로 전송
EOF

if [ "${SYSLOG_PROTOCOL}" = "tcp" ]; then
    echo "    @@${SYSLOG_SERVER}:${SYSLOG_PORT}" >> ${KMIP_SYSLOG_CONF}
else
    echo "    @${SYSLOG_SERVER}:${SYSLOG_PORT}" >> ${KMIP_SYSLOG_CONF}
fi

cat >> ${KMIP_SYSLOG_CONF} << EOF
    
    # 추가 처리 중지
    stop
}

# 모든 로그도 원격으로 전송 (선택적)
# *.* @${SYSLOG_SERVER}:${SYSLOG_PORT}

# 백업 로그
if \$programname == '${SYSLOG_TAG}-backup' then {
    /app/logs/backup.log;KMIPLogFormat
EOF

if [ "${SYSLOG_PROTOCOL}" = "tcp" ]; then
    echo "    @@${SYSLOG_SERVER}:${SYSLOG_PORT}" >> ${KMIP_SYSLOG_CONF}
else
    echo "    @${SYSLOG_SERVER}:${SYSLOG_PORT}" >> ${KMIP_SYSLOG_CONF}
fi

cat >> ${KMIP_SYSLOG_CONF} << 'EOF'
    stop
}

# 로그 로테이션 로그
if $programname == 'kmip-rotation' then {
    /app/logs/rotation.log;KMIPLogFormat
    stop
}
EOF

echo "✓ Syslog configuration created: ${KMIP_SYSLOG_CONF}"
echo ""

# 메인 rsyslog 설정 확인/수정
if [ ! -f "${RSYSLOG_CONF}" ]; then
    cat > ${RSYSLOG_CONF} << 'EOF'
# rsyslog configuration

# Load modules
module(load="imuxsock")
module(load="imklog")

# Include custom configurations
$IncludeConfig /etc/rsyslog.d/*.conf

# Default rules
*.info;mail.none;authpriv.none;cron.none    /var/log/messages
authpriv.*                                   /var/log/secure
mail.*                                       -/var/log/maillog
cron.*                                       /var/log/cron
*.emerg                                      :omusrmsg:*
uucp,news.crit                              /var/log/spooler
local7.*                                    /var/log/boot.log
EOF
    echo "✓ Created rsyslog.conf"
fi

# rsyslog 재시작
if pgrep rsyslogd > /dev/null; then
    echo "Restarting rsyslog..."
    killall rsyslogd 2>/dev/null || true
    sleep 1
fi

rsyslogd

if pgrep rsyslogd > /dev/null; then
    echo "✓ rsyslog started"
else
    echo "✗ Failed to start rsyslog"
    exit 1
fi

echo ""
echo "=== Syslog Setup Complete ==="
echo ""
echo "Configuration:"
echo "  Server: ${SYSLOG_SERVER}:${SYSLOG_PORT}"
echo "  Protocol: ${SYSLOG_PROTOCOL}"
echo "  Tag: ${SYSLOG_TAG}"
echo ""
echo "Test syslog:"
echo "  logger -t ${SYSLOG_TAG} 'Test message from KMIP'"
echo ""
echo "View local logs:"
echo "  tail -f /app/logs/kmip.log"
echo ""
echo "Monitor rsyslog:"
echo "  tail -f /var/log/messages"
