#!/bin/bash

# Let's Encrypt 인증서 자동 설정 및 갱신 스크립트
# Certbot을 사용하여 무료 SSL 인증서 발급

set -e

echo "🔐 Let's Encrypt 인증서 설정"
echo "=============================="
echo ""

# Certbot 설치 확인
if ! command -v certbot &> /dev/null; then
    echo "📦 Certbot 설치 중..."
    
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Ubuntu/Debian
        if command -v apt-get &> /dev/null; then
            sudo apt-get update
            sudo apt-get install -y certbot
        # CentOS/RHEL
        elif command -v yum &> /dev/null; then
            sudo yum install -y certbot
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        brew install certbot
    else
        echo "❌ 지원하지 않는 운영체제입니다."
        exit 1
    fi
fi

echo "📝 도메인 정보 입력"
echo "-------------------"
echo ""

read -p "도메인 이름 (예: kmip.example.com): " DOMAIN

if [ -z "$DOMAIN" ]; then
    echo "❌ 도메인을 입력해야 합니다."
    exit 1
fi

read -p "이메일 주소 (인증서 만료 알림용): " EMAIL

if [ -z "$EMAIL" ]; then
    echo "❌ 이메일을 입력해야 합니다."
    exit 1
fi

echo ""
echo "⚠️  주의사항:"
echo "  1. 도메인이 이 서버의 공인 IP를 가리켜야 합니다."
echo "  2. 80포트가 열려 있어야 합니다 (인증용)."
echo "  3. 방화벽에서 80, 443 포트를 허용해야 합니다."
echo ""

read -p "계속하시겠습니까? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "❌ 취소되었습니다."
    exit 0
fi

# Standalone 모드로 인증서 발급
echo ""
echo "🔄 인증서 발급 중..."
echo ""

sudo certbot certonly \
    --standalone \
    --preferred-challenges http \
    --email "$EMAIL" \
    --agree-tos \
    --no-eff-email \
    -d "$DOMAIN"

# 인증서 위치
CERT_DIR="/etc/letsencrypt/live/$DOMAIN"
CERTS_DIR="certs"

# 심볼릭 링크 생성
echo ""
echo "🔗 인증서 링크 생성 중..."

mkdir -p "$CERTS_DIR"

sudo ln -sf "$CERT_DIR/fullchain.pem" "$CERTS_DIR/server.crt"
sudo ln -sf "$CERT_DIR/privkey.pem" "$CERTS_DIR/server.key"

# 권한 설정
sudo chmod 644 "$CERTS_DIR/server.crt"
sudo chmod 600 "$CERTS_DIR/server.key"

# 자동 갱신 설정
echo ""
echo "⏰ 자동 갱신 설정 중..."

# Cron 작업 추가 (매월 1일 자정에 갱신 시도)
CRON_JOB="0 0 1 * * certbot renew --quiet --post-hook 'systemctl restart kmip-web-ui'"

(crontab -l 2>/dev/null | grep -v "certbot renew"; echo "$CRON_JOB") | crontab -

echo ""
echo "✅ Let's Encrypt 인증서 설정 완료!"
echo "===================================="
echo ""
echo "📁 인증서 위치:"
echo "  원본: $CERT_DIR"
echo "  링크: $CERTS_DIR/server.crt"
echo "  링크: $CERTS_DIR/server.key"
echo ""
echo "🔄 자동 갱신:"
echo "  Cron 작업이 등록되어 매월 1일에 자동 갱신됩니다."
echo "  수동 갱신: sudo certbot renew"
echo ""
echo "🚀 웹 서버 시작:"
echo "  cd cmd/web-ui"
echo "  sudo TLS_CERT_FILE=$CERTS_DIR/server.crt TLS_KEY_FILE=$CERTS_DIR/server.key go run main.go"
echo ""
echo "🌐 접속 주소:"
echo "  https://$DOMAIN:8443"
echo ""
echo "💡 팁:"
echo "  - 웹 서버를 systemd 서비스로 등록하여 자동 시작"
echo "  - Nginx를 리버스 프록시로 사용하여 443 포트로 서비스"
echo ""
