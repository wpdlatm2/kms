#!/bin/bash

# TLS 인증서 자동 생성 스크립트

set -e

CERTS_DIR="certs"
DAYS=3650  # 10년

echo "🔐 TLS 인증서 생성 스크립트"
echo "=============================="
echo ""

# 인증서 디렉토리 생성
mkdir -p "$CERTS_DIR"

# 이미 존재하는지 확인
if [ -f "$CERTS_DIR/server.crt" ] && [ -f "$CERTS_DIR/server.key" ]; then
    echo "⚠️  기존 인증서가 발견되었습니다."
    read -p "덮어쓰시겠습니까? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "❌ 취소되었습니다."
        exit 0
    fi
fi

echo "📝 인증서 정보 입력"
echo "-------------------"

# 기본값 설정
DEFAULT_COUNTRY="KR"
DEFAULT_STATE="Seoul"
DEFAULT_CITY="Seoul"
DEFAULT_ORG="KMIP Server"
DEFAULT_CN="localhost"

read -p "국가 코드 (KR): " COUNTRY
COUNTRY=${COUNTRY:-$DEFAULT_COUNTRY}

read -p "시/도 (Seoul): " STATE
STATE=${STATE:-$DEFAULT_STATE}

read -p "시/군/구 (Seoul): " CITY
CITY=${CITY:-$DEFAULT_CITY}

read -p "조직명 (KMIP Server): " ORG
ORG=${ORG:-$DEFAULT_ORG}

read -p "Common Name (localhost): " CN
CN=${CN:-$DEFAULT_CN}

echo ""
echo "📋 인증서 정보:"
echo "  국가: $COUNTRY"
echo "  시/도: $STATE"
echo "  시/군/구: $CITY"
echo "  조직: $ORG"
echo "  CN: $CN"
echo "  유효기간: $DAYS일 (약 10년)"
echo ""

# 개인키 생성
echo "🔑 개인키 생성 중..."
openssl genrsa -out "$CERTS_DIR/server.key" 2048

# CSR 생성
echo "📄 CSR 생성 중..."
openssl req -new \
    -key "$CERTS_DIR/server.key" \
    -out "$CERTS_DIR/server.csr" \
    -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORG/CN=$CN"

# 인증서 생성 (자체 서명)
echo "✍️  인증서 서명 중..."
openssl x509 -req \
    -days $DAYS \
    -in "$CERTS_DIR/server.csr" \
    -signkey "$CERTS_DIR/server.key" \
    -out "$CERTS_DIR/server.crt" \
    -extfile <(printf "subjectAltName=DNS:localhost,DNS:*.localhost,IP:127.0.0.1")

# CSR 파일 삭제 (더 이상 필요 없음)
rm "$CERTS_DIR/server.csr"

# 권한 설정
chmod 600 "$CERTS_DIR/server.key"
chmod 644 "$CERTS_DIR/server.crt"

echo ""
echo "✅ 인증서 생성 완료!"
echo "===================="
echo ""
echo "📁 생성된 파일:"
echo "  인증서: $CERTS_DIR/server.crt"
echo "  개인키: $CERTS_DIR/server.key"
echo ""
echo "🔍 인증서 정보 확인:"
echo "  openssl x509 -in $CERTS_DIR/server.crt -text -noout"
echo ""
echo "🚀 웹 서버 시작:"
echo "  cd cmd/web-ui"
echo "  go run main.go"
echo ""
echo "🌐 접속 주소:"
echo "  https://localhost:8443"
echo ""
echo "⚠️  브라우저 경고:"
echo "  자체 서명 인증서이므로 브라우저에서 보안 경고가 표시됩니다."
echo "  '고급' → '안전하지 않음(계속)' 클릭하여 접속하세요."
echo ""
echo "💡 프로덕션 환경:"
echo "  Let's Encrypt 등의 공인 인증서 사용을 권장합니다."
echo ""
