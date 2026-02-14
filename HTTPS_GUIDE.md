# 🔒 HTTPS 웹 서버 설정 가이드

## 개요

웹 UI 서버에 **TLS/SSL 암호화**를 적용하여 안전한 HTTPS 통신을 제공합니다.

### 주요 기능

- ✅ **TLS 1.2+ 지원**: 최신 보안 프로토콜
- ✅ **자체 서명 인증서**: 개발/테스트 환경
- ✅ **Let's Encrypt**: 프로덕션 환경 무료 인증서
- ✅ **HTTP → HTTPS 리다이렉트**: 자동 전환
- ✅ **강력한 암호화 스위트**: 보안 강화
- ✅ **자동 인증서 갱신**: Let's Encrypt

## 🚀 빠른 시작

### 방법 1: 자체 서명 인증서 (개발용)

```bash
# 1. 인증서 생성
./scripts/generate-certs.sh

# 2. 웹 서버 시작
cd cmd/web-ui
go run main.go

# 3. 브라우저 접속
https://localhost:8443
```

### 방법 2: Let's Encrypt (프로덕션용)

```bash
# 1. Let's Encrypt 설정
./scripts/setup-letsencrypt.sh

# 2. 웹 서버 시작
cd cmd/web-ui
sudo go run main.go

# 3. 브라우저 접속
https://your-domain.com:8443
```

## 📋 자체 서명 인증서

### 인증서 생성

```bash
./scripts/generate-certs.sh
```

**대화형 입력:**
```
국가 코드 (KR): KR
시/도 (Seoul): Seoul
시/군/구 (Seoul): Gangnam
조직명 (KMIP Server): My Company
Common Name (localhost): localhost
```

**생성되는 파일:**
```
certs/
├── server.crt  (인증서)
└── server.key  (개인키)
```

### 인증서 정보 확인

```bash
# 인증서 상세 정보
openssl x509 -in certs/server.crt -text -noout

# 인증서 유효기간
openssl x509 -in certs/server.crt -noout -dates

# 인증서와 키 일치 확인
openssl x509 -noout -modulus -in certs/server.crt | openssl md5
openssl rsa -noout -modulus -in certs/server.key | openssl md5
```

### 브라우저 경고 해결

자체 서명 인증서는 브라우저에서 경고를 표시합니다:

**Chrome:**
```
1. "고급" 클릭
2. "localhost(으)로 이동(안전하지 않음)" 클릭
```

**Firefox:**
```
1. "고급" 클릭
2. "위험을 감수하고 계속" 클릭
```

**Safari:**
```
1. "세부사항 보기" 클릭
2. "웹 사이트 방문" 클릭
```

### 인증서를 신뢰할 수 있는 인증서로 등록 (선택)

**macOS:**
```bash
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain certs/server.crt
```

**Linux (Ubuntu/Debian):**
```bash
sudo cp certs/server.crt /usr/local/share/ca-certificates/kmip-server.crt
sudo update-ca-certificates
```

**Windows:**
```
1. server.crt 더블클릭
2. "인증서 설치" 클릭
3. "신뢰할 수 있는 루트 인증 기관" 선택
```

## 🌐 Let's Encrypt (무료 공인 인증서)

### 사전 요구사항

1. **공인 도메인**: 도메인이 서버 IP를 가리켜야 함
2. **80포트 개방**: 인증 과정에서 필요
3. **방화벽 설정**: 80, 443 포트 허용

### 인증서 발급

```bash
./scripts/setup-letsencrypt.sh
```

**입력 정보:**
```
도메인 이름: kmip.example.com
이메일 주소: admin@example.com
```

### 수동 인증서 발급

```bash
# Certbot 설치
sudo apt-get install certbot  # Ubuntu/Debian
sudo yum install certbot       # CentOS/RHEL

# 인증서 발급
sudo certbot certonly \
  --standalone \
  --preferred-challenges http \
  --email admin@example.com \
  --agree-tos \
  -d kmip.example.com

# 인증서 위치 확인
ls -la /etc/letsencrypt/live/kmip.example.com/
```

### 인증서 갱신

**자동 갱신 (Cron):**
```bash
# Crontab 등록 (매월 1일 자정)
0 0 1 * * certbot renew --quiet --post-hook 'systemctl restart kmip-web-ui'
```

**수동 갱신:**
```bash
sudo certbot renew
```

**갱신 테스트:**
```bash
sudo certbot renew --dry-run
```

### 인증서 심볼릭 링크

```bash
# 프로젝트 certs 디렉토리에 링크
mkdir -p certs
sudo ln -sf /etc/letsencrypt/live/kmip.example.com/fullchain.pem certs/server.crt
sudo ln -sf /etc/letsencrypt/live/kmip.example.com/privkey.pem certs/server.key
```

## 🔧 서버 설정

### 환경 변수

```bash
# 인증서 경로 지정
export TLS_CERT_FILE="certs/server.crt"
export TLS_KEY_FILE="certs/server.key"

# 웹 서버 시작
cd cmd/web-ui
go run main.go
```

### 포트 변경

**코드 수정:**
```go
// cmd/web-ui/main.go
server := &http.Server{
    Addr:      ":443",  // 기본 HTTPS 포트
    TLSConfig: tlsConfig,
}
```

**443 포트 사용 (권한 필요):**
```bash
# 방법 1: sudo 사용
sudo go run main.go

# 방법 2: setcap 사용
go build -o web-ui main.go
sudo setcap CAP_NET_BIND_SERVICE=+eip web-ui
./web-ui
```

## 🔒 TLS 설정

### 보안 강화

현재 설정된 TLS 옵션:

```go
tlsConfig := &tls.Config{
    MinVersion: tls.VersionTLS12,  // TLS 1.2 이상만 허용
    PreferServerCipherSuites: true, // 서버 우선 암호화
    CipherSuites: []uint16{
        tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    },
}
```

### TLS 1.3 활성화

```go
tlsConfig := &tls.Config{
    MinVersion: tls.VersionTLS13,  // TLS 1.3만 허용
}
```

### HSTS 헤더 추가

```go
// HTTP Strict Transport Security
w.Header().Set("Strict-Transport-Security", 
    "max-age=31536000; includeSubDomains; preload")
```

## 📊 접속 테스트

### SSL Labs 테스트

```
https://www.ssllabs.com/ssltest/analyze.html?d=your-domain.com
```

### OpenSSL 테스트

```bash
# TLS 연결 테스트
openssl s_client -connect localhost:8443

# 특정 TLS 버전 테스트
openssl s_client -connect localhost:8443 -tls1_2
openssl s_client -connect localhost:8443 -tls1_3

# 인증서 체인 확인
openssl s_client -connect localhost:8443 -showcerts
```

### curl 테스트

```bash
# HTTPS 요청
curl https://localhost:8443

# 자체 서명 인증서 무시 (테스트용)
curl -k https://localhost:8443

# 인증서 검증
curl --cacert certs/server.crt https://localhost:8443
```

## 🐳 Docker 환경

### Dockerfile

```dockerfile
FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY . .
RUN go build -o web-ui cmd/web-ui/main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates openssl

WORKDIR /root/
COPY --from=builder /app/web-ui .
COPY --from=builder /app/certs ./certs

EXPOSE 8443
CMD ["./web-ui"]
```

### Docker Compose

```yaml
version: '3.8'

services:
  web-ui:
    build: .
    ports:
      - "8443:8443"
      - "8080:8080"
    volumes:
      - ./certs:/root/certs:ro
    environment:
      - TLS_CERT_FILE=/root/certs/server.crt
      - TLS_KEY_FILE=/root/certs/server.key
    restart: unless-stopped
```

## 🔄 Nginx 리버스 프록시

### 설정 파일

```nginx
# /etc/nginx/sites-available/kmip-web-ui
server {
    listen 80;
    server_name kmip.example.com;
    
    # HTTP to HTTPS redirect
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name kmip.example.com;
    
    # SSL 인증서
    ssl_certificate /etc/letsencrypt/live/kmip.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/kmip.example.com/privkey.pem;
    
    # SSL 설정
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers 'ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256';
    
    # HSTS
    add_header Strict-Transport-Security "max-age=31536000" always;
    
    # 프록시 설정
    location / {
        proxy_pass https://localhost:8443;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### 설정 적용

```bash
# 심볼릭 링크 생성
sudo ln -s /etc/nginx/sites-available/kmip-web-ui \
            /etc/nginx/sites-enabled/

# 설정 테스트
sudo nginx -t

# Nginx 재시작
sudo systemctl restart nginx
```

## 🎯 Systemd 서비스

### 서비스 파일 설치

```bash
# 서비스 파일 복사
sudo cp scripts/kmip-web-ui.service /etc/systemd/system/

# 서비스 활성화
sudo systemctl daemon-reload
sudo systemctl enable kmip-web-ui
sudo systemctl start kmip-web-ui

# 상태 확인
sudo systemctl status kmip-web-ui

# 로그 확인
sudo journalctl -u kmip-web-ui -f
```

### 서비스 관리

```bash
# 시작
sudo systemctl start kmip-web-ui

# 중지
sudo systemctl stop kmip-web-ui

# 재시작
sudo systemctl restart kmip-web-ui

# 상태
sudo systemctl status kmip-web-ui
```

## 🐛 트러블슈팅

### 인증서 오류

```
문제: "certificate signed by unknown authority"
해결:
1. 자체 서명 인증서인 경우: 브라우저에서 예외 추가
2. Let's Encrypt인 경우: 인증서 체인 확인
   sudo certbot certificates
```

### 포트 충돌

```
문제: "bind: address already in use"
해결:
1. 실행 중인 프로세스 확인
   sudo lsof -i :8443
2. 프로세스 종료
   sudo kill -9 <PID>
```

### 권한 오류

```
문제: "permission denied" (443 포트)
해결:
1. sudo 사용
   sudo go run main.go
2. setcap 사용
   sudo setcap CAP_NET_BIND_SERVICE=+eip ./web-ui
```

### 인증서 갱신 실패

```
문제: Let's Encrypt 갱신 실패
해결:
1. 80포트 확인
   sudo netstat -tlnp | grep :80
2. 방화벽 확인
   sudo ufw status
3. DNS 확인
   nslookup kmip.example.com
```

## 📊 보안 체크리스트

```
✅ TLS 1.2 이상 사용
✅ 강력한 암호화 스위트
✅ HSTS 헤더 설정
✅ 인증서 유효기간 모니터링
✅ 자동 갱신 설정
✅ HTTP → HTTPS 리다이렉트
✅ 방화벽 설정
✅ 로그 모니터링
```

## 🎉 요약

```
✅ HTTPS/TLS 암호화 지원
✅ 자체 서명 인증서 (개발)
✅ Let's Encrypt (프로덕션)
✅ 자동 인증서 갱신
✅ HTTP → HTTPS 리다이렉트
✅ TLS 1.2+ 지원
✅ 강력한 암호화
✅ Systemd 서비스
✅ Nginx 리버스 프록시
✅ Docker 지원
```

**이제 안전한 HTTPS로 웹 UI를 서비스하세요!** 🔒✨
