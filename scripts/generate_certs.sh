#!/bin/bash

# KMIP 서버용 자체 서명 인증서 생성 스크립트

echo "Generating self-signed certificates for KMIP server..."

# CA 키 생성
openssl genrsa -out ca.key 4096

# CA 인증서 생성
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt \
  -subj "/C=KR/ST=Seoul/L=Seoul/O=KMIP Test CA/CN=KMIP Test CA"

# 서버 키 생성
openssl genrsa -out server.key 4096

# 서버 CSR 생성
openssl req -new -key server.key -out server.csr \
  -subj "/C=KR/ST=Seoul/L=Seoul/O=KMIP Server/CN=localhost"

# 서버 인증서 생성
openssl x509 -req -days 365 -in server.csr \
  -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt \
  -extfile <(echo "subjectAltName=DNS:localhost,IP:127.0.0.1")

# 클라이언트 키 생성 (선택적)
openssl genrsa -out client.key 4096

# 클라이언트 CSR 생성
openssl req -new -key client.key -out client.csr \
  -subj "/C=KR/ST=Seoul/L=Seoul/O=KMIP Client/CN=client"

# 클라이언트 인증서 생성
openssl x509 -req -days 365 -in client.csr \
  -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out client.crt

# 임시 파일 정리
rm -f server.csr client.csr ca.srl

echo "Certificates generated successfully:"
echo "  - ca.crt (CA certificate)"
echo "  - ca.key (CA private key)"
echo "  - server.crt (Server certificate)"
echo "  - server.key (Server private key)"
echo "  - client.crt (Client certificate)"
echo "  - client.key (Client private key)"
echo ""
echo "Start server with: ./kmip-server -cert server.crt -key server.key"
echo "For client authentication: ./kmip-server -cert server.crt -key server.key -ca ca.crt"
