#!/usr/bin/env bash
# Prepares the directory this script lives in: PKI, first console user, data folders, .env.
# Idempotent: existing certificates, keys and users are never overwritten.
#   bash setup.sh [--web-san IP_OR_DNS[,IP_OR_DNS...]]    (default SAN of the web certificate: this host + localhost)
set -euo pipefail
cd "$(dirname "$0")"
umask 077

WEB_SAN=""
while [ $# -gt 0 ]; do case "$1" in --web-san) WEB_SAN="$2"; shift 2 ;; *) echo "unknown option $1"; exit 2 ;; esac; done

mkdir -p pki data console secrets
chmod 700 pki secrets

issue() { # issue NAME CN SAN-EXT EKU DAYS
  local n="$1" cn="$2" san="$3" eku="$4" days="$5"
  [ -s "pki/$n.crt" ] && return 0
  openssl req -newkey rsa:3072 -nodes -keyout "pki/$n.key" -out "pki/$n.csr" -subj "/CN=$cn" 2>/dev/null
  printf "extendedKeyUsage=%s\n%s\n" "$eku" "$san" > "pki/$n.ext"
  openssl x509 -req -in "pki/$n.csr" -CA pki/ca.crt -CAkey pki/ca.key -CAcreateserial -out "pki/$n.crt" -days "$days" -extfile "pki/$n.ext" 2>/dev/null
  rm -f "pki/$n.csr" "pki/$n.ext"
  echo "issued $n ($cn)"
}

if [ ! -s pki/ca.crt ]; then
  openssl req -x509 -newkey rsa:4096 -nodes -keyout pki/ca.key -out pki/ca.crt -days 3650 -subj "/CN=pqc-kms internal CA" 2>/dev/null
  echo "created CA"
fi

IPS="$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+\.' | sed 's/^/IP:/' | paste -sd, -)"
SAN_WEB="subjectAltName=DNS:localhost,IP:127.0.0.1${IPS:+,$IPS}"
if [ -n "$WEB_SAN" ]; then
  extra="$(echo "$WEB_SAN" | tr ',' '\n' | while read -r s; do case "$s" in *[a-zA-Z]*) echo "DNS:$s" ;; *) echo "IP:$s" ;; esac; done | paste -sd, -)"
  SAN_WEB="$SAN_WEB,$extra"
fi
issue kms            kms          "subjectAltName=DNS:kms,DNS:localhost,IP:127.0.0.1" serverAuth 825
issue console        console      "$SAN_WEB"                                           serverAuth 825
# the console's own identity towards the backend: it must be listed with -trusted-proxy
issue console-client kms-console  "subjectAltName=DNS:kms-console"                     clientAuth 825
# identity of the key server's self test: a client certificate that is granted nothing at all
issue selfcheck      kms-selfcheck "subjectAltName=DNS:kms-selfcheck"                    clientAuth 825
chmod 600 pki/*.key pki/ca.key
chmod 644 pki/*.crt

if [ ! -s console/users.json ]; then
  [ -x ./kmsadmin ] || { echo "kmsadmin binary missing next to setup.sh"; exit 1; }
  PW="$(openssl rand -base64 24 | tr -d '/+=' | cut -c1-20)-A9"
  printf '%s\n' "$PW" > secrets/admin_password
  chmod 600 secrets/admin_password
  printf '%s\n' "$PW" | ./kmsadmin -users console/users.json useradd admin
  echo "console user 'admin' created (global administrator of the backend); password in $(pwd)/secrets/admin_password"
  echo "the first login asks for the one-time password (OTP) enrollment"
fi

TSS="$(getent group tss | cut -d: -f3 || true)"
[ -f .env ] || printf 'PQC_UID=%s\nPQC_GID=%s\nTSS_GID=%s\nPQC_OTP=required\n' "$(id -u)" "$(id -g)" "${TSS:-985}" > .env
echo "setup done. Next: docker compose build && docker compose up -d"
