#!/usr/bin/env bash
# Builds the static Linux binaries used by deploy/Dockerfile: deploy/kmsd and deploy/kmsadmin.
set -euo pipefail
cd "$(dirname "$0")/.."
for b in kmsd kmsadmin kmsagent; do
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o "deploy/$b" "./cmd/$b"
  echo "built deploy/$b"
done
