#!/usr/bin/env bash
# Installs the host agent as a systemd service (run as root from the deployment directory).
# The agent needs access to docker: the service user must be in the docker group (the user that owns this folder).
set -euo pipefail
cd "$(dirname "$0")"
DIR="$(pwd)"
USER_NAME="$(stat -c %U "$DIR")"
id -nG "$USER_NAME" | tr ' ' '\n' | grep -qx docker || { echo "user $USER_NAME is not in the docker group"; exit 1; }
install -d -m 750 -o "$USER_NAME" run
sed -e "s|@USER@|$USER_NAME|g" -e "s|@DIR@|$DIR|g" kmsagent.service.in > /etc/systemd/system/pqc-kms-agent.service
systemctl daemon-reload
systemctl enable --now pqc-kms-agent.service
sleep 1
systemctl --no-pager --lines=5 status pqc-kms-agent.service || true
ls -l run/agent.sock
