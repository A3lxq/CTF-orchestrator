#!/bin/bash
set -euo pipefail

: "${CTF_SECRET:?CTF_SECRET must be set}"
export CTF_SECRET

mkdir -p /var/log/supervisor

/opt/venv/bin/python3 /opt/boot_setup.py

ssh-keygen -A >/dev/null 2>&1 || true

echo "[entrypoint] ledger-tools ready."
exec /usr/bin/supervisord -c /etc/supervisor/conf.d/ctf.conf
