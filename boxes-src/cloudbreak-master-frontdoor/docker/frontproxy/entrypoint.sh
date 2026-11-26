#!/bin/bash
set -euo pipefail

: "${CTF_SECRET:?CTF_SECRET must be set}"
export CTF_SECRET

mkdir -p /var/log/supervisor

echo "[entrypoint] frontproxy ready."
exec /usr/bin/supervisord -c /etc/supervisor/conf.d/ctf.conf
