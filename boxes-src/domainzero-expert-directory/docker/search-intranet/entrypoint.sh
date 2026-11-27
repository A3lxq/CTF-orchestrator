#!/bin/bash
set -euo pipefail

: "${CTF_SECRET:?CTF_SECRET must be set}"
export CTF_SECRET

echo "[*] search-intranet ready."
exec /opt/venv/bin/python3 /opt/app/app.py
