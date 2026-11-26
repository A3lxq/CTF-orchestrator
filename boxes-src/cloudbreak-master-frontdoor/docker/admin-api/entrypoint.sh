#!/bin/bash
set -euo pipefail

: "${CTF_SECRET:?CTF_SECRET must be set}"
export CTF_SECRET

# Matches app.py's own OPS_SSH_PASSWORD constant -- disclosed to players
# only via the /admin/users smuggling target (flag 5's JSON blob).
OPS_SSH_PASSWORD="NimbusOps-Patch-Me-2026!"

mkdir -p /var/log/supervisor /root/secret

getflag() { /usr/bin/python3 -c "import sys; sys.path.insert(0,'/opt/shared'); from generate_flags import flag_for; print(flag_for('$CTF_SECRET', $1))"; }

# --- ops account: the SSH foothold, flag 6 ---------------------------------
echo "ops:${OPS_SSH_PASSWORD}" | chpasswd
getflag 6 > /home/ops/user.txt
chown ops:ops /home/ops/user.txt
chmod 600 /home/ops/user.txt

# --- hint pointing at the sudo/GTFOBins privesc, flag 7 ---------------------
cat > /home/ops/notes.txt <<EOF
To-do:
- Ops left passwordless sudo on 'env' for a one-off deploy wrapper years
  ago and never got around to scoping it down. GTFOBins has the escape
  for this one if I ever forget: sudo env /bin/sh.

Flag 7: $(getflag 7)
EOF
chown ops:ops /home/ops/notes.txt
chmod 644 /home/ops/notes.txt

# --- root-only file, reachable only via the env escape, flag 8 -------------
cat > /root/secret/audit.log <<EOF
[audit] ops's sudo 'env' rule has never been scoped down since it was
[audit] added for the one-off deploy wrapper mentioned in notes.txt

Flag 8: $(getflag 8)
EOF
chown root:root /root/secret/audit.log
chmod 600 /root/secret/audit.log

# --- pre-root checkpoint note, reachable the same way, flag 9 --------------
cat > /root/secret/checkpoint.txt <<EOF
Pre-root checkpoint -- if you can read this, the env escalation worked.
root.txt is right next to this file.

Flag 9: $(getflag 9)
EOF
chown root:root /root/secret/checkpoint.txt
chmod 600 /root/secret/checkpoint.txt

# --- root.txt, flag 10 -------------------------------------------------------
getflag 10 > /root/root.txt
chown root:root /root/root.txt
chmod 600 /root/root.txt

ssh-keygen -A >/dev/null 2>&1 || true

echo "[entrypoint] admin-api ready."
exec /usr/bin/supervisord -c /etc/supervisor/conf.d/ctf.conf
