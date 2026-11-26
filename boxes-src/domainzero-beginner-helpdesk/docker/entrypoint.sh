#!/bin/bash
set -e

: "${CTF_SECRET:?CTF_SECRET must be set}"
export CTF_SECRET

flag() { python3 /opt/generate_flags.py "$1"; }

OPS_PASSWORD="Triage-Escalate-99!"  # fixed/narrative -- matches app.js's own constant, leaked via the auth-bypassed admin endpoint

echo "[*] Initializing Meridian Systems Helpdesk..."

mkdir -p /opt/app
python3 /opt/generate_flags.py all-json > /opt/app/flags.json

# --- Linux account (also the SSH foothold, password reused from the --
# --- leaked admin-endpoint credential) -----------------------------------
if ! id ops-triage &>/dev/null; then
    useradd -m -s /bin/bash ops-triage
fi
echo "ops-triage:${OPS_PASSWORD}" | chpasswd
mkdir -p /run/sshd
ssh-keygen -A

# --- SSH foothold flag + a hint toward the sudo/GTFOBins privesc --------
HOME_DIR="/home/ops-triage"
echo "$(flag 7)" > "$HOME_DIR/user.txt"
cat << EOF > "$HOME_DIR/notes.txt"
To-do:
- Stop reusing the admin-endpoint password as my own login.
- IT gave me passwordless sudo on 'vi' ages ago so I can edit configs
  without bugging ops for root. Never got around to asking for
  anything narrower.

Flag 8: $(flag 8)
EOF
chown -R ops-triage:ops-triage "$HOME_DIR"
chmod 600 "$HOME_DIR/user.txt"
chmod 644 "$HOME_DIR/notes.txt"

# --- A root-only file, reachable via the 'vi' GTFOBins trick before ----
# --- going for a full root shell (flag 9) --------------------------------
mkdir -p /var/log
cat << EOF > /var/log/helpdesk-admin.log
[audit] prototype-pollution report filed, still open
[audit] ops-triage password unchanged since onboarding

Flag 9: $(flag 9)
EOF
chown root:root /var/log/helpdesk-admin.log
chmod 600 /var/log/helpdesk-admin.log

# --- sudoers: ops-triage may run 'vi' as root, no password --------------
cat << 'EOF' > /etc/sudoers.d/ops-triage
ops-triage ALL=(ALL) NOPASSWD: /usr/bin/vi
EOF
chmod 440 /etc/sudoers.d/ops-triage

# --- Final root flag ------------------------------------------------------
echo "$(flag 10)" > /root/root.txt
chmod 600 /root/root.txt

node /opt/app/app.js &

exec /usr/sbin/sshd -D -e
