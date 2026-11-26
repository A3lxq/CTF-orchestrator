#!/bin/bash
set -e

: "${CTF_SECRET:?CTF_SECRET must be set}"
export CTF_SECRET

flag() { /opt/venv/bin/python3 /opt/app/generate_flags.py "$1"; }

SSH_PASSWORD="NimbusDeploy-Rotate-Me-42!"  # fixed/narrative, matches secretsmgr.py's own copy

echo "[*] Bringing up Nimbus Freight vendor portal..."

# Real cloud providers' link-local metadata address -- added to this
# container's own loopback so imds.py (below) can bind it, exactly the
# way a real cloud instance's kernel already has it configured. Needs
# NET_ADMIN (see the box's spec's extra_capabilities).
ip addr add 169.254.169.254/32 dev lo scope host 2>/dev/null || true

if ! id svc-deploy &>/dev/null; then
    useradd -m -s /bin/bash svc-deploy
fi
echo "svc-deploy:${SSH_PASSWORD}" | chpasswd
mkdir -p /run/sshd
ssh-keygen -A

HOME_DIR="/home/svc-deploy"
echo "$(flag 7)" > "$HOME_DIR/user.txt"
cat << EOF > "$HOME_DIR/notes.txt"
To-do:
- Ops left me passwordless sudo on 'nmap' for a one-off network-mapping
  script years ago. Never got around to asking for anything narrower.
EOF
chown -R svc-deploy:svc-deploy "$HOME_DIR"
chmod 600 "$HOME_DIR/user.txt"
chmod 644 "$HOME_DIR/notes.txt"

# A root-only checkpoint, reachable via the 'nmap' GTFOBins trick
# before going for a full root shell (flag 8).
cat << EOF > /var/log/nmap-scan-audit.log
[audit] svc-deploy's sudo nmap rule has never been scoped down
[audit] the IMDSv1 deploy-role credentials have never been rotated

Flag 8: $(flag 8)
EOF
chown root:root /var/log/nmap-scan-audit.log
chmod 600 /var/log/nmap-scan-audit.log

cat << 'EOF' > /etc/sudoers.d/svc-deploy
svc-deploy ALL=(ALL) NOPASSWD: /usr/bin/nmap
EOF
chmod 440 /etc/sudoers.d/svc-deploy

mkdir -p /root
cat << EOF > /root/decommission_notes.txt
IMDSv2 (session-token-required) was supposed to replace this ages ago.
Migration ticket's still sitting in the backlog.

Flag 9: $(flag 9)
EOF
chmod 600 /root/decommission_notes.txt

echo "$(flag 10)" > /root/root.txt
chmod 600 /root/root.txt

echo "[*] cloudbreak-intermediate-metadata ready."
mkdir -p /var/log/supervisor
exec /usr/bin/supervisord -c /etc/supervisor/conf.d/ctf.conf
