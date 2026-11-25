#!/bin/bash
set -e

: "${CTF_SECRET:?CTF_SECRET must be set}"
export CTF_SECRET

flag() { python3 /opt/generate_flags.py "$1"; }

SVC_PASSWORD="Reception2024!"  # fixed/narrative -- discoverable via the leaked config backup, same for every team by design

echo "[*] Initializing Meridian Systems Reception Server..."

# --- Linux account (also the SMB account, and the SSH foothold) --------
if ! id svc_helpdesk &>/dev/null; then
    useradd -m -s /bin/bash svc_helpdesk
fi
echo "svc_helpdesk:${SVC_PASSWORD}" | chpasswd
mkdir -p /var/lib/samba/private
printf '%s\n%s\n' "${SVC_PASSWORD}" "${SVC_PASSWORD}" | smbpasswd -s -a svc_helpdesk

mkdir -p /run/sshd

# --- Share content, flags substituted in place --------------------------
sed -i "s/FLAG1_PLACEHOLDER/$(flag 1)/" /srv/shares/reception/welcome.txt
sed -i "s/FLAG2_PLACEHOLDER/$(flag 2)/" /srv/shares/reception/staff_directory.txt
sed -i "s/FLAG3_PLACEHOLDER/$(flag 3)/" /srv/shares/ops-archive/readme.txt
sed -i "s/FLAG4_PLACEHOLDER/$(flag 4)/" /srv/shares/ops-archive/backup_svc_config.xml.bak
sed -i "s/FLAG5_PLACEHOLDER/$(flag 5)/" /srv/shares/secure-ops/internal_memo.txt
chmod -R a+rX /srv/shares

# --- svc_helpdesk's home: SSH foothold (flag 6) + a hint toward the ---
# --- sudo/less GTFOBins privesc (flag 7) -------------------------------
HOME_DIR="/home/svc_helpdesk"
echo "$(flag 6)" > "$HOME_DIR/user.txt"

cat << EOF > "$HOME_DIR/notes.txt"
To-do:
- Stop reusing the helpdesk password everywhere (yeah, right).
- IT gave me passwordless sudo on 'less' ages ago so I can review
  logs without bugging ops for root. Never got around to asking for
  anything narrower.

Flag 7: $(flag 7)
EOF
chown -R svc_helpdesk:svc_helpdesk "$HOME_DIR"
chmod 600 "$HOME_DIR/user.txt"
chmod 644 "$HOME_DIR/notes.txt"

# --- A root-only log, reachable via the 'less' GTFOBins trick before --
# --- going for a full root shell (flag 8) ------------------------------
mkdir -p /var/log
cat << EOF > /var/log/secure_ops.log
[ops] rotation reminder dispatched again, still ignored
[ops] svc_helpdesk password unchanged since onboarding

Flag 8: $(flag 8)
EOF
chown root:root /var/log/secure_ops.log
chmod 600 /var/log/secure_ops.log

# --- sudoers: svc_helpdesk may run 'less' as root, no password ---------
cat << 'EOF' > /etc/sudoers.d/svc_helpdesk
svc_helpdesk ALL=(ALL) NOPASSWD: /usr/bin/less
EOF
chmod 440 /etc/sudoers.d/svc_helpdesk

# --- Post-escalation checkpoint (flag 9) + final root flag (flag 10) --
mkdir -p /root
cat << EOF > /root/decommission_notes.txt
This box is slated for decommission once the helpdesk tooling
migration finishes. Nobody's touched it in months -- which is
probably how you got this far.

Flag 9: $(flag 9)
EOF
chmod 600 /root/decommission_notes.txt

echo "$(flag 10)" > /root/root.txt
chmod 600 /root/root.txt

ssh-keygen -A

service smbd start
service nmbd start
exec /usr/sbin/sshd -D -e
