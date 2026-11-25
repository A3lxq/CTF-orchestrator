#!/bin/bash
set -e

: "${CTF_SECRET:?CTF_SECRET must be set}"
export CTF_SECRET

flag() { python3 /scripts/generate_flags.py "$1"; }

echo "[*] Initializing Apex Cyber Defense Exam Environment..."

if ! id "alicesmith" &>/dev/null; then
    useradd -m -s /bin/bash alicesmith
    echo "alicesmith:CyberVanguard" | chpasswd
fi

USER_HOME="/home/alicesmith"
mkdir -p "$USER_HOME/.ssh"
chmod 700 "$USER_HOME/.ssh"

if [ -f "/scripts/id_rsa" ]; then
    cp "/scripts/id_rsa" "$USER_HOME/.ssh/id_rsa"
    cp "/scripts/id_rsa.pub" "$USER_HOME/.ssh/authorized_keys"
else
    ssh-keygen -t rsa -b 2048 -f "$USER_HOME/.ssh/id_rsa" -N "" -C "alicesmith@apexdefense.local"
    cp "$USER_HOME/.ssh/id_rsa.pub" "$USER_HOME/.ssh/authorized_keys"
fi
chmod 600 "$USER_HOME/.ssh/authorized_keys"
chmod 600 "$USER_HOME/.ssh/id_rsa"

# FTP has ONLY ssh_instructions.txt (No key in FTP!)
rm -rf "$USER_HOME/id_rsa" "$USER_HOME/backups"
cp /scripts/ssh_instructions.txt "$USER_HOME/ssh_instructions.txt"
chmod 644 "$USER_HOME/ssh_instructions.txt"

# Flag 1: web recon -- substitute into the already-deployed about.html
sed -i "s/FLAG1_PLACEHOLDER/$(flag 1)/" /var/www/html/about.html

# Flag 2 & Clue
echo "$(flag 2)" > "$USER_HOME/user.txt"
chmod 600 "$USER_HOME/user.txt"

cat << EOF > "$USER_HOME/clue.txt"
========================================================================
STAGE 3 COMPLETE - PRIVILEGE ESCALATION NOTICE
========================================================================
Flag 2: $(flag 2)

CLUE FOR NEXT STAGE:
The target system has a misconfigured administrative utility.
1. Check what commands your user is permitted to run as root: sudo -l
2. Check GTFOBins (https://gtfobins.github.io/) to exploit this binary.
3. Catch a root reverse shell (nc -lvnp 4444) or spawn root.
4. Capture the final root flag located at: /root/root.txt
========================================================================
EOF
chmod 644 "$USER_HOME/clue.txt"

# Flags 1-3 are also retrievable as plain files over the same FTP
# session as ssh_instructions.txt/clue.txt/user.txt -- matches the
# original OVA's own /home/ctf/flags/{flag1,flag2,flag3}.txt, except
# flag3.txt here is genuinely distinct (on the OVA it duplicated the
# root flag verbatim; this box has 4 real, independent flags).
echo "$(flag 1)" > "$USER_HOME/flag1.txt"
echo "$(flag 2)" > "$USER_HOME/flag2.txt"
echo "$(flag 3)" > "$USER_HOME/flag3.txt"
chmod 644 "$USER_HOME/flag1.txt" "$USER_HOME/flag2.txt" "$USER_HOME/flag3.txt"

chown -R alicesmith:alicesmith "$USER_HOME"

# Flag 4: root compromise
mkdir -p /root
echo "$(flag 4)" > /root/root.txt
chmod 600 /root/root.txt

# Sudoers
cp /etc/sudoers_exam /etc/sudoers.d/alicesmith 2>/dev/null || true
chmod 440 /etc/sudoers.d/alicesmith

mkdir -p /run/sshd
ssh-keygen -A
mkdir -p /var/run/vsftpd/empty

# Passive FTP port range + externally-reachable address, injected by the
# orchestrator (docker_backend.py/k8s_backend.py via the spec's
# pasv_range). Defaults keep this box working unchanged for a standalone/
# non-orchestrated run (docker-compose.yml's own static port mapping).
PASV_MIN_PORT="${PASV_MIN_PORT:-21100}"
PASV_MAX_PORT="${PASV_MAX_PORT:-21110}"
PASV_ADDRESS="${PASV_ADDRESS:-}"
sed -i \
    -e "s/PASV_MIN_PORT_PLACEHOLDER/$PASV_MIN_PORT/" \
    -e "s/PASV_MAX_PORT_PLACEHOLDER/$PASV_MAX_PORT/" \
    /etc/vsftpd.conf
if [ -n "$PASV_ADDRESS" ]; then
    sed -i "s/PASV_ADDRESS_PLACEHOLDER/$PASV_ADDRESS/" /etc/vsftpd.conf
else
    sed -i "/pasv_address=PASV_ADDRESS_PLACEHOLDER/d" /etc/vsftpd.conf
fi

service nginx start

# Not `service vsftpd start`: that wrapper's `start-stop-daemon
# --background -m` pidfile tracking is unreliable in at least one real
# container/pod environment observed during testing -- it wrote its
# OWN pid (and itself never exited, spinning at 100% CPU) instead of
# vsftpd's actual forked pid, so the init script's own post-start
# `ps -C vsftpd | grep "$_PID"` check always failed even though vsftpd
# was genuinely running fine. Launching it directly sidesteps that
# daemonization dance entirely -- nothing else here needs the pidfile.
/usr/sbin/vsftpd /etc/vsftpd.conf &

exec /usr/sbin/sshd -D -e -f /etc/ssh/sshd_config
