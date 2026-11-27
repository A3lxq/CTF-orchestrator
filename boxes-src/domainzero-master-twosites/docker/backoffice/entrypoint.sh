#!/bin/bash
set -euo pipefail

: "${CTF_SECRET:?CTF_SECRET must be set}"
export CTF_SECRET

getflag() { /opt/venv/bin/python3 -c "import sys; sys.path.insert(0,'/opt/shared'); from generate_flags import flag_for; print(flag_for('$CTF_SECRET', $1))"; }

mkdir -p /var/log/supervisor

# --- boadmin: the real SSH foothold. Password fixed/narrative -- same
# every team by design, matches app.py's BOADMIN_PASSWORD constant, and
# is only ever discoverable via the GraphQL over-fetch bug on /graphql,
# never written anywhere a player could find without exploiting it. ----
BOADMIN_PASSWORD="Back0ffice-Recovery-9x!"
echo "boadmin:${BOADMIN_PASSWORD}" | chpasswd

HOME_DIR="/home/boadmin"
getflag 7 > "$HOME_DIR/user.txt"

cat << EOF > "$HOME_DIR/notes.txt"
To-do (leftover from the last admin):
- Stop reusing this recovery password everywhere.
- IT gave this account passwordless sudo on 'perl' ages ago for a
  one-off log-parsing script and never walked it back.
EOF
chown -R boadmin:boadmin "$HOME_DIR"
chmod 600 "$HOME_DIR/user.txt"
chmod 644 "$HOME_DIR/notes.txt"

# --- A root-only file, reachable via the GTFOBins perl escape before --
# going for a full root shell (flag 8). ---------------------------------
mkdir -p /var/log
cat << EOF > /var/log/backoffice_audit.log
[audit] boadmin recovery password unchanged since onboarding
[audit] sudo perl rule still in place -- nobody ever asked IT to remove it

Flag 8: $(getflag 8)
EOF
chown root:root /var/log/backoffice_audit.log
chmod 600 /var/log/backoffice_audit.log

# --- Post-escalation checkpoint (flag 9) + final root flag (flag 10) --
mkdir -p /root
cat << EOF > /root/checkpoint_notes.txt
This workstation was meant to be decommissioned alongside the rest of
the backoffice migration. It's still here -- which is probably how
you got this far.

Flag 9: $(getflag 9)
EOF
chmod 600 /root/checkpoint_notes.txt

getflag 10 > /root/root.txt
chmod 600 /root/root.txt

echo "[entrypoint] Back Office ready."
exec /usr/bin/supervisord -c /etc/supervisor/conf.d/ctf.conf
