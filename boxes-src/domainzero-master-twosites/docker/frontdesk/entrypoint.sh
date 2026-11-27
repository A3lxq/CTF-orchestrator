#!/bin/bash
set -e

: "${CTF_SECRET:?CTF_SECRET must be set}"
export CTF_SECRET

flag() { python3 /opt/generate_flags.py "$1"; }

# --- TCP relay: frontdesk:2222 -> backoffice:22, frontdesk:4000 ->
# backoffice:4000. backoffice has no published port of its own, so this
# is the real network path a player uses to reach it once they have a
# credential -- see tcp_relay.py's own docstring. Started early (doesn't
# depend on the AD provisioning below at all) and left running in the
# background for the life of the container; samba becomes the
# container's PID 1 via `exec` at the end of this script, same as
# domainzero-intermediate-domainedge's own entrypoint pattern.
python3 /opt/tcp_relay.py &

REALM="DOMAINZERO.LOCAL"
DOMAIN="DOMAINZERO"
ADMIN_BOOTSTRAP_PASSWORD="Pr0vis10n-Only-2024!"  # provisioning-only, never meant to be found by a player

echo "[*] Provisioning the DOMAINZERO domain (frontdesk, two-sites engagement)..."
rm -f /etc/samba/smb.conf  # the package's own default (standalone server role) conflicts with provision
samba-tool domain provision \
    --use-rfc2307 \
    --realm="${REALM}" \
    --domain="${DOMAIN}" \
    --server-role=dc \
    --dns-backend=SAMBA_INTERNAL \
    --adminpass="${ADMIN_BOOTSTRAP_PASSWORD}" >/tmp/provision.log 2>&1

# --- Custom file shares, backed by the domain's own DC, flags substituted
# in place. This box's own flag chain never requires an authenticated SMB
# session on frontdesk itself -- the AD DC is here to be a real, working
# domain controller (same precedent as domainzero-intermediate-domainedge),
# but every recon share below is deliberately guest-accessible so the
# chain's actual gate (pass-the-hash onto backoffice's GraphQL API) isn't
# diluted by a second, unrelated SMB-auth puzzle on this host. ---
mkdir -p /srv/shares/reception /srv/shares/ops-archive
cp /opt/shares/reception/* /srv/shares/reception/
cp /opt/shares/ops-archive/* /srv/shares/ops-archive/

sed -i "s/FLAG1_PLACEHOLDER/$(flag 1)/" /srv/shares/reception/welcome.txt
sed -i "s/FLAG2_PLACEHOLDER/$(flag 2)/" /srv/shares/ops-archive/readme.txt
sed -i "s/FLAG3_PLACEHOLDER/$(flag 3)/" /srv/shares/ops-archive/svc_backoffice_pwdump.bak
chmod -R a+rX /srv/shares

cat >> /etc/samba/smb.conf <<EOF

[reception]
    path = /srv/shares/reception
    guest ok = yes
    browseable = yes
    read only = yes

[ops-archive]
    path = /srv/shares/ops-archive
    guest ok = yes
    browseable = no
    read only = yes
EOF

echo "[*] domainzero-master-twosites (frontdesk) ready."
exec samba -i
