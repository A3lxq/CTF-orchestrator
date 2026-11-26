#!/bin/bash
set -e

: "${CTF_SECRET:?CTF_SECRET must be set}"
export CTF_SECRET

flag() { python3 /opt/generate_flags.py "$1"; }

REALM="DOMAINZERO.LOCAL"
DOMAIN="DOMAINZERO"
ADMIN_BOOTSTRAP_PASSWORD="Pr0vis10n-Only-2024!"  # provisioning-only, never meant to be found by a player
WEAK_USER="r.chen"
WEAK_PASSWORD="Winter2026!"  # fixed/narrative -- the password-spray target, same for every team by design
ESCALATION_USER="svc-helpdesk-lead"
ESCALATION_PASSWORD="Triage-OnCall-2024!"  # fixed/narrative -- leaked via the hr-confidential share

DECOY_USERS=(j.alvarez p.natarajan m.webb d.kowalski s.okafor t.nguyen l.fischer a.bianchi \
             k.oyelaran b.santos c.wren h.park f.dubois n.ibrahim q.delgado v.sokolov \
             w.tremblay z.adeyemi y.lindqvist)
DECOY_PASSWORD="NotTheWeakOne#2026"

echo "[*] Provisioning the DOMAINZERO domain..."
rm -f /etc/samba/smb.conf  # the package's own default (standalone server role) conflicts with provision
samba-tool domain provision \
    --use-rfc2307 \
    --realm="${REALM}" \
    --domain="${DOMAIN}" \
    --server-role=dc \
    --dns-backend=SAMBA_INTERNAL \
    --adminpass="${ADMIN_BOOTSTRAP_PASSWORD}" >/tmp/provision.log 2>&1

echo "[*] Creating domain accounts..."
for u in "${DECOY_USERS[@]}"; do
    samba-tool user create "$u" "${DECOY_PASSWORD}" >/dev/null
done
samba-tool user create "${WEAK_USER}" "${WEAK_PASSWORD}" >/dev/null
samba-tool user create "${ESCALATION_USER}" "${ESCALATION_PASSWORD}" >/dev/null

# --- Start samba once so LDAPS is reachable for the attribute writes ---
samba -i &
echo "[*] Waiting for samba to come up..."
for i in $(seq 1 30); do
    if timeout 1 bash -c "echo > /dev/tcp/127.0.0.1/389" 2>/dev/null; then break; fi
    sleep 1
done
sleep 2

BASE_DN="DC=domainzero,DC=local"
ldap_set_description() {
    local cn="$1" value="$2"
    cat > /tmp/mod.ldif <<EOF
dn: CN=${cn},CN=Users,${BASE_DN}
changetype: modify
replace: description
description: ${value}
EOF
    LDAPTLS_REQCERT=never ldapmodify -x \
        -D "CN=Administrator,CN=Users,${BASE_DN}" -w "${ADMIN_BOOTSTRAP_PASSWORD}" \
        -H ldaps://127.0.0.1 -f /tmp/mod.ldif >/dev/null
}

# Flag 4: the weak-password account's own description -- proves a
# successful password spray + authenticated bind.
ldap_set_description "${WEAK_USER}" "$(flag 4)"
# Flag 9: the escalation account's own description.
ldap_set_description "${ESCALATION_USER}" "$(flag 9)"
# Flag 10: the Administrator's description -- the final capstone,
# readable by any authenticated domain account under AD's own default
# ACLs (not a privilege the player needs to separately earn).
ldap_set_description "Administrator" "$(flag 10)"

# --- Custom file shares, backed by the domain's own accounts ------------
mkdir -p /srv/shares/reception /srv/shares/hr-confidential /srv/shares/it-admin-drop
cp /opt/shares/reception/* /srv/shares/reception/
cp /opt/shares/hr-confidential/* /srv/shares/hr-confidential/
cp /opt/shares/it-admin-drop/* /srv/shares/it-admin-drop/

sed -i "s/FLAG1_PLACEHOLDER/$(flag 1)/" /srv/shares/reception/welcome.txt
sed -i "s/FLAG2_PLACEHOLDER/$(flag 2)/" /srv/shares/reception/employee-list.txt
sed -i "s/FLAG3_PLACEHOLDER/$(flag 3)/" /srv/shares/reception/it-policy.txt
sed -i "s/FLAG5_PLACEHOLDER/$(flag 5)/" /srv/shares/hr-confidential/readme.txt
sed -i "s/FLAG6_PLACEHOLDER/$(flag 6)/" /srv/shares/hr-confidential/escalation-note.txt
sed -i "s/FLAG7_PLACEHOLDER/$(flag 7)/" /srv/shares/it-admin-drop/readme.txt
sed -i "s/FLAG8_PLACEHOLDER/$(flag 8)/" /srv/shares/it-admin-drop/handoff-notes.txt
chmod -R a+rX /srv/shares

cat >> /etc/samba/smb.conf <<EOF

[reception]
    path = /srv/shares/reception
    guest ok = yes
    browseable = yes
    read only = yes

[hr-confidential]
    path = /srv/shares/hr-confidential
    guest ok = no
    browseable = no
    read only = yes
    valid users = ${DOMAIN}\\${WEAK_USER}, ${DOMAIN}\\${ESCALATION_USER}, ${DOMAIN}\\Administrator

[it-admin-drop]
    path = /srv/shares/it-admin-drop
    guest ok = no
    browseable = no
    read only = yes
    valid users = ${DOMAIN}\\${ESCALATION_USER}, ${DOMAIN}\\Administrator
EOF

# Reload smb.conf (new shares) without a full samba restart.
smbcontrol all reload-config >/dev/null 2>&1 || true

echo "[*] domainzero-intermediate-domainedge ready."
wait -n
