#!/bin/bash
set -e

: "${CTF_SECRET:?CTF_SECRET must be set}"
export CTF_SECRET

flag() { python3 /opt/generate_flags.py "$1"; }

REALM="DOMAINZERO.LOCAL"
DOMAIN="DOMAINZERO"
BASE_DN="DC=domainzero,DC=local"
ADMIN_BOOTSTRAP_PASSWORD="Dir3ctory-Provision-Only-2026!"  # provisioning-only, never meant to be found by a player

JCARTER_USER="jcarter"
# Fixed/narrative -- same value search-intranet's own app.py hard-codes as
# jcarter's "directory_password" record, so the NoSQL-injection login on
# that host hands back a real, working AD password for this account.
JCARTER_PASSWORD="Meridian-Newhire-24!"

SVC_REPORTS_USER="svc-reports"
# Fixed but NEVER written to any share, attribute, or log a player can
# reach -- by design, svc-reports is "not directly compromisable by jcarter
# through any normal means." The only way to a usable svc-reports
# credential is the ForceChangePassword abuse below.
SVC_REPORTS_ORIGINAL_PASSWORD="R3ports-0rig-Unknown-$(python3 -c 'import secrets; print(secrets.token_hex(8))')"

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
samba-tool user create "${JCARTER_USER}" "${JCARTER_PASSWORD}" >/dev/null
samba-tool user create "${SVC_REPORTS_USER}" "${SVC_REPORTS_ORIGINAL_PASSWORD}" >/dev/null

JCARTER_SID=$(samba-tool user show "${JCARTER_USER}" 2>/dev/null | awk -F': ' '/^objectSid:/ {print $2}')
echo "[*] jcarter's SID: ${JCARTER_SID}"

# --- THE misconfiguration -------------------------------------------------
# Grant jcarter the User-Force-Change-Password extended right (GUID
# 00299570-246d-11d0-a768-00aa006e0529) over svc-reports, by adding an
# explicit object-specific ACE directly to svc-reports's own
# nTSecurityDescriptor -- the real AD ACL-abuse primitive this tier is
# built around (BloodHound calls this edge "ForceChangePassword").
#
# ForceChangePassword (rather than a blanket GenericWrite) was chosen
# deliberately: it's the more surgical, more realistic misconfiguration for
# a single over-shared service account -- it grants exactly one capability
# (reset THIS account's password, no old password required) rather than
# write access to every non-protected attribute on it. `samba-tool dsacl`
# has no built-in --car choice for it (its --car list only covers DRS/FSMO
# rights), so the ACE is added via --sddl instead.
#
# Confirmed via a pre-build spike (a throwaway `docker run` of this exact
# Samba 4.15.13 base image) that on this Samba version:
#   (a) `samba-tool dsacl set --sddl=...` genuinely rewrites the SD and
#       `samba-tool dsacl get` reads it back unchanged;
#   (b) jcarter can then exploit it for real: `samba-tool user setpassword
#       svc-reports --newpassword=... -U jcarter%<jcarter-password> -H
#       ldap://<dc>` succeeds ("Changed password OK") purely off this ACE;
#   (c) svc-reports can then bind with that NEW password;
#   (d) jcarter can NOT do the same against an unrelated account (e.g.
#       Administrator) with no such ACE -- LDAP error 50, insufficient
#       access rights -- so the grant is genuinely scoped, not a side
#       effect of some broader default.
# `samba-tool dsacl set` operates directly against the local sam.ldb (no
# -H given), same as the `samba-tool user create` calls above -- no need
# for the samba daemon to be running yet.
samba-tool dsacl set \
    --objectdn="CN=${SVC_REPORTS_USER},CN=Users,${BASE_DN}" \
    --sddl="(OA;;CR;00299570-246d-11d0-a768-00aa006e0529;;${JCARTER_SID})" >/dev/null

# --- Start samba once so LDAPS is reachable for the attribute writes ---
samba -i &
echo "[*] Waiting for samba to come up..."
for i in $(seq 1 30); do
    if timeout 1 bash -c "echo > /dev/tcp/127.0.0.1/389" 2>/dev/null; then break; fi
    sleep 1
done
sleep 2

ldap_set_attr() {
    local dn="$1" attr="$2" value="$3"
    cat > /tmp/mod.ldif <<EOF
dn: ${dn}
changetype: modify
replace: ${attr}
${attr}: ${value}
EOF
    LDAPTLS_REQCERT=never ldapmodify -x \
        -D "CN=Administrator,CN=Users,${BASE_DN}" -w "${ADMIN_BOOTSTRAP_PASSWORD}" \
        -H ldaps://127.0.0.1 -f /tmp/mod.ldif >/dev/null
}

# Flag 5: svc-reports's own `description` -- the reward for authenticating
# as jcarter and actually inspecting svc-reports (its nTSecurityDescriptor,
# read via the Microsoft SD_FLAGS control -- a plain unscoped attribute
# read of nTSecurityDescriptor returns nothing even to an authenticated
# non-admin bind, confirmed via the same spike), discovering the
# ForceChangePassword ACE sitting on it. Deliberately NOT gated any
# further -- this is the discovery step, not the exploit itself.
ldap_set_attr "CN=${SVC_REPORTS_USER},CN=Users,${BASE_DN}" description "$(flag 5)"
# Flags 6-8 (the actual proof the password-reset exploit worked, plus the
# privilege-gated reads that follow from it) live on the "reports-archive"
# and "it-vault" SMB shares below, NOT as LDAP attributes. Confirmed via
# the same spike: Samba's dsdb "acl" module does not filter ordinary
# attribute reads (description/info/etc.) by the object's DACL at all --
# any authenticated bind, including jcarter's own, can already read
# svc-reports's or even Domain Admins's plain attributes with no special
# grant. (The one read it DOES gate is nTSecurityDescriptor itself, and
# even that only via the SD_FLAGS control -- see flag 5's comment above.)
# So an LDAP-attribute "reward" readable by any authenticated user would
# have been a free skip straight past the whole ACL-abuse step. SMB's
# `valid users =` share ACL, by contrast, is genuinely enforced per
# connection (same mechanism domainzero-intermediate-domainedge already
# relies on for its own escalation-tier shares) -- so that's the real gate
# for flags 6-8: you cannot even open these shares without a working
# svc-reports SMB session, which requires the password jcarter just set.
# Flag 10: the finale -- "Domain Admins"'s own `info` attribute, the
# AD-native capstone (no Linux shell needed at all, matching
# domainzero-intermediate-domainedge's own precedent of an AD-native
# ending). Intended path: reach it authenticated as svc-reports, having
# earned that identity via the ACL abuse above. Same caveat as that box's
# own flag 10 (its description attribute explicitly calls out being
# "readable under AD's own default ACLs, no special privilege needed") --
# given the attribute-read permissiveness noted above, this is technically
# reachable by any authenticated domain bind, jcarter's included. That's a
# real, known Samba AD DC limitation, not a design oversight specific to
# this box.
ldap_set_attr "CN=Domain Admins,CN=Users,${BASE_DN}" info "$(flag 10)"

# --- Custom file shares, backed by the domain's own accounts ------------
mkdir -p /srv/shares/staff-notices /srv/shares/reports-archive /srv/shares/it-vault
cp /opt/shares/staff-notices/* /srv/shares/staff-notices/
cp /opt/shares/reports-archive/* /srv/shares/reports-archive/
cp /opt/shares/it-vault/* /srv/shares/it-vault/

sed -i "s/FLAG1_PLACEHOLDER/$(flag 1)/" /srv/shares/staff-notices/welcome.txt
sed -i "s/FLAG2_PLACEHOLDER/$(flag 2)/" /srv/shares/staff-notices/app-rollout.txt
sed -i "s/FLAG6_PLACEHOLDER/$(flag 6)/" /srv/shares/reports-archive/readme.txt
sed -i "s/FLAG7_PLACEHOLDER/$(flag 7)/" /srv/shares/reports-archive/quarterly-notes.txt
sed -i "s/FLAG8_PLACEHOLDER/$(flag 8)/" /srv/shares/it-vault/handoff.txt
sed -i "s/FLAG9_PLACEHOLDER/$(flag 9)/" /srv/shares/it-vault/closing-note.txt
chmod -R a+rX /srv/shares

cat >> /etc/samba/smb.conf <<EOF

[staff-notices]
    path = /srv/shares/staff-notices
    guest ok = yes
    browseable = yes
    read only = yes

[reports-archive]
    path = /srv/shares/reports-archive
    guest ok = no
    browseable = no
    read only = yes
    valid users = ${DOMAIN}\\${SVC_REPORTS_USER}, ${DOMAIN}\\Administrator

[it-vault]
    path = /srv/shares/it-vault
    guest ok = no
    browseable = no
    read only = yes
    valid users = ${DOMAIN}\\${SVC_REPORTS_USER}, ${DOMAIN}\\Administrator
EOF

# Reload smb.conf (new shares) without a full samba restart.
smbcontrol all reload-config >/dev/null 2>&1 || true

echo "[*] domainzero-expert-directory (directory host) ready."
wait -n
