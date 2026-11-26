"""Phase 15 verification: domainzero-intermediate-domainedge -- the
Intermediate tier of "Domain Zero Directory", and this project's first
real Samba AD DC box. Built on the empirical spike findings recorded in
the plan file / domain-zero-cloudbreak-games.md: Samba's internal KDC
does not honor UF_DONT_REQUIRE_PREAUTH (AS-REP Roasting doesn't work),
so this tier's foothold technique is password spraying instead,
confirmed working against the real KDC via an authenticated LDAPS
bind. Real Kerberoasting (which the spike DID prove works, via the
real system krb5 client) is reserved for the Veteran tier.

Needs `extra_capabilities: [SYS_ADMIN, NET_ADMIN]` on its HostSpec --
confirmed via the spike this is sufficient (no `--privileged` needed)
-- and, on the Kubernetes backend, the same `pod-security.kubernetes.
io/enforce: privileged` namespace label `nested_docker` boxes already
needed, now applied generically to any box with `extra_capabilities`
set (see k8s_backend.py's _provision_sync).

10 real flags, climbing difficulty: anonymous SMB recon (flags 1-3,
including the username list and the weak seasonal-password pattern
hint) -> password spray lands a real domain account, proven via an
authenticated LDAPS bind reading that account's own `description`
attribute (flag 4) -> a domain-auth-gated SMB share (flag 5) -> a
second, escalation-tier credential leaked there (flag 6) -> a second
domain-auth-gated SMB share reachable with it (flags 7-8) -> that
account's own `description` attribute (flag 9) -> the domain
Administrator's own `description` attribute, read under AD's own
default ACLs with no special privilege needed (flag 10).

Real SMB, real authenticated LDAPS binds against a real Samba AD
domain controller -- no mocks. Requires the box image already built
(ctf-boxes/domainzero-intermediate-domainedge:latest), `smbclient` and
`ldap-utils` on PATH, and a running orchestrator reachable at
ORCHESTRATOR_TEST_URL.
"""
import hashlib
import hmac
import os
import secrets as pysecrets
import subprocess
import tempfile

import pytest
import requests

BASE_URL = os.environ.get("ORCHESTRATOR_TEST_URL", "http://127.0.0.1:9100")
BOX_ID = "domainzero-intermediate-domainedge"
_TEAM_ID_BASE = pysecrets.randbelow(1_000_000)

WEAK_USER = "r.chen"
WEAK_PASSWORD = "Winter2026!"  # fixed/narrative -- the password-spray target
ESCALATION_USER = "svc-helpdesk-lead"
ESCALATION_PASSWORD = "Triage-OnCall-2024!"  # fixed/narrative -- leaked via hr-confidential
BASE_DN = "DC=domainzero,DC=local"


def expected_flag(secret: str, n: int) -> str:
    digest = hmac.new(secret.encode(), f"{BOX_ID}:{n}".encode(), hashlib.sha256).hexdigest()
    return f"HLC{{{digest[:10]}}}"


def _port(inst: dict, container_port: int) -> int:
    for p in inst["ports"]:
        if p["container_port"] == container_port:
            return p["host_port"]
    raise AssertionError(f"no port {container_port} in instance ports: {inst['ports']}")


def _smb_get(host: str, port: int, share: str, filename: str, user: str | None = None, password: str | None = None) -> str:
    with tempfile.TemporaryDirectory() as tmp:
        local_path = os.path.join(tmp, "out")
        auth = ["-N"] if user is None else ["-U", f"DOMAINZERO\\{user}%{password}"]
        cmd = ["smbclient", f"//{host}/{share}", "-p", str(port), *auth, "-c", f"get {filename} {local_path}"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        assert result.returncode == 0, f"smbclient failed: {result.stdout} {result.stderr}"
        with open(local_path) as f:
            return f.read()


def _ldap_description(host: str, port: int, bind_user: str, bind_password: str, target_sam: str) -> str:
    result = subprocess.run(
        [
            "ldapsearch", "-x", "-H", f"ldaps://{host}:{port}",
            "-D", f"CN={bind_user},CN=Users,{BASE_DN}", "-w", bind_password,
            "-b", BASE_DN, f"(sAMAccountName={target_sam})", "description",
        ],
        capture_output=True, text=True, timeout=20,
        env={**os.environ, "LDAPTLS_REQCERT": "never"},
    )
    assert result.returncode == 0, f"ldapsearch failed: {result.stderr}"
    for line in result.stdout.splitlines():
        if line.startswith("description:"):
            return line.split(":", 1)[1].strip()
    raise AssertionError(f"no description attribute in ldapsearch output: {result.stdout}")


@pytest.fixture(params=["docker", "kubernetes"])
def box_instance(request):
    backend = request.param
    team_id = _TEAM_ID_BASE + (1 if backend == "docker" else 2)
    secret = pysecrets.token_hex(32)
    r = requests.post(
        f"{BASE_URL}/instances",
        json={"team_id": team_id, "box_id": BOX_ID, "team_secret": secret, "backend": backend},
    )
    r.raise_for_status()
    inst = r.json()
    try:
        yield inst, secret, backend
    finally:
        resp = requests.delete(f"{BASE_URL}/instances/{inst['instance_id']}")
        if not resp.ok:
            raise AssertionError(f"teardown failed to destroy instance: {resp.status_code} {resp.text}")


def test_full_ten_flag_chain(box_instance):
    inst, secret, backend = box_instance
    host = inst["entry_host"]
    smb_port, ldaps_port = _port(inst, 445), _port(inst, 636)

    # Flags 1-3: anonymous SMB recon on the "reception" share.
    welcome = _smb_get(host, smb_port, "reception", "welcome.txt")
    assert expected_flag(secret, 1) in welcome
    employees = _smb_get(host, smb_port, "reception", "employee-list.txt")
    assert expected_flag(secret, 2) in employees
    assert WEAK_USER in employees
    policy = _smb_get(host, smb_port, "reception", "it-policy.txt")
    assert expected_flag(secret, 3) in policy
    assert "Winter2026" in policy or "<Season><Year>" in policy

    # Flag 4: the password spray lands a real domain account, proven
    # via an authenticated LDAPS bind reading its own description.
    desc_weak = _ldap_description(host, ldaps_port, WEAK_USER, WEAK_PASSWORD, WEAK_USER)
    assert expected_flag(secret, 4) in desc_weak

    # Flags 5-6: the domain-auth-gated "hr-confidential" share.
    hr_readme = _smb_get(host, smb_port, "hr-confidential", "readme.txt", user=WEAK_USER, password=WEAK_PASSWORD)
    assert expected_flag(secret, 5) in hr_readme
    escalation_note = _smb_get(
        host, smb_port, "hr-confidential", "escalation-note.txt", user=WEAK_USER, password=WEAK_PASSWORD
    )
    assert expected_flag(secret, 6) in escalation_note
    assert ESCALATION_PASSWORD in escalation_note

    # Flags 7-8: the second, escalation-tier "it-admin-drop" share.
    drop_readme = _smb_get(
        host, smb_port, "it-admin-drop", "readme.txt", user=ESCALATION_USER, password=ESCALATION_PASSWORD
    )
    assert expected_flag(secret, 7) in drop_readme
    handoff = _smb_get(
        host, smb_port, "it-admin-drop", "handoff-notes.txt", user=ESCALATION_USER, password=ESCALATION_PASSWORD
    )
    assert expected_flag(secret, 8) in handoff

    # Flag 9: the escalation account's own description.
    desc_escalation = _ldap_description(host, ldaps_port, ESCALATION_USER, ESCALATION_PASSWORD, ESCALATION_USER)
    assert expected_flag(secret, 9) in desc_escalation

    # Flag 10: the domain Administrator's own description -- readable
    # under AD's own default ACLs, no special privilege needed.
    desc_admin = _ldap_description(host, ldaps_port, ESCALATION_USER, ESCALATION_PASSWORD, "Administrator")
    assert expected_flag(secret, 10) in desc_admin


def test_idempotent_create(box_instance):
    inst, secret, backend = box_instance
    r = requests.post(
        f"{BASE_URL}/instances",
        json={
            "team_id": inst["team_id"], "box_id": BOX_ID, "team_secret": "a-different-secret-must-be-ignored",
            "backend": backend,
        },
    )
    r.raise_for_status()
    assert r.json()["instance_id"] == inst["instance_id"]


def test_cross_team_flag_isolation(box_instance):
    inst, secret, backend = box_instance
    team_id_b = inst["team_id"] + 1000
    secret_b = pysecrets.token_hex(32)
    r = requests.post(
        f"{BASE_URL}/instances",
        json={"team_id": team_id_b, "box_id": BOX_ID, "team_secret": secret_b, "backend": backend},
    )
    r.raise_for_status()
    inst_b = r.json()
    try:
        host_a, port_a = inst["entry_host"], _port(inst, 445)
        host_b, port_b = inst_b["entry_host"], _port(inst_b, 445)
        welcome_a = _smb_get(host_a, port_a, "reception", "welcome.txt")
        welcome_b = _smb_get(host_b, port_b, "reception", "welcome.txt")
        assert expected_flag(secret, 1) in welcome_a
        assert expected_flag(secret_b, 1) in welcome_b
        assert expected_flag(secret, 1) != expected_flag(secret_b, 1)
        assert expected_flag(secret, 1) not in welcome_b
    finally:
        resp = requests.delete(f"{BASE_URL}/instances/{inst_b['instance_id']}")
        if not resp.ok:
            raise AssertionError(f"teardown failed to destroy instance: {resp.status_code} {resp.text}")
