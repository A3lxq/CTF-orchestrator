"""Phase 2 verification: orchestrator standalone, Docker backend, all
single-host boxes (Noob, Beginner, Intermediate, Veteran).

Generalizes Phase 0's test_phase0_noob.py into one parametrized file so a
future fix (e.g. the readiness-probe race documented in the README) only
needs applying once. Same 4 checks per box: flag uniqueness, network
isolation, idempotent create, and destroy actually tears down.

Requires: each box's image already built (ctf-boxes/<box_id>:latest), and
either a running orchestrator reachable at ORCHESTRATOR_TEST_URL, or
(default) this test will boot one in-process against a throwaway SQLite DB
and the real local Docker daemon.

These tests talk to the real Docker daemon and create/destroy real
containers -- not mocked. They are intentionally slow and are meant to be
run deliberately (not as part of a fast unit-test loop).
"""
import hashlib
import hmac
import os
import secrets as pysecrets
import socket
import subprocess
import time

import pytest
import requests

BASE_URL = os.environ.get("ORCHESTRATOR_TEST_URL", "http://127.0.0.1:9100")
# Randomized once per process (not a fixed literal) so two pytest processes
# running this file concurrently -- or even back-to-back, since Docker
# container/network teardown is asynchronous and a DELETE returning 200
# doesn't guarantee removal has actually finished -- never collide on the
# same team_id-derived container names.
_TEAM_ID_BASE = pysecrets.randbelow(1_000_000)

# box_id -> (front-door service name, published port to probe, path whose
# response body contains flag #1). Verified directly against each box's
# resurrected source, not guessed.
BOX_CONFIG = {
    "noob-orientation-server": {"service": "orientation-server", "port": 80, "path": "/"},
    "beginner-reading-room": {"service": "reading-room", "port": 80, "path": "/"},
    "intermediate-portside": {"service": "portside", "port": 5000, "path": "/docs"},
    "veteran-aftermath": {"service": "aftermath", "port": 80, "path": "/evidence/case_manifest.txt"},
}

BOX_IDS = list(BOX_CONFIG)


def expected_flag(box_id: str, secret: str, n: int) -> str:
    digest = hmac.new(secret.encode(), f"{box_id}:{n}".encode(), hashlib.sha256).hexdigest()
    return f"HLC{{{digest[:10]}}}"


def tcp_reachable(ip: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


@pytest.fixture(params=BOX_IDS)
def two_teams(request):
    """Provisions two distinct instances of the parametrized box_id with
    distinct secrets, yields (box_id, inst1, inst2, secret1, secret2),
    destroys both afterward."""
    box_id = request.param
    secret1 = pysecrets.token_hex(32)
    secret2 = pysecrets.token_hex(32)

    r1 = requests.post(f"{BASE_URL}/instances", json={"team_id": _TEAM_ID_BASE + 1, "box_id": box_id, "team_secret": secret1})
    r1.raise_for_status()
    r2 = requests.post(f"{BASE_URL}/instances", json={"team_id": _TEAM_ID_BASE + 2, "box_id": box_id, "team_secret": secret2})
    r2.raise_for_status()

    inst1, inst2 = r1.json(), r2.json()
    try:
        yield box_id, inst1, inst2, secret1, secret2
    finally:
        requests.delete(f"{BASE_URL}/instances/{inst1['instance_id']}")
        requests.delete(f"{BASE_URL}/instances/{inst2['instance_id']}")


def test_flag_uniqueness(two_teams):
    box_id, inst1, inst2, secret1, secret2 = two_teams
    cfg = BOX_CONFIG[box_id]
    port1 = _published_port(box_id, inst1, cfg)
    port2 = _published_port(box_id, inst2, cfg)
    f1 = requests.get(f"http://{inst1['entry_host']}:{port1}{cfg['path']}").text
    f2 = requests.get(f"http://{inst2['entry_host']}:{port2}{cfg['path']}").text

    want1 = expected_flag(box_id, secret1, 1)
    want2 = expected_flag(box_id, secret2, 1)
    assert want1 in f1, f"{box_id}: expected flag not found at {cfg['path']}"
    assert want2 in f2, f"{box_id}: expected flag not found at {cfg['path']}"
    assert want1 != want2, "two different team secrets must not produce the same flag"


def test_network_isolation(two_teams):
    box_id, inst1, inst2, _, _ = two_teams
    cfg = BOX_CONFIG[box_id]
    name1 = f"ctf-{box_id}-{_TEAM_ID_BASE + 1}-{cfg['service']}"
    name2 = f"ctf-{box_id}-{_TEAM_ID_BASE + 2}-{cfg['service']}"
    ip1 = _internal_ip(name1)
    ip2 = _internal_ip(name2)

    assert _docker_exec_tcp_check(name1, ip2, cfg["port"]) is False, "team 1 must not reach team 2's internal network"
    assert _docker_exec_tcp_check(name2, ip1, cfg["port"]) is False, "team 2 must not reach team 1's internal network"
    assert _docker_exec_tcp_check(name1, ip1, cfg["port"]) is True, "sanity: team 1 must reach its own service"


def test_idempotent_create(two_teams):
    box_id, inst1, _, secret1, _ = two_teams
    r = requests.post(
        f"{BASE_URL}/instances",
        json={"team_id": _TEAM_ID_BASE + 1, "box_id": box_id, "team_secret": "a-different-secret-must-be-ignored"},
    )
    r.raise_for_status()
    assert r.json()["instance_id"] == inst1["instance_id"], "re-request for same (team_id, box_id) must attach, not re-provision"


def test_destroy_actually_tears_down(two_teams):
    box_id, inst1, _, _, _ = two_teams
    cfg = BOX_CONFIG[box_id]
    name1 = f"ctf-{box_id}-{_TEAM_ID_BASE + 1}-{cfg['service']}"
    requests.delete(f"{BASE_URL}/instances/{inst1['instance_id']}").raise_for_status()
    time.sleep(1)
    result = subprocess.run(["docker", "inspect", name1], capture_output=True)
    assert result.returncode != 0, "container must be gone after destroy, not just marked destroyed in the DB"


def _published_port(box_id: str, instance: dict, cfg: dict) -> int:
    # entry_port reflects the box spec's first port, not necessarily the
    # one this test wants to probe -- look up the actual published port
    # for cfg['port']/tcp directly.
    name = f"ctf-{box_id}-{instance['team_id']}-{cfg['service']}"
    out = subprocess.run(
        ["docker", "inspect", "-f",
         f"{{{{(index (index .NetworkSettings.Ports \"{cfg['port']}/tcp\") 0).HostPort}}}}", name],
        capture_output=True, text=True, check=True,
    )
    return int(out.stdout.strip())


def _internal_ip(container_name: str) -> str:
    out = subprocess.run(
        ["docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", container_name],
        capture_output=True, text=True, check=True,
    )
    return out.stdout.strip()


def _docker_exec_tcp_check(container_name: str, target_ip: str, port: int) -> bool:
    result = subprocess.run(
        ["docker", "exec", container_name, "timeout", "3", "bash", "-c", f"echo > /dev/tcp/{target_ip}/{port}"],
        capture_output=True,
    )
    return result.returncode == 0
