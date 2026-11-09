"""Phase 0 verification: orchestrator standalone, Docker backend, Noob only.

Requires: the orchestrator image ctf-boxes/noob-orientation-server:latest
already built, and either a running orchestrator reachable at
ORCHESTRATOR_TEST_URL, or (default) this test will boot one in-process
against a throwaway SQLite DB and the real local Docker daemon.

These tests talk to the real Docker daemon and create/destroy real
containers -- not mocked. They are intentionally slow and are meant to be
run deliberately (not as part of a fast unit-test loop).
"""
import hashlib
import hmac
import os
import socket
import subprocess
import time

import pytest
import requests

BASE_URL = os.environ.get("ORCHESTRATOR_TEST_URL", "http://127.0.0.1:9100")
BOX_ID = "noob-orientation-server"


def expected_flag(secret: str, n: int) -> str:
    digest = hmac.new(secret.encode(), f"{BOX_ID}:{n}".encode(), hashlib.sha256).hexdigest()
    return f"HLC{{{digest[:10]}}}"


def tcp_reachable(ip: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


@pytest.fixture
def two_teams():
    """Provisions two distinct Noob instances with distinct secrets, yields
    (team1_info, team2_info, secret1, secret2), destroys both afterward."""
    import secrets as pysecrets

    secret1 = pysecrets.token_hex(32)
    secret2 = pysecrets.token_hex(32)

    r1 = requests.post(f"{BASE_URL}/instances", json={"team_id": 101, "box_id": BOX_ID, "team_secret": secret1})
    r1.raise_for_status()
    r2 = requests.post(f"{BASE_URL}/instances", json={"team_id": 102, "box_id": BOX_ID, "team_secret": secret2})
    r2.raise_for_status()

    inst1, inst2 = r1.json(), r2.json()
    try:
        yield inst1, inst2, secret1, secret2
    finally:
        requests.delete(f"{BASE_URL}/instances/{inst1['instance_id']}")
        requests.delete(f"{BASE_URL}/instances/{inst2['instance_id']}")


def test_flag_uniqueness(two_teams):
    inst1, inst2, secret1, secret2 = two_teams
    f1 = requests.get(f"http://{inst1['entry_host']}:{_web_port(inst1)}/").text
    f2 = requests.get(f"http://{inst2['entry_host']}:{_web_port(inst2)}/").text

    want1 = expected_flag(secret1, 1)
    want2 = expected_flag(secret2, 1)
    assert want1 in f1
    assert want2 in f2
    assert want1 != want2, "two different team secrets must not produce the same flag"


def test_network_isolation(two_teams):
    inst1, inst2, _, _ = two_teams
    name1 = f"ctf-{BOX_ID}-101-orientation-server"
    name2 = f"ctf-{BOX_ID}-102-orientation-server"
    ip1 = _internal_ip(name1)
    ip2 = _internal_ip(name2)

    assert _docker_exec_tcp_check(name1, ip2, 80) is False, "team 1 must not reach team 2's internal network"
    assert _docker_exec_tcp_check(name2, ip1, 80) is False, "team 2 must not reach team 1's internal network"
    assert _docker_exec_tcp_check(name1, ip1, 80) is True, "sanity: team 1 must reach its own service"


def test_idempotent_create(two_teams):
    inst1, _, secret1, _ = two_teams
    r = requests.post(
        f"{BASE_URL}/instances",
        json={"team_id": 101, "box_id": BOX_ID, "team_secret": "a-different-secret-must-be-ignored"},
    )
    r.raise_for_status()
    assert r.json()["instance_id"] == inst1["instance_id"], "re-request for same (team_id, box_id) must attach, not re-provision"


def test_destroy_actually_tears_down(two_teams):
    inst1, _, _, _ = two_teams
    name1 = f"ctf-{BOX_ID}-101-orientation-server"
    requests.delete(f"{BASE_URL}/instances/{inst1['instance_id']}").raise_for_status()
    time.sleep(1)
    result = subprocess.run(["docker", "inspect", name1], capture_output=True)
    assert result.returncode != 0, "container must be gone after destroy, not just marked destroyed in the DB"


def _web_port(instance: dict) -> int:
    # entry_port currently reflects the first spec port (SSH); look up the
    # actual published web port (80/tcp) directly for this test, since
    # GZCTF-facing "which port is THE port" is a Phase 1 concern, not
    # Phase 0's.
    name = f"ctf-{BOX_ID}-{instance['team_id']}-orientation-server"
    out = subprocess.run(
        ["docker", "inspect", "-f", "{{(index (index .NetworkSettings.Ports \"80/tcp\") 0).HostPort}}", name],
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
