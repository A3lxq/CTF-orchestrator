"""Phase 3 verification: multi-host boxes (Master, Expert, God), Docker
backend. First real exercise of the public/internal per-instance network
pair -- single-host boxes (Phase 0-2) never had an internal-only service
to get wrong.

Beyond the Phase 2 checks (flag uniqueness, idempotent create, clean
destroy), this file specifically verifies:
- internal-only hosts are unreachable from outside the instance (no
  published port at all), reachable only via the front door's own
  internal-net membership
- the front door can reach each internal-only host by the box's ORIGINAL
  docker-compose service name (not just the orchestrator's own container
  name) -- every box's intended solve path has the player type that
  hostname literally into a shell, confirmed via each box's own writeup
- team A's front door cannot reach team B's internal-only hosts (the
  internal-net isolation extends the same per-team guarantee Phase 0
  proved for single-host boxes)

Requires: each box's images already built (ctf-boxes/<box_id>-<service>:latest),
and either a running orchestrator reachable at ORCHESTRATOR_TEST_URL, or
(default) this test will boot one in-process against a throwaway SQLite DB
and the real local Docker daemon.
"""
import hashlib
import hmac
import os
import secrets as pysecrets
import subprocess
import time

import pytest
import requests

BASE_URL = os.environ.get("ORCHESTRATOR_TEST_URL", "http://127.0.0.1:9100")

# box_id -> front-door service/port/path (flag #1 location, verified
# against each box's resurrected source) + internal-only hosts as
# (service_name, port) pairs -- service_name doubles as both the box's
# original compose hostname (the alias under test) and the orchestrator's
# own ctf-<box_id>-<team_id>-<service> container name suffix.
#
# "internal" lists every internal-only host (used by the not-published and
# cross-team-isolation checks, which apply regardless of internal topology).
# "front_door_reachable" (defaults to the same list when omitted) lists only
# the internal hosts the front door can reach DIRECTLY -- for god-the-ferryman
# that's a strict subset: Portal's own internal_groups spec entry only puts
# it on Waystation's segment, not Vault's (see god-the-ferryman.yaml and
# registry.py's HostSpec.internal_groups) -- the box's own chain topology
# (Portal -> Waystation -> Vault, no direct Portal<->Vault) is exercised by
# the dedicated test_god_chain_topology tests below instead.
BOX_CONFIG = {
    "master-two-offices": {
        "front_door": {"service": "frontdesk", "port": 5000, "path": "/"},
        "internal": [("backoffice", 6000)],
    },
    "expert-the-annex": {
        "front_door": {"service": "gateway", "port": 5000, "path": "/"},
        "internal": [("directory", 389), ("fileserver", 22)],
    },
    "god-the-ferryman": {
        "front_door": {"service": "portal", "port": 5000, "path": "/"},
        "internal": [("waystation", 7000), ("vault", 22)],
        "front_door_reachable": [("waystation", 7000)],
    },
}

BOX_IDS = list(BOX_CONFIG)


def expected_flag(box_id: str, secret: str, n: int) -> str:
    digest = hmac.new(secret.encode(), f"{box_id}:{n}".encode(), hashlib.sha256).hexdigest()
    return f"HLC{{{digest[:10]}}}"


@pytest.fixture(params=BOX_IDS)
def two_teams(request):
    box_id = request.param
    secret1 = pysecrets.token_hex(32)
    secret2 = pysecrets.token_hex(32)

    r1 = requests.post(f"{BASE_URL}/instances", json={"team_id": 201, "box_id": box_id, "team_secret": secret1})
    r1.raise_for_status()
    r2 = requests.post(f"{BASE_URL}/instances", json={"team_id": 202, "box_id": box_id, "team_secret": secret2})
    r2.raise_for_status()

    inst1, inst2 = r1.json(), r2.json()
    try:
        yield box_id, inst1, inst2, secret1, secret2
    finally:
        requests.delete(f"{BASE_URL}/instances/{inst1['instance_id']}")
        requests.delete(f"{BASE_URL}/instances/{inst2['instance_id']}")


def _front_door_container(box_id: str, team_id: int) -> str:
    return f"ctf-{box_id}-{team_id}-{BOX_CONFIG[box_id]['front_door']['service']}"


def _internal_container(box_id: str, team_id: int, service: str) -> str:
    return f"ctf-{box_id}-{team_id}-{service}"


def _published_port(container_name: str, container_port: int) -> int:
    out = subprocess.run(
        ["docker", "inspect", "-f",
         f"{{{{(index (index .NetworkSettings.Ports \"{container_port}/tcp\") 0).HostPort}}}}", container_name],
        capture_output=True, text=True, check=True,
    )
    return int(out.stdout.strip())


def _exec(container_name: str, *cmd: str) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", "exec", container_name, *cmd], capture_output=True, text=True)


def test_flag_uniqueness(two_teams):
    box_id, inst1, inst2, secret1, secret2 = two_teams
    cfg = BOX_CONFIG[box_id]["front_door"]
    fd1 = _front_door_container(box_id, 201)
    fd2 = _front_door_container(box_id, 202)
    port1 = _published_port(fd1, cfg["port"])
    port2 = _published_port(fd2, cfg["port"])

    f1 = requests.get(f"http://{inst1['entry_host']}:{port1}{cfg['path']}").text
    f2 = requests.get(f"http://{inst2['entry_host']}:{port2}{cfg['path']}").text

    want1 = expected_flag(box_id, secret1, 1)
    want2 = expected_flag(box_id, secret2, 1)
    assert want1 in f1, f"{box_id}: expected flag not found at {cfg['path']}"
    assert want2 in f2, f"{box_id}: expected flag not found at {cfg['path']}"
    assert want1 != want2


def test_internal_hosts_not_published(two_teams):
    box_id, inst1, _, _, _ = two_teams
    for service, _port in BOX_CONFIG[box_id]["internal"]:
        name = _internal_container(box_id, 201, service)
        out = subprocess.run(
            ["docker", "inspect", "-f", "{{json .NetworkSettings.Ports}}", name],
            capture_output=True, text=True, check=True,
        )
        import json
        ports = json.loads(out.stdout)
        for proto_port, bindings in ports.items():
            assert bindings is None, f"{box_id}:{service} must have no published ports, found {proto_port} -> {bindings}"


def test_front_door_reaches_internal_hosts_by_alias(two_teams):
    """The whole point of the alias fix: the box's own writeup has the
    player type the ORIGINAL compose service name, not the orchestrator's
    container name, from a shell on the front door."""
    box_id, inst1, _, _, _ = two_teams
    fd1 = _front_door_container(box_id, 201)
    for service, port in BOX_CONFIG[box_id].get("front_door_reachable", BOX_CONFIG[box_id]["internal"]):
        resolved = _exec(fd1, "getent", "hosts", service)
        assert resolved.returncode == 0, f"{box_id}: front door could not resolve internal hostname {service!r}: {resolved.stderr}"

        reach = _exec(fd1, "timeout", "3", "bash", "-c", f"echo > /dev/tcp/{service}/{port}")
        assert reach.returncode == 0, f"{box_id}: front door could not reach {service}:{port} by alias"


def test_cross_team_internal_isolation(two_teams):
    """Team A's front door must not reach team B's internal-only hosts --
    same per-team guarantee Phase 0 proved for single-host boxes, now
    across the internal-net too."""
    box_id, inst1, inst2, _, _ = two_teams
    fd1 = _front_door_container(box_id, 201)
    for service, port in BOX_CONFIG[box_id]["internal"]:
        team2_internal_name = _internal_container(box_id, 202, service)
        ip_out = subprocess.run(
            ["docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}", team2_internal_name],
            capture_output=True, text=True, check=True,
        )
        team2_ip = ip_out.stdout.split()[0]
        reach = _exec(fd1, "timeout", "3", "bash", "-c", f"echo > /dev/tcp/{team2_ip}/{port}")
        assert reach.returncode != 0, f"{box_id}: team 1's front door must not reach team 2's {service} directly"


@pytest.fixture
def god_instance():
    """Single-team instance of god-the-ferryman specifically, for the chain-
    topology checks below -- a fresh team_id (203) rather than reusing
    two_teams' 201/202 so this never races/collides with that fixture's own
    teardown for the same box."""
    box_id = "god-the-ferryman"
    secret = pysecrets.token_hex(32)
    r = requests.post(f"{BASE_URL}/instances", json={"team_id": 203, "box_id": box_id, "team_secret": secret})
    r.raise_for_status()
    inst = r.json()
    try:
        yield inst
    finally:
        requests.delete(f"{BASE_URL}/instances/{inst['instance_id']}")


def test_god_chain_topology(god_instance):
    """god-the-ferryman's intended solve path chains Portal -> Waystation ->
    Vault (per that box's original VM-build design notes: wiring Portal
    directly to Vault breaks the box). Portal must NOT be able to reach
    Vault directly at the network layer -- only Waystation, the declared
    pivot (god-the-ferryman.yaml's segment-a/segment-b internal_groups),
    can. test_front_door_reaches_internal_hosts_by_alias above already
    confirms Portal can still reach Waystation, the one legal hop."""
    box_id = "god-the-ferryman"
    portal = _front_door_container(box_id, 203)
    waystation = _internal_container(box_id, 203, "waystation")
    vault = _internal_container(box_id, 203, "vault")

    # Portal cannot resolve or reach Vault by alias -- no shared segment.
    resolved = _exec(portal, "getent", "hosts", "vault")
    assert resolved.returncode != 0, "portal must not resolve vault's alias (no shared internal segment)"
    reach = _exec(portal, "timeout", "3", "bash", "-c", "echo > /dev/tcp/vault/22")
    assert reach.returncode != 0, "portal must not reach vault directly -- chain topology requires routing via waystation"

    # Belt-and-suspenders: rule out "alias just didn't resolve" masking an
    # actually-reachable network by also trying Vault's bare IP.
    vault_ip_out = subprocess.run(
        ["docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}", vault],
        capture_output=True, text=True, check=True,
    )
    for vault_ip in vault_ip_out.stdout.split():
        reach_ip = _exec(portal, "timeout", "3", "bash", "-c", f"echo > /dev/tcp/{vault_ip}/22")
        assert reach_ip.returncode != 0, f"portal must not reach vault at {vault_ip} either"

    # Waystation -- the declared pivot -- CAN reach Vault directly.
    pivot_reach = _exec(waystation, "timeout", "3", "bash", "-c", "echo > /dev/tcp/vault/22")
    assert pivot_reach.returncode == 0, "waystation (the pivot) must be able to reach vault directly"

    # And the chain's one legal hop (Portal -> Waystation) still works, so
    # Vault remains reachable from the front door's side -- just via
    # Waystation, never directly.
    hop = _exec(portal, "timeout", "3", "bash", "-c", "echo > /dev/tcp/waystation/7000")
    assert hop.returncode == 0, "portal must still reach waystation directly (the one legal hop in the chain)"


def test_idempotent_create(two_teams):
    box_id, inst1, _, secret1, _ = two_teams
    r = requests.post(
        f"{BASE_URL}/instances",
        json={"team_id": 201, "box_id": box_id, "team_secret": "a-different-secret-must-be-ignored"},
    )
    r.raise_for_status()
    assert r.json()["instance_id"] == inst1["instance_id"]


def test_destroy_actually_tears_down(two_teams):
    box_id, inst1, _, _, _ = two_teams
    all_names = [_front_door_container(box_id, 201)] + [
        _internal_container(box_id, 201, s) for s, _p in BOX_CONFIG[box_id]["internal"]
    ]
    requests.delete(f"{BASE_URL}/instances/{inst1['instance_id']}").raise_for_status()
    time.sleep(1)
    for name in all_names:
        result = subprocess.run(["docker", "inspect", name], capture_output=True)
        assert result.returncode != 0, f"{box_id}: {name} must be gone after destroy"
