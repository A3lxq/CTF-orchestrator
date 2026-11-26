"""Phase 6 verification: the three ctf-platform-driven orchestrator
patches -- the `ports` field (every published front-door port, not just
the single `entry_port`), `GET /boxes` (the box catalog over HTTP), and
the per-team instance quota (`ORCHESTRATOR_MAX_INSTANCES_PER_TEAM`).

Requires: the box images these tests provision already built, and a
running orchestrator reachable at ORCHESTRATOR_TEST_URL (default
http://127.0.0.1:9100) -- same real-HTTP-no-mocks philosophy as every
other test file in this suite. Talks to the real Docker daemon and
creates/destroys real containers; intentionally slow (the quota test
alone provisions 4 real instances), run deliberately.
"""
import os
import secrets as pysecrets
import subprocess

import requests

BASE_URL = os.environ.get("ORCHESTRATOR_TEST_URL", "http://127.0.0.1:9100")
MAX_INSTANCES_PER_TEAM = int(os.environ.get("ORCHESTRATOR_MAX_INSTANCES_PER_TEAM", "4"))
_TEAM_ID_BASE = pysecrets.randbelow(1_000_000)

ALL_BOX_IDS = {
    "noob-orientation-server",
    "beginner-reading-room",
    "intermediate-portside",
    "veteran-aftermath",
    "master-two-offices",
    "expert-the-annex",
    "god-the-ferryman",
    "legendary-ferrymans-relay",
}
# Not exhaustive: more boxes (bonus-*, domainzero-*, cloudbreak-*) have
# been registered since this file was written. Checked as a subset
# below rather than exact equality, so this file doesn't need editing
# every time a new box is added -- it only needs to prove the original
# 8 are still present/registered correctly.

# Four single-host boxes -- fastest to provision/destroy, used to fill
# (and stay at) the quota without the multi-host/nested-docker boxes'
# much slower bring-up time.
FILL_BOX_IDS = ["noob-orientation-server", "beginner-reading-room", "intermediate-portside", "veteran-aftermath"]


def _published_port(box_id: str, team_id: int, service_name: str, container_port: int) -> int:
    name = f"ctf-{box_id}-{team_id}-{service_name}"
    out = subprocess.run(
        ["docker", "inspect", "-f",
         f"{{{{(index (index .NetworkSettings.Ports \"{container_port}/tcp\") 0).HostPort}}}}", name],
        capture_output=True, text=True, check=True,
    )
    return int(out.stdout.strip())


def test_get_boxes_lists_all_known_boxes():
    r = requests.get(f"{BASE_URL}/boxes")
    r.raise_for_status()
    boxes = r.json()
    box_ids = {b["box_id"] for b in boxes}
    assert ALL_BOX_IDS <= box_ids

    by_id = {b["box_id"]: b for b in boxes}
    noob = by_id["noob-orientation-server"]
    assert noob["is_multi_host"] is False
    front_doors = [h for h in noob["hosts"] if h["front_door"]]
    assert len(front_doors) == 1
    container_ports = {p["container_port"] for p in front_doors[0]["ports"]}
    assert container_ports == {80, 21, 22}, "noob's front door publishes HTTP, FTP, and SSH"


def test_get_single_box():
    r = requests.get(f"{BASE_URL}/boxes/beginner-reading-room")
    r.raise_for_status()
    body = r.json()
    assert body["box_id"] == "beginner-reading-room"
    assert body["is_multi_host"] is False


def test_get_unknown_box_404s():
    r = requests.get(f"{BASE_URL}/boxes/not-a-real-box")
    assert r.status_code == 404


def test_ports_field_reflects_every_published_port():
    """The real gap this patches: noob-orientation-server's front door
    publishes 3 ports (HTTP, SSH, FTP), but entry_port alone can only
    ever represent one of them. Cross-checked against the actual
    container's own published ports via `docker inspect`, not just
    trusted from the API response."""
    team_id = _TEAM_ID_BASE + 1
    secret = pysecrets.token_hex(32)
    r = requests.post(
        f"{BASE_URL}/instances",
        json={"team_id": team_id, "box_id": "noob-orientation-server", "team_secret": secret},
    )
    r.raise_for_status()
    inst = r.json()
    try:
        ports = inst["ports"]
        assert ports is not None
        by_container_port = {p["container_port"]: p for p in ports}
        assert set(by_container_port) == {80, 21, 22}
        for container_port, p in by_container_port.items():
            assert p["service_name"] == "orientation-server"
            assert p["protocol"] == "tcp"
            real_host_port = _published_port("noob-orientation-server", team_id, "orientation-server", container_port)
            assert p["host_port"] == real_host_port, f"container_port {container_port}: API-reported host_port must match the real container"
        # entry_port (the single backward-compatible field) must be one
        # of the host_ports also present in the full list.
        assert inst["entry_port"] in {p["host_port"] for p in ports}
    finally:
        requests.delete(f"{BASE_URL}/instances/{inst['instance_id']}")


def test_ports_field_single_port_box():
    """A box with only one published port (beginner-reading-room) still
    gets a correctly-shaped (if single-element) ports list."""
    team_id = _TEAM_ID_BASE + 2
    secret = pysecrets.token_hex(32)
    r = requests.post(
        f"{BASE_URL}/instances",
        json={"team_id": team_id, "box_id": "beginner-reading-room", "team_secret": secret},
    )
    r.raise_for_status()
    inst = r.json()
    try:
        assert inst["ports"] is not None
        assert len(inst["ports"]) == 1
        assert inst["ports"][0]["container_port"] == 80
        assert inst["ports"][0]["host_port"] == inst["entry_port"]
    finally:
        requests.delete(f"{BASE_URL}/instances/{inst['instance_id']}")


def test_per_team_quota_blocks_past_the_cap():
    team_id = _TEAM_ID_BASE + 3
    secret = pysecrets.token_hex(32)
    created_ids = []
    try:
        assert len(FILL_BOX_IDS) == MAX_INSTANCES_PER_TEAM, (
            "this test's fill list must match the server's configured cap -- "
            "if ORCHESTRATOR_MAX_INSTANCES_PER_TEAM was overridden, override FILL_BOX_IDS too"
        )
        for box_id in FILL_BOX_IDS:
            r = requests.post(f"{BASE_URL}/instances", json={"team_id": team_id, "box_id": box_id, "team_secret": secret})
            r.raise_for_status()
            created_ids.append(r.json()["instance_id"])

        # One more, genuinely new (team, box) pair past the cap -- must
        # be rejected with 429, not provisioned.
        blocked = requests.post(
            f"{BASE_URL}/instances",
            json={"team_id": team_id, "box_id": "master-two-offices", "team_secret": secret},
        )
        assert blocked.status_code == 429, blocked.text
        assert str(MAX_INSTANCES_PER_TEAM) in blocked.json()["detail"]

        # The idempotent reattach path for an ALREADY-provisioned (team,
        # box) must never be blocked by the cap, even while at it.
        reattach = requests.post(
            f"{BASE_URL}/instances",
            json={"team_id": team_id, "box_id": FILL_BOX_IDS[0], "team_secret": "ignored-on-reattach"},
        )
        assert reattach.status_code == 200, reattach.text
        assert reattach.json()["instance_id"] == created_ids[0]
    finally:
        for instance_id in created_ids:
            requests.delete(f"{BASE_URL}/instances/{instance_id}")

    # After tearing every instance down, the team must be able to
    # provision again -- confirms DESTROYED rows never count toward the
    # cap.
    secret2 = pysecrets.token_hex(32)
    r = requests.post(
        f"{BASE_URL}/instances",
        json={"team_id": team_id, "box_id": "noob-orientation-server", "team_secret": secret2},
    )
    r.raise_for_status()
    requests.delete(f"{BASE_URL}/instances/{r.json()['instance_id']}").raise_for_status()
