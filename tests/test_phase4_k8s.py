"""Phase 4 verification: KubernetesBackend, all 7 boxes (Noob, Beginner,
Intermediate, Veteran single-host; Master, Expert, God multi-host).

Requires: every box's images already loaded into the target cluster
(`kind load docker-image ctf-boxes/<name>:latest --name <cluster>` per
image), a running orchestrator reachable at ORCHESTRATOR_TEST_URL with
ORCHESTRATOR_K8S_POD_CIDR set in its own environment (KubernetesBackend
refuses to construct without it), and `kubectl` on PATH pointed at that
same cluster.

Every instance created here passes `"backend": "kubernetes"` explicitly
in the POST body, so this suite can run against the same orchestrator
process already serving Docker-backed instances elsewhere (DEFAULT_BACKEND
stays "docker"; this is a per-request override, not a server-wide switch).

The cross-team isolation checks are the ones that caught a real,
confirmed bug before this file existed (see docker_backend.py's sibling
k8s_backend.py and the project's gaps-and-limitations notes) -- their
presence here, not as an ad-hoc script, is deliberate.
"""
import hashlib
import hmac
import json
import os
import secrets as pysecrets
import subprocess
import time

import pytest
import requests

BASE_URL = os.environ.get("ORCHESTRATOR_TEST_URL", "http://127.0.0.1:9100")
KUBECTL = os.environ.get("KUBECTL_BIN", "kubectl")

# box_id -> front-door service/port/path (verified against each box's
# resurrected source in Phases 2-3) + internal-only hosts as
# (service_name, port) pairs (empty for single-host boxes).
BOX_CONFIG = {
    "noob-orientation-server": {
        "front_door": {"service": "orientation-server", "port": 80, "path": "/"},
        "internal": [],
    },
    "beginner-reading-room": {
        "front_door": {"service": "reading-room", "port": 80, "path": "/"},
        "internal": [],
    },
    "intermediate-portside": {
        "front_door": {"service": "portside", "port": 5000, "path": "/docs"},
        "internal": [],
    },
    "veteran-aftermath": {
        "front_door": {"service": "aftermath", "port": 80, "path": "/evidence/case_manifest.txt"},
        "internal": [],
    },
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
    },
}

BOX_IDS = list(BOX_CONFIG)


def expected_flag(box_id: str, secret: str, n: int) -> str:
    digest = hmac.new(secret.encode(), f"{box_id}:{n}".encode(), hashlib.sha256).hexdigest()
    return f"HLC{{{digest[:10]}}}"


def _kubectl(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([KUBECTL, *args], capture_output=True, text=True)


@pytest.fixture(params=BOX_IDS)
def two_teams(request):
    box_id = request.param
    secret1 = pysecrets.token_hex(32)
    secret2 = pysecrets.token_hex(32)

    r1 = requests.post(f"{BASE_URL}/instances", json={
        "team_id": 801, "box_id": box_id, "team_secret": secret1, "backend": "kubernetes",
    })
    r1.raise_for_status()
    r2 = requests.post(f"{BASE_URL}/instances", json={
        "team_id": 802, "box_id": box_id, "team_secret": secret2, "backend": "kubernetes",
    })
    r2.raise_for_status()

    inst1, inst2 = r1.json(), r2.json()
    try:
        yield box_id, inst1, inst2, secret1, secret2
    finally:
        # Loud on purpose: a silently-swallowed destroy failure here used
        # to leave a stale non-RUNNING row that (before the idempotent-
        # create fix in api/instances.py) got silently reattached to by
        # every later test for the same box_id, turning one transient
        # failure into a permanent one with no visible cause. Surface it
        # immediately at the test that caused it instead.
        errors = []
        for inst in (inst1, inst2):
            resp = requests.delete(f"{BASE_URL}/instances/{inst['instance_id']}")
            if not resp.ok:
                errors.append(f"{inst['instance_id']}: {resp.status_code} {resp.text}")
        if errors:
            raise AssertionError(f"{box_id}: teardown failed to destroy instance(s): {errors}")


def _namespace(box_id: str, team_id: int) -> str:
    # Mirrors KubernetesBackend's own _k8s_name("ctf", box_id, str(team_id)).
    name = f"ctf-{box_id}-{team_id}".lower()
    import re
    name = re.sub(r"[^a-z0-9-]", "-", name)
    name = re.sub(r"-+", "-", name).strip("-")
    return name[:63].rstrip("-")


def test_flag_uniqueness(two_teams):
    box_id, inst1, inst2, secret1, secret2 = two_teams
    cfg = BOX_CONFIG[box_id]["front_door"]

    f1 = requests.get(f"http://{inst1['entry_host']}:{inst1['entry_port']}{cfg['path']}", timeout=10).text
    f2 = requests.get(f"http://{inst2['entry_host']}:{inst2['entry_port']}{cfg['path']}", timeout=10).text

    want1 = expected_flag(box_id, secret1, 1)
    want2 = expected_flag(box_id, secret2, 1)
    assert want1 in f1, f"{box_id}: expected flag not found at {cfg['path']}"
    assert want2 in f2, f"{box_id}: expected flag not found at {cfg['path']}"
    assert want1 != want2


def test_internal_hosts_have_no_node_port(two_teams):
    box_id, inst1, _, _, _ = two_teams
    ns1 = _namespace(box_id, 801)
    for service, _port in BOX_CONFIG[box_id]["internal"]:
        out = _kubectl("get", "svc", "-n", ns1, service, "-o", "jsonpath={.spec.type}")
        assert out.returncode == 0, out.stderr
        assert out.stdout.strip() == "ClusterIP", f"{box_id}:{service} must be ClusterIP, not externally exposed"


def test_front_door_reaches_internal_hosts_by_name(two_teams):
    box_id, inst1, _, _, _ = two_teams
    ns1 = _namespace(box_id, 801)
    fd_service = BOX_CONFIG[box_id]["front_door"]["service"]
    for service, port in BOX_CONFIG[box_id]["internal"]:
        reach = _kubectl(
            "exec", "-n", ns1, f"deploy/{fd_service}", "--",
            "timeout", "3", "bash", "-c", f"echo > /dev/tcp/{service}/{port}",
        )
        assert reach.returncode == 0, f"{box_id}: front door could not reach {service}:{port} by name: {reach.stderr}"


def test_cross_team_isolation(two_teams):
    """The check that caught a real, confirmed bug: without the pod-CIDR
    ipBlock exclusion + externalTrafficPolicy=Local fix, team A's pod
    could reach team B's pod directly, cross-namespace."""
    box_id, inst1, inst2, _, _ = two_teams
    ns1 = _namespace(box_id, 801)
    ns2 = _namespace(box_id, 802)
    fd_service = BOX_CONFIG[box_id]["front_door"]["service"]
    fd_port = BOX_CONFIG[box_id]["front_door"]["port"]

    cross_fqdn = f"{fd_service}.{ns2}.svc.cluster.local"
    blocked = _kubectl(
        "exec", "-n", ns1, f"deploy/{fd_service}", "--",
        "timeout", "3", "bash", "-c", f"echo > /dev/tcp/{cross_fqdn}/{fd_port}",
    )
    assert blocked.returncode != 0, f"{box_id}: team 1 must NOT reach team 2's front door cross-namespace"

    own = _kubectl(
        "exec", "-n", ns1, f"deploy/{fd_service}", "--",
        "timeout", "3", "bash", "-c", f"echo > /dev/tcp/127.0.0.1/{fd_port}",
    )
    assert own.returncode == 0, f"{box_id}: sanity check failed -- team 1 couldn't even reach its own pod"


def test_idempotent_create(two_teams):
    box_id, inst1, _, secret1, _ = two_teams
    r = requests.post(f"{BASE_URL}/instances", json={
        "team_id": 801, "box_id": box_id, "team_secret": "a-different-secret-must-be-ignored",
        "backend": "kubernetes",
    })
    r.raise_for_status()
    assert r.json()["instance_id"] == inst1["instance_id"]


def test_destroy_actually_tears_down(two_teams):
    box_id, inst1, _, _, _ = two_teams
    ns1 = _namespace(box_id, 801)
    requests.delete(f"{BASE_URL}/instances/{inst1['instance_id']}").raise_for_status()
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        out = _kubectl("get", "namespace", ns1)
        if out.returncode != 0:
            return
        time.sleep(2)
    raise AssertionError(f"{box_id}: namespace {ns1} still exists after destroy")
