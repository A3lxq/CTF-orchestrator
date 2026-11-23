"""Phase 7 verification: admin custom box upload (POST /boxes). Builds a
trivial real test box on the fly (a tiny Python HTTP server computing
the same HMAC flag scheme every other box uses), uploads it, confirms
it builds/registers/provisions/is reachable with a real correct flag,
then exercises the two real error paths (duplicate box_id, a
deliberately broken Dockerfile). Real HTTP, real Docker, no mocks --
same philosophy as every other test file here.

Cleans up everything it creates on disk (boxes-src/<box_id>/,
boxes/specs/<box_id>.yaml) and the built image(s), since those land in
this repo's own git-tracked directories, not a throwaway test fixture
dir -- a leftover would show up in `git status` after every run.

Requires: a running orchestrator reachable at ORCHESTRATOR_TEST_URL
(default http://127.0.0.1:9100), real Docker, outbound access to pull
python:3.11-alpine (small, cached after the first run).
"""
import hashlib
import hmac
import io
import json
import os
import secrets as pysecrets
import shutil
import tarfile

import docker
import requests
import yaml

BASE_URL = os.environ.get("ORCHESTRATOR_TEST_URL", "http://127.0.0.1:9100")
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_RUN_ID = pysecrets.token_hex(4)


def expected_flag(box_id: str, secret: str, n: int) -> str:
    digest = hmac.new(secret.encode(), f"{box_id}:{n}".encode(), hashlib.sha256).hexdigest()
    return f"HLC{{{digest[:10]}}}"


def _make_tarball(box_id: str) -> bytes:
    """A single-host box: one Python process serving flag 1 on :80,
    computed from CTF_SECRET the same way every other box does."""
    entrypoint = f"""
import hashlib, hmac, http.server, os

SECRET = os.environ["CTF_SECRET"]
digest = hmac.new(SECRET.encode(), {box_id!r}.encode() + b":1", hashlib.sha256).hexdigest()
FLAG = "HLC{{" + digest[:10] + "}}"

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(FLAG.encode())

http.server.HTTPServer(("0.0.0.0", 80), Handler).serve_forever()
"""
    # The build context is the box root (same convention
    # build_boxes.sh/upload.py both use), not the docker/ subdirectory
    # the Dockerfile itself lives in -- COPY paths are relative to that
    # context root.
    dockerfile = "FROM python:3.11-alpine\nCOPY docker/entrypoint.py /entrypoint.py\nEXPOSE 80\nCMD [\"python3\", \"/entrypoint.py\"]\n"

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, content in [("docker/Dockerfile", dockerfile), ("docker/entrypoint.py", entrypoint)]:
            data = content.encode()
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _make_broken_tarball() -> bytes:
    dockerfile = "FROM python:3.11-alpine\nRUN false\n"
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        data = dockerfile.encode()
        info = tarfile.TarInfo(name="docker/Dockerfile")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _cleanup_box(box_id: str) -> None:
    shutil.rmtree(os.path.join(REPO_ROOT, "boxes-src", box_id), ignore_errors=True)
    spec_path = os.path.join(REPO_ROOT, "orchestrator", "boxes", "specs", f"{box_id}.yaml")
    if os.path.isfile(spec_path):
        os.remove(spec_path)
    try:
        client = docker.from_env()
        client.images.remove(f"ctf-boxes/{box_id}:latest", force=True)
    except Exception:
        pass


def test_upload_build_provision_and_flag():
    box_id = f"test-upload-{_RUN_ID}"
    spec = {"box_id": box_id, "hosts": [{"name": "web", "front_door": True, "ports": [{"container_port": 80, "protocol": "tcp"}]}]}
    tarball = _make_tarball(box_id)

    try:
        r = requests.post(
            f"{BASE_URL}/boxes",
            data={"spec": json.dumps(spec)},
            files={"context": ("context.tar", tarball, "application/x-tar")},
        )
        assert r.status_code == 200, r.text
        assert r.json()["box_id"] == box_id

        # Registered immediately -- no restart needed.
        got = requests.get(f"{BASE_URL}/boxes/{box_id}")
        assert got.status_code == 200, got.text

        # The spec file this created must match build_boxes.sh's own
        # on-disk convention exactly (same tagging, same directory shape).
        spec_path = os.path.join(REPO_ROOT, "orchestrator", "boxes", "specs", f"{box_id}.yaml")
        assert os.path.isfile(spec_path)
        with open(spec_path) as f:
            on_disk = yaml.safe_load(f)
        assert on_disk["hosts"][0]["image"] == f"ctf-boxes/{box_id}:latest"

        # Provision a real instance and confirm the real, correctly-derived flag.
        secret = pysecrets.token_hex(32)
        inst = requests.post(f"{BASE_URL}/instances", json={"team_id": pysecrets.randbelow(1_000_000), "box_id": box_id, "team_secret": secret})
        assert inst.status_code == 200, inst.text
        inst_body = inst.json()
        try:
            page = requests.get(f"http://{inst_body['entry_host']}:{inst_body['entry_port']}/").text
            assert page == expected_flag(box_id, secret, 1)
        finally:
            requests.delete(f"{BASE_URL}/instances/{inst_body['instance_id']}")

        # Duplicate box_id must be rejected with 409, not silently reused.
        dup = requests.post(
            f"{BASE_URL}/boxes",
            data={"spec": json.dumps(spec)},
            files={"context": ("context.tar", tarball, "application/x-tar")},
        )
        assert dup.status_code == 409, dup.text
    finally:
        _cleanup_box(box_id)


def test_broken_dockerfile_returns_clean_400():
    box_id = f"test-upload-broken-{_RUN_ID}"
    spec = {"box_id": box_id, "hosts": [{"name": "web", "front_door": True, "ports": [{"container_port": 80}]}]}
    try:
        r = requests.post(
            f"{BASE_URL}/boxes",
            data={"spec": json.dumps(spec)},
            files={"context": ("context.tar", _make_broken_tarball(), "application/x-tar")},
        )
        assert r.status_code == 400, r.text
        assert "build failed" in r.json()["detail"]
        # Must not have left a half-registered box behind.
        assert requests.get(f"{BASE_URL}/boxes/{box_id}").status_code == 404
    finally:
        _cleanup_box(box_id)


def test_missing_front_door_rejected():
    box_id = f"test-upload-nofd-{_RUN_ID}"
    spec = {"box_id": box_id, "hosts": [{"name": "web", "front_door": False, "ports": [{"container_port": 80}]}]}
    try:
        r = requests.post(
            f"{BASE_URL}/boxes",
            data={"spec": json.dumps(spec)},
            files={"context": ("context.tar", _make_tarball(box_id), "application/x-tar")},
        )
        assert r.status_code == 400, r.text
        assert "front_door" in r.json()["detail"]
    finally:
        _cleanup_box(box_id)
