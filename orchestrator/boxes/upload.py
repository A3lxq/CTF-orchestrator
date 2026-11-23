"""Admin-driven custom box upload: a Dockerfile (or one per service, for
a multi-host box) + a spec, built and registered immediately -- no
registry account, no restart. Deliberately narrower than the full
internal BoxSpec: no `nested_docker` (Legendary's docker-socket-in-a-box
pattern is far too specialized/risky to expose to arbitrary uploads) and
no `pasv_range` (FTP passive-mode port range, a one-off for Noob).

Security note, stated plainly: this lets anyone with admin credentials
(the only caller -- see api/boxes.py's require_auth gate) trigger an
arbitrary `docker build` on this host. That's not a new trust boundary
(the admin role already controls every team's instances), but it is
real additional attack surface worth the operator knowing about before
handing out admin access to anyone they wouldn't also hand host access.
"""
import io
import os
import re
import tarfile
from dataclasses import dataclass, field

import docker
import yaml
from pydantic import BaseModel, field_validator

from .. import config
from .registry import registry

_BOX_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$")
_HOST_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,30}[a-z0-9]$|^[a-z0-9]$")


class UploadPortSpec(BaseModel):
    container_port: int
    protocol: str = "tcp"


class UploadHostSpec(BaseModel):
    name: str
    front_door: bool = False
    ports: list[UploadPortSpec] = []
    extra_env: dict[str, str] = {}

    @field_validator("name")
    @classmethod
    def _valid_name(cls, v: str) -> str:
        if not _HOST_NAME_RE.match(v):
            raise ValueError(f"invalid host name {v!r} -- must be lowercase alphanumeric/hyphens, 1-32 chars")
        return v


class UploadBoxSpec(BaseModel):
    box_id: str
    hosts: list[UploadHostSpec]

    @field_validator("box_id")
    @classmethod
    def _valid_box_id(cls, v: str) -> str:
        if not _BOX_ID_RE.match(v):
            raise ValueError(f"invalid box_id {v!r} -- must be lowercase alphanumeric/hyphens, 3-63 chars")
        return v


class BoxUploadError(Exception):
    """Carries a detail message safe to return to the (admin) caller --
    build log excerpts, validation errors, duplicate box_id, etc.
    status_code defaults to 400; the duplicate-box_id case uses 409."""

    def __init__(self, detail: str, status_code: int = 400):
        self.detail = detail
        self.status_code = status_code
        super().__init__(detail)


@dataclass
class _ExtractedHost:
    host: UploadHostSpec
    dockerfile_path: str
    image_tag: str


def _safe_extract_tar(data: bytes, dest_dir: str) -> None:
    """Extracts a tarball into dest_dir, rejecting anything that would
    escape it (tar-slip / path traversal) or that isn't a plain file or
    directory (symlinks/hardlinks/devices are a second, related escape
    vector -- rejected outright rather than trusted)."""
    dest_real = os.path.realpath(dest_dir)
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        for member in tar.getmembers():
            if member.issym() or member.islnk() or member.isdev():
                raise BoxUploadError(f"tar member {member.name!r} is a symlink/hardlink/device, not allowed")
            target = os.path.realpath(os.path.join(dest_dir, member.name))
            if target != dest_real and not target.startswith(dest_real + os.sep):
                raise BoxUploadError(f"tar member {member.name!r} would extract outside the target directory")
            if member.isfile() or member.isdir():
                tar.extract(member, path=dest_dir, filter="data") if _supports_data_filter() else tar.extract(
                    member, path=dest_dir
                )


def _supports_data_filter() -> bool:
    # Python 3.12+'s tarfile.extract() accepts `filter=` for a second,
    # independent layer of the same protection -- use it when available,
    # but don't depend on it (our own path check above already covers
    # every Python version this project supports).
    import sys

    return sys.version_info >= (3, 12)


def _boxes_src_dir() -> str:
    return os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "boxes-src")


def upload_box_sync(spec: UploadBoxSpec, tarball: bytes) -> None:
    """Synchronous, blocking (Docker SDK + filesystem + build) -- call
    via asyncio.to_thread from the route handler, same pattern
    docker_backend.py already uses for every other blocking Docker SDK
    call in this codebase."""
    front_doors = [h for h in spec.hosts if h.front_door]
    if len(front_doors) != 1:
        raise BoxUploadError(f"exactly one host must be front_door: true (found {len(front_doors)})")
    if len({h.name for h in spec.hosts}) != len(spec.hosts):
        raise BoxUploadError("host names must be unique within a box")

    try:
        registry.get(spec.box_id)
        raise BoxUploadError(
            f"box_id {spec.box_id!r} already exists -- re-upload under a new id, no overwrite support",
            status_code=409,
        )
    except KeyError:
        pass  # good, doesn't exist yet

    box_dir = os.path.join(_boxes_src_dir(), spec.box_id)
    if os.path.exists(box_dir):
        raise BoxUploadError(
            f"boxes-src/{spec.box_id} already exists on disk (even though not registered) -- pick a different box_id",
            status_code=409,
        )

    docker_dir = os.path.join(box_dir, "docker")
    os.makedirs(docker_dir)
    try:
        _safe_extract_tar(tarball, box_dir)

        is_multi_host = len(spec.hosts) > 1
        extracted: list[_ExtractedHost] = []
        for host in spec.hosts:
            if is_multi_host:
                dockerfile_path = os.path.join(docker_dir, host.name, "Dockerfile")
                tag = f"{config.BOX_IMAGE_PREFIX}/{spec.box_id}-{host.name}:latest"
            else:
                dockerfile_path = os.path.join(docker_dir, "Dockerfile")
                tag = f"{config.BOX_IMAGE_PREFIX}/{spec.box_id}:latest"
            if not os.path.isfile(dockerfile_path):
                raise BoxUploadError(
                    f"expected Dockerfile at {os.path.relpath(dockerfile_path, box_dir)} for host {host.name!r} "
                    f"(single-host boxes: docker/Dockerfile; multi-host: docker/<host-name>/Dockerfile)"
                )
            extracted.append(_ExtractedHost(host=host, dockerfile_path=dockerfile_path, image_tag=tag))

        client = docker.from_env()
        for eh in extracted:
            try:
                client.images.build(path=box_dir, dockerfile=eh.dockerfile_path, tag=eh.image_tag, rm=True)
            except docker.errors.BuildError as e:
                log_tail = "\n".join(
                    line.get("stream", "").rstrip("\n") for line in e.build_log if isinstance(line, dict)
                )[-4000:]
                raise BoxUploadError(f"build failed for host {eh.host.name!r} ({eh.image_tag}): {e}\n{log_tail}") from e
            except docker.errors.APIError as e:
                raise BoxUploadError(f"build failed for host {eh.host.name!r} ({eh.image_tag}): {e}") from e

        _write_spec_yaml(spec, extracted)
        registry.reload()
    except Exception:
        _cleanup_dir(box_dir)
        raise


def _write_spec_yaml(spec: UploadBoxSpec, extracted: list[_ExtractedHost]) -> None:
    raw = {
        "box_id": spec.box_id,
        "hosts": [
            {
                "name": eh.host.name,
                "image": eh.image_tag,
                "front_door": eh.host.front_door,
                "ports": [{"container_port": p.container_port, "protocol": p.protocol} for p in eh.host.ports],
                "extra_env": eh.host.extra_env,
            }
            for eh in extracted
        ],
    }
    spec_path = os.path.join(config.SPECS_DIR, f"{spec.box_id}.yaml")
    with open(spec_path, "w") as f:
        yaml.safe_dump(raw, f, sort_keys=False)


def _cleanup_dir(path: str) -> None:
    import shutil

    shutil.rmtree(path, ignore_errors=True)
