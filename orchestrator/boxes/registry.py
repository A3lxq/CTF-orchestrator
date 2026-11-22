import os
from dataclasses import dataclass, field

import yaml

from .. import config


@dataclass
class PortSpec:
    container_port: int
    protocol: str = "tcp"


@dataclass
class PasvRangeSpec:
    """Contiguous host==container port range for passive-mode protocols
    (e.g. FTP) where the port NUMBER itself is announced to the client and
    can't be silently remapped across NAT -- see noob-orientation-server's
    vsftpd.conf parameterization for why this needs to stay 1:1."""

    container_min: int
    container_max: int
    env_min_var: str
    env_max_var: str
    env_address_var: str | None = None


@dataclass
class HostSpec:
    name: str
    image: str
    front_door: bool = False
    ports: list[PortSpec] = field(default_factory=list)
    pasv_range: PasvRangeSpec | None = None
    extra_env: dict[str, str] = field(default_factory=dict)
    # Which internal-network segment(s) this host joins, by name. Every box
    # defaults to the single shared group "internal" -- one segment, every
    # host (front door included) a member -- reproducing today's flat
    # topology exactly for boxes that don't set this. A host listing MORE
    # than one group (e.g. a pivot host in a chain) joins all of them, so
    # it can bridge traffic between segments that otherwise can't reach
    # each other; see god-the-ferryman.yaml for the motivating case (a
    # deliberate Portal -> Waystation -> Vault chain, no direct
    # Portal<->Vault reachability, mirroring that box's original VM-build
    # topology).
    internal_groups: list[str] = field(default_factory=lambda: ["internal"])
    # True only on a BoxSpec that also sets `nested_docker` (see below) --
    # marks this host as "no top-level container of its own," just an
    # image to preload into, and run inside, the box's one outer dind
    # container. Meaningless (and never checked) on a box that doesn't set
    # BoxSpec.nested_docker.
    nested_docker: bool = False


@dataclass
class NestedDockerSpec:
    """Present only on a box whose own design needs real Docker-socket
    access as part of the puzzle (currently: legendary-ferrymans-relay).
    Rather than exposing the real per-host Docker daemon to any team's
    container -- which on this shared, multi-tenant orchestrator would
    hand that team control over every OTHER team's containers too, not a
    contained escalation -- the box's entire stack runs inside one
    disposable nested Docker daemon per instance instead. See
    docker_backend.py's _provision_nested_docker_sync for the actual
    bring-up; see legendary-ferrymans-relay.yaml for the motivating case.
    """

    outer_image: str
    privileged: bool = True
    dockerd_ready_timeout_seconds: float = 90.0
    # Any image besides this box's own HostSpec images that the nested
    # bring-up script needs preloaded (e.g. "alpine:latest", spun up fresh
    # by the player via the escaped socket) -- the nested daemon has no
    # internet egress, so anything it might need to `docker run` must be
    # preloaded, not pulled live.
    extra_preload_images: list[str] = field(default_factory=list)


@dataclass
class BoxSpec:
    box_id: str
    hosts: list[HostSpec]
    nested_docker: NestedDockerSpec | None = None

    @property
    def is_multi_host(self) -> bool:
        return len(self.hosts) > 1

    @property
    def front_door_host(self) -> HostSpec:
        for h in self.hosts:
            if h.front_door:
                return h
        raise ValueError(f"box {self.box_id} has no front_door host defined")


def _parse_host(raw: dict) -> HostSpec:
    ports = [PortSpec(**p) for p in raw.get("ports", [])]
    pasv_raw = raw.get("pasv_range")
    pasv = PasvRangeSpec(**pasv_raw) if pasv_raw else None
    return HostSpec(
        name=raw["name"],
        image=raw["image"],
        front_door=raw.get("front_door", False),
        ports=ports,
        pasv_range=pasv,
        extra_env=raw.get("extra_env", {}),
        internal_groups=list(raw.get("internal_groups") or ["internal"]),
        nested_docker=raw.get("nested_docker", False),
    )


def _parse_nested_docker(raw: dict | None) -> NestedDockerSpec | None:
    if not raw:
        return None
    return NestedDockerSpec(
        outer_image=raw["outer_image"],
        privileged=raw.get("privileged", True),
        dockerd_ready_timeout_seconds=raw.get("dockerd_ready_timeout_seconds", 90.0),
        extra_preload_images=list(raw.get("extra_preload_images") or []),
    )


def load_spec(path: str) -> BoxSpec:
    with open(path) as f:
        raw = yaml.safe_load(f)
    hosts = [_parse_host(h) for h in raw["hosts"]]
    spec = BoxSpec(
        box_id=raw["box_id"],
        hosts=hosts,
        nested_docker=_parse_nested_docker(raw.get("nested_docker")),
    )
    if not any(h.front_door for h in spec.hosts):
        raise ValueError(f"box {spec.box_id} spec has no front_door host")
    return spec


class BoxRegistry:
    def __init__(self, specs_dir: str = config.SPECS_DIR):
        self._specs_dir = specs_dir
        self._cache: dict[str, BoxSpec] = {}

    def get(self, box_id: str) -> BoxSpec:
        if box_id not in self._cache:
            path = os.path.join(self._specs_dir, f"{box_id}.yaml")
            if not os.path.isfile(path):
                raise KeyError(f"no box spec found for box_id={box_id!r} (looked at {path})")
            self._cache[box_id] = load_spec(path)
        return self._cache[box_id]

    def reload(self) -> None:
        self._cache.clear()

    def all_box_ids(self) -> list[str]:
        return sorted(
            fname[: -len(".yaml")]
            for fname in os.listdir(self._specs_dir)
            if fname.endswith(".yaml")
        )

    def all(self) -> list[BoxSpec]:
        return [self.get(box_id) for box_id in self.all_box_ids()]


registry = BoxRegistry()
