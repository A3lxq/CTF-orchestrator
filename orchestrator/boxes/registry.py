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


@dataclass
class BoxSpec:
    box_id: str
    hosts: list[HostSpec]

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
    )


def load_spec(path: str) -> BoxSpec:
    with open(path) as f:
        raw = yaml.safe_load(f)
    hosts = [_parse_host(h) for h in raw["hosts"]]
    spec = BoxSpec(box_id=raw["box_id"], hosts=hosts)
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


registry = BoxRegistry()
