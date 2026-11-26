from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from ..boxes.registry import BoxSpec
from ..models import Instance


@dataclass
class ProvisionedHost:
    service_name: str
    container_ref: str
    internal_ip: str | None
    is_front_door: bool


@dataclass
class PortBinding:
    """One published front-door port. entry_host/entry_port above stay
    the single "the" port for backward compatibility (existing callers,
    existing DB column); this is the full list -- several boxes
    (noob-orientation-server, master-two-offices, veteran-aftermath,
    legendary-ferrymans-relay) publish a second port (commonly SSH
    alongside HTTP) that entry_port alone can never represent."""

    service_name: str
    container_port: int
    host_port: int
    protocol: str


@dataclass
class ProvisionResult:
    network_name: str
    entry_host: str
    entry_port: int
    hosts: list[ProvisionedHost]
    ports: list[PortBinding] = field(default_factory=list)


class RuntimeBackend(ABC):
    name: str

    @abstractmethod
    async def provision(self, instance: Instance, spec: BoxSpec, team_secret: str) -> ProvisionResult: ...

    @abstractmethod
    async def status(self, instance: Instance) -> str: ...

    @abstractmethod
    async def destroy(self, instance: Instance) -> None: ...

    @abstractmethod
    async def cleanup_failed_provision(self, instance: Instance, spec: BoxSpec) -> None:
        """Best-effort teardown after `provision()` raises partway
        through. Deliberately does NOT reuse `destroy()`'s own logic,
        which keys off `instance.network_name`/`instance.hosts` --
        neither is populated yet at the point a provisioning attempt
        can fail (the API layer only fills them in on SUCCESS, see
        api/instances.py's create_instance), so a naive `destroy()`
        call here would silently no-op and leave whatever real
        containers/namespaces/networks the failed attempt already
        created running forever. Found as a real bug: three full
        domainzero-intermediate-domainedge instances (a real Samba AD
        DC each) were left running indefinitely after repeated
        provisioning failures during this box's own test suite,
        compounding host CPU contention into every subsequent attempt.
        Re-derives the exact same deterministic names `provision()`
        itself uses (box_id + team_id + host name) instead, so this
        works regardless of how far provisioning actually got."""
        ...
