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
