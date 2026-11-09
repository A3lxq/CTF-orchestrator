from abc import ABC, abstractmethod
from dataclasses import dataclass

from ..boxes.registry import BoxSpec
from ..models import Instance


@dataclass
class ProvisionedHost:
    service_name: str
    container_ref: str
    internal_ip: str | None
    is_front_door: bool


@dataclass
class ProvisionResult:
    network_name: str
    entry_host: str
    entry_port: int
    hosts: list[ProvisionedHost]


class RuntimeBackend(ABC):
    name: str

    @abstractmethod
    async def provision(self, instance: Instance, spec: BoxSpec, team_secret: str) -> ProvisionResult: ...

    @abstractmethod
    async def status(self, instance: Instance) -> str: ...

    @abstractmethod
    async def destroy(self, instance: Instance) -> None: ...
