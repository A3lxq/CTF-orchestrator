from datetime import datetime

from pydantic import BaseModel


class CreateInstanceRequest(BaseModel):
    team_id: int
    box_id: str
    team_secret: str
    ttl_minutes: int | None = None
    backend: str | None = None  # None = use config.DEFAULT_BACKEND


class RenewInstanceRequest(BaseModel):
    extra_minutes: int


class PortBindingResponse(BaseModel):
    service_name: str
    container_port: int
    host_port: int
    protocol: str

    class Config:
        from_attributes = True


class InstanceResponse(BaseModel):
    instance_id: str
    team_id: int
    box_id: str
    status: str
    entry_host: str | None
    entry_port: int | None
    # Every published front-door port -- entry_host/entry_port above stay
    # "the" single one for backward compatibility. None for an instance
    # provisioned before this field existed.
    ports: list[PortBindingResponse] | None
    created_at: datetime
    expires_at: datetime

    class Config:
        from_attributes = True


class BoxPortInfo(BaseModel):
    container_port: int
    protocol: str


class BoxHostInfo(BaseModel):
    name: str
    front_door: bool
    ports: list[BoxPortInfo]


class BoxInfo(BaseModel):
    box_id: str
    is_multi_host: bool
    hosts: list[BoxHostInfo]
