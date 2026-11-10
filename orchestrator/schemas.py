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


class InstanceResponse(BaseModel):
    instance_id: str
    team_id: int
    box_id: str
    status: str
    entry_host: str | None
    entry_port: int | None
    created_at: datetime
    expires_at: datetime

    class Config:
        from_attributes = True
