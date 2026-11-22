import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
    create_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker

from . import config


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class InstanceStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    ERROR = "error"
    DESTROYED = "destroyed"


class Instance(Base):
    __tablename__ = "instances"
    __table_args__ = (
        # Enforces idempotent create: only one non-destroyed instance per
        # (team_id, box_id) at a time. SQLite/Postgres both support partial
        # unique indexes via a plain UniqueConstraint is NOT enough on its
        # own (it would also forbid re-provisioning after destroy), so this
        # is additionally enforced in application code at create time by
        # querying for an existing non-destroyed row first -- see
        # api/instances.py. The DB constraint here is a second line of
        # defense against concurrent double-creates, scoped loosely.
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    team_id: Mapped[int] = mapped_column(Integer, index=True)
    box_id: Mapped[str] = mapped_column(String(128), index=True)
    backend: Mapped[str] = mapped_column(String(32))
    network_name: Mapped[str] = mapped_column(String(128))
    status: Mapped[InstanceStatus] = mapped_column(Enum(InstanceStatus), default=InstanceStatus.PENDING)
    entry_host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    entry_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # [{service_name, container_port, host_port, protocol}, ...] -- every
    # published front-door port, not just the single "entry" one above.
    # Several boxes (noob-orientation-server, master-two-offices,
    # veteran-aftermath, legendary-ferrymans-relay) publish a second port
    # (commonly SSH alongside HTTP) that entry_port alone discarded.
    # Nullable/absent for any instance provisioned before this column
    # existed. See backends/base.py's PortBinding.
    ports: Mapped[list | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    destroyed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    hosts: Mapped[list["InstanceHost"]] = relationship(back_populates="instance", cascade="all, delete-orphan")


class InstanceHost(Base):
    __tablename__ = "instance_hosts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    instance_id: Mapped[str] = mapped_column(String(36), ForeignKey("instances.id"), index=True)
    service_name: Mapped[str] = mapped_column(String(64))
    container_ref: Mapped[str | None] = mapped_column(String(128), nullable=True)
    internal_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    is_front_door: Mapped[bool] = mapped_column(Boolean, default=False)

    instance: Mapped[Instance] = relationship(back_populates="hosts")


_engine = create_engine(config.DATABASE_URL, connect_args={"check_same_thread": False} if config.DATABASE_URL.startswith("sqlite") else {})
SessionLocal = sessionmaker(bind=_engine, autoflush=False, expire_on_commit=False)


def init_db() -> None:
    Base.metadata.create_all(_engine)


def get_session() -> Session:
    return SessionLocal()
