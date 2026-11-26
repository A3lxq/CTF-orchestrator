from datetime import timedelta

from fastapi import APIRouter, Depends, Header, HTTPException

from .. import config
from ..backends.base import RuntimeBackend
from ..backends.docker_backend import DockerBackend
from ..boxes.registry import registry
from ..models import Instance, InstanceHost, InstanceStatus, get_session, utcnow
from ..schemas import CreateInstanceRequest, InstanceResponse, RenewInstanceRequest

router = APIRouter(prefix="/instances", tags=["instances"])

_backends: dict[str, RuntimeBackend] = {}
_BACKEND_FACTORIES = {"docker": DockerBackend}
# KubernetesBackend isn't imported eagerly: constructing it loads a
# kubeconfig/in-cluster config immediately, which would make every
# Docker-only deployment of this orchestrator fail at import time if no
# cluster is reachable. Imported lazily, only the first time "kubernetes"
# is actually requested.


def get_backend(name: str | None = None) -> RuntimeBackend:
    name = name or config.DEFAULT_BACKEND
    if name not in _backends:
        if name == "kubernetes" and name not in _BACKEND_FACTORIES:
            from ..backends.k8s_backend import KubernetesBackend
            _BACKEND_FACTORIES["kubernetes"] = KubernetesBackend
        _backends[name] = _BACKEND_FACTORIES[name]()
    return _backends[name]


def require_auth(authorization: str | None = Header(default=None)) -> None:
    if config.AUTH_BEARER_TOKEN is None:
        return  # dev mode: auth disabled
    expected = f"Bearer {config.AUTH_BEARER_TOKEN}"
    if authorization != expected:
        raise HTTPException(status_code=401, detail="invalid or missing bearer token")


def _to_response(instance: Instance) -> InstanceResponse:
    return InstanceResponse(
        instance_id=instance.id,
        team_id=instance.team_id,
        box_id=instance.box_id,
        status=instance.status.value,
        entry_host=instance.entry_host,
        entry_port=instance.entry_port,
        ports=instance.ports,
        created_at=instance.created_at,
        expires_at=instance.expires_at,
    )


@router.post("", response_model=InstanceResponse, dependencies=[Depends(require_auth)])
async def create_instance(req: CreateInstanceRequest):
    session = get_session()
    try:
        existing = (
            session.query(Instance)
            .filter(
                Instance.team_id == req.team_id,
                Instance.box_id == req.box_id,
                # Only reattach to a genuinely RUNNING instance -- `!=
                # DESTROYED` also matched ERROR (and PENDING) rows,
                # meaning a single transient provisioning failure got
                # cached forever: every later request for that same
                # (team_id, box_id) silently got handed back the same
                # broken row (status=ERROR, entry_host/entry_port still
                # null from before the exception) instead of ever
                # retrying. Confirmed via direct DB inspection after a
                # real run hit exactly this.
                Instance.status == InstanceStatus.RUNNING,
            )
            .one_or_none()
        )
        if existing is not None:
            # Idempotent: a second GZCTF challenge card for the same
            # (team, box) attaches to the already-running instance rather
            # than provisioning a duplicate.
            return _to_response(existing)

        # Per-team cap, enforced only here -- a genuinely NEW instance --
        # never on the idempotent reattach path above. Load-bearing now
        # that ctf-platform's self-registration is open to anyone: a
        # single anonymous signup could otherwise request all 8 boxes
        # with no limit.
        active_count = (
            session.query(Instance)
            .filter(
                Instance.team_id == req.team_id,
                Instance.status != InstanceStatus.DESTROYED,
            )
            .count()
        )
        if active_count >= config.MAX_INSTANCES_PER_TEAM:
            raise HTTPException(
                status_code=429,
                detail=f"team already has {active_count} active instances (max {config.MAX_INSTANCES_PER_TEAM})",
            )

        try:
            spec = registry.get(req.box_id)
        except KeyError as e:
            raise HTTPException(status_code=404, detail=str(e)) from e

        ttl = req.ttl_minutes or config.DEFAULT_TTL_MINUTES
        instance = Instance(
            team_id=req.team_id,
            box_id=req.box_id,
            backend=req.backend or config.DEFAULT_BACKEND,
            network_name="",  # filled in after provisioning
            status=InstanceStatus.PENDING,
            expires_at=utcnow() + timedelta(minutes=ttl),
        )
        session.add(instance)
        session.commit()
        session.refresh(instance)

        backend = get_backend(instance.backend)
        try:
            result = await backend.provision(instance, spec, req.team_secret)
        except Exception as e:
            instance.status = InstanceStatus.ERROR
            session.commit()
            try:
                await backend.cleanup_failed_provision(instance, spec)
            except Exception:
                pass  # best-effort; don't mask the original provisioning error
            raise HTTPException(status_code=500, detail=f"provisioning failed: {e}") from e

        instance.network_name = result.network_name
        instance.entry_host = result.entry_host
        instance.entry_port = result.entry_port
        instance.ports = [
            {
                "service_name": p.service_name,
                "container_port": p.container_port,
                "host_port": p.host_port,
                "protocol": p.protocol,
            }
            for p in result.ports
        ]
        instance.status = InstanceStatus.RUNNING
        for h in result.hosts:
            session.add(
                InstanceHost(
                    instance_id=instance.id,
                    service_name=h.service_name,
                    container_ref=h.container_ref,
                    internal_ip=h.internal_ip,
                    is_front_door=h.is_front_door,
                )
            )
        session.commit()
        session.refresh(instance)
        return _to_response(instance)
    finally:
        session.close()


@router.get("", response_model=InstanceResponse, dependencies=[Depends(require_auth)])
async def get_instance_by_key(team_id: int, box_id: str):
    session = get_session()
    try:
        instance = (
            session.query(Instance)
            .filter(
                Instance.team_id == team_id,
                Instance.box_id == box_id,
                Instance.status == InstanceStatus.RUNNING,
            )
            .one_or_none()
        )
        if instance is None:
            raise HTTPException(status_code=404, detail="no running instance for this (team_id, box_id)")
        return _to_response(instance)
    finally:
        session.close()


@router.get("/{instance_id}", response_model=InstanceResponse, dependencies=[Depends(require_auth)])
async def get_instance(instance_id: str):
    session = get_session()
    try:
        instance = session.get(Instance, instance_id)
        if instance is None:
            raise HTTPException(status_code=404, detail="instance not found")
        return _to_response(instance)
    finally:
        session.close()


@router.post("/{instance_id}/renew", response_model=InstanceResponse, dependencies=[Depends(require_auth)])
async def renew_instance(instance_id: str, req: RenewInstanceRequest):
    session = get_session()
    try:
        instance = session.get(Instance, instance_id)
        if instance is None:
            raise HTTPException(status_code=404, detail="instance not found")
        if instance.status == InstanceStatus.DESTROYED:
            raise HTTPException(status_code=409, detail="instance already destroyed")
        instance.expires_at = instance.expires_at + timedelta(minutes=req.extra_minutes)
        session.commit()
        session.refresh(instance)
        return _to_response(instance)
    finally:
        session.close()


@router.delete("/{instance_id}", status_code=204, dependencies=[Depends(require_auth)])
async def destroy_instance(instance_id: str):
    session = get_session()
    try:
        instance = session.get(Instance, instance_id)
        if instance is None:
            raise HTTPException(status_code=404, detail="instance not found")
        if instance.status == InstanceStatus.DESTROYED:
            return
        backend = get_backend(instance.backend)
        await backend.destroy(instance)
        instance.status = InstanceStatus.DESTROYED
        instance.destroyed_at = utcnow()
        session.commit()
    finally:
        session.close()
