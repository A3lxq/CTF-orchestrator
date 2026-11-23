import asyncio

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from pydantic import ValidationError

from ..boxes.registry import registry
from ..boxes.upload import BoxUploadError, UploadBoxSpec, upload_box_sync
from ..schemas import BoxHostInfo, BoxInfo, BoxPortInfo
from .instances import require_auth

router = APIRouter(prefix="/boxes", tags=["boxes"])


def _to_box_info(spec) -> BoxInfo:
    return BoxInfo(
        box_id=spec.box_id,
        is_multi_host=spec.is_multi_host,
        hosts=[
            BoxHostInfo(
                name=h.name,
                front_door=h.front_door,
                ports=[BoxPortInfo(container_port=p.container_port, protocol=p.protocol) for p in h.ports],
            )
            for h in spec.hosts
        ],
    )


@router.get("", response_model=list[BoxInfo])
async def list_boxes():
    """No auth required -- this is a static catalog (box_ids, host
    topology, published ports), not per-team or otherwise sensitive data.
    Lets ctf-platform (or any caller) discover what's available instead
    of hardcoding a mirror of registry.py's spec files."""
    return [_to_box_info(spec) for spec in registry.all()]


@router.get("/{box_id}", response_model=BoxInfo)
async def get_box(box_id: str):
    try:
        spec = registry.get(box_id)
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    return _to_box_info(spec)


@router.post("", response_model=BoxInfo, dependencies=[Depends(require_auth)])
async def upload_box(spec: str = Form(...), context: UploadFile = File(...)):
    """Admin-only (same bearer auth as every other mutating endpoint --
    the only caller is ctf-platform's own trusted admin API, never a
    browser directly). `spec` is a JSON-encoded UploadBoxSpec; `context`
    is a tarball containing docker/Dockerfile (single-host) or
    docker/<host-name>/Dockerfile per host (multi-host). See
    boxes/upload.py for the full validation/build/registration pipeline
    and its security framing."""
    try:
        parsed_spec = UploadBoxSpec.model_validate_json(spec)
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=f"invalid spec: {e}") from e

    tarball = await context.read()
    try:
        await asyncio.to_thread(upload_box_sync, parsed_spec, tarball)
    except BoxUploadError as e:
        raise HTTPException(status_code=e.status_code, detail=e.detail) from e

    return _to_box_info(registry.get(parsed_spec.box_id))
