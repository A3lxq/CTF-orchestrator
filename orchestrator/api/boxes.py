from fastapi import APIRouter, HTTPException

from ..boxes.registry import registry
from ..schemas import BoxHostInfo, BoxInfo, BoxPortInfo

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
