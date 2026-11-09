import asyncio
import logging

from . import config
from .api.instances import get_backend
from .models import Instance, InstanceStatus, get_session, utcnow

logger = logging.getLogger("orchestrator.reaper")


async def reap_once() -> int:
    """Destroy every non-destroyed instance past its expires_at. Runs
    independently of GZCTF's own TTL cron -- defense in depth, so nothing
    accumulates unbounded in Docker/Kubernetes even if GZCTF is down or its
    own reaper silently fails."""
    session = get_session()
    reaped = 0
    try:
        expired = (
            session.query(Instance)
            .filter(Instance.status != InstanceStatus.DESTROYED, Instance.expires_at < utcnow())
            .all()
        )
        for instance in expired:
            try:
                backend = get_backend(instance.backend)
                await backend.destroy(instance)
                instance.status = InstanceStatus.DESTROYED
                instance.destroyed_at = utcnow()
                reaped += 1
            except Exception:
                logger.exception("failed to reap instance %s", instance.id)
        session.commit()
    finally:
        session.close()
    return reaped


async def run_forever() -> None:
    while True:
        try:
            count = await reap_once()
            if count:
                logger.info("reaped %d expired instance(s)", count)
        except Exception:
            logger.exception("reaper sweep failed")
        await asyncio.sleep(config.REAPER_INTERVAL_SECONDS)
