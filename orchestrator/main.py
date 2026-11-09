import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from . import reaper
from .api import health, instances
from .models import init_db

logging.basicConfig(level=logging.INFO)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    reaper_task = asyncio.create_task(reaper.run_forever())
    yield
    reaper_task.cancel()


app = FastAPI(title="ctf-orchestrator", lifespan=lifespan)
app.include_router(health.router)
app.include_router(instances.router)
