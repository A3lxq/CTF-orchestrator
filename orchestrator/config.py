import os

DATABASE_URL = os.environ.get("ORCHESTRATOR_DATABASE_URL", "sqlite:///./orchestrator.db")
BOX_IMAGE_PREFIX = os.environ.get("ORCHESTRATOR_IMAGE_PREFIX", "ctf-boxes")
DOCKER_HOST_PUBLIC_ADDRESS = os.environ.get("ORCHESTRATOR_PUBLIC_ADDRESS", "127.0.0.1")
PORT_POOL_START = int(os.environ.get("ORCHESTRATOR_PORT_POOL_START", "20000"))
PORT_POOL_END = int(os.environ.get("ORCHESTRATOR_PORT_POOL_END", "29999"))
DEFAULT_TTL_MINUTES = int(os.environ.get("ORCHESTRATOR_DEFAULT_TTL_MINUTES", "120"))
REAPER_INTERVAL_SECONDS = int(os.environ.get("ORCHESTRATOR_REAPER_INTERVAL_SECONDS", "60"))
AUTH_BEARER_TOKEN = os.environ.get("ORCHESTRATOR_AUTH_TOKEN")  # None disables auth check (dev only)
SPECS_DIR = os.environ.get(
    "ORCHESTRATOR_SPECS_DIR",
    os.path.join(os.path.dirname(__file__), "boxes", "specs"),
)
