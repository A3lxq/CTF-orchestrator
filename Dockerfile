# Containerizes the orchestrator service itself -- NOT a nested Docker
# daemon. Talks to the real host's Docker daemon via a bind-mounted
# /var/run/docker.sock (see ctf-platform/docker-compose.yml), the same
# way the native (non-containerized) deployment always has. Every
# container this process creates (box instances, Legendary's nested
# daemons) lands on that real host daemon, not inside this one.
FROM python:3.11-slim

# Needs the real `docker` CLI binary, not just the docker-py SDK:
# Legendary's nested-docker image preload shells out to
# `docker save <image> | docker exec -i <container> docker load`, which
# has no clean SDK-only equivalent (see
# orchestrator/backends/docker_backend.py's _preload_nested_images).
# docker.io's bundled dockerd is never started here -- this container
# only ever talks to the real host daemon through the mounted socket.
RUN sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list.d/debian.sources \
    && apt-get update && apt-get install -y --no-install-recommends docker.io ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# Mount a volume at /app/data in compose and point
# ORCHESTRATOR_DATABASE_URL at sqlite:////app/data/orchestrator.db so
# the DB survives `docker compose down`/up -- the default
# sqlite:///./orchestrator.db would otherwise live in this container's
# own throwaway filesystem.
RUN mkdir -p /app/data

EXPOSE 9100

# Builds every box image on first start (fast on reruns -- Docker's own
# build cache, not re-downloaded) before serving, so `docker compose up`
# alone is enough to get a fully working instance, no separate manual
# build step.
CMD ["sh", "-c", "./scripts/build_boxes.sh && exec uvicorn orchestrator.main:app --host 0.0.0.0 --port 9100"]
