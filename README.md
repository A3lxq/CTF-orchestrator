# ctf-orchestrator

Per-team container orchestration for The Halcyon Protocol CTF boxes,
built to sit behind a modified GZCTF (team management, scoring,
scoreboard, admin UI) without touching GZCTF's own Restricted-licensed
container-provisioning code. See
`/home/immanuvel/.claude/plans/sparkling-roaming-sedgewick.md` for the
full design and rationale (why this exists as a separate service, the
GZCTF licensing constraint, the per-box resurrection plan, build
sequence).

Each team gets their own fresh container instance of a chosen box, with
a per-team secret injected as `CTF_SECRET` — the box derives all 10 of
its own flags from that secret via the same
`HMAC-SHA256(secret, "box_id:n")` scheme already used by every box's own
`flags/generate_flags.py`. Two teams playing the same box always get
different flags; a leaked flag is attributable to whichever team it
belongs to.

## Status: Phase 0 complete

Orchestrator standalone, Docker backend, proven against
`noob-orientation-server` only (not yet wired to GZCTF — that's Phase 1).
See `tests/test_phase0_noob.py`, run against a real local Docker daemon
(no mocks):

- Two different team secrets → two isolated containers, each producing
  flags that match `HMAC-SHA256(team_secret, "box_id:n")` for that
  specific team, and differ from each other.
- Network isolation: team A cannot reach team B's instance, proven via a
  live in-container TCP connection attempt, not just inspecting network
  config.
- `POST /instances` is idempotent on `(team_id, box_id)` — re-requesting
  an already-running instance attaches to it rather than double-
  provisioning (required for the later "10 GZCTF challenges, 1 real
  instance" design).
- `DELETE /instances/{id}` actually removes the container(s) and
  network, not just a DB row.

## Running it locally

```
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

# build a box image (see boxes-src/<box_id>/ for the resurrected Docker
# source, pulled from each box repo's pre-removal git history)
cd boxes-src/noob-orientation-server
docker build -t ctf-boxes/noob-orientation-server:latest -f docker/Dockerfile .
cd ../..

# start the orchestrator (SQLite by default; set ORCHESTRATOR_DATABASE_URL
# for Postgres in production)
.venv/bin/python3 -m uvicorn orchestrator.main:app --host 127.0.0.1 --port 9100

# in another shell
.venv/bin/python3 -m pytest tests/test_phase0_noob.py -v
```

## Layout

```
orchestrator/
  main.py              FastAPI app
  config.py             env-driven settings (DB URL, port pool, TTL, auth token)
  models.py              Instance / InstanceHost (SQLAlchemy)
  schemas.py              Pydantic request/response models
  reaper.py                independent TTL sweep (destroys expired instances)
  api/
    instances.py            POST/GET/DELETE /instances, /renew
    health.py                 /healthz
  boxes/
    registry.py                box_id -> BoxSpec, loaded from boxes/specs/*.yaml
    specs/*.yaml                 one per box_id: hosts, images, ports, pasv ranges
  backends/
    base.py                       RuntimeBackend ABC: provision/status/destroy
    docker_backend.py              DockerBackend (Phase 0-3)
    k8s_backend.py (Phase 4, not yet built)
boxes-src/<box_id>/            resurrected Docker source per box (git history,
                                adapted: no static container_name/ports, since
                                those collide across concurrent team instances)
tests/
```

## Why a readiness wait, and why HTTP-level for port 80 specifically

`DockerBackend.provision()` doesn't return until every front-door port is
actually answering — a container reporting `running` only means the
process started, not that nginx/sshd/vsftpd (started via supervisord
inside) have finished coming up. A plain TCP connect isn't a reliable
enough signal for this: Docker's userland proxy accepts the handshake as
soon as the container exists and only resets the connection once it
tries (and fails) to reach a backend that isn't listening yet — so a bare
`connect()` can report success well before the real service is up. Hit
this exact race building the Phase 0 test suite (an HTTP GET got
"Connection reset by peer" immediately after a prior raw TCP check had
already reported the port open). Port 80 gets a real HTTP probe
(`_wait_for_http`); other ports fall back to TCP connect, which is still
better than no wait but should get the same HTTP-style treatment if a
future box hits the same race on its own front door.
