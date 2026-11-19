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

## Status: all 8 boxes done, both backends

All 7 originally in-scope Halcyon Protocol boxes (Noob, Beginner,
Intermediate, Veteran, Master, Expert, God) plus Legendary (Ferryman's
Relay) run on the Docker backend; the first 7 also run on an optional
Kubernetes backend (Legendary is Docker-only by design — its puzzle
needs a disposable per-team Docker daemon, which only the Docker
backend provides). Not yet wired to a real GZCTF deployment — that's a
separate, larger integration layer, not covered here.

Each team gets a fresh, isolated instance with real, running
containers — proven via live checks, not mocks: cross-team network
isolation (a live in-container connection attempt, not just config
inspection), idempotent `POST /instances` on `(team_id, box_id)`, and
`DELETE /instances/{id}` that actually tears down every container/
network/volume, not just a DB row.

## Setting this up

See **[SETUP.md](SETUP.md)** for the full walkthrough — cloning,
building all 8 box images, starting the service, and verifying a real
instance provisions correctly, plus optional sections for the
Kubernetes backend and running the full test suites.

## Layout

```
orchestrator/
  main.py              FastAPI app
  config.py             env-driven settings (DB URL, port pool, TTL, auth token,
                          Kubernetes backend settings)
  models.py              Instance / InstanceHost (SQLAlchemy)
  schemas.py              Pydantic request/response models
  reaper.py                independent TTL sweep (destroys expired instances)
  api/
    instances.py            POST/GET/DELETE /instances, /renew
    health.py                 /healthz
  boxes/
    registry.py                box_id -> BoxSpec, loaded from boxes/specs/*.yaml
    specs/*.yaml                 one per box_id: hosts, images, ports, pasv ranges,
                                   internal_groups (network segmentation), and
                                   nested_docker (Legendary only)
  backends/
    base.py                       RuntimeBackend ABC: provision/status/destroy
    docker_backend.py              DockerBackend
    k8s_backend.py                 KubernetesBackend
    nested_stacks/                  per-box bring-up scripts for boxes that run
                                      their whole stack inside one disposable
                                      nested Docker daemon (currently: Legendary)
boxes-src/<box_id>/            resurrected Docker source per box (git history,
                                adapted: no static container_name/ports, since
                                those collide across concurrent team instances)
scripts/
  build_boxes.sh                builds every box image + pulls Legendary's
                                  nested-daemon prerequisites
  health_check.sh                 provisions a real instance, checks its flag,
                                    destroys it -- see SETUP.md
tests/
```

See `SETUP.md` for how to stand this up and `boxes/specs/*.yaml` for
each box's exact topology.

## Why a readiness wait

`provision()` doesn't return until every front-door port is actually
answering — a container reporting `running` only means the process
started, not that the service inside (nginx/sshd/vsftpd, started via
supervisord) has finished coming up. A plain TCP connect isn't reliable
enough for this: Docker's userland proxy accepts the handshake as soon
as the container exists and only resets once it tries (and fails) to
reach a backend that isn't listening yet, so a bare `connect()` can
report success well before the real service is up. `docker_backend.py`'s
`_tcp_probe_attempt` handles this with a protocol-agnostic probe
(server-first banner, falling back to a generic HTTP GET) rather than
special-casing port 80 — see its own comments for the exact race that
required this.
