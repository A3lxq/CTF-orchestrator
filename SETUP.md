# Setup Guide — ctf-orchestrator

This is the single entry point for standing up the orchestrator and all
8 Halcyon Protocol box images from a clean checkout. If you already have
everything built and just want the fast path, skip to **5. Verify**.

**Want the whole player-facing platform running, not just this
service?** See
[`ctf-platform`](https://github.com/A3lxq/ctf-platform)'s own
`SETUP.md` instead — its one-command setup (Docker or native) stands up
*both* this orchestrator and the player/admin frontend together,
without you needing to follow the steps below by hand. This guide is
for standing up the orchestrator **on its own** (e.g. for development,
or if you're building a different frontend against it).

## 0. What you're setting up

- A standalone FastAPI service (`orchestrator/`) that, given a `box_id`
  and a per-team secret, provisions an isolated instance of that box
  (one container for single-host boxes, several for multi-host boxes)
  and returns where to reach it.
- 8 pre-built CTF box images (`ctf-boxes/*`), resurrected from each
  box's own original Docker source and checked into this repo under
  `boxes-src/`.
- By default this runs on the **Docker backend** (one real Docker
  daemon on this host). A **Kubernetes backend** also exists and is
  covered as an optional section further down — start with Docker
  first, it's simpler and what the rest of this guide assumes.

## 1. Prerequisites

```
# Debian/Ubuntu
sudo apt-get update && sudo apt-get install -y docker.io python3 python3-venv git
```

- **Docker Engine, with the real `docker` CLI binary on PATH** — not
  just a reachable daemon. One box (Legendary) preloads images into a
  nested Docker daemon via `docker save | docker exec -i ... docker
  load`, which shells out to the CLI directly; the Python `docker` SDK
  has no equivalent primitive for that.
- **Python 3.11+** and `git`.
- **Disk space** — check what you actually have before starting:
  ```
  df -h /
  docker system df
  ```
  Building all 8 boxes' images takes a few GB. **If you're on a host
  that's already tight on space, stop and free some up first** — this
  project has repeatedly hit disk exhaustion during its own development
  (one host was observed at 98% full with 5.5GB free at one point).
  Legendary in particular is heavier than every other box: each
  provisioned instance runs its own nested Docker daemon with its own
  independent copy of that box's images (no layer-sharing across teams,
  unlike every other box) — don't enable it at any real concurrency
  without real headroom.
- **Optional**, only needed for the Kubernetes backend section:
  [`kind`](https://kind.sigs.k8s.io/) and `kubectl` on PATH.

## 2. Clone and set up the orchestrator

Some newer boxes (everything under `boxes-src/domainzero-*` and
`boxes-src/cloudbreak-*`) live in their own separate repos, pulled in
as git submodules -- `--recurse-submodules` (or a separate
`git submodule update --init` after a plain clone) is required or
those boxes' `docker/` directories come down empty.

```
git clone --recurse-submodules git@github.com:A3lxq/CTF-orchestrator.git ctf-orchestrator
cd ctf-orchestrator

python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python3 --version   # confirm the venv's own interpreter resolves
```

Already have a clone without submodules initialized?
```
git submodule update --init --recursive
```

## 3. Build the box images

Each box's resurrected Docker source already lives in this repo under
`boxes-src/<box_id>/` — pulled from that box's own original repo
history, with static container names/ports stripped (they'd collide the
moment two teams run the same box at once). You don't need to re-extract
anything from the original box repos; it's already here.

```
./scripts/build_boxes.sh
```

This builds every box's image(s) and pulls the two extra images
Legendary's nested Docker daemon needs preloaded (`docker:27-dind`,
`alpine:latest`). It prints a running summary and exits non-zero if
anything failed, so it's safe to treat a clean exit as "everything's
ready." Takes a few minutes on a cold cache.

| box_id | image tag(s) |
|---|---|
| `noob-orientation-server` | `ctf-boxes/noob-orientation-server:latest` |
| `beginner-reading-room` | `ctf-boxes/beginner-reading-room:latest` |
| `intermediate-portside` | `ctf-boxes/intermediate-portside:latest` |
| `veteran-aftermath` | `ctf-boxes/veteran-aftermath:latest` |
| `master-two-offices` | `ctf-boxes/master-two-offices-frontdesk:latest`, `...-backoffice:latest` |
| `expert-the-annex` | `ctf-boxes/expert-the-annex-gateway:latest`, `...-directory:latest`, `...-fileserver:latest` |
| `god-the-ferryman` | `ctf-boxes/god-the-ferryman-portal:latest`, `...-waystation:latest`, `...-vault:latest` |
| `legendary-ferrymans-relay` | `ctf-boxes/legendary-ferrymans-relay-web:latest`, `...-relay:latest`, `...-vault:latest` |

If one box's build fails, you can re-run just that one directly, e.g.:
```
docker build -f boxes-src/noob-orientation-server/docker/Dockerfile \
  -t ctf-boxes/noob-orientation-server:latest boxes-src/noob-orientation-server/
```

## 4. Start the orchestrator

```
.venv/bin/python3 -m uvicorn orchestrator.main:app --host 127.0.0.1 --port 9100
```

SQLite (`./orchestrator.db`) is the default DB and is fine for
dev/small-scale use. Swap `ORCHESTRATOR_DATABASE_URL` for a Postgres URL
in production — same SQLAlchemy layer underneath, no code changes
needed.

Env vars worth knowing about (all optional, sensible defaults shown):

| Variable | Default | What it does |
|---|---|---|
| `ORCHESTRATOR_DATABASE_URL` | `sqlite:///./orchestrator.db` | SQLAlchemy connection string |
| `ORCHESTRATOR_DEFAULT_BACKEND` | `docker` | `docker` or `kubernetes` — which `RuntimeBackend` new instances use unless a request overrides it |
| `ORCHESTRATOR_PUBLIC_ADDRESS` | `127.0.0.1` | The address returned to callers as `entry_host` — set this to your real host's reachable address/DNS name for anything beyond local testing |
| `ORCHESTRATOR_PORT_POOL_START` / `_END` | `20000` / `29999` | Host port range allocated to front doors |
| `ORCHESTRATOR_DEFAULT_TTL_MINUTES` | `120` | How long an instance lives before the reaper destroys it automatically |
| `ORCHESTRATOR_AUTH_TOKEN` | unset (auth disabled) | **Dev-only default.** Set a real bearer token before exposing this past localhost — with it unset, anyone who can reach the API can provision/destroy instances. |

## 5. Verify

```
./scripts/health_check.sh
```

Provisions a real `noob-orientation-server` instance, confirms its flag
matches the expected `HMAC-SHA256(team_secret, "box_id:n")` value,
destroys it, and confirms the container is actually gone. Expected
output ends with:

```
RESULT: healthy
```

If it prints `RESULT: FAILED -- <reason>` instead, the reason is the
actual problem — common ones:
- **stale container name collision** — a crashed previous run left a
  container behind with the same name a new one needs. The orchestrator
  already removes stale containers itself before creating a new one
  (`_start_host`'s own stale-removal), so this should self-heal on
  retry; if it doesn't, `docker rm -f` the named container manually.
- **port already allocated** — the port pool
  (`ORCHESTRATOR_PORT_POOL_START`-`_END`) is exhausted by leftover
  instances; `docker ps -a | grep ^ctf-` to find them.
- **disk space** — see the prerequisites section above.

## 6. Try another box by hand

The health check only exercises one single-host box. To see a
multi-host box work too:

```
curl -X POST http://127.0.0.1:9100/instances -H "Content-Type: application/json" \
  -d '{"team_id": 1, "box_id": "master-two-offices", "team_secret": "my-test-secret"}'
```

The response's `entry_host`/`entry_port` is `frontdesk`'s published
web port. Confirm flag 1:

```
curl http://<entry_host>:<entry_port>/
python3 -c "
import hmac, hashlib
secret = 'my-test-secret'
digest = hmac.new(secret.encode(), b'master-two-offices:1', hashlib.sha256).hexdigest()
print(f'HLC{{{digest[:10]}}}')"
```

The two should match. Clean up with:

```
curl -X DELETE http://127.0.0.1:9100/instances/<instance_id>
```

(`<instance_id>` is in the `POST`'s own response.)

## 7. (Optional) Enable the Kubernetes backend

This project's own testing uses [`kind`](https://kind.sigs.k8s.io/)
locally. **kind's default CNI does not enforce NetworkPolicy at all**,
which would make the cross-team isolation design a silent no-op — the
cluster below is deliberately created without it, replaced with Calico.

```
cat > /tmp/kind-config.yaml <<'EOF'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
EOF
kind create cluster --name ctf-test --config /tmp/kind-config.yaml

kubectl --context kind-ctf-test apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.28.0/manifests/tigera-operator.yaml
# then apply a Calico custom-resources manifest with your chosen pod CIDR,
# and confirm it's actually enforcing policy before trusting it:
kubectl --context kind-ctf-test get ippool -o yaml   # note the pod CIDR shown here
```

Load every box image into the cluster (it has no registry behind it):

```
for img in $(docker images --format '{{.Repository}}:{{.Tag}}' | grep ^ctf-boxes/); do
  kind load docker-image "$img" --name ctf-test
done
```

Start the orchestrator with the cluster's real pod CIDR
(**required, no default** — getting it wrong silently reopens
cross-team isolation with no error, so the backend refuses to start
without it):

```
ORCHESTRATOR_K8S_POD_CIDR=<cidr from the ippool above> \
ORCHESTRATOR_K8S_CONTEXT=kind-ctf-test \
.venv/bin/python3 -m uvicorn orchestrator.main:app --host 127.0.0.1 --port 9100
```

Then repeat the check from step 6, adding `"backend": "kubernetes"` to
the `POST /instances` body. Legendary works here too -- its nested
Docker daemon runs as a privileged `docker:dind` container in the
instance's own Pod instead of a plain outer container, but needs no
extra setup beyond what's already above (`docker:27-dind` is a public
image the cluster pulls directly; Legendary's own 3 service images are
preloaded straight into the nested daemon by the orchestrator itself,
bypassing `kind load docker-image` entirely for them).

## 8. (Optional) Running the full test suites

Each exercises real Docker/Kubernetes state — no mocks — and are
intentionally slow:

| File | Covers | Rough runtime |
|---|---|---|
| `tests/test_phase2_boxes.py` | Single-host boxes | ~3min |
| `tests/test_phase3_multihost.py` | Multi-host boxes (Docker) | ~4min |
| `tests/test_phase4_k8s.py` | All 7 original boxes (Kubernetes) | ~20-40min |
| `tests/test_phase5_legendary.py` | Legendary's full exploit chain | ~9-11min |

```
ORCHESTRATOR_TEST_URL=http://127.0.0.1:9100 .venv/bin/python3 -m pytest tests/test_phase2_boxes.py -v
```

## Resetting between runs

```
docker ps -a --format '{{.Names}}' | grep '^ctf-' | xargs -r docker rm -f
docker network ls --format '{{.Name}}' | grep '^ctf-' | xargs -r docker network rm
rm -f orchestrator.db
```

## Something went wrong

If you hit a failure not covered in step 5's troubleshooting list above,
check the memory/plan notes this project kept for itself while building
each phase — in particular, `docker:27-dind-rootless` is known to fail
outright on at least one host this was built on (`[rootlesskit:parent]
error: failed to start the child: fork/exec /proc/self/exe: operation
not permitted`, regardless of flags) — if you hit that exact error
building or modifying Legendary's backing, it's a known environmental
issue, not something to debug from scratch; `docker:27-dind` (not the
`-rootless` variant) is what this project actually ships with.
