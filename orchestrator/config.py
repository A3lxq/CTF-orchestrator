import os

DATABASE_URL = os.environ.get("ORCHESTRATOR_DATABASE_URL", "sqlite:///./orchestrator.db")
# Which RuntimeBackend new instances use by default ("docker" or
# "kubernetes") -- a deployment-wide choice (dev/small-scale vs. a real
# cluster), not something GZCTF picks per-request. CreateInstanceRequest
# can still override it explicitly for testing both backends side by side
# against the same orchestrator.
DEFAULT_BACKEND = os.environ.get("ORCHESTRATOR_DEFAULT_BACKEND", "docker")
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

# KubernetesBackend-specific settings. NodePort's own valid range
# (default 30000-32767, the apiserver's --service-node-port-range) is
# used as the port pool rather than reusing PORT_POOL_START/END above --
# the two ranges don't overlap, but keeping them visibly distinct avoids
# ever assuming NodePort will accept an arbitrary Docker-pool port.
K8S_NODE_PORT_POOL_START = int(os.environ.get("ORCHESTRATOR_K8S_NODE_PORT_POOL_START", "30000"))
K8S_NODE_PORT_POOL_END = int(os.environ.get("ORCHESTRATOR_K8S_NODE_PORT_POOL_END", "32767"))
# None means "auto-detect from the cluster's own Node objects" (first
# node's InternalIP/ExternalIP). Set explicitly for a real multi-node
# cluster behind a known-reachable address (e.g. a cloud LB or a fixed
# node IP) rather than trusting whichever node the API happens to list
# first.
K8S_NODE_PUBLIC_ADDRESS = os.environ.get("ORCHESTRATOR_K8S_NODE_PUBLIC_ADDRESS")
# None means "use the default kubeconfig resolution" (in-cluster config
# if running inside a pod, else ~/.kube/config) -- the standard client-go
# / kubernetes-client-python behavior other k8s tooling expects.
K8S_KUBECONFIG_CONTEXT = os.environ.get("ORCHESTRATOR_K8S_CONTEXT")
# Required, no default: the cluster's pod network CIDR (the CNI's overall
# IP pool, e.g. Calico's IPPool cidr -- NOT any single node's narrower
# Node.spec.podCIDR slice, which only covers that one node). This is what
# lets the front door's NetworkPolicy allow genuinely external traffic
# while still excluding traffic from another team's pod -- getting it
# wrong (or leaving it unset) silently reopens the exact cross-namespace
# isolation hole this was added to close, with no error to signal it, so
# KubernetesBackend refuses to start without it rather than guess.
K8S_POD_CIDR = os.environ.get("ORCHESTRATOR_K8S_POD_CIDR")
