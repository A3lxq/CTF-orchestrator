import asyncio
import contextlib
import re
import socket
import threading
import time

from kubernetes import client as k8s_client
from kubernetes import config as k8s_config
from kubernetes.client.rest import ApiException

from .. import config
from ..boxes.registry import BoxSpec, HostSpec
from ..models import Instance
from .base import PortBinding, ProvisionedHost, ProvisionResult, RuntimeBackend

# The kubernetes-client SDK is sync-only (same situation as docker-py) --
# every call into it below is wrapped in asyncio.to_thread so the async
# FastAPI event loop isn't blocked waiting on the API server.


class NodePortAllocationError(RuntimeError):
    pass


def _pod_cidr_exclusion_block() -> k8s_client.V1IPBlock:
    """V1IPBlock(cidr=..., except=...) with its `except` field set via
    constructor kwarg (var_except=... or **{"except": ...}) silently
    fails to serialize in kubernetes-client 37.0.2 -- to_dict()/the
    actual API request body comes out with no `except` key at all, no
    error raised, confirmed by direct inspection of the live
    NetworkPolicy object this produced (and the isolation bug that one
    specific gap let through). Setting the attribute AFTER construction
    does serialize correctly -- confirmed via api_client.sanitize_for_serialization().
    Do not "simplify" this back to a single constructor call."""
    block = k8s_client.V1IPBlock(cidr="0.0.0.0/0")
    block.var_except = [config.K8S_POD_CIDR]
    return block


def _k8s_name(*parts: str) -> str:
    """RFC 1123 label/subdomain-safe name: lowercase, hyphens only,
    <=63 chars (the limit that actually bites -- Namespace and Service
    names are both capped at 63, not DNS's full 253)."""
    name = "-".join(parts).lower()
    name = re.sub(r"[^a-z0-9-]", "-", name)
    name = re.sub(r"-+", "-", name).strip("-")
    return name[:63].rstrip("-")


class KubernetesBackend(RuntimeBackend):
    name = "kubernetes"

    def __init__(self):
        if not config.K8S_POD_CIDR:
            # Refuse to start rather than silently provision instances
            # whose front-door NetworkPolicy can't actually distinguish
            # external traffic from another team's pod -- see this
            # backend's own _apply_network_policies for why this value is
            # load-bearing for isolation, not cosmetic.
            raise RuntimeError(
                "ORCHESTRATOR_K8S_POD_CIDR must be set to the cluster's pod "
                "network CIDR (the CNI's overall IP pool, not a single "
                "node's narrower podCIDR slice) before KubernetesBackend "
                "can be used -- see config.py's K8S_POD_CIDR for why."
            )
        try:
            k8s_config.load_incluster_config()
        except k8s_config.ConfigException:
            k8s_config.load_kube_config(context=config.K8S_KUBECONFIG_CONTEXT)
        self._core = k8s_client.CoreV1Api()
        self._apps = k8s_client.AppsV1Api()
        self._net = k8s_client.NetworkingV1Api()
        # A real threading.Lock, not asyncio.Lock -- _provision_sync runs
        # in a worker thread (via asyncio.to_thread), not a coroutine, so
        # an asyncio.Lock can't be correctly acquired here at all. Same
        # fix, same reasoning, as DockerBackend's own _alloc_lock: a
        # NodePort is picked from a live snapshot (_used_node_ports) with
        # nothing stopping two concurrent provisions from picking the same
        # "free" port before either has actually committed it via
        # _create_service.
        self._alloc_lock = threading.Lock()
        self._node_address_cache: str | None = None

    # ---- provision -----------------------------------------------------

    async def provision(self, instance: Instance, spec: BoxSpec, team_secret: str) -> ProvisionResult:
        return await asyncio.to_thread(self._provision_sync, instance, spec, team_secret)

    def _provision_sync(self, instance: Instance, spec: BoxSpec, team_secret: str) -> ProvisionResult:
        namespace = _k8s_name("ctf", spec.box_id, str(instance.team_id))
        self._ensure_namespace(namespace)

        used_node_ports = self._used_node_ports()
        provisioned: list[ProvisionedHost] = []
        front_door_port: int | None = None
        entry_ports: list[PortBinding] = []

        for host_spec in spec.hosts:
            # Only a front-door host actually allocates a NodePort from
            # the shared pool (internal-only hosts get a plain ClusterIP,
            # no race possible) -- see __init__'s comment on _alloc_lock.
            # Held across refresh-snapshot + allocate + the _create_service
            # call that actually commits the NodePort to the k8s API,
            # since that's the real moment a stale snapshot could collide.
            lock = self._alloc_lock if host_spec.front_door else contextlib.nullcontext()
            with lock:
                if host_spec.front_door:
                    used_node_ports |= self._used_node_ports()
                svc_ports, node_port_env = self._allocate_host_ports(host_spec, used_node_ports)
                self._create_deployment(namespace, host_spec, team_secret, instance, node_port_env)
                service = self._create_service(namespace, host_spec, svc_ports)

            if host_spec.front_door:
                # Prefer port 80 as "the" single entry port when present,
                # same convention DockerBackend uses, falling back to the
                # first spec'd port otherwise.
                preferred = sorted(host_spec.ports, key=lambda p: p.container_port != 80)
                front_container_port = preferred[0].container_port
                for p in service.spec.ports:
                    if p.port == front_container_port:
                        front_door_port = p.node_port
                # Every published NodePort, not just the preferred one --
                # same reasoning as DockerBackend's entry_ports (see
                # base.py's PortBinding): a box like master-two-offices
                # publishes SSH alongside HTTP, and entry_port alone can't
                # represent that second port.
                for p in service.spec.ports:
                    entry_ports.append(
                        PortBinding(
                            service_name=host_spec.name,
                            container_port=p.port,
                            host_port=p.node_port,
                            protocol=(p.protocol or "TCP").lower(),
                        )
                    )

            provisioned.append(
                ProvisionedHost(
                    service_name=host_spec.name,
                    container_ref=host_spec.name,
                    internal_ip=f"{host_spec.name}.{namespace}.svc.cluster.local",
                    is_front_door=host_spec.front_door,
                )
            )

        self._apply_network_policies(namespace, spec)

        # Wait for every Deployment's pod(s) to actually be Ready -- unlike
        # the Docker backend, the k8s API gives us real readiness signal
        # for every host, not just the front door's published port, so
        # internal-only hosts get the same wait here (a gap the Docker
        # backend still has, see docker_backend.py's own comment).
        for host_spec in spec.hosts:
            self._wait_for_deployment_ready(namespace, host_spec.name)

        if front_door_port is None:
            raise RuntimeError("front-door host did not come up with an expected NodePort")

        entry_host = self._node_public_address()
        # The Deployment/pod being Ready doesn't guarantee kube-proxy's
        # NodePort iptables/ipvs rules have finished propagating yet --
        # same class of race as Docker's userland-proxy accept-then-reset
        # (see docker_backend.py), different mechanism, same symptom.
        # Confirm the published port is actually answering before
        # reporting the instance ready.
        self._wait_for_service(entry_host, front_door_port)

        return ProvisionResult(
            network_name=namespace,
            entry_host=entry_host,
            entry_port=front_door_port,
            hosts=provisioned,
            ports=entry_ports,
        )

    def _ensure_namespace(self, namespace: str) -> None:
        try:
            self._core.read_namespace(namespace)
            return
        except ApiException as e:
            if e.status != 404:
                raise
        self._core.create_namespace(
            k8s_client.V1Namespace(metadata=k8s_client.V1ObjectMeta(name=namespace))
        )

    def _used_node_ports(self) -> set[int]:
        used: set[int] = set()
        for svc in self._core.list_service_for_all_namespaces().items:
            if svc.spec.type != "NodePort":
                continue
            for p in svc.spec.ports or []:
                if p.node_port:
                    used.add(p.node_port)
        return used

    def _allocate_node_port(self, used: set[int]) -> int:
        for port in range(config.K8S_NODE_PORT_POOL_START, config.K8S_NODE_PORT_POOL_END + 1):
            if port not in used:
                used.add(port)
                return port
        raise NodePortAllocationError("no free NodePort in pool")

    def _allocate_host_ports(
        self, host_spec: HostSpec, used_node_ports: set[int]
    ) -> tuple[list[k8s_client.V1ServicePort], dict[str, str]]:
        """Returns the Service ports to create for this host, plus any
        extra env vars needed (pasv range address/min/max, mirroring
        DockerBackend's pattern)."""
        svc_ports: list[k8s_client.V1ServicePort] = []
        env: dict[str, str] = {}

        if not host_spec.front_door:
            # Internal-only hosts get a ClusterIP (no NodePort) for every
            # spec'd port, so the front door (and siblings) can reach them
            # by name within the namespace -- no external exposure at all.
            for p in host_spec.ports:
                svc_ports.append(
                    k8s_client.V1ServicePort(name=f"p{p.container_port}", port=p.container_port,
                                              target_port=p.container_port, protocol=p.protocol.upper())
                )
            return svc_ports, env

        for p in host_spec.ports:
            node_port = self._allocate_node_port(used_node_ports)
            svc_ports.append(
                k8s_client.V1ServicePort(name=f"p{p.container_port}", port=p.container_port,
                                          target_port=p.container_port, protocol=p.protocol.upper(),
                                          node_port=node_port)
            )

        if host_spec.pasv_range:
            size = host_spec.pasv_range.container_max - host_spec.pasv_range.container_min + 1
            # PASV announces a raw port NUMBER with no NAT-aware
            # translation (see docker_backend.py's own note on this) --
            # so container port N must equal NodePort N for every N in
            # the range, which means allocating a contiguous NodePort
            # block and forcing each ServicePort's node_port to match its
            # own container port number exactly, not letting k8s pick.
            range_start = self._allocate_node_port_range(size, used_node_ports)
            for offset in range(size):
                port_num = range_start + offset
                svc_ports.append(
                    k8s_client.V1ServicePort(name=f"pasv{offset}", port=port_num,
                                              target_port=port_num, protocol="TCP",
                                              node_port=port_num)
                )
            env[host_spec.pasv_range.env_min_var] = str(range_start)
            env[host_spec.pasv_range.env_max_var] = str(range_start + size - 1)
            if host_spec.pasv_range.env_address_var:
                env[host_spec.pasv_range.env_address_var] = self._node_public_address()

        return svc_ports, env

    def _allocate_node_port_range(self, size: int, used: set[int]) -> int:
        start = config.K8S_NODE_PORT_POOL_START
        while start + size - 1 <= config.K8S_NODE_PORT_POOL_END:
            candidate = range(start, start + size)
            if all(p not in used for p in candidate):
                used.update(candidate)
                return start
            start += 1
        raise NodePortAllocationError(f"no free contiguous NodePort block of {size} ports in pool")

    def _create_deployment(self, namespace: str, host_spec: HostSpec, team_secret: str,
                            instance: Instance, extra_env: dict[str, str]) -> None:
        env = {"CTF_SECRET": team_secret, **host_spec.extra_env, **extra_env}
        env_list = [k8s_client.V1EnvVar(name=k, value=v) for k, v in env.items()]
        labels = {"app": host_spec.name, "ctf-instance": f"{instance.box_id}-{instance.team_id}"}

        # A real k8s readinessProbe -- the gap this whole function used to
        # have is exactly what let Expert-the-annex's `directory` host
        # (OpenLDAP slapd) go undetected while crash-looping under k8s:
        # supervisord (pid 1) never died even while slapd, its CHILD, kept
        # dying and restarting every few seconds, so the pod's Ready
        # condition -- driven purely by "container process is alive" with
        # no probe at all -- stayed true the entire time. A tcpSocket
        # probe makes "Ready" mean "something is actually accepting
        # connections on this port" instead, for every host (front door
        # included), not just the published NodePort that
        # _wait_for_service already protocol-probes from outside the
        # cluster. This is also why _wait_for_deployment_ready below reads
        # available_replicas (which respects minReadySeconds) rather than
        # ready_replicas (an instantaneous snapshot): a port that flaps
        # up/down every few seconds could otherwise still show
        # ready_replicas>=1 in the exact instant our poll loop happens to
        # sample it, which is precisely the kind of flapping crash loop
        # that bit us.
        #
        # V1Container only accepts a single readiness_probe, so when a
        # host declares more than one port we probe the first declared
        # TCP port -- every current box spec's internal-only hosts (the
        # ones with no other readiness signal at all) declare exactly one
        # port, and multi-port hosts are always the front door, which
        # already gets its own stronger protocol-aware check via
        # _wait_for_service on the externally published port.
        tcp_ports = [p for p in host_spec.ports if p.protocol.lower() == "tcp"]
        readiness_probe = None
        if tcp_ports:
            readiness_probe = k8s_client.V1Probe(
                tcp_socket=k8s_client.V1TCPSocketAction(port=tcp_ports[0].container_port),
                initial_delay_seconds=3,
                period_seconds=3,
                timeout_seconds=3,
                # Generous enough (~9-12s of unbroken failure) to ride out
                # this host's own CPU-contention-induced transient probe
                # delays without flagging a healthy service as not-ready,
                # while still reliably catching a service that crash-loops
                # every few seconds (3 consecutive misses can't land
                # inside a single live window of one of those loops).
                failure_threshold=3,
                success_threshold=1,
            )

        container = k8s_client.V1Container(
            name=host_spec.name,
            image=host_spec.image,
            # Every box image is tagged :latest, for which k8s otherwise
            # defaults image_pull_policy to Always -- that ignores an
            # image already loaded locally (e.g. via `kind load
            # docker-image`) and tries (and, with no registry behind
            # these tags, fails) to pull it from docker.io instead.
            image_pull_policy="IfNotPresent",
            env=env_list,
            ports=[k8s_client.V1ContainerPort(container_port=p.container_port) for p in host_spec.ports],
            readiness_probe=readiness_probe,
        )
        template = k8s_client.V1PodTemplateSpec(
            metadata=k8s_client.V1ObjectMeta(labels=labels),
            spec=k8s_client.V1PodSpec(containers=[container], restart_policy="Always"),
        )
        deployment = k8s_client.V1Deployment(
            metadata=k8s_client.V1ObjectMeta(name=host_spec.name, namespace=namespace, labels=labels),
            spec=k8s_client.V1DeploymentSpec(
                replicas=1,
                selector=k8s_client.V1LabelSelector(match_labels={"app": host_spec.name}),
                template=template,
                # Requires the Ready condition to hold continuously for
                # 10s before a pod counts toward available_replicas --
                # see the readiness_probe comment above for why an
                # instantaneous Ready snapshot isn't trustworthy on its
                # own.
                min_ready_seconds=10,
            ),
        )
        self._apps.create_namespaced_deployment(namespace, deployment)

    def _create_service(self, namespace: str, host_spec: HostSpec,
                         ports: list[k8s_client.V1ServicePort]) -> k8s_client.V1Service:
        # Naming the Service object == host_spec.name (the box's ORIGINAL
        # docker-compose service name, per the box registry) gives every
        # other pod in the namespace DNS resolution for that exact
        # hostname via k8s's built-in cluster DNS, natively -- no
        # equivalent of the Docker backend's manual alias
        # disconnect/reconnect dance needed here.
        spec_kwargs = dict(
            selector={"app": host_spec.name},
            ports=ports,
            type="NodePort" if host_spec.front_door else "ClusterIP",
        )
        if host_spec.front_door:
            # Preserves the real client source IP instead of kube-proxy's
            # default Cluster-policy SNAT -- required for the
            # ipBlock-except-pod-CIDR check in _apply_network_policies to
            # actually distinguish genuine external traffic from another
            # team's pod (which would otherwise look source-IP-identical
            # to real traffic after SNAT). Standard practice for NodePort
            # behind an external LB in production too, not a kind-only
            # workaround.
            spec_kwargs["external_traffic_policy"] = "Local"
        service = k8s_client.V1Service(
            metadata=k8s_client.V1ObjectMeta(name=host_spec.name, namespace=namespace),
            spec=k8s_client.V1ServiceSpec(**spec_kwargs),
        )
        return self._core.create_namespaced_service(namespace, service)

    def _apply_network_policies(self, namespace: str, spec: BoxSpec) -> None:
        front_door = spec.front_door_host
        # k8s has no separate network-topology layer the way Docker has
        # separate bridge networks -- every pod in a namespace already
        # shares one flat pod network, so segmentation (HostSpec's
        # internal_groups) has to be enforced here, at the NetworkPolicy
        # layer, instead. One per-host policy selecting only that host's
        # own pod, allowing Ingress only from the OTHER hosts it shares at
        # least one internal_groups entry with -- for the common case
        # where every host defaults to the same single group "internal",
        # that's every other host, so this reproduces the old blanket
        # "allow-intra-namespace" policy's ANY-pod-to-ANY-pod behavior
        # exactly. Once ANY NetworkPolicy selects a pod for Ingress, that
        # pod's ingress becomes default-deny except what's explicitly
        # allowed across all matching policies -- each host being
        # selected by its own policy here (an empty ingress list for a
        # host with no groupmates) already makes every pod in this
        # namespace default-deny-from-outside, same as before, with no
        # separate explicit deny-all policy needed.
        for host in spec.hosts:
            peers = [
                k8s_client.V1NetworkPolicyPeer(pod_selector=k8s_client.V1LabelSelector(match_labels={"app": other.name}))
                for other in spec.hosts
                if other.name != host.name and set(other.internal_groups) & set(host.internal_groups)
            ]
            group_policy = k8s_client.V1NetworkPolicy(
                metadata=k8s_client.V1ObjectMeta(name=f"allow-group-{host.name}", namespace=namespace),
                spec=k8s_client.V1NetworkPolicySpec(
                    pod_selector=k8s_client.V1LabelSelector(match_labels={"app": host.name}),
                    policy_types=["Ingress"],
                    ingress=[k8s_client.V1NetworkPolicyIngressRule(_from=peers)] if peers else [],
                ),
            )
            self._net.create_namespaced_network_policy(namespace, group_policy)

        # Omitting `from` entirely would mean "allow from literally any
        # source" -- which, combined with every host being the front door
        # on a single-host box, was confirmed (by direct test) to let one
        # team's pod reach another team's pod directly cross-namespace,
        # defeating the entire point of per-instance namespaces. k8s has
        # no native "only traffic that actually arrived via NodePort from
        # outside the cluster" concept, so this uses the standard
        # workaround instead: allow everything EXCEPT the cluster's own
        # pod CIDR. Pod-to-pod traffic's source IP always falls inside
        # that CIDR; genuine external traffic doesn't -- but only because
        # the Service above sets external_traffic_policy=Local, which
        # keeps the real client IP instead of letting kube-proxy SNAT it
        # to something that could land back inside the excluded range.
        allow_external = k8s_client.V1NetworkPolicy(
            metadata=k8s_client.V1ObjectMeta(name="allow-front-door-external", namespace=namespace),
            spec=k8s_client.V1NetworkPolicySpec(
                pod_selector=k8s_client.V1LabelSelector(match_labels={"app": front_door.name}),
                policy_types=["Ingress"],
                ingress=[
                    k8s_client.V1NetworkPolicyIngressRule(
                        _from=[
                            k8s_client.V1NetworkPolicyPeer(ip_block=_pod_cidr_exclusion_block())
                        ],
                        ports=[
                            k8s_client.V1NetworkPolicyPort(protocol=p.protocol.upper(), port=p.container_port)
                            for p in front_door.ports
                        ]
                    )
                ],
            ),
        )
        self._net.create_namespaced_network_policy(namespace, allow_external)

    def _wait_for_deployment_ready(self, namespace: str, name: str, timeout_seconds: float = 120.0) -> None:
        """Waits for available_replicas >= 1, NOT ready_replicas.
        ready_replicas is an instantaneous snapshot of the Pod's Ready
        condition -- a service that's crash-looping every few seconds
        (see _create_deployment's readiness_probe comment for the real
        incident this is about) can still show ready_replicas>=1 at the
        exact moment this loop happens to poll it. available_replicas only
        counts a pod once its Ready condition has held continuously for
        the Deployment's min_ready_seconds, which is what actually rules
        out that class of flapping false-positive. Combined with the
        tcpSocket readinessProbe added to every host's container, this is
        real service-level verification -- not just "the process is
        alive" -- for every host in the box, internal-only hosts included,
        not just the front door's own externally-probed NodePort."""
        deadline = time.monotonic() + timeout_seconds
        last_status = None
        while time.monotonic() < deadline:
            dep = self._apps.read_namespaced_deployment(name, namespace)
            last_status = dep.status
            if dep.status.available_replicas and dep.status.available_replicas >= 1:
                return
            time.sleep(1)
        raise RuntimeError(f"deployment {namespace}/{name} never became ready within {timeout_seconds}s ({last_status})")

    def _wait_for_service(self, host: str, port: int, timeout_seconds: float = 90.0) -> None:
        """Same protocol-agnostic probe as DockerBackend's
        _wait_for_service (see its own docstring for the full
        rationale) -- reused here verbatim since NodePort's readiness
        race is the same class of problem, just a different proxy
        layer (kube-proxy instead of Docker's userland-proxy)."""
        deadline = time.monotonic() + timeout_seconds
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            try:
                with socket.create_connection((host, port), timeout=1.0) as s:
                    s.settimeout(1.0)
                    try:
                        data = s.recv(16)
                        if data:
                            return
                        last_error = RuntimeError("connection closed with no data")
                        time.sleep(0.5)
                        continue
                    except TimeoutError:
                        pass

                    s.sendall(f"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
                    data = s.recv(16)
                    if data:
                        return
                    last_error = RuntimeError("connection accepted but no response to probe")
            except OSError as e:
                last_error = e
            time.sleep(0.5)
        raise RuntimeError(f"port {host}:{port} never produced a real response within {timeout_seconds}s ({last_error})")

    def _node_public_address(self) -> str:
        if config.K8S_NODE_PUBLIC_ADDRESS:
            return config.K8S_NODE_PUBLIC_ADDRESS
        if self._node_address_cache:
            return self._node_address_cache
        nodes = self._core.list_node().items
        if not nodes:
            raise RuntimeError("no nodes found in cluster")
        addrs = {a.type: a.address for a in nodes[0].status.addresses}
        address = addrs.get("ExternalIP") or addrs.get("InternalIP")
        if not address:
            raise RuntimeError(f"node {nodes[0].metadata.name} has no usable address: {addrs}")
        self._node_address_cache = address
        return address

    # ---- status ----------------------------------------------------------

    async def status(self, instance: Instance) -> str:
        return await asyncio.to_thread(self._status_sync, instance)

    def _status_sync(self, instance: Instance) -> str:
        try:
            ns = self._core.read_namespace(instance.network_name)
        except ApiException as e:
            if e.status == 404:
                return "destroyed"
            raise
        if ns.status.phase == "Terminating":
            return "destroyed"
        try:
            deployments = self._apps.list_namespaced_deployment(instance.network_name).items
        except ApiException as e:
            if e.status == 404:
                return "destroyed"
            raise
        # available_replicas, not ready_replicas -- same reasoning as
        # _wait_for_deployment_ready: ready_replicas is an instantaneous
        # snapshot that a flapping/crash-looping service can still
        # satisfy, available_replicas requires the Ready condition (now
        # backed by each container's tcpSocket readinessProbe) to have
        # held for min_ready_seconds.
        healthy = all((d.status.available_replicas or 0) >= 1 for d in deployments)
        return "running" if healthy else "error"

    # ---- destroy -----------------------------------------------------------

    async def destroy(self, instance: Instance) -> None:
        await asyncio.to_thread(self._destroy_sync, instance)

    def _destroy_sync(self, instance: Instance, timeout_seconds: float = 180.0) -> None:
        # Namespace-per-instance means destroy is just deleting the
        # namespace -- k8s garbage-collects every Deployment/Pod/Service/
        # NetworkPolicy inside it automatically, mirroring how the Docker
        # backend removes every container then both networks explicitly
        # (there, nothing does that cleanup for it).
        try:
            self._core.delete_namespace(instance.network_name)
        except ApiException as e:
            if e.status != 404:
                raise
            return

        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            try:
                self._core.read_namespace(instance.network_name)
            except ApiException as e:
                if e.status == 404:
                    return
                raise
            time.sleep(1)
        raise RuntimeError(f"namespace {instance.network_name} did not finish terminating within {timeout_seconds}s")
