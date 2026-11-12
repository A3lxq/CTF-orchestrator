import asyncio
import socket
import time

import docker
from docker.errors import NotFound

from .. import config
from ..boxes.registry import BoxSpec, HostSpec
from ..models import Instance
from .base import ProvisionedHost, ProvisionResult, RuntimeBackend

# Docker API calls are blocking (the docker-py SDK is sync-only); every
# call into the client below is wrapped in asyncio.to_thread so the async
# FastAPI event loop isn't blocked waiting on the Docker daemon.


class PortAllocationError(RuntimeError):
    pass


class DockerBackend(RuntimeBackend):
    name = "docker"

    def __init__(self):
        self._client = docker.from_env()
        self._alloc_lock = asyncio.Lock()

    def _used_host_ports(self) -> set[int]:
        """Ports currently bound by ANY container on this host, derived
        from live Docker state rather than in-memory bookkeeping, so this
        stays correct across orchestrator restarts."""
        used: set[int] = set()
        for container in self._client.containers.list(all=True):
            ports = container.attrs.get("NetworkSettings", {}).get("Ports") or {}
            for bindings in ports.values():
                if not bindings:
                    continue
                for binding in bindings:
                    host_port = binding.get("HostPort")
                    if host_port:
                        used.add(int(host_port))
        return used

    def _port_is_free(self, port: int, used: set[int]) -> bool:
        if port in used:
            return False
        # Belt-and-suspenders: also confirm nothing non-Docker is squatting
        # on it (e.g. a leftover process from a crashed instance).
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("0.0.0.0", port))
                return True
            except OSError:
                return False

    def _allocate_single_port(self, used: set[int]) -> int:
        for port in range(config.PORT_POOL_START, config.PORT_POOL_END + 1):
            if self._port_is_free(port, used):
                used.add(port)
                return port
        raise PortAllocationError("no free port in pool")

    def _allocate_port_range(self, size: int, used: set[int]) -> tuple[int, int]:
        start = config.PORT_POOL_START
        while start + size - 1 <= config.PORT_POOL_END:
            candidate = range(start, start + size)
            if all(self._port_is_free(p, used) for p in candidate):
                used.update(candidate)
                return start, start + size - 1
            start += 1
        raise PortAllocationError(f"no free contiguous block of {size} ports in pool")

    async def provision(self, instance: Instance, spec: BoxSpec, team_secret: str) -> ProvisionResult:
        return await asyncio.to_thread(self._provision_sync, instance, spec, team_secret)

    def _provision_sync(self, instance: Instance, spec: BoxSpec, team_secret: str) -> ProvisionResult:
        network_name = f"ctf-{spec.box_id}-{instance.team_id}"
        internal_network_name = f"{network_name}-internal"

        pub_network = self._get_or_create_network(network_name)
        int_network = self._get_or_create_network(internal_network_name, internal=True) if spec.is_multi_host else None

        used_ports = self._used_host_ports()
        provisioned: list[ProvisionedHost] = []
        front_door_host_port: int | None = None
        front_door_all_host_ports: list[int] = []
        front_door_container = None
        internal_wait_targets: list[tuple[str, int]] = []

        for host_spec in spec.hosts:
            container = self._start_host(
                instance=instance,
                host_spec=host_spec,
                team_secret=team_secret,
                pub_network=pub_network,
                int_network=int_network,
                used_ports=used_ports,
            )
            container.reload()
            internal_ip = None
            net_settings = container.attrs.get("NetworkSettings", {}).get("Networks", {})
            # Multi-host boxes give the front-door host membership in BOTH
            # networks (see _start_host's comment) -- report the INTERNAL
            # network's IP here, since that's the address siblings (and
            # any future consumer of this field) would actually use to
            # reach it, not the public-facing one. Single-host boxes have
            # no internal network at all (int_network is None), so there
            # the public network's IP is the only one there is.
            if int_network is not None and internal_network_name in net_settings:
                internal_ip = net_settings[internal_network_name].get("IPAddress")
            elif network_name in net_settings:
                internal_ip = net_settings[network_name].get("IPAddress")

            provisioned.append(
                ProvisionedHost(
                    service_name=host_spec.name,
                    container_ref=container.id,
                    internal_ip=internal_ip,
                    is_front_door=host_spec.front_door,
                )
            )

            if host_spec.front_door:
                front_door_container = container
                ports = container.attrs.get("NetworkSettings", {}).get("Ports") or {}
                # Prefer port 80 (HTTP) as "the" single entry port shown to
                # callers/GZCTF when present -- it's the most meaningful
                # first point of contact for a player -- falling back to
                # the first spec'd port otherwise. Every published port is
                # still returned via `hosts`/hostports and tracked for the
                # readiness wait below, since boxes like this one need
                # SSH/FTP reachable too, not just the "entry" one.
                preferred_order = sorted(host_spec.ports, key=lambda p: p.container_port != 80)
                for p in preferred_order:
                    bindings = ports.get(f"{p.container_port}/{p.protocol}")
                    if bindings:
                        port_num = int(bindings[0]["HostPort"])
                        front_door_all_host_ports.append((port_num, p.container_port))
                        if front_door_host_port is None:
                            front_door_host_port = port_num
            else:
                # Internal-only host: no published port to probe from the
                # orchestrator host side, so remember it (name == its
                # network alias, per _start_host) to be probed below via
                # the front door, once every container has been started.
                for p in host_spec.ports:
                    internal_wait_targets.append((host_spec.name, p.container_port))

        if front_door_host_port is None:
            raise RuntimeError("front-door host did not come up with an expected published port")

        # The container process starting isn't the same as the service(s)
        # inside it (nginx/sshd/vsftpd via supervisord) actually accepting
        # connections yet -- wait for EVERY published front-door port to
        # answer before reporting this instance as ready, so callers never
        # get a "running" instance where some service hasn't finished
        # starting. A plain TCP connect isn't a reliable readiness signal
        # here: Docker's userland proxy accepts the handshake immediately
        # once the container exists, then resets the connection if it
        # can't reach a listener inside yet -- so a bare connect() can
        # "succeed" well before the real service is actually up. This bit
        # a non-80 HTTP front door (Intermediate's Flask app on 5000):
        # connect() succeeded but the follow-up GET got a connection
        # reset. Probe every port the same, protocol-agnostic way instead
        # of special-casing port 80.
        for port_num, _container_port in front_door_all_host_ports:
            self._wait_for_service(config.DOCKER_HOST_PUBLIC_ADDRESS, port_num)

        # Internal-only hosts (Master's backoffice, Expert's
        # directory/fileserver, God's waystation/vault, ...) have no
        # published port at all, so they never went through the wait
        # above -- without this they'd be reported "running" the instant
        # their container object exists, with no confirmation the service
        # inside has actually finished starting (e.g. real slapd on
        # Expert's directory host). Mirrors the Kubernetes backend's
        # _provision_sync, which waits on every HostSpec via
        # _wait_for_deployment_ready, not just the front door's.
        if internal_wait_targets:
            assert front_door_container is not None, "internal-only hosts require a front-door host in the spec"
            for host, port in internal_wait_targets:
                self._wait_for_internal_service(front_door_container, host, port)

        return ProvisionResult(
            network_name=network_name,
            entry_host=config.DOCKER_HOST_PUBLIC_ADDRESS,
            entry_port=front_door_host_port,
            hosts=provisioned,
        )

    def _wait_for_service(self, host: str, port: int, timeout_seconds: float = 30.0) -> None:
        """Protocol-agnostic readiness probe, for a host-reachable
        (published) port -- the front door's own ports, probed directly
        from the orchestrator host. See _retry_probe for the shared
        retry loop and _tcp_probe_attempt for the shared per-attempt
        banner-or-GET decision tree this and _wait_for_internal_service
        both rely on."""
        self._retry_probe(
            lambda: self._tcp_probe_attempt(host, port),
            timeout_seconds,
            f"port {host}:{port}",
        )

    def _wait_for_internal_service(
        self, front_door_container, host: str, port: int, timeout_seconds: float = 30.0
    ) -> None:
        """Readiness probe for an internal-only host, which has no
        published port reachable from the orchestrator host at all --
        instead this runs the probe via `docker exec` inside the
        front-door container, which is already a confirmed member of
        the internal network (see _start_host) and can resolve `host`
        by its network alias. Uses the same retry loop (_retry_probe)
        as _wait_for_service, but NOT the same per-attempt banner-or-GET
        probe -- see _exec_probe_attempt's own comment for why a plain
        connect() is the right (and, for a protocol like raw LDAP, the
        only correct) signal here, unlike for a published front-door
        port."""
        self._retry_probe(
            lambda: self._exec_probe_attempt(front_door_container, host, port),
            timeout_seconds,
            f"internal host {host}:{port} (probed via front-door container exec)",
        )

    def _retry_probe(self, probe_once, timeout_seconds: float, description: str) -> None:
        """Shared retry loop: call probe_once() (a single readiness
        attempt, True meaning "got a real response") repeatedly until it
        succeeds or timeout_seconds elapses. Used by both
        _wait_for_service (direct host-side TCP probe) and
        _wait_for_internal_service (docker-exec-based probe from inside
        the front door) -- only the single-attempt probe differs between
        the two; the wait/retry policy is identical."""
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            if probe_once():
                return
            time.sleep(0.5)
        raise RuntimeError(f"{description} never produced a real response within {timeout_seconds}s")

    def _tcp_probe_attempt(self, host: str, port: int) -> bool:
        """Single readiness-probe attempt via a direct host-side TCP
        connection. A plain TCP connect() is not enough (see
        _wait_for_service's call site in _provision_sync for the race
        this guards against): this requires an actual response from the
        listener behind the connection -- either a server-first banner
        (SSH/FTP send one unprompted) or, if nothing arrives unprompted,
        a reply to a generic HTTP GET. A reset while waiting for either,
        or no response from either probe, means this attempt was not
        ready (caller retries)."""
        try:
            with socket.create_connection((host, port), timeout=1.0) as s:
                s.settimeout(1.0)
                try:
                    data = s.recv(16)
                    if data:
                        return True
                    return False  # connection closed with no data
                except TimeoutError:
                    pass  # no server-first banner -- try an HTTP probe below

                s.sendall(f"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
                data = s.recv(16)
                return bool(data)
        except OSError:
            return False

    # _tcp_probe_attempt's banner-or-GET dance exists ONLY because of
    # Docker's userland-proxy, which sits in front of a *published* host
    # port and accepts the TCP handshake immediately on the host side
    # even before anything inside the container is listening yet, then
    # resets once it tries (and fails) to reach a real listener -- so a
    # bare connect() against a published port can "succeed" well before
    # the real service is up (see _wait_for_service's own docstring).
    # Internal-only hosts have no published port and no userland-proxy
    # in the path at all: this exec's connection is a plain
    # container-to-container hop over the bridge network straight to
    # the target container's own kernel socket, so a successful
    # connect() here already means a real listener accepted it -- no
    # NAT/proxy layer to be fooled by. Trying to layer the SAME
    # banner-or-GET heuristic on top here was tried and is actively
    # wrong, not just unnecessary: confirmed by direct reproduction
    # against Expert's `directory` host, real OpenLDAP slapd on 389,
    # which never sends an unprompted banner and silently ignores (or
    # drops the connection on) a garbage HTTP GET -- so that version of
    # this probe timed out on every attempt forever, even once slapd was
    # genuinely up and accepting connections, misreporting a perfectly
    # healthy service as never-ready. `timeout 5` wraps the whole script
    # as a last-resort guard in case /dev/tcp's connect itself blocks
    # instead of being refused immediately (not expected on a Docker
    # bridge network, but cheap insurance).
    _EXEC_PROBE_SCRIPT = r"""
host="$1"; port="$2"
exec 3<>"/dev/tcp/${host}/${port}" 2>/dev/null && exit 0
exit 1
"""

    def _exec_probe_attempt(self, front_door_container, host: str, port: int) -> bool:
        exit_code, _output = front_door_container.exec_run(
            ["timeout", "5", "bash", "-c", self._EXEC_PROBE_SCRIPT, "probe", host, str(port)],
            demux=False,
        )
        return exit_code == 0

    def _get_or_create_network(self, name: str, internal: bool = False):
        try:
            return self._client.networks.get(name)
        except NotFound:
            return self._client.networks.create(name, driver="bridge", internal=internal)

    def _start_host(self, instance, host_spec: HostSpec, team_secret: str, pub_network, int_network, used_ports: set[int]):
        env = {"CTF_SECRET": team_secret, **host_spec.extra_env}
        ports: dict[str, int] = {}

        if host_spec.front_door:
            for p in host_spec.ports:
                host_port = self._allocate_single_port(used_ports)
                ports[f"{p.container_port}/{p.protocol}"] = host_port
                # The first port in the spec's list is treated as "the"
                # entry port by the caller (_provision_sync reads it back
                # off the container's own port bindings after start).

            if host_spec.pasv_range:
                size = host_spec.pasv_range.container_max - host_spec.pasv_range.container_min + 1
                range_start, range_end = self._allocate_port_range(size, used_ports)
                for offset in range(size):
                    ports[f"{range_start + offset}/tcp"] = range_start + offset
                env[host_spec.pasv_range.env_min_var] = str(range_start)
                env[host_spec.pasv_range.env_max_var] = str(range_end)
                if host_spec.pasv_range.env_address_var:
                    env[host_spec.pasv_range.env_address_var] = config.DOCKER_HOST_PUBLIC_ADDRESS
                # vsftpd needs its OWN internal listen range to match the
                # host-mapped numbers 1:1 (passive mode announces a raw
                # port number to the client with no NAT-aware translation),
                # so container_port == host_port for every pasv port here.

        container_name = f"ctf-{instance.box_id}-{instance.team_id}-{host_spec.name}"[:63]
        # Remove any stale container left behind from a previous failed run.
        try:
            stale = self._client.containers.get(container_name)
            stale.remove(force=True)
        except NotFound:
            pass

        primary_network = pub_network if host_spec.front_door else (int_network or pub_network)

        container = self._client.containers.create(
            image=host_spec.image,
            name=container_name,
            environment=env,
            ports=ports if host_spec.front_door else None,
            network=primary_network.name,
            detach=True,
        )
        # Several multi-host boxes' own intended solve path has the
        # player, after pivoting in via the front door, type the box's
        # ORIGINAL docker-compose service name as a literal hostname from
        # an internal shell (e.g. `curl http://backoffice:6000/`,
        # `ssh ops@fileserver`, `ssh traveler@vault`) -- this is baked
        # into each box's own writeup, not something settable via an env
        # var, so every network membership needs a DNS alias equal to
        # host_spec.name (which is set to match the original compose
        # service name in every box spec), not just the orchestrator's
        # own ctf-<box_id>-<team_id>-<service> container name. The
        # high-level create() API has no alias parameter, so connect
        # once without one, then disconnect/reconnect with the alias --
        # safe to do before start(): Docker's published-port NAT setup
        # reads the container's network config at `start()` time, not at
        # `create()` time, confirmed by direct test.
        primary_network.disconnect(container)
        primary_network.connect(container, aliases=[host_spec.name])

        # Multi-host boxes: connect every host to the internal network too
        # (front-door hosts need BOTH the published network and the
        # internal one, since they're the pivot point into internal-only
        # services -- mirrors the original compose files' frontdesk/gateway
        # services being members of both public-net and internal-net).
        if int_network and host_spec.front_door:
            int_network.connect(container, aliases=[host_spec.name])
        # Internal-only hosts were created with network=int_network.name
        # above and never joined to pub_network at all -- "no published
        # ports, no route except via the front door" is simply never
        # giving them a second network, matching the original compose
        # design's internal-only services exactly.

        container.start()
        return container

    async def status(self, instance: Instance) -> str:
        return await asyncio.to_thread(self._status_sync, instance)

    def _status_sync(self, instance: Instance) -> str:
        try:
            healthy = True
            for host in instance.hosts:
                c = self._client.containers.get(host.container_ref)
                if c.status != "running":
                    healthy = False
            return "running" if healthy else "error"
        except NotFound:
            return "destroyed"

    async def destroy(self, instance: Instance) -> None:
        await asyncio.to_thread(self._destroy_sync, instance)

    def _destroy_sync(self, instance: Instance) -> None:
        for host in instance.hosts:
            try:
                c = self._client.containers.get(host.container_ref)
                c.remove(force=True)
            except NotFound:
                pass
        for net_name in (instance.network_name, f"{instance.network_name}-internal"):
            try:
                net = self._client.networks.get(net_name)
                net.remove()
            except NotFound:
                pass
            except docker.errors.APIError:
                pass
