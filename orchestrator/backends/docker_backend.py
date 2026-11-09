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
            if network_name in net_settings:
                internal_ip = net_settings[network_name].get("IPAddress")
            elif internal_network_name in net_settings:
                internal_ip = net_settings[internal_network_name].get("IPAddress")

            provisioned.append(
                ProvisionedHost(
                    service_name=host_spec.name,
                    container_ref=container.id,
                    internal_ip=internal_ip,
                    is_front_door=host_spec.front_door,
                )
            )

            if host_spec.front_door:
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
        # "succeed" well before the real service is actually up (hit this
        # exact race: the test's HTTP GET got a connection reset even
        # though a prior TCP connect had already reported success). For
        # port 80, do a real HTTP probe instead; other ports fall back to
        # TCP connect, which is still an improvement over no wait at all.
        for port_num, container_port in front_door_all_host_ports:
            if container_port == 80:
                self._wait_for_http(config.DOCKER_HOST_PUBLIC_ADDRESS, port_num)
            else:
                self._wait_for_port(config.DOCKER_HOST_PUBLIC_ADDRESS, port_num)

        return ProvisionResult(
            network_name=network_name,
            entry_host=config.DOCKER_HOST_PUBLIC_ADDRESS,
            entry_port=front_door_host_port,
            hosts=provisioned,
        )

    def _wait_for_port(self, host: str, port: int, timeout_seconds: float = 30.0) -> None:
        deadline = time.monotonic() + timeout_seconds
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            try:
                with socket.create_connection((host, port), timeout=1.0):
                    return
            except OSError as e:
                last_error = e
                time.sleep(0.5)
        raise RuntimeError(f"front-door port {host}:{port} never accepted a connection within {timeout_seconds}s ({last_error})")

    def _wait_for_http(self, host: str, port: int, timeout_seconds: float = 30.0) -> None:
        deadline = time.monotonic() + timeout_seconds
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            try:
                with socket.create_connection((host, port), timeout=1.0) as s:
                    s.sendall(f"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
                    s.settimeout(1.0)
                    data = s.recv(16)
                    if data.startswith(b"HTTP/"):
                        return
                    last_error = RuntimeError(f"unexpected response start: {data!r}")
            except OSError as e:
                last_error = e
            time.sleep(0.5)
        raise RuntimeError(f"http port {host}:{port} never returned a valid response within {timeout_seconds}s ({last_error})")

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

        container = self._client.containers.create(
            image=host_spec.image,
            name=container_name,
            environment=env,
            ports=ports if host_spec.front_door else None,
            network=pub_network.name if host_spec.front_door else (int_network.name if int_network else pub_network.name),
            detach=True,
        )
        # Multi-host boxes: connect every host to the internal network too
        # (front-door hosts need BOTH the published network and the
        # internal one, since they're the pivot point into internal-only
        # services -- mirrors the original compose files' frontdesk/gateway
        # services being members of both public-net and internal-net).
        if int_network and host_spec.front_door:
            int_network.connect(container)
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
