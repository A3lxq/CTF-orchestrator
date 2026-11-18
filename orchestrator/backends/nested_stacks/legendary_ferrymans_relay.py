"""Nested bring-up for legendary-ferrymans-relay inside its per-instance
outer dind container (see docker_backend.py's _provision_nested_docker_sync
and registry.py's NestedDockerSpec for why this box runs this way at all).

This replays the box's original docker-compose.yml topology
(boxes-src/legendary-ferrymans-relay/docker-compose.yml) as a plain ordered
sequence of `docker` commands run via `exec_run` inside the outer
container, rather than installing/invoking `docker compose` in there --
the dind images don't ship the compose plugin by default, and for one
bespoke 4-container bring-up a short explicit command list has fewer
moving parts than ensuring compose is present and version-compatible
inside a fresh disposable daemon every single time.

Two literal names are player-facing (confirmed via the box's own
writeup) and MUST survive exactly as the original compose file defined
them: the container name `halcyon-legendary-web` (flag 8's `docker exec`
target) and the volume name `halcyon-legendary-host-secrets` (flags
9-10's `docker run -v` target). `relay-client` connects to hostname
`relay` specifically (the compose *service* name, not the container
name) -- every nested container below gets an explicit `--network-alias`
matching its own original compose service name for exactly this reason,
the same lesson docker_backend.py's own _start_host already learned once
for the top-level case.
"""


def bring_up(container, team_secret: str, images: dict[str, str]) -> None:
    """images maps this box's HostSpec names ("web"/"relay"/"vault") to
    their already-preloaded image tags -- sourced from the box's own YAML
    spec by the caller (docker_backend.py), not hardcoded here, so the
    image name used to preload and the image name used to `docker run`
    can never drift out of sync with each other."""

    def ex(cmd: list[str]) -> None:
        exit_code, output = container.exec_run(cmd, environment={"CTF_SECRET": team_secret})
        if exit_code != 0:
            raise RuntimeError(
                f"legendary-ferrymans-relay nested bring-up step failed "
                f"({cmd}): {output.decode(errors='replace')}"
            )

    ex(["docker", "network", "create", "public-net"])
    ex(["docker", "network", "create", "--internal", "internal-net"])
    ex(["docker", "volume", "create", "shared-vol"])
    ex(["docker", "volume", "create", "halcyon-legendary-host-secrets"])

    # web: front door, both of its original compose ports (5000 Flask,
    # 22 sshd). --network-alias web added defensively for consistency with
    # relay/vault below, even though nothing currently resolves it by that
    # hostname.
    ex(
        [
            "docker", "run", "-d", "--name", "halcyon-legendary-web",
            "--network", "public-net", "--network-alias", "web",
            "-p", "5000:5000", "-p", "22:22",
            "-e", f"CTF_SECRET={team_secret}", images["web"],
        ]
    )
    ex(["docker", "network", "connect", "--alias", "web", "internal-net", "halcyon-legendary-web"])

    # relay: internal-only. --network-alias relay is REQUIRED, not
    # defensive -- relay-client (run from web's SSH session) connects to
    # hostname "relay", which Docker's embedded DNS does NOT resolve to
    # this container just because its --name happens to be different.
    ex(
        [
            "docker", "run", "-d", "--name", "halcyon-legendary-relay",
            "--network", "internal-net", "--network-alias", "relay",
            "-v", "shared-vol:/shared",
            "-e", f"CTF_SECRET={team_secret}", images["relay"],
        ]
    )

    # vault: internal-only. The docker.sock mount here refers to THIS
    # nested daemon's own socket (this command runs inside the outer
    # container's own mount namespace) -- it never leaves this one team's
    # disposable outer container, unlike the box's native (VM) deployment
    # where this same line would be the real host's socket.
    ex(
        [
            "docker", "run", "-d", "--name", "halcyon-legendary-vault",
            "--network", "internal-net", "--network-alias", "vault",
            "-v", "shared-vol:/shared",
            "-v", "/var/run/docker.sock:/var/run/docker.sock",
            "-e", f"CTF_SECRET={team_secret}", images["vault"],
        ]
    )

    # init: one-shot, reuses vault's image with a different entrypoint,
    # exactly like the original compose file's restart:"no" service.
    # exec_run blocks until this nested `docker run` itself exits -- that
    # IS the "run to completion, then never again" semantics needed here.
    ex(
        [
            "docker", "run", "--rm", "--name", "halcyon-legendary-init",
            "--network", "internal-net",
            "--entrypoint", "/opt/init_hostsecrets.sh",
            "-v", "halcyon-legendary-host-secrets:/hostsecrets",
            "-e", f"CTF_SECRET={team_secret}", images["vault"],
        ]
    )
