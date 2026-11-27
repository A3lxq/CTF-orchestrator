#!/usr/bin/env python3
"""
Minimal raw TCP relay/bastion forwarder, run alongside Samba on
frontdesk.

DESIGN FIX, DOCUMENTED: `backoffice` has no published port at all under
either backend (DockerBackend never publishes ports for a non-front-door
host; KubernetesBackend only gives it a ClusterIP) -- so without this
relay, a real external player who steals the pass-the-hash credential
via backoffice's GraphQL API, or who then SSHes in as boadmin, would
have NO actual network path to backoffice -- only frontdesk (the front
door) is reachable from outside. That breaks this project's core
invariant that every box must be completable end-to-end over its own
published ports, nothing else.

frontdesk -- the only host in this box with published ports -- therefore
runs this tiny protocol-unaware byte relay for both internal services a
player needs to reach: SSH (backoffice:22, surfaced on frontdesk:2222)
and the GraphQL API (backoffice:4000, surfaced on frontdesk:4000 too,
same port number for simplicity). This is exactly the real-world
"bastion/jump host forwarding to an internal host" pattern AD
environments actually use (an RDS Gateway, `ssh -J`, a reverse proxy in
front of an internal app) -- each relay pair just splices two TCP
streams verbatim, with zero awareness of SSH, HTTP, or anything else
riding on top of them.
"""
import socket
import sys
import threading

# (listen_port, target_host, target_port)
RELAYS = [
    (2222, "backoffice", 22),
    (4000, "backoffice", 4000),
]


def _pump(src: socket.socket, dst: socket.socket) -> None:
    try:
        while True:
            data = src.recv(4096)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def _handle(conn: socket.socket, target_host: str, target_port: int) -> None:
    try:
        upstream = socket.create_connection((target_host, target_port), timeout=10)
    except OSError as e:
        print(f"[tcp_relay] could not reach {target_host}:{target_port}: {e}", file=sys.stderr, flush=True)
        conn.close()
        return
    t1 = threading.Thread(target=_pump, args=(conn, upstream), daemon=True)
    t2 = threading.Thread(target=_pump, args=(upstream, conn), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    conn.close()
    upstream.close()


def _serve(listen_port: int, target_host: str, target_port: int) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", listen_port))
    srv.listen(50)
    print(f"[tcp_relay] listening on {listen_port} -> {target_host}:{target_port}", file=sys.stderr, flush=True)
    while True:
        conn, _addr = srv.accept()
        threading.Thread(target=_handle, args=(conn, target_host, target_port), daemon=True).start()


if __name__ == "__main__":
    threads = []
    for listen_port, target_host, target_port in RELAYS:
        t = threading.Thread(target=_serve, args=(listen_port, target_host, target_port), daemon=False)
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
