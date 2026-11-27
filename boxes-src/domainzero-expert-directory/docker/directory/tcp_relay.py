#!/usr/bin/env python3
"""Minimal, protocol-unaware TCP relay: LISTEN_PORT on this host ->
TARGET_HOST:TARGET_PORT.

Why this exists: "search-intranet" is internal-only (never published by
the orchestrator spec -- see this box's spec YAML and master-two-offices'
own precedent), reachable only from "directory" over this instance's
shared internal network group. A real external player only ever has the
orchestrator's public address plus whatever ports "directory" (the front
door) actually publishes -- they have no route to the internal bridge
network at all. Without this relay, flags 3-4 (recon + the NoSQL
operator-injection auth bypass on search-intranet's /login) would be
unreachable over the box's own published surface, breaking the
"solvable end-to-end over published ports alone" invariant every other
box in this project relies on.

This is a plain two-thread-per-connection socket splice -- no HTTP
awareness, no TLS termination, nothing box-specific baked in. It just
forwards raw bytes both ways, so search-intranet's own HTTP responses
(status codes, JSON bodies, etc.) reach the player completely unchanged.
stdlib only (socket + threading) -- no extra pip dependency needed on
top of what "directory"'s own Dockerfile already installs (python3).
"""
import socket
import threading

LISTEN_PORT = 8080
TARGET_HOST = "search-intranet"
TARGET_PORT = 5000


def _pipe(src: socket.socket, dst: socket.socket) -> None:
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


def _handle(client: socket.socket) -> None:
    try:
        upstream = socket.create_connection((TARGET_HOST, TARGET_PORT), timeout=10)
    except OSError:
        client.close()
        return
    t1 = threading.Thread(target=_pipe, args=(client, upstream), daemon=True)
    t2 = threading.Thread(target=_pipe, args=(upstream, client), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    client.close()
    upstream.close()


def main() -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", LISTEN_PORT))
    server.listen(50)
    while True:
        client, _addr = server.accept()
        threading.Thread(target=_handle, args=(client,), daemon=True).start()


if __name__ == "__main__":
    main()
