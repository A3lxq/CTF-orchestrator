"""
frontproxy -- Nimbus Freight's public edge gateway. Port 80 (published).

DELIBERATELY NAIVE, hand-rolled Python TCP proxy (raw `socket` module, no
WSGI framework -- a real framework/WSGI server normalizes/rejects
ambiguous framing long before app code ever sees it, which is exactly the
behavior that makes genuine request smuggling hard to reproduce against
it). This is the textbook front-end half of a classic CL.TE desync:

  - It determines request body length PURELY from the Content-Length
    header. Any Transfer-Encoding header on the inbound request is read
    only so it can be forwarded verbatim -- it is NEVER consulted to
    decide how many body bytes to read here. That's the front-end's "CL"
    behavior.
  - It reads exactly Content-Length bytes of body, then forwards the
    request line + headers + that exact body to the backend (admin-api)
    over a single persistent, reused TCP connection shared by every
    request this proxy ever forwards.
  - It enforces exactly one application rule, checked BEFORE anything is
    forwarded: any request whose path starts with "/admin/" gets an
    immediate 403, never reaching admin-api at all. That's the control
    the smuggling attack exists to bypass.
  - After forwarding, it reads exactly one HTTP response back from the
    backend's persistent connection and relays it to the client, then
    leaves that backend connection open for the next request to reuse.

That last point is the actual bug: if a smuggled "request" hidden inside
one request's body gets treated by the backend as its OWN separate
pipelined request on that same reused connection, admin-api will queue a
SECOND response behind the first one. This proxy's "read exactly one
response, then move on" logic has no idea that happened -- the next
thing it forwards will get that stale, smuggled response handed back
instead of its own. That's the desync.

This host is the box's ONLY published front door -- admin-api never
gets a published port of its own on purpose. So frontproxy also runs a
second, completely separate listener on port 2222: a dumb, blind
bidirectional TCP relay/passthrough to admin-api:22, no protocol
awareness at all (same spirit as a bastion host forwarding SSH to an
internal box). This is what makes the SSH foothold (once a player has
stolen the ops credential via the smuggling chain above) actually
reachable by a real external player hitting only this box's published
ports -- not a shortcut, just the standard jump-host pattern.
"""
import os
import socket
import sys
import threading

sys.path.insert(0, "/opt/shared")
from generate_flags import flag_for  # noqa: E402

SECRET = os.environ["CTF_SECRET"]
LISTEN_PORT = 80
BACKEND_HOST = "admin-api"
BACKEND_PORT = 8000

# Blind SSH relay -- published alongside port 80 so a real external
# player can actually reach admin-api's sshd, the same way a bastion
# host forwards SSH to an internal box. See module docstring.
RELAY_LISTEN_PORT = 2222
RELAY_BACKEND_HOST = "admin-api"
RELAY_BACKEND_PORT = 22

# One single persistent connection to the backend, reused by every
# request this proxy ever forwards -- never one-connection-per-request.
# This is what makes a smuggled request's hidden response actually able
# to leak into a LATER, unrelated client's reply.
_backend_lock = threading.Lock()
_backend_sock = None
_backend_rfile = None


def flag(n):
    return flag_for(SECRET, n)


def _get_backend():
    global _backend_sock, _backend_rfile
    if _backend_sock is None:
        _backend_sock = socket.create_connection((BACKEND_HOST, BACKEND_PORT))
        _backend_rfile = _backend_sock.makefile("rb")
    return _backend_sock, _backend_rfile


def _reset_backend():
    global _backend_sock, _backend_rfile
    try:
        if _backend_sock:
            _backend_sock.close()
    except OSError:
        pass
    _backend_sock = None
    _backend_rfile = None


def _read_headers(rfile):
    """Reads one request/status line plus headers up to the blank line
    that ends them. Returns (first_line_str, headers_dict, raw_bytes) or
    (None, None, None) on a clean EOF before any bytes arrived."""
    first_line = rfile.readline()
    if not first_line:
        return None, None, None
    raw = first_line
    headers = {}
    while True:
        line = rfile.readline()
        if not line:
            return None, None, None
        raw += line
        if line in (b"\r\n", b"\n"):
            break
        if b":" in line:
            k, _, v = line.decode("latin-1").partition(":")
            headers[k.strip().lower()] = v.strip()
    return first_line.decode("latin-1").strip(), headers, raw


def _read_exact(rfile, n):
    data = b""
    remaining = n
    while remaining > 0:
        chunk = rfile.read(min(remaining, 65536))
        if not chunk:
            break
        data += chunk
        remaining -= len(chunk)
    return data


def _http_response(status, ctype, body: bytes) -> bytes:
    head = (
        f"HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\n"
        f"Content-Length: {len(body)}\r\nConnection: keep-alive\r\n\r\n"
    ).encode("latin-1")
    return head + body


def _serve_local(path: str) -> bytes:
    if path == "/":
        body = f"""<!DOCTYPE html><html><head><title>Nimbus Freight -- Edge Gateway</title></head><body>
<!-- {flag(1)} -->
<h1>Nimbus Freight -- Pipeline Edge Gateway</h1>
<p>This gateway fronts our internal deployment tooling. See
<a href="/docs">/docs</a> for the operator changelog.</p>
</body></html>""".encode()
        return _http_response("200 OK", "text/html", body)
    # /docs
    body = f"""<!DOCTYPE html><html><body>
<h2>frontproxy -- operator changelog</h2>
<!-- {flag(2)} -->
<ul>
<li>2026-02-02: all /admin/* paths are now blocked at the edge proxy -- the
    internal admin tooling should never be reachable directly from
    outside this gateway.</li>
<li>2026-01-18: split the monolith -- admin tooling now lives on its own
    internal host, "admin-api", behind this proxy.</li>
<li>2026-01-05: this gateway now also relays SSH on :2222 through to the
    ops host for anyone with a valid credential -- same box, same
    front door, two different protocols.</li>
</ul>
</body></html>""".encode()
    return _http_response("200 OK", "text/html", body)


def _forward_to_backend(raw_request: bytes) -> bytes:
    with _backend_lock:
        for attempt in range(2):
            try:
                _sock, rfile = _get_backend()
                _sock.sendall(raw_request)
                status_line, headers, raw_head = _read_headers(rfile)
                if status_line is None:
                    raise OSError("backend closed connection")
                try:
                    length = int(headers.get("content-length", "0"))
                except ValueError:
                    length = 0
                body = _read_exact(rfile, length)
                return raw_head + body
            except OSError:
                _reset_backend()
                if attempt == 1:
                    return _http_response("502 Bad Gateway", "text/plain", b"backend unreachable\n")
    return _http_response("502 Bad Gateway", "text/plain", b"backend unreachable\n")


def handle_client(conn):
    rfile = conn.makefile("rb")
    try:
        while True:
            first_line, headers, raw_head = _read_headers(rfile)
            if first_line is None:
                break
            try:
                method, path, _version = first_line.split(" ", 2)
            except ValueError:
                break
            path_only = path.split("?", 1)[0]

            # Body length determined PURELY from Content-Length -- this
            # is the front-end's "CL" half of the mismatch. Whatever
            # Transfer-Encoding header the client sent (if any) stays in
            # raw_head, unexamined, to be forwarded verbatim.
            try:
                content_length = int(headers.get("content-length", "0"))
            except ValueError:
                content_length = 0
            body = _read_exact(rfile, content_length)

            if path_only.startswith("/admin/"):
                conn.sendall(_http_response("403 Forbidden", "text/plain", b"Forbidden -- admin paths are blocked at the edge.\n"))
                continue

            if path_only in ("/", "/docs"):
                conn.sendall(_serve_local(path_only))
                continue

            raw_request = raw_head + body
            response = _forward_to_backend(raw_request)
            conn.sendall(response)
    except (OSError, ValueError):
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def _relay_pump(src: socket.socket, dst: socket.socket):
    """Blindly shovels bytes from src to dst until src closes/errors --
    no protocol awareness, just a TCP splice. Half-closes dst's write
    side afterward so the other pump (running the opposite direction on
    another thread) still gets to finish draining its own side."""
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


def handle_relay_client(client_conn: socket.socket):
    try:
        backend_conn = socket.create_connection((RELAY_BACKEND_HOST, RELAY_BACKEND_PORT))
    except OSError:
        try:
            client_conn.close()
        except OSError:
            pass
        return
    t1 = threading.Thread(target=_relay_pump, args=(client_conn, backend_conn), daemon=True)
    t2 = threading.Thread(target=_relay_pump, args=(backend_conn, client_conn), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    for s in (client_conn, backend_conn):
        try:
            s.close()
        except OSError:
            pass


def relay_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", RELAY_LISTEN_PORT))
    srv.listen(128)
    print(f"[frontproxy] ssh relay listening on :{RELAY_LISTEN_PORT} -> {RELAY_BACKEND_HOST}:{RELAY_BACKEND_PORT}", flush=True)
    while True:
        conn, _addr = srv.accept()
        threading.Thread(target=handle_relay_client, args=(conn,), daemon=True).start()


def main():
    threading.Thread(target=relay_server, daemon=True).start()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", LISTEN_PORT))
    srv.listen(128)
    print(f"[frontproxy] listening on :{LISTEN_PORT}, backend {BACKEND_HOST}:{BACKEND_PORT}", flush=True)
    while True:
        conn, _addr = srv.accept()
        threading.Thread(target=handle_client, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
