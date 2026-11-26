"""
admin-api -- Nimbus Freight's internal admin tooling. Port 8000.
INTERNAL-ONLY: never published, reachable only from inside frontproxy's
internal network (by the alias "admin-api") -- see the box spec's
internal_groups and docker-compose.yml.

Built directly on Python's http.server/socketserver (NOT Flask/WSGI): a
real framework normalizes request framing in ways that would mask the
exact bug being demonstrated here. This handler genuinely honors
Transfer-Encoding: chunked request bodies -- a real dechunking
implementation, not just ignoring the header -- which is the backend's
"TE" half of the CL.TE mismatch with frontproxy. When both
Content-Length and Transfer-Encoding are present (which should never
happen on a legitimate request), this parses the body using chunked
framing and ignores Content-Length entirely -- exactly the opposite
priority from frontproxy, and exactly the disagreement a CL.TE desync
exploits: frontproxy forwards bytes using ITS OWN (Content-Length)
framing, admin-api then reads those same bytes using chunked framing,
the two disagree about where the body ends, and whatever's left over
gets parsed by admin-api as a brand new, separate pipelined request.
"""
import http.server
import json
import os
import socketserver
import sys

sys.path.insert(0, "/opt/shared")
from generate_flags import flag_for  # noqa: E402

SECRET = os.environ["CTF_SECRET"]
LISTEN_PORT = 8000
OPS_SSH_PASSWORD = "NimbusOps-Patch-Me-2026!"  # matches entrypoint.sh's ops account


def flag(n):
    return flag_for(SECRET, n)


class AdminAPIHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"  # keep-alive by default -- required for the pipelined-smuggled-request desync

    def _read_body(self) -> bytes:
        """Genuinely honors Transfer-Encoding: chunked, independent of
        whatever Content-Length also claims. This disagreement with
        frontproxy's own Content-Length-only framing is the whole bug."""
        te = self.headers.get("Transfer-Encoding", "")
        if te and "chunked" in te.lower():
            body = b""
            while True:
                size_line = self.rfile.readline()
                if not size_line:
                    break
                size_str = size_line.split(b";")[0].strip()
                try:
                    size = int(size_str, 16)
                except ValueError:
                    break
                if size == 0:
                    # Terminating chunk -- consume the trailer section
                    # (we don't support real trailers, just the common
                    # no-trailer blank line that ends it).
                    trailer = self.rfile.readline()
                    while trailer not in (b"\r\n", b"\n", b""):
                        trailer = self.rfile.readline()
                    break
                body += self.rfile.read(size)
                self.rfile.read(2)  # each chunk's data is followed by a CRLF
            return body
        cl = self.headers.get("Content-Length")
        if cl:
            try:
                length = int(cl)
            except ValueError:
                length = 0
            return self.rfile.read(length)
        return b""

    def _respond(self, code, ctype, body: bytes):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _route(self):
        self._read_body()  # always consume, even on routes that ignore it
        path = self.path.split("?", 1)[0]

        if path == "/internal/ping":
            self._respond(200, "text/plain", f"pong -- admin-api internal health check\n{flag(3)}\n".encode())
            return
        if path == "/admin/dashboard":
            self._respond(
                200, "text/html",
                f"<h1>Nimbus Freight -- Admin Dashboard</h1><p>{flag(4)}</p>".encode(),
            )
            return
        if path == "/admin/users":
            payload = {
                "flag": flag(5),
                "note": "internal only -- never expose this past the edge proxy",
                "ssh_hint": "this host's sshd is only reachable through frontproxy's relay -- ssh -p 2222 ops@<frontproxy>",
                "users": [
                    {"username": "ops", "role": "linux-shell", "ssh_password": OPS_SSH_PASSWORD},
                    {"username": "svc", "role": "service-account (no shell)"},
                ],
            }
            self._respond(200, "application/json", json.dumps(payload).encode())
            return
        self._respond(404, "text/plain", b"not found\n")

    def do_GET(self):
        self._route()

    def do_POST(self):
        self._route()

    def log_message(self, fmt, *args):
        sys.stderr.write("[admin-api] " + (fmt % args) + "\n")


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    srv = ThreadingHTTPServer(("0.0.0.0", LISTEN_PORT), AdminAPIHandler)
    print(f"[admin-api] listening on :{LISTEN_PORT}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
