"""
A plain internal health-check endpoint, bound to 127.0.0.1:5001 only --
never published as a front-door port (see the box's spec), so it's
reachable solely via the main app's /fetch SSRF, proving the SSRF
reaches past the container's own loopback before going for the real
target (the metadata service).
"""
import os
from flask import Flask, Response

from generate_flags import flag_for

SECRET = os.environ["CTF_SECRET"]

app = Flask(__name__)


@app.route("/ping")
def ping():
    return Response(f"ok\n{flag_for(SECRET, 3)}\n", mimetype="text/plain")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001)
