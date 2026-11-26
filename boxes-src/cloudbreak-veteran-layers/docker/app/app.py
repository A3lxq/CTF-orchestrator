"""
Nimbus Freight -- internal CI build-artifact server. Flask app, port 5000
(published). This box's headline technique is Docker image LAYER
ARCHAEOLOGY: entrypoint.sh (not this app) synthesizes a build artifact
tarball, nimbus-build-artifact.tar, containing several numbered layer
directories that genuinely mimic Docker's own real OverlayFS layer-diff
convention -- a file a layer adds just sits there as a plain file, and a
file a LATER layer "deletes" is a zero-length ".wh.<name>" whiteout
marker (the real, exact convention Docker/OCI tar layers themselves use
-- see entrypoint.sh for the full explanation). A secret added in an
early layer is still sitting in that layer's own directory even though a
later layer whites it out -- the naive "final merged state" view never
shows it, but the tarball itself still has it, because deleting a file
in OverlayFS never scrubs the earlier layer's own copy.

This app just serves plain static recon pages and the artifact download
-- no app-level vulnerability here, unlike the other Cloudbreak boxes.
The puzzle lives entirely inside the tarball.
"""
import os

from flask import Flask, Response, send_from_directory

from generate_flags import flag_for

SECRET = os.environ["CTF_SECRET"]
ARTIFACT_DIR = "/opt/app/static/artifacts"
ARTIFACT_NAME = "nimbus-build-artifact.tar"

app = Flask(__name__)


def flag(n):
    return flag_for(SECRET, n)


@app.route("/")
def index():
    return """<!DOCTYPE html><html><head><title>Nimbus Freight -- CI Build Server</title></head>
    <body>
    <h1>Nimbus Freight Logistics -- CI Build Artifact Server</h1>
    <p>Internal build pipeline status. See <a href="/docs">docs</a> or the
    <a href="/changelog">changelog</a>.</p>
    </body></html>"""


@app.route("/docs")
def docs():
    # flag1: left in a comment by whoever wrote this page, same as every
    # other "temporary" internal docs page nobody ever cleans up.
    return f"""<!DOCTYPE html><html><head><title>CI Build Server Docs</title></head>
    <body>
    <!-- {flag(1)} -->
    <h1>Build Pipeline (internal)</h1>
    <p>Every successful build exports its final image as a layered
    tarball for audit purposes. This is the SAME raw layer tarball
    format `docker save` itself produces -- each numbered layer
    directory inside it is an independent snapshot (its own diff
    against the layer below), not a pre-merged filesystem.</p>
    <p>See the <a href="/changelog">changelog</a> for where the latest
    one lives.</p>
    </body></html>"""


@app.route("/changelog")
def changelog():
    # flag2: an ops aside that also doubles as the hint toward where the
    # build-artifact download link is and what it's for.
    return f"""<!DOCTYPE html><html><head><title>Changelog</title></head>
    <body>
    <h1>Deploy notes</h1>
    <ul>
      <li>2026-10-01: Pipeline now archives every build's full layer
      history as a tarball, not just the final merged image -- download
      the latest one at <a href="/artifacts/{ARTIFACT_NAME}">/artifacts/{ARTIFACT_NAME}</a>.</li>
      <!-- {flag(2)} -->
      <li>2026-10-03: Security cleanup pass -- stripped a stray secrets
      file out of the pipeline before it ships. (Removing a file in a
      later build step doesn't rewrite the earlier step's own layer,
      but nobody on this team seems to know that yet.)</li>
      <li>2026-10-05: Final artifact now includes a build-info stamp in
      the top layer for quick sanity checks.</li>
    </ul>
    </body></html>"""


@app.route("/artifacts/<path:filename>")
def artifacts(filename):
    return send_from_directory(ARTIFACT_DIR, filename, as_attachment=True)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
