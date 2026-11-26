"""
Nimbus Freight -- internal "vendor invoice" portal. Flask app, port 5000
(published). The SSRF-vulnerable /fetch endpoint is this box's headline
bug: it's used to pivot to the cloud instance metadata service (IMDS),
steal a role's temporary credentials, then use those credentials against
a small fake Secrets Manager -- a different objective from
intermediate-portside's own SSRF (which targets an internal diagnostics
API, not cloud credentials).
"""
import os
import requests
from flask import Flask, request, Response

from generate_flags import flag_for

SECRET = os.environ["CTF_SECRET"]

app = Flask(__name__)


def flag(n):
    return flag_for(SECRET, n)


@app.route("/")
def index():
    return """<!DOCTYPE html><html><head><title>Nimbus Freight -- Vendor Portal</title></head>
    <body>
    <h1>Nimbus Freight Logistics -- Vendor Invoice Portal</h1>
    <p>Preview a vendor's hosted invoice before it's attached to a shipment
    record. See <a href="/docs">API docs</a> or the
    <a href="/changelog">changelog</a>.</p>
    </body></html>"""


@app.route("/docs")
def docs():
    # flag1: left in a comment by whoever wrote this page, same as every
    # other "temporary" internal docs page nobody ever cleans up.
    return f"""<!DOCTYPE html><html><head><title>Vendor Portal API Docs</title></head>
    <body>
    <!-- {flag(1)} -->
    <h1>Vendor Portal API (internal)</h1>
    <ul>
      <li><code>GET /fetch?url=...</code> -- server-side fetch of a vendor-hosted
      invoice URL, so the preview renders without the vendor's own CORS
      policy getting in the way</li>
      <li><code>GET /changelog</code> -- recent deploy notes</li>
    </ul>
    </body></html>"""


@app.route("/changelog")
def changelog():
    # flag2: an ops aside, left in by whoever wrote this changelog entry,
    # that also doubles as the hint toward where this box's real target
    # is -- the instance metadata service at 169.254.169.254.
    return f"""<!DOCTYPE html><html><head><title>Changelog</title></head>
    <body>
    <h1>Deploy notes</h1>
    <ul>
      <li>2026-10-14: Rolled the preview fetcher out to prod.</li>
      <!-- {flag(2)} -->
      <!-- Reminder to self: our outbound firewall rule still lets this
           container reach 169.254.169.254 on :80. IT ticket #4417 to
           have that closed off has been open for two months. Don't
           let the preview fetcher anywhere near it until that lands. -->
      <li>2026-10-21: Bumped the invoice-renderer timeout to 25s --
      some vendors' hosting is painfully slow.</li>
    </ul>
    </body></html>"""


@app.route("/fetch")
def fetch():
    # INTENTIONALLY VULNERABLE: SSRF. The only "filter" is a weak,
    # trivially-bypassed substring block on the literal word "localhost"
    # -- 127.0.0.1 and the cloud metadata address 169.254.169.254 both
    # sail straight through untouched.
    url = request.args.get("url", "")
    if "localhost" in url.lower():
        return Response("Blocked: internal URLs are not allowed.", status=400)
    try:
        resp = requests.get(url, timeout=10)
        return Response(resp.text[:4000], mimetype="text/plain")
    except Exception as e:
        return Response(f"Fetch failed: {e}", status=502, mimetype="text/plain")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
