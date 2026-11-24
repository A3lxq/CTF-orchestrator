"""
ledger-tools -- the "forgotten administrator" box's internal web app.
Flask, port 5000 (published). INTENTIONALLY VULNERABLE: an IDOR in the
records viewer (Stage 4a) -- /records/<id> only checks that *someone*
is logged in, never that the viewer owns that record. A normal user
(john) can read another user's (admin's) record just by changing the
id in the URL, disclosing the admin web password -- which is also (the
box's real second vulnerability: credential reuse) the real Linux
`admin` account's own SSH password.
"""
import os
import sys
from pathlib import Path

from flask import Flask, Response, request, send_file, session

sys.path.insert(0, "/opt/shared")
from generate_flags import flag_for  # noqa: E402

SECRET = os.environ["CTF_SECRET"]
MATERIALS = Path("/var/www/materials")

app = Flask(__name__)
app.secret_key = os.urandom(32)

# Fixed/narrative, identical for every team -- not derived from
# CTF_SECRET. Two separate identity spaces, same as the original box:
# these are *web app* accounts; the real Linux `admin` SSH account
# happens to share admin's password (that reuse is the puzzle).
USERS = {
    "john": {"password": "Summer2019!", "is_admin": False},
    "admin": {"password": "N3tOps-Diag#7", "is_admin": True},
}

RECORDS = {
    1: {
        "owner": "john",
        "title": "Handover notes",
        "body": (
            "Reminder to self: finish migrating the internal tools before "
            "I leave. Ask admin if anything looks broken after the handover."
        ),
    },
    2: {
        "owner": "admin",
        "title": "Access notes",
        "body": (
            "Login for this account during the handover window: "
            "admin / N3tOps-Diag#7 -- rotate after the review. (Same "
            "password on the server itself, saves remembering two -- "
            "never got around to rotating that either.)"
        ),
    },
}


def flag(n: int) -> str:
    return flag_for(SECRET, n)


@app.route("/")
def index():
    return """<!DOCTYPE html><html><head><title>ledger-tools</title></head><body>
    <h1>ledger-tools</h1>
    <p>Internal handover tooling. Maintained by jtyler_dev until the 2019
    handover. See <a href="/project">the project page</a> or
    <a href="/profile">jtyler_dev's profile</a> for background, or
    <a href="/login">staff login</a> if you already have an account.</p>
    </body></html>"""


@app.route("/profile")
def profile():
    # Decoy d1a: loud on purpose, a red-bordered "cached status badge"
    # that looks like a flag but scores nothing.
    return """<!doctype html>
<html><head><title>SynHub -- jtyler_dev</title></head>
<body>
<h1>jtyler_dev</h1>
<blockquote style="border:2px solid #c00;padding:0.5em">
  <strong>cached status badge, 2017 (spark-ci-badge, dead project):</strong><br>
  <code>test-flag: FFLAG{old_profile_rev1_55c2}</code>
</blockquote>
<p>Full-stack tinkerer. Builds small internal tools, then forgets about
them. Previously: <em>ledger-tools</em> (internal), a few archived
scripts.</p>
<h2>Activity</h2>
<ul>
  <li>2019-11: Archived project <code>ledger-tools</code> -- "handed off,
      see project page"</li>
  <li>2017-03: Archived project <code>spark-ci-badge</code> (dead CI
      integration, badge cached above)</li>
</ul>
<p>Contact: jtyler (dot) dev (at) oldmail example -- inbox is dead, don't
bother.</p>
</body></html>"""


@app.route("/project")
def project():
    # Flag 1: plaintext, buried in ordinary changelog prose -- requires
    # actually reading the line, not just skimming for brackets.
    return f"""<!doctype html>
<html><head><title>ledger-tools -- internal project page</title></head>
<body>
<h1>ledger-tools</h1>
<p>Internal handover tooling. Maintained by jtyler_dev until the 2019
handover. See the admin for ongoing access.</p>
<h2>Changelog</h2>
<ul>
  <li>v0.4 -- handover notes added, see repo history. Tagged this build
      {flag(1)} in case anyone needs to reference it later.</li>
  <li>v0.3 -- admin account provisioned (reused the same password
      everywhere -- todo: fix before launch -- never got fixed)</li>
  <li>v0.2 -- initial IDOR-prone record viewer (todo: fix before launch --
      never got fixed)</li>
  <li>v0.1 -- initial commit</li>
</ul>
</body></html>"""


@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        user = USERS.get(u)
        if user and user["password"] == p:
            session["username"] = u
            return f"""<h2>Welcome back, {u}.</h2>
            <p><a href="/records/mine">Your records</a></p>"""
        error = "Invalid credentials."
    return f"""<!DOCTYPE html><html><body>
    <h2>Staff Login</h2>
    <p style="color:red">{error}</p>
    <form method="post">
      Username: <input name="username"><br>
      Password: <input name="password" type="password"><br>
      <button type="submit">Log in</button>
    </form></body></html>"""


@app.route("/records/mine")
def my_record():
    username = session.get("username")
    if not username:
        return Response("login required", status=401)
    for record_id, record in RECORDS.items():
        if record["owner"] == username:
            return Response(f'redirecting to /records/{record_id}\n', status=302,
                             headers={"Location": f"/records/{record_id}"})
    return Response("not found", status=404)


@app.route("/records/<int:record_id>")
def view_record(record_id):
    # --- INTENTIONAL VULNERABILITY (IDOR) ---
    # A correct implementation would also check that the logged-in
    # user owns this record. That check is deliberately absent: any
    # logged-in user can view any record by id, which is exactly how a
    # player reaches admin's own record (id=2) while logged in as john.
    if not session.get("username"):
        return Response("login required", status=401)
    record = RECORDS.get(record_id)
    if record is None:
        return Response("not found", status=404)
    return f"""<!doctype html><html><body>
    <h2>{record['title']}</h2>
    <p><em>owner: {record['owner']}</em></p>
    <p>{record['body']}</p>
    </body></html>"""


@app.route("/materials/metadata/<path:filename>")
def metadata_file(filename):
    path = MATERIALS / "metadata" / filename
    if not path.is_file():
        return Response("not found", status=404)
    return send_file(path)


@app.route("/materials/stage3/<path:filename>")
def stage3_file(filename):
    path = MATERIALS / "stage3" / filename
    if not path.is_file():
        return Response("not found", status=404)
    return send_file(path)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
