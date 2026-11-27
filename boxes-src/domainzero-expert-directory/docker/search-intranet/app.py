"""
Search Intranet -- Meridian Systems' internal staff-directory search tool.
Flask, port 5000. Internal-only: never published by the orchestrator spec,
reachable only from "directory" (the front-door AD DC host) over this
instance's shared internal network group, by the alias "search-intranet".

INTENTIONALLY VULNERABLE: a hand-rolled NoSQL (MongoDB-style) operator
injection in /login. This box deliberately does NOT run a real MongoDB --
at ~700MB+ it would blow this host's disk budget for what's a one-endpoint
bug demo. Instead, USERS below is a tiny in-memory dict standing in for a
"users" collection, and _op_match() below reproduces the exact class of bug
a real Mongo-backed app gets when it passes `request.json` straight into a
query filter with no type checking: a query VALUE that is itself a dict
gets treated as a MongoDB operator expression (`$ne`, `$regex`, etc.)
instead of a literal to compare against. Same spirit as this project's
other hand-rolled protocol-shape stand-ins (the fake IMDS, the fake S3/
Secrets Manager) -- the bug class is real and exploited over real HTTP/JSON,
only the backing "database" is simplified.

A classic injection payload --
    {"username": "jcarter", "password": {"$ne": null}}
-- bypasses the password check entirely (stored password is never null, so
"not equal to null" is trivially true for ANY non-null value) and logs the
attacker in as jcarter with no real password. The response for a
successful login also hands back jcarter's real AD password, so a player
can just bind directly against the "directory" domain controller too --
no need to keep going through this app.
"""
import os
import sys

from flask import Flask, Response, jsonify, request

sys.path.insert(0, os.path.dirname(__file__))
from generate_flags import flag_for  # noqa: E402

SECRET = os.environ["CTF_SECRET"]
app = Flask(__name__)


def flag(n):
    return flag_for(SECRET, n)


# The app's own local copy of a handful of staff accounts -- a real
# Mongo-backed version of this tool would keep these in a "users"
# collection. jcarter's password here is deliberately the SAME string as
# jcarter's real Active Directory password (a realistic, bad habit: one
# shared credential reused between an internal web tool and the domain
# itself) -- see "directory" host's own entrypoint.sh for the matching
# JCARTER_PASSWORD constant.
USERS = {
    "jcarter": {
        "password": "Meridian-Newhire-24!",
        "role": "staff",
        "full_name": "J. Carter",
    },
    "guest": {
        "password": "Browse-Only-NoAD!",
        "role": "guest",
        "full_name": "Guest Browsing Account",
    },
}


def _op_match(stored, query):
    """Naive, intentionally-vulnerable MongoDB-style filter evaluation.

    A real app passing `request.json` straight into `collection.find_one()`
    would let a query VALUE shaped like {"$ne": ..., "$regex": ...} act as
    an operator expression against the stored field, instead of being
    compared as a literal. This reproduces exactly that behavior for the
    handful of operators a classic auth-bypass payload needs -- nothing
    more. Any non-dict query is a plain, literal equality check.
    """
    if not isinstance(query, dict):
        return stored == query
    for op, val in query.items():
        if op == "$eq":
            ok = stored == val
        elif op == "$ne":
            ok = stored != val
        elif op == "$gt":
            ok = stored > val
        elif op == "$gte":
            ok = stored >= val
        elif op == "$lt":
            ok = stored < val
        elif op == "$lte":
            ok = stored <= val
        elif op == "$in":
            ok = stored in val
        elif op == "$nin":
            ok = stored not in val
        elif op == "$exists":
            ok = bool(val)  # `stored` is always present in this toy "collection"
        elif op == "$regex":
            import re
            ok = re.search(val, stored) is not None
        else:
            return False  # unknown operator -- fail closed, not open
        if not ok:
            return False
    return True


@app.route("/")
def index():
    return f"""Meridian Systems -- Search Intranet
=====================================
recon note: {flag(3)}

Internal staff-directory search tool (early rollout -- staff login
only, public search coming later).

API:
  POST /login
    Content-Type: application/json
    Body: {{"username": "<str>", "password": "<str>"}}
    Returns your staff profile on success.

This tool keeps its own local copy of staff login info, synced from
the directory at onboarding time. Report sync issues to IT.
"""


@app.route("/login", methods=["POST"])
def login():
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return Response("Bad request: expected a JSON object body.\n", status=400)

    username_query = body.get("username")
    password_query = body.get("password")

    for uname, rec in USERS.items():
        if _op_match(uname, username_query) and _op_match(rec["password"], password_query):
            return jsonify({
                "message": f"Login successful. Welcome, {rec['full_name']}.",
                "username": uname,
                "role": rec["role"],
                "directory_password": rec["password"],
                "note": (
                    "This is the same password on file for your Active "
                    "Directory account -- use it directly against the "
                    "domain controller if you'd rather not keep coming "
                    "back through this app."
                ),
                "flag": flag(4),
            })

    return Response("Login failed: invalid username or password.\n", status=401)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
