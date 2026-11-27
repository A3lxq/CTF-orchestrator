"""
Back Office -- the Two Sites engagement's second internal site. Flask,
port 4000. NEVER published by the orchestrator's spec -- same
"internal-only host" pattern as master-two-offices' own backoffice. A
real external player reaches this host's GraphQL API (and, later, SSH)
only through frontdesk's own TCP relay (frontdesk:4000 and
frontdesk:2222 -- see frontdesk/tcp_relay.py), never directly; this
module itself has no awareness of that relay at all, which is the
point -- the bridging is handled entirely at the network layer, one
level below this application.

HAND-ROLLED GRAPHQL, DOCUMENTED SIMPLIFICATION: this is NOT a real GraphQL
server (no graphql-core, no schema language, no real query parser). It is
a single POST /graphql endpoint that accepts {"query": "...", "variables":
{...}} and does simple string-based dispatch on a handful of recognized
operation shapes (an introspection-style probe, the `login` mutation, the
`record` query). This mirrors the same "hand-roll a minimal, honestly-
simplified fake of the real protocol shape" approach this project already
uses elsewhere (the fake IMDS in cloudbreak-intermediate-metadata, the S3
mock in cloudbreak-noob-bucket) -- it is NOT a claim of real GraphQL
spec/engine fidelity, just enough surface for introspection recon,
authentication, and an authorization bug to all be real, exercisable
behaviors against this exact endpoint.

INTENTIONALLY VULNERABLE, two distinct bugs:
  1. Pass-the-hash: the `login` mutation accepts EITHER the real plaintext
     password OR the exact NTLM-hash-dump string for svc-backoffice as the
     credential. The plaintext is never discoverable anywhere in this box
     on purpose -- the intended path is to pass the hash itself, exactly
     as found on frontdesk, which is the actual defining behavior of a
     real pass-the-hash attack (using the hash as the authentication
     material, not cracking it back to plaintext first).
  2. GraphQL over-fetch / missing field-level authorization: `record(id)`
     returns an `internalNotes` field with no check that the authenticated
     session's role is entitled to see it -- ANY authenticated session
     (even the low-privilege svc-backoffice one from step 1) can read an
     admin-only record's internal notes just by asking for that field.
     This is a distinct bug from the pass-the-hash step above.
"""
import os
import re
import secrets
import sys

from flask import Flask, jsonify, request

sys.path.insert(0, "/opt/shared")
from generate_flags import flag_for  # noqa: E402

SECRET = os.environ["CTF_SECRET"]
app = Flask(__name__)


def flag(n: int) -> str:
    return flag_for(SECRET, n)


# --- svc-backoffice's AD-style account, as it exists on this host's own
# user store (NOT the Linux account -- this is the GraphQL API's own
# login, modeling an app-level identity backed by the domain account of
# the same name). The plaintext is intentionally unknowable: no file,
# env var, or response anywhere in this box ever reveals it. The NTLM
# hash below is the SAME exact string as the one leaked via frontdesk's
# legacy backup share -- pass it as-is, don't try to crack it.
SVC_BACKOFFICE_USERNAME = "svc-backoffice"
SVC_BACKOFFICE_PLAINTEXT = secrets.token_hex(32)  # unknowable by design, never logged or exposed
SVC_BACKOFFICE_NTLM_HASH = "8846f7eaee8fb117ad06bdd830b7586c"

# The second credential (flag 6's payload): a real Linux account on THIS
# host, discoverable only via the GraphQL over-fetch bug below.
BOADMIN_USERNAME = "boadmin"
BOADMIN_PASSWORD = "Back0ffice-Recovery-9x!"  # fixed/narrative -- same every team by design, matches the Linux account's own password set in entrypoint.sh

# In-memory session store: token -> username. Lost on restart, which is
# fine -- a fresh login is one GraphQL call away.
SESSIONS: dict[str, str] = {}

# The "database" this internal tools API serves. `role_required` exists
# on every record, as a real field a careful resolver WOULD check -- the
# bug is that `record`'s own resolver below never looks at it.
RECORDS = {
    1: {
        "title": "Vendor Contact List",
        "role_required": None,
        "internal_notes": "Nothing sensitive here -- public vendor contact info only.",
    },
    2: {
        "title": "Backoffice Workstation Admin Recovery",
        "role_required": "admin",
        "internal_notes": (
            f"{flag(6)} :: local recovery credential for this workstation -- "
            f"{BOADMIN_USERNAME}:{BOADMIN_PASSWORD} -- this box has no direct "
            "network route of its own; reach it through frontdesk's own SSH "
            "relay on port 2222"
        ),
    },
}


def _is_introspection(query: str) -> bool:
    return "__schema" in query or "IntrospectionQuery" in query


def _extract_credential(query: str, variables: dict) -> tuple[str, str]:
    username = variables.get("username") or variables.get("u") or ""
    password = variables.get("password") or variables.get("p") or ""
    if not username:
        m = re.search(r'username\s*:\s*"([^"]*)"', query)
        username = m.group(1) if m else ""
    if not password:
        m = re.search(r'password\s*:\s*"([^"]*)"', query)
        password = m.group(1) if m else ""
    return username, password


def _extract_record_id(query: str, variables: dict) -> int | None:
    rid = variables.get("id")
    if rid is None:
        m = re.search(r'id\s*:\s*"?(\d+)"?', query)
        rid = m.group(1) if m else None
    try:
        return int(rid) if rid is not None else None
    except (TypeError, ValueError):
        return None


def _current_user() -> str | None:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    return SESSIONS.get(auth[len("Bearer "):].strip())


@app.route("/")
def index():
    return (
        "Back Office internal tools API (Meridian Systems -- Two Sites)\n"
        "-----------------------------------------------------------\n"
        "GraphQL endpoint: POST /graphql  {\"query\": \"...\"}\n"
    )


@app.route("/graphql", methods=["POST"])
def graphql():
    body = request.get_json(silent=True) or {}
    query = body.get("query", "") or ""
    variables = body.get("variables") or {}

    # --- Introspection: reveal the schema shape, no auth required. -----
    if _is_introspection(query):
        return jsonify({
            "data": {
                "__schema": {
                    "queryType": {
                        "name": "Query",
                        "fields": [
                            {
                                "name": "record",
                                "description": "Look up an internal record by id. Requires an authenticated session (Authorization: Bearer <token>).",
                                "args": [{"name": "id", "type": "ID"}],
                            },
                        ],
                    },
                    "mutationType": {
                        "name": "Mutation",
                        "fields": [
                            {
                                "name": "login",
                                "description": (
                                    "Authenticate with username + password. Accepts either the "
                                    "plaintext password or the account's own NTLM hash in place "
                                    f"of it (legacy compatibility shim). {flag(4)}"
                                ),
                                "args": [
                                    {"name": "username", "type": "String"},
                                    {"name": "password", "type": "String"},
                                ],
                            },
                        ],
                    },
                },
            },
        })

    # --- login(username, password): plaintext OR NTLM hash accepted. ---
    if "login(" in query or "login (" in query:
        username, password = _extract_credential(query, variables)
        if username == SVC_BACKOFFICE_USERNAME and password in (
            SVC_BACKOFFICE_PLAINTEXT,
            SVC_BACKOFFICE_NTLM_HASH,
        ):
            token = secrets.token_hex(16)
            SESSIONS[token] = username
            return jsonify({"data": {"login": {"token": token, "flag": flag(5)}}})
        return jsonify({"errors": [{"message": "Invalid credentials"}]}), 401

    # --- record(id): authenticated, but no per-field authorization ----
    # check on internalNotes -- the over-fetch bug. ----------------------
    if "record(" in query or "record (" in query:
        user = _current_user()
        if not user:
            return jsonify({"errors": [{"message": "Unauthenticated -- call login first"}]}), 401
        rid = _extract_record_id(query, variables)
        record = RECORDS.get(rid)
        if not record:
            return jsonify({"errors": [{"message": f"No such record: {rid}"}]}), 404
        # BUG: `record.role_required` is never compared against the
        # caller's own role here, so any authenticated session -- even
        # svc-backoffice's own low-privilege one -- gets internalNotes
        # for records it was never meant to see.
        return jsonify({
            "data": {
                "record": {
                    "id": rid,
                    "title": record["title"],
                    "internalNotes": record["internal_notes"],
                },
            },
        })

    return jsonify({"errors": [{"message": "Unrecognized query/mutation"}]}), 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=4000)
