#!/usr/bin/env python3
"""
Deterministic per-deployment flag generator for domainzero-master-twosites.

Flags are HMAC-SHA256(secret, "<box_id>:<flag_number>"), truncated to 10 hex
chars, wrapped as HLC{...} -- same scheme every other box uses.

Shipped as a single file to BOTH hosts (frontdesk, backoffice) in this
box: frontdesk's entrypoint.sh (plain bash + system python3) uses the CLI
form (`python3 generate_flags.py <n>`), the same way
domainzero-intermediate-domainedge's entrypoint.sh does; backoffice's
Flask app (app.py) imports `flag_for` directly instead, the same way
master-two-offices' two Flask apps do.
"""
import hmac
import hashlib
import os
import sys

BOX_ID = "domainzero-master-twosites"


def flag_for(secret: str, n: int) -> str:
    digest = hmac.new(secret.encode(), f"{BOX_ID}:{n}".encode(), hashlib.sha256).hexdigest()
    return f"HLC{{{digest[:10]}}}"


if __name__ == "__main__":
    secret = os.environ.get("CTF_SECRET")
    if not secret:
        print("CTF_SECRET not set", file=sys.stderr)
        sys.exit(1)
    if len(sys.argv) != 2:
        print("usage: generate_flags.py <n>", file=sys.stderr)
        sys.exit(1)
    print(flag_for(secret, int(sys.argv[1])))
