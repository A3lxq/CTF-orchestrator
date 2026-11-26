#!/usr/bin/env python3
"""
Deterministic per-deployment flag generator for domainzero-beginner-helpdesk.

Flags are HMAC-SHA256(secret, "<box_id>:<flag_number>"), truncated to 10 hex
chars, wrapped as HLC{...} -- same scheme every other box uses.
"""
import hmac
import hashlib
import json
import os
import sys

BOX_ID = "domainzero-beginner-helpdesk"


def flag_for(n: int, secret: str) -> str:
    digest = hmac.new(secret.encode(), f"{BOX_ID}:{n}".encode(), hashlib.sha256).hexdigest()
    return f"HLC{{{digest[:10]}}}"


if __name__ == "__main__":
    secret = os.environ.get("CTF_SECRET")
    if not secret:
        print("CTF_SECRET not set", file=sys.stderr)
        sys.exit(1)

    if len(sys.argv) == 2 and sys.argv[1] == "all-json":
        print(json.dumps({str(n): flag_for(n, secret) for n in range(1, 11)}))
    elif len(sys.argv) == 2:
        print(flag_for(int(sys.argv[1]), secret))
    else:
        print("usage: generate_flags.py <n> | generate_flags.py all-json", file=sys.stderr)
        sys.exit(1)
