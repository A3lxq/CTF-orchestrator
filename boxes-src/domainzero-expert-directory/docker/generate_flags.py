#!/usr/bin/env python3
"""
Deterministic per-deployment flag generator for domainzero-expert-directory.

Flags are HMAC-SHA256(secret, "<box_id>:<flag_number>"), truncated to 10 hex
chars, wrapped as HLC{...} -- same scheme every other box uses.

Shipped twice inside this box's own source tree (once per host, copied in by
each Dockerfile) so neither host needs the other to compute its own flags --
same pattern as master-two-offices' shared docker/generate_flags.py, just
with one copy per host-specific build context here since the two hosts
don't otherwise share a vendored /opt/shared directory.
"""
import hashlib
import hmac
import os
import sys

BOX_ID = "domainzero-expert-directory"


def flag_for(secret: str, n: int) -> str:
    digest = hmac.new(secret.encode(), f"{BOX_ID}:{n}".encode(), hashlib.sha256).hexdigest()
    return f"HLC{{{digest[:10]}}}"


if __name__ == "__main__":
    env_secret = os.environ.get("CTF_SECRET")
    if not env_secret:
        print("CTF_SECRET not set", file=sys.stderr)
        sys.exit(1)
    if len(sys.argv) != 2:
        print("usage: generate_flags.py <n>", file=sys.stderr)
        sys.exit(1)
    print(flag_for(env_secret, int(sys.argv[1])))
