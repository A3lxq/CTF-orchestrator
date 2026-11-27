FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        samba samba-dsdb-modules samba-vfs-modules winbind krb5-user \
        ldap-utils python3 \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/shares/reception /opt/shares/ops-archive

COPY docker/frontdesk/shares/reception/ /opt/shares/reception/
COPY docker/frontdesk/shares/ops-archive/ /opt/shares/ops-archive/
COPY docker/generate_flags.py /opt/generate_flags.py
COPY docker/frontdesk/tcp_relay.py /opt/tcp_relay.py
COPY docker/frontdesk/entrypoint.sh /opt/entrypoint.sh
RUN chmod +x /opt/entrypoint.sh

# AD DC: DNS, Kerberos, LDAP/LDAPS, SMB, Global Catalog, RPC -- same port
# list as domainzero-intermediate-domainedge (the only other real Samba AD
# DC in this project) -- PLUS 2222 and 4000. `backoffice` (the second
# host) has no published port of its own under either backend, so
# frontdesk -- the only host with published ports -- runs tcp_relay.py
# (stdlib-only, no extra packages needed) to forward 2222 -> backoffice:22
# and 4000 -> backoffice:4000. Without this, a real external player would
# have no network path to backoffice at all once they have the SSH or
# GraphQL credential, breaking this project's "solvable over published
# ports alone" invariant. See tcp_relay.py's own docstring.
EXPOSE 53 88 135 139 389 445 464 636 3268 3269 2222 4000

ENTRYPOINT ["/opt/entrypoint.sh"]
