FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        samba samba-dsdb-modules samba-vfs-modules winbind krb5-user \
        ldap-utils python3 \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/shares/staff-notices /opt/shares/reports-archive /opt/shares/it-vault

COPY docker/shares/staff-notices/ /opt/shares/staff-notices/
COPY docker/shares/reports-archive/ /opt/shares/reports-archive/
COPY docker/shares/it-vault/ /opt/shares/it-vault/
COPY docker/generate_flags.py /opt/generate_flags.py
COPY docker/directory/tcp_relay.py /opt/tcp_relay.py
COPY docker/directory/entrypoint.sh /opt/entrypoint.sh
RUN chmod +x /opt/entrypoint.sh

# AD DC: DNS, Kerberos, LDAP/LDAPS, SMB, Global Catalog, RPC -- same port
# set as domainzero-intermediate-domainedge (this game's only other real
# Samba AD DC box). Plus 8080: a plain TCP relay (tcp_relay.py) onto
# search-intranet:5000 -- that host is internal-only/never published, so
# without this, a real player would have no published-port path to it at
# all (see tcp_relay.py's own docstring).
EXPOSE 53 88 135 139 389 445 464 636 3268 3269 8080

ENTRYPOINT ["/opt/entrypoint.sh"]
