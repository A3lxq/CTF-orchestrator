FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        samba samba-dsdb-modules samba-vfs-modules winbind krb5-user \
        ldap-utils python3 \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/shares/reception /opt/shares/hr-confidential /opt/shares/it-admin-drop

COPY shares/reception/ /opt/shares/reception/
COPY shares/hr-confidential/ /opt/shares/hr-confidential/
COPY shares/it-admin-drop/ /opt/shares/it-admin-drop/
COPY generate_flags.py /opt/generate_flags.py
COPY entrypoint.sh /opt/entrypoint.sh
RUN chmod +x /opt/entrypoint.sh

# AD DC: DNS, Kerberos, LDAP/LDAPS, SMB, Global Catalog, RPC.
EXPOSE 53 88 135 139 389 445 464 636 3268 3269

ENTRYPOINT ["/opt/entrypoint.sh"]
