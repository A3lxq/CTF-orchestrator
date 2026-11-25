FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        samba samba-common-bin \
        openssh-server \
        sudo \
        python3 \
        less \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /srv/shares/reception /srv/shares/ops-archive /srv/shares/secure-ops

COPY share-reception/ /srv/shares/reception/
COPY share-ops-archive/ /srv/shares/ops-archive/
COPY share-secure-ops/ /srv/shares/secure-ops/
COPY smb.conf /etc/samba/smb.conf
COPY generate_flags.py /opt/generate_flags.py
COPY entrypoint.sh /opt/entrypoint.sh
RUN chmod +x /opt/entrypoint.sh

EXPOSE 445 139 22

ENTRYPOINT ["/opt/entrypoint.sh"]
