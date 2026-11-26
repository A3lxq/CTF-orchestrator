FROM debian:12-slim

# No pip dependencies at all -- app.py is pure stdlib (socket, threading,
# hmac/hashlib via generate_flags.py). openssh-client + sshpass are here
# only so this gateway's own container can be used as the network
# pivot point to reach admin-api's sshd (see docker/README notes in
# entrypoint.sh / the box's writeup) -- admin-api has no published port
# of its own, by design.
RUN apt-get update -qq && apt-get install -y --no-install-recommends -qq \
        python3 supervisor openssh-client sshpass \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/log/supervisor /opt/shared /opt/app

COPY docker/generate_flags.py /opt/shared/generate_flags.py
COPY docker/frontproxy/app.py /opt/app/app.py
COPY docker/frontproxy/entrypoint.sh /opt/entrypoint.sh
COPY docker/frontproxy/supervisord.conf /etc/supervisor/conf.d/ctf.conf

RUN chmod +x /opt/entrypoint.sh

EXPOSE 80

ENTRYPOINT ["/opt/entrypoint.sh"]
