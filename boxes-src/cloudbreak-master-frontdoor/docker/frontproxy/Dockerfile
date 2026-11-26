FROM debian:12-slim

# No pip dependencies at all -- app.py is pure stdlib (socket, threading,
# hmac/hashlib via generate_flags.py). No SSH client needed in this
# image either: the SSH foothold on admin-api is reached by a real
# external player through app.py's own blind TCP relay on :2222, not
# from a shell inside this container.
RUN apt-get update -qq && apt-get install -y --no-install-recommends -qq \
        python3 supervisor \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/log/supervisor /opt/shared /opt/app

COPY docker/generate_flags.py /opt/shared/generate_flags.py
COPY docker/frontproxy/app.py /opt/app/app.py
COPY docker/frontproxy/entrypoint.sh /opt/entrypoint.sh
COPY docker/frontproxy/supervisord.conf /etc/supervisor/conf.d/ctf.conf

RUN chmod +x /opt/entrypoint.sh

EXPOSE 80 2222
# 2222 is the blind SSH relay to admin-api:22 -- see app.py's module
# docstring. admin-api itself still has no published port of its own.

ENTRYPOINT ["/opt/entrypoint.sh"]
