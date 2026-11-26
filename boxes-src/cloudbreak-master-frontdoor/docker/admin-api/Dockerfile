FROM debian:12-slim

# No pip dependencies -- app.py is pure stdlib http.server/socketserver.
RUN apt-get update -qq && apt-get install -y --no-install-recommends -qq \
        python3 supervisor openssh-server sudo \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/run/sshd /var/log/supervisor /opt/shared /opt/app

COPY docker/generate_flags.py /opt/shared/generate_flags.py
COPY docker/admin-api/app.py /opt/app/app.py
COPY docker/admin-api/entrypoint.sh /opt/entrypoint.sh
COPY docker/admin-api/supervisord.conf /etc/supervisor/conf.d/ctf.conf

RUN chmod +x /opt/entrypoint.sh

# The HTTP service itself runs as this unprivileged account (not root).
# "ops" is the real SSH foothold, disclosed only via the /admin/users
# smuggling target. "svc" is a honeypot-flavored service account that
# shows up in the JSON blob too but has no shell and no valid path.
RUN useradd -m -s /usr/sbin/nologin svc
RUN useradd -m -s /bin/bash ops

# Privesc (Stage 7-8): passwordless sudo on `env` -- the GTFOBins escape
# is `sudo env /bin/sh`, which spawns a root shell because env execs its
# argument with sudo's own (root) privileges. Binaries already used
# elsewhere in this project for the same trick are `less`, `tar`, `vi`,
# `python3`, `find`, `nmap`, `awk`, `perl` -- this box deliberately uses
# a different one (`env`) so the series doesn't repeat itself.
RUN echo 'ops ALL=(ALL) NOPASSWD: /usr/bin/env' > /etc/sudoers.d/ops \
    && chmod 440 /etc/sudoers.d/ops

EXPOSE 8000 22
# Port 8000 is NEVER published anywhere -- admin-api is reachable only
# via frontproxy's own internal_groups network alias, by design. Port 22
# is listed here for Kubernetes-Service parity with other multi-host
# boxes in this project (ports: is otherwise unused by the Docker
# backend for a non-front-door host -- see master-two-offices.yaml's own
# comment on this), but it is likewise never published to the host by
# the Docker backend. See this box's writeup/tests for how the SSH step
# is actually reached.

ENTRYPOINT ["/opt/entrypoint.sh"]
