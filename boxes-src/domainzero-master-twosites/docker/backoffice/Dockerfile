FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update -qq && apt-get install -y --no-install-recommends -qq \
        python3 python3-venv python3-pip \
        openssh-server supervisor \
        sudo perl \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/run/sshd /var/log/supervisor /opt/shared

RUN python3 -m venv /opt/venv
COPY docker/backoffice/requirements.txt /opt/app/requirements.txt
RUN /opt/venv/bin/pip install -q --no-cache-dir --retries 10 --timeout 120 \
        -r /opt/app/requirements.txt

COPY docker/generate_flags.py /opt/shared/generate_flags.py
COPY docker/backoffice/app.py /opt/app/app.py
COPY docker/backoffice/entrypoint.sh /opt/entrypoint.sh
COPY docker/backoffice/supervisord.conf /etc/supervisor/conf.d/ctf.conf

RUN chmod +x /opt/entrypoint.sh

# The GraphQL app itself runs as this unprivileged account (not root) --
# the GraphQL bugs above therefore do NOT hand you root directly. The
# real SSH foothold is the separate "boadmin" account created below,
# whose password is discoverable only via the over-fetch bug in app.py.
RUN useradd -m -s /usr/sbin/nologin svc
RUN useradd -m -s /bin/bash boadmin

# Privesc (GTFOBins `perl`): a sudoers rule grants boadmin passwordless
# `sudo perl`. Deliberately NOT reusing any GTFOBins binary already used
# elsewhere in this project (less, tar, vi, python3 subprocess spawn,
# find SUID, nmap NSE, awk) -- perl's own shell escape
# (`sudo perl -e 'exec "/bin/sh";'`) is a direct execve of a root shell,
# verified reliable and distinct from all of those.
RUN echo "boadmin ALL=(ALL) NOPASSWD: /usr/bin/perl" > /etc/sudoers.d/boadmin \
    && chmod 440 /etc/sudoers.d/boadmin

RUN ssh-keygen -A

EXPOSE 4000 22
# Never published by the orchestrator's spec -- internal-only on purpose.

ENTRYPOINT ["/opt/entrypoint.sh"]
