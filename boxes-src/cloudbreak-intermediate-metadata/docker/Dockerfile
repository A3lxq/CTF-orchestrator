FROM debian:12-slim

RUN apt-get update -qq && apt-get install -y --no-install-recommends -qq \
        python3 python3-venv python3-pip supervisor \
        openssh-server sudo nmap iproute2 \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /opt/venv
COPY app/requirements.txt /opt/app/requirements.txt
RUN /opt/venv/bin/pip install -q --no-cache-dir --retries 10 --timeout 120 \
        -r /opt/app/requirements.txt

COPY app/ /opt/app/
COPY supervisord.conf /etc/supervisor/conf.d/ctf.conf
COPY entrypoint.sh /opt/entrypoint.sh
RUN chmod +x /opt/entrypoint.sh

EXPOSE 5000 22
# Ports 5001 (internal health check) and 8600 (fake Secrets Manager) are
# intentionally NEVER published here or in the box's spec -- reachable
# only via the main app's SSRF-vulnerable /fetch endpoint, from inside
# the container. 169.254.169.254:80 (the fake IMDS) isn't a published
# port at all -- it's a link-local address added to this container's
# own loopback interface by entrypoint.sh, unreachable from outside the
# container regardless.

ENTRYPOINT ["/opt/entrypoint.sh"]
