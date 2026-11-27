FROM debian:12-slim

RUN apt-get update -qq && apt-get install -y --no-install-recommends -qq \
        python3 python3-venv python3-pip \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/app

RUN python3 -m venv /opt/venv
COPY docker/search-intranet/requirements.txt /opt/app/requirements.txt
RUN /opt/venv/bin/pip install -q --no-cache-dir --retries 10 --timeout 120 \
        -r /opt/app/requirements.txt

COPY docker/generate_flags.py /opt/app/generate_flags.py
COPY docker/search-intranet/app.py /opt/app/app.py
COPY docker/search-intranet/entrypoint.sh /opt/entrypoint.sh
RUN chmod +x /opt/entrypoint.sh

EXPOSE 5000
# Never published in the orchestrator spec -- internal-only, reachable
# only from "directory" (the front-door AD DC host) over this instance's
# shared internal network group.

ENTRYPOINT ["/opt/entrypoint.sh"]
