FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        nodejs \
        openssh-server \
        sudo \
        python3 \
        vim \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/app

COPY app.js /opt/app/app.js
COPY generate_flags.py /opt/generate_flags.py
COPY entrypoint.sh /opt/entrypoint.sh
RUN chmod +x /opt/entrypoint.sh

EXPOSE 22 5000

ENTRYPOINT ["/opt/entrypoint.sh"]
