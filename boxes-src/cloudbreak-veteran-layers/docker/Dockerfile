FROM debian:12-slim

RUN apt-get update -qq && apt-get install -y --no-install-recommends -qq \
        python3 python3-venv python3-pip supervisor \
        openssh-server sudo gawk \
    && rm -rf /var/lib/apt/lists/* \
    # Debian's update-alternatives system picks whichever awk provider
    # registered most recently as the default for the generic /usr/bin/awk
    # name -- pin it explicitly to gawk so flag 8's sudoers rule
    # (/usr/bin/awk) always resolves the same binary this image was built
    # and tested against.
    && update-alternatives --set awk /usr/bin/gawk

RUN python3 -m venv /opt/venv
COPY app/requirements.txt /opt/app/requirements.txt
RUN /opt/venv/bin/pip install -q --no-cache-dir --retries 10 --timeout 120 \
        -r /opt/app/requirements.txt

COPY app/ /opt/app/
COPY supervisord.conf /etc/supervisor/conf.d/ctf.conf
COPY entrypoint.sh /opt/entrypoint.sh
RUN chmod +x /opt/entrypoint.sh

EXPOSE 5000 22

ENTRYPOINT ["/opt/entrypoint.sh"]
