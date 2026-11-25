FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

# Install essential services and tools
RUN apt-get update && apt-get install -y --no-install-recommends     openssh-server     vsftpd     nginx     sudo     curl     net-tools     procps     iproute2     python3     ca-certificates     && rm -rf /var/lib/apt/lists/*

# Copy configuration files
COPY config/sshd_config /etc/ssh/sshd_config
COPY config/vsftpd.conf /etc/vsftpd.conf
COPY config/sudoers_exam /etc/sudoers_exam

# Copy web files
RUN rm -rf /var/www/html/*
COPY web/ /var/www/html/

# Copy startup scripts (entrypoint, per-team flag generator, SSH key
# material, FTP instructions, the stego backup image)
COPY scripts/ /scripts/
RUN chmod +x /scripts/entrypoint.sh

# Expose only the 3 designated challenge ports (+ passive FTP ports)
EXPOSE 80 21 2222 21100-21110

ENTRYPOINT ["/scripts/entrypoint.sh"]
