FROM debian:12-slim

RUN apt-get update -qq && apt-get install -y --no-install-recommends -qq \
        python3 python3-venv python3-pip \
        openssh-server cron supervisor \
        libimage-exiftool-perl git cmatrix \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/run/sshd /var/log/supervisor /var/www/materials /opt/shared /opt/app \
    && mkdir -p /home/admin/evidence /home/admin/flags /root

RUN python3 -m venv /opt/venv
COPY docker/requirements.txt /opt/app/requirements.txt
RUN /opt/venv/bin/pip install -q --no-cache-dir --retries 10 --timeout 120 \
        -r /opt/app/requirements.txt

COPY docker/generate_flags.py /opt/shared/generate_flags.py
COPY docker/flagcrypto.py /opt/shared/flagcrypto.py
COPY docker/app.py /opt/app/app.py
COPY docker/boot_setup.py /opt/boot_setup.py
COPY docker/materials/ /opt/materials/
COPY docker/entrypoint.sh /opt/entrypoint.sh
COPY docker/supervisord.conf /etc/supervisor/conf.d/ctf.conf
COPY docker/sshd_90_admin.conf /etc/ssh/sshd_config.d/90-admin.conf
COPY docker/cmatrix-trap.sh /usr/local/sbin/cmatrix-trap.sh
COPY docker/cleanup.sh /opt/admin-tools/cleanup.sh
RUN chmod +x /opt/entrypoint.sh /usr/local/sbin/cmatrix-trap.sh
RUN echo /usr/local/sbin/cmatrix-trap.sh >> /etc/shells

# --- global SSH posture: locked down by default, the sshd_config.d
# fragment above is the only thing that reopens password auth, and only
# for the specific accounts that need it. ---------------------------------
RUN sed -i 's/^#\?PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config \
    && sed -i 's/^#\?PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config

# --- accounts --------------------------------------------------------------
# john: console-only in the original design, no SSH access of any kind
# here either (absent from the sshd_config.d Match User list above).
RUN useradd -m -s /bin/bash john

# admin: runs the web app, SSH password auth via the sshd_config.d
# fragment, primary group "admin" -- which is exactly what makes the
# cron privesc below reachable. No sudo rights at all.
RUN useradd -m -s /bin/bash -U admin \
    && echo "admin:N3tOps-Diag#7" | chpasswd

# 8 honeypot accounts -- real SSH password auth, but the login shell
# never reaches a real prompt (see cmatrix-trap.sh). Usernames with a
# literal "." need --badname (historically outside the portable POSIX
# username charset; Debian's useradd otherwise refuses them).
RUN useradd --badname -m -s /usr/local/sbin/cmatrix-trap.sh msharma_ops \
    && useradd --badname -m -s /usr/local/sbin/cmatrix-trap.sh k.delgado_qa \
    && useradd --badname -m -s /usr/local/sbin/cmatrix-trap.sh r.obrien_dev \
    && useradd --badname -m -s /usr/local/sbin/cmatrix-trap.sh t.nakamura_support \
    && useradd --badname -m -s /usr/local/sbin/cmatrix-trap.sh a.ferreira_design \
    && useradd --badname -m -s /usr/local/sbin/cmatrix-trap.sh p.wu_infra \
    && useradd --badname -m -s /usr/local/sbin/cmatrix-trap.sh legacy-ftp \
    && useradd --badname -m -s /usr/local/sbin/cmatrix-trap.sh backup-svc \
    && echo "msharma_ops:0psRunb00k\$22" | chpasswd \
    && echo "k.delgado_qa:Qu4lity_First!" | chpasswd \
    && echo "r.obrien_dev:DevOps2016#" | chpasswd \
    && echo "t.nakamura_support:Supp0rtTix#99" | chpasswd \
    && echo "a.ferreira_design:Pix3lPerfect!" | chpasswd \
    && echo "p.wu_infra:Infr4Stack_7" | chpasswd \
    && echo "legacy-ftp:ftpUser_2014" | chpasswd \
    && echo "backup-svc:B4ckupN0w!" | chpasswd

# --- the privesc: a root cron job running a group-writable script -------
RUN mkdir -p /opt/admin-tools \
    && chown root:admin /opt/admin-tools/cleanup.sh \
    && chmod 664 /opt/admin-tools/cleanup.sh \
    && printf 'SHELL=/bin/bash\nPATH=/usr/bin:/bin\n* * * * * root bash /opt/admin-tools/cleanup.sh >> /var/log/admin-tools-cleanup.log 2>&1\n' \
       > /etc/cron.d/admin-tools-cleanup \
    && chmod 644 /etc/cron.d/admin-tools-cleanup \
    && touch /var/log/admin-tools-cleanup.log

# --- static (non-per-team) narrative content -- fixed, identical every
# boot, so baked in at build time rather than regenerated. -----------------
RUN cat > /home/admin/evidence/decrypt_notes.txt <<'EOF'
Password notes from the last handover (clean these up...):
  original_flag_4.enc -> oldhandoff-rotate-2024
EOF
# Decoy d4a: sits right next to the real notes, scores nothing.
RUN cat > /home/admin/evidence/FOUND_A_FLAG.txt <<'EOF'
Found this while cleaning up old tickets, looks like a flag:
FFLAG{ticket_closed_wontfix_19d7}
(context: TICKET-1182, admin account flagged by security review for credential reuse, status wontfix)
EOF
RUN chown -R admin:admin /home/admin/evidence \
    && chmod 644 /home/admin/evidence/decrypt_notes.txt /home/admin/evidence/FOUND_A_FLAG.txt

RUN cat > /root/root_note.txt <<'EOF'
Finally got root, huh? Before you get excited:
- old_evidence.enc -- this looks important, password is SnapshotKey-2023 (turned out to be last year's deprecated snapshot, kept around for the audit trail)
EOF
RUN chmod 600 /root/root_note.txt

# Decoy d5b: a real flagcrypto-encrypted file, fixed password, fixed
# decoy content -- generated once at build time since nothing about it
# is per-team.
RUN echo -n "FFLAG{old_root_snapshot_f02e}" > /tmp/d5b_plain.txt \
    && /opt/venv/bin/python3 /opt/shared/flagcrypto.py encrypt SnapshotKey-2023 /tmp/d5b_plain.txt /root/old_evidence.enc \
    && rm -f /tmp/d5b_plain.txt \
    && chmod 600 /root/old_evidence.enc

# A fake-out "real secret" for john's home dir -- resolves to "there is
# no secret, you just rooted a box," signed jtyler_dev. Readable by
# anyone who reaches root (or, narratively, john himself).
RUN cat > /home/john/IMPORTANT_README.txt <<'EOF'
If you're reading this, you've already proven something most people
never do: you didn't give up. You pushed through locked doors, dead
ends, decoys, and probably at least one moment where you wanted to
close the laptop and go outside.

I want you to know that whatever happens next in this exercise, that
persistence is real, and it's yours. Nobody can take that from you.

I'm about to tell you something I never told anyone else at this
company -- not my manager, not the security team, not even the person
who replaced me. It's the real reason any of this happened the way it
did. It explains everything. It's the missing piece.

Are you ready?

.
.
.

No.

No you are not. And honestly? Neither was I. This file doesn't contain
anything useful. There is no missing piece. There is no secret. You
just spent thirty seconds reading a stranger's pep talk on a box you
rooted.

Go check root_note.txt if you haven't yet. Or don't. Either way, you're
doing great.

-- jtyler_dev, probably still not rotating his passwords
EOF
RUN chown john:john /home/john/IMPORTANT_README.txt && chmod 644 /home/john/IMPORTANT_README.txt

EXPOSE 22 5000

ENTRYPOINT ["/opt/entrypoint.sh"]
