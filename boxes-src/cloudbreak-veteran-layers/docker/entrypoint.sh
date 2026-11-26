#!/bin/bash
set -e

: "${CTF_SECRET:?CTF_SECRET must be set}"
export CTF_SECRET

flag() { /opt/venv/bin/python3 /opt/app/generate_flags.py "$1"; }

echo "[*] Bringing up Nimbus Freight CI build-artifact server..."

# --- The layer-archaeology mechanic, simplified honestly --------------
# A real `docker save`/`docker load` round-trip (or a nested Docker
# daemon just to produce one tarball) is too heavy for a single box, so
# this entrypoint synthesizes the SAME kind of artifact by hand: a plain
# tar containing several numbered layer directories, each one a snapshot
# of a small filesystem tree -- genuinely mimicking Docker's own real
# OverlayFS layer-diff convention, not inventing a fake one:
#   - a file a layer ADDS just exists as a plain file in that layer's
#     own directory (layer-0N/path/to/file);
#   - a file a LATER layer "DELETES" is represented the real Docker/OCI
#     way -- a zero-length file named ".wh.<filename>" sitting next to
#     where the original lived (the actual "AUFS whiteout" convention
#     the OCI image spec documents and `docker save` itself produces in
#     its layer tars -- not an invented stand-in).
# A naive linear extraction of the WHOLE tarball in layer order (later
# layers' whiteouts removing earlier layers' files, the way a real
# OverlayFS mount would present the final merged filesystem) would never
# show a whited-out file. But the tarball's individual layer directories
# are each still sitting there untouched -- so opening layer-01/ by
# itself still has the "deleted" secret. That's the actual puzzle: look
# at the numbered layers themselves, not just the final merged state.
BUILD_ROOT="/tmp/nimbus-build"
rm -rf "$BUILD_ROOT"
mkdir -p "$BUILD_ROOT"

DEPLOY_SECRET_VALUE="$(flag 5)"

# layer-00: base rootfs snapshot. Nothing interesting -- just confirms
# the numbering convention starts at the bottom of the stack.
mkdir -p "$BUILD_ROOT/layer-00/etc/nimbus"
cat << EOF > "$BUILD_ROOT/layer-00/etc/nimbus/README.txt"
Nimbus Freight CI build base image.
This is layer-00, the base rootfs snapshot this build started from.
EOF

# layer-01: an early build step adds the deploy secret. This is the
# flag-5 headline: the real secret, sitting in an early layer.
mkdir -p "$BUILD_ROOT/layer-01/etc/nimbus"
cat << EOF > "$BUILD_ROOT/layer-01/etc/nimbus/deploy-secrets.env"
# Nimbus Freight CI -- deploy secrets (added by build step 1)
DEPLOY_API_KEY=${DEPLOY_SECRET_VALUE}
EOF

# layer-02: a middle build step adds a pipeline config file that
# references where the secret lived -- the flag-4 hint pointing at the
# exact path that gets whited out two layers later.
mkdir -p "$BUILD_ROOT/layer-02/etc/nimbus"
cat << EOF > "$BUILD_ROOT/layer-02/etc/nimbus/build.conf"
# Nimbus Freight CI pipeline config (build step 2)
ARTIFACT_VERSION=2026.10.3
# secrets_path was wired up to /etc/nimbus/deploy-secrets.env here --
# that file gets removed in a later "security cleanup" build step, but
# removing a file in a later layer doesn't touch THIS layer's own copy
# of the path it referenced.

# Flag 4: $(flag 4)
EOF

# layer-03: the "security cleanup" build step. Whites out the secrets
# file -- a real OverlayFS/Docker whiteout marker, not a deletion of the
# earlier layer's own copy (which is still sitting in layer-01/ above).
mkdir -p "$BUILD_ROOT/layer-03/etc/nimbus"
touch "$BUILD_ROOT/layer-03/etc/nimbus/.wh.deploy-secrets.env"
cat << 'EOF' > "$BUILD_ROOT/layer-03/etc/nimbus/CHANGELOG-internal.txt"
Security cleanup pass: removed deploy-secrets.env before shipping to
prod (ticket OPS-881). Final merged image no longer shows this file.
EOF

# layer-04: the latest/top layer -- a simple build-info stamp, just to
# confirm a player is actually opening the tar and reading individual
# layer directories correctly before the real puzzle underneath.
mkdir -p "$BUILD_ROOT/layer-04/var/nimbus"
cat << EOF > "$BUILD_ROOT/layer-04/var/nimbus/build-info.txt"
Nimbus Freight CI Build Artifact
Build: 2026.10.3 (final layer)
This is the top layer of the exported build image.

Flag 3: $(flag 3)
EOF

ARTIFACT_DIR="/opt/app/static/artifacts"
mkdir -p "$ARTIFACT_DIR"
( cd "$BUILD_ROOT" && tar -cf "$ARTIFACT_DIR/nimbus-build-artifact.tar" layer-00 layer-01 layer-02 layer-03 layer-04 )
rm -rf "$BUILD_ROOT"

# --- Linux account (SSH foothold) --------------------------------------
# The DEPLOY_API_KEY value recovered from layer-01 above doubles as this
# account's SSH password -- recovering flag 5 IS recovering the
# credential, not a separate narrative password.
if ! id ci-bot &>/dev/null; then
    useradd -m -s /bin/bash ci-bot
fi
echo "ci-bot:${DEPLOY_SECRET_VALUE}" | chpasswd
mkdir -p /run/sshd
ssh-keygen -A

# A simplified stand-in for a real OpenSSH /etc/motd banner: a plain
# file read right after SSH login succeeds, rather than wiring up real
# PAM/motd session machinery (which depends on pty allocation and isn't
# reliably shown for a non-interactive `ssh host cmd`) -- same kind of
# honest simplification as this project's other hand-rolled stand-ins
# for real infrastructure.
cat << EOF > /etc/nimbus-ci-welcome.txt
Nimbus Freight CI runner -- authenticated session confirmed.

Flag 6: $(flag 6)
EOF
chmod 644 /etc/nimbus-ci-welcome.txt

HOME_DIR="/home/ci-bot"
echo "$(flag 7)" > "$HOME_DIR/user.txt"
cat << 'EOF' > "$HOME_DIR/notes.txt"
To-do:
- Ops left me passwordless sudo on 'awk' for a one-off log-reformatting
  script, ages ago. Never got around to asking for anything narrower.
EOF
chown -R ci-bot:ci-bot "$HOME_DIR"
chmod 600 "$HOME_DIR/user.txt"
chmod 644 "$HOME_DIR/notes.txt"

# --- A root-only file, reachable via the 'awk' GTFOBins trick ----------
# --- before going for a full root shell (flag 8) ------------------------
cat << EOF > /var/log/ci-pipeline-audit.log
[audit] deploy-secrets.env removal didn't scrub it from the build's
        earlier layer -- it's still sitting in layer-01/ of every
        exported artifact
[audit] ci-bot's sudo awk rule has never been scoped down

Flag 8: $(flag 8)
EOF
chown root:root /var/log/ci-pipeline-audit.log
chmod 600 /var/log/ci-pipeline-audit.log

# --- sudoers: ci-bot may run 'awk' as root, no password -----------------
cat << 'EOF' > /etc/sudoers.d/ci-bot
ci-bot ALL=(ALL) NOPASSWD: /usr/bin/awk
EOF
chmod 440 /etc/sudoers.d/ci-bot

# --- Post-escalation checkpoint (flag 9) + final root flag (flag 10) ---
mkdir -p /root
cat << EOF > /root/decommission_notes.txt
This build pipeline is getting replaced next quarter. Nobody's gone
back through old exported artifacts to check whether "removed" secrets
are still sitting in their original layers -- which is probably how you
got this far.

Flag 9: $(flag 9)
EOF
chmod 600 /root/decommission_notes.txt

echo "$(flag 10)" > /root/root.txt
chmod 600 /root/root.txt

echo "[*] cloudbreak-veteran-layers ready."
mkdir -p /var/log/supervisor
exec /usr/bin/supervisord -c /etc/supervisor/conf.d/ctf.conf
