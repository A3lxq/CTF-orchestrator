#!/bin/bash
# Login shell for the 8 honeypot accounts -- their passwords genuinely
# work for SSH password auth, but the only thing waiting on the other
# end is this. Ignores SIGINT at this level (without this, Ctrl-C kills
# the script before the punchline prints -- the documented way to
# dismiss cmatrix is any regular keystroke, which "-s" screensaver mode
# already handles). Never reads its own argv ($0/$@/"$*" appear nowhere
# below), so this can't become a command-execution path even via
# `ssh user@host 'some command'` (sshd runs the configured shell with
# `-c '<command>'` for a non-interactive session -- ignoring argv
# entirely closes that off completely, not just for an interactive
# login).
trap '' INT
cmatrix -abs || true
echo
echo "Access revoked. This account's credentials were deactivated"
echo "when its owner left SynHub. Nice try though."
exit 0
