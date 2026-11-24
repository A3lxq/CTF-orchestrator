#!/bin/bash
# Housekeeping, nothing more -- run every minute by root via
# /etc/cron.d/admin-tools-cleanup. THE vulnerability is not in this
# script's content, it's this file's own permission bits: owned
# root:admin, mode 664 (group-writable). The `admin` Linux account's
# primary group is `admin`, so admin can append to this file and have
# root execute whatever they add within a minute -- see the Dockerfile
# for the exact chown/chmod, and instructor notes for the intended
# discovery path (enumerate /etc/cron.d/, notice this script is
# group-writable, append a payload, wait for the next tick).
mkdir -p /var/cache/admin-tools
find /var/cache/admin-tools -mtime +1 -delete
