#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## style-ok: no-has -- runs in bare distro CI containers, before helper-scripts
## is installed.

## CI setup: bring tor up. On apt-based images 'service' works; dnf-based
## images have no working init in the container, so the systemd/systemctl
## attempts are best-effort (tolerated failures).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

if command -v apt-get; then
   service tor start
   service tor status
elif command -v dnf; then
   ## 'service' not available on Fedora; systemd is not PID 1 in the container
   ## ("System has not been booted with systemd as init system"), so these are
   ## best-effort only.
   /lib/systemd/systemd --system || true
   /usr/sbin/init || true
   systemctl enable --now tor || true
   systemctl start tor || true
   systemctl status tor || true
fi
