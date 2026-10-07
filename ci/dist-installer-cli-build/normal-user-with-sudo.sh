#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## CI setup: create an unprivileged 'user' with passwordless sudo, so the
## installer runs as a normal user the way it does on a real system.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

if test -f /etc/debian_version; then
   ## Debian trixie needs "--comment"; older Debian needs "--gecos".
   adduser --comment "" --disabled-password user || adduser --gecos "" --disabled-password user
   usermod -aG sudo user
   printf '%s\n' "%sudo ALL=(ALL) NOPASSWD: ALL" | tee /etc/sudoers.d/user
elif test -f /etc/fedora-release; then
   adduser user
   usermod -aG wheel user
   printf '%s\n' "%wheel ALL=(ALL) NOPASSWD: ALL" | tee /etc/sudoers.d/user
else
   exit 1
fi

## The installer takes a per-user concurrency lock (helper-scripts lockfile.sh)
## that needs a runtime dir. A CI container has no logind session to create
## /run/user/<uid>, and 'sudo -u user' does not pass XDG_RUNTIME_DIR, so the
## installer falls back to /run/user/${EUID} -- which must exist and be owned by
## 'user'. Create it here (lockfile.sh documents that a pre-login caller must).
user_uid="$(id --user user)"
mkdir --parents -- "/run/user/${user_uid}"
chown user -- "/run/user/${user_uid}"
chmod 0700 -- "/run/user/${user_uid}"
