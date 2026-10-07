#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## style-ok: no-has -- runs in bare distro CI containers, before helper-scripts
## is installed.

## CI setup: install the packages the installer test run needs, across the
## apt- and dnf-based images in the build matrix.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

if command -v apt-get; then
   apt-get update --error-on=any
   ## Installer aborts if package upgrades are pending.
   apt-get dist-upgrade --yes
   apt-get install --yes shellcheck sudo adduser tor locales
   ## Enable the ru_RU.UTF-8 locale the installer tests exercise. Debian workflow:
   ## uncomment it in /etc/locale.gen, then generate. No '|| true' -- a failure
   ## here must abort, not silently leave the tests running without the locale.
   sed -i 's/^# \(ru_RU.UTF-8 UTF-8\)$/\1/' /etc/locale.gen
   locale-gen
elif command -v dnf; then
   dnf upgrade --assumeyes
   ## Fedora has no locale-gen workflow; glibc-langpack-ru ships ru_RU.UTF-8.
   dnf install --assumeyes ShellCheck sudo tor systemd gawk glibc-langpack-ru
   ## Debugging.
   dnf provides needs-restarting
else
   exit 1
fi

## Fail LOUDLY if the locale the tests need is absent, on either image. The old
## code masked both distro paths behind '|| true', so Fedora silently ran the
## locale-dependent tests with no ru_RU.UTF-8 at all.
if ! locale -a | grep --ignore-case --extended-regexp '^ru_RU\.utf-?8$' >/dev/null; then
   printf '%s\n' 'ERROR: ru_RU.UTF-8 locale not available after setup' >&2
   exit 1
fi
