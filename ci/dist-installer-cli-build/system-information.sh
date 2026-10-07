#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## style-ok: no-has -- runs in bare distro CI containers, before helper-scripts
## is installed.

## CI debugging: dump OS, kernel, PATH, locale and apt/dnf repository
## configuration so a failing installer run can be diagnosed from the log.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

sep="--------------------"

cat /etc/os-release
printf '%s\n' "${sep}"
uname -a
printf '%s\n' "${sep}"
printf '%s\n' "${PATH}"
printf '%s\n' "${sep}"
## Diagnostics only -- never abort the dump: localedef --list-archive exits
## nonzero when the locale archive is absent (a bare image pre locale-gen).
localedef --list-archive || true
printf '%s\n' "${sep}"
locale || true
printf '%s\n' "${sep}"
if command -v apt-get >/dev/null; then
   for f in \
      /etc/apt/sources.list \
      /etc/apt/sources.list.d/*.list \
      /etc/apt/sources.list.d/*.sources
   do
      test -f "${f}" || continue
      printf '%s\n' "### ${f} ###" "$(cat "${f}")" "${sep}"
   done
elif command -v dnf >/dev/null; then
   for f in \
      /etc/yum.repos.d/*.repo
   do
      test -f "${f}" || continue
      printf '%s\n' "### ${f} ###" "$(cat "${f}")" "${sep}"
   done
fi
printf '%s\n' "${sep}"
