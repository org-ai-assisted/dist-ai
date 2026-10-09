#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## dm-calamares-install (dist-ai's release install gate) must launch exactly what a
## user's click on the live desktop's installer launcher runs: the Exec= line of
## live-config-dist's install-host.desktop. If the two diverge, the gate exercises an
## entry point users never reach and its PASS says nothing about the real one.
##
## Sources the real dm-calamares-install (INSTALL_HOST_CMD) and reads the real
## desktop file from LIVE_CONFIG_DIST_REPO (else the installed package). No root,
## no network, no VM.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v LIVE_CONFIG_DIST_REPO ] || LIVE_CONFIG_DIST_REPO=""

test_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

subject="${DM_CALAMARES_INSTALL_BIN:-}"
if [ -z "${subject}" ]; then
   if [ -f "${test_dir}/../../bin/dm-calamares-install" ]; then
      subject="${test_dir}/../../bin/dm-calamares-install"
   else
      subject='/usr/bin/dm-calamares-install'
   fi
fi
[ -r "${subject}" ] || { printf '%s\n' "FATAL: dm-calamares-install not found at '${subject}'" >&2; exit 1; }

desktop_file="${LIVE_CONFIG_DIST_REPO:-}/usr/share/applications/install-host.desktop"
[ -r "${desktop_file}" ] || { printf '%s\n' "FATAL: install-host.desktop not found at '${desktop_file}'" >&2; exit 1; }

# shellcheck source=../../bin/dm-calamares-install
source "${subject}"

## Exec= of the [Desktop Entry] group (an [Desktop Action ...] group has its own Exec).
desktop_exec="$(awk '
   /^\[/ { in_entry = ($0 == "[Desktop Entry]") }
   in_entry && /^Exec=/ { sub(/^Exec=/, ""); print; exit }
' "${desktop_file}")"

if [ -z "${desktop_exec}" ]; then
   printf '%s\n' "FAIL: no Exec= in the [Desktop Entry] group of '${desktop_file}'" >&2
   exit 1
fi
if [ "${INSTALL_HOST_CMD}" != "${desktop_exec}" ]; then
   printf '%s\n' "FAIL: dm-calamares-install launches '${INSTALL_HOST_CMD}', but install-host.desktop runs '${desktop_exec}'" >&2
   exit 1
fi
printf '%s\n' "ok: dm-calamares-install launches the desktop launcher's command '${desktop_exec}'"
