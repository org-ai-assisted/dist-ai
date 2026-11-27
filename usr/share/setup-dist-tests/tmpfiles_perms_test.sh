#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## style-ok: R-003 - 3-space to match the setup-dist-tests suite

## Regression guard: the tmpfiles.d entry that owns
## /var/cache/setup-dist/status-files must declare it root-owned and NOT
## group/world-writable. The "setup done" markers there are written by root
## via privleap; a group/world-writable directory would let any local user
## plant a .done/.skip and skip the wizard. Fails if the declared mode grants
## group or other write.
##
## Subject: the shipped tmpfiles conf. Set SETUP_DIST_REPO to a checkout, else
## the installed package. No root, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v SETUP_DIST_REPO ] || SETUP_DIST_REPO=""

status_files_dir='/var/cache/setup-dist/status-files'

if [ -n "${SETUP_DIST_REPO}" ]; then
   conf="${SETUP_DIST_REPO}/usr/lib/tmpfiles.d/setup-dist.conf"
else
   conf='/usr/lib/tmpfiles.d/setup-dist.conf'
fi

if [ ! -r "${conf}" ]; then
   printf '%s\n' "FATAL: setup-dist tmpfiles conf not found at '${conf}'" >&2
   printf '%s\n' "set SETUP_DIST_REPO to a checkout, or install the package" >&2
   exit 1
fi

## True (rc 0) if an octal tmpfiles mode grants write to group or other.
mode_grants_group_or_other_write() {
   local mode="$1"
   ## Strip a leading tmpfiles mode modifier ('~' mask, ':' only-on-create).
   mode="${mode#[~:]}"
   if [[ ! "${mode}" =~ ^[0-7]{3,4}$ ]]; then
      ## Unparseable mode: flag rather than wave it through.
      return 0
   fi
   local group_digit="${mode: -2:1}"
   local other_digit="${mode: -1}"
   if (( (8#${group_digit} & 2) != 0 || (8#${other_digit} & 2) != 0 )); then
      return 0
   fi
   return 1
}

## Self-canary: the checker must flag a world/group-writable mode and pass a
## safe one, so a broken checker cannot green a bad conf.
if mode_grants_group_or_other_write '0755'; then
   printf '%s\n' "FAIL: checker flagged safe mode 0755" >&2
   exit 1
fi
for bad_mode in 0775 0757 0777 0070; do
   if ! mode_grants_group_or_other_write "${bad_mode}"; then
      printf '%s\n' "FAIL: checker missed writable mode ${bad_mode}" >&2
      exit 1
   fi
done

## The tmpfiles directory entry for the status-files dir. Types d/D/z/Z all
## carry a mode in field 3 and apply it to the directory.
line="$(grep --extended-regexp "^[dDzZ][[:space:]]+${status_files_dir}([[:space:]]|\$)" -- "${conf}" || true)"

if [ -z "${line}" ]; then
   printf '%s\n' "FAIL: no d/z tmpfiles entry for ${status_files_dir} in ${conf}" >&2
   exit 1
fi

# shellcheck disable=SC2086
set -- ${line}
mode="$3"

if mode_grants_group_or_other_write "${mode}"; then
   printf '%s\n' "FAIL: ${conf} declares ${status_files_dir} mode ${mode} (group/world-writable)" >&2
   exit 1
fi

printf '%s\n' "PASS: ${status_files_dir} declared ${mode} (no group/other write)"
exit 0
