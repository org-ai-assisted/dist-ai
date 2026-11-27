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
   if [ "${mode}" = "-" ]; then
      ## '-' = systemd's default mode (0755 for a 'd' entry); root-write only.
      return 1
   fi
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

## True (rc 0) if a tmpfiles owner field names a non-root user. '-'/'0'/'root'
## all resolve to root for a root-run 'd' entry.
owner_is_nonroot() {
   local owner="$1"
   case "${owner}" in
      root|0|-)
         return 1
         ;;
      *)
         return 0
         ;;
   esac
}

## Self-canary: neither checker may green a bad conf, so prove each flags the
## unsafe cases and passes the safe ones before trusting it on the real conf.
for safe_mode in 0755 0700 -; do
   if mode_grants_group_or_other_write "${safe_mode}"; then
      printf '%s\n' "FAIL: checker flagged safe mode ${safe_mode}" >&2
      exit 1
   fi
done
for bad_mode in 0775 0757 0777 0070; do
   if ! mode_grants_group_or_other_write "${bad_mode}"; then
      printf '%s\n' "FAIL: checker missed writable mode ${bad_mode}" >&2
      exit 1
   fi
done
for root_owner in root 0 -; do
   if owner_is_nonroot "${root_owner}"; then
      printf '%s\n' "FAIL: owner checker flagged root owner ${root_owner}" >&2
      exit 1
   fi
done
for bad_owner in user nobody 1000; do
   if ! owner_is_nonroot "${bad_owner}"; then
      printf '%s\n' "FAIL: owner checker missed non-root owner ${bad_owner}" >&2
      exit 1
   fi
done

## The tmpfiles directory entry for the status-files dir. Types d/D/z/Z all
## carry a mode in field 3 and apply it to the directory.
##
## Scope: guards OUR shipped one-line conf against a realistic regression (a
## widened mode or a non-root owner on the 'd' line). It is NOT a full systemd
## tmpfiles parser: crafted multi-line evasion (a second glob z/Z, an a+ ACL
## line, exotic types e/q/v, quoted fields) is out of scope -- our conf is a
## single plain 'd' line and will stay one.
line="$(grep --extended-regexp "^[dDzZ][[:space:]]+${status_files_dir}([[:space:]]|\$)" -- "${conf}" || true)"

if [ -z "${line}" ]; then
   printf '%s\n' "FAIL: no d/z tmpfiles entry for ${status_files_dir} in ${conf}" >&2
   exit 1
fi

# shellcheck disable=SC2086
set -- ${line}
## Field 3 is the mode, field 4 the owner; an omitted/`-` field means the
## systemd default (mode 0755, owner root), both safe. ${n:--} also avoids a
## set -u abort on a short line.
mode="${3:--}"
owner="${4:--}"

if mode_grants_group_or_other_write "${mode}"; then
   printf '%s\n' "FAIL: ${conf} declares ${status_files_dir} mode ${mode} (group/world-writable)" >&2
   exit 1
fi

## Root-owned is half the property: a non-root owner of a 0755 dir can still
## plant .done/.skip.
if owner_is_nonroot "${owner}"; then
   printf '%s\n' "FAIL: ${conf} declares ${status_files_dir} owner ${owner} (not root)" >&2
   exit 1
fi

printf '%s\n' "PASS: ${status_files_dir} declared mode ${mode} owner ${owner} (root-owned, no group/other write)"
exit 0
