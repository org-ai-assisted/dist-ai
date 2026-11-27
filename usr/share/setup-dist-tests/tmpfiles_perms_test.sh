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
## group or other write, OR if the mode/owner is left unspecified ('-'):
## systemd only applies a default on creation and preserves an existing dir's
## mode/owner, so an explicit safe mode and explicit root owner are required to
## enforce the property idempotently.
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

## True (rc 0) if a tmpfiles mode does NOT enforce safe, root-only-writable
## perms on this dir: an unspecified '-', an unparseable mode, or an explicit
## octal granting group/other write. A security-sensitive dir needs an EXPLICIT
## safe octal: with '-' systemd leaves mode_set false and sets the mode only on
## CREATION, preserving an existing dir's perms, so a pre-set 0777 is never
## corrected. Only an explicit non-group/other-write octal enforces idempotently.
mode_not_safe_enforced() {
   local mode="$1"
   if [ "${mode}" = "-" ]; then
      ## Unspecified: not enforced on an existing dir -- require explicit octal.
      return 0
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

## True (rc 0) if a tmpfiles owner field does NOT enforce root ownership: a
## non-root name, OR an unspecified '-'. With '-' systemd leaves uid_set false
## and preserves an existing dir's owner, so a pre-existing non-root (e.g. UID
## 1000) owner is never corrected and can still plant .done/.skip. Only an
## explicit 'root'/'0' enforces root ownership idempotently.
owner_not_root_enforced() {
   local owner="$1"
   case "${owner}" in
      root|0)
         return 1
         ;;
      *)
         return 0
         ;;
   esac
}

## Self-canary: neither checker may green a bad conf, so prove each flags the
## unsafe cases and passes the safe ones before trusting it on the real conf.
for safe_mode in 0755 0700; do
   if mode_not_safe_enforced "${safe_mode}"; then
      printf '%s\n' "FAIL: checker flagged safe mode ${safe_mode}" >&2
      exit 1
   fi
done
## '-' is unenforced on an existing dir (systemd preserves perms), so it must be
## flagged as unsafe, not waved through as a safe default.
for bad_mode in 0775 0757 0777 0070 -; do
   if ! mode_not_safe_enforced "${bad_mode}"; then
      printf '%s\n' "FAIL: checker missed unenforced/writable mode ${bad_mode}" >&2
      exit 1
   fi
done
for root_owner in root 0; do
   if owner_not_root_enforced "${root_owner}"; then
      printf '%s\n' "FAIL: owner checker flagged root owner ${root_owner}" >&2
      exit 1
   fi
done
## '-' preserves an existing dir's owner (unenforced), so it must be flagged.
for bad_owner in user nobody 1000 -; do
   if ! owner_not_root_enforced "${bad_owner}"; then
      printf '%s\n' "FAIL: owner checker missed unenforced/non-root owner ${bad_owner}" >&2
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
## Field 3 is the mode, field 4 the owner. An omitted/`-` field is NOT a safe
## default here: systemd only applies the default on creation and preserves an
## existing dir's mode/owner, so this security-sensitive dir must declare both
## explicitly. ${n:--} maps a short line to '-', which the checks then reject.
mode="${3:--}"
owner="${4:--}"

if mode_not_safe_enforced "${mode}"; then
   printf '%s\n' "FAIL: ${conf} declares ${status_files_dir} mode ${mode} (not an enforced root-only mode)" >&2
   exit 1
fi

## Enforced root ownership is half the property: a non-root owner of a 0755 dir
## can still plant .done/.skip.
if owner_not_root_enforced "${owner}"; then
   printf '%s\n' "FAIL: ${conf} declares ${status_files_dir} owner ${owner} (not enforced root)" >&2
   exit 1
fi

printf '%s\n' "PASS: ${status_files_dir} declared mode ${mode} owner ${owner} (explicit root-owned, no group/other write)"
exit 0
