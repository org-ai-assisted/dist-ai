#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Drift guard: dm-calamares-install's story-capture GUI/SuppressMessages list and vbox-host-shot's
## MUST stay identical -- both grab the same VirtualBox GUI surfaces (window frontend / Manager), so
## a popup one suppresses and the other does not rides straight into a published frame. That exact
## drift (vbox-host-shot suppressed showRuntimeError.warning.HostAudioNotResponding +
## confirmGoingFullscreen; the lane's list did not) let the "non-fatal problem" (HostAudioNotResponding)
## modal be grim-grabbed into firmware-logo. This FAILS if the two lists diverge as sets, and
## separately asserts the runtime-warning suppression is present in both.
## Reads the REAL installed/checkout scripts -- no copies. Exit: 0 pass | 1 fail.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

resolve() {
   ## $1 = env override var value, $2.. = fallback candidate paths. Prints the first executable.
   local cand
   for cand in "$@"; do
      [ -n "${cand}" ] || continue
      if [ -x "${cand}" ]; then
         readlink --canonicalize -- "${cand}"
         return 0
      fi
   done
   return 1
}

lane="$(resolve "${DM_CALAMARES_INSTALL:-}" \
   "${test_dir}/../../bin/dm-calamares-install" "/usr/bin/dm-calamares-install")" \
   || { printf '%s\n' "FATAL: dm-calamares-install not found (set DM_CALAMARES_INSTALL)." >&2; exit 1; }
shot="$(resolve "${VBOX_HOST_SHOT:-}" \
   "${test_dir}/../../bin/vbox-host-shot" "/usr/bin/vbox-host-shot")" \
   || { printf '%s\n' "FATAL: vbox-host-shot not found (set VBOX_HOST_SHOT)." >&2; exit 1; }

pass=0
fail=0
check() {
   if [ "$2" -eq 0 ]; then
      pass=$(( pass + 1 ))
      printf '%s\n' "PASS: $1"
   else
      fail=$(( fail + 1 ))
      printf '%s\n' "FAIL: $1"
   fi
}

## Print "0" if the given command succeeds, "1" otherwise (feeds check's int arg without echo).
yn() {
   if "$@"; then printf '%s' 0; else printf '%s' 1; fi
}

## 0 if $2 is a whole line within the newline-delimited set $1, else 1. while-read over a
## here-string: no grep consuming a pipe (R-161), no subshell.
in_set() {
   local line
   while IFS= read -r line; do
      [ "${line}" = "$2" ] && return 0
   done <<< "$1"
   return 1
}

## Extract the single comma-list value handed to `setextradata global GUI/SuppressMessages`: the one
## list line carries the canonical marker token (remindAboutAutoCapture); the restore call sites pass
## no value. Pull the content between the first and matching double quotes on that line.
extract_list() {
   grep -m1 -- 'remindAboutAutoCapture' "$1" | sed -E 's/^[^"]*"([^"]*)".*/\1/'
}

## Set-normalize (split on commas, sort, drop blanks) so order never matters.
normalize_set() {
   printf '%s' "$1" | tr ',' '\n' | sed '/^$/d' | sort -u
}

lane_list="$(extract_list "${lane}")"
shot_list="$(extract_list "${shot}")"

check "lane suppress list is non-empty" "$(yn test -n "${lane_list}")"
check "vbox-host-shot suppress list is non-empty" "$(yn test -n "${shot_list}")"

lane_set="$(normalize_set "${lane_list}")"
shot_set="$(normalize_set "${shot_list}")"

if [ "${lane_set}" = "${shot_set}" ]; then
   check "story-capture and vbox-host-shot suppress the SAME message set" 0
else
   check "story-capture and vbox-host-shot suppress the SAME message set" 1
   printf '%s\n' "  only in dm-calamares-install:" >&2
   comm -23 <(printf '%s\n' "${lane_set}") <(printf '%s\n' "${shot_set}") | sed 's/^/    /' >&2
   printf '%s\n' "  only in vbox-host-shot:" >&2
   comm -13 <(printf '%s\n' "${lane_set}") <(printf '%s\n' "${shot_set}") | sed 's/^/    /' >&2
fi

## The specific regression: the HostAudioNotResponding runtime warning (the popup that was captured)
## must be suppressed in BOTH -- a guard that survives even if the full lists are later trimmed.
rt='showRuntimeError.warning.HostAudioNotResponding'
check "lane suppresses ${rt}" "$(yn in_set "${lane_set}" "${rt}")"
check "vbox-host-shot suppresses ${rt}" "$(yn in_set "${shot_set}" "${rt}")"

printf '%s\n' "${pass} pass, ${fail} fail, 0 skip"
[ "${fail}" -eq 0 ]
