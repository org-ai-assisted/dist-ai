#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression: a CORRUPT / unreadable capture must never be ACCEPTED as a valid shot
## (silent-green). Two coupled defects, same class as the shipped-1x1 leak:
##   1. shots_shot_is_blank FAILED OPEN -- `convert ... || printf '0'` made a convert failure on
##      an unreadable PNG read as "not blank", so the caller accepted the corrupt shot. Fixed to
##      fail CLOSED (an unreadable grab is treated as blank -> re-grab/discard).
##   2. capture_settled left a STALE dest on the capture_window-failure path, so the caller's
##      `[ -f dest ]` check accepted a leftover file as a fresh shot. Fixed to remove dest on
##      every failure, so capture_settled leaves a file ONLY on success.
##
## Sources comparison-capture.sh (source-safe) for capture_settled + shots_shot_is_blank, stubs
## capture_window / tighten_deadspace / sleep. ImageMagick convert is REQUIRED (exit 1, R-220).
##
## Canary: revert shots_shot_is_blank to `|| printf '0'` and arms 1+3 fail; drop the safe-rm on
## capture_settled's capture_window-failure path and arm 2 fails.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

subject=''
for cand in \
   "${SECURE_TERMINAL_SHOTS_DIR:-}/comparison-capture.sh" \
   "${script_dir}/../secure-terminal-shots/comparison-capture.sh" \
   "${script_dir}/../../share/secure-terminal-shots/comparison-capture.sh" \
   '/usr/share/secure-terminal-shots/comparison-capture.sh'; do
   if [ -f "${cand}" ]; then
      subject="$(readlink --canonicalize -- "${cand}")"
      break
   fi
done
if [ -z "${subject}" ]; then
   printf '%s\n' 'FATAL: comparison-capture.sh not found (set SECURE_TERMINAL_SHOTS_DIR)' >&2
   exit 1
fi
if ! type -P convert >/dev/null 2>&1; then
   printf '%s\n' 'FATAL: ImageMagick convert not found (required to build/read shot fixtures)' >&2
   exit 1
fi

## Source the real script (source-safe: its was-executed guard runs no capture on source), so the
## tested functions are the CURRENT ones. Stubs below override its collaborators.
# shellcheck source=../secure-terminal-shots/comparison-capture.sh
source "${subject}"

work="$(mktemp --directory)"
cleanup() { safe-rm --recursive --force -- "${work}" 2>/dev/null || true; }
trap cleanup EXIT

## No real waiting between retries. (Stubs are invoked indirectly by the sourced capture_settled,
## which shellcheck cannot see -- SC2317.)
# shellcheck disable=SC2317
sleep() { :; }
## tighten is irrelevant here (only on the accept path) -- no-op.
# shellcheck disable=SC2317
tighten_deadspace() { :; }

pass=0
fail=0
check() {  ## $1=label $2=ok?(non-empty=pass)
   if [ -n "$2" ]; then
      printf '%s\n' "PASS: $1"; pass=$(( pass + 1 ))
   else
      printf '%s\n' "FAIL: $1"; fail=$(( fail + 1 ))
   fi
}

## ARM 1: shots_shot_is_blank on an unreadable file returns TRUE (blank) -- fail-CLOSED.
corrupt="${work}/corrupt.png"
printf 'this is not a PNG' > "${corrupt}"
rc=0; shots_shot_is_blank "${corrupt}" || rc=$?
check 'an unreadable/corrupt shot is treated as blank (fail-closed, rc 0)' "$([ "${rc}" -eq 0 ] && printf y)"

## a genuinely flat (black) shot is blank; a content shot is not -- the happy path still works.
convert -size 80x60 xc:black "${work}/flat.png"
rc=0; shots_shot_is_blank "${work}/flat.png" || rc=$?
check 'a flat black shot is blank' "$([ "${rc}" -eq 0 ] && printf y)"
convert -size 80x60 xc:black -fill white -draw 'rectangle 10,10 70,50' "${work}/content.png"
rc=0; shots_shot_is_blank "${work}/content.png" || rc=$?
check 'a content shot is NOT blank' "$([ "${rc}" -ne 0 ] && printf y)"

## ARM 2: capture_settled whose capture_window FAILS must leave NO dest (not a stale one).
dest2="${work}/st2.png"
convert -size 80x60 xc:red "${dest2}"   ## a stale leftover from a prior attempt
# shellcheck disable=SC2317  # invoked indirectly by the sourced capture_settled
capture_window() { return 1; }          ## this capture fails
rc=0; capture_settled "${dest2}" fakewid >/dev/null 2>&1 || rc=$?
check 'capture_settled returns non-zero when the grab fails' "$([ "${rc}" -ne 0 ] && printf y)"
check 'capture_settled removes the stale dest on a failed grab (no false-accept)' "$([ ! -e "${dest2}" ] && printf y)"

## ARM 3: capture_window "succeeds" but writes a CORRUPT file -> capture_settled must NOT accept
## it (retries, then discards), returning non-zero with no dest.
dest3="${work}/st3.png"
# shellcheck disable=SC2317  # invoked indirectly by the sourced capture_settled
capture_window() {
   printf 'garbage-not-a-png' > "$1"
}
rc=0; capture_settled "${dest3}" fakewid >/dev/null 2>&1 || rc=$?
check 'capture_settled does not accept a corrupt grab (rc non-zero)' "$([ "${rc}" -ne 0 ] && printf y)"
check 'capture_settled discards the corrupt grab (no dest)' "$([ ! -e "${dest3}" ] && printf y)"

printf '%s\n' '' "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   exit 1
fi
printf '%s\n' 'OK: a corrupt/unreadable grab is never accepted as a valid shot'
