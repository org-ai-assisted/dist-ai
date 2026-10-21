#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## install-host must WAIT for the unrestricted-admin unlock before elevating.
##
## On a live ISO booted boot-role=unrestricted-admin, check-unrestricted-admin.service
## purges user-sysmaint-split (slow apt), which restores sudo/pkexec to setuid root:root.
## The autologin desktop appears before that finishes, so install-host raced it and
## died "Unable To Elevate". The fix: install-host sources the sanctioned helper-scripts
## readiness wait (try-wait-for-system-ready, which polls 'leaprun system-ready-check' on a
## monotonic deadline) and CALLS it before the elevation assert -- it does NOT start the
## unit and does NOT busy-poll.
##
## This pins that contract:
##   - a CODE line sources the try-wait-for-system-ready helper, and a CODE line calls
##     try_wait_for_system_ready (matched on non-comment lines only -- install-host's own
##     explanatory comment names the wait, so a bare substring over the whole file would
##     false-pass if the call were removed but the comment kept);
##   - the call runs BEFORE the pkexec/sudo elevation assert;
##   - the superseded elevate_deadline busy-poll band-aid and the --user readiness variant
##     are gone.
##
## Static contract check (no root, no network, no sourcing).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v LIVE_CONFIG_DIST_REPO ] || LIVE_CONFIG_DIST_REPO=""
if [ -n "${LIVE_CONFIG_DIST_REPO}" ]; then
   subject="${LIVE_CONFIG_DIST_REPO}/usr/bin/install-host"
else
   subject='/usr/bin/install-host'
fi

if [ ! -r "${subject}" ]; then
   printf '%s\n' "FATAL: subject not readable at '${subject}'" >&2
   printf '%s\n' "set LIVE_CONFIG_DIST_REPO to a live-config-dist checkout, or install live-config-dist" >&2
   exit 1
fi

fail=0

## '<lineno>:<text>' for lines matching the ERE that are NOT full-line comments. Anchoring to
## code avoids matching install-host's own comments (which name these same tokens). '|| true'
## keeps a no-match from tripping errexit/pipefail.
code_lines() {
   grep -nE -- "$1" "${subject}" | grep --invert-match -E '^[0-9]+:[[:space:]]*#' || true
}

assert_code_present() {
   local re="$1" why="$2"
   if [ -n "$(code_lines "${re}")" ]; then
      printf '%s\n' "ok: present -- ${why}"
   else
      printf '%s\n' "FAIL: no code line matches /${re}/ -- ${why}" >&2
      fail=1
   fi
}

assert_code_absent() {
   local re="$1" why="$2"
   if [ -z "$(code_lines "${re}")" ]; then
      printf '%s\n' "ok: absent -- ${why}"
   else
      printf '%s\n' "FAIL: code line matches /${re}/ -- ${why}" >&2
      fail=1
   fi
}

## Match the call at COMMAND position (line start, after indentation), so neither a
## near-miss rename (try_wait_for_system_ready_extra) nor an assignment value
## (foo=try_wait_for_system_ready) satisfies the "wait is called" contract.
fn_call='^[[:space:]]*try_wait_for_system_ready([^[:alnum:]_]|$)'

assert_code_present 'source .*/try-wait-for-system-ready' 'sources the sanctioned helper-scripts system-ready wait'
assert_code_present "${fn_call}" 'calls the system-ready wait before elevating (via leaprun system-ready-check, not --user, not systemctl start)'
assert_code_present 'boot-role=unrestricted-admin' 'the unlock wait is gated on the unrestricted-admin boot-role'
assert_code_absent 'elevate_deadline' 'the superseded 180s busy-poll band-aid is gone'
assert_code_absent 'systemctl --user' 'the --user readiness variant is not used for a system unit'

## Ordering: the readiness wait must run BEFORE the pkexec/sudo elevation assert, otherwise it
## cannot prevent the race it exists to close.
call_line="$(code_lines "${fn_call}" | head -n1 | cut -d: -f1)"
assert_line="$(grep -nF -- "[ -x '/usr/bin/pkexec' ]" "${subject}" | head -n1 | cut -d: -f1 || true)"
if [ -n "${call_line}" ] && [ -n "${assert_line}" ] && [ "${call_line}" -lt "${assert_line}" ]; then
   printf '%s\n' "ok: readiness wait (line ${call_line}) precedes the elevation assert (line ${assert_line})"
else
   printf '%s\n' "FAIL: readiness wait must precede the elevation assert (wait=${call_line:-none} assert=${assert_line:-none})" >&2
   fail=1
fi

printf '%s\n' ""
if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "unrestricted_admin_unlock_wait: FAIL"
   exit 1
fi
printf '%s\n' "unrestricted_admin_unlock_wait: PASS"
exit 0
