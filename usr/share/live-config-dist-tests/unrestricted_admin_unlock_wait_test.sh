#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## install-host must WAIT for the unrestricted-admin unlock before elevating.
##
## On a live ISO booted boot-role=unrestricted-admin, check-unrestricted-admin.service
## purges user-sysmaint-split (slow apt), which restores sudo/pkexec to setuid root:root.
## The autologin desktop appears before that finishes, so install-host raced it and
## died "Unable To Elevate". The fix: install-host waits for system-ready via the
## sanctioned system-wide helper-scripts action `leaprun system-ready-check` before the
## elevation assert -- it does NOT start the unit and does NOT busy-poll.
##
## This pins that contract:
##   - install-host invokes `leaprun system-ready-check` under a boot-role=unrestricted-admin
##     guard;
##   - the superseded 180s `elevate_deadline` busy-poll band-aid is gone.
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

content="$(cat -- "${subject}")"

fail=0

assert_contains() {
   local needle="$1" why="$2"
   if [[ "${content}" == *"${needle}"* ]]; then
      printf '%s\n' "ok: present -- ${why}"
   else
      printf '%s\n' "FAIL: missing '${needle}' -- ${why}" >&2
      fail=1
   fi
}

assert_absent() {
   local needle="$1" why="$2"
   if [[ "${content}" == *"${needle}"* ]]; then
      printf '%s\n' "FAIL: unexpected '${needle}' -- ${why}" >&2
      fail=1
   else
      printf '%s\n' "ok: absent -- ${why}"
   fi
}

## The wait: sanctioned system-wide readiness action, gated on the unrestricted-admin boot.
assert_contains 'boot-role=unrestricted-admin' 'unlock wait is gated on the unrestricted-admin boot-role'
assert_contains 'leaprun system-ready-check' 'waits via the system-wide system-ready-check action (not --user, not systemctl start)'

## No regressions: neither the superseded busy-poll band-aid nor a direct unit start.
assert_absent 'elevate_deadline' 'the 180s busy-poll band-aid must be gone'
assert_absent 'systemctl --user' 'the user-manager readiness variant must not be used for a system unit'

printf '%s\n' ""
if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "unrestricted_admin_unlock_wait: FAIL"
   exit 1
fi
printf '%s\n' "unrestricted_admin_unlock_wait: PASS"
exit 0
