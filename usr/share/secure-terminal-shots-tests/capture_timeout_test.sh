#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression: a capture that HANGS must be bounded. Launches a stub "hung capture" (sleep 300)
## in its own session via the REAL shots_spawn_session, arms the REAL per-capture watchdog with
## a short deadline, and asserts the watchdog TERMs/KILLs the whole process group within the
## deadline and flags the timeout -- so the capture loop continues instead of stalling. Also
## asserts the CANCEL path: a capture that finishes in time is NOT reaped.
##
## FAILS on the old harness (no shots_spawn_session / shots_watchdog_start), so it is a genuine
## regression test.
##
## Subject: lib-capture.sh, resolved from SECURE_TERMINAL_SHOTS_DIR, a checkout default, or the
## installed path. Absent -> exit 77 (SKIP). Spawns + kills processes, so run it in the sandbox
## (it only touches its OWN sessions).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

lib=''
for cand in \
   "${SECURE_TERMINAL_SHOTS_DIR:-}/lib-capture.sh" \
   "${script_dir}/../secure-terminal-shots/lib-capture.sh" \
   "${script_dir}/../../share/secure-terminal-shots/lib-capture.sh" \
   '/usr/share/secure-terminal-shots/lib-capture.sh'; do
   if [ -n "${cand}" ] && [ -f "${cand}" ]; then
      lib="$(readlink --canonicalize -- "${cand}")"
      break
   fi
done
if [ -z "${lib}" ]; then
   printf '%s\n' 'SKIP: lib-capture.sh not found (set SECURE_TERMINAL_SHOTS_DIR)' >&2
   exit 77
fi

# shellcheck source=../secure-terminal-shots/lib-capture.sh
source "${lib}"

pass=0
fail=0
check() {  ## $1=got $2=want $3=label
   if [ "$1" = "$2" ]; then
      printf '%s\n' "PASS: $3"
      pass=$(( pass + 1 ))
   else
      printf '%s\n' "FAIL: $3 (got '$1', want '$2')"
      fail=$(( fail + 1 ))
   fi
}

pgids=()
tmpfiles=()
cleanup() {
   local g f
   for g in "${pgids[@]:-}"; do [ -n "${g}" ] && kill -s KILL "-${g}" 2>/dev/null || true; done
   for f in "${tmpfiles[@]:-}"; do [ -n "${f}" ] && safe-rm -f -- "${f}" "${f}.timeout" 2>/dev/null || true; done
}
trap cleanup EXIT

if ! declare -F shots_spawn_session >/dev/null 2>&1 \
      || ! declare -F shots_watchdog_start >/dev/null 2>&1 \
      || ! declare -F shots_reap_group >/dev/null 2>&1; then
   printf '%s\n' 'FAIL: shots_spawn_session / shots_watchdog_start / shots_reap_group not defined -- old harness has no per-capture deadline'
   printf '%s\n' '' '0 pass, 1 fail, 0 skip'
   exit 1
fi

## read a PGID file written by shots_spawn_session, waiting briefly for it to appear.
read_pgid() {  ## $1=pgid-file -> echoes the PGID (empty on timeout)
   local f="$1" i pgid=''
   for i in $(seq 1 50); do
      pgid="$(cat "${f}" 2>/dev/null || true)"
      [ -n "${pgid}" ] && break
      sleep 0.1
   done
   printf '%s' "${pgid}"
}

## ---- 1. TIMEOUT path: a hung capture is reaped within the deadline -----------------
pgf1="$(mktemp)"; tmpfiles+=("${pgf1}")
shots_spawn_session "${pgf1}" sleep 300
pgid1="$(read_pgid "${pgf1}")"
pgids+=("${pgid1}")
if [ -z "${pgid1}" ]; then
   check nopgid gotpgid 'spawn_session recorded the hung capture PGID'
else
   check gotpgid gotpgid 'spawn_session recorded the hung capture PGID'
fi
## the group is alive before the deadline.
if kill -0 "-${pgid1}" 2>/dev/null; then
   check alive alive 'hung capture group is alive before the deadline'
else
   check dead alive 'hung capture group is alive before the deadline'
fi
## arm the watchdog with a 2s deadline; do NOT cancel -> it must reap the group + flag it.
wdog1="$(shots_watchdog_start 2 "${pgf1}" "${pgf1}.timeout")"
## wait up to ~8s for the reap (2s deadline + grace).
reaped=alive
for _ in $(seq 1 40); do
   if ! kill -0 "-${pgid1}" 2>/dev/null; then
      reaped=dead
      break
   fi
   sleep 0.25
done
wait "${wdog1}" 2>/dev/null || true
check "${reaped}" dead 'watchdog reaped the hung capture group within the deadline'
if [ -e "${pgf1}.timeout" ]; then
   check flagged flagged 'watchdog flagged the timeout so the caller can warn'
else
   check noflag flagged 'watchdog flagged the timeout so the caller can warn'
fi

## ---- 2. CANCEL path: a capture that finishes in time is NOT reaped -----------------
pgf2="$(mktemp)"; tmpfiles+=("${pgf2}")
shots_spawn_session "${pgf2}" sleep 300
pgid2="$(read_pgid "${pgf2}")"
pgids+=("${pgid2}")
wdog2="$(shots_watchdog_start 5 "${pgf2}" "${pgf2}.timeout")"
shots_watchdog_cancel "${wdog2}"    ## capture "finished" -> cancel before the deadline
sleep 6                              ## past when the deadline WOULD have fired
if kill -0 "-${pgid2}" 2>/dev/null; then
   check alive alive 'cancelled watchdog did NOT reap an in-time capture'
else
   check dead alive 'cancelled watchdog did NOT reap an in-time capture'
fi
if [ -e "${pgf2}.timeout" ]; then
   check flagged noflag 'cancelled watchdog left NO timeout flag'
else
   check noflag noflag 'cancelled watchdog left NO timeout flag'
fi
## reap the survivor now (its group is real).
shots_reap_group "${pgid2}"

printf '%s\n' '' "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   exit 1
fi
printf '%s\n' 'OK: per-capture deadline'
