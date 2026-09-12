#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression (functional): wl_headless_stop must not HANG the lane on a labwc that
## ignores SIGTERM. The teardown once did `kill PID; wait PID` -- SIGTERM only, then
## an UNBOUNDED wait -- so a wedged compositor blocked the wait forever. This drives
## the REAL wl_headless_stop against a SIGTERM-ignoring victim process and asserts it
## force-kills (SIGKILL) and returns in bounded time. A background watchdog SIGKILLs
## the victim after 15s so even the pre-fix hang cannot wedge THIS test; the canary is
## the elapsed time (pre-fix ~15s via the watchdog, post-fix ~5s via the bounded poll).
##
## Subject: usr/share/dist-ai-tests-common/wl-headless-lib.bash (override WL_HEADLESS_LIB).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

lib=''
for cand in \
   "${WL_HEADLESS_LIB:-}" \
   "${script_dir}/../dist-ai-tests-common/wl-headless-lib.bash" \
   '/usr/share/dist-ai-tests-common/wl-headless-lib.bash'; do
   if [ -n "${cand}" ] && [ -f "${cand}" ]; then
      lib="$(readlink --canonicalize -- "${cand}")"
      break
   fi
done
if [ -z "${lib}" ]; then
   printf '%s\n' 'FATAL: wl-headless-lib.bash not found (set WL_HEADLESS_LIB)' >&2
   exit 1
fi
# shellcheck source=../dist-ai-tests-common/wl-headless-lib.bash
source "${lib}"

pass=0
fail=0
check() {  ## $1=label $2=ok?(non-empty=pass)
   if [ -n "$2" ]; then
      printf '%s\n' "PASS: $1"; pass=$(( pass + 1 ))
   else
      printf '%s\n' "FAIL: $1"; fail=$(( fail + 1 ))
   fi
}

work="$(mktemp --directory)"
cleanup() { safe-rm --recursive --force -- "${work}" 2>/dev/null || true; }
trap cleanup EXIT

## A victim that IGNORES SIGTERM: a SIG_IGN disposition survives exec, so the exec'd
## sleep cannot be killed by SIGTERM -- only SIGKILL ends it. This is the wedged-labwc
## shape (a compositor stuck ignoring/deferring SIGTERM). It signals readiness AFTER
## installing the trap so wl_headless_stop's SIGTERM cannot race in during the startup
## window (before the trap) and kill it on the default disposition -- which would make
## the victim die instantly and mask the very hang this test exists to catch.
ready="${work}/victim-ready"
bash -c 'trap "" TERM; : > "'"${ready}"'"; exec sleep 300' &
victim="$!"
for _ in $(seq 1 50); do
   [ -e "${ready}" ] && break
   sleep 0.1
done
if [ ! -e "${ready}" ]; then
   printf '%s\n' 'FATAL: victim never signalled readiness' >&2
   kill -KILL "${victim}" 2>/dev/null || true
   exit 1
fi

## Bound THIS test regardless of the outcome: if wl_headless_stop hangs (pre-fix), the
## watchdog SIGKILLs the victim so the unbounded wait can finally return.
( sleep 15; kill -KILL "${victim}" 2>/dev/null || true ) &
watchdog="$!"

WL_HEADLESS_LABWC_PID="${victim}"
start="${SECONDS}"
wl_headless_stop
elapsed="$(( SECONDS - start ))"

kill "${watchdog}" 2>/dev/null || true
wait "${watchdog}" 2>/dev/null || true

if kill -0 "${victim}" 2>/dev/null; then
   victim_dead=''
else
   victim_dead='1'
fi
check 'wl_headless_stop force-kills a SIGTERM-ignoring labwc (SIGKILL fallback)' "${victim_dead}"
## The discriminating canary: the bounded poll returns in ~5s; the pre-fix unbounded
## wait only returned when the 15s watchdog fired.
check "wl_headless_stop returns bounded, not hung (elapsed=${elapsed}s < 10)" \
   "$( [ "${elapsed}" -lt 10 ] && printf '1' )"

printf '%s\n' ''
printf '%s\n' "${pass} pass, ${fail} fail, 0 skip"
[ "${fail}" -eq 0 ]
