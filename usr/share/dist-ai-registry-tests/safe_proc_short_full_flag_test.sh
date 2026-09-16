#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## safe-pgrep / safe-pkill must accept '-f' as an alias for '--full'.
##
## These wrappers exist to REPLACE 'pgrep -f' / 'pkill -f', so a caller reaches for '-f' by pure
## reflex. The pre-fix parser knew only the long '--full' and rejected '-f' with
## 'unknown option: -f' + exit 2 -- a silent no-op: no signal sent, no list printed, and the rc is
## easily misread as "nothing matched". That is exactly the recall-trap the wrappers are meant to
## remove (a real session killed a process by falling back to a raw 'kill -9' after 'safe-pkill -f'
## quietly did nothing). Full-match is already the DEFAULT, so '-f' is a pure no-op alias.
##
## CANARY: spawns a throwaway marker process and asserts '-f' finds/targets it exactly like
## '--full'. FAILS on the pre-fix scripts (they exit 2 on '-f'). No root, no network; the only
## process signalled is safe-pkill --dry-run (nothing) -- the marker is reaped by PID at exit.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
## usr/share/dist-ai-registry-tests -> repo root is three levels up (installed: '/').
repo="${DIST_AI_REPO:-${test_dir}/../../..}"
pgrep_bin="${repo}/usr/bin/safe-pgrep"
pkill_bin="${repo}/usr/bin/safe-pkill"
for f in "${pgrep_bin}" "${pkill_bin}"; do
   [ -f "${f}" ] || { printf '%s\n' "FATAL: required dist-ai file not found: ${f}" >&2; exit 1; }
done

failures=0
pass() { printf '%s\n' "PASS: $*"; }
fail() { printf '%s\n' "FAIL: $*" >&2; failures=$(( failures + 1 )); }

## Throwaway marker process: exec 'sleep' with a UNIQUE argv[0] so a full-command-line match on
## the marker finds it and nothing else. It is a background CHILD of this shell -- a sibling of the
## safe-* invocation, never an ancestor -- so it is neither self-excluded nor ancestor-protected.
## The marker is unique (not a generic name), so the generic-name denylist does not refuse it.
marker="SAFEF-$$-${RANDOM}${RANDOM}"
bash -c 'exec -a "$1" sleep 300' _ "${marker}" &
marker_pid=$!
cleanup() { kill "${marker_pid}" 2>/dev/null || true; }
trap cleanup EXIT

## Wait until the marker process is visible via a full-cmdline match (bounded ~2s).
for _ in $(seq 1 20); do
   if pgrep --full -- "${marker}" >/dev/null 2>&1; then
      break
   fi
   sleep 0.1
done

## run <tool> <args...> -> captures rc into RUN_RC and stdout into RUN_OUT (stderr merged so an
## 'unknown option' from the pre-fix code shows up in the asserted text).
RUN_RC=0
RUN_OUT=''
run() {
   RUN_RC=0
   RUN_OUT="$("$@" 2>&1)" || RUN_RC="$?"
}

## 1. safe-pgrep -f MARKER finds exactly the marker process (rc 0).
run "${pgrep_bin}" -f "${marker}"
if [ "${RUN_RC}" -eq 0 ] && [ "${RUN_OUT}" = "${marker_pid}" ]; then
   pass "safe-pgrep -f matches the full command line (found ${marker_pid})"
else
   fail "safe-pgrep -f failed (rc=${RUN_RC}, out='${RUN_OUT}', expected '${marker_pid}')"
fi

## 2. -f is identical to --full.
run "${pgrep_bin}" --full "${marker}"
full_out="${RUN_OUT}"
full_rc="${RUN_RC}"
run "${pgrep_bin}" -f "${marker}"
if [ "${RUN_RC}" -eq "${full_rc}" ] && [ "${RUN_OUT}" = "${full_out}" ]; then
   pass "safe-pgrep -f is identical to --full"
else
   fail "safe-pgrep -f differs from --full (-f: rc=${RUN_RC} out='${RUN_OUT}'; --full: rc=${full_rc} out='${full_out}')"
fi

## 3. -f combines with other flags (-a listing).
run "${pgrep_bin}" -a -f "${marker}"
if [ "${RUN_RC}" -eq 0 ] && case "${RUN_OUT}" in "${marker_pid} "*"${marker}"*) true ;; *) false ;; esac; then
   pass "safe-pgrep -a -f lists the marker with its command line"
else
   fail "safe-pgrep -a -f failed (rc=${RUN_RC}, out='${RUN_OUT}')"
fi

## 4. safe-pkill -f --dry-run targets the marker (rc 0), and never reports 'unknown option'.
run "${pkill_bin}" -f --dry-run "${marker}"
if [ "${RUN_RC}" -eq 0 ] \
   && case "${RUN_OUT}" in *"${marker_pid}"*) true ;; *) false ;; esac \
   && case "${RUN_OUT}" in *"unknown option"*) false ;; *) true ;; esac; then
   pass "safe-pkill -f --dry-run targets the marker (${marker_pid})"
else
   fail "safe-pkill -f --dry-run failed (rc=${RUN_RC}, out='${RUN_OUT}')"
fi

## 5. safe-pkill --full -f -n order-independent and equivalent.
run "${pkill_bin}" --full -n "${marker}"
if [ "${RUN_RC}" -eq 0 ] && case "${RUN_OUT}" in *"${marker_pid}"*) true ;; *) false ;; esac; then
   pass "safe-pkill --full -n targets the marker (equivalence)"
else
   fail "safe-pkill --full -n failed (rc=${RUN_RC}, out='${RUN_OUT}')"
fi

printf '%s\n' '' "$(( 5 - failures )) pass, ${failures} fail, 0 skip"
if [ "${failures}" -ne 0 ]; then
   exit 1
fi
printf '%s\n' 'OK: safe-pgrep/safe-pkill accept -f as an alias for --full'
