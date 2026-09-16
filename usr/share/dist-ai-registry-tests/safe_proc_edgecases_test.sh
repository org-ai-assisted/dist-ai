#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression tests for four safe-pgrep/safe-pkill edge cases (all reproduced before the fix):
##
##  F2  --name and --full/-f are mutually exclusive: last-wins used to SILENTLY downgrade an
##      explicit --name (the narrower, self-safe mode) back to full-command-line matching when
##      -f was appended by reflex. Now a usage error (exit 2), order-independent.
##  F3  a whitespace-only PATTERN used to crash with "bad array subscript" (empty key into the
##      generic-name set), exit 1, leaking an internal path. Now rejected as empty (exit 2), and
##      the shared denylist guards the empty key so no caller can crash on it.
##  F4  --signal -9 (the kill -9 muscle-memory spelling) used to be rejected "invalid signal";
##      now a leading dash is stripped so -9 -> 9, -KILL -> KILL.
##  F1  a failed kill on an UNREADABLE /proc/PID/stat used to be assumed "gone" -> under a
##      hidepid /proc (standard on Kicksecure/Whonix) a live, hidden, unsignalled process was
##      reported as success. classify_kill_failure now decides by kill's errno message and fails
##      closed ('live') when it cannot confirm the process exited.
##
## No root, no network. F4 signals nothing (--dry-run); the F1 unit calls the extracted pure
## function with fabricated errno strings; marker processes are reaped by PID at exit.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo="${DIST_AI_REPO:-${test_dir}/../../..}"
pgrep_bin="${repo}/usr/bin/safe-pgrep"
pkill_bin="${repo}/usr/bin/safe-pkill"
for f in "${pgrep_bin}" "${pkill_bin}"; do
   [ -f "${f}" ] || { printf '%s\n' "FATAL: required dist-ai file not found: ${f}" >&2; exit 1; }
done

failures=0
passes=0
pass() { printf '%s\n' "PASS: $*"; passes=$(( passes + 1 )); }
fail() { printf '%s\n' "FAIL: $*" >&2; failures=$(( failures + 1 )); }

RUN_RC=0
RUN_OUT=''
run() {  ## run a command, capture rc into RUN_RC and merged stdout+stderr into RUN_OUT
   RUN_RC=0
   RUN_OUT="$("$@" 2>&1)" || RUN_RC="$?"
}

## --- F2: --name / --full conflict is a usage error, both tools, both orders -------------------
for tool in "${pgrep_bin}" "${pkill_bin}"; do
   name="$(basename -- "${tool}")"
   run "${tool}" --name -f somepat
   if [ "${RUN_RC}" -eq 2 ] && case "${RUN_OUT}" in *'mutually exclusive'*) true ;; *) false ;; esac; then
      pass "${name}: --name -f is a usage error (not a silent downgrade)"
   else
      fail "${name}: --name -f expected exit 2 conflict (rc=${RUN_RC}, out='${RUN_OUT}')"
   fi
   run "${tool}" -f --name somepat
   if [ "${RUN_RC}" -eq 2 ] && case "${RUN_OUT}" in *'mutually exclusive'*) true ;; *) false ;; esac; then
      pass "${name}: -f --name conflict is order-independent"
   else
      fail "${name}: -f --name expected exit 2 conflict (rc=${RUN_RC}, out='${RUN_OUT}')"
   fi
done

## --- F3: whitespace-only PATTERN is rejected as empty, never a crash --------------------------
for tool in "${pgrep_bin}" "${pkill_bin}"; do
   name="$(basename -- "${tool}")"
   run "${tool}" " "
   if [ "${RUN_RC}" -eq 2 ] \
      && case "${RUN_OUT}" in *'empty or whitespace-only'*) true ;; *) false ;; esac \
      && case "${RUN_OUT}" in *'bad array subscript'*) false ;; *) true ;; esac; then
      pass "${name}: a whitespace-only PATTERN is a clean usage error, not a crash"
   else
      fail "${name}: whitespace PATTERN expected exit 2 without crash (rc=${RUN_RC}, out='${RUN_OUT}')"
   fi
done

## --- F4: --signal -9 / -KILL accepted (leading dash stripped) ---------------------------------
marker="EDGE-$$-${RANDOM}${RANDOM}"
bash -c 'exec -a "$1" sleep 300' _ "${marker}" &
marker_pid=$!
cleanup() { kill "${marker_pid}" 2>/dev/null || true; }
trap cleanup EXIT
for _ in $(seq 1 20); do
   if pgrep --full -- "${marker}" >/dev/null 2>&1; then break; fi
   sleep 0.1
done
run "${pkill_bin}" --signal -9 --dry-run "${marker}"
if [ "${RUN_RC}" -eq 0 ] && case "${RUN_OUT}" in *'would send 9 to'*"${marker_pid}"*) true ;; *) false ;; esac; then
   pass "safe-pkill --signal -9 is accepted (normalised to 9)"
else
   fail "safe-pkill --signal -9 failed (rc=${RUN_RC}, out='${RUN_OUT}')"
fi
run "${pkill_bin}" -s -KILL --dry-run "${marker}"
if [ "${RUN_RC}" -eq 0 ] && case "${RUN_OUT}" in *'would send KILL to'*"${marker_pid}"*) true ;; *) false ;; esac; then
   pass "safe-pkill -s -KILL is accepted (leading dash stripped)"
else
   fail "safe-pkill -s -KILL failed (rc=${RUN_RC}, out='${RUN_OUT}')"
fi

## --- F1: classify_kill_failure fails closed when it cannot confirm the process exited ---------
## Extract the pure function from the CURRENT script text (no drift) and call it with fabricated
## errno strings. On the pre-fix script the function is absent -> extraction is empty -> FAIL.
fn="$(awk '/^classify_kill_failure\(\) \{/{f=1} f{print} f&&/^\}/{exit}' "${pkill_bin}")"
if [ -z "${fn}" ]; then
   fail "classify_kill_failure could not be extracted from ${pkill_bin} (pre-fix script?)"
else
   ## ESRCH message -> 'gone' (benign: process exited before the kill).
   verdict="$(eval "${fn}"; classify_kill_failure 'bash: kill: (999999) - No such process' 999999)"
   if [ "${verdict}" = 'gone' ]; then
      pass "classify_kill_failure: ESRCH -> gone"
   else
      fail "classify_kill_failure: ESRCH expected 'gone', got '${verdict}'"
   fi
   ## EPERM message on an UNREADABLE /proc (pid 999999 does not exist) -> 'live' (fail closed):
   ## this is the hidepid case -- unreadable stat must NOT be read as 'gone'.
   verdict="$(eval "${fn}"; classify_kill_failure 'bash: kill: (999999) - Operation not permitted' 999999)"
   if [ "${verdict}" = 'live' ]; then
      pass "classify_kill_failure: EPERM + unreadable /proc -> live (fail closed, not 'gone')"
   else
      fail "classify_kill_failure: EPERM+unreadable expected 'live', got '${verdict}'"
   fi
   ## EPERM message on a READABLE, non-zombie /proc (this test shell) -> 'live'.
   verdict="$(eval "${fn}"; classify_kill_failure 'bash: kill: ('"$$"') - Operation not permitted' "$$")"
   if [ "${verdict}" = 'live' ]; then
      pass "classify_kill_failure: EPERM + readable live /proc -> live"
   else
      fail "classify_kill_failure: EPERM+live expected 'live', got '${verdict}'"
   fi
fi

printf '%s\n' '' "${passes} pass, ${failures} fail, 0 skip"
## Guard against a silently-skipped block reading green: the full path runs 11 assertions, so a
## clean run with fewer means something was skipped (e.g. the marker never appeared for F4).
if [ "${failures}" -eq 0 ] && [ "$(( passes + failures ))" -ne 11 ]; then
   printf 'FAIL: expected 11 assertions, only %s ran -- a block was silently skipped\n' \
      "$(( passes + failures ))" >&2
   exit 1
fi
if [ "${failures}" -ne 0 ]; then
   exit 1
fi
printf '%s\n' 'OK: safe-pgrep/safe-pkill edge cases (name/full conflict, whitespace, signal, kill-failure)'
