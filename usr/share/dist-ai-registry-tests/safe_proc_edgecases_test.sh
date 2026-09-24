#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Invariants for safe-pgrep/safe-pkill edge cases (each assertion drives the real scripts):
##
##  F2  --name and --full/-f are mutually exclusive -- a usage error (exit 2), order-independent,
##      never a silent downgrade of the narrower self-safe --name mode.
##  F3  an empty or whitespace-only PATTERN is a clean usage error (exit 2), never a crash: the
##      shared denylist guards the empty key so no caller trips "bad array subscript".
##  F4  --signal accepts the kill -9 muscle-memory spelling: a leading dash is stripped, so -9
##      means 9 and -KILL means KILL.
##  F1  a failed kill is classified by kill's errno message, not /proc readability, and fails
##      closed ('live') when it cannot confirm the process exited -- so a live process hidden by
##      a hidepid /proc (standard on Kicksecure/Whonix) is never reported as "gone".
##  F5  SAFE_PROC_ALLOW_GENERIC is fail-safe: only a truthy value disables the generic-name guard.
##  F6  safe-pgrep -a is newline-safe: one output line per match even with a newline in argv.
##  F7  safe-pkill exit code honors the contract: 0 iff >= 1 process was signalled.
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
## One cleanup for every marker this test spawns (later ones are set after the trap; guarded so
## an early exit before they exist is harmless). No sleep 300 leaks if an assertion aborts.
cleanup() {
   local p
   for p in "${marker_pid:-}" "${nl_pid:-}" "${c1_pid:-}"; do
      # shellcheck disable=SC2015  # guarded cleanup: || true is the intended fallthrough
      [ -n "${p}" ] && kill "${p}" 2>/dev/null || true
   done
}
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

## --- F5: SAFE_PROC_ALLOW_GENERIC is fail-safe -- only a truthy value disables the guard -------
## '=0' (a near-universal "off" spelling) must NOT bypass the generic-name refusal.
for tool in "${pgrep_bin}" "${pkill_bin}"; do
   name="$(basename -- "${tool}")"
   RUN_RC=0; RUN_OUT="$(SAFE_PROC_ALLOW_GENERIC=0 "${tool}" --dry-run sleep 2>&1)" || RUN_RC="$?"
   ## safe-pgrep has no --dry-run, but the generic-name refusal fires during arg-independent
   ## validation before the flag is rejected; either way we require the refusal, not a bypass.
   if [ "${name}" = 'safe-pgrep' ]; then
      RUN_RC=0; RUN_OUT="$(SAFE_PROC_ALLOW_GENERIC=0 "${tool}" sleep 2>&1)" || RUN_RC="$?"
   fi
   if [ "${RUN_RC}" -eq 2 ] && case "${RUN_OUT}" in *'refusing the generic process name'*) true ;; *) false ;; esac; then
      pass "${name}: SAFE_PROC_ALLOW_GENERIC=0 keeps the guard ON (fail-safe)"
   else
      fail "${name}: SAFE_PROC_ALLOW_GENERIC=0 bypassed the generic guard (rc=${RUN_RC}, out='${RUN_OUT}')"
   fi
done
## '=1' still opts in (the documented override): the generic name is allowed past the guard.
RUN_RC=0; RUN_OUT="$(SAFE_PROC_ALLOW_GENERIC=1 "${pgrep_bin}" -c sleep 2>&1)" || RUN_RC="$?"
if [ "${RUN_RC}" -ne 2 ] && case "${RUN_OUT}" in *'refusing the generic'*) false ;; *) true ;; esac; then
   pass "safe-pgrep: SAFE_PROC_ALLOW_GENERIC=1 still opts in (override works)"
else
   fail "safe-pgrep: SAFE_PROC_ALLOW_GENERIC=1 did not opt in (rc=${RUN_RC}, out='${RUN_OUT}')"
fi

## --- F6: safe-pgrep -a is newline-safe -- one output line per match --------------------------
nlmarker="NL-$$-${RANDOM}"
bash -c 'exec -a "$1" sleep 300' _ "$(printf '%s\nINJECTED-SECOND-LINE' "${nlmarker}")" &
nl_pid=$!
for _ in $(seq 1 20); do
   if pgrep --full -- "${nlmarker}" >/dev/null 2>&1; then break; fi
   sleep 0.1
done
line_count="$("${pgrep_bin}" -a "${nlmarker}" | wc -l)"
if [ "${line_count}" -eq 1 ]; then
   pass "safe-pgrep -a renders one line per match despite a newline in argv"
else
   fail "safe-pgrep -a produced ${line_count} lines for one match (newline leaked)"
fi

## --- F7: exit-code contract -- 0 iff >= 1 signalled ------------------------------------------
c1marker="EXIT-$$-${RANDOM}"
bash -c 'exec -a "$1" sleep 300' _ "${c1marker}" &
c1_pid=$!
run "${pkill_bin}" "${c1marker}"
if [ "${RUN_RC}" -eq 0 ] && ! kill -0 "${c1_pid}" 2>/dev/null; then
   pass "safe-pkill exits 0 when it signalled the match (contract)"
else
   fail "safe-pkill contract: expected exit 0 + killed (rc=${RUN_RC})"
fi
kill "${c1_pid}" 2>/dev/null || true
run "${pkill_bin}" "NOMATCH-$$-${RANDOM}${RANDOM}"
if [ "${RUN_RC}" -eq 1 ]; then
   pass "safe-pkill exits 1 when nothing matched (contract)"
else
   fail "safe-pkill contract: expected exit 1 on no match (rc=${RUN_RC}, out='${RUN_OUT}')"
fi

printf '%s\n' '' "${passes} pass, ${failures} fail, 0 skip"
## Guard against a silently-skipped block reading green: the full path runs 17 assertions, so a
## clean run with fewer means something was skipped (e.g. a marker never appeared).
if [ "${failures}" -eq 0 ] && [ "$(( passes + failures ))" -ne 17 ]; then
   printf 'FAIL: expected 17 assertions, only %s ran -- a block was silently skipped\n' \
      "$(( passes + failures ))" >&2
   exit 1
fi
if [ "${failures}" -ne 0 ]; then
   exit 1
fi
printf '%s\n' 'OK: safe-pgrep/safe-pkill edge cases (name/full conflict, whitespace, signal, kill-failure)'
