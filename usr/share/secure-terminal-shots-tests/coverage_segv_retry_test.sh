#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression + CANARY: the coverage runner RETRIES a suite that SIGSEGVs (exit 139) and
## only fails if it crashes on EVERY attempt. test_mainwin's real single-instance IPC
## handoff (background client thread + main-thread Qt event loop + SIGCHLD pty reaping)
## intermittently segfaults under coverage even on the thread-safe sysmon core -- a CRASH
## artifact, not a test verdict -- so a single 139 must NOT fail the gate.
##
## Extracts run_suite_under_coverage from the REAL runner by BEGIN/END sentinel (reads the
## current script text -> no drift) and drives it with a stub suite that segfaults
## deterministically while a per-run counter is <= a threshold. Two cases:
##   recovery: 2 crashes then a clean run -> final rc 0, exactly 3 attempts.
##   bounded : always crashes, retries=3 -> final rc 139, exactly 3 attempts (no infinite
##             loop, no false green).
##
## FAILS on a runner WITHOUT the retry loop (the sentinel/function is absent -> the
## extraction tripwire fires), so it is a genuine regression test.
##
## Subject: usr/bin/secure-terminal-tests-coverage. Needs importable coverage; absent ->
## exit 77 (SKIP). Runs coverage on a NULL-deref stub, so run it in the sandbox.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

runner=''
for cand in \
   "${SECURE_TERMINAL_TESTS_COVERAGE:-}" \
   "${script_dir}/../../bin/secure-terminal-tests-coverage" \
   '/usr/bin/secure-terminal-tests-coverage'; do
   if [ -n "${cand}" ] && [ -f "${cand}" ]; then
      runner="$(readlink --canonicalize -- "${cand}")"
      break
   fi
done
if [ -z "${runner}" ]; then
   printf '%s\n' 'SKIP: secure-terminal-tests-coverage not found (set SECURE_TERMINAL_TESTS_COVERAGE)' >&2
   exit 77
fi
if ! python3 -c 'import coverage' 2>/dev/null; then
   printf '%s\n' 'SKIP: python3 coverage not importable' >&2
   exit 77
fi

work="$(mktemp --directory)"
cleanup() { safe-rm --recursive --force -- "${work}" 2>/dev/null || true; }
trap cleanup EXIT

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

## Extract the function under test by sentinel. Absent -> the old, no-retry runner.
fn="${work}/run_suite_under_coverage.sh"
sed -n '/## BEGIN-EXTRACT run_suite_under_coverage/,/## END-EXTRACT run_suite_under_coverage/p' \
   -- "${runner}" > "${fn}"
if ! grep -q 'run_suite_under_coverage()' -- "${fn}"; then
   printf '%s\n' 'FAIL: run_suite_under_coverage not found in the runner -- no SIGSEGV retry (old runner)'
   printf '%s\n' '' '0 pass, 1 fail'
   exit 1
fi

## A stub "suite": segfault (NULL deref -> exit 139) while a per-run counter is <= the
## threshold, otherwise exit 0. The counter file records how many attempts the runner made.
stub="${work}/segv_stub.py"
cat > "${stub}" <<'PY'
import os
counter = os.environ['SEGV_COUNTER']
threshold = int(os.environ['SEGV_THRESHOLD'])
try:
    with open(counter) as fh:
        n = int(fh.read().strip() or '0')
except FileNotFoundError:
    n = 0
n += 1
with open(counter, 'w') as fh:
    fh.write(str(n))
if n <= threshold:
    import ctypes
    ctypes.string_at(0)   # NULL dereference -> SIGSEGV (exit 139)
PY

## --source needs a real path to scope measurement; the stub dir is harmless.
pkg="${work}"
hooks="${work}"
# shellcheck disable=SC1090  # a runtime-extracted temp file has no static path to follow
source "${fn}"

drive() {  ## $1=threshold $2=retries $3=counter-file (fresh path) -> echoes the final rc
   local rc=0
   ## no pre-truncate: $3 is a fresh path and the stub treats a missing file as count 0.
   SEGV_COUNTER="$3" SEGV_THRESHOLD="$1" COVERAGE_SEGV_RETRIES="$2" \
      QT_QPA_PLATFORM=offscreen \
      run_suite_under_coverage "${stub}" >/dev/null 2>&1 || rc="$?"
   printf '%s' "${rc}"
}

## ---- recovery: 2 crashes then clean; retries=5 -> rc 0 after exactly 3 attempts -------
c1="${work}/counter1"
rc1="$(drive 2 5 "${c1}")"
check "${rc1}" 0 'a suite that SIGSEGVs twice then succeeds ends GREEN (retry recovered)'
check "$(cat "${c1}")" 3 'recovery retried exactly until the clean run (3 attempts)'

## ---- bounded: always crashes; retries=3 -> rc 139 after exactly 3 attempts ------------
c2="${work}/counter2"
rc2="$(drive 99 3 "${c2}")"
check "${rc2}" 139 'a suite that SIGSEGVs every time still FAILS (persistent crash is fatal)'
check "$(cat "${c2}")" 3 'a persistent crash is bounded by COVERAGE_SEGV_RETRIES (no infinite retry)'

printf '%s\n' '' "${pass} pass, ${fail} fail"
if [ "${fail}" -ne 0 ]; then
   exit 1
fi
printf '%s\n' 'OK: coverage runner retries a SIGSEGV suite and bounds a persistent crash'
