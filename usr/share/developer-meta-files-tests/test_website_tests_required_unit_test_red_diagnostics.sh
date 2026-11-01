#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## style-ok: no-has -- standalone test; does not source helper-scripts.

## Behavioral regression for usr/bin/website-tests run_required_unit_test: on a FAILING
## required unit test it MUST print the captured diagnostics AND a "FATAL: <name> FAILED"
## line, then exit non-zero. Pre-fix (errexit+inherit_errexit aborted the `out="$(...)"`
## capture before the replay/FATAL block) it printed NOTHING -- a silent abort that defeats
## the suite's output-must-not-lie rule. CANARY: this test FAILS on the pre-fix runner.
##
## Drives the real function by SOURCING website-tests (its source-able guard returns before the
## suite body), overriding tests_dir to a fixture, and calling run_required_unit_test in a
## subshell so a pre-fix errexit abort is observed rather than killing this test.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

pass_count=0
fail_count=0
pass() { pass_count=$(( pass_count + 1 )); printf '%s\n' "PASS: $*"; }
fail() { fail_count=$(( fail_count + 1 )); printf '%s\n' "FAIL: $*" >&2; }

test_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
runner="${test_dir}/../../bin/website-tests"
[ -r "${runner}" ] || runner='/usr/bin/website-tests'
if [ ! -r "${runner}" ]; then
   printf '%s\n' "FATAL: website-tests not found" >&2
   exit 1
fi

fixture="$(mktemp --directory)"
cleanup() { safe-rm --recursive --force -- "${fixture}"; }
trap cleanup EXIT

## A FAILING required unit test (prints a summary-shaped line, then exits non-zero).
cat > "${fixture}/fail_test.py" <<'PYEOF'
#!/usr/bin/python3 -I
import sys
print("boomdiag: 2 pass, 1 fail")
sys.exit(1)
PYEOF
chmod +x "${fixture}/fail_test.py"

## A PASSING required unit test (summary line, exit 0).
cat > "${fixture}/ok_test.py" <<'PYEOF'
#!/usr/bin/python3 -I
print("ok_test: 3 pass, 0 fail, 0 skip")
PYEOF
chmod +x "${fixture}/ok_test.py"

## Drive the real function in a SEPARATE bash process (website-tests-red-diag-driver.sh). The
## sourced runner's errexit must be ACTIVE and uncontaminated: bash IGNORES errexit throughout a
## subshell/function that runs in a caught context (`$(...) ||`, `if`, ...), so a same-shell
## `( source ...; fn ) || rc=$?` would MASK the very abort under test (this canary did exactly
## that until fixed). A child process has its own errexit; we observe only its exit status +
## output here. This mirrors how website-tests calls run_required_unit_test: a bare simple command
## under active errexit. The guard in the runner makes `source` return before the suite body.
driver="${test_dir}/website-tests-red-diag-driver.sh"
drive() {
   bash "${driver}" "${runner}" "${fixture}" "$1"
}

## RED path: a failing required unit test MUST print its diagnostics + the FATAL line and exit non-zero.
red_out=''
red_rc=0
red_out="$(drive fail_test.py 2>&1)" || red_rc=$?
if [ "${red_rc}" -ne 0 ] \
      && grep --quiet --fixed-strings 'boomdiag' <<< "${red_out}" \
      && grep --quiet --fixed-strings 'FATAL: fail_test.py FAILED' <<< "${red_out}"; then
   pass 'failing required unit test prints captured diagnostics + FATAL line, exits non-zero'
else
   fail "failing required unit test: expected diagnostics+FATAL+nonzero, got rc=${red_rc} out=<<${red_out}>>"
fi

## GREEN path: a passing required unit test yields its summary line and success.
green_out=''
green_rc=0
green_out="$(drive ok_test.py 2>&1)" || green_rc=$?
if [ "${green_rc}" -eq 0 ] && grep --quiet --fixed-strings 'ok_test: 3 pass' <<< "${green_out}"; then
   pass 'passing required unit test yields summary line and success'
else
   fail "passing required unit test: expected summary+success, got rc=${green_rc} out=<<${green_out}>>"
fi

printf '%s\n' "" "test_website_tests_required_unit_test_red_diagnostics: ${pass_count} pass, ${fail_count} fail, 0 skip"
[ "${fail_count}" -eq 0 ]
