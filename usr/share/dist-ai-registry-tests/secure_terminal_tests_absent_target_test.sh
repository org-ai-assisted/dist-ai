#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Pins the secure-terminal-tests absent-target policy: an absent secure_terminal
## checkout is a hard FATAL (exit 1), NOT a silent exit-77 SKIP -- UNLESS the caller
## authorized the skip via DIST_AI_SKIP_AUTHORIZED=1 (which dist-ai-tests-all sets for a
## --allow-skip'd or a lenient non-strict run). A bare exit-77 on an absent target reads
## green in a summary line; making it FATAL keeps a misconfigured run (no checkout, no
## authorization) from passing while it tested nothing.
##
## The absent-target guard returns at the top of secure-terminal-tests, before importing
## the module or running any test, so invoking it here neither runs the suite nor recurses.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_script="$(readlink --canonicalize -- "${BASH_SOURCE[0]}")"
test_dir="${test_script%/*}"

## Installed layout is /usr/share/...; from a checkout the entrypoints sit at ../../bin.
runner="${test_dir}/../../bin/secure-terminal-tests"
[ -x "${runner}" ] || runner='/usr/bin/secure-terminal-tests'
orch="${test_dir}/../../bin/dist-ai-tests-all"
[ -r "${orch}" ] || orch='/usr/bin/dist-ai-tests-all'

if [ ! -x "${runner}" ]; then
   printf '%s\n' 'FATAL: secure_terminal_tests_absent_target_test: secure-terminal-tests not found' >&2
   exit 1
fi

## A path guaranteed to hold no secure_terminal module, forcing the absent-target guard.
## Never created, so the guard's -d test is false regardless of the operator's checkout.
absent="${test_dir}/no-such-secure-terminal-checkout-$$"

failures=0

## 1) Unauthorized absent target -> hard FATAL (exit 1), never a silent 77.
rc=0
env --unset=DIST_AI_SKIP_AUTHORIZED "SECURE_TERMINAL_REPO=${absent}" \
   "${runner}" >/dev/null 2>&1 || rc="$?"
if [ "${rc}" -eq 1 ]; then
   printf 'PASS: absent target without authorization is FATAL (exit 1)\n'
else
   printf 'FAIL: absent target without authorization exited %s, expected 1 (FATAL)\n' "${rc}" >&2
   failures=$((failures + 1))
fi

## 2) Authorized absent target -> SKIP (exit 77), so --allow-skip still works.
rc=0
env "DIST_AI_SKIP_AUTHORIZED=1" "SECURE_TERMINAL_REPO=${absent}" \
   "${runner}" >/dev/null 2>&1 || rc="$?"
if [ "${rc}" -eq 77 ]; then
   printf 'PASS: absent target WITH authorization SKIPs (exit 77)\n'
else
   printf 'FAIL: absent target with DIST_AI_SKIP_AUTHORIZED=1 exited %s, expected 77\n' "${rc}" >&2
   failures=$((failures + 1))
fi

## 3) The orchestrator sets that authorization ONLY when it would tolerate the skip.
##    Static, by reading dist-ai-tests-all: running it would run the whole registry.
##    The line that sets DIST_AI_SKIP_AUTHORIZED must be guarded by skip_is_fatal, not
##    unconditional -- an unconditional set would authorize every skip and re-open the hole.
if [ ! -r "${orch}" ]; then
   printf 'FAIL: dist-ai-tests-all not found for the plumbing check\n' >&2
   failures=$((failures + 1))
else
   plumb="$(grep -B1 -- 'DIST_AI_SKIP_AUTHORIZED=1' "${orch}" 2>/dev/null || true)"
   if [ -z "${plumb}" ]; then
      printf 'FAIL: dist-ai-tests-all never sets DIST_AI_SKIP_AUTHORIZED (suite can never be authorized to skip)\n' >&2
      failures=$((failures + 1))
   elif [[ "${plumb}" == *'! skip_is_fatal'* ]]; then
      ## Require the NEGATION: authorize the skip only when it is NOT fatal. An inverted
      ## guard ('if skip_is_fatal') authorizes exactly when it should fail -- a security
      ## regression -- so matching a bare 'skip_is_fatal' substring is not enough.
      printf 'PASS: dist-ai-tests-all gates DIST_AI_SKIP_AUTHORIZED on "! skip_is_fatal"\n'
   else
      printf 'FAIL: dist-ai-tests-all sets DIST_AI_SKIP_AUTHORIZED without an "! skip_is_fatal" guard (missing or inverted)\n' >&2
      failures=$((failures + 1))
   fi
fi

## 4) A non-pure suite's exit-77 (e.g. a Qt suite on missing PyQt6/pyte) must NOT be a
##    silent skip: the loop fails closed on it unless authorized. Read statically -- the
##    fail-closed path must be present, not a bare continue that reads green.
if grep --quiet -- 'exited 77 (skipped)' "${runner}"; then
   printf 'PASS: a non-pure suite exit-77 is fail-closed, not a silent continue\n'
else
   printf 'FAIL: secure-terminal-tests silently continues on a non-pure suite exit-77\n' >&2
   failures=$((failures + 1))
fi

## 5) An AUTHORIZED skip of a required (non-pure) suite must make the runner exit 77
##    (SKIP), not 0 (PASS) -- else a lenient-skipped run is indistinguishable from a
##    clean full pass by exit code. Force that branch with a stub python3 that skips
##    only test_fuzz_widget.py (exit 77) and passes every other suite (exit 0), against a
##    stub checkout so the top guard passes.
stubdir="$(mktemp -d)"
fakerepo="$(mktemp -d)"
## An absent safe-rm is tolerated rather than failing cleanup.
cleanup_stub() { safe-rm --recursive --force -- "${stubdir}" "${fakerepo}" || true; }
trap cleanup_stub EXIT
mkdir -p -- "${fakerepo}/usr/lib/python3/dist-packages/secure_terminal"
cat > "${stubdir}/python3" <<'STUB'
#!/bin/sh
for a in "$@"; do
   case "${a}" in *test_fuzz_widget.py) exit 77 ;; esac
done
exit 0
STUB
chmod 0755 -- "${stubdir}/python3"
rc=0
env "DIST_AI_SKIP_AUTHORIZED=1" "SECURE_TERMINAL_REPO=${fakerepo}" "PATH=${stubdir}:${PATH}" \
   "${runner}" >/dev/null 2>&1 || rc="$?"
if [ "${rc}" -eq 77 ]; then
   printf 'PASS: an authorized non-pure skip makes the runner exit 77, not a silent 0\n'
else
   printf 'FAIL: authorized non-pure skip exited %s, expected 77 (lenient skip hidden as PASS)\n' "${rc}" >&2
   failures=$((failures + 1))
fi

if [ "${failures}" -gt 0 ]; then
   printf 'secure_terminal_tests_absent_target_test: %s assertion(s) FAILED.\n' "${failures}" >&2
   exit 1
fi
printf 'secure_terminal_tests_absent_target_test: OK\n'
