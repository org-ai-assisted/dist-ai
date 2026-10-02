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

## 5-6) Dynamic skip + fail-closed aggregation, driven through the runner with a stub
##    python3 on PATH. The suites forced here are DERIVED from the runner's own suites=()
##    array, NEVER hardcoded: a hardcoded basename silently goes inert the moment the
##    runner's suite list changes (the exact drift this file must resist). Mirror
##    registry_test.sh's array scan -- the entries have the fixed quoted form
##    "${tests_dir}/<name>.py", so matching the literal 'tests_dir}/<name>.py' yields their
##    basenames in the runner's canonical judging order, skipping the
##    suites=("${_only_suites[@]}") reassignment and the prose names in comments (which lack
##    that form). The pattern stays '$'-free on purpose: a literal '${tests_dir}' inside a
##    single-quoted pattern trips SC2016, which the shellcheck-clean-tree gate fails on.
runner_suites=()
while IFS= read -r _entry; do
   _entry="${_entry##*/}"      ## drop through the last '/': leaves '<name>.py'
   runner_suites+=("${_entry%.py}")
done < <(grep -oE 'tests_dir}/[A-Za-z0-9_]+\.py' -- "${runner}")

## Write a stub python3 to $1 that exits a forced code for each named suite and 0 for the
## rest. Remaining args are <basename>:<code> pairs; the runner invokes a suite as
## 'python3 -Bsu .../<basename>.py', so each arm anchors on '/<basename>.py'. Values come
## from the runner's own array (basenames [A-Za-z0-9_], integer codes), safe to embed.
## Quoted-delimiter heredocs emit the fixed skeleton literally (no SC2016); only the
## per-suite case arms are interpolated.
write_stub_python3() {
   local dest="$1" ; shift
   {
      cat <<'STUB'
#!/bin/sh
for a in "$@"; do
   case "${a}" in
STUB
      local pair
      for pair in "$@"; do
         printf '      */%s.py) exit %s ;;\n' "${pair%%:*}" "${pair##*:}"
      done
      cat <<'STUB'
   esac
done
exit 0
STUB
   } > "${dest}"
   chmod 0755 -- "${dest}"
}

## Run the runner authorized against a stub checkout (so the top guard passes) with the
## stub python3 on PATH; echo its exit code. $1 = stub python3 path, $2 = fake repo root.
run_with_stub() {
   local _rc=0
   env "DIST_AI_SKIP_AUTHORIZED=1" "SECURE_TERMINAL_REPO=$2" "PATH=${1%/*}:${PATH}" \
      "${runner}" >/dev/null 2>&1 || _rc="$?"
   printf '%s\n' "${_rc}"
}

## One cleanup for every temp dir the dynamic tests mint.
_st_tmpdirs=()
# shellcheck disable=SC2317  # invoked via the EXIT trap
_st_cleanup() {
   [ "${#_st_tmpdirs[@]}" -gt 0 ] || return 0
   ## An absent safe-rm is tolerated rather than failing cleanup.
   safe-rm --recursive --force -- "${_st_tmpdirs[@]}" || true
}
trap _st_cleanup EXIT

if [ "${#runner_suites[@]}" -eq 0 ]; then
   ## Anti-drift backstop: the scan matched ZERO suites, so the dynamic assertions below
   ## would test nothing. Either the array moved to a form this anchor no longer matches,
   ## or the runner lists none -- either way FATAL, never a silent green.
   printf 'FAIL: could not read the plain runner suites=() array (format changed? update this test)\n' >&2
   failures=$((failures + 1))
fi

## 5) An AUTHORIZED skip of a required (non-pure) suite must make the runner exit 77 (SKIP),
##    not 0 (PASS) -- else a lenient-skipped run is indistinguishable from a clean full pass
##    by exit code. Force the FIRST real suite to skip (77) and the rest to pass (0).
if [ "${#runner_suites[@]}" -ge 1 ]; then
   stubdir="$(mktemp -d)" ; _st_tmpdirs+=("${stubdir}")
   fakerepo="$(mktemp -d)" ; _st_tmpdirs+=("${fakerepo}")
   mkdir -p -- "${fakerepo}/usr/lib/python3/dist-packages/secure_terminal"
   write_stub_python3 "${stubdir}/python3" "${runner_suites[0]}:77"
   rc="$(run_with_stub "${stubdir}/python3" "${fakerepo}")"
   if [ "${rc}" -eq 77 ]; then
      printf 'PASS: an authorized non-pure skip makes the runner exit 77, not a silent 0\n'
   else
      printf 'FAIL: authorized non-pure skip exited %s, expected 77 (lenient skip hidden as PASS)\n' "${rc}" >&2
      failures=$((failures + 1))
   fi
fi

## 6) FAIL-CLOSED aggregation: a LATER suite's real failure (rc 1) must NOT be masked by an
##    EARLIER suite's authorized skip (rc 77). The result loop must evaluate every suite and
##    exit 1, never short-circuit to 77 on the first skip. Force the FIRST suite to skip (77)
##    and the LAST to fail (1), so the skip is judged BEFORE the failure in canonical order.
##    Needs >=2 suites to express; fewer is a FATAL "cannot prove", never a silent skip.
if [ "${#runner_suites[@]}" -ge 2 ]; then
   stubdir="$(mktemp -d)" ; _st_tmpdirs+=("${stubdir}")
   fakerepo="$(mktemp -d)" ; _st_tmpdirs+=("${fakerepo}")
   mkdir -p -- "${fakerepo}/usr/lib/python3/dist-packages/secure_terminal"
   write_stub_python3 "${stubdir}/python3" "${runner_suites[0]}:77" "${runner_suites[-1]}:1"
   rc="$(run_with_stub "${stubdir}/python3" "${fakerepo}")"
   if [ "${rc}" -eq 1 ]; then
      printf 'PASS: a later suite failure is not masked by an earlier authorized skip (exit 1)\n'
   else
      printf 'FAIL: fail-closed aggregation exited %s, expected 1 (a real failure was masked)\n' "${rc}" >&2
      failures=$((failures + 1))
   fi
else
   printf 'FAIL: fail-closed aggregation needs >=2 runner suites to prove it; runner lists %s (revisit this test)\n' "${#runner_suites[@]}" >&2
   failures=$((failures + 1))
fi

## 7) A registered suite whose .py file is MISSING from the checkout must fail closed (FATAL),
##    never be silently skipped -- a dropped/renamed suite must not read as a clean pass
##    (run_suites_parallel writes no rc file for an absent suite, so the result loop is the only
##    place to catch it). Static check, mirroring test 4: the fail-closed guard must be present.
if grep --quiet -- 'registered suite missing from checkout' "${runner}"; then
   printf 'PASS: a missing registered suite fails closed, not a silent skip\n'
else
   printf 'FAIL: the runner silently skips a missing registered suite (no fail-closed guard)\n' >&2
   failures=$((failures + 1))
fi

if [ "${failures}" -gt 0 ]; then
   printf 'secure_terminal_tests_absent_target_test: %s assertion(s) FAILED.\n' "${failures}" >&2
   exit 1
fi
printf 'secure_terminal_tests_absent_target_test: OK\n'
