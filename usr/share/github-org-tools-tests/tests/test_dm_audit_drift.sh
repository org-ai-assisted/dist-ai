#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Mock-API test: dm-github-org-policy --audit must FAIL on policy drift.
##
## Regression for the empty-allowlist incident: the org policy shipped
## 'allowed_actions: selected' with 'patterns_allowed: []', which blocks
## every cross-org reusable-workflow call (consumers outside the org that
## hosts the reusables get startup_failure and zero jobs). It survived
## --apply, --dry-run and --audit because:
##
##   * --audit rendered patterns_allowed as a COUNT ('patterns=0') and
##     compared it to nothing;
##   * audit_get returned 0 on every branch, and main() returned 0
##     unconditionally, so --audit could not fail at all.
##
## So this test asserts the failing direction explicitly: given a live
## state that does NOT match the policy, --audit must exit non-zero and
## name the drifted field. A test that only ever exercises the healthy
## fixtures cannot catch a check that is incapable of failing.
##
## Each case is a STATIC overlay under ../fixtures-drift/<case>/, holding
## only the endpoints that case changes; the rest come from ../fixtures.
## The drifted JSON is checked in and diffable rather than printf'd at
## runtime, so what is being asserted is readable without running it.
##
## Companion to test_dm_audit.sh (the clean direction).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

if [ "${CI:-}" != "true" ]; then
   printf '%s\n' \
      'error: this script must run with CI=true (GitHub Actions or equivalent).' >&2
   exit 1
fi

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" && pwd )"
FIXTURES_DIR="$(cd -- "${SCRIPT_DIR}/../fixtures" && pwd)"
DRIFT_DIR="$(cd -- "${SCRIPT_DIR}/../fixtures-drift" && pwd)"

work=''

# shellcheck disable=SC2317  # invoked via the EXIT trap, not inline
cleanup() {
   ## '|| true': a failing cleanup must not replace the test's verdict.
   [ -z "${work}" ] || safe-rm --recursive --force -- "${work}" || true
}
trap cleanup EXIT

work="$(mktemp --directory)"

export GHORG_MOCK=true
export GHORG_MOCK_DIR="${work}"

fail=0

## Reset to the healthy fixtures, then lay the named case over them.
## Args: $1 = case directory name under fixtures-drift/.
load_case() {
   local case_name

   case_name="$1"
   if [ ! -d "${DRIFT_DIR}/${case_name}" ]; then
      printf '%s\n' "FAIL: no such drift fixture case: '${case_name}'" >&2
      fail=1
      return 1
   fi
   cp -a -- "${FIXTURES_DIR}/." "${work}/"
   cp -a -- "${DRIFT_DIR}/${case_name}/." "${work}/"
}

## Assert that --audit fails and says why.
## Args: $1 = case dir, $2 = description, $3 = expected substring.
expect_drift() {
   local case_name desc needle rc out

   case_name="$1"
   desc="$2"
   needle="$3"

   load_case "${case_name}" || return 0

   rc=0
   out="$(ORGS_OVERRIDE='org-ai-assisted' dm-github-org-policy --audit 2>&1)" || rc=$?

   if [ "${rc}" -eq 0 ]; then
      printf '%s\n' "FAIL: ${desc}: --audit exited 0 despite drift" >&2
      printf '%s\n' '--- captured output ---' >&2
      printf '%s\n' "${out}" >&2
      fail=1
      return 0
   fi
   if ! grep --quiet --fixed-strings -- "${needle}" <<< "${out}"; then
      printf '%s\n' "FAIL: ${desc}: --audit failed but did not report '${needle}'" >&2
      printf '%s\n' '--- captured output ---' >&2
      printf '%s\n' "${out}" >&2
      fail=1
      return 0
   fi
   printf '%s\n' "PASS: ${desc}"
}

## The exact shape of the incident: selected + an empty allowlist.
expect_drift 'empty-patterns' \
   'empty patterns_allowed is drift' 'patterns_allowed:'

## An endpoint we could not read is NOT a pass. A run that failed to
## verify the state must never report clean.
expect_drift 'unreadable-endpoint' \
   'unreadable endpoint is not a pass' 'NOT VERIFIED'

## allowed_actions flipped away from the policy value.
expect_drift 'allowed-actions-all' \
   'allowed_actions drift is caught' 'allowed_actions:'

## An HTTP 200 whose body is not the expected shape: the comparison
## cannot run, and a comparison that could not run must not be reported
## as one that passed.
expect_drift 'unparseable-body' \
   'an unparseable 200 body is not a pass' 'NOT VERIFIED'

## Every setting backed by a POLICY_* literal is compared, not just the
## Actions pair. These two were previously PRINTED only, so a loosened
## fork-PR policy or a writable GITHUB_TOKEN audited green.
expect_drift 'fork-pr-approval-loose' \
   'a loosened fork-PR approval policy is drift' 'approval_policy:'
expect_drift 'workflow-perms-write' \
   'a writable workflow GITHUB_TOKEN is drift' 'default_workflow_permissions:'

## Control: the unmodified fixtures match policy, so --audit must pass.
## Without this, a tool that ALWAYS failed would satisfy every case above.
cp -a -- "${FIXTURES_DIR}/." "${work}/"
rc=0
out="$(ORGS_OVERRIDE='org-ai-assisted' dm-github-org-policy --audit 2>&1)" || rc=$?
if [ "${rc}" -ne 0 ]; then
   printf '%s\n' "FAIL: control: --audit exited '${rc}' on fixtures that match policy" >&2
   printf '%s\n' '--- captured output ---' >&2
   printf '%s\n' "${out}" >&2
   fail=1
else
   printf '%s\n' 'PASS: control: clean fixtures still audit green'
fi

exit "${fail}"
