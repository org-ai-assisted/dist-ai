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

work=''

# shellcheck disable=SC2317  # invoked via the EXIT trap, not inline
cleanup() {
   ## '|| true': a failing cleanup must not replace the test's verdict.
   [ -z "${work}" ] || safe-rm --recursive --force -- "${work}" || true
}
trap cleanup EXIT

work="$(mktemp --directory)"
cp -a -- "${FIXTURES_DIR}/." "${work}/"

export GHORG_MOCK=true
export GHORG_MOCK_DIR="${work}"

fail=0

## Assert that --audit fails and says why.
## Args: $1 = case name, $2 = expected substring.
expect_drift() {
   local desc needle rc out

   desc="$1"
   needle="$2"

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

## Case 1: the exact shape of the incident -- selected + empty patterns.
printf '%s\n' \
   '{"github_owned_allowed":true,"verified_allowed":true,"patterns_allowed":[]}' \
   'HTTP_STATUS:200' \
   > "${work}/GET_orgs_org-ai-assisted_actions_permissions_selected-actions"
expect_drift 'empty patterns_allowed is drift' 'patterns_allowed:'

## Case 2: an unreadable endpoint must NOT read as clean. A run that
## could not verify the state is a failure, not a pass.
cp -a -- "${FIXTURES_DIR}/." "${work}/"
printf '%s\n' '{"message":"Not Found"}' 'HTTP_STATUS:404' \
   > "${work}/GET_orgs_org-ai-assisted_actions_permissions_selected-actions"
expect_drift 'unreadable endpoint is not a pass' 'NOT VERIFIED'

## Case 3: allowed_actions flipped away from the policy value.
cp -a -- "${FIXTURES_DIR}/." "${work}/"
printf '%s\n' '{"enabled_repositories":"all","allowed_actions":"all"}' 'HTTP_STATUS:200' \
   > "${work}/GET_orgs_org-ai-assisted_actions_permissions"
expect_drift 'allowed_actions drift is caught' 'allowed_actions:'

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
