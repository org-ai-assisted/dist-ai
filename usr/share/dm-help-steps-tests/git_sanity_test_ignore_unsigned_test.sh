#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for git_sanity_test's no-AI-skip policy at the CONSUMPTION point.
##
## THE GAP IT GUARDS: parse-cmd only refuses --allow-unsigned in its FLAG branch, but
## dist_build_ignore_unsigned=true also reaches sq_git_verify() from the environment
## or a buildconfig.d snippet, bypassing the flag. sq_git_verify() is where the skip
## is HONORED, so the AI refusal lives there too: an AI session (CLAUDECODE) or a
## context setting dist_build_forbid_allow_unsigned=true must NOT skip signature
## verification; human override dist_build_unlock_dangerous_options=true.
##
## git_sanity_test is source-able (the `sourceable` skill): main() auto-runs only
## when executed, so sourcing it here defines sq_git_verify (plus the real colors +
## die) WITHOUT running the tool. The ignore-unsigned branch returns before any
## sq-git call, so no repo / sq-git is needed.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

if [ -n "${DERIVATIVE_MAKER_DIR:-}" ]; then
   dm_checkout="${DERIVATIVE_MAKER_DIR}"
else
   dm_checkout="${HOME}/derivative-maker"
fi
script="${dm_checkout}/help-steps/git_sanity_test"
if [ ! -r "${script}" ]; then
   printf '%s\n' "FATAL: git_sanity_test not found at '${script}' (set DERIVATIVE_MAKER_DIR)." >&2
   exit 1
fi

pass() {
   printf '%s\n' "PASS: $*"
}
test_failures=0
fail() {
   printf '%s\n' "FAIL: $*" >&2
   test_failures=$((test_failures + 1))
}

## Source the REAL script: defines sq_git_verify (and the colors / die it uses)
## without running main(). No sed extraction, so the test cannot drift from the code.
# shellcheck disable=SC1090
source "${script}"
if [ "$(type -t sq_git_verify)" != "function" ]; then
   printf '%s\n' "FATAL: sourcing git_sanity_test did not define sq_git_verify." >&2
   exit 1
fi

## Run the real sq_git_verify on the skip path (dist_build_ignore_unsigned=true)
## with the given env; echo its return code. Subshell so env does not leak.
## $1 = env-setup snippet.
verify_rc() {
   local rc=0
   (
      dist_build_redistributable='false'
      dist_build_ignore_unsigned='true'
      eval "$1"
      sq_git_verify HEAD testlabel >/dev/null 2>&1
   ) || rc="$?"
   printf '%s' "${rc}"
}

## Refused (nonzero): AI session, and the general forbid var.
if [ "$(verify_rc 'export CLAUDECODE=1')" -ne 0 ]; then
   pass "AI session (CLAUDECODE=1) is refused the skip"
else
   fail "AI session skipped verification (env bypass of the policy)"
fi
if [ "$(verify_rc 'unset CLAUDECODE; export dist_build_forbid_allow_unsigned=true')" -ne 0 ]; then
   pass "general forbid var is refused the skip"
else
   fail "dist_build_forbid_allow_unsigned=true did not refuse the skip"
fi

## Allowed (zero = skip proceeds): a human build, and the dangerous-options unlock.
if [ "$(verify_rc 'unset CLAUDECODE')" -eq 0 ]; then
   pass "human (no CLAUDECODE) skip proceeds"
else
   fail "human skip was wrongly refused"
fi
if [ "$(verify_rc 'export CLAUDECODE=1 dist_build_unlock_dangerous_options=true')" -eq 0 ]; then
   pass "AI + dangerous-options unlock skip proceeds"
else
   fail "dangerous-options unlock did not allow the skip"
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: git_sanity_test ignore-unsigned AI policy."
