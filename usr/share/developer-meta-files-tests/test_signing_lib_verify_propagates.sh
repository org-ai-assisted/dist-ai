#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for signing-lib.bsh verify_signature() / sign_and_verify():
## every signature check MUST propagate its failure.
##
## THE BUG IT GUARDS: the lib is sourceable and carries no errexit, so a run of
## UNCHAINED statements returns only the LAST command's status. verify_cmd_signify
## returns 0 unconditionally for a file_size_mb >= 1000, so a >=1000MB artifact
## with an INVALID OpenPGP signature verified as GOOD -- a verifier whose failure
## reads as success. The fix chains every check with '|| return'.

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
lib="${dm_checkout}/packages/kicksecure/developer-meta-files/usr/libexec/developer-meta-files/signing-lib.bsh"
if [ ! -r "${lib}" ]; then
   printf '%s\n' "FATAL: signing-lib.bsh not found at '${lib}' (set DERIVATIVE_MAKER_DIR)." >&2
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

## Run verify_signature with the OpenPGP check stubbed to return ${1} and the
## file forced to the >=1000MB path (where the REAL verify_cmd_signify returns 0
## unconditionally -- the exact spot the bypass hid). Echo verify_signature's
## exit code. A subshell so the stubs cannot leak between cases.
verify_rc() {
   local pgp_rc="$1" rc=0
   (
      # shellcheck disable=SC1090
      source "${lib}"
      ## Force the large-file branch: real verify_cmd_signify then returns 0.
      # shellcheck disable=SC2317
      signing_lib_set_file_size_mb() { file_size_mb="1000"; }
      # shellcheck disable=SC2317
      verify_cmd_openpgp() { return "${pgp_rc}"; }
      verify_signature /nonexistent-artifact >/dev/null 2>&1
   ) || rc="$?"
   printf '%s' "${rc}"
}

## CANARY: an INVALID OpenPGP signature on a >=1000MB file must FAIL, even though
## signify is skipped-and-returns-0. Returns 0 on the pre-fix code.
if [ "$(verify_rc 1)" -ne 0 ]; then
   pass "verify_signature FAILS on a bad OpenPGP sig for a >=1000MB file"
else
   fail "verify_signature returned 0 for a bad OpenPGP sig (signature-verification bypass)"
fi

## A valid OpenPGP signature on a >=1000MB file still verifies (signify skipped).
if [ "$(verify_rc 0)" -eq 0 ]; then
   pass "verify_signature succeeds when the OpenPGP sig is valid (large file)"
else
   fail "verify_signature wrongly failed a valid signature"
fi

## sign_and_verify has the same 4-check structure; assert every check chains.
## An unchained 'verify_cmd_openpgp ... ' line (no trailing '|| return') is the bug.
if grep --extended-regexp --quiet '^\s+(sign|verify)_cmd_(openpgp|signify) "\$\{1\}"[^|]*$' -- "${lib}"; then
   fail "signing-lib.bsh has an UNCHAINED sign/verify check (status would be masked)"
else
   pass "every sign/verify check in signing-lib.bsh is chained (|| return)"
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: signing-lib verify propagation."
