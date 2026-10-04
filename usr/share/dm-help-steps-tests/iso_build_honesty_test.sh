#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Meta-regression test for iso_build_test.sh -- it guards the GUARD, so two
## quality defects in the suite itself cannot come back:
##
## 1. Honest summary: when the end-to-end case (the only one proving the REAL
##    official path emits '--repo true') is SKIPPED for want of a derivative-maker
##    checkout, the final 'OK:' summary must NOT claim that property. A skipped
##    assertion read as verified is a fabricated green.
##
## 2. Env isolation: iso_build_test.sh's run_iso must strip the caller's ambient
##    DM_* so a stray DM_ARCH/etc. in the environment cannot FALSELY fail the
##    default-value assertions.
##
## Both cases drive the REAL iso_build_test.sh with an EMPTY derivative-maker
## checkout, so the e2e case deterministically skips and the behaviour under test
## is isolated. Needs no root, no network, no build (iso_build_test.sh drives the
## real dm-iso-build against its own recording stub).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=./help_steps_test_lib.bsh
source "${test_dir}/help_steps_test_lib.bsh"

## Test seam (mirrors iso_build_test.sh's DM_ISO_BUILD_BIN): point the meta-test
## at a pre-fix copy to confirm these assertions FAIL on the old suite.
subject="${DM_ISO_BUILD_TEST_SH:-${test_dir}/iso_build_test.sh}"
if [ ! -r "${subject}" ]; then
   printf '%s\n' "FATAL: iso_build_test.sh not found/readable at '${subject}'." >&2
   exit 1
fi

## An empty directory has no help-steps/dm-build-official-one, so iso_build_test.sh's
## e2e case skips -- giving both assertions a deterministic skipped-e2e run.
empty_checkout="$(mktemp --directory)"
cleanup() { safe-rm --recursive --force -- "${empty_checkout}"; }
trap cleanup EXIT

## --- Case 1 (finding 1): a skipped e2e is never summarised as verified -----------
## Run with no derivative-maker checkout; the suite must still pass its stub cases
## (exit 0), REPORT the skip, and NOT claim 'real path emits --repo true'.
rc1=0
out1="$(DERIVATIVE_MAKER_DIR="${empty_checkout}" bash -- "${subject}" 2>&1)" || rc1="$?"
if [ "${rc1}" -eq 0 ] \
   && grep --quiet --fixed-strings -- 'SKIP (end-to-end)' <<< "${out1}" \
   && grep --quiet --fixed-strings -- 'OK: dm-iso-build' <<< "${out1}" \
   && ! grep --quiet --fixed-strings -- 'real path emits --repo true' <<< "${out1}"; then
   pass "a skipped e2e is reported and NOT summarised as verified '--repo true'"
else
   fail "skipped-e2e summary is dishonest or the run did not pass; rc=${rc1} out=<<<${out1}>>>"
fi

## --- Case 2 (finding 2): ambient DM_* cannot falsely fail a default-value case ---
## DM_ARCH=arm64 in the environment must not reach the wrapper's default-value
## assertions; run_iso strips it, so the suite still passes (exit 0).
rc2=0
out2="$(DM_ARCH=arm64 DERIVATIVE_MAKER_DIR="${empty_checkout}" bash -- "${subject}" 2>&1)" || rc2="$?"
if [ "${rc2}" -eq 0 ]; then
   pass "ambient DM_ARCH does not contaminate the default-value assertions"
else
   fail "ambient DM_ARCH leaked into the suite and falsely failed it; rc=${rc2} out=<<<${out2}>>>"
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: iso_build_test.sh reports a skipped e2e honestly and isolates ambient DM_* from its default-value assertions."
