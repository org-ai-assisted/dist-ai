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
## e2e case skips -- giving the first two assertions a deterministic skipped-e2e run.
empty_checkout="$(mktemp --directory)"

## A fake derivative-maker checkout whose dm-build-official-one stub dry-plans like the
## real official path -- but mirrors ONE real behaviour the e2e leak depends on: a
## non-empty dist_build_multi_target_list (what an ambient DM_TARGET sets) re-plans the
## build off ISO, dropping the '--target iso' line the e2e greps for. Present (not empty),
## so iso_build_test.sh's e2e case RUNS against it.
fake_checkout="$(mktemp --directory)"
mkdir --parents -- "${fake_checkout}/help-steps"
{
   printf '%s\n' '#!/bin/bash'
   # shellcheck disable=SC2016  ## literal stub body: expand in the stub, not here
   printf '%s\n' 'if [ -n "${dist_build_multi_target_list:-}" ]; then'
   # shellcheck disable=SC2016
   printf '%s\n' '   printf "%s\n" "./derivative-maker --arch ${dist_build_target_arch:-amd64} --repo true --target ${dist_build_multi_target_list} --flavor ${flavors_list:-kicksecure-lxqt} --freshness frozen"'
   printf '%s\n' 'else'
   # shellcheck disable=SC2016
   printf '%s\n' '   printf "%s\n" "./derivative-maker --arch ${dist_build_target_arch:-amd64} --repo true --target iso --flavor ${flavors_list:-kicksecure-lxqt} --freshness frozen"'
   printf '%s\n' 'fi'
} > "${fake_checkout}/help-steps/dm-build-official-one"
chmod +x -- "${fake_checkout}/help-steps/dm-build-official-one"

cleanup() { safe-rm --recursive --force -- "${empty_checkout}" "${fake_checkout}"; }
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

## --- Case 3 (finding 2, e2e invocation): ambient DM_* cannot contaminate case 8 -------
## DM_TARGET=qcow2 in the environment must not reach the e2e official-path invocation; if
## it did, dm-iso-build would re-plan off ISO and the '--target iso' grep would false-fail.
## With the fake checkout present, case 8 RUNS and must still verify '--repo true' (exit 0).
rc3=0
out3="$(DM_TARGET=qcow2 DERIVATIVE_MAKER_DIR="${fake_checkout}" bash -- "${subject}" 2>&1)" || rc3="$?"
if [ "${rc3}" -eq 0 ] \
   && grep --quiet --fixed-strings -- 'PASS: the real official path dry-plans the ISO build with --repo true' <<< "${out3}"; then
   pass "ambient DM_TARGET does not contaminate the e2e official-path assertion"
else
   fail "ambient DM_TARGET leaked into the e2e assertion; rc=${rc3} out=<<<${out3}>>>"
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: iso_build_test.sh reports a skipped e2e honestly and isolates ambient DM_* from its default-value and e2e assertions."
