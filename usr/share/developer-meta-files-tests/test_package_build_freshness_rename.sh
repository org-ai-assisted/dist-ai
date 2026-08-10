#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Guards the rename of the rebuild-detection library from 'reprepro-freshness.bsh'
## to 'package-build-freshness.bsh' (it manages package-build-hash manifests, not
## just reprepro state). The regression is a STALE reference: the library lives in
## the developer-meta-files submodule but is sourced from the derivative-maker
## SUPERPROJECT (build-steps.d/2100_create-debian-packages), so a missed path
## silently breaks the package-build step. Assert the new name is present and the
## old name is gone on BOTH sides.
##
## Self-contained; greps files, runs nothing. Needs no root, no network, no build.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

if [ -n "${DERIVATIVE_MAKER_DIR:-}" ]; then
   dm_checkout="${DERIVATIVE_MAKER_DIR}"
else
   dm_checkout="${HOME}/derivative-maker"
fi

pass_count=0
pass() {
   pass_count=$(( pass_count + 1 ))
   printf '%s\n' "PASS: $*"
}
test_failures=0
fail() {
   test_failures=$((test_failures + 1))
   printf '%s\n' "FAIL: $*" >&2
}

## The derivative-maker superproject holds the caller (build-steps.d) and the
## developer-meta-files submodule holds the library. Both come from one checkout.
caller="${dm_checkout}/build-steps.d/2100_create-debian-packages"
dmf_libexec="${dm_checkout}/packages/kicksecure/developer-meta-files/usr/libexec/developer-meta-files"
if [ -n "${DEVELOPER_META_FILES_DIR:-}" ]; then
   dmf_libexec="${DEVELOPER_META_FILES_DIR}/usr/libexec/developer-meta-files"
fi
if [ ! -r "${caller}" ] || [ ! -d "${dmf_libexec}" ]; then
   printf '%s\n' "SKIP: derivative-maker superproject checkout not found (set DERIVATIVE_MAKER_DIR)." >&2
   exit 77
fi

new_name='package-build-freshness.bsh'
old_name='reprepro-freshness.bsh'

## --- the library file: new name present, old gone --------------------------
if [ -r "${dmf_libexec}/${new_name}" ]; then
   pass "library exists at ${new_name}"
else
   fail "library ${new_name} not found in ${dmf_libexec}"
fi
if [ -e "${dmf_libexec}/${old_name}" ]; then
   fail "the old ${old_name} still exists; the rename left a duplicate"
else
   pass "the old ${old_name} is gone"
fi

## --- the caller sources the new name, never the old ------------------------
if grep --quiet --fixed-strings -- "${new_name}" "${caller}"; then
   pass "$(basename -- "${caller}") references ${new_name}"
else
   fail "$(basename -- "${caller}") does not reference ${new_name}; the source path is stale"
fi
if grep --quiet --fixed-strings -- "${old_name}" "${caller}"; then
   fail "$(basename -- "${caller}") still references the old ${old_name}"
else
   pass "$(basename -- "${caller}") has no stale ${old_name} reference"
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s) (${pass_count} passed)." >&2
   exit 1
fi
printf '%s\n' "OK: package-build-freshness rename (${pass_count} assertions)."
