#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for dm-check-unicode's Unicode allow-list mechanism.
##
## Some vendored / upstream files legitimately carry non-ASCII (e.g. translated
## manpages), are not ours to change, and must not trip the Unicode check. This
## drives the REAL 'whitelist_list' array and the REAL 'whitelist_pattern'
## construction line out of the script (no drift), then applies the exact
## production filter to assert a whitelisted path is excluded while a
## non-whitelisted path is still reported (canary: the filter is not blanket-off).

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
## Standalone dmf component checkout wins (DEVELOPER_META_FILES_DIR); else the
## derivative-maker submodule path.
script="${DEVELOPER_META_FILES_DIR:-${dm_checkout}/packages/kicksecure/developer-meta-files}/usr/bin/dm-check-unicode"
if [ ! -r "${script}" ]; then
   printf '%s\n' "FATAL: dm-check-unicode not found at '${script}' (set DEVELOPER_META_FILES_DIR or DERIVATIVE_MAKER_DIR)." >&2
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

## Materialize the production allow-list + pattern EXACTLY as the script builds them.
## Reads the current script text, so the test cannot drift from the code it guards.
eval "$( sed -n '/^whitelist_list=(/,/^)/p' -- "${script}" )"
eval "$( sed -n '/^whitelist_pattern=/p' -- "${script}" )"

## Structural: a representative whitelisted path (translated manpages) is present.
## Uses a currently-shipped entry as the fixture, so the test tracks the live
## allow-list rather than a specific historical entry.
sample_entry='./live-build/manpages/po/fr/.*'
found=no
for entry in "${whitelist_list[@]}"; do
   if [ "${entry}" = "${sample_entry}" ]; then
      found=yes
   fi
done
if [ "${found}" = yes ]; then
   pass "whitelist_list contains the sample allow-list entry"
else
   fail "whitelist_list is missing '${sample_entry}'"
fi

## Behavioral: run the SAME invert-match filter production uses. A whitelisted hit
## must be filtered OUT; a non-whitelisted hit must survive.
sample_hit='./live-build/manpages/po/fr/debian.po:94: emoji here'
other_hit='./packages/kicksecure/some-package/usr/bin/some-file:1: emoji here'
filtered="$( printf '%s\n%s\n' "${sample_hit}" "${other_hit}" \
   | grep --invert-match --extended-regexp -- "${whitelist_pattern}" || true )"

case "${filtered}" in
   *"${sample_hit}"*)
      fail "whitelisted hit was NOT excluded by the whitelist"
      ;;
   *)
      pass "whitelisted hit is excluded by the whitelist"
      ;;
esac
case "${filtered}" in
   *"${other_hit}"*)
      pass "a non-whitelisted unicode hit still survives the filter (check not blanket-disabled)"
      ;;
   *)
      fail "canary broken: a non-whitelisted hit was also filtered -- the pattern over-matches"
      ;;
esac

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: dm-check-unicode Unicode allow-list mechanism."
