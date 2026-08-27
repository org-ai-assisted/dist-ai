#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for dm-check-unicode's grml-debootstrap workflow allow-list.
##
## Upstream grml-debootstrap CI workflows carry emoji in PR/release-note text; they
## are not ours to change and not shipped in any image, so dm-check-unicode must not
## reject them. This drives the REAL 'whitelist_list' array and the REAL
## 'whitelist_pattern' construction line out of the script (no drift), then applies
## the exact production filter to assert a grml workflow path is excluded while a
## non-whitelisted path is still reported (canary: dropping the entry re-blocks it).

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
script="${dm_checkout}/packages/kicksecure/developer-meta-files/usr/bin/dm-check-unicode"
if [ ! -r "${script}" ]; then
   printf '%s\n' "FATAL: dm-check-unicode not found at '${script}' (set DERIVATIVE_MAKER_DIR)." >&2
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

## Structural: the grml workflows dir is in the allow-list.
grml_entry='./grml-debootstrap/.github/workflows/.*'
found=no
for entry in "${whitelist_list[@]}"; do
   if [ "${entry}" = "${grml_entry}" ]; then
      found=yes
   fi
done
if [ "${found}" = yes ]; then
   pass "whitelist_list contains the grml workflows entry"
else
   fail "whitelist_list is missing '${grml_entry}'"
fi

## Behavioral: run the SAME invert-match filter production uses (line ~196). A grml
## workflow hit must be filtered OUT; a non-whitelisted hit must survive.
grml_hit='./grml-debootstrap/.github/workflows/release.yml:94: emoji here'
other_hit='./packages/kicksecure/some-package/usr/bin/some-file:1: emoji here'
filtered="$( printf '%s\n%s\n' "${grml_hit}" "${other_hit}" \
   | grep --invert-match --extended-regexp -- "${whitelist_pattern}" || true )"

case "${filtered}" in
   *"${grml_hit}"*)
      fail "grml workflow hit was NOT excluded by the whitelist"
      ;;
   *)
      pass "grml workflow hit is excluded by the whitelist"
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
printf '%s\n' "OK: dm-check-unicode grml workflow allow-list."
