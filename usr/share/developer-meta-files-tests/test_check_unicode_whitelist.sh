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

## Structural: the allow-list is NOT empty. An emptied list would turn the Unicode
## check into a blanket pass for every path -- that is the regression this guards.
## WHICH paths are whitelisted is dm-check-unicode's call; the test tracks the LIVE
## list (see the behavioral check) rather than mandating a historical entry, so a
## legitimate allow-list edit never false-fails it.
# shellcheck disable=SC2154  # whitelist_list: populated by the eval of the subject script above
if [ "${#whitelist_list[@]}" -ge 1 ]; then
   pass "whitelist_list is non-empty (${#whitelist_list[@]} entries)"
else
   fail "whitelist_list is empty -- the Unicode allow-list would blanket-pass"
fi

## Behavioral: run the SAME invert-match filter production uses, against a hit built
## from a LIVE allow-list entry, so the test cannot drift from the script's actual
## list. A whitelisted hit must be filtered OUT; a non-whitelisted hit must survive.
## Entries are path patterns, so a line that BEGINS with an entry's text is matched
## by that entry's ERE (a literal path matches itself; a '.*'-tailed one matches any
## suffix) -- true for every historical and current entry.
if [ "${#whitelist_list[@]}" -ge 1 ]; then
   sample_hit="${whitelist_list[0]}:94: emoji here"
   ## A path no whitelist entry names. The canary below fails loudly if some entry
   ## ever does match it, so an accidental collision cannot pass silently.
   other_hit='./not-whitelisted/unicode-check-canary:1: emoji here'
   # shellcheck disable=SC2154  # whitelist_pattern: eval'd from the script under test above
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
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: dm-check-unicode Unicode allow-list mechanism."
