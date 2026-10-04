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
## Pre-init both so a script that no longer defines them (renamed/refactored, the sed
## matching nothing) leaves an EMPTY list/pattern -- a clean structural fail below --
## rather than tripping 'set -o nounset' with an 'unbound variable' crash.
whitelist_list=()
whitelist_pattern=''
eval "$( sed -n '/^whitelist_list=(/,/^)/p' -- "${script}" )"
eval "$( sed -n '/^whitelist_pattern=/p' -- "${script}" )"

## Structural: the allow-list is NOT empty. An emptied list would turn the Unicode
## check into a blanket pass for every path -- that is the regression this guards.
## WHICH paths are whitelisted is dm-check-unicode's call; the test tracks the LIVE
## list (see the behavioral check) rather than mandating a historical entry, so a
## legitimate allow-list edit never false-fails it.
if [ "${#whitelist_list[@]}" -ge 1 ]; then
   pass "whitelist_list is non-empty (${#whitelist_list[@]} entries)"
else
   fail "whitelist_list is empty -- the Unicode allow-list would blanket-pass"
fi

## Behavioral: run the SAME invert-match filter production uses. A non-whitelisted
## hit must SURVIVE the filter; a whitelisted hit must be EXCLUDED. Uses the LIVE
## pattern so the test cannot drift from the script's actual list.
if [ "${#whitelist_list[@]}" -ge 1 ]; then
   ## Re-index densely so the first element is [0] even if the source array was
   ## sparse (a '[0]' read on a sparse/empty array crashes under nounset).
   dense=("${whitelist_list[@]}")
   entry="${dense[0]}"
   ## A path no legitimate allow-list entry names.
   other_hit='./not-whitelisted/unicode-check-canary:1: emoji here'

   ## CANARY -- runs UNCONDITIONALLY. A non-whitelisted hit MUST survive the filter.
   ## This is the load-bearing assertion: it fails on a blanket pattern (matches
   ## everything), an over-broad '^./.*', AND a malformed ERE (grep errors -> empty
   ## invert output -> the hit is dropped), each of which makes production's
   ## 'grep -v -E ... || true' silently drop every Unicode hit. It must NOT be gated
   ## behind the positive check below, or those cases slip through as a SKIP.
   canary_filtered="$( printf '%s\n' "${other_hit}" \
      | grep --invert-match --extended-regexp -- "${whitelist_pattern}" 2>/dev/null \
      || true )"
   case "${canary_filtered}" in
      *"${other_hit}"*)
         pass "a non-whitelisted unicode hit survives the filter (not blanket/over-matching)"
         ;;
      *)
         fail "a non-whitelisted hit was filtered out -- the pattern is blanket, over-broad, or a malformed ERE"
         ;;
   esac

   ## POSITIVE (best-effort) -- a path the first entry's ERE matches MUST be excluded.
   ## Synthesize by dropping a trailing '.*' (the ':94:' suffix then satisfies it) and
   ## keeping a literal path as-is; CONFIRM the live pattern matches it, else skip (an
   ## unusual ERE form this cannot synthesize is not a false fail -- the canary above
   ## already enforces the dangerous direction).
   sample_hit="${entry%.\*}:94: emoji here"
   if grep --quiet --extended-regexp -- "${whitelist_pattern}" <<< "${sample_hit}" \
      2>/dev/null; then
      pos_filtered="$( printf '%s\n' "${sample_hit}" \
         | grep --invert-match --extended-regexp -- "${whitelist_pattern}" 2>/dev/null \
         || true )"
      case "${pos_filtered}" in
         *"${sample_hit}"*)
            fail "whitelisted hit was NOT excluded by the whitelist"
            ;;
         *)
            pass "whitelisted hit is excluded by the whitelist"
            ;;
      esac
   else
      printf '%s\n' "SKIP: could not synthesize a positive sample for entry '${entry}' (unusual ERE form); negative canary still enforced"
   fi
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: dm-check-unicode Unicode allow-list mechanism."
