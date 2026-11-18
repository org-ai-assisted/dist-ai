#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## Pins a silent-green regression in usr/bin/website-tests: check_mobile.py and
## check_width.py are co-located SHIPPED tests (usr/share/website-tests/). Their
## `if [ -f ... ]` guards must FATAL (overall=1) on absence: a bare guard with no
## else (the regression this guards) makes a missing required test a full PASS
## (exit 0) with nothing run -- a false green in the Pages-deploy gate.
##
## Asserted STRUCTURALLY on the shipped runner text (driving the full runner needs
## a live site + Playwright detection; a full-layout drive is disproportionate for a
## missing-file branch). Each -f guard's block must contain an `else` that FATALs.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

pass_count=0
fail_count=0
pass() { pass_count=$(( pass_count + 1 )); printf '%s\n' "PASS: $*"; }
fail() { fail_count=$(( fail_count + 1 )); printf '%s\n' "FAIL: $*" >&2; }

test_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
runner="${test_dir}/../../bin/website-tests"
[ -r "${runner}" ] || runner='/usr/bin/website-tests'
if [ ! -r "${runner}" ]; then
   printf '%s\n' "FATAL: website-tests not found" >&2
   exit 1
fi

## The browser-lane checkers (mobile/width/footer/console/webplatform/forced_reflow) are co-located
## SHIPPED tests. Their presence (install integrity) MUST be verified up front, before the browser
## probe/dispatch -- so a missing one FATALs as a broken install even on a host with no browser,
## where it used to read as a plain "browser SKIP" (silent green). Assert the single up-front loop,
## that it FATALs, that it precedes the browser dispatch, and that no browser-lane checker's
## integrity is gated behind the browser-present branch. On the pre-fix runner (existence checked
## only inside the browser-present branch) the up-front loop is absent -> fail.
browser_lane_checks=(check_mobile.py check_width.py check_footer.py check_console.py \
                     check_webplatform.py check_forced_reflow.py)

## (1) the up-front integrity loop exists and lists every browser-lane checker.
loop_body="$(sed -n '/^for _req in check_mobile\.py/,/^done$/p' -- "${runner}")"
if [ -n "${loop_body}" ]; then
   pass 'browser-lane integrity: an up-front for-_req loop over the browser-lane checkers exists'
else
   fail 'browser-lane integrity: no up-front for-_req loop (a missing checker reads as a browser SKIP, silent green)'
fi
missing_from_loop=0
for chk in "${browser_lane_checks[@]}"; do
   grep --quiet --fixed-strings "${chk}" <<< "${loop_body}" \
      || { fail "browser-lane integrity: ${chk} missing from the up-front loop"; missing_from_loop=1; }
done
[ "${missing_from_loop}" -eq 0 ] \
   && pass 'browser-lane integrity: every browser-lane checker is covered by the up-front loop'

## (2) the loop FATALs (message + overall=1 + install_intact=false) on an absent checker.
if grep --quiet --fixed-strings 'required browser-lane test missing' <<< "${loop_body}" \
      && grep --quiet --extended-regexp 'overall=1' <<< "${loop_body}" \
      && grep --quiet --fixed-strings "install_intact='false'" <<< "${loop_body}"; then
   pass 'browser-lane integrity: a missing checker FATALs (message + overall=1 + install_intact=false)'
else
   fail 'browser-lane integrity: the up-front loop does not FATAL on an absent checker'
fi

## (3) integrity precedes browser dispatch: the loop is ABOVE the "Local browser present" branch.
loop_ln="$(grep --line-number --max-count=1 --fixed-strings 'for _req in check_mobile.py' "${runner}" | cut -d: -f1)"
disp_ln="$(grep --line-number --max-count=1 --fixed-strings 'Local browser present' "${runner}" | cut -d: -f1)"
if [ -n "${loop_ln}" ] && [ -n "${disp_ln}" ] && [ "${loop_ln}" -lt "${disp_ln}" ]; then
   pass 'browser-lane integrity: the up-front loop precedes the browser-present dispatch'
else
   fail 'browser-lane integrity: integrity is not verified before the browser dispatch'
fi

## (4) no per-lane browser-gated FATAL remains for a browser-lane checker (the old silent-skip shape:
## a literal 'FATAL: check_<x>.py not found' that fires only inside the browser-present branch).
leftover=0
for chk in "${browser_lane_checks[@]}"; do
   if grep --quiet --fixed-strings "FATAL: ${chk} not found" "${runner}"; then
      fail "browser-lane integrity: a per-lane 'FATAL: ${chk} not found' remains (integrity still browser-gated)"
      leftover=1
   fi
done
[ "${leftover}" -eq 0 ] \
   && pass 'browser-lane integrity: no per-lane browser-gated FATAL remains for a browser-lane checker'

## The five *_test.py unit regressions run via the run_required_unit_test helper, which
## FATALs on an absent shipped test. Assert: (a) the helper exists and FATALs on absence,
## (b) every one of the five is invoked through it, and (c) NO bare `if [ -f
## "${tests_dir}/<x>_test.py" ]` guard remains (that was the silent-skip pattern).
if grep --quiet --extended-regexp '^run_required_unit_test\(\) \{' "${runner}"; then
   helper_body="$(sed -n '/^run_required_unit_test() {/,/^}/p' -- "${runner}")"
   if grep --quiet --fixed-strings 'FATAL:' <<< "${helper_body}" \
         && grep --quiet --extended-regexp 'exit 1' <<< "${helper_body}"; then
      pass 'run_required_unit_test helper FATALs (message + exit 1) on an absent shipped test'
   else
      fail 'run_required_unit_test helper does not FATAL on an absent test'
   fi
else
   fail 'run_required_unit_test helper is missing (the 5 unit-test guards lost their FATAL)'
fi

for ut in check_site_test.py check_mobile_test.py check_width_test.py check_seo_test.py site_generate_test.py; do
   if grep --quiet --fixed-strings "run_required_unit_test ${ut}" "${runner}"; then
      pass "${ut}: invoked via run_required_unit_test (FATAL-on-absent)"
   else
      fail "${ut}: not routed through run_required_unit_test -> may be a silent-skip bare guard"
   fi
done

## No bare `if [ -f "${tests_dir}/<x>_test.py" ]` unit-test guard may survive (the silent-skip shape).
if grep --quiet --extended-regexp 'if \[ -f "\$\{tests_dir\}/[a-z_]+_test\.py" \]' "${runner}"; then
   fail 'a bare -f guard on a *_test.py unit test remains (silent-skip); route it through run_required_unit_test'
else
   pass 'no bare -f guard on a *_test.py unit test remains'
fi

printf '%s\n' "" "test_website_tests_required_check_fatal: ${pass_count} pass, ${fail_count} fail, 0 skip"
[ "${fail_count}" -eq 0 ]
