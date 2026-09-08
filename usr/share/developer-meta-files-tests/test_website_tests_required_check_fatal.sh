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

## For each required check, the fix adds an else arm printing a distinct FATAL message
## immediately followed by overall=1. Assert both are present and adjacent: grep the
## FATAL-message line and confirm the NEXT line is overall=1. Also confirm the `-f`
## guard itself still exists (so the check is real, not a dangling message). On the
## pre-fix runner (bare `-f` guard, no else) the FATAL message is absent -> fail.
check_guard_fatal() {
   local check="$1"
   if ! grep --quiet --fixed-strings "[ -f \"\${tests_dir}/${check}\" ]" "${runner}"; then
      fail "${check}: its -f guard is gone (test stale, or the check was removed)"
      return
   fi
   local ctx
   ctx="$(grep --after-context=1 --fixed-strings "FATAL: ${check} not found" "${runner}" || true)"
   if grep --quiet --extended-regexp 'overall=1' <<< "${ctx}"; then
      pass "${check}: absent required test is FATAL (message + overall=1), not a silent skip"
   else
      fail "${check}: -f guard has no FATAL else -> a missing required test reads as a green PASS (silent green)"
   fi
}

check_guard_fatal 'check_mobile.py'
check_guard_fatal 'check_width.py'

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
