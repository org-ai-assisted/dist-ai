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

printf '%s\n' "" "test_website_tests_required_check_fatal: ${pass_count} pass, ${fail_count} fail, 0 skip"
[ "${fail_count}" -eq 0 ]
