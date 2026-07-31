#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## W-008 (OWNER-GATE): every job that runs steps must be gated on the
## CI-enabled variable.
##
## Why the rule exists: our workflows used to run wherever the branch
## landed -- burning Kicksecure/Whonix runner quota once merged upstream,
## and running the whole suite unbidden on every contributor fork. Only
## 5 of 136 workflow files carried any owner gate.
##
## Why it is machine-checked: the gate is ONE STRING repeated across ~50
## files. A typo or a renamed variable would disable it everywhere while
## every run still reported green. Checking the exact literal is what
## makes repeating it safe.
##
## Fixtures are static repo roots under ../fixtures/owner-gate/, one per
## case, so what is being asserted is readable without running it.
##
## Both directions are asserted. A rule that only ever flags things
## would satisfy the negative cases while breaking every real repo, and
## a rule that never flags anything would satisfy the positive ones.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

if [ "${CI:-}" != "true" ]; then
   printf '%s\n' \
      'error: this script must run with CI=true (GitHub Actions or equivalent).' >&2
   exit 1
fi

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" && pwd )"
FIXTURES="$(cd -- "${SCRIPT_DIR}/../fixtures/owner-gate" && pwd)"
VALIDATOR="${SCRIPT_DIR}/test_workflow_yaml.py"

if [ ! -r "${VALIDATOR}" ]; then
   printf 'FAIL: validator not found at %s\n' "${VALIDATOR}" >&2
   exit 1
fi

pass_count=0
fail_count=0

pass() {
   pass_count=$(( pass_count + 1 ))
   printf 'PASS: %s\n' "$1"
}

fail() {
   fail_count=$(( fail_count + 1 ))
   printf 'FAIL: %s\n' "$1" >&2
}

## Args: $1 = fixture dir, $2 = expect 'flag' | 'clean', $3 = description.
check_case() {
   local case_dir expect desc out rc flagged

   case_dir="${FIXTURES}/$1"
   expect="$2"
   desc="$3"

   if [ ! -d "${case_dir}" ]; then
      fail "${desc}: fixture '${case_dir}' missing"
      return 0
   fi

   rc=0
   out="$(python3 -- "${VALIDATOR}" "${case_dir}" 2>&1)" || rc=$?

   flagged='no'
   if printf '%s\n' "${out}" | grep --quiet -- ':W-008:'; then
      flagged='yes'
   fi

   case "${expect}" in
      'flag')
         if [ "${flagged}" = 'yes' ] && [ "${rc}" -ne 0 ]; then
            pass "${desc}"
         else
            fail "${desc} (flagged=${flagged}, rc=${rc})"
            printf '%s\n' "${out}" | sed 's/^/    | /' >&2
         fi
         ;;
      'clean')
         if [ "${flagged}" = 'no' ]; then
            pass "${desc}"
         else
            fail "${desc} (unexpectedly flagged)"
            printf '%s\n' "${out}" | sed 's/^/    | /' >&2
         fi
         ;;
      *)
         fail "${desc}: bad expectation '${expect}'"
         ;;
   esac
}

## The rule bites.
check_case 'ungated'          'flag'  'an ungated job with steps is flagged'
## An unexplained carve-out is itself a finding: a gate nobody had to
## justify turning off is how coverage quietly disappears.
check_case 'exempt-no-reason' 'flag'  'an exemption with no reason is flagged'

## The rule does not over-reach.
check_case 'gated'            'clean' 'a gated job passes'
check_case 'exempt'           'clean' 'an exemption WITH a reason passes'
## A wrapper job allocates no runner of its own; the reusable it calls
## carries the gate.
check_case 'wrapper-only'     'clean' 'a uses:-only wrapper job is not flagged'
## 'if: false' allocates no runner either way.
check_case 'kill-switch'      'clean' 'an if:false kill-switch is not flagged'

printf '\n%s pass, %s fail, 0 skip\n' "${pass_count}" "${fail_count}"
[ "${fail_count}" -eq 0 ]
