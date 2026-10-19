#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## W-009 (FORK-PR-GUARD): a reusable (workflow_call) job that checks
## out a PR-controllable ref -- an actions/checkout whose 'ref:' is a
## '${{ ... }}' expression -- must carry the fork-PR guard in its 'if:'.
##
## Why the rule exists: reusable-coverity.yml checked out
## 'ref: ${{ env.DIST_AI_REF }}' (which resolves to github.sha on the
## dist-ai repo) in its secret-bearing Coverity job, yet was the one
## PR-triggered reusable missing the fork-PR guard every sibling
## carried. CodeQL's actions/untrusted-checkout flagged it. Nothing
## enforced the guard, so the omission was silent -- exactly the class
## this rule closes.
##
## Why it is machine-checked: a reusable cannot see its caller's
## trigger, so the guard is the ONLY thing standing between a
## pull_request_target caller and fork code running with secrets. A new
## reusable must not be able to omit it unnoticed.
##
## Fixtures are static repo roots under ../fixtures/fork-pr-guard/, one
## per case, so what is asserted is readable without running it. Both
## directions are asserted: a rule that only ever flags, or never
## flags, would pass half the cases while being useless.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

if [ "${CI:-}" != "true" ]; then
   printf '%s\n' \
      'error: this script must run with CI=true (GitHub Actions or equivalent).' >&2
   exit 1
fi

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" && pwd )"
FIXTURES="$(cd -- "${SCRIPT_DIR}/../fixtures/fork-pr-guard" && pwd)"
VALIDATOR="${SCRIPT_DIR}/test_workflow_yaml.py"

if [ ! -r "${VALIDATOR}" ]; then
   printf '%s\n' "FAIL: validator not found at ${VALIDATOR}" >&2
   exit 1
fi

pass_count=0
fail_count=0

pass() {
   pass_count=$(( pass_count + 1 ))
   printf '%s\n' "PASS: ${1}"
}

fail() {
   fail_count=$(( fail_count + 1 ))
   printf '%s\n' "FAIL: ${1}" >&2
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
   out="$("${VALIDATOR}" "${case_dir}" 2>&1)" || rc=$?

   flagged='no'
   if grep --quiet -- ':W-009 FORK-PR-GUARD:' <<< "${out}"; then
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
check_case 'flag-unguarded'    'flag'  'a reusable checking out an expression ref with no fork-PR guard is flagged'
## Naming pull_request without the head-repo check still runs on fork PRs.
check_case 'flag-pr-event-only' 'flag' 'a pull_request-gated reusable without the head-repo check is flagged'
## A negated non-PR event ('!= schedule') is true on a PR -> must NOT be treated as safe (fail-closed).
check_case 'flag-negated-nonpr-event' 'flag' 'a reusable gated on a negated non-PR event is flagged (no fail-open)'
## The guard literal present only in a non-gating '||' arm must still flag (per-disjunct check).
check_case 'flag-or-arm-bypass' 'flag' 'a guard literal in a bypassable OR-arm is flagged'
## A bare 'event_name != pull_request' does not defend pull_request_target -> require the head-repo guard.
check_case 'flag-bare-pr-negation' 'flag' 'a bare pull_request event negation (no head-repo guard) is flagged'
## The head-repo substring inside a '||' with a fork-firing sibling arm must still flag.
check_case 'flag-guard-wrong-event' 'flag' 'a guard-shaped clause with the wrong event (|| != schedule) is flagged'

## The rule does not over-reach.
check_case 'clean-guarded'     'clean' 'a reusable with the fork-PR guard passes'
## A schedule/workflow_dispatch-only job never sees a pull_request.
check_case 'clean-non-pr'      'clean' 'a non-pull_request-only reusable job passes'
## The same-repo-PR-only AND form (event==pull_request && head-repo match) is safe.
check_case 'clean-same-repo-pr' 'clean' 'a same-repo-PR-only AND-form reusable job passes'
## Normalization treats 'event_name==x' (no spaces) as equivalent -> not a false positive.
check_case 'clean-nospace-event' 'clean' 'a non-PR event gate without spaces around == passes'
## A literal trusted ref ('master') is not PR-controllable.
check_case 'clean-literal-ref' 'clean' 'a reusable checking out a literal ref is not flagged'
## A non-reusable workflow bounds its own risk via its in-file 'on:'.
check_case 'clean-not-reusable' 'clean' 'a non-reusable workflow is out of scope'

printf '%s\n' "" "${pass_count} pass, ${fail_count} fail, 0 skip"
[ "${fail_count}" -eq 0 ]
