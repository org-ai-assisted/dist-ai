#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## style-ok: no-has -- standalone test; does not source helper-scripts.

## Behavioral regression for WEBSITE_TESTS_SKIP_SITES in usr/bin/website-tests. Drives the REAL
## exclusion path (SOURCE the runner -- its guard returns before the suite -- then call the real
## site_in_skip_set / add_site / resolve_st_site guard; NO function-body extraction). Asserts:
##  - opt-in skip of a non-target sibling drops it from roots and logs a loud NOTICE;
##  - FAIL-CLOSED: skipping a site that has an explicit _REPO override (site-deploy's publish
##    target) is a FATAL, never a silent green (the false-green this guards);
##  - exact space-padded token match (skipping "ai" must NOT drop "org-ai-assisted.github.io");
##  - a non-skipped site is still added normally;
##  - the secure-terminal shot-inventory path (resolve_st_site) is gated by the same skip set.

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

## A real-looking site checkout so add_root would accept the default path (has index.html).
fixture="$(mktemp --directory)"
cleanup() { safe-rm --recursive --force -- "${fixture}"; }
trap cleanup EXIT
touch "${fixture}/index.html"

## Source the runner: its source-able guard returns before the suite body, leaving the site-set
## helpers defined. Set the globals they read (the execution section that normally sets them is
## below the guard, so it did not run).
# shellcheck disable=SC1090
source "${runner}"
## Globals read by the sourced add_root/site_in_skip_set (cross-function; not seen by shellcheck).
# shellcheck disable=SC2034
home_unset=''

## 1. site_in_skip_set: exact space-padded token, never substring.
WEBSITE_TESTS_SKIP_SITES='ai computer-security-research.github.io'
if ! site_in_skip_set org-ai-assisted.github.io && site_in_skip_set computer-security-research.github.io; then
   pass 'site_in_skip_set matches whole tokens only (ai does not match org-ai-assisted.github.io)'
else
   fail 'site_in_skip_set token matching wrong (substring match or missed an exact token)'
fi

## 2. Skip a non-target sibling (no override): dropped from roots, loud NOTICE, nothing added.
WEBSITE_TESTS_SKIP_SITES='computer-security-research.github.io'
roots=(); root_sites=()
skip_err="${fixture}/skip.err"
add_site computer-security-research.github.io '' "${fixture}" 2> "${skip_err}"
if [ "${#roots[@]}" -eq 0 ] && [ "${#root_sites[@]}" -eq 0 ] \
      && grep --quiet --fixed-strings 'NOTICE: skipping computer-security-research.github.io' "${skip_err}"; then
   pass 'skipping a non-target sibling drops it from roots and logs a NOTICE'
else
   fail "skip-no-override: roots=${#roots[@]} root_sites=${#root_sites[@]} err=<<$(cat "${skip_err}")>>"
fi

## 3. FAIL-CLOSED: skipping a site that HAS an explicit override (the publish target) is FATAL.
## add_site calls `exit 1`, so drive it in a subshell and capture the status + message.
WEBSITE_TESTS_SKIP_SITES='output-lies.github.io'
roots=(); root_sites=()
fc_err="${fixture}/fc.err"
fc_rc=0
( add_site output-lies.github.io "${fixture}" "${fixture}" ) 2> "${fc_err}" || fc_rc=$?
if [ "${fc_rc}" -ne 0 ] \
      && grep --quiet --fixed-strings 'refusing to skip the site being tested' "${fc_err}"; then
   pass 'skipping the explicitly-targeted (override-set) site is a FATAL, not a false green'
else
   fail "fail-closed: expected FATAL+nonzero, got rc=${fc_rc} err=<<$(cat "${fc_err}")>>"
fi

## 4. A non-skipped site with no override is still added normally (empty skip set).
## (read by the sourced site_in_skip_set; shellcheck cannot see the cross-function use)
# shellcheck disable=SC2034
WEBSITE_TESTS_SKIP_SITES=''
roots=(); root_sites=()
add_site output-lies.github.io '' "${fixture}" 2> /dev/null
if [ "${#roots[@]}" -eq 1 ] && [ "${roots[0]}" = "${fixture}" ] && [ "${root_sites[0]}" = 'output-lies.github.io' ]; then
   pass 'a non-skipped site is added normally (default scan unchanged)'
else
   fail "normal-add: roots=(${roots[*]:-}) root_sites=(${root_sites[*]:-})"
fi

## 5. resolve_st_site is gated by the same skip set (finding: secure-terminal had a 2nd entry
## point). Structural: the call must be guarded by site_in_skip_set (behavior of the predicate
## itself is covered above; this pins the wiring so the shot-inventory guard honors the skip).
## Literal source text to grep for, not shell to expand -- single quotes are intentional.
# shellcheck disable=SC2016
## Match the skip predicate on secure-terminal alone (no `if`/`; then` anchors): the guard ANDs a
## single-site-scope check, so site_in_skip_set sits on a continuation line, not at the `if`.
if grep --quiet --extended-regexp '! site_in_skip_set secure-terminal\.github\.io' "${runner}" \
      && grep --quiet --fixed-strings 'resolve_st_site "${SECURE_TERMINAL_SITE_REPO}"' "${runner}"; then
   pass 'resolve_st_site (shot-inventory path) is gated by the skip set'
else
   fail 'resolve_st_site is not guarded by site_in_skip_set -- secure-terminal skip would be incomplete'
fi

printf '%s\n' "" "test_website_tests_skip_sites: ${pass_count} pass, ${fail_count} fail, 0 skip"
[ "${fail_count}" -eq 0 ]
