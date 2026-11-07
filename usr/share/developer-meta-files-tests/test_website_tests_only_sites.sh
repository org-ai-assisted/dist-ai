#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## style-ok: no-has -- standalone test; does not source helper-scripts.

## Behavioral regression for WEBSITE_TESTS_ONLY_SITES in usr/bin/website-tests -- the opt-in ALLOW
## list (inverse of WEBSITE_TESTS_SKIP_SITES) that test-results-deploy sets to gate ONLY
## org-ai-assisted when publishing the automated-test-results plane, so an unrelated sibling-site
## regression cannot block the results publish. Drives the REAL path (SOURCE the runner -- its
## guard returns before the suite -- then call the real site_in_only_set / add_site; NO
## function-body extraction). Asserts:
##  - empty allow-list (the default) allows EVERY site, so the full family gate is unchanged;
##  - a non-empty list allows ONLY its tokens (exact space-padded match: "ai" must NOT match
##    "org-ai-assisted.github.io");
##  - a non-target sibling excluded by the allow-list is dropped from roots with a loud NOTICE;
##  - the allowed target site is still added -- it stays gated;
##  - FAIL-CLOSED: dropping a site that has an explicit _REPO override (the publish/test target)
##    is a FATAL, never a silent green (the false-green this guards).

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
## Globals read by the sourced add_root/site_in_skip_set/site_in_only_set (cross-function; not
## seen by shellcheck). add_site now consults BOTH sets, so both must be defined under nounset.
# shellcheck disable=SC2034
home_unset=''
## (read by the sourced site_in_skip_set inside add_site; shellcheck cannot see the cross-function use)
# shellcheck disable=SC2034
WEBSITE_TESTS_SKIP_SITES=''

## 1. Empty allow-list (the default) allows every site -- the full family gate is unchanged.
WEBSITE_TESTS_ONLY_SITES=''
if site_in_only_set org-ai-assisted.github.io && site_in_only_set output-lies.github.io; then
   pass 'empty WEBSITE_TESTS_ONLY_SITES allows every site (full family gate unchanged by default)'
else
   fail 'empty allow-list did not allow every site'
fi

## 2. Non-empty list allows ONLY its tokens; exact space-padded match, never substring.
WEBSITE_TESTS_ONLY_SITES='ai org-ai-assisted.github.io'
if site_in_only_set org-ai-assisted.github.io && ! site_in_only_set output-lies.github.io; then
   pass 'site_in_only_set allows only listed sites; "ai" token does not match org-ai-assisted.github.io'
else
   fail 'site_in_only_set membership wrong (substring match or missed/leaked a token)'
fi

## 3. A non-target sibling (no override) excluded by the allow-list: dropped from roots, loud
## NOTICE, nothing added.
WEBSITE_TESTS_ONLY_SITES='org-ai-assisted.github.io'
roots=(); root_sites=()
only_err="${fixture}/only.err"
add_site output-lies.github.io '' "${fixture}" 2> "${only_err}"
if [ "${#roots[@]}" -eq 0 ] && [ "${#root_sites[@]}" -eq 0 ] \
      && grep --quiet --fixed-strings 'NOTICE: skipping output-lies.github.io (not in WEBSITE_TESTS_ONLY_SITES)' "${only_err}"; then
   pass 'a sibling excluded by the allow-list is dropped from roots and logs a NOTICE'
else
   fail "only-drop: roots=${#roots[@]} root_sites=${#root_sites[@]} err=<<$(cat "${only_err}")>>"
fi

## 4. The allowed target site is still added normally -- it stays gated.
WEBSITE_TESTS_ONLY_SITES='org-ai-assisted.github.io'
roots=(); root_sites=()
add_site org-ai-assisted.github.io "${fixture}" "${fixture}" 2> /dev/null
if [ "${#roots[@]}" -eq 1 ] && [ "${roots[0]}" = "${fixture}" ] && [ "${root_sites[0]}" = 'org-ai-assisted.github.io' ]; then
   pass 'the allowed target (org-ai-assisted.github.io) is still added -- it stays gated'
else
   fail "allowed-add: roots=(${roots[*]:-}) root_sites=(${root_sites[*]:-})"
fi

## 5. FAIL-CLOSED: excluding a site that HAS an explicit override (the publish target) is FATAL.
## add_site calls `exit 1`, so drive it in a subshell and capture the status + message.
## (read by the sourced site_in_only_set inside add_site; shellcheck cannot see the cross-function use)
# shellcheck disable=SC2034
WEBSITE_TESTS_ONLY_SITES='org-ai-assisted.github.io'
roots=(); root_sites=()
fc_err="${fixture}/fc.err"
fc_rc=0
( add_site output-lies.github.io "${fixture}" "${fixture}" ) 2> "${fc_err}" || fc_rc=$?
if [ "${fc_rc}" -ne 0 ] \
      && grep --quiet --fixed-strings 'refusing to drop the site being tested' "${fc_err}"; then
   pass 'excluding the explicitly-targeted (override-set) site is a FATAL, not a false green'
else
   fail "fail-closed: expected FATAL+nonzero, got rc=${fc_rc} err=<<$(cat "${fc_err}")>>"
fi

printf '%s\n' "" "test_website_tests_only_sites: ${pass_count} pass, ${fail_count} fail, 0 skip"
[ "${fail_count}" -eq 0 ]
