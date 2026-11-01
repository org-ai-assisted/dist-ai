#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## style-ok: no-has -- standalone structural test; does not source helper-scripts.

## Pins the WEBSITE_TESTS_SKIP_SITES opt-in exclude in usr/bin/website-tests: a deploy that must
## not gate on an in-progress sibling (e.g. a journal _site being actively rebuilt) drops the
## named site from the scanned set. Asserted STRUCTURALLY on add_site: driving root resolution
## behaviorally needs the full suite preamble (the run_required_unit_test calls run before root
## resolution, so add_site is not reachable via the source-able guard) -- disproportionate here.
## The matching MUST be exact-token (space-padded, comma-normalized), never substring, so skipping
## "ai" cannot drop "org-ai-assisted.github.io". End-to-end behavior is confirmed by site-deploy.

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

## (a) the env var is defaulted (unset -> empty, i.e. scan every site).
if grep --quiet --extended-regexp '^\[ -v WEBSITE_TESTS_SKIP_SITES \] \|\| WEBSITE_TESTS_SKIP_SITES=' "${runner}"; then
   pass 'WEBSITE_TESTS_SKIP_SITES is defaulted (empty = scan all, the unchanged default)'
else
   fail 'WEBSITE_TESTS_SKIP_SITES has no default guard'
fi

## (b) add_site honors it: a case over the comma-normalized, space-padded list, a loud NOTICE,
## and an early return (so a skipped site never reaches add_root / the roots array).
add_site_body="$(sed -n '/^add_site(){/,/^}/p' -- "${runner}")"
## Literal source text to grep for, not shell to expand -- single quotes are intentional.
# shellcheck disable=SC2016
if grep --quiet --fixed-strings 'WEBSITE_TESTS_SKIP_SITES//,/ ' <<< "${add_site_body}" \
      && grep --quiet --fixed-strings '*" ${site} "*' <<< "${add_site_body}"; then
   pass 'add_site matches skip list by EXACT space-padded token (not substring)'
else
   fail 'add_site skip match is missing or not exact-token (substring match would mis-drop sites)'
fi
if grep --quiet --fixed-strings 'NOTICE: skipping' <<< "${add_site_body}" \
      && grep --quiet --extended-regexp '^[[:space:]]*return$' <<< "${add_site_body}"; then
   pass 'a skipped site logs a loud NOTICE and returns before add_root (never scanned silently)'
else
   fail 'skip path lacks a NOTICE log or the early return'
fi

printf '%s\n' "" "test_website_tests_skip_sites: ${pass_count} pass, ${fail_count} fail, 0 skip"
[ "${fail_count}" -eq 0 ]
