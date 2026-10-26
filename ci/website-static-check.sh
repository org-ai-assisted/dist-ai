#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Static website-consistency CI lane: the browser-free, sandbox-free checks that
## CAN run on a stock GitHub runner --
##   check_site.py       links + wording + footer + nav + card-layout + csp + seo + ...
##   check_svg_safety.py first-party SVG active-content (defusedxml-guarded)
## Both are pure Python (no Playwright, no Qubes bwrap), so they exit 0/1 and gate CI
## cleanly. The full website-tests wrapper ALSO drives the browser lanes (Playwright)
## and the sandbox-delegated lanes (lint/vnu/lighthouse/axe, Qubes bwrap), NEITHER of
## which a GitHub runner has, so there it exits 78 (env-unmet) and cannot gate CI --
## hence this dedicated static lane. The browser lanes have their own CI wrappers
## (website-mobile-check.sh / website-width-check.sh); the sandbox lanes stay on the
## operator's local pre-push / sandbox path.
##
## Args: one or more site roots (each a directory with index.html).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"
tests_dir="${script_dir}/../usr/share/website-tests"
check_site="${tests_dir}/check_site.py"
check_svg="${tests_dir}/check_svg_safety.py"

for checker in "${check_site}" "${check_svg}"; do
   if [ ! -f "${checker}" ]; then
      printf '%s\n' "FAIL: required static checker not found: '${checker}'" >&2
      exit 1
   fi
done

if [ "$#" -eq 0 ]; then
   printf '%s\n' 'FAIL: no site root given' >&2
   exit 1
fi

## check_site.py / check_svg_safety.py silently drop a non-directory argument, so a
## misspelled root among good ones would let the gate pass without ever loading that
## site. Reject it here -- the same guard the browser-lane wrappers apply.
for site_root in "$@"; do
   if [ ! -d "${site_root}" ]; then
      printf '%s\n' "FAIL: site root is not a directory: '${site_root}'" >&2
      exit 1
   fi
done

## Both checkers are +x with an absolute-path shebang ('#!/usr/bin/python3 -Bsu'),
## so direct-exec honours that shebang's isolation (no pyc, no user-site, unbuffered)
## and self-resolves dist_ai from the checkout. Run BOTH even if the first finds
## something, so one invocation reports every static finding rather than stopping at
## the first.
rc=0
"${check_site}" "$@" || rc=1
"${check_svg}" "$@" || rc=1
exit "${rc}"
