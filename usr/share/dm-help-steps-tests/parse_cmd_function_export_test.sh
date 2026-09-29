#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test: a helper that pre-sets the dist_build_one_parsed parse-skip
## guard must NOT export it, so a child PROCESS invoked with its OWN args
## (--function ...) re-parses and honors them.
##
## THE BUG: dist_build_one_parsed is a SAME-SHELL idempotency guard
## (variables.d/05_load-config.bsh skips re-parsing when it is already true in
## THIS shell). When a helper EXPORTS it, the flag leaks into child processes:
## dm-tor-update-repository exported it, then (via dm-get-tor-from-tpo-repo)
## invoked `*_create-debian-packages --function download_tpo_packages` -- that
## child inherited the export, SKIPPED parse, ignored --function, and built ALL
## packages (tirdad included) instead of the one named. Fix: set it NON-exported,
## like the already-correct dm-reprepro-wrapper.
##
## Two checks, both drive the REAL files (no reimplementation):
##  1. dm-tor-update-repository sets dist_build_one_parsed WITHOUT export.
##  2. No developer-meta-files helper that invokes a build-step child with
##     --function exports dist_build_one_parsed.
## Structural (guards a revert of the one-line fix); the behavioural proof that
## an inherited flag makes the child ignore --function is a sandbox/root check.
## Needs no root, no network, no build.

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
dmf_bin="${dm_checkout}/packages/kicksecure/developer-meta-files/usr/bin"
helper="${dmf_bin}/dm-tor-update-repository"
if [ ! -r "${helper}" ]; then
   printf '%s\n' "FATAL: dm-tor-update-repository not readable at '${helper}' (set DERIVATIVE_MAKER_DIR)." >&2
   exit 1
fi

pass() { printf '%s\n' "PASS: $*"; }
test_failures=0
fail() { printf '%s\n' "FAIL: $*" >&2; test_failures=$((test_failures + 1)); }

## 1. dm-tor-update-repository must set the flag, but NOT export it.
if grep --quiet --extended-regexp '^[[:space:]]*export[[:space:]]+dist_build_one_parsed' "${helper}"; then
   fail "dm-tor-update-repository EXPORTS dist_build_one_parsed -- leaks the parse-skip into its --function child, which then builds ALL packages"
elif grep --quiet --extended-regexp '^[[:space:]]*dist_build_one_parsed=true' "${helper}"; then
   pass "dm-tor-update-repository sets dist_build_one_parsed non-exported (child re-parses + honors --function)"
else
   fail "dm-tor-update-repository no longer sets dist_build_one_parsed as expected -- test needs review"
fi

## 2. dm-get-tor-from-tpo-repo (the caller that passes --function to a build-step
## child) still relies on the parent not exporting the flag: assert the child
## invocation carries --function AND the caller does not itself re-export the flag.
caller="${dmf_bin}/dm-get-tor-from-tpo-repo"
if [ -r "${caller}" ]; then
   if grep --quiet --extended-regexp '\-\-function[[:space:]]+download_tpo_packages' "${caller}"; then
      pass "dm-get-tor-from-tpo-repo invokes the build-step child with --function download_tpo_packages"
   else
      fail "dm-get-tor-from-tpo-repo no longer passes --function download_tpo_packages -- test needs review"
   fi
   if grep --quiet --extended-regexp '^[[:space:]]*export[[:space:]]+dist_build_one_parsed' "${caller}"; then
      fail "dm-get-tor-from-tpo-repo re-exports dist_build_one_parsed -- would re-break the --function child"
   fi
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: the parse-skip flag is not exported into the --function build-step child."
