#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test: dist_build_one_parsed is a SAME-SHELL idempotency guard
## (variables.d/05_load-config.bsh skips re-parsing when it is already true in
## THIS shell). It must NEVER be exported. Exporting leaks the parse-skip into
## child build-step PROCESSES, which then skip validating their OWN argv:
##   - an unknown flag (e.g. a typo like --rebuild-packages) is silently ignored
##     instead of erroring;
##   - --function is dropped, so create-debian-packages builds ALL packages
##     instead of the one named.
## The correct pattern is non-exported (like dm-reprepro-wrapper): every process
## re-parses its own complete argv (the main flow forwards full args).
##
## Whole-surface guard: NO file in the derivative-maker tree may export the flag
## -- catches a revert at the config loader OR any helper (sign-and-tag,
## sign-tag-head, dm-tor-update-repository, dm-virtualbox-guest-additions-iso-update).
## Structural + fast: no root, no network, no build. The behavioural proof (a
## build-step child errors on an unknown flag / honors --function) is the real
## build.

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
if [ ! -d "${dm_checkout}" ]; then
   printf '%s\n' "FATAL: derivative-maker checkout not found at '${dm_checkout}' (set DERIVATIVE_MAKER_DIR)." >&2
   exit 1
fi
loader="${dm_checkout}/variables.d/05_load-config.bsh"
dmf_bin="${dm_checkout}/packages/kicksecure/developer-meta-files/usr/bin"

pass() { printf '%s\n' "PASS: $*"; }
test_failures=0
fail() { printf '%s\n' "FAIL: $*" >&2; test_failures=$((test_failures + 1)); }

## 1. Whole-surface: nothing in the tree may `export dist_build_one_parsed`.
##    grep -r over the tracked tree; .git is excluded.
mapfile -t exporters < <(
   grep -rIln --exclude-dir=.git --extended-regexp \
      '^[[:space:]]*export[[:space:]]+dist_build_one_parsed' "${dm_checkout}" 2>/dev/null || true
)
if [ "${#exporters[@]}" -eq 0 ]; then
   pass "no file exports dist_build_one_parsed (same-shell guard cannot leak into child processes)"
else
   for exporter in "${exporters[@]}"; do
      fail "exports dist_build_one_parsed -- leaks parse-skip into --function/unknown-flag children: ${exporter#"${dm_checkout}/"}"
   done
fi

## 2. The config loader must STILL set the guard (non-exported) -- guards against
##    deleting the idempotency guard while removing the export.
if [ ! -r "${loader}" ]; then
   fail "config loader not readable at '${loader}' -- test needs review"
elif grep --quiet --extended-regexp '^[[:space:]]*dist_build_one_parsed="true"' "${loader}"; then
   pass "config loader sets dist_build_one_parsed non-exported (same-shell idempotency preserved)"
else
   fail "config loader no longer sets dist_build_one_parsed=\"true\" -- test needs review"
fi

## 3. dm-tor-update-repository still pre-sets the guard (non-exported) before
##    invoking its --function child, proving the leak path stays closed.
helper="${dmf_bin}/dm-tor-update-repository"
if [ -r "${helper}" ]; then
   if grep --quiet --extended-regexp '^[[:space:]]*dist_build_one_parsed=true' "${helper}"; then
      pass "dm-tor-update-repository pre-sets the guard non-exported (child re-parses + honors --function)"
   else
      fail "dm-tor-update-repository no longer sets dist_build_one_parsed as expected -- test needs review"
   fi
fi

## 4. dm-get-tor-from-tpo-repo (the caller that passes --function to a build-step
##    child) still relies on the child re-parsing: assert the invocation carries
##    --function.
caller="${dmf_bin}/dm-get-tor-from-tpo-repo"
if [ -r "${caller}" ]; then
   if grep --quiet --extended-regexp '\-\-function[[:space:]]+download_tpo_packages' "${caller}"; then
      pass "dm-get-tor-from-tpo-repo invokes the build-step child with --function download_tpo_packages"
   else
      fail "dm-get-tor-from-tpo-repo no longer passes --function download_tpo_packages -- test needs review"
   fi
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: dist_build_one_parsed is never exported; the parse-skip cannot leak into a child process."
