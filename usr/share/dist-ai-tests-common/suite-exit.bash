#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Canonical test-result vocabulary + suite-runner exit decision, sourced by every
## usr/bin/<component>-tests runner. Exit codes follow the GNU Automake test
## convention: 0 PASS, 77 SKIP, any other nonzero FAIL. The orchestrator
## (dist-ai-tests-all) classifies a suite by this code.
##
## AUDIT-STRICT skip policy (deliberate): mainstream harnesses count skips but let
## a passed+skipped run report overall PASS. dist-ai's goal is COVERAGE AUDIT, so
## ANY skip surfaces as SKIP (77) for the orchestrator's --allow-skip to govern --
## a component's own CI authorizes no skips, so a test that did not run reds the
## build instead of passing green.
##
## Pure sourced-only fragment: functions only, no strict-mode preamble and no
## was_executed guard, so sourcing it into a runner changes nothing but the
## available functions.
## style-ok: no-strict -- sourced-only fragment

## --- result emitters: exit with the canonical code (never return) ---
## Each takes an OPTIONAL message (printed to stderr); runners call these directly
## with a reason, suite_exit (below) calls them with none.

result_pass() {
   exit 0
}

result_fail() {
   [ -z "${1:-}" ] || printf '%s\n' "${1}" >&2
   exit 1
}

result_skip() {
   [ -z "${1:-}" ] || printf '%s\n' "${1}" >&2
   ## style-ok: allow-skip: canonical SKIP emitter; the caller decided this is an optional/authorized skip, --allow-skip governs it at the orchestrator
   exit 77
}

## Map an exit code to its word, for reporting.
result_word() {
   case "${1:-}" in
      0)
         printf '%s' 'PASS'
         ;;
      77)
         printf '%s' 'SKIP'
         ;;
      *)
         printf '%s' 'FAIL'
         ;;
   esac
}

## suite_exit <failed> <skipped>: aggregate per-case counts into the canonical
## suite result. Precedence fail > skip > pass:
##   - failed>0  -> FAIL (1): a real test defect.
##   - skipped>0 -> SKIP (77): coverage did not fully run; --allow-skip must
##     authorize it or the orchestrator reds the suite (audit-strict, see above).
##   - else      -> PASS (0).
## Missing/empty counts default to 0. Never returns.
suite_exit() {
   local failed_count="${1:-0}" skipped_count="${2:-0}"
   if [ "${failed_count}" -gt 0 ]; then
      result_fail ''
   fi
   if [ "${skipped_count}" -gt 0 ]; then
      result_skip ''
   fi
   result_pass
}
