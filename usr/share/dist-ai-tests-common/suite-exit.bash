#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Canonical test-result vocabulary + suite-runner exit decision, sourced by every
## usr/bin/<component>-tests runner and usable by case scripts.
##
## Exit codes are DISTINCT per outcome so a code is never overloaded -- each skip
## category means exactly one thing and is named by its emitter:
##   0  PASS                 result_pass
##   1  FAIL                  result_fail             -- a real test defect
##   77 SKIP:target-absent    result_skip_target_absent -- the code UNDER TEST is
##        not present (unwired / cross-component / not-yet-shipped). A coverage
##        gap: in a full or own-component run it should NOT happen. (77 keeps the
##        GNU Automake skip convention for this canonical case.)
##   78 SKIP:env-unmet        result_skip_env_unmet   -- a RUNTIME capability the
##        test needs is absent in this environment (root, display, network, a live
##        service, a VM/sandbox). "Cannot run here", legitimately tolerated where
##        the environment genuinely lacks it.
## The specific thing missing rides in each emitter's REASON argument, not its own
## code -- a per-capability code would sprawl without adding policy value.
##
## AUDIT-STRICT: every skip surfaces (never folded into a green pass) so the
## orchestrator's --allow-skip governs it per category -- a component's own CI
## authorizes no skips, so a test that did not run reds the build.
##
## Pure sourced-only fragment: functions only, no strict-mode preamble and no
## was_executed guard.
## style-ok: no-strict -- sourced-only fragment

## --- result emitters: exit with the canonical code (never return) ---
## Each takes an OPTIONAL reason (printed to stderr). Runners/cases call these
## directly with a reason; suite_exit (below) calls them with none.

result_pass() {
   exit 0
}

result_fail() {
   [ -z "${1:-}" ] || printf '%s\n' "${1}" >&2
   exit 1
}

result_skip_target_absent() {
   [ -z "${1:-}" ] || printf '%s\n' "SKIP (target absent): ${1}" >&2
   ## style-ok: allow-skip: canonical target-absent SKIP emitter; the code under test is not present, --allow-skip governs it at the orchestrator
   exit 77
}

result_skip_env_unmet() {
   [ -z "${1:-}" ] || printf '%s\n' "SKIP (environment unmet): ${1}" >&2
   ## style-ok: allow-skip: canonical env-unmet SKIP emitter; a runtime capability is absent here, --allow-skip governs it at the orchestrator
   exit 78
}

## Map an exit code to its word, for reporting.
result_word() {
   case "${1:-}" in
      0)
         printf '%s' 'PASS'
         ;;
      77)
         printf '%s' 'SKIP:target-absent'
         ;;
      78)
         printf '%s' 'SKIP:env-unmet'
         ;;
      *)
         printf '%s' 'FAIL'
         ;;
   esac
}

## suite_exit <failed> <target_absent> <env_unmet>: aggregate per-case counts into
## the canonical suite result. Precedence fail > target-absent > env-unmet > pass:
##   - failed>0       -> FAIL (1).
##   - target_absent>0 -> SKIP:target-absent (77): the more serious coverage gap.
##   - env_unmet>0    -> SKIP:env-unmet (78).
##   - else           -> PASS (0).
## Each skip surfaces for --allow-skip to govern. Missing counts default to 0.
## Never returns.
suite_exit() {
   local failed_count="${1:-0}" target_absent_count="${2:-0}" env_unmet_count="${3:-0}"
   if [ "${failed_count}" -gt 0 ]; then
      result_fail ''
   fi
   if [ "${target_absent_count}" -gt 0 ]; then
      result_skip_target_absent ''
   fi
   if [ "${env_unmet_count}" -gt 0 ]; then
      result_skip_env_unmet ''
   fi
   result_pass
}
