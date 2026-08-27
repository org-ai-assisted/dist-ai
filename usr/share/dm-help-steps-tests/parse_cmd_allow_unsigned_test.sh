#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for parse-cmd's --allow-unsigned policy gate.
##
## THE POLICY IT GUARDS: skipping git_sanity_test signature verification
## ('--allow-unsigned true' -> dist_build_ignore_unsigned=true) is a HUMAN escape
## hatch. An AI agent (CLAUDECODE set) must NOT use it -- it has a sanctioned
## alternative (--sign-and-tag) that keeps verification meaningful. A general
## 'dist_build_forbid_allow_unsigned=true' lets any other context (CI, a hardened
## policy) forbid it too. Both are overridable only by the explicit
## dangerous-options unlock.
##
## Drives the REAL parse-cmd. It normally gets colors + error() from help-steps/pre;
## standalone it does not source pre, so this stubs ONLY that reporting layer (empty
## color vars + an error() that prints its message and aborts) -- the arg-parsing
## LOGIC under test is the real script's.

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
parse_cmd="${dm_checkout}/help-steps/parse-cmd"
if [ ! -x "${parse_cmd}" ]; then
   printf '%s\n' "FATAL: parse-cmd not found/executable at '${parse_cmd}' (set DERIVATIVE_MAKER_DIR)." >&2
   exit 1
fi

pass() {
   printf '%s\n' "PASS: $*"
}
test_failures=0
fail() {
   printf '%s\n' "FAIL: $*" >&2
   test_failures=$((test_failures + 1))
}

## The reporting layer help-steps/pre would provide. error() prints its message so
## the refusal string is greppable, then aborts like pre's real error() (which
## trips the fatal ERR trap).
export bold='' cyan='' eunder='' red='' reset='' under=''
error() {
   printf '%s\n' "$*"
   exit 1
}
export -f error

REFUSAL='allow-unsigned true is refused'

## $1 label, $2 expected (refused|allowed), then env assignments for this run.
probe() {
   local label="$1" expect="$2"; shift 2
   local out
   out="$( env "$@" "${parse_cmd}" --allow-unsigned true 2>&1 || true )"
   local got='allowed'
   case "${out}" in
      *"${REFUSAL}"*)
         got='refused'
         ;;
   esac
   if [ "${got}" = "${expect}" ]; then
      pass "${label} -> ${got}"
   else
      fail "${label}: expected ${expect}, got ${got}"
   fi
}

## Refused: AI session, and any context that opts into the general forbid.
probe "AI session (CLAUDECODE=1)"                refused CLAUDECODE=1
probe "general forbid var, no AI"               refused -u CLAUDECODE dist_build_forbid_allow_unsigned=true

## Allowed: a human build (no marker), and the explicit dangerous-options unlock.
probe "human (no CLAUDECODE, no forbid)"        allowed -u CLAUDECODE
probe "AI + dangerous-options unlock"           allowed CLAUDECODE=1 dist_build_unlock_dangerous_options=true
probe "forbid var + dangerous-options unlock"   allowed -u CLAUDECODE dist_build_forbid_allow_unsigned=true dist_build_unlock_dangerous_options=true

## --allow-unsigned false never trips the gate, even for an AI session.
false_out="$( env CLAUDECODE=1 "${parse_cmd}" --allow-unsigned false 2>&1 || true )"
case "${false_out}" in
   *"${REFUSAL}"*)
      fail "--allow-unsigned false wrongly refused for an AI session"
      ;;
   *)
      pass "--allow-unsigned false is never refused"
      ;;
esac

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: parse-cmd --allow-unsigned policy gate."
