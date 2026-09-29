#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for derivative-maker help-steps/parse-cmd: --function must be
## EXPORTED, like every other parsed variable.
##
## THE BUG: parse-cmd set FUNCTION as a plain (unexported) shell variable while
## dist_build_one_parsed IS exported. A parent that pre-exports
## dist_build_one_parsed=true (help-steps/sign-and-tag, sign-tag-head, any wrapper)
## makes a child SKIP the parse (variables.d/05_load-config.bsh), so the child
## inherits dist_build_one_parsed=true but NOT FUNCTION -> FUNCTION defaults empty
## -> build-steps.d/2100_create-debian-packages runs ALL packages instead of the
## single named --function. Fix: export FUNCTION at parse time so a child inherits
## the scope exactly as it inherits the parse-skip flag.
##
## Drives the REAL parse-cmd by SOURCING it (parse-cmd defines
## dist_build_one_parse_cmd but does not run it when sourced) and reads the export
## attribute from a CHILD process -- the exact parent->child inheritance the bug
## needs. No logic is reimplemented. Needs no root, no network, no build.

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
parse_cmd="${PARSE_CMD:-${dm_checkout}/help-steps/parse-cmd}"
if [ ! -r "${parse_cmd}" ]; then
   printf '%s\n' "FATAL: parse-cmd not readable at '${parse_cmd}' (set DERIVATIVE_MAKER_DIR or PARSE_CMD)." >&2
   exit 1
fi

pass() { printf '%s\n' "PASS: $*"; }
test_failures=0
fail() { printf '%s\n' "FAIL: $*" >&2; test_failures=$((test_failures + 1)); }

## Drive the REAL arg parser with "$@", then print how a CHILD process sees
## FUNCTION. A child inherits FUNCTION only if parse-cmd exported it -- the exact
## mechanism that decides whether an inherited-parse-skip child scopes to the one
## function or builds everything. parse-cmd re-enables errexit at source time and
## calls exit/error on mandatory-arg checks; both are neutralized INSIDE this
## subshell only so the arg loop runs to completion.
child_sees_function() {
   (
      # shellcheck disable=SC1090
      source "${parse_cmd}" >/dev/null 2>&1
      ## style-ok: allow-errexit-toggle -- neutralize parse-cmd's mandatory-arg
      ## exit/error so the arg loop under test runs to completion in this probe
      set +o errexit
      set +o nounset
      set +o pipefail
      # shellcheck disable=SC2317  # invoked indirectly, from the sourced parse-cmd
      exit() { return "${1:-0}"; }
      # shellcheck disable=SC2317  # invoked indirectly, from the sourced parse-cmd
      error() { return 0; }
      unset FUNCTION
      dist_build_one_parse_cmd "$@" >/dev/null 2>&1
      ## A fresh child shell: prints FUNCTION only if it was EXPORTED into the env.
      bash -c 'printf "%s" "${FUNCTION:-UNSET-IN-CHILD}"'
   )
}

out="$( child_sees_function --function download_tpo_packages )"
if [ "${out}" = "download_tpo_packages" ]; then
   pass "--function is exported: a child inherits FUNCTION='${out}'"
else
   fail "--function not exported: child saw '${out}', expected 'download_tpo_packages' (an inherited-parse-skip child would build ALL packages)"
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: parse-cmd exports --function; an inherited-parse-skip child keeps the single-function scope."
