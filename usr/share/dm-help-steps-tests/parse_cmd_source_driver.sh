#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Helper for parse_cmd_boolean_flags_test.sh. Sources the REAL parse-cmd and runs
## the real dist_build_one_parse_cmd with the given args, printing one exported
## variable. A dedicated script (not an inline 'bash -c') so it is style-gated and
## shellcheck'd, and so the test can bound it with 'timeout' (the infinite-loop
## guard). No parser logic is reimplemented.
##
## $1 parse-cmd path, $2 variable to read back, $3 preseed, rest: args forwarded to
## the parser. $3 empty -> the read-back variable starts cleared; $3 non-empty ->
## it is pre-exported to that value before the parser runs, so a test can assert an
## explicit flag value OVERRIDES an inherited environment value. Passed explicitly
## (not via the environment) so no caller can be contaminated by an inherited value.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

parse_cmd="$1"
var_name="$2"
preseed="$3"
shift 3

# shellcheck disable=SC1090  # dynamic path to the subject parse-cmd under test
source "${parse_cmd}" >/dev/null 2>&1

## style-ok: allow-errexit-toggle -- neutralize parse-cmd's strict mode and its
## mandatory-arg exit/error so the arg loop under test runs to completion here.
set +o errexit
set +o nounset
set +o pipefail
export dist_build_unlock_dangerous_options="true"

# shellcheck disable=SC2317  # invoked indirectly, from the sourced parse-cmd
exit() {
   return "${1:-0}"
}
# shellcheck disable=SC2317  # invoked indirectly, from the sourced parse-cmd
error() {
   return 0
}

if [ -n "${preseed}" ]; then
   export "${var_name}=${preseed}"
else
   unset "${var_name}"
fi
## dist_build_one_parse_cmd's exit STATUS is deliberately discarded: its error/exit
## path is neutralized to return() above (so the loop under test runs to completion),
## and in this isolated harness the parser ALSO takes that path on EVERY invocation
## for an unrelated reason (no action/subcommand follows the lone flag), so the status
## is a CONSTANT that carries no per-flag parse-success information -- capturing it
## would be a fabricated signal, not a real one. The read-back VALUE below is the
## genuine signal: a flag that failed value validation never sets its variable, so a
## bad parse cannot satisfy a value assertion (the caller's bogus-value cases drive
## the real parse-cmd via run_err and assert on its emitted error instead).
dist_build_one_parse_cmd "$@" >/dev/null 2>&1
printf '%s' "${!var_name:-UNSET}"
