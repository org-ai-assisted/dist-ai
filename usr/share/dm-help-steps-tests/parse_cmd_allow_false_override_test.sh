#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for derivative-maker help-steps/parse-cmd: an explicit
## '--<flag> false' MUST override an inherited '<var>=true' from the environment.
##
## The false branch of --allow-uncommitted / --allow-untagged / --unsafe-io only
## printed an INFO line and never exported the variable to "false" (unlike the
## correct sibling --allow-unsigned). Since the variables default to "false" only
## when EMPTY, an inherited '=true' survived the explicit override -- a silent
## no-op. This asserts the override wins.
##
## Drives the REAL parse-cmd via parse_cmd_source_driver.sh (its preseed positional
## pre-exports the variable to "true"), reads it back, asserts "false". On the pre-fix
## parser each reads back "true" -> FAIL (canary RED). Bounded by 'timeout' so a
## non-terminating arg loop surfaces as a FAIL instead of hanging the suite. No
## parser logic is reimplemented. Needs no root, no network, no build.

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
tests_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source_driver="${tests_dir}/parse_cmd_source_driver.sh"
if [ ! -r "${source_driver}" ]; then
   printf '%s\n' "FATAL: driver not readable at '${source_driver}'." >&2
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

## $1 var to read back, $2 preseed value, rest = args. Prints the var value, or
## '__TIMEOUT__' if the parse hangs (the infinite-loop guard).
drive_preseed() {
   local var_name="$1" preseed="$2"
   shift 2
   local out rc
   out="$(timeout --kill-after=5 10 bash "${source_driver}" "${parse_cmd}" "${var_name}" "${preseed}" "$@")" && rc=0 || rc=$?
   ## 124 = killed by SIGTERM on timeout; 137 = killed by SIGKILL (--kill-after).
   if [ "${rc}" -eq 124 ] || [ "${rc}" -eq 137 ]; then
      printf '%s' '__TIMEOUT__'
      return 0
   fi
   printf '%s' "${out}"
}

## $1 flag, $2 variable: inherited '<var>=true' must be overridden to "false" by
## '<flag> false'.
check_false_override() {
   local flag="$1" var="$2" out
   out="$(drive_preseed "${var}" true "${flag}" false)"
   if [ "${out}" = "false" ]; then
      pass "${flag} false overrides inherited ${var}=true -> 'false'"
   else
      fail "${flag} false did not override inherited ${var}=true: ${var}='${out}', expected 'false'"
   fi
}

check_false_override --allow-uncommitted dist_build_ignore_uncommitted
check_false_override --allow-untagged    dist_build_ignore_untagged
check_false_override --unsafe-io         dist_build_unsafe_io

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: parse-cmd '--<flag> false' overrides an inherited '=true' for allow-uncommitted, allow-untagged, unsafe-io."
