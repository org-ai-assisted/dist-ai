#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## strings.bsh's variable-name validators must read/write the CALLER's variable
## correctly even when the caller's variable is named exactly like one of the
## function's own locals.
##
## THE BUG: these functions take a variable NAME and reach the caller's variable
## by indirect expansion (${!name}) / printf -v, but declared internal locals
## (strings_bsh_value, strings_bsh_varname, strings_bsh_var_name,
## strings_bsh_default_value). Under bash dynamic scoping a caller variable with
## one of those exact names is SHADOWED by the empty local, so the function reads
## the empty local instead of the caller's value -- a silent wrong result (a
## valid value reported empty/invalid; a default written to the local, never the
## caller's variable). The fix captures the value via the positional ${!1}
## before any shadowing local is declared, and default_if_empty operates on
## $1/$2 directly.
##
## Sources the REAL strings.bsh; each probe assigns the candidate to a variable
## named like an internal local, then calls the validator. No root, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v HELPER_SCRIPTS_REPO ] || HELPER_SCRIPTS_REPO=""

tree_root="${HELPER_SCRIPTS_REPO:-${HELPER_SCRIPTS_PATH:-}}"
tree_root="${tree_root%/}"
strings_bsh="${tree_root}/usr/libexec/helper-scripts/strings.bsh"

if [ ! -r "${strings_bsh}" ]; then
   printf '%s\n' "FATAL: strings.bsh not readable at '${strings_bsh}'" >&2
   printf '%s\n' "set HELPER_SCRIPTS_REPO (or HELPER_SCRIPTS_PATH) to a helper-scripts checkout, or install helper-scripts" >&2
   exit 1
fi

export HELPER_SCRIPTS_PATH="${tree_root}"

## The reject path of some validators calls 'sanitize-echo' (a python tool);
## resolve it and its module from the tree under test.
if [ -n "${tree_root}" ]; then
   PATH="${tree_root}/usr/bin:${PATH}"
   export PATH
   PYTHONPATH="${tree_root}/usr/lib/python3/dist-packages${PYTHONPATH:+:${PYTHONPATH}}"
   export PYTHONPATH
fi

# shellcheck disable=SC1090,SC1091
source "${strings_bsh}"

for fn in check_is_alpha_numeric validate_safe_filename check_is_not_empty_and_only_one_line default_if_empty; do
   if [ "$(type -t "${fn}")" != 'function' ]; then
      printf '%s\n' "FATAL: sourcing '${strings_bsh}' defined no '${fn}'" >&2
      exit 1
   fi
done

pass_count=0
fail_count=0
ok() { pass_count=$(( pass_count + 1 )); printf '%s\n' "PASS: $1"; }
notok() { fail_count=$(( fail_count + 1 )); printf '%s\n' "FAIL: $1" >&2; }

## Each probe assigns a VALID value to a variable named like an internal local of
## the function under test, then calls it. On the buggy (shadowing) code the value
## is read as empty -> wrong verdict. The probe locals are read only via the
## validator's indirect expansion, which shellcheck cannot see (SC2034).

# shellcheck disable=SC2034
probe_alnum_value() {
   local strings_bsh_value='abc123'
   check_is_alpha_numeric strings_bsh_value
}
# shellcheck disable=SC2034
probe_alnum_varname() {
   local strings_bsh_varname='abc123'
   check_is_alpha_numeric strings_bsh_varname
}
# shellcheck disable=SC2034
probe_safe_value() {
   local strings_bsh_value='hello.txt'
   validate_safe_filename strings_bsh_value
}
# shellcheck disable=SC2034
probe_oneline_value() {
   local strings_bsh_value='Hello, World!'
   check_is_not_empty_and_only_one_line strings_bsh_value
}

## Run the probe in a subshell: a validator's reject path returns non-zero (and
## runs sanitize-echo); the subshell confines the resulting errexit exit so the
## '|| rc=$?' captures a verdict instead of aborting the harness (no set +-e
## toggle, per R-011).
run_accept() {
   local label="$1" fn="$2" rc=0
   ( "${fn}" ) >/dev/null 2>&1 || rc=$?
   case "${rc}" in
      0)
         ok "${label}: caller variable read correctly (accepted)"
         ;;
      1)
         notok "${label}: caller variable SHADOWED -> valid value seen as empty/invalid"
         ;;
      *)
         notok "${label}: HARNESS ERROR (rc=${rc})"
         ;;
   esac
}

run_accept 'check_is_alpha_numeric / caller var "strings_bsh_value"' probe_alnum_value
run_accept 'check_is_alpha_numeric / caller var "strings_bsh_varname"' probe_alnum_varname
run_accept 'validate_safe_filename / caller var "strings_bsh_value"' probe_safe_value
run_accept 'check_is_not_empty_and_only_one_line / caller var "strings_bsh_value"' probe_oneline_value

## default_if_empty WRITES the caller's variable; a shadowed name means the
## default lands on the local and the caller's variable stays empty.
probe_default_writes() {
   local caller_name="$1"
   ( ## subshell so each probe's caller variable is independent
      ## create the caller variable, empty, under the colliding name (guard the
      ## dynamic printf -v name per R-063, though it is a fixed test literal).
      check_variable_name "${caller_name}" || exit 2
      printf -v "${caller_name}" '%s' ''
      default_if_empty "${caller_name}" 'fallback'
      [ "${!caller_name}" = 'fallback' ]
   )
}
run_default() {
   local label="$1" caller_name="$2" rc=0
   probe_default_writes "${caller_name}" || rc=$?
   case "${rc}" in
      0)
         ok "${label}: default written to the caller's variable"
         ;;
      1)
         notok "${label}: caller variable SHADOWED -> default written to the local, caller left empty"
         ;;
      *)
         notok "${label}: HARNESS ERROR (rc=${rc})"
         ;;
   esac
}
run_default 'default_if_empty / caller var "strings_bsh_var_name"' strings_bsh_var_name
run_default 'default_if_empty / caller var "strings_bsh_default_value"' strings_bsh_default_value

## Sanity: a normal (non-colliding) caller variable still validates correctly,
## and a genuinely empty value is still rejected -- so the fix did not blunt the
## checks.
# shellcheck disable=SC2034
probe_normal_ok() {
   local myval='ok_123'
   check_is_alpha_numeric myval
}
# shellcheck disable=SC2034
probe_normal_empty() {
   local myval=''
   check_is_alpha_numeric myval
}
run_accept 'check_is_alpha_numeric / normal caller var' probe_normal_ok
rc=0
( probe_normal_empty ) >/dev/null 2>&1 || rc=$?
if [ "${rc}" = 1 ]; then
   ok 'check_is_alpha_numeric / genuinely empty still rejected'
else
   notok "check_is_alpha_numeric / genuinely empty not rejected (rc=${rc})"
fi

printf '%s\n' ""
printf '%s\n' "${pass_count} pass, ${fail_count} fail"
[ "${fail_count}" -eq 0 ]
