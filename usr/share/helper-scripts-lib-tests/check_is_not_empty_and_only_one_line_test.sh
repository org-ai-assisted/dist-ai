#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## strings.bsh: check_is_not_empty_and_only_one_line, which accepts a value that
## is exactly one non-empty line and rejects empty / whitespace-only / carriage-
## return / multi-line values.
##
## THE BUG: it counts lines with 'mapfile -t <<<"${value}"'. The '<<<' here-
## string appends a newline of its OWN, so a legitimate single line that already
## ends in a newline becomes two mapfile elements and is FALSE-REJECTED as
## "more than one line". The fix strips one trailing newline before mapfile; a
## genuine multi-line value still counts as >1 line.
##
## The function takes a VARIABLE NAME whose VALUE it validates (it calls
## check_variable_name then reads the value by indirect expansion), so each
## candidate is assigned to a variable and its name is passed.
##
## Sources the REAL strings.bsh (no reimplementation). Tests the INSTALLED
## library by default; HELPER_SCRIPTS_REPO / HELPER_SCRIPTS_PATH point it at a
## checkout, which is what the suite runner wires in CI. No root, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v HELPER_SCRIPTS_REPO ] || HELPER_SCRIPTS_REPO=""

## Single source of truth for the tree under test: HELPER_SCRIPTS_REPO, else
## HELPER_SCRIPTS_PATH, else '' (the installed /usr/libexec tree). A named
## checkout that lacks strings.bsh is a FATAL misconfiguration, never a silent
## fallback to a different tree.
tree_root="${HELPER_SCRIPTS_REPO:-${HELPER_SCRIPTS_PATH:-}}"
tree_root="${tree_root%/}"
strings_bsh="${tree_root}/usr/libexec/helper-scripts/strings.bsh"

if [ ! -r "${strings_bsh}" ]; then
   printf '%s\n' "FATAL: strings.bsh not readable at '${strings_bsh}'" >&2
   printf '%s\n' "set HELPER_SCRIPTS_REPO (or HELPER_SCRIPTS_PATH) to a helper-scripts checkout, or install helper-scripts" >&2
   exit 1
fi

## strings.bsh sources its siblings (wc-test.sh, check_runtime.bsh) via
## ${HELPER_SCRIPTS_PATH:-}, so point that at the same tree; unset it would
## resolve those to the installed copy instead of the tree under test.
export HELPER_SCRIPTS_PATH="${tree_root}"

## The validator calls 'sanitize-echo' (a python tool) on a reject. With a
## checkout, resolve it -- and its sanitize_string module -- from that tree, so
## the case under test never silently exercises an installed copy (or dies
## ModuleNotFoundError where helper-scripts is not installed, e.g. CI).
if [ -n "${tree_root}" ]; then
   PATH="${tree_root}/usr/bin:${PATH}"
   export PATH
   PYTHONPATH="${tree_root}/usr/lib/python3/dist-packages${PYTHONPATH:+:${PYTHONPATH}}"
   export PYTHONPATH
fi

## shellcheck resolves the file statically from dist-ai's own tree, which has no
## helper-scripts copy, so there is nothing to point 'source=' at.
# shellcheck disable=SC1090,SC1091
source "${strings_bsh}"

if [ ! "$(type -t check_is_not_empty_and_only_one_line)" = 'function' ]; then
   printf '%s\n' "FATAL: sourcing '${strings_bsh}' defined no 'check_is_not_empty_and_only_one_line'" >&2
   printf '%s\n' "every case below would then fail on 'command not found', not on behaviour" >&2
   exit 1
fi

pass_count=0
fail_count=0

## Run the validator on a candidate value and echo its exit code. The candidate
## is held in a local variable whose NAME is passed (indirect expansion inside
## the function reads it via dynamic scope).
probe() {
   local candidate="$1" rc=0
   ## probe_value is read by check_is_not_empty_and_only_one_line via indirect
   ## expansion of the NAME passed to it; shellcheck cannot see that use.
   # shellcheck disable=SC2034
   local probe_value="${candidate}"
   check_is_not_empty_and_only_one_line probe_value >/dev/null 2>&1 || rc=$?
   printf '%s' "${rc}"
}

## A validator returns 0 (accept) or 1 (reject); ANY other value means it was
## never invoked -- a HARNESS error, NOT a verdict -- so a broken environment is
## never mistaken for a pass.
assert_accepts() {
   local label="$1" rc
   rc="$(probe "$2")"
   case "${rc}" in
      0)
         pass_count=$(( pass_count + 1 ))
         printf '%s\n' "PASS: ${label} -- accepted"
         ;;
      1)
         fail_count=$(( fail_count + 1 ))
         printf '%s\n' "FAIL: ${label} -- rejected a valid single line" >&2
         ;;
      *)
         fail_count=$(( fail_count + 1 ))
         printf '%s\n' "FAIL: ${label} -- HARNESS ERROR: validator not invoked (rc='${rc}')" >&2
         ;;
   esac
}

assert_rejects() {
   local label="$1" rc
   rc="$(probe "$2")"
   case "${rc}" in
      1)
         pass_count=$(( pass_count + 1 ))
         printf '%s\n' "PASS: ${label} -- rejected"
         ;;
      0)
         fail_count=$(( fail_count + 1 ))
         printf '%s\n' "FAIL: ${label} -- accepted an invalid value" >&2
         ;;
      *)
         fail_count=$(( fail_count + 1 ))
         printf '%s\n' "FAIL: ${label} -- HARNESS ERROR: validator not invoked (rc='${rc}')" >&2
         ;;
   esac
}

assert_accepts 'a plain single line' 'Hello, World!'
assert_accepts 'a single line with surrounding spaces' '  Hello  '
## The regression: a single line that already ends in a newline. Fails on the
## old code (the here-string's own newline inflates the mapfile count to 2).
assert_accepts 'a single line with a trailing newline' $'Hello, World!\n'

assert_rejects 'a genuine two-line value' $'Hello\nWorld'
assert_rejects 'a two-line value with a trailing newline' $'Hello\nWorld\n'
assert_rejects 'an empty value' ''
assert_rejects 'a whitespace-and-newlines-only value' $'\n\n   '
assert_rejects 'a value containing a carriage return' $'Hello\rWorld'

printf '%s\n' ""
printf '%s\n' "${pass_count} pass, ${fail_count} fail"
[ "${fail_count}" -eq 0 ]
