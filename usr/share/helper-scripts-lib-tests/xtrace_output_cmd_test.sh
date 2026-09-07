#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## xtrace.bsh: output_cmd_set builds the output_cmd ARRAY used as
## "${output_cmd[@]}" "message". Off xtrace it is 'printf %s\n' (prints the
## message verbatim); on xtrace it is 'true' (no-op, so -x traces are not
## doubled by a re-print).
##
## THE BUG the array form fixes: the old string form output_cmd="echo" both
## re-split via '$output_cmd' AND used 'echo', which EATS a leading '-n'/'-e'
## argument and mangles backslashes. So a status line that happens to start
## with '-n' silently vanished. These cases assert the message is printed
## VERBATIM -- which the old 'echo' form cannot do -- and that output_cmd is a
## real array, not a scalar.
##
## Sources the INSTALLED xtrace.bsh by default; HELPER_SCRIPTS_REPO points it at
## a checkout (what the suite runner wires in CI). No root, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v HELPER_SCRIPTS_REPO ] || HELPER_SCRIPTS_REPO=""

if [ -n "${HELPER_SCRIPTS_REPO}" ]; then
   xtrace_bsh="${HELPER_SCRIPTS_REPO}/usr/libexec/helper-scripts/xtrace.bsh"
else
   xtrace_bsh='/usr/libexec/helper-scripts/xtrace.bsh'
fi

if [ ! -r "${xtrace_bsh}" ]; then
   printf '%s\n' "FATAL: xtrace.bsh not readable at '${xtrace_bsh}'" >&2
   printf '%s\n' "set HELPER_SCRIPTS_REPO to a checkout, or install helper-scripts" >&2
   exit 1
fi

# shellcheck disable=SC1090,SC1091
source "${xtrace_bsh}"

if [ ! "$(type -t output_cmd_set)" = 'function' ]; then
   printf '%s\n' "FATAL: sourcing '${xtrace_bsh}' defined no 'output_cmd_set' function" >&2
   exit 1
fi

pass_count=0
fail_count=0
ok() { pass_count=$(( pass_count + 1 )); printf '%s\n' "  ok: $1"; }
notok() { fail_count=$(( fail_count + 1 )); printf '%s\n' "  NOT OK: $1" >&2; }

## Assert that invoking output_cmd (off xtrace) with $2 prints exactly $3.
assert_prints() {
   local desc arg want got
   desc="$1"; arg="$2"; want="$3"
   set +o xtrace
   output_cmd_set
   got="$("${output_cmd[@]}" "${arg}")"
   if [ "${got}" = "${want}" ]; then
      ok "${desc}"
   else
      notok "${desc}: got '${got}', want '${want}'"
   fi
}

## output_cmd must be a real array, not a scalar.
output_cmd_set
output_cmd_decl="$(declare -p output_cmd 2>/dev/null || true)"
if [[ "${output_cmd_decl}" == *"declare -a"* ]]; then
   ok "output_cmd is an array"
else
   notok "output_cmd is not an array: ${output_cmd_decl}"
fi

## Verbatim printing, including the arguments 'echo' would eat or mangle.
assert_prints "prints a plain message verbatim" "INFO: starting build" "INFO: starting build"
assert_prints "prints a leading -n verbatim (echo would eat it)" "-n" "-n"
assert_prints "prints a leading -e verbatim (echo would eat it)" "-e" "-e"
assert_prints "keeps backslashes literal (echo -e would interpret)" 'a\tb' 'a\tb'
assert_prints "keeps a percent literal" "100% done" "100% done"

## On xtrace, output_cmd is a no-op: it must print nothing to stdout.
## 'local -' scopes 'set -o xtrace' to the function so it restores on return;
## stderr (the -x traces) is dropped by the caller. The assertion runs in the
## MAIN shell so its pass/fail counts (a subshell's counter would be lost).
run_output_cmd_under_xtrace() {
   local -
   set -o xtrace
   output_cmd_set
   "${output_cmd[@]}" "$1"
}
xtrace_stdout="$(run_output_cmd_under_xtrace "should not be printed" 2>/dev/null)"
if [ -z "${xtrace_stdout}" ]; then
   ok "no-op under xtrace (no stdout)"
else
   notok "under xtrace expected no stdout, got '${xtrace_stdout}'"
fi

printf '%s\n' ""
printf '%s\n' "${pass_count} passed, ${fail_count} failed"
[ "${fail_count}" -eq 0 ]
