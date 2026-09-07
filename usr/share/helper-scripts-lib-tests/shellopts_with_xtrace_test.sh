#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## xtrace.bsh shellopts_with_xtrace() returns $SHELLOPTS with 'xtrace' present
## EXACTLY ONCE, for passing to a sudo/flock re-exec. When xtrace is already on,
## SHELLOPTS already lists it, so a naive "${SHELLOPTS}:xtrace" append produced a
## superfluous duplicate. This asserts 'xtrace' appears exactly once in both
## states.
##
## Sources the REAL xtrace.bsh in a child shell. No root, no network.

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

pass_count=0
fail_count=0
ok() { pass_count=$(( pass_count + 1 )); printf '%s\n' "  ok: $1"; }
notok() { fail_count=$(( fail_count + 1 )); printf '%s\n' "  NOT OK: $1" >&2; }

## Count how many ':'-separated fields equal 'xtrace' in shellopts_with_xtrace's
## output, with xtrace $1 (on|off) in the child shell.
probe='source "$0" >/dev/null 2>&1; [ "$1" = on ] && set -o xtrace; out="$(shellopts_with_xtrace)"; set +o xtrace; n=0; IFS=:; for f in ${out}; do [ "$f" = xtrace ] && n=$((n+1)); done; printf %s "$n"'

count_xtrace() {
   /usr/bin/bash -c "${probe}" "${xtrace_bsh}" "$1" 2>/dev/null
}

n_on="$(count_xtrace on)"
if [ "${n_on}" = '1' ]; then
   ok "xtrace on: 'xtrace' present exactly once (no duplicate)"
else
   notok "xtrace on: expected exactly one 'xtrace', got ${n_on}"
fi

n_off="$(count_xtrace off)"
if [ "${n_off}" = '1' ]; then
   ok "xtrace off: 'xtrace' added exactly once"
else
   notok "xtrace off: expected exactly one 'xtrace', got ${n_off}"
fi

printf '%s\n' ""
printf '%s\n' "${pass_count} passed, ${fail_count} failed"
[ "${fail_count}" -eq 0 ]
