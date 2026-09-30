#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## use_leaprun.sh sets use_leaprun=yes/no and, when privleap is not usable, stores
## the reason in ${leaprun_useable_result} and emits it via leaprun_useable_output.
## That diagnostic is a WARNING and must go to STDERR, never STDOUT: consumers
## (systemcheck sourcing chain, updatecheck, onion-time-pre-script) source this at
## load time, so a warning on stdout becomes the first line of their output.
##
## Sources the REAL use_leaprun.sh in a child bash with leaprun forced off PATH
## (deterministic "Cannot use privleap" branch, regardless of privleapd state) and
## asserts: stdout is EMPTY, the warning is on stderr, use_leaprun=no, and
## leaprun_useable_result is populated. No root, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v HELPER_SCRIPTS_REPO ] || HELPER_SCRIPTS_REPO=""

if [ -n "${HELPER_SCRIPTS_REPO}" ]; then
   repo="${HELPER_SCRIPTS_REPO}"
else
   repo=""
fi

use_leaprun_sh="${repo:-}/usr/libexec/helper-scripts/use_leaprun.sh"
[ -r "${use_leaprun_sh}" ] || use_leaprun_sh='/usr/libexec/helper-scripts/use_leaprun.sh'

if [ ! -r "${use_leaprun_sh}" ]; then
   printf '%s\n' "FATAL: use_leaprun.sh not readable at '${use_leaprun_sh}'" >&2
   printf '%s\n' "set HELPER_SCRIPTS_REPO to a checkout, or install helper-scripts" >&2
   exit 1
fi

pass_count=0
fail_count=0
ok() { pass_count=$(( pass_count + 1 )); printf '%s\n' "  ok: $1"; }
notok() { fail_count=$(( fail_count + 1 )); printf '%s\n' "  NOT OK: $1" >&2; }

## Source the REAL use_leaprun.sh in a child bash with leaprun unresolvable (PATH
## without it), so the source-time leaprun_useable_test deterministically hits its
## first "Cannot use privleap" branch. $1 is extra bash appended after the source.
child_probe() {
   local extra="$1"
   # shellcheck disable=SC2016  # ${...} expands in the inner bash -c, not here
   local payload='source "${USE_LEAPRUN_SH}"'
   [ -z "${extra}" ] || payload="${payload}"$'\n'"${extra}"
   env PATH='/nonexistent' USE_LEAPRUN_SH="${use_leaprun_sh}" \
      /usr/bin/bash -c "${payload}"
}

## 1. The warning must NOT reach stdout (the reported bug: it did, as the first line).
stdout_capture="$(child_probe '' 2>/dev/null)"
if [ -z "${stdout_capture}" ]; then
   ok "privleap-unusable warning does not go to stdout"
else
   notok "warning leaked to stdout: '${stdout_capture}'"
fi

## 2. The warning must reach stderr.
stderr_capture="$( { child_probe '' >/dev/null; } 2>&1 )"
if [[ "${stderr_capture}" == *'Cannot use privleap'* ]]; then
   ok "privleap-unusable warning goes to stderr"
else
   notok "warning not found on stderr: '${stderr_capture}'"
fi

## 3. use_leaprun=no is still set (behaviour consumers rely on).
# shellcheck disable=SC2016  # ${use_leaprun} expands in the inner bash -c
use_leaprun_value="$(child_probe 'printf "%s" "${use_leaprun}"' 2>/dev/null)"
if [ "${use_leaprun_value}" = 'no' ]; then
   ok "use_leaprun set to 'no' when privleap unusable"
else
   notok "expected use_leaprun=no, got '${use_leaprun_value}'"
fi

## 4. leaprun_useable_result still holds the reason (updatecheck reads this variable).
# shellcheck disable=SC2016  # ${leaprun_useable_result} expands in the inner bash -c
result_len="$(child_probe 'printf "%s" "${#leaprun_useable_result}"' 2>/dev/null)"
if [ -n "${result_len}" ] && [ "${result_len}" != '0' ]; then
   ok "leaprun_useable_result is populated (length ${result_len})"
else
   notok "leaprun_useable_result empty; consumers lose the reason"
fi

printf '%s\n' ""
printf '%s\n' "${pass_count} passed, ${fail_count} failed"
[ "${fail_count}" -eq 0 ]
