#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## use_leaprun.sh, when privleap is not usable, stores the reason in
## ${leaprun_useable_result} and emits it via leaprun_useable_output. That
## diagnostic is a WARNING and must go to STDERR, never STDOUT: consumers
## (systemcheck's load-time source, updatecheck, onion-time-pre-script) source
## this file, so a warning on stdout becomes the first line of their output.
##
## Runs the REAL use_leaprun.sh (via the executed use_leaprun_probe.bash fixture)
## with leaprun forced off PATH -- the deterministic "Cannot use privleap" branch,
## independent of privleapd state -- and asserts the warning is on stderr, not
## stdout, while use_leaprun=no and leaprun_useable_result is populated. No root,
## no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"
probe="${script_dir}/use_leaprun_probe.bash"

[ -v HELPER_SCRIPTS_REPO ] || HELPER_SCRIPTS_REPO=""
repo="${HELPER_SCRIPTS_REPO:-}"
use_leaprun_sh="${repo:-}/usr/libexec/helper-scripts/use_leaprun.sh"
[ -r "${use_leaprun_sh}" ] || use_leaprun_sh='/usr/libexec/helper-scripts/use_leaprun.sh'

if [ ! -r "${use_leaprun_sh}" ]; then
   printf '%s\n' "FATAL: use_leaprun.sh not readable at '${use_leaprun_sh}'" >&2
   printf '%s\n' "set HELPER_SCRIPTS_REPO to a checkout, or install helper-scripts" >&2
   exit 1
fi
[ -r "${probe}" ] || { printf '%s\n' "FATAL: probe fixture missing: ${probe}" >&2; exit 1; }

pass_count=0
fail_count=0
ok() { pass_count=$(( pass_count + 1 )); printf '%s\n' "  ok: $1"; }
notok() { fail_count=$(( fail_count + 1 )); printf '%s\n' "  NOT OK: $1" >&2; }

## Value of the probe's own 'use_leaprun=' line (exact line, not a substring --
## a substring match false-passes on 'notreally' and can be steered by warning text).
verdict_of() { printf '%s\n' "$1" | sed -n 's/^use_leaprun=//p'; }
result_len_of() { printf '%s\n' "$1" | sed -n 's/^result_len=//p'; }

## Run the probe with leaprun unresolvable (PATH without it) so use_leaprun.sh
## hits its first "Cannot use privleap" branch. Clear the fake-mode toggles so an
## inherited one cannot divert the probe. Capture the two streams apart.
probe_stdout="$(env --unset=LEAPRUN_FAKE_USABLE --unset=LEAPRUN_FAKE_EMPTY_PID \
   PATH='/nonexistent' USE_LEAPRUN_SH="${use_leaprun_sh}" /usr/bin/bash "${probe}" 2>/dev/null)"
probe_stderr="$( { env --unset=LEAPRUN_FAKE_USABLE --unset=LEAPRUN_FAKE_EMPTY_PID \
   PATH='/nonexistent' USE_LEAPRUN_SH="${use_leaprun_sh}" /usr/bin/bash "${probe}" >/dev/null; } 2>&1 )"

## stdout must carry ONLY the probe's own two lines -- no warning of any kind.
stdout_lines="$(printf '%s\n' "${probe_stdout}" | wc -l)"
if [ "${stdout_lines}" = '2' ] && [[ "${probe_stdout}" != *'Cannot use privleap'* ]]; then
   ok "no warning on stdout (only the probe's own 2 lines)"
else
   notok "unexpected stdout (${stdout_lines} line(s)): '${probe_stdout}'"
fi

if [[ "${probe_stderr}" == *'Cannot use privleap'* ]]; then
   ok "privleap-unusable warning goes to stderr"
else
   notok "warning not found on stderr: '${probe_stderr}'"
fi

if [ "$(verdict_of "${probe_stdout}")" = 'no' ]; then
   ok "use_leaprun set to 'no' when privleap unusable"
else
   notok "expected use_leaprun=no, got '$(verdict_of "${probe_stdout}")'"
fi

result_len="$(result_len_of "${probe_stdout}")"
if [ -n "${result_len}" ] && [ "${result_len}" != '0' ]; then
   ok "leaprun_useable_result is populated (length ${result_len})"
else
   notok "leaprun_useable_result empty; consumers lose the reason"
fi

printf '%s\n' ""
printf '%s\n' "${pass_count} passed, ${fail_count} failed"
[ "${fail_count}" -eq 0 ]
