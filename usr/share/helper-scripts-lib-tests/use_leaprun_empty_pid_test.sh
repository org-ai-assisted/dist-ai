#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## use_leaprun.sh reads the privleapd pid from /run/privleapd/pid and then checks
## /proc/<pid>. An EMPTY pid file makes that check '[ -d /proc/ ]', which is always
## true -- so a not-running privleapd would wrongly read as usable. The probe must
## reject an empty (or non-numeric) pid and report use_leaprun='no'.
##
## Fakes /run/privleapd with an EMPTY pid file (but a valid UID comm socket and a
## stub leaprun, so ONLY the pid guard can make the difference) under an
## unprivileged bwrap, via the executed use_leaprun_probe.bash fixture. No root,
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
# shellcheck source=./bwrap_capability.bash
source "${script_dir}/bwrap_capability.bash"

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

if ! bwrap_can_sandbox; then
   printf '%s\n' "unprivileged bwrap sandbox unavailable; cannot fake /run/privleapd; skipping." >&2
   exit 77  ## style-ok: allow-skip: unprivileged bwrap sandbox unavailable here
fi

pass_count=0
fail_count=0
ok() { pass_count=$(( pass_count + 1 )); printf '%s\n' "  ok: $1"; }
notok() { fail_count=$(( fail_count + 1 )); printf '%s\n' "  NOT OK: $1" >&2; }

probe_stdout="$(bwrap --bind / / --dev /dev --proc /proc --tmpfs /run/privleapd \
   env LEAPRUN_FAKE_EMPTY_PID=1 USE_LEAPRUN_SH="${use_leaprun_sh}" \
   /usr/bin/bash "${probe}" 2>/dev/null)" || probe_stdout='bwrap-run-failed'

## Exact 'use_leaprun=' line, not a substring.
verdict="$(printf '%s\n' "${probe_stdout}" | sed -n 's/^use_leaprun=//p')"
if [ "${verdict}" = 'no' ]; then
   ok "use_leaprun='no' when the pid file is empty (not treated as /proc/ = running)"
else
   notok "expected use_leaprun=no (empty pid); got verdict='${verdict}' from '${probe_stdout}' -- empty pid read as running?"
fi

printf '%s\n' ""
printf '%s\n' "${pass_count} passed, ${fail_count} failed"
[ "${fail_count}" -eq 0 ]
