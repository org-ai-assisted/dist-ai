#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression: use_leaprun.sh must report privleap usable when the daemon is
## reachable even if its '/proc/<pid>' is invisible. A pidfile + '/proc/<pid>'
## heuristic false-NEGATIVES under 'proc' 'hidepid=2': privleapd runs as root, so
## an unprivileged caller cannot see '/proc/<pid>' and wrongly concludes the
## daemon is down -- although its comm socket connects fine. Only a real connect()
## reaches the right verdict.
##
## Fakes that state inside an unprivileged bwrap mount namespace via the executed
## use_leaprun_probe.bash fixture: a live AF_UNIX listener at the UID-named comm
## socket, but a pid file whose '/proc/<pid>' never exists (pid_max, which no
## process can own) -- the deterministic stand-in for a hidepid-hidden daemon pid.
## The old heuristic reads 'no'; the connect-probe code must read 'yes'. No root,
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
   env LEAPRUN_FAKE_HIDEPID=1 USE_LEAPRUN_SH="${use_leaprun_sh}" \
   /usr/bin/bash "${probe}" 2>/dev/null)" || probe_stdout='bwrap-run-failed'

## Exact 'use_leaprun=' line, not a substring.
verdict="$(printf '%s\n' "${probe_stdout}" | sed -n 's/^use_leaprun=//p')"
if [ "${verdict}" = 'yes' ]; then
   ok "use_leaprun='yes' when reachable but '/proc/<pid>' is hidden (connect, not proc)"
else
   notok "expected use_leaprun=yes (reachable, proc hidden); got verdict='${verdict}' from '${probe_stdout}' -- relying on '/proc/<pid>' instead of a real connect?"
fi

printf '%s\n' ""
printf '%s\n' "${pass_count} passed, ${fail_count} failed"
[ "${fail_count}" -eq 0 ]
