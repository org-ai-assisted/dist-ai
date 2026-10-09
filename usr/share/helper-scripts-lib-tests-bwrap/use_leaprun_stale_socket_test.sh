#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression: use_leaprun.sh must NOT report privleap usable on a STALE socket.
## A pidfile + '/proc/<pid>' heuristic false-POSITIVES when privleapd has crashed
## but its pid got reused (so '/proc/<pid>' exists) and its comm socket inode
## lingers (so '[ -e socket ]' passes) -- yet no connection is possible. Only a
## real connect() catches this.
##
## Fakes exactly that state inside an unprivileged bwrap mount namespace via the
## executed use_leaprun_probe.bash fixture: a live pid (so the old '/proc/<pid>'
## check passes) plus a dead socket inode (bound then closed, nothing listening).
## The old heuristic reads 'yes'; the connect-probe code must read 'no'. No root,
## no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"
## The probe fixture is shared with the unsandboxed use_leaprun_test.sh.
probe="${script_dir}/../helper-scripts-lib-tests/use_leaprun_probe.bash"
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

bwrap_require

pass_count=0
fail_count=0
ok() { pass_count=$(( pass_count + 1 )); printf '%s\n' "  ok: $1"; }
notok() { fail_count=$(( fail_count + 1 )); printf '%s\n' "  NOT OK: $1" >&2; }

probe_stdout="$(bwrap --bind / / --dev /dev --proc /proc --tmpfs /run/privleapd \
   env LEAPRUN_FAKE_STALE=1 USE_LEAPRUN_SH="${use_leaprun_sh}" \
   /usr/bin/bash "${probe}" 2>/dev/null)" || probe_stdout='bwrap-run-failed'

## Exact 'use_leaprun=' line, not a substring.
verdict="$(printf '%s\n' "${probe_stdout}" | sed -n 's/^use_leaprun=//p')"
if [ "${verdict}" = 'no' ]; then
   ok "use_leaprun='no' on a stale socket (connect refused, not just '[ -e socket ]')"
else
   notok "expected use_leaprun=no (stale socket); got verdict='${verdict}' from '${probe_stdout}' -- socket existence trusted without a real connect?"
fi

printf '%s\n' ""
printf '%s\n' "${pass_count} passed, ${fail_count} failed"
[ "${fail_count}" -eq 0 ]
