#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## use_leaprun.sh must look up the per-user comm socket by UID, matching how
## privleapd names it: /run/privleapd/comm/<uid> (privleap leaprun.py builds
## comm_dir/str(user_uid)). A regression used `id --name --user` (the username),
## so the socket was never found and use_leaprun was wrongly set to 'no' even
## when privleap was fully usable -- the always-reproducible "Cannot use privleap".
##
## Fakes a USABLE privleap inside an unprivileged bwrap mount namespace (tmpfs
## /run/privleapd with a live AF_UNIX listener at the UID-named comm socket plus
## a stub leaprun, all set up by the executed use_leaprun_probe.bash fixture) and
## asserts use_leaprun='yes'. use_leaprun.sh's real connect() only reaches the
## listener if it resolves the socket by UID; on the old (username) code the path
## does not match, the connect fails, and it reads 'no'. No root, no network.

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
   env LEAPRUN_FAKE_USABLE=1 USE_LEAPRUN_SH="${use_leaprun_sh}" \
   /usr/bin/bash "${probe}" 2>/dev/null)" || probe_stdout='bwrap-run-failed'

## Exact 'use_leaprun=' line, not a substring (a substring false-passes on
## 'yesplease' and can be steered by warning text that echoes the value).
verdict="$(printf '%s\n' "${probe_stdout}" | sed -n 's/^use_leaprun=//p')"
if [ "${verdict}" = 'yes' ]; then
   ok "use_leaprun='yes' when the UID-named comm socket exists (looked up by UID)"
else
   notok "expected use_leaprun=yes (UID socket present); got verdict='${verdict}' from '${probe_stdout}' -- looked up by name, not UID?"
fi

printf '%s\n' ""
printf '%s\n' "${pass_count} passed, ${fail_count} failed"
[ "${fail_count}" -eq 0 ]
