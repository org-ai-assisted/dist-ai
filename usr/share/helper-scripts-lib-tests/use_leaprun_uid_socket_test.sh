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
## /run/privleapd with a live pid + a UID-named comm socket + a stub leaprun, all
## set up by the executed use_leaprun_probe.bash fixture) and asserts
## use_leaprun='yes'. On the old (username) code the socket path does not match
## and it reads 'no'. No root, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

## style-ok: no-has -- probing bwrap; sourcing has.bsh into a lib test is overkill

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

if ! command -v bwrap >/dev/null 2>&1; then
   printf '%s\n' "bwrap not available; cannot fake /run/privleapd; skipping." >&2
   exit 77  ## style-ok: allow-skip: needs unprivileged bwrap to fake the /run/privleapd namespace
fi

pass_count=0
fail_count=0
ok() { pass_count=$(( pass_count + 1 )); printf '%s\n' "  ok: $1"; }
notok() { fail_count=$(( fail_count + 1 )); printf '%s\n' "  NOT OK: $1" >&2; }

probe_stdout="$(bwrap --bind / / --dev /dev --proc /proc --tmpfs /run/privleapd \
   env LEAPRUN_FAKE_USABLE=1 USE_LEAPRUN_SH="${use_leaprun_sh}" \
   /usr/bin/bash "${probe}" 2>/dev/null)" || probe_stdout='bwrap-run-failed'

if [[ "${probe_stdout}" == *'use_leaprun=yes'* ]]; then
   ok "use_leaprun='yes' when the UID-named comm socket exists (looked up by UID)"
else
   notok "expected use_leaprun=yes (UID socket present); got '${probe_stdout}' -- looked up by name, not UID?"
fi

printf '%s\n' ""
printf '%s\n' "${pass_count} passed, ${fail_count} failed"
[ "${fail_count}" -eq 0 ]
