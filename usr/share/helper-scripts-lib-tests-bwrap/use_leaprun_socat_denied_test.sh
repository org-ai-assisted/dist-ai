#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression: when the socat connect probe itself cannot run (such as an
## AppArmor exec denial under a confined caller like systemcheck: exit code 126,
## 'Permission denied'), use_leaprun.sh must say so in its warning. A bare
## "privleapd is not reachable" hides the cause and reads like a dead daemon.
##
## Fakes a live privleapd listener plus a stub socat that fails like an exec
## denial, inside an unprivileged bwrap mount namespace via the executed
## use_leaprun_probe.bash fixture. Asserts use_leaprun='no' and that the warning
## carries socat's exit code and stderr. No root, no network.

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

stderr_file="$(mktemp)"
# shellcheck disable=SC2317  # reached via the EXIT trap
cleanup() { safe-rm --force -- "${stderr_file}"; }
trap cleanup EXIT

## Clear the other fake-mode toggles: the fixture checks them first, so an
## inherited one would skip the socat stub.
probe_stdout="$(bwrap --bind / / --dev /dev --proc /proc --tmpfs /run/privleapd \
   env --unset=LEAPRUN_FAKE_USABLE --unset=LEAPRUN_FAKE_STALE --unset=LEAPRUN_FAKE_HIDEPID \
   LEAPRUN_FAKE_SOCAT_DENIED=1 USE_LEAPRUN_SH="${use_leaprun_sh}" \
   /usr/bin/bash "${probe}" 2>"${stderr_file}")" || probe_stdout='bwrap-run-failed'
probe_stderr="$(cat -- "${stderr_file}")"

## Exact 'use_leaprun=' line, not a substring.
verdict="$(printf '%s\n' "${probe_stdout}" | sed -n 's/^use_leaprun=//p')"
if [ "${verdict}" = 'no' ]; then
   ok "use_leaprun='no' when the socat probe cannot run"
else
   notok "expected use_leaprun=no; got verdict='${verdict}' from '${probe_stdout}'"
fi

if [[ "${probe_stderr}" == *"socat exit code: '126'"* ]]; then
   ok "warning carries socat's exit code"
else
   notok "warning lacks socat's exit code 126: '${probe_stderr}'"
fi

## Match the warning's own quoted field, not a bare substring: a socat whose
## stderr leaks straight through would otherwise pass.
if [[ "${probe_stderr}" == *"socat output: 'socat: Permission denied'"* ]]; then
   ok "warning carries socat's stderr"
else
   notok "warning lacks socat's stderr 'Permission denied': '${probe_stderr}'"
fi

printf '%s\n' ""
printf '%s\n' "${pass_count} passed, ${fail_count} failed"
[ "${fail_count}" -eq 0 ]
