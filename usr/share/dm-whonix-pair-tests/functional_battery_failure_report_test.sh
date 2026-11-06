#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## #4: main_functional must REPORT which release check failed (number + reason) and exit
## FAIL_RC, not abort with a bare errexit rc=1. Canary: the pre-fix bare battery call aborts
## rc=1 with no reason line.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

here="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
## DM_WHONIX_PAIR_BIN overrides the subject (the canary points it at a pre-fix export).
tool="${DM_WHONIX_PAIR_BIN:-${here}/../../bin/dm-whonix-pair}"
[ -x "${tool}" ] || { printf '%s\n' "FATAL: dm-whonix-pair not found at ${tool}" >&2; exit 1; }

work="$(mktemp --directory)"
# shellcheck disable=SC2317  ## runs via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${work}"; }
trap cleanup EXIT

# shellcheck source=../../bin/dm-whonix-pair
source "${tool}"

## Shadow the VM-driving prefix/suffix of main_functional so only the battery-call handling
## is exercised; make the battery record a failed check and return 1.
# shellcheck disable=SC2317
on_exit() { :; }
# shellcheck disable=SC2317
boot_gateway_functional() { :; }
# shellcheck disable=SC2317
boot_workstation_user() { :; }
# shellcheck disable=SC2317
ws_func_tor_gate() { :; }
# shellcheck disable=SC2317
wait_ready() { :; }
# shellcheck disable=SC2317
open_terminal() { :; }
# shellcheck disable=SC2317
run_release_check_battery() {
   RELEASE_CHECK_FAILED_NUM=8
   RELEASE_CHECK_FAILED_REASON='systemcheck'
   return 1
}

pass=0
fail=0
assert() { local label="$1"; shift; if "$@"; then pass=$(( pass + 1 )); printf '%s\n' "PASS: ${label}"; else fail=$(( fail + 1 )); printf '%s\n' "FAIL: ${label}"; fi; }

err="${work}/err"
rc=0
( main_functional ) >/dev/null 2>"${err}" || rc=$?
assert "failed battery exits FAIL_RC(5)" test "${rc}" -eq 5
assert "failure names the check number + reason" grep --quiet --fixed-strings 'release check 8 (systemcheck) FAILED' "${err}"

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
[ "${fail}" -eq 0 ] || exit 1
