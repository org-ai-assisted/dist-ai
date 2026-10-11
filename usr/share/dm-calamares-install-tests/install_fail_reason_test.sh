#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression for dm-calamares-install's on_exit failure-reason capture.
##
## THE BUG IT GUARDS: a failure BEFORE the check battery (install / boot / Calamares-launch --
## e.g. "guestcontrol never came up" under Secure Boot) left only a bare "FAILED (rc=N)" in the
## published check-log, so the results page showed an opaque rc with no cause. on_exit now leads
## the check-log fallback with the REAL die() reason (stashed in die_reason by die). CANARY: the
## pre-fix on_exit wrote the generic note WITHOUT the reason, failing the first assertion.
##
## Drives the REAL on_exit (sourced define-only). vm_started=false isolates the check-log
## composition (skips all VBox/guestcontrol teardown); empty shot/shot_dir take the
## no-screenshot branch; HOME has no stuck.png. No VM, no root, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

subject=""
for candidate in "${DM_CALAMARES_INSTALL:-}" \
   "${test_dir}/../../bin/dm-calamares-install" \
   "/usr/bin/dm-calamares-install"; do
   [ -n "${candidate}" ] || continue
   if [ -x "${candidate}" ]; then
      subject="$(readlink --canonicalize -- "${candidate}")"
      break
   fi
done
if [ -z "${subject}" ]; then
   printf '%s\n' "FATAL: dm-calamares-install not found (set DM_CALAMARES_INSTALL)." >&2
   exit 1
fi

work="$(mktemp --directory)"
# shellcheck disable=SC2317  ## runs via the EXIT trap
cleanup() {
   safe-rm --recursive --force -- "${work}"
}
trap cleanup EXIT

# shellcheck disable=SC1090
source "${subject}"

## Globals on_exit reads. vm_started=false skips the VBox/guestcontrol teardown + launch-log
## fetch; empty shot/shot_dir take the no-screenshot branch; HOME has no me-stuck.png.
# shellcheck disable=SC2034
HOME="${work}"
check_log="${work}/checklog"
# shellcheck disable=SC2034
shot=""
# shellcheck disable=SC2034
shot_dir=""
# shellcheck disable=SC2034
vm_started="false"
# shellcheck disable=SC2034
keep_failed="false"

pass=0
fail=0
check() {
   if [ "$2" -eq 0 ]; then pass=$(( pass + 1 )); printf '%s\n' "PASS: $1"; else fail=$(( fail + 1 )); printf '%s\n' "FAIL: $1"; fi
}
has() { case "$2" in *"$1"*) return 0 ;; *) return 1 ;; esac }

## Run on_exit with a non-zero status and a die() reason set, exactly as a pre-check die() leaves
## the process. The `|| on_exit` form invokes on_exit with $?=5 (the failed left command's status)
## without toggling errexit; on_exit then exits 5, captured below.
run_on_exit() {
   true > "${check_log}"
   rc=0
   ( bash -c 'exit 5' || on_exit ) >/dev/null 2>&1 || rc=$?
}

## --- a pre-check die() reason reaches the published check-log ------------------------------
die_reason="guestcontrol (VBoxService) never came up in the live session"
run_on_exit
got=0; [ "${rc}" -eq 5 ] || got=1
check "on_exit preserves the exit status" "${got}"
got=0; has 'guestcontrol (VBoxService) never came up in the live session' "$(cat -- "${check_log}")" || got=1
check "the real die() reason is written to the check log" "${got}"
got=0; has 'FAILED (rc=5)' "$(cat -- "${check_log}")" || got=1
check "the rc is still recorded alongside the reason" "${got}"

## --- no die() reason (e.g. an errexit abort) -> clean generic note, no dangling separator ----
# shellcheck disable=SC2034  ## read by the sourced on_exit in the run_on_exit subshell
die_reason=""
run_on_exit
got=0; has 'FAILED (rc=5).' "$(cat -- "${check_log}")" || got=1
check "a reasonless failure still writes a clean generic note" "${got}"
got=0; if has 'FAILED (rc=5):' "$(cat -- "${check_log}")"; then got=1; fi
check "no dangling ': ' separator when there is no reason" "${got}"

printf '%s\n' "" "$(basename -- "$0"): ${pass} pass, ${fail} fail"
[ "${fail}" -eq 0 ] || exit 1
exit 0
