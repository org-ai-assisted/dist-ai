#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## check 3 (upgrade-nonroot) over CLI guestcontrol must survive a VBoxService restart: the apt
## upgrade can pull a newer virtualbox-guest-additions-iso whose reinstall RESTARTS VBoxService,
## severing the guestcontrol session running the command (VERR_TIMEOUT). So the CLI executor runs
## check 3 DETACHED (setsid) and polls its rc over fresh sessions. Canary: the pre-fix executor ran
## check 3 synchronously over one session (no setsid), so the restart killed it -> false FAIL.
## Drives the REAL ws_func_cli_exec (define-only source); gc_run is stubbed to record the launch.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

here="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
tool="${DM_WHONIX_PAIR_BIN:-${here}/../../bin/dm-whonix-pair}"
[ -x "${tool}" ] || { printf '%s\n' "FATAL: dm-whonix-pair not found at ${tool}" >&2; exit 1; }

# shellcheck source=../../bin/dm-whonix-pair
source "${tool}"

pass=0
fail=0
## negation helper: succeeds only when the pattern is ABSENT from the file (a bare
## `grep --invert-match` would pass whenever ANY line lacks it, not what we want).
absent() { ! grep --quiet --fixed-strings -- "$1" "$2"; }

assert() {
   local label="$1"
   shift
   if "$@"; then
      pass=$(( pass + 1 ))
      printf '%s\n' "PASS: ${label}"
   else
      fail=$(( fail + 1 ))
      printf '%s\n' "FAIL: ${label}"
   fi
}

work="$(mktemp --directory --tmpdir dm-whonix-pair-cli-upgrade.XXXXXX)"
# shellcheck disable=SC2317  ## invoked via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${work}"; }
trap cleanup EXIT

## Stub gc_run: resolve the guest HOME, record the detached launch, answer the rc poll + tail.
launch_seen=''
staged_rc='0'
# shellcheck disable=SC2317  ## called indirectly by ws_func_cli_exec
gc_run() {
   case "$2" in
      *HOME*)
         printf '%s' '/home/user'
         ;;
      *setsid*)
         launch_seen="$2"
         ;;
      *.dm-cli-upgrade-*.rc*)
         printf '%s' "${staged_rc}"
         ;;
      *.dm-cli-upgrade-*.out*)
         printf '%s' 'upgrade output tail here'
         ;;
   esac
   return 0
}
me='cli-upgrade-test'
ws='Whonix-Workstation-CLI'
vm="${ws}"
check_log=''

## --- PASS path: the detached upgrade reports rc 0 ---
launch_seen=''
staged_rc='0'
rc=0
ws_func_cli_exec 3 user 'upgrade-nonroot --yes' 1800 > "${work}/pass.out" 2>&1 || rc=$?
assert "check 3 runs DETACHED (launch snippet uses setsid)" \
   grep --quiet --fixed-strings 'setsid' <<< "${launch_seen}"
assert "the detached launch carries the real upgrade command" \
   grep --quiet --fixed-strings 'upgrade-nonroot --yes' <<< "${launch_seen}"
assert "the launch writes the rc to the polled guest-home file" \
   grep --quiet --fixed-strings '.dm-cli-upgrade-' <<< "${launch_seen}"
assert "check 3 PASS when the detached upgrade rc is 0" test "${rc}" -eq 0
assert "the PASS line is printed (executor contract)" \
   grep --quiet --fixed-strings 'check 3 PASS' "${work}/pass.out"

## --- FAIL path: the detached upgrade reports a nonzero rc ---
launch_seen=''
staged_rc='100'
check_log="${work}/check.log"
rc=0
ws_func_cli_exec 3 user 'upgrade-nonroot --yes' 1800 > /dev/null 2>&1 || rc=$?
assert "check 3 returns the detached upgrade's nonzero rc" test "${rc}" -eq 100
assert "the failed upgrade tail is recorded to check_log" \
   grep --quiet --fixed-strings 'FAILED rc=100' "${check_log}"

## --- --local-repo path: check 3 must run apt-get DIRECTLY, not upgrade-nonroot. CANARY for the
## critical fix -- upgrade-nonroot is a user usability wrapper that deliberately does NOT forward
## apt options, so the offline upgrade must bypass it and pass -o to apt-get itself.
launch_seen=''
staged_rc='0'
check_log=''
local_repo='whonix'
rc=0
ws_func_cli_exec 3 user 'upgrade-nonroot --yes' 1800 > "${work}/local.out" 2>&1 || rc=$?
local_repo=''
assert "check 3 --local-repo launches apt-get full-upgrade DIRECTLY (not upgrade-nonroot)" \
   grep --quiet --fixed-strings 'apt-get' <<< "${launch_seen}"
assert "check 3 --local-repo passes the offline local-sources options to apt-get" \
   grep --quiet --fixed-strings 'Dir::Etc::sourceparts' <<< "${launch_seen}"
## Honest PASS label: the local-repo path must NOT claim upgrade-nonroot (it runs apt-get direct).
assert "check 3 --local-repo PASS line names apt-get full-upgrade from local repo" \
   grep --quiet --fixed-strings 'check 3 PASS (apt-get full-upgrade from local repo' "${work}/local.out"
assert "check 3 --local-repo PASS line does NOT claim upgrade-nonroot" \
   absent 'upgrade-nonroot' "${work}/local.out"

printf '%s\n' "cli_upgrade_detached_test: ${pass} pass, ${fail} fail, 0 skip"
[ "${fail}" -eq 0 ]
