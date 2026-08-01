#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for derivative-maker 'help-steps/dm-build-official-one': the
## '~/.ssh' guard and what is allowed to lift it.
##
## THE BUG IT GUARDS: the guard's own comment documents '--dry-run true' as a
## reason to skip the check, because rsync is mocked under dry-run and ~/.ssh is
## never used. But it tested only $build_dry_run, which 'help-steps/parse-cmd'
## sets -- and parse-cmd runs DOWNSTREAM of this script. So the branch was dead:
## passing the documented option did nothing, and only an exported CI=true got
## past. Every caller driving the real entrypoint through 'help-steps/run-as-user'
## hit it, because run-as-user's 'sudo --preserve-env=PATH' does not carry CI to
## the build user. That is exactly how the CI dry-run lane failed.
##
## Drives the SHIPPED slice, so a regression in the real guard fails here.
##
## Needs no root, no network, no build.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=./help_steps_test_lib.bsh
source "${test_dir}/help_steps_test_lib.bsh"

subject=""
locate_subject() {
   local candidate

   for candidate in "${DM_BUILD_OFFICIAL_ONE:-}" \
      "${DERIVATIVE_MAKER_DIR:-}/help-steps/dm-build-official-one" \
      "${dm_checkout}/help-steps/dm-build-official-one"; do
      case "${candidate}" in
         ''|'/help-steps/dm-build-official-one')
            continue
            ;;
      esac
      if [ -r "${candidate}" ]; then
         subject="${candidate}"
         return 0
      fi
   done
   return 1
}

if ! locate_subject; then
   printf '%s\n' "SKIP: dm-build-official-one not found (set DM_BUILD_OFFICIAL_ONE)." >&2
   exit 77
fi

## From the argv scan down to the 'fi' that closes the guard. Both halves have to
## be in the slice: the fix is that the scan feeds the guard.
guard="$(sed -n '/^forwarded_args=()/,/^fi$/p' -- "${subject}")"
if [ -z "${guard}" ]; then
   printf '%s\n' "FAILED: could not extract the argv scan + ssh guard." >&2
   exit 1
fi
case "${guard}" in
   *'.ssh'*)
      pass "extracted slice contains the ~/.ssh guard"
      ;;
   *)
      fail "extracted slice does not reach the ~/.ssh guard; the slice is wrong, not the code"
      ;;
esac

workdir=""
cleanup() {
   [ -z "${workdir}" ] || safe-rm --recursive --force -- "${workdir}"
}
trap cleanup EXIT
workdir="$(mktemp --directory)"

no_ssh_home="${workdir}/home-without-ssh"
with_ssh_home="${workdir}/home-with-ssh"
mkdir --parents -- "${no_ssh_home}" "${with_ssh_home}/.ssh"

## $CI is passed explicitly so an inherited CI from the surrounding environment
## cannot make every case pass.
run_guard() {
   local home_dir="$1" ci_value="$2"
   shift 2

   env --unset=TESTING_MODE HOME="${home_dir}" CI="${ci_value}" \
      bash -- "${test_dir}/dry_run_ssh_guard_inner.sh" "${guard}" "$@" 2>&1
}

## --- the bug: '--dry-run true', no CI, no ~/.ssh -> must get through --------
rc=0
out="$(run_guard "${no_ssh_home}" "" --dry-run true --flavor kicksecure-cli --target raw)" || rc="$?"
if [ "${rc}" -eq 0 ]; then
   pass "--dry-run true without CI and without ~/.ssh: passes the guard"
else
   fail "--dry-run true without CI and without ~/.ssh: blocked (${rc}) -- the documented skip is still dead -- ${out}"
fi

## --- CI=true keeps working -------------------------------------------------
rc=0
out="$(run_guard "${no_ssh_home}" true --flavor kicksecure-cli --target raw)" || rc="$?"
if [ "${rc}" -eq 0 ]; then
   pass "CI=true without ~/.ssh: passes the guard"
else
   fail "CI=true without ~/.ssh: blocked (${rc}) -- ${out}"
fi

## --- CANARY: the guard must still BITE -------------------------------------
## Without this, the assertions above are satisfied by deleting the check, which
## would let a real upload-bound build start with no ssh credentials and fail at
## the end of an hour instead of the start.
rc=0
out="$(run_guard "${no_ssh_home}" "" --flavor kicksecure-cli --target raw)" || rc="$?"
if [ "${rc}" -ne 0 ]; then
   pass "canary: no dry-run, no CI, no ~/.ssh: still rejected (${rc})"
else
   fail "canary broken: the ~/.ssh guard no longer rejects a real build with no credentials"
fi

## --- CANARY: '--dry-run false' must not be read as a dry run ----------------
## The scan pairs the option with its VALUE; a scan that only looked for the
## '--dry-run' token would wrongly pass here.
rc=0
out="$(run_guard "${no_ssh_home}" "" --dry-run false --flavor kicksecure-cli --target raw)" || rc="$?"
if [ "${rc}" -ne 0 ]; then
   pass "canary: '--dry-run false' is not treated as a dry run"
else
   fail "canary broken: '--dry-run false' lifted the guard; the scan ignores the option's value"
fi

## --- a real build WITH credentials passes ----------------------------------
rc=0
out="$(run_guard "${with_ssh_home}" "" --flavor kicksecure-cli --target raw)" || rc="$?"
if [ "${rc}" -eq 0 ]; then
   pass "real build with ~/.ssh present: passes the guard"
else
   fail "real build with ~/.ssh present: blocked (${rc}) -- ${out}"
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: dry-run ssh guard."
