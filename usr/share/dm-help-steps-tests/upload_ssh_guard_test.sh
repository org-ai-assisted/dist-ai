#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for derivative-maker 'help-steps/dm-build-official-one': the
## '~/.ssh' guard is keyed on a single positive opt-in, '--upload true'.
##
## Upload is SIMULATED by default (rsync mocked in 'variables.d/35_rsync.bsh'), so
## '~/.ssh' is NOT needed for any build unless the operator explicitly opts into a
## real upload with '--upload true'. The guard must therefore:
##   - let every non-upload build through with no '~/.ssh' (default, '--upload
##     false', '--dry-run', CI -- all simulate the upload);
##   - still BITE for '--upload true' with no '~/.ssh', so a real-upload build
##     fails fast at the start instead of at the end of an hour-long build.
##
## '$dist_build_upload' is parsed by this script's OWN argv loop (parse-cmd runs
## DOWNSTREAM), so the guard sees the opt-in; this test drives the shipped slice.
## Needs no root, no network, no build.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

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
   printf '%s\n' "FATAL: dm-build-official-one not found (set DM_BUILD_OFFICIAL_ONE)." >&2
   exit 1
fi

## From the argv scan down to the 'fi' that closes the guard. Both halves have to
## be in the slice: the argv scan parses '--upload' locally so the guard sees it.
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
case "${guard}" in
   *'dist_build_upload'*)
      pass "guard keys off \$dist_build_upload (the --upload opt-in)"
      ;;
   *)
      fail "guard does not reference \$dist_build_upload; it is not the upload-opt-in guard"
      ;;
esac
## The remote axis MUST use the canonical 'build_remote_derivative_pkgs' -- the
## same name 'variables.d/35_rsync.bsh' reads -- or the gate and the real-upload
## decision can disagree (gate says "simulated", rsync uploads for real).
case "${guard}" in
   *'build_remote_derivative_pkgs'*)
      pass "guard keys the remote axis off the canonical \$build_remote_derivative_pkgs"
      ;;
   *)
      fail "guard does not reference \$build_remote_derivative_pkgs; it may disagree with 35_rsync.bsh"
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
## cannot skew a case. The guard no longer special-cases CI, but passing it proves
## CI is irrelevant to the opt-in.
run_guard() {
   local home_dir="$1" ci_value="$2"
   shift 2

   env --unset=TESTING_MODE HOME="${home_dir}" CI="${ci_value}" \
      bash -- "${test_dir}/upload_ssh_guard_inner.sh" "${guard}" "$@" 2>&1
}

## --- default (no --upload): upload simulated, no ~/.ssh needed --------------
rc=0
out="$(run_guard "${no_ssh_home}" "" --flavor kicksecure-cli --target raw)" || rc="$?"
if [ "${rc}" -eq 0 ]; then
   pass "default (no --upload) without ~/.ssh: passes the guard (upload simulated)"
else
   fail "default without ~/.ssh: blocked (${rc}) -- upload is simulated by default -- ${out}"
fi

## --- '--upload false': explicit simulate, no ~/.ssh needed ------------------
rc=0
out="$(run_guard "${no_ssh_home}" "" --upload false --flavor kicksecure-cli --target raw)" || rc="$?"
if [ "${rc}" -eq 0 ]; then
   pass "--upload false without ~/.ssh: passes the guard"
else
   fail "--upload false without ~/.ssh: blocked (${rc}) -- ${out}"
fi

## --- '--dry-run true' and CI are not special; still pass with no ~/.ssh -----
rc=0
out="$(run_guard "${no_ssh_home}" "" --dry-run true --flavor kicksecure-cli --target raw)" || rc="$?"
if [ "${rc}" -eq 0 ]; then
   pass "--dry-run true without ~/.ssh: passes the guard (no --upload)"
else
   fail "--dry-run true without ~/.ssh: blocked (${rc}) -- ${out}"
fi
rc=0
out="$(run_guard "${no_ssh_home}" true --flavor kicksecure-cli --target raw)" || rc="$?"
if [ "${rc}" -eq 0 ]; then
   pass "CI=true without ~/.ssh: passes the guard (no --upload)"
else
   fail "CI=true without ~/.ssh: blocked (${rc}) -- ${out}"
fi

## --- CANARY: '--upload true' with no ~/.ssh must BITE -----------------------
## Without this, the pass-cases above are satisfied by deleting the check, which
## would let a real upload-bound build start with no ssh credentials and fail at
## the end of an hour instead of the start.
rc=0
out="$(run_guard "${no_ssh_home}" "" --upload true --flavor kicksecure-cli --target raw)" || rc="$?"
if [ "${rc}" -ne 0 ]; then
   pass "canary: --upload true with no ~/.ssh: still rejected (${rc})"
else
   fail "canary broken: --upload true no longer requires ~/.ssh (a real upload would start without credentials)"
fi

## --- --upload true but a fail-closed mode applies: NOT a real upload, so the ---
## --- guard must NOT require ~/.ssh (matches variables.d/35_rsync.bsh). --------
rc=0
out="$(run_guard "${no_ssh_home}" true --upload true --flavor kicksecure-cli --target raw)" || rc="$?"
if [ "${rc}" -eq 0 ]; then
   pass "--upload true + CI=true, no ~/.ssh: passes (CI simulates the upload)"
else
   fail "--upload true + CI=true wrongly required ~/.ssh (${rc}) -- ${out}"
fi
rc=0
out="$(run_guard "${no_ssh_home}" "" --upload true --dry-run true --flavor kicksecure-cli --target raw)" || rc="$?"
if [ "${rc}" -eq 0 ]; then
   pass "--upload true + --dry-run true, no ~/.ssh: passes (dry-run simulates the upload)"
else
   fail "--upload true + --dry-run true wrongly required ~/.ssh (${rc}) -- ${out}"
fi
rc=0
out="$(run_guard "${no_ssh_home}" "" --upload true --remote-derivative-packages true --flavor kicksecure-cli --target raw)" || rc="$?"
if [ "${rc}" -eq 0 ]; then
   pass "--upload true + --remote-derivative-packages true, no ~/.ssh: passes (not publishable)"
else
   fail "--upload true + remote pkgs wrongly required ~/.ssh (${rc}) -- ${out}"
fi

## --- CANARY: '--upload false' must not be read as the opt-in ----------------
## The scan pairs the option with its VALUE; a scan matching only the '--upload'
## token would wrongly bite here.
rc=0
out="$(run_guard "${no_ssh_home}" "" --upload false --flavor kicksecure-cli --target raw)" || rc="$?"
if [ "${rc}" -eq 0 ]; then
   pass "canary: '--upload false' is not treated as the upload opt-in"
else
   fail "canary broken: '--upload false' triggered the ~/.ssh requirement; the scan ignores the option's value"
fi

## --- '--upload true' WITH credentials passes --------------------------------
rc=0
out="$(run_guard "${with_ssh_home}" "" --upload true --flavor kicksecure-cli --target raw)" || rc="$?"
if [ "${rc}" -eq 0 ]; then
   pass "--upload true with ~/.ssh present: passes the guard"
else
   fail "--upload true with ~/.ssh present: blocked (${rc}) -- ${out}"
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: upload ssh guard."
