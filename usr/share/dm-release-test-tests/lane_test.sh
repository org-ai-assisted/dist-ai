#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for the Kicksecure lane's acquire step. Canary targets:
##   - a FAILED iso-download must FAIL the lane, publish verdict FAIL, and NEVER
##     reach the installer (errexit is disabled inside a function called as
##     `... || rc=$?`, so the lane must check the download rc explicitly -- a
##     reverted fix falls through to the install and emits a false PASS).
##   - the lane must pin the RESOLVED version via --version, not re-resolve.
## A sudo passthrough stub lets the (reverted) fall-through actually reach the
## installer recorder, so the "installer not invoked" assertion is a real canary.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

subject="${DM_RELEASE_TEST_BIN:-}"
if [ -z "${subject}" ]; then
   if [ -f "${test_dir}/../../bin/dm-release-test" ]; then
      subject="${test_dir}/../../bin/dm-release-test"
   else
      subject='/usr/bin/dm-release-test'
   fi
fi
[ -r "${subject}" ] || { printf 'FATAL: dm-release-test not found at %s\n' "${subject}" >&2; exit 1; }
# shellcheck disable=SC1090
source "${subject}"

failures=0
work="$(mktemp --directory --tmpdir dm-release-test-lane.XXXXXX)"

lane_test_cleanup() {
   [ -n "${work}" ] || return 0
   safe-rm --recursive --force -- "${work}"
}
trap lane_test_cleanup EXIT

stubbin="${work}/bin"
mkdir --parents -- "${stubbin}"
iso_argv="${work}/iso-download.argv"
install_argv="${work}/calamares.argv"

## iso-download stub: record argv, then FAIL (stands in for a verification failure).
iso_stub="${stubbin}/iso-download-stub"
{
   printf '%s\n' '#!/bin/bash'
   printf '%s\n' "printf '%s\\n' \"\$*\" >> '${iso_argv}'"
   printf '%s\n' 'exit 1'
} > "${iso_stub}"

## dm-calamares-install recorder: record argv, succeed. The fixed lane must NEVER
## reach this after a failed download.
install_stub="${stubbin}/dm-calamares-install"
{
   printf '%s\n' '#!/bin/bash'
   printf '%s\n' "printf '%s\\n' \"\$*\" >> '${install_argv}'"
   printf '%s\n' 'exit 0'
} > "${install_stub}"

## sudo passthrough: drop "-u <user>" and a leading "--", run the rest as this
## user, so the lane's sudo steps work without root (and a reverted fall-through
## actually reaches the installer recorder).
sudo_stub="${stubbin}/sudo"
## The single-quoted lines are the stub's literal source; they must NOT expand here.
# shellcheck disable=SC2016
{
   printf '%s\n' '#!/bin/bash'
   printf '%s\n' 'args=()'
   printf '%s\n' 'while [ "$#" -gt 0 ]; do'
   printf '%s\n' '  if [ "$1" = "-u" ]; then shift 2; continue; fi'
   printf '%s\n' '  if [ "$1" = "--" ]; then shift; break; fi'
   printf '%s\n' '  args+=("$1"); shift'
   printf '%s\n' 'done'
   printf '%s\n' 'exec "${args[@]}" "$@"'
} > "${sudo_stub}"

chmod 0770 -- "${iso_stub}" "${install_stub}" "${sudo_stub}"

## Globals the lane reads (normally set by main()); consumed inside the sourced
## dm-release-test functions. export marks them used (shellcheck cannot see the
## cross-file use).
export PATH="${stubbin}:${PATH}"
export ISO_DOWNLOAD="${iso_stub}"
export DM_CALAMARES_INSTALL="${install_stub}"
export interface='lxqt'
export desktop='LXQt'
export channel='developers'
export run_checks='false'
export firmware='efi-secureboot'
export RESULTS_ROOT="${work}/results"
export RESULTS_OWNER
RESULTS_OWNER="$(id --user --name)"

rc=0
rt_lane_kicksecure "persist-stable-kicksecure" 18.2.3.5 >/dev/null 2>&1 || rc=$?

check() {
   local label cond
   label="$1"
   cond="$2"
   if [ "${cond}" = 'true' ]; then
      printf 'ok: %s\n' "${label}"
   else
      printf 'FAIL: %s\n' "${label}" >&2
      failures=$((failures + 1))
   fi
}

## A: the download failure propagates, the installer is never reached, and the
## published verdict is a FAIL (not a false PASS).
check "lane returns nonzero on download failure" "$([ "${rc}" -ne 0 ] && printf true || printf false)"
check "installer was NOT invoked after a failed download" "$([ ! -s "${install_argv}" ] && printf true || printf false)"
json="$(find "${RESULTS_ROOT}" -name result.json -print -quit 2>/dev/null || true)"
check "a result.json was published" "$([ -n "${json}" ] && [ -f "${json}" ] && printf true || printf false)"
if [ -n "${json}" ]; then
   check "published verdict is FAIL" "$(grep --quiet '"verdict": "FAIL"' -- "${json}" && printf true || printf false)"
fi

## B: the lane pinned the resolved version (did not re-resolve).
check "iso-download was invoked with --version 18.2.3.5" \
   "$(grep --quiet -- '--version 18.2.3.5' "${iso_argv}" && printf true || printf false)"

if [ "${failures}" -ne 0 ]; then
   printf '\n%s lane assertion(s) failed\n' "${failures}" >&2
   exit 1
fi
printf '\nall lane assertions passed\n'
