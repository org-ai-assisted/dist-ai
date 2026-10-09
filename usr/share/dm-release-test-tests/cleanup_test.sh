#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for rt_eph_cleanup. Canary: a VBoxSVC owned by the ephemeral
## account lingers after the VM stops and blocks userdel (observed leaking the
## account in a live run), so cleanup MUST kill the account's processes BEFORE
## userdel. Stubs image-test-gc / pkill / userdel as order-recording stand-ins
## and asserts the kill precedes the userdel.

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
work="$(mktemp --directory --tmpdir dm-release-test-cleanup.XXXXXX)"

cleanup_test_cleanup() {
   [ -n "${work}" ] || return 0
   safe-rm --recursive --force -- "${work}"
}
trap cleanup_test_cleanup EXIT

stubbin="${work}/bin"
mkdir --parents -- "${stubbin}"
order="${work}/order.log"

for tool in image-test-gc pkill userdel; do
   {
      printf '%s\n' '#!/bin/bash'
      printf '%s\n' "printf '%s %s\\n' '${tool}' \"\$*\" >> '${order}'"
      printf '%s\n' 'exit 0'
   } > "${stubbin}/${tool}"
done
chmod 0770 -- "${stubbin}/image-test-gc" "${stubbin}/pkill" "${stubbin}/userdel"

## Globals rt_eph_cleanup reads (exported so shellcheck sees them used).
export PATH="${stubbin}:${PATH}"
export IMAGE_TEST_GC="${stubbin}/image-test-gc"
export EPH_CLEANUP_SETTLE=0
export NFT_FLEET_TOOL="definitely-not-on-path-${RANDOM}"
export eph_account='eph-inst-kicksecure-18-2-3-5'

rt_eph_cleanup >/dev/null 2>&1

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

pkill_line="$(grep -n '^pkill ' -- "${order}" | head -n 1 | cut -d: -f1)"
userdel_line="$(grep -n '^userdel ' -- "${order}" | head -n 1 | cut -d: -f1)"

check "image-test-gc was invoked" "$(grep --quiet '^image-test-gc ' -- "${order}" && printf true || printf false)"
check "pkill killed the account by uid" "$(grep --quiet -- 'pkill .*--uid eph-inst-kicksecure-18-2-3-5' "${order}" && printf true || printf false)"
check "userdel was invoked" "$([ -n "${userdel_line}" ] && printf true || printf false)"
## Canary: a reverted fix (userdel with no prior pkill) leaves pkill_line empty or after userdel.
check "pkill ran BEFORE userdel" "$([ -n "${pkill_line}" ] && [ -n "${userdel_line}" ] && [ "${pkill_line}" -lt "${userdel_line}" ] && printf true || printf false)"

if [ "${failures}" -ne 0 ]; then
   printf '\n%s cleanup assertion(s) failed\n' "${failures}" >&2
   exit 1
fi
printf '\nall cleanup assertions passed\n'
