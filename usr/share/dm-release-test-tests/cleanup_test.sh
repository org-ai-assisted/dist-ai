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

## getent stub: the eph account resolves to a fake home under ${work}; anything else is
## passed to the real getent.
eph_home="${work}/home"
mkdir --parents -- "${eph_home}"
real_getent='/usr/bin/getent'
{
   printf '%s\n' '#!/bin/bash'
   printf '%s\n' "if [ \"\${1:-}\" = passwd ] && [ \"\${2:-}\" = 'eph-inst-kicksecure-18-2-3-5' ]; then"
   printf '%s\n' "   printf '%s\\n' 'eph-inst-kicksecure-18-2-3-5:x:5005:5005::${eph_home}:/bin/bash'"
   printf '%s\n' '   exit 0'
   printf '%s\n' 'fi'
   printf '%s\n' "'${real_getent}' \"\$@\""
} > "${stubbin}/getent"
chmod 0770 -- "${stubbin}/getent"

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

## ---- keep-on-failure + reclaim ------------------------------------------------------
export ISO_DIR="${work}/iso"
mkdir --parents -- "${ISO_DIR}"
## rt_kept_staged_marker comes from the sourced subject.
# shellcheck disable=SC2154
marker="${eph_home}/${rt_kept_staged_marker}"

## Sets $? for the next command, as main's exit status does for the EXIT trap.
rc_is() {
   return "$1"
}

## (a) FAILED run, keep on (default): nothing torn down, staged ISO kept, marker written.
true >| "${order}"
rt_staged_dir="$(mktemp --directory -- "${ISO_DIR}/.built-XXXXXX")"
export DM_RELEASE_TEST_KEEP_FAILED=1
rc_is 5 || rt_eph_cleanup >/dev/null 2>&1
check "keep: failed run tears nothing down" "$([ ! -s "${order}" ] && printf true || printf false)"
check "keep: staged ISO dir kept (VM still has it attached)" "$([ -d "${rt_staged_dir}" ] && printf true || printf false)"
check "keep: marker records the staged dir" "$([ "$(cat -- "${marker}" 2>/dev/null)" = "${rt_staged_dir}" ] && printf true || printf false)"
kept_dir="${rt_staged_dir}"

## (b) FAILED run, keep off: torn down as before.
true >| "${order}"
rt_staged_dir=""
export DM_RELEASE_TEST_KEEP_FAILED=0
rc_is 5 || rt_eph_cleanup >/dev/null 2>&1
check "no-keep: failed run invokes image-test-gc" "$(grep --quiet '^image-test-gc ' -- "${order}" && printf true || printf false)"
check "no-keep: failed run invokes userdel" "$(grep --quiet '^userdel ' -- "${order}" && printf true || printf false)"

## (c) reclaim of the kept account removes exactly the marked staged dir.
printf '%s\n' "${kept_dir}" > "${marker}"
rt_eph_reclaim 'eph-inst-kicksecure-18-2-3-5' >/dev/null 2>&1
check "reclaim: removes the kept staged ISO dir" "$([ ! -e "${kept_dir}" ] && printf true || printf false)"

## (d) the marker lives in a home the account owned: a path outside ISO_DIR/.built-*,
## or one escaping it with '..', is never removed.
victim="${work}/victim"
mkdir --parents -- "${victim}"
printf '%s\n' "${victim}" > "${marker}"
rt_eph_reclaim 'eph-inst-kicksecure-18-2-3-5' >/dev/null 2>&1
check "reclaim: ignores a marker outside ISO_DIR/.built-*" "$([ -d "${victim}" ] && printf true || printf false)"
## .built-x must EXIST, else the path walk fails and the escape is never attempted.
mkdir --parents -- "${ISO_DIR}/.built-x"
printf '%s\n' "${ISO_DIR}/.built-x/../../victim" > "${marker}"
rt_eph_reclaim 'eph-inst-kicksecure-18-2-3-5' >/dev/null 2>&1
check "reclaim: ignores a '..' escape from ISO_DIR/.built-*" "$([ -d "${victim}" ] && printf true || printf false)"

if [ "${failures}" -ne 0 ]; then
   printf '\n%s cleanup assertion(s) failed\n' "${failures}" >&2
   exit 1
fi
printf '\nall cleanup assertions passed\n'
