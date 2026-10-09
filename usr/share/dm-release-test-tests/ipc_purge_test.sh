#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for rt_purge_foreign_vbox_ipc. Canary: VBoxXPCOMIPCD keeps its
## per-user IPC socket under <base>/.vbox-<user>-ipc and REFUSES a dir it does not
## own, so VBoxManage fails "Failed to create the VirtualBox object". userdel leaves
## the dir behind and an eph-inst-<guest>-<version> account is reused by NAME with a
## fresh uid; the old uid is later reused by another account, so the stale dir is now
## foreign-owned and poisons the next same-named account. The purge MUST remove a
## foreign-owned dir, KEEP one the account owns (a persist-* account's own dir), and
## no-op cleanly when absent.

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
work="$(mktemp --directory --tmpdir dm-release-test-ipc.XXXXXX)"

ipc_test_cleanup() {
   [ -n "${work}" ] || return 0
   safe-rm --recursive --force -- "${work}"
}
trap ipc_test_cleanup EXIT

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

## Point the per-user IPC base at a throwaway dir (the function's test seam), so the
## purge never touches a real /tmp/.vbox-*-ipc.
export VBOX_IPC_BASE="${work}/ipc"
mkdir --parents -- "${VBOX_IPC_BASE}"
me="$(id --user --name)"

## Case 1: a FOREIGN-owned dir (created by this test user, named for a DIFFERENT
## account) is the exact poison state -> must be removed.
foreign_acct='eph-inst-kicksecure-18-2-3-5'
[ "${foreign_acct}" != "${me}" ] || foreign_acct='eph-inst-other-account-1'
mkdir -- "${VBOX_IPC_BASE}/.vbox-${foreign_acct}-ipc"
rt_purge_foreign_vbox_ipc "${foreign_acct}"
check "foreign-owned stale IPC dir removed" \
   "$([ ! -e "${VBOX_IPC_BASE}/.vbox-${foreign_acct}-ipc" ] && printf true || printf false)"

## Case 2: a dir the account OWNS (this test user) must be preserved -- a persist-*
## account legitimately keeps its own dir across runs.
mine="${VBOX_IPC_BASE}/.vbox-${me}-ipc"
mkdir -- "${mine}"
rt_purge_foreign_vbox_ipc "${me}"
check "account-owned IPC dir preserved" \
   "$([ -d "${mine}" ] && printf true || printf false)"

## Case 3: absent -> clean no-op (returns success, errexit-safe).
absent_rc=0
rt_purge_foreign_vbox_ipc 'eph-inst-absent-account-1' || absent_rc=$?
check "absent IPC dir is a clean no-op" \
   "$([ "${absent_rc}" -eq 0 ] && printf true || printf false)"

## Case 4: a SYMLINK at the IPC path (it lives in world-writable /tmp) is removed as
## a LINK -- never followed -- so its target is untouched. Guards the /tmp symlink
## hardening note: a planted symlink must not let --recursive delete the target.
target_dir="${work}/precious"
mkdir -- "${target_dir}"
touch -- "${target_dir}/keep"
ln --symbolic -- "${target_dir}" "${VBOX_IPC_BASE}/.vbox-eph-inst-symlink-1-ipc"
rt_purge_foreign_vbox_ipc 'eph-inst-symlink-1'
check "symlink at the IPC path is removed (the link itself)" \
   "$([ ! -e "${VBOX_IPC_BASE}/.vbox-eph-inst-symlink-1-ipc" ] && [ ! -L "${VBOX_IPC_BASE}/.vbox-eph-inst-symlink-1-ipc" ] && printf true || printf false)"
check "symlink target is untouched (not followed/recursed)" \
   "$([ -f "${target_dir}/keep" ] && printf true || printf false)"

if [ "${failures}" -ne 0 ]; then
   printf '\n%s ipc-purge assertion(s) failed\n' "${failures}" >&2
   exit 1
fi
printf '\nall ipc-purge assertions passed\n'
