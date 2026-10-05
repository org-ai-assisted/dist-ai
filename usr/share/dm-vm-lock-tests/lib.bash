#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## style-ok: no-strict -- sourced-only fragment; a top-level strict-mode block would leak
## set -o errexit/nounset into the consumer (every *_test.sh already sets it).

## Shared setup for the dm-vm-lock suite: resolve the REAL dm-vm-lock, a check() counter, a
## fresh temp lock dir (DM_VM_LOCK_DIR seam, with a pre-created vm.lock as the deployed
## tmpfiles.d entry would), and a race-free wait for a holder registry file. Sourced by each
## *_test.sh; not a test itself (no _test.sh suffix -> the runner skips it).

vmlock_dir="$(dirname -- "$(readlink --canonicalize -- "${BASH_SOURCE[0]}")")"

## Test seam: point the suite at a deliberately-broken copy to confirm a case FAILS on it.
TOOL="${DM_VM_LOCK_BIN:-}"
if [ -z "${TOOL}" ]; then
   if [ -x "${vmlock_dir}/../../bin/dm-vm-lock" ]; then
      TOOL="${vmlock_dir}/../../bin/dm-vm-lock"
   else
      TOOL='/usr/bin/dm-vm-lock'
   fi
fi
[ -x "${TOOL}" ] || { printf 'FATAL: dm-vm-lock not found/executable at %s\n' "${TOOL}" >&2; exit 1; }

vmlock_failures=0
check() {
   if [ "$2" -eq 0 ]; then
      printf 'PASS: %s\n' "$1"
   else
      printf 'FAIL: %s\n' "$1"
      vmlock_failures=$(( vmlock_failures + 1 ))
   fi
}

## A fresh lock dir with a pre-created vm.lock (what the shipped tmpfiles.d materializes).
## Prints the path; the caller exports DM_VM_LOCK_DIR=<it>.
new_lockdir() {
   local d
   d="$(mktemp --directory --tmpdir dm-vm-lock-test.XXXXXX)"
   printf '' > "${d}/vm.lock"
   printf '%s' "${d}"
}

## Wait (bounded, ~5s) for a holder registry file of a class to appear, so a test never races
## a background acquirer. Returns 0 once present, 1 on timeout.
wait_for_holder() {
   local dir="$1" class="$2" i
   local -a files
   shopt -s nullglob
   for (( i = 0; i < 100; i++ )); do
      files=("${dir}/holder.${class}."*)
      [ "${#files[@]}" -eq 0 ] || return 0
      sleep 0.05
   done
   return 1
}

vmlock_done() {
   printf '\n%s: %s fail\n' "$(basename -- "$0")" "${vmlock_failures}"
   [ "${vmlock_failures}" -eq 0 ] || exit 1
   exit 0
}
