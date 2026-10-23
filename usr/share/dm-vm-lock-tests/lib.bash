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
[ -x "${TOOL}" ] || { printf '%s\n' "FATAL: dm-vm-lock not found/executable at ${TOOL}" >&2; exit 1; }

vmlock_failures=0
check() {
   if [ "$2" -eq 0 ]; then
      printf '%s\n' "PASS: ${1}"
   else
      printf '%s\n' "FAIL: ${1}"
      vmlock_failures=$(( vmlock_failures + 1 ))
   fi
}

## Materialize the deployed lock layout (vm.lock + slot.1..slot.4) in an EXISTING dir -- what the
## shipped tmpfiles.d creates. Pre-creating the slots is the DEFAULT so every work-class test gets
## a deployable dir with nothing to remember; a test probing the missing-slot path removes one
## explicitly. Keep the slot count in sync with debian/dist-ai.tmpfiles.
materialize_lockdir() {
   local d="$1" i
   printf '%s' "" > "${d}/vm.lock"
   for (( i = 1; i <= 4; i++ )); do
      printf '%s' "" > "${d}/slot.${i}"
   done
}

## A FRESH temp lock dir, fully materialized. Prints the path; the caller exports DM_VM_LOCK_DIR=<it>.
new_lockdir() {
   local d
   d="$(mktemp --directory --tmpdir dm-vm-lock-test.XXXXXX)"
   materialize_lockdir "${d}"
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
   printf '%s\n' "" "$(basename -- "$0"): ${vmlock_failures} fail"
   [ "${vmlock_failures}" -eq 0 ] || exit 1
   exit 0
}
