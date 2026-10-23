#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Canary: the work class is a BOUNDED semaphore (DM_VM_LOCK_WORK_SLOTS, default 2), not the
## unbounded shared lock. N work holders coexist; the N+1'th is capped (this FAILS on the old
## unbounded LOCK_SH). A freed slot is reusable; a leak still excludes ALL work regardless of
## free slots; a reentrant work-under-work takes NO second slot; a missing slot file is a loud
## deploy-precondition error, never a silent lower cap. Drives the REAL dm-vm-lock.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"
# shellcheck source=./lib.bash
source "${test_dir}/lib.bash"

## Background work/leak holders launched below; killed + reaped, and their lock dirs removed, on
## exit. Each holder is a dm-vm-lock wrapper around `sleep`; killing the wrapper forwards TERM to
## the timeout child and releases the flock.
pids=()
dirs=()
# shellcheck disable=SC2317  ## runs via the EXIT trap
cleanup() {
   local p d
   for p in "${pids[@]}"; do
      kill "${p}" 2>/dev/null || true
      wait "${p}" 2>/dev/null || true
   done
   for d in "${dirs[@]}"; do
      safe-rm --recursive --force -- "${d}" 2>/dev/null || true
   done
}
trap cleanup EXIT

## Hold a slot in the background: `<class> <lockdir> [slots]`. Records the pid. Returns once the
## holder's registry file exists (slot already claimed), so the caller never races acquisition.
bg_hold() {
   local class="$1" dir="$2" slots="${3:-}"
   DM_VM_LOCK_WORK_SLOTS="${slots}" DM_VM_LOCK_DIR="${dir}" \
      "${TOOL}" acquire --class "${class}" --ttl 120 --wait 10 -- sleep 120 &
   pids+=("$!")
}

## Wait (bounded ~10s) until at least n work-holder registry files exist in dir.
wait_for_n_work() {
   local dir="$1" n="$2" i
   local -a files
   shopt -s nullglob
   for (( i = 0; i < 200; i++ )); do
      files=("${dir}"/holder.work.*)
      [ "${#files[@]}" -ge "${n}" ] && return 0
      sleep 0.05
   done
   return 1
}

## --- N=2 default: two work holders coexist, the third is capped (75). FAILS on old unbounded. ---
d1="$(new_lockdir)"; dirs+=("${d1}")
bg_hold work "${d1}" 2
bg_hold work "${d1}" 2
if wait_for_n_work "${d1}" 2; then r=0; else r=1; fi
check 'two work holders coexist under the default N=2' "${r}"

rc=0; DM_VM_LOCK_WORK_SLOTS=2 DM_VM_LOCK_DIR="${d1}" "${TOOL}" acquire --class work --nonblock -- true 2>/dev/null || rc=$?
if [ "${rc}" -eq 75 ]; then r=0; else r=1; fi
check 'a third work holder is capped (75) under N=2 -- not the old unbounded shared lock' "${r}"

## --- a freed slot is reusable: kill one of the two holders, a new work holder then fits. ---
kill "${pids[-1]}" 2>/dev/null || true
wait "${pids[-1]}" 2>/dev/null || true
## Wait for the freed holder's registry file to drain back to one.
for (( i = 0; i < 200; i++ )); do
   files=("${d1}"/holder.work.*)
   [ "${#files[@]}" -le 1 ] && break
   sleep 0.05
done
rc=0; DM_VM_LOCK_WORK_SLOTS=2 DM_VM_LOCK_DIR="${d1}" "${TOOL}" acquire --class work --nonblock -- true 2>/dev/null || rc=$?
if [ "${rc}" -eq 0 ]; then r=0; else r=1; fi
check 'a freed slot is reusable (a new work holder acquires after one exits)' "${r}"

## --- a leak excludes ALL work regardless of free slots (slots do not weaken leak exclusion). ---
d2="$(new_lockdir)"; dirs+=("${d2}")
bg_hold leak "${d2}"
if wait_for_holder "${d2}" leak; then r=0; else r=1; fi
check 'a leak holder is recorded' "${r}"
rc=0; DM_VM_LOCK_DIR="${d2}" "${TOOL}" acquire --class work --nonblock -- true 2>/dev/null || rc=$?
if [ "${rc}" -eq 75 ]; then r=0; else r=1; fi
check 'a leak holder excludes work even with all slots free (75)' "${r}"

## --- the knob: DM_VM_LOCK_WORK_SLOTS=1 caps work at one. ---
d3="$(new_lockdir)"; dirs+=("${d3}")
bg_hold work "${d3}" 1
if wait_for_n_work "${d3}" 1; then r=0; else r=1; fi
check 'one work holder under DM_VM_LOCK_WORK_SLOTS=1' "${r}"
rc=0; DM_VM_LOCK_WORK_SLOTS=1 DM_VM_LOCK_DIR="${d3}" "${TOOL}" acquire --class work --nonblock -- true 2>/dev/null || rc=$?
if [ "${rc}" -eq 75 ]; then r=0; else r=1; fi
check 'DM_VM_LOCK_WORK_SLOTS=1 caps work at one (2nd -> 75)' "${r}"

## --- reentrant work-under-work takes NO second slot: runs through even with the only slot busy. ---
rc=0; DM_VM_LOCK_HELD=work DM_VM_LOCK_WORK_SLOTS=1 DM_VM_LOCK_DIR="${d3}" \
   "${TOOL}" acquire --class work --nonblock -- true 2>/dev/null || rc=$?
if [ "${rc}" -eq 0 ]; then r=0; else r=1; fi
check 'reentrant work-under-work consumes no second slot (pass-through runs despite busy slot)' "${r}"

## --- a missing slot file is a loud 69, never a silent lower cap. ---
d4="$(new_lockdir)"; dirs+=("${d4}")
safe-rm --force -- "${d4}/slot.2" "${d4}/slot.3" "${d4}/slot.4"
rc=0; DM_VM_LOCK_WORK_SLOTS=2 DM_VM_LOCK_DIR="${d4}" "${TOOL}" acquire --class work --nonblock -- true 2>/dev/null || rc=$?
if [ "${rc}" -eq 69 ]; then r=0; else r=1; fi
check 'a missing slot file is rejected (69), not silently capped lower' "${r}"

## --- --wait is a true DEADLINE, not rounded up to the poll interval. With poll (10s) >> wait
##     (2s) and the only slot held, the cap must return 75 at ~wait, NOT ~poll. FAILS on the old
##     code that always slept a full poll before re-checking the deadline. ---
d5="$(new_lockdir)"; dirs+=("${d5}")
bg_hold work "${d5}" 1
if wait_for_n_work "${d5}" 1; then r=0; else r=1; fi
check 'one work holder under N=1 (deadline test setup)' "${r}"
start_s=${SECONDS}
rc=0; DM_VM_LOCK_WORK_SLOTS=1 DM_VM_LOCK_SLOT_POLL=10 DM_VM_LOCK_DIR="${d5}" \
   "${TOOL}" acquire --class work --wait 2 -- true 2>/dev/null || rc=$?
dur_s=$(( SECONDS - start_s ))
if [ "${rc}" -eq 75 ] && [ "${dur_s}" -lt 6 ]; then r=0; else r=1; fi
check "the slot wait honors --wait as a deadline (75 at ~2s, not ~10s; got rc=${rc} dur=${dur_s}s)" "${r}"

## --- a work waiter polling for a slot holds the shared lock, so `status` MUST show it (its
##     holder record is written BEFORE the poll). Otherwise a blocked leak sees "no holders".
##     Holder A takes the only slot; waiter B then polls -> two work holder records must appear.
##     FAILS on the old code that wrote B's record only after it claimed a slot (which it never does). ---
d6="$(new_lockdir)"; dirs+=("${d6}")
bg_hold work "${d6}" 1
if wait_for_n_work "${d6}" 1; then r=0; else r=1; fi
check 'holder A takes the only slot (waiter-visibility setup)' "${r}"
DM_VM_LOCK_WORK_SLOTS=1 DM_VM_LOCK_DIR="${d6}" \
   "${TOOL}" acquire --class work --ttl 30 --wait 20 -- sleep 20 &
pids+=("$!")
if wait_for_n_work "${d6}" 2; then r=0; else r=1; fi
check 'a work waiter polling for a slot is visible in status (record written before the poll)' "${r}"

vmlock_done
