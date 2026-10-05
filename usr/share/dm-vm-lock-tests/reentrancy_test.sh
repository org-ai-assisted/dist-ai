#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Canary: DM_VM_LOCK_HELD makes acquire a pass-through no-op -- it runs the command and takes
## NO lock. Without the no-op, a nested acquire (e.g. dm-release-test -> a self-locking leaf)
## would block/deadlock behind the already-held exclusive lock. Proven here by holding an
## EXCLUSIVE leak and showing a reentrant acquire still runs immediately.

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

d="$(new_lockdir)"
export DM_VM_LOCK_DIR="${d}"
# shellcheck disable=SC2317  ## runs via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${d}"; }
trap cleanup EXIT

"${TOOL}" acquire --class leak --ttl 30 --wait 10 -- sleep 3 &
bgpid=$!
rc=0; wait_for_holder "${d}" leak || rc=$?
check 'a leak holder is up' "${rc}"

## A reentrant acquire (DM_VM_LOCK_HELD set) must RUN IMMEDIATELY despite the held leak.
rc=0; out="$(DM_VM_LOCK_HELD=work "${TOOL}" acquire --class work --nonblock -- printf 'reentrant')" || rc=$?
if [ "${rc}" -eq 0 ] && [ "${out}" = 'reentrant' ]; then r=0; else r=1; fi
check 'reentrant acquire (DM_VM_LOCK_HELD set) runs through even while a leak is held' "${r}"

## ...and it registered NO holder of its own (it took no lock).
shopt -s nullglob
work_holders=("${d}"/holder.work.*)
if [ "${#work_holders[@]}" -eq 0 ]; then r=0; else r=1; fi
check 'reentrant acquire registers no holder (took no lock)' "${r}"

wait "${bgpid}" 2>/dev/null || true

## Class-aware reentrancy: a held 'work' (shared) does NOT cover a nested 'leak' (exclusive),
## so it must be REFUSED (not silently run non-exclusively), while a held 'leak' covers anything.
rc=0; DM_VM_LOCK_HELD=work "${TOOL}" acquire --class leak --nonblock -- true 2>/dev/null || rc=$?
if [ "${rc}" -eq 70 ]; then r=0; else r=1; fi
check 'a leak acquire while holding work is refused (70), not run non-exclusively' "${r}"

rc=0; out="$(DM_VM_LOCK_HELD=leak "${TOOL}" acquire --class work --nonblock -- printf 'ok')" || rc=$?
if [ "${rc}" -eq 0 ] && [ "${out}" = 'ok' ]; then r=0; else r=1; fi
check 'a work acquire while holding leak passes through (leak covers work)' "${r}"

vmlock_done
