#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Canary: a signal to the dm-vm-lock WRAPPER is forwarded to the wrapped command, and the child
## is reaped BEFORE the flock is released -- the lock must never be freed while the VM-work
## command keeps running (orphaned). Without the signal-forwarding, killing the wrapper would
## release the lock while the command lived on, and a leak test could start alongside it.

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

childpid_file="${d}/childpid"
## The wrapped command records its own PID then execs sleep (same PID), so we can check it died.
script="printf '%s' \"\$\$\" > '${childpid_file}'; exec sleep 60"
"${TOOL}" acquire --class leak --ttl 60 --wait 10 -- sh -c "${script}" &
wrapper=$!

rc=0; wait_for_holder "${d}" leak || rc=$?
check 'wrapper acquired the leak lock' "${rc}"

cpid=""
for (( i = 0; i < 100; i++ )); do
   if [ -s "${childpid_file}" ]; then
      cpid="$(cat -- "${childpid_file}")"
      break
   fi
   sleep 0.05
done
if [ -n "${cpid}" ]; then r=0; else r=1; fi
check 'the wrapped command started' "${r}"

## Signal the WRAPPER (as an ssh disconnect / supervisor stop would).
kill -TERM "${wrapper}" 2>/dev/null || true
wait "${wrapper}" 2>/dev/null || true

## The wrapped command must be GONE (forwarded + reaped), not orphaned.
gone=1
for (( i = 0; i < 100; i++ )); do
   if [ ! -e "/proc/${cpid}" ]; then
      gone=0
      break
   fi
   sleep 0.05
done
if [ "${gone}" -eq 0 ]; then r=0; else r=1; fi
check 'signaling the wrapper took the wrapped command down with it (not orphaned)' "${r}"

## ...and the lock is free (the flock outlived the command, released only after it was reaped).
rc=0; "${TOOL}" acquire --class leak --nonblock -- true 2>/dev/null || rc=$?
check 'the lock is released once the signaled wrapper exits' "${rc}"

vmlock_done
