#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Canary: the readers-writer class semantics. leak is EXCLUSIVE (blocks + is blocked by
## work); work is SHARED (two work holders coexist). On a tool that flocked leak as shared,
## or work as exclusive, these assertions FAIL. Also: acquire runs the wrapped command and
## propagates its exit code, and releases on exit.

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

## --- acquire runs the command + propagates its exit code -------------------------------
rc=0; out="$("${TOOL}" acquire --class work --ttl 60 --wait 5 -- printf 'ran')" || rc=$?
if [ "${rc}" -eq 0 ] && [ "${out}" = 'ran' ]; then r=0; else r=1; fi
check 'acquire runs the wrapped command (rc 0, output passes through)' "${r}"

rc=0; "${TOOL}" acquire --class work --ttl 60 --wait 5 -- sh -c 'exit 7' || rc=$?
if [ "${rc}" -eq 7 ]; then r=0; else r=1; fi
check 'acquire propagates the wrapped command exit code' "${r}"

"${TOOL}" status > "${d}/st" 2>&1 || true
rc=0; grep --quiet -- 'no current VM-work lock holders' "${d}/st" || rc=1
check 'lock released after the command exits (no holders remain)' "${rc}"

## --- leak EXCLUDES work ---------------------------------------------------------------
"${TOOL}" acquire --class leak --ttl 30 --wait 10 -- sleep 3 &
bgpid=$!
rc=0; wait_for_holder "${d}" leak || rc=$?
check 'a leak holder registers' "${rc}"
rc=0; "${TOOL}" acquire --class work --nonblock -- true 2>/dev/null || rc=$?
if [ "${rc}" -eq 75 ]; then r=0; else r=1; fi
check 'a leak holder blocks a work acquire (exit 75)' "${r}"
wait "${bgpid}" 2>/dev/null || true

## --- work EXCLUDES leak ---------------------------------------------------------------
"${TOOL}" acquire --class work --ttl 30 --wait 10 -- sleep 3 &
bgpid=$!
rc=0; wait_for_holder "${d}" work || rc=$?
check 'a work holder registers' "${rc}"
rc=0; "${TOOL}" acquire --class leak --nonblock -- true 2>/dev/null || rc=$?
if [ "${rc}" -eq 75 ]; then r=0; else r=1; fi
check 'a work holder blocks a leak acquire (exit 75)' "${r}"
wait "${bgpid}" 2>/dev/null || true

## --- two WORK holders coexist (shared) ------------------------------------------------
"${TOOL}" acquire --class work --ttl 30 --wait 10 -- sleep 3 &
bgpid=$!
rc=0; wait_for_holder "${d}" work || rc=$?
check 'a first work holder registers' "${rc}"
rc=0; "${TOOL}" acquire --class work --nonblock -- true || rc=$?
if [ "${rc}" -eq 0 ]; then r=0; else r=1; fi
check 'a second work holder coexists with the first (shared)' "${r}"
wait "${bgpid}" 2>/dev/null || true

vmlock_done
