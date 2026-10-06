#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Canary: the error/usage paths fail with distinct, documented exit codes -- a bad class and
## a missing command are usage errors (64); a missing lock file is a deploy precondition error
## (69), NOT a silent run unlocked.

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
# shellcheck disable=SC2317  ## runs via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${d}"; }
trap cleanup EXIT
export DM_VM_LOCK_DIR="${d}"

rc=0; "${TOOL}" acquire --class bogus -- true 2>/dev/null || rc=$?
if [ "${rc}" -eq 64 ]; then r=0; else r=1; fi
check 'a bad --class is rejected (64)' "${r}"

rc=0; "${TOOL}" acquire --class work -- 2>/dev/null || rc=$?
if [ "${rc}" -eq 64 ]; then r=0; else r=1; fi
check 'a missing command after -- is rejected (64)' "${r}"

rc=0; "${TOOL}" bogus 2>/dev/null || rc=$?
if [ "${rc}" -eq 64 ]; then r=0; else r=1; fi
check 'an unknown subcommand is rejected (64)' "${r}"

## A missing lock file is a deploy-precondition error, never a silent unlocked run.
nolock="${d}/nolock"; mkdir -- "${nolock}"
rc=0; DM_VM_LOCK_DIR="${nolock}" "${TOOL}" acquire --class work -- true 2>/dev/null || rc=$?
if [ "${rc}" -eq 69 ]; then r=0; else r=1; fi
check 'a missing lock file is rejected (69), not run unlocked' "${r}"

## --ttl 0 would tell timeout(1) to DISABLE the deadline -- reject it (the backstop must stay).
rc=0; "${TOOL}" acquire --class work --ttl 0 -- true 2>/dev/null || rc=$?
if [ "${rc}" -eq 64 ]; then r=0; else r=1; fi
check 'a zero --ttl is rejected (64), not silently unbounded' "${r}"

## A leading-zero TTL is base-10, not octal: --ttl 08 must RUN (8s), not die on octal arithmetic.
rc=0; out="$("${TOOL}" acquire --class work --ttl 08 --wait 5 -- printf 'ok')" || rc=$?
if [ "${rc}" -eq 0 ] && [ "${out}" = 'ok' ]; then r=0; else r=1; fi
check 'a leading-zero --ttl (08) is parsed base-10 and runs' "${r}"

## A value-taking option given as the LAST arg (no value) is a clean usage error (64), not a
## shift-2 crash (exit 1) under errexit+shift_verbose.
for opt in --class --ttl --wait; do
   rc=0; "${TOOL}" acquire "${opt}" 2>/dev/null || rc=$?
   if [ "${rc}" -eq 64 ]; then r=0; else r=1; fi
   check "a trailing ${opt} with no value is rejected (64), not a crash" "${r}"
done

vmlock_done
