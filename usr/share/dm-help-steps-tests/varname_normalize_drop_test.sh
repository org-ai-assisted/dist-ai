#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression + CANARY for varname_snapshot_lib.bsh's vs_filter_and_normalize:
## a 'git describe'-derived, checkout-volatile variable whose snapshot value is a
## pin artifact (dist_build_version_described) must be DROPPED by name -- else it is
## perpetual snapshot noise (a NEW dm variable absent from the committed baseline
## fails varname_snapshot_test on every dev checkout that has it, with no stable
## placeholder to normalize the value to).
##
## Pure unit test: sources the lib, feeds a synthetic 'declare -p' stream through
## vs_filter_and_normalize, and asserts the volatile-derived var is dropped while a
## normal build var survives. FAILS on the old lib (no vs_volatile_derived_re), so
## it is a genuine regression test. No dm checkout, no root, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

lib="${test_dir}/varname_snapshot_lib.bsh"
if [ ! -r "${lib}" ]; then
   printf '%s\n' "FATAL: varname_snapshot_lib.bsh not found at '${lib}'." >&2
   exit 1
fi
# shellcheck source=./varname_snapshot_lib.bsh
source "${lib}"

## vs_filter_and_normalize subtracts names listed in vs_baseline_file; an EMPTY file
## means "subtract nothing", so only the shell-special + volatile-derived drops apply.
vs_baseline_file="$(mktemp)"
# shellcheck disable=SC2317  # reached only via the EXIT trap
cleanup() { safe-rm --force -- "${vs_baseline_file}"; }
trap cleanup EXIT

## A sentinel dm path that cannot collide with the test payload (so vs_normalize's
## @DM@ path substitution is a no-op here).
dm_sentinel='/nonexistent-dm-checkout-sentinel'

out="$(
   printf '%s\n' \
      'declare -x dist_build_version_described="deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"' \
      'declare -x dist_build_flavor="kicksecure-cli"' \
      'declare -x BASH_REMATCH="lazily-populated"' \
   | vs_filter_and_normalize "${dm_sentinel}"
)"

fail=0
check() {  ## $1=got $2=want $3=label
   if [ "$1" = "$2" ]; then
      printf 'PASS: %s\n' "$3"
   else
      printf 'FAIL: %s (got %s, want %s)\n' "$3" "$1" "$2" >&2
      fail=$(( fail + 1 ))
   fi
}

## THE REGRESSION: the volatile-derived var is dropped from the snapshot.
n_described="$(printf '%s\n' "${out}" | grep -c -- 'dist_build_version_described' || true)"
check "${n_described}" 0 "dist_build_version_described is dropped (no perpetual snapshot noise)"

## A normal build variable is KEPT (the drop is targeted, not a blanket filter).
n_flavor="$(printf '%s\n' "${out}" | grep -c -- 'dist_build_flavor' || true)"
check "${n_flavor}" 1 "an ordinary build variable survives the filter"

## Control: the existing shell-special drop still works (guards against a broken filter).
n_special="$(printf '%s\n' "${out}" | grep -c -- 'BASH_REMATCH' || true)"
check "${n_special}" 0 "a shell-special is still dropped (filter intact)"

if [ "${fail}" -gt 0 ]; then
   printf 'varname_normalize_drop_test: %s assertion(s) FAILED.\n' "${fail}" >&2
   exit 1
fi
printf 'varname_normalize_drop_test: OK\n'
