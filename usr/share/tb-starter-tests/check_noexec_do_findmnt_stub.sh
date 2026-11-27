#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Stub 'findmnt' for check_noexec_do_test.sh. Models the one behavior
## check_noexec_do relies on: 'findmnt --target PATH' needs an EXISTING path --
## real findmnt exits non-zero on a missing one (it does NOT walk to the parent).
## So this stub exits 1 unless its --target argument exists, which is what forces
## check_noexec_do to resolve the nearest existing ancestor first. For an
## existing target it prints the scenario's controlled mount OPTIONS
## (FINDMNT_STUB_OPTIONS) with exit 0. FINDMNT_STUB_RC, when non-zero, overrides:
## it models a findmnt that fails even on an existing path.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

target=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--target" ]; then
    shift
    target="${1:-}"
    break
  fi
  shift
done

rc="${FINDMNT_STUB_RC:-0}"
if [ "${rc}" != "0" ]; then
  exit "${rc}"
fi

## Real findmnt --target fails on a nonexistent (or empty) path.
if [ -z "${target}" ] || [ ! -e "${target}" ]; then
  exit 1
fi

## Record the resolved --target (when asked) so a test can assert check_noexec_do
## queried tb_home_folder's own ancestor, not a hardcoded path.
if [ -n "${FINDMNT_STUB_TARGET_FILE:-}" ]; then
  printf '%s\n' "${target}" >> "${FINDMNT_STUB_TARGET_FILE}"
fi

printf '%s\n' "${FINDMNT_STUB_OPTIONS:-}"
