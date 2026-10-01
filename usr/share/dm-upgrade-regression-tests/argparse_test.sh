#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Drive the REAL dm-upgrade-regression with --validate-only (parses + validates,
## then exits before any VM/VBox work) and assert its exit codes. CANARY: the
## mandatory --persist|--revert choice -- if a silent default were (re)introduced,
## the "no mode" case would exit 0 and this test would fail.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"
if [ -n "${DM_UPGRADE_REGRESSION_BIN:-}" ]; then
   bin="${DM_UPGRADE_REGRESSION_BIN}"
else
   bin="${script_dir}/../../bin/dm-upgrade-regression"
fi
[ -x "${bin}" ] || { printf 'ERROR: dm-upgrade-regression not found/executable: %s\n' "${bin}" >&2; exit 1; }

pass=0
fail=0

## Run the recipe (always with --validate-only) and assert it exits WANT.
expect_rc() {
   local want="$1" desc="$2"; shift 2
   local rc=0
   "${bin}" --validate-only "$@" >/dev/null 2>&1 || rc=$?
   if [ "${rc}" -eq "${want}" ]; then
      printf 'PASS: %s (rc=%s)\n' "${desc}" "${rc}"
      pass=$(( pass + 1 ))
   else
      printf 'FAIL: %s (want rc=%s, got %s)\n' "${desc}" "${want}" "${rc}" >&2
      fail=$(( fail + 1 ))
   fi
}

SETUP_RC=2

## Valid combinations -> 0.
expect_rc 0 'R6: stable-proposed-updates + --persist'        --vm v --repository stable-proposed-updates --persist
expect_rc 0 'developer persona: developers + --persist'      --vm v --repository developers --persist
expect_rc 0 'developer persona non-blocking'                 --vm v --repository developers --persist --non-blocking

## CANARY: the persist/revert choice is MANDATORY (no silent default).
expect_rc "${SETUP_RC}" 'missing --persist/--revert is a setup error' --vm v --repository developers
## Mutually exclusive.
expect_rc "${SETUP_RC}" '--persist + --revert is a setup error'       --vm v --repository developers --persist --revert
## --revert lane reserved (not yet implemented).
expect_rc "${SETUP_RC}" '--revert is not-yet-implemented setup error' --vm v --repository developers --revert
## Repository must be an upgrade SOURCE.
expect_rc "${SETUP_RC}" 'repository=stable is not an upgrade source'  --vm v --repository stable --persist
expect_rc "${SETUP_RC}" 'repository=bogus is invalid'                 --vm v --repository bogus --persist
## --vm is required.
expect_rc "${SETUP_RC}" 'missing --vm is a setup error'               --repository developers --persist

printf '\n%s: %s pass, %s fail\n' "$(basename -- "$0")" "${pass}" "${fail}"
[ "${fail}" -eq 0 ] || exit 1
exit 0
