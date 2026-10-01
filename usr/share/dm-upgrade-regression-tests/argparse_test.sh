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

## passphrase-file fixtures: 0600 accepted, 0644 rejected.
tmp="$(mktemp --directory)"
# shellcheck disable=SC2317  ## runs via the EXIT trap, not a direct call
cleanup() { safe-rm --recursive --force -- "${tmp}"; }
trap cleanup EXIT
pass_ok="${tmp}/pass-0600"
printf 'secret\n' > "${pass_ok}"
chmod 0600 "${pass_ok}"
pass_bad="${tmp}/pass-0644"
printf 'secret\n' > "${pass_bad}"
chmod 0644 "${pass_bad}"

## Valid combinations -> 0.
expect_rc 0 'R6: stable-proposed-updates + --persist'        --vm v --repository stable-proposed-updates --persist
expect_rc 0 'developer persona: developers + --persist'      --vm v --repository developers --persist
expect_rc 0 'a 0600 passphrase-file is accepted'             --vm v --repository developers --persist --passphrase-file "${pass_ok}"
## A snapshot value that is literally "--revert" must NOT register a mode conflict
## (the conflict check reads flags, not option values).
expect_rc 0 'snapshot value --revert is not a mode conflict'  --vm v --repository developers --persist --snapshot-name --revert

## CANARY: the persist/revert choice is MANDATORY (no silent default).
expect_rc "${SETUP_RC}" 'missing --persist/--revert is a setup error' --vm v --repository developers
## Both flags given -> mutually exclusive.
expect_rc "${SETUP_RC}" '--persist + --revert is a setup error'       --vm v --repository developers --persist --revert
## The revert lane is reserved for later.
expect_rc "${SETUP_RC}" '--revert alone is a setup error'            --vm v --repository developers --revert
## Only an upgrade SOURCE is a valid persona (R6 cannot be silently downgraded).
expect_rc "${SETUP_RC}" 'repository=stable is rejected'              --vm v --repository stable --persist
expect_rc "${SETUP_RC}" 'repository=bogus is rejected'               --vm v --repository bogus --persist
## --vm is required.
expect_rc "${SETUP_RC}" 'missing --vm is a setup error'              --repository developers --persist
## CANARY: a trailing value-option with no value is a clean setup error, not a
## nounset crash (exit 1).
expect_rc "${SETUP_RC}" 'trailing --vm with no value is setup, not a crash' --repository developers --persist --vm
## CANARY: a world-readable (0644) passphrase file is refused.
expect_rc "${SETUP_RC}" 'a 0644 passphrase-file is refused'          --vm v --repository developers --persist --passphrase-file "${pass_bad}"

printf '\n%s: %s pass, %s fail\n' "$(basename -- "$0")" "${pass}" "${fail}"
[ "${fail}" -eq 0 ] || exit 1
exit 0
