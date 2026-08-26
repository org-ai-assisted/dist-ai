#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for derivative-maker 'help-steps/variables' frozen snapshot
## pin validation.
##
## THE BUG IT GUARDS: the frozen snapshot pin is a BARE UNIX EPOCH -- the
## generator (dm-update-frozen-snapshot) writes 'date +%s', consumers derive the
## snapshot.debian.org YYYYMMDDTHHMMSSZ id from it via 'date --date=@<pin>', and
## variables assigns it straight to SOURCE_DATE_EPOCH. A refactor inverted the
## validation so it ERRORED on a valid integer epoch ("Malformed snapshot pin"),
## failing every frozen build at 1100_sanity-tests. This drives the SHIPPED
## validation block and fails if the direction inverts again.
##
## Drives the real 'if frozen ... fi' block extracted from variables; no drift,
## no root, no network, no build.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=./help_steps_test_lib.bsh
source "${test_dir}/help_steps_test_lib.bsh"

variables=""
for candidate in "${DM_VARIABLES:-}" \
   "${DERIVATIVE_MAKER_DIR:-}/help-steps/variables" \
   "${dm_checkout}/help-steps/variables"; do
   case "${candidate}" in
      ''|'/help-steps/variables')
         continue
         ;;
   esac
   if [ -r "${candidate}" ]; then
      variables="${candidate}"
      break
   fi
done

if [ -z "${variables}" ]; then
   printf '%s\n' "FATAL: no derivative-maker help-steps/variables found (set DM_VARIABLES)." >&2
   exit 1
fi

## Extract the top-level frozen-pin block. There is MORE than one col-0
## 'if [ "${dist_build_apt_freshness...}" = "frozen" ]' block, so select the one
## that actually mentions dist_frozen_snapshot_pin. Opening 'if' and closing 'fi'
## sit at column 0; nested 'fi's are indented, so a bare 'fi' bounds the outer one.
block="$(awk '
   /^if \[ "\$\{dist_build_apt_freshness.*= "frozen" \]/ { buf = $0 ORS; cap = 1; next }
   cap {
      buf = buf $0 ORS
      if ($0 == "fi") {
         if (buf ~ /dist_frozen_snapshot_pin/) { printf "%s", buf; exit }
         cap = 0; buf = ""
      }
   }
' < "${variables}")"
if [ -z "${block}" ] || [[ "${block}" != *dist_frozen_snapshot_pin* ]]; then
   printf '%s\n' "FATAL: could not extract the frozen-pin block from ${variables}." >&2
   exit 1
fi

workdir=""
# shellcheck disable=SC2317  # reached only via the EXIT trap
cleanup() {
   [ -z "${workdir}" ] || safe-rm --recursive --force -- "${workdir}"
}
trap cleanup EXIT
workdir="$(mktemp --directory)"

## Run the extracted block against a pin value in a subshell; echo a verdict line
## + exit status. error() is stubbed to a distinctive exit so the block's reject
## path is observable; a clean run prints the SOURCE_DATE_EPOCH the block exported.
## The block's own conditionals are errexit-exempt, so no errexit toggle is needed.
run_pin() {
   local pin_value="$1" root
   root="$(mktemp --directory --tmpdir="${workdir}")"
   mkdir --parents -- "${root}/build_sources"
   printf '%s\n' "${pin_value}" > "${root}/build_sources/frozen-snapshot-timestamp"
   (
      # shellcheck disable=SC2317  # called by the sourced block on the reject path
      error() {
         printf 'PIN_REJECTED: %s\n' "$*"
         exit 3
      }
      dist_build_apt_freshness=frozen
      source_code_folder_dist="${root}"
      SOURCE_DATE_EPOCH=""
      # shellcheck disable=SC1090
      source <(printf '%s\n' "${block}")
      printf 'PIN_ACCEPTED: SOURCE_DATE_EPOCH=%s\n' "${SOURCE_DATE_EPOCH}"
   )
}

## A valid bare epoch must be ACCEPTED and become SOURCE_DATE_EPOCH.
out="$(run_pin 1787278985 2>&1)" && rc=0 || rc=$?
if [ "${rc}" -eq 0 ] && [[ "${out}" == *"PIN_ACCEPTED: SOURCE_DATE_EPOCH=1787278985"* ]]; then
   pass "bare Unix epoch pin is accepted and set as SOURCE_DATE_EPOCH"
else
   fail "epoch pin rejected (the inversion regression): rc=${rc} out=${out}"
fi

## The old snapshot-id format is NOT a valid epoch (consumers do 'date --date=@');
## it must be REJECTED as malformed.
out="$(run_pin 20260821T022305Z 2>&1)" && rc=0 || rc=$?
if [ "${rc}" -eq 3 ] && [[ "${out}" == *"PIN_REJECTED"*"Malformed snapshot pin"* ]]; then
   pass "a non-integer pin (snapshot-id) is rejected as malformed"
else
   fail "non-integer pin not rejected: rc=${rc} out=${out}"
fi

## Garbage is rejected too.
out="$(run_pin 'not-a-timestamp' 2>&1)" && rc=0 || rc=$?
if [ "${rc}" -eq 3 ]; then
   pass "a garbage pin is rejected as malformed"
else
   fail "garbage pin not rejected: rc=${rc} out=${out}"
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: frozen snapshot pin validation."
