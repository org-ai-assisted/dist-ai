#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Pins dm-calamares-install's write_pass_roster: on a fully-passing run it records the
## release-critical check roster to ${check_log} so the PUBLISHED result surfaces which
## authoritative checks ran + passed -- check 8 (systemcheck) above all. Regression target: a
## green run previously preserved NO per-check evidence (the record kept only a failure tail), so
## systemcheck's PASS was invisible on the results page.
##
## Drives the REAL function (sourced define-only) against the REAL shared check table
## (release-checks.bsh, sourced by the subject). No VM, no root.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
subject=""
for candidate in "${DM_CALAMARES_INSTALL:-}" \
   "${test_dir}/../../bin/dm-calamares-install" \
   "/usr/bin/dm-calamares-install"; do
   [ -n "${candidate}" ] || continue
   if [ -x "${candidate}" ]; then
      subject="$(readlink --canonicalize -- "${candidate}")"
      break
   fi
done
[ -n "${subject}" ] || { printf '%s\n' "FATAL: dm-calamares-install not found" >&2; exit 1; }

work="$(mktemp --directory)"
# shellcheck disable=SC2317  ## runs via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${work}"; }
trap cleanup EXIT

# shellcheck disable=SC1090
source "${subject}"

pass=0; fail=0
check() { if [ "$2" -eq 0 ]; then pass=$(( pass + 1 )); printf '%s\n' "PASS: $1"; else fail=$(( fail + 1 )); printf '%s\n' "FAIL: $1"; fi; }
has() { case "$2" in *"$1"*) return 0 ;; *) return 1 ;; esac }

## --- a non-empty check_log gets the full roster, incl. check 8 systemcheck --------------------
check_log="${work}/roster"
write_pass_roster
got=0; [ -s "${check_log}" ] || got=1
check "roster: a non-empty check_log is written" "${got}"

roster="$(cat -- "${check_log}")"
got=0; has 'all PASS' "${roster}" || got=1
check "roster: states the checks all passed" "${got}"

## check 8 is the authoritative systemcheck -- it MUST be named with its real command.
got=0; { has 'check 8' "${roster}" && has 'systemcheck' "${roster}"; } || got=1
check "roster: check 8 systemcheck is surfaced by name" "${got}"

## every check in the shared order is present (no silent gap).
missing=0
## RELEASE_CHECK_ORDER comes from the sourced release-checks.bsh, not this file.
# shellcheck disable=SC2154
for num in "${RELEASE_CHECK_ORDER[@]}"; do
   has "check ${num} " "${roster}" || missing=1
done
check "roster: every check in RELEASE_CHECK_ORDER is listed" "${missing}"

## --- no check_log -> silent no-op, success -------------------------------------------------
check_log=""
rc=0; write_pass_roster || rc=1
check "roster: empty check_log is a no-op success" "${rc}"

printf '%s\n' "" "$(basename -- "$0"): ${pass} pass, ${fail} fail"
[ "${fail}" -eq 0 ] || exit 1
exit 0
