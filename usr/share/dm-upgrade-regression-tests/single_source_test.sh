#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Guards the SINGLE source of truth shared by the install gate (dm-calamares-install) and
## the R6 upgrade gate (dm-upgrade-regression): the numbered release-critical checks
## (release-checks.bsh). Asserts: dm-calamares-install sources the check table + runs the
## battery (not an inline copy); no literal `run_check N '<cmd>'` battery lines remain; and
## the shared table is non-vacuous + numbered/polarised as expected. No VM, no network.
##
## SC2154: RELEASE_CHECK_CMD et al. are read from the sourced release-checks.bsh.
# shellcheck disable=SC2154

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"
cal="${script_dir}/../../bin/dm-calamares-install"
rc_lib="${script_dir}/../dm-smbios-reader-boot-tests/release-checks.bsh"
for f in "${cal}" "${rc_lib}"; do
   [ -r "${f}" ] || { printf 'ERROR: required dist-ai file missing: %s\n' "${f}" >&2; exit 1; }
done

pass=0
fail=0
ok()  { printf 'PASS: %s\n' "$1"; pass=$(( pass + 1 )); }
bad() { printf 'FAIL: %s\n' "$1" >&2; fail=$(( fail + 1 )); }

## --- A. dm-calamares-install uses the single source, not an inline copy ---------
## grep for the LITERAL source line in dm-calamares-install (no expansion wanted).
# shellcheck disable=SC2016
if grep --quiet 'source "${release_checks_lib}"' "${cal}"; then
   ok 'dm-calamares-install sources release-checks.bsh'
else
   bad 'dm-calamares-install does NOT source release-checks.bsh'
fi
if grep --quiet 'run_release_check_battery' "${cal}"; then
   ok 'dm-calamares-install runs the shared battery driver'
else
   bad 'dm-calamares-install does NOT call run_release_check_battery'
fi
## No literal numbered run_check battery lines may remain (comments excluded): the
## commands now live only in the table.
literals="$(grep -nE 'run_check [0-9]' "${cal}" | grep -vE ':[[:space:]]*##' || true)"
if [ -z "${literals}" ]; then
   ok 'no inline run_check N literals remain (table is the only source)'
else
   bad "inline run_check literals still present: ${literals}"
fi

## --- B. the shared table is non-vacuous + numbered as expected ------------------
# shellcheck source=../dm-smbios-reader-boot-tests/release-checks.bsh
source "${rc_lib}"
want_nums='1 2 3 4 5 6 8'
got_nums="$(printf '%s\n' "${!RELEASE_CHECK_CMD[@]}" | sort -n | tr '\n' ' ')"
if [ "${got_nums% }" = "${want_nums}" ]; then
   ok "table defines exactly checks ${want_nums}"
else
   bad "table numbers [${got_nums% }] != expected [${want_nums}]"
fi
## Spot the load-bearing polarity/intent in the single source (the python contract
## test asserts the full set; this is the bash-side non-vacuous guard).
if [[ "${RELEASE_CHECK_CMD[1]:-}" == '!'* && "${RELEASE_CHECK_CMD[1]:-}" == *boot-role=sysmaint* ]]; then
   ok 'check 1 negated boot-role'
else
   bad "check 1 wrong: ${RELEASE_CHECK_CMD[1]:-<unset>}"
fi
if [[ "${RELEASE_CHECK_CMD[2]:-}" != '!'* && "${RELEASE_CHECK_CMD[2]:-}" == *boot-role=sysmaint* ]]; then
   ok 'check 2 non-negated boot-role'
else
   bad "check 2 wrong: ${RELEASE_CHECK_CMD[2]:-<unset>}"
fi
if [[ "${RELEASE_CHECK_CMD[3]:-}" == *upgrade-nonroot* ]]; then
   ok 'check 3 upgrade-nonroot'
else
   bad "check 3 wrong: ${RELEASE_CHECK_CMD[3]:-<unset>}"
fi
if [[ "${RELEASE_CHECK_CMD[8]:-}" == *systemcheck* ]]; then
   ok 'check 8 systemcheck'
else
   bad "check 8 wrong: ${RELEASE_CHECK_CMD[8]:-<unset>}"
fi
## --leak-tests (aka --ip-test) is a Tor/Whonix connectivity check (curl
## check.torproject.org through a SocksPort); every caller of this table is
## Kicksecure (Calamares install + upgrade gate), which has no Tor, so it must
## never appear here -- the Whonix leak battery is dm-whonix-pair's own lane.
if [[ "${RELEASE_CHECK_CMD[8]:-}" != *leak* && "${RELEASE_CHECK_CMD[8]:-}" != *ip-test* ]]; then
   ok 'check 8 carries no Whonix leak/ip test'
else
   bad "check 8 runs a Whonix leak test on a Kicksecure table: ${RELEASE_CHECK_CMD[8]:-<unset>}"
fi

printf '\n%s: %s pass, %s fail\n' "$(basename -- "$0")" "${pass}" "${fail}"
[ "${fail}" -eq 0 ] || exit 1
exit 0
