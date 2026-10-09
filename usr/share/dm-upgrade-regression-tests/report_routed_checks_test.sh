#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Assert dm-upgrade-regression DISCLOSES routed-away checks so a skipped check never
## reads as a pass: write_report records "routed_checks": [8] in report.json (and []
## when nothing is routed). The fast-path ALWAYS routes check 8 to the authoritative
## GUI-OCR gate, so a report consumer must be able to tell check 8 did not run here.
## Drives the REAL functions (sed-extracted from the script, no copy/drift). No VM,
## no network. Caught in ai-review: a PASS + report.json that omit the skip overstate
## coverage.
##
## SC2034: caller globals are consumed by the eval-EXTRACTED write_report /
## routed_checks_sorted (invisible to shellcheck's static view), not unused.
# shellcheck disable=SC2034

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"
bin="${script_dir}/../../bin/dm-upgrade-regression"
[ -r "${bin}" ] || { printf '%s\n' "ERROR: dm-upgrade-regression not found: ${bin}" >&2; exit 1; }

tmp="$(mktemp --directory)"
# shellcheck disable=SC2317  ## runs via the EXIT trap, not a direct call
cleanup() { safe-rm --recursive --force -- "${tmp}"; }
trap cleanup EXIT

## Extract the REAL functions (closing brace at column 0, fragment style) -- no copy.
extract_fn() { sed -n "/^$1() {/,/^}/p" "${bin}"; }
eval "$(extract_fn json_escape)"
eval "$(extract_fn routed_checks_sorted)"
eval "$(extract_fn write_report)"

## Caller globals write_report consumes.
# shellcheck disable=SC2034
me='routed-test'
# shellcheck disable=SC2034
vm='v'
# shellcheck disable=SC2034
repository='r'
# shellcheck disable=SC2034
persist_mode='m'
# shellcheck disable=SC2034
blocking='false'
# shellcheck disable=SC2034
snapshot_name='s'
# shellcheck disable=SC2034
status='pass'
# shellcheck disable=SC2034
REASON=''
report_dir="${tmp}"
declare -A RELEASE_CHECK_SKIP_REASON=()

pass=0
fail=0
assert() {
   if [ "$2" = "$3" ]; then
      printf '%s\n' "PASS: ${1}"; pass=$(( pass + 1 ))
   else
      printf '%s\n' "FAIL: ${1}" "  got:  ${2}" "  want: ${3}" >&2; fail=$(( fail + 1 ))
   fi
}
has_line() { grep --quiet --fixed-strings -- "$2" "$1" && printf '%s' "yes" || printf '%s' "no"; }

## Default: nothing routed.
assert 'routed_checks_sorted empty by default' "$(routed_checks_sorted | tr '\n' ' ')" ''

## Check 8 routed -> report.json records it as a JSON int array (not a silent pass).
RELEASE_CHECK_SKIP_REASON[8]='routed to GUI-OCR'
write_report >/dev/null
assert 'routed_checks_sorted lists 8'          "$(routed_checks_sorted | tr '\n' ' ')" '8 '
assert 'report.json records routed_checks [8]' "$(has_line "${tmp}/report.json" '"routed_checks": [8],')" 'yes'

## Nothing routed -> empty array (canary: pre-fix report.json has no routed_checks key).
RELEASE_CHECK_SKIP_REASON=()
write_report >/dev/null
assert 'report.json routed_checks [] when none routed' "$(has_line "${tmp}/report.json" '"routed_checks": [],')" 'yes'

printf '%s\n' "" "$(basename -- "$0"): ${pass} pass, ${fail} fail"
[ "${fail}" -eq 0 ] || exit 1
exit 0
