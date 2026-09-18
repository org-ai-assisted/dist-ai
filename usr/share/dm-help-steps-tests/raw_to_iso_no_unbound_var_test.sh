#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## dm-raw-to-iso runs under 'set -o nounset', so a variable referenced after its
## assignment was removed aborts the whole ISO build at runtime -- a wasted
## ~40-minute CI build for a defect a static check sees instantly. The dm tree
## disables SC2154 ('referenced but not assigned') project-wide in .shellcheckrc,
## because most scripts source help-steps/{colors,variables} whose vars
## shellcheck cannot follow. dm-raw-to-iso is SELF-CONTAINED (args + the one
## sourced build-step-helpers.bsh), so SC2154 has no false positives there and
## its ONE true positive (a dropped assignment) is exactly this class of bug.
##
## Run the REAL shellcheck WITHOUT the dm rcfile (so SC2154 is active) and assert
## zero SC2154 findings. Only SC2154 is inspected; the rc-disabled SC1090/1091/
## SC2034 that fire without the rcfile are irrelevant here and ignored.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

if ! test -r /usr/libexec/helper-scripts/has.bsh ; then
   printf '%s\n' "FATAL: helper-scripts has.bsh is not installed (/usr/libexec/helper-scripts/has.bsh)" >&2
   exit 1
fi
# shellcheck source=../../../helper-scripts/usr/libexec/helper-scripts/has.bsh
source /usr/libexec/helper-scripts/has.bsh

if [ -n "${DERIVATIVE_MAKER_DIR:-}" ]; then
   dm_checkout="${DERIVATIVE_MAKER_DIR}"
else
   dm_checkout="${HOME}/derivative-maker"
fi

target="${dm_checkout}/help-steps/dm-raw-to-iso"
if [ ! -r "${target}" ]; then
   printf '%s\n' "FAIL: cannot read ${target}" >&2
   exit 1
fi

## shellcheck is a required dependency of this gate; its absence is an
## environment bug, not an optional skip.
if ! has shellcheck ; then
   printf '%s\n' "FATAL: shellcheck not on PATH (apt-get install shellcheck)" >&2
   exit 1
fi

pass_count=0
fail_count=0
pass() {
   pass_count=$(( pass_count + 1 ))
   printf '%s\n' "PASS: $*"
}
fail() {
   fail_count=$(( fail_count + 1 ))
   printf '%s\n' "FAIL: $*" >&2
}

## Count SC2154 findings for a file. No --rcfile: the dm rc disables SC2154, and
## the point is to run it. --external-sources + --source-path lets the
## '# shellcheck source=' directive resolve build-step-helpers.bsh so its
## definitions are known (nothing there defines the checked vars anyway).
count_sc2154() {
   local file src_dir
   file="$1"
   src_dir="$( dirname -- "${file}" )"
   shellcheck --external-sources --source-path="${src_dir}" --format=gcc -- "${file}" 2>/dev/null \
      | grep --count '\[SC2154\]' || true
}

## --- the real assertion --------------------------------------------------------
sc2154="$( count_sc2154 "${target}" )"
if [ "${sc2154}" = "0" ]; then
   pass "dm-raw-to-iso has no SC2154 (referenced-but-not-assigned) variables"
else
   fail "dm-raw-to-iso has ${sc2154} SC2154 finding(s); run: shellcheck --format=gcc -- ${target}"
fi

## --- CANARY: the check detects a dropped assignment ----------------------------
## A copy that references an unassigned variable MUST raise SC2154, or the check
## above proves nothing.
canary_dir="$( mktemp -d )"
# shellcheck disable=SC2317  # reached only via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${canary_dir}"; }
trap cleanup EXIT

canary="${canary_dir}/canary"
{
   printf '%s\n' '#!/bin/bash'
   printf '%s\n' 'set -o nounset'
   printf '%s\n' 'printf "%s\n" "${dropped_assignment_var}"'
} > "${canary}"
canary_sc2154="$( count_sc2154 "${canary}" )"
if [ "${canary_sc2154}" -ge 1 ]; then
   pass 'canary: an unassigned variable raises SC2154 (the check has teeth)'
else
   fail 'canary broken: an unassigned variable did not raise SC2154'
fi

summary_line="===== dm-raw-to-iso unbound-var: ${pass_count} pass, ${fail_count} fail ====="
printf '%s\n' "${summary_line}"
if [ "${fail_count}" -gt 0 ]; then
   exit 1
fi
exit 0
