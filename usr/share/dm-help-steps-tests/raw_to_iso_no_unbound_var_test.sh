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
## Run the REAL shellcheck with --norc (so SC2154 is active) and assert zero
## SC2154 findings. --norc is REQUIRED, not merely omitting --rcfile: shellcheck
## discovers a .shellcheckrc by walking UP from the target file's own directory,
## so on the real dm tree it still loads help-steps/../.shellcheckrc and disables
## SC2154 -- which would make this gate a silent no-op. Only SC2154 is inspected;
## the SC1090/1091/SC2034 that fire without the rc are irrelevant here.

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
if [ ! -f "${target}" ] || [ ! -r "${target}" ]; then
   printf '%s\n' "FAIL: not a readable regular file: ${target}" >&2
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

## Print the SC2154 count for a file, or 'ERROR' if shellcheck could not fully
## analyze it -- a bare count of 0 must not be read as "clean" when the analysis
## never ran. --norc (see the header) makes SC2154 active; --external-sources +
## --source-path resolves the '# shellcheck source=' build-step-helpers.bsh
## (nothing there defines the checked vars). rc>=2 means the file could not be
## processed (unreadable, a directory); a gcc 'error:' line means a parse abort
## stopped analysis before the unassigned-variable pass -- either way the count
## is untrustworthy. shellcheck exits 1 on ordinary findings, so capture its
## status via '|| rc=$?' rather than letting errexit abort on it.
count_sc2154() {
   local file src_dir output rc
   file="$1"
   src_dir="$( dirname -- "${file}" )"
   rc=0
   output="$( shellcheck --norc --external-sources --source-path="${src_dir}" --format=gcc -- "${file}" 2>/dev/null )" || rc=$?
   if [ "${rc}" -ge 2 ]; then
      printf '%s\n' "ERROR"
      return 0
   fi
   case "${output}" in
      *": error:"*)
         printf '%s\n' "ERROR"
         return 0
         ;;
   esac
   printf '%s\n' "${output}" | grep --count '\[SC2154\]' || true
}

## --- the real assertion --------------------------------------------------------
sc2154="$( count_sc2154 "${target}" )"
if [ "${sc2154}" = "ERROR" ]; then
   fail "shellcheck could not fully analyze ${target} (unreadable or parse error); cannot certify it SC2154-clean"
elif [ "${sc2154}" = "0" ]; then
   pass "dm-raw-to-iso has no SC2154 (referenced-but-not-assigned) variables"
else
   fail "dm-raw-to-iso has ${sc2154} SC2154 finding(s); run: shellcheck --norc --format=gcc -- ${target}"
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
if [ "${canary_sc2154}" = "ERROR" ]; then
   fail 'canary broken: the unbound-var canary did not analyze cleanly'
elif [ "${canary_sc2154}" -ge 1 ]; then
   pass 'canary: an unassigned variable raises SC2154 (the check has teeth)'
else
   fail 'canary broken: an unassigned variable did not raise SC2154'
fi

## --- CANARY 2: an unanalyzable file yields ERROR, never a false 0 --------------
## A file shellcheck cannot fully parse emits no SC2154 line; without the
## parse-error guard it would read as clean. The unbound '${dropped...}' below is
## masked by the unterminated quote, so a 0 count here would be a false pass.
badfile="${canary_dir}/parseerr"
{
   printf '%s\n' '#!/bin/bash'
   printf '%s\n' 'set -o nounset'
   printf '%s\n' 'echo "unterminated'
   printf '%s\n' 'printf "%s\n" "${dropped_assignment_var}"'
} > "${badfile}"
if [ "$( count_sc2154 "${badfile}" )" = "ERROR" ]; then
   pass 'canary: an unparseable file yields ERROR, not a false 0'
else
   fail 'canary broken: an unparseable file did not yield ERROR'
fi

summary_line="===== dm-raw-to-iso unbound-var: ${pass_count} pass, ${fail_count} fail ====="
printf '%s\n' "${summary_line}"
if [ "${fail_count}" -gt 0 ]; then
   exit 1
fi
exit 0
