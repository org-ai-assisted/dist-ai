#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## get_kernel_param.bsh: parses a named parameter out of the kernel command
## line. read_kernel_cmdline reads /proc/cmdline, falling back to the NUL-
## separated /proc/1/cmdline when /proc/cmdline is unreadable. This suite
## sources the real lib and drives both source paths via the
## GET_KERNEL_PARAM_PROC_CMDLINE / GET_KERNEL_PARAM_PROC_1_CMDLINE seams.
## Pure logic: no root, no device, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v HELPER_SCRIPTS_REPO ] || HELPER_SCRIPTS_REPO=""

if [ -n "${HELPER_SCRIPTS_REPO}" ]; then
   lib_path="${HELPER_SCRIPTS_REPO}/usr/libexec/helper-scripts/get_kernel_param.bsh"
else
   lib_path='/usr/libexec/helper-scripts/get_kernel_param.bsh'
fi

if [ ! -r "${lib_path}" ]; then
   printf '%s\n' "FATAL: get_kernel_param.bsh not readable at '${lib_path}'" >&2
   printf '%s\n' "set HELPER_SCRIPTS_REPO to a checkout, or install helper-scripts" >&2
   exit 1
fi

# shellcheck disable=SC1090,SC1091
source "${lib_path}"

if [ ! "$(type -t get_kernel_param)" = 'function' ]; then
   printf '%s\n' "FATAL: sourcing '${lib_path}' defined no 'get_kernel_param' function" >&2
   exit 1
fi

pass_count=0
fail_count=0
check_eq() {
   ## check_eq <label> <expected> <actual>
   if [ "$2" = "$3" ]; then
      pass_count=$(( pass_count + 1 )); printf '%s\n' "PASS: $1"
   else
      fail_count=$(( fail_count + 1 ))
      printf '%s\n' "FAIL: $1"
      printf '%s\n' "  expected: $(printf '%q' "$2")"
      printf '%s\n' "  actual:   $(printf '%q' "$3")"
   fi
}

workdir="$(mktemp --directory)"
cleanup() { safe-rm --recursive --force -- "${workdir}" || true; }
if ! type -P safe-rm >/dev/null 2>&1; then
   printf '%s\n' "FATAL: safe-rm not on PATH" >&2
   exit 1
fi
trap cleanup EXIT

## A fresh lookup: clear the per-shell cache so each call re-reads the source.
gkp() {
   local rc=0 out
   ## Cache global consumed by the sourced get_kernel_param.bsh.
   # shellcheck disable=SC2034
   get_kernel_param_kernel_cmdline=""
   out="$(get_kernel_param "$@")" || rc=$?
   printf '%s' "${out}"
   return "${rc}"
}

## --- normal /proc/cmdline path (trailing newline, as the kernel provides) ----
cmdline_fix="${workdir}/cmdline"
printf '%s\n' 'BOOT_IMAGE=/vmlinuz foo=bar baz quiet' > "${cmdline_fix}"
export GET_KERNEL_PARAM_PROC_CMDLINE="${cmdline_fix}"

check_eq "cmdline: value parameter returns its value" \
   "bar" "$(gkp foo)"
check_eq "cmdline: bare parameter is PRESENT" \
   "GKP_PRESENT" "$(gkp baz)"
check_eq "cmdline: bare parameter 'quiet' is PRESENT" \
   "GKP_PRESENT" "$(gkp quiet)"
check_eq "cmdline: absent parameter is ABSENT" \
   "GKP_ABSENT" "$(gkp nosuchparam)"

## --- PID 1 fallback: /proc/cmdline UNREADABLE -> /proc/1/cmdline ------------
## REGRESSION: /proc/1/cmdline is NUL-separated and ends with a NUL, NOT a
## newline. The pre-fix code used 'read ... < <(tr ...)', and 'read' returns
## FAILURE at EOF-without-newline even though it assigned the text -- so the
## FIRST lookup wrongly returned nothing (only a second, cache-warmed lookup in
## the same shell succeeded). The fix captures via command substitution, keyed
## on 'tr's own exit status, so the very first lookup succeeds.
export GET_KERNEL_PARAM_PROC_CMDLINE="${workdir}/does-not-exist-cmdline"
pid1_fix="${workdir}/pid1-cmdline"
## NUL-separated, trailing NUL, no newline -- exactly like /proc/1/cmdline.
printf '%s\0' init mode=live persistence > "${pid1_fix}"
export GET_KERNEL_PARAM_PROC_1_CMDLINE="${pid1_fix}"

first_rc=0
first_out="$(gkp mode)" || first_rc=$?
check_eq "pid1 fallback: FIRST lookup returns the value (regression)" \
   "live" "${first_out}"
check_eq "pid1 fallback: FIRST lookup exits 0 (regression)" \
   "0" "${first_rc}"
check_eq "pid1 fallback: bare parameter PRESENT on first lookup" \
   "GKP_PRESENT" "$(gkp persistence)"
check_eq "pid1 fallback: absent parameter ABSENT" \
   "GKP_ABSENT" "$(gkp nope)"

## --- neither source readable -> lookup fails (rc 1), no value ----------------
export GET_KERNEL_PARAM_PROC_CMDLINE="${workdir}/does-not-exist-cmdline"
export GET_KERNEL_PARAM_PROC_1_CMDLINE="${workdir}/does-not-exist-pid1"
none_rc=0
none_out="$(gkp foo)" || none_rc=$?
check_eq "no readable source: lookup returns nonzero" "1" "${none_rc}"
check_eq "no readable source: no value printed" "" "${none_out}"

printf '%s\n' ""
printf '%s\n' "===== get_kernel_param: ${pass_count} pass, ${fail_count} fail ====="
[ "${fail_count}" -eq 0 ]
