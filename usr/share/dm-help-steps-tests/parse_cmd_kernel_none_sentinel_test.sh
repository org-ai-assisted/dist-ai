#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for derivative-maker help-steps/parse-cmd: the 'none' sentinel
## of --kernel / --headers / --initramfs must be coherent across repeated flags.
##
## THE BUG: '--kernel none --kernel linux-image-amd64' produced
## BUILD_KERNEL_PKGS="none linux-image-amd64" (the else-branch appended to the
## prior "none"), and build-steps.d/3500_install-packages only skips when the
## value is EXACTLY "none", so it then tried to 'apt-get install none ...' and
## failed the build. Fix: a real package clears a prior "none"; "none" stays the
## exclusive sentinel.
##
## Drives the REAL parse-cmd by SOURCING it (parse-cmd defines
## dist_build_one_parse_cmd but does not run it when sourced) and calling the real
## function in an exit-stubbed subshell -- no logic is reimplemented. Needs no
## root, no network, no build.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

if [ -n "${DERIVATIVE_MAKER_DIR:-}" ]; then
   dm_checkout="${DERIVATIVE_MAKER_DIR}"
else
   dm_checkout="${HOME}/derivative-maker"
fi
parse_cmd="${PARSE_CMD:-${dm_checkout}/help-steps/parse-cmd}"
if [ ! -r "${parse_cmd}" ]; then
   printf '%s\n' "FATAL: parse-cmd not readable at '${parse_cmd}' (set DERIVATIVE_MAKER_DIR or PARSE_CMD)." >&2
   exit 1
fi

pass() { printf '%s\n' "PASS: $*"; }
test_failures=0
fail() { printf '%s\n' "FAIL: $*" >&2; test_failures=$((test_failures + 1)); }

## Resolve BUILD_<x>_PKGS after driving the REAL arg parser with "$@". parse-cmd
## re-enables errexit at source time and calls 'exit'/'error' on mandatory-arg
## checks; both are neutralized INSIDE this subshell only, so the arg loop (which
## sets the variable) runs to completion and the value is read back. The subshell
## isolates the exit stub from this test's own control flow.
drive() {
   local var_name="$1"
   shift
   (
      # shellcheck disable=SC1090
      source "${parse_cmd}" >/dev/null 2>&1
      ## style-ok: allow-errexit-toggle -- neutralize parse-cmd's mandatory-arg
      ## 'exit'/'error' so the arg loop under test runs to completion in this probe
      set +o errexit
      set +o nounset
      set +o pipefail
      # shellcheck disable=SC2317  # invoked indirectly, from the sourced parse-cmd
      exit() { return "${1:-0}"; }
      # shellcheck disable=SC2317  # invoked indirectly, from the sourced parse-cmd
      error() { return 0; }
      unset "${var_name}"
      dist_build_one_parse_cmd "$@" >/dev/null 2>&1
      printf '%s' "${!var_name:-UNSET}"
   )
}

## $1 flag, $2 var name. Runs the four coherence cases for one option.
check_option() {
   local flag="$1" var="$2" out

   ## none then a real package -> the real package only (no literal 'none' token).
   out="$( drive "${var}" "${flag}" none "${flag}" real-pkg-a )"
   case " ${out} " in
      *" none "*)
         fail "${flag}: 'none' then a package left a literal 'none' in '${out}'"
         ;;
      *" real-pkg-a "*)
         pass "${flag}: a real package after 'none' clears the sentinel (-> '${out}')"
         ;;
      *)
         fail "${flag}: 'none' then a package gave unexpected '${out}'"
         ;;
   esac

   ## a real package then none -> none stays exclusive.
   out="$( drive "${var}" "${flag}" real-pkg-a "${flag}" none )"
   if [ "${out}" = "none" ]; then
      pass "${flag}: 'none' after a package overrides to the exclusive sentinel"
   else
      fail "${flag}: 'none' after a package gave '${out}', expected 'none'"
   fi

   ## two real packages still accumulate.
   out="$( drive "${var}" "${flag}" real-pkg-a "${flag}" real-pkg-b )"
   if [[ "${out}" == *"real-pkg-a"* ]] && [[ "${out}" == *"real-pkg-b"* ]]; then
      pass "${flag}: two real packages accumulate (-> '${out}')"
   else
      fail "${flag}: two real packages did not accumulate: '${out}'"
   fi
}

check_option --kernel    BUILD_KERNEL_PKGS
check_option --headers   BUILD_HEADER_PKGS
check_option --initramfs BUILD_INITRAMFS_PKGS

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: --kernel/--headers/--initramfs none sentinel is coherent."
