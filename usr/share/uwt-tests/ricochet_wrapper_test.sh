#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## ricochet.anondist wrapper: ricochet has no unix-domain-socket support, so the
## wrapper must export TOR_CONTROL_HOST / TOR_CONTROL_PORT (otherwise ricochet
## would try to start its own Tor instance). The wrapper is source-able via the
## was_executed guard (same pattern as curl.anondist / dnf-3.anondist): sourced,
## it defines main() + exec_uwtwrapper but runs neither, so sourcing has no side
## effects on the caller's shell.
##
## Method: source the REAL ricochet.anondist in a subshell (was_executed false,
## so main is not auto-run), OVERRIDE exec_uwtwrapper so it records instead of
## exec'ing, then call main -- which sets the TOR_CONTROL_* exports and hands off
## to the override. The subshell confines main's strict-mode / LC_ALL=C so they
## never touch this harness, and a regressed guard (a bare exec) replaces only
## that subshell, so the value never appears and the assertion fails loudly.
##
## Targets the installed package by default; set UWT_REPO to test a checkout
## (then HELPER_SCRIPTS_PATH must point at a helper-scripts checkout so the
## wrapper can source check_runtime.bsh). A missing subject or helper library is
## a REQUIRED-dependency environment bug -> exit 1 (FATAL), never a skip.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v UWT_REPO ] || UWT_REPO=""
if [ -n "${UWT_REPO}" ]; then
   bin_dir="${UWT_REPO}/usr/bin"
else
   bin_dir='/usr/bin'
fi
ricochet="${bin_dir}/ricochet.anondist"

## ricochet.anondist sources check_runtime.bsh via ${HELPER_SCRIPTS_PATH:-}
## (set by dist-ai-tests-all's wire; unset -> installed /usr/libexec). Export it
## so the subshell source below resolves the same library.
[ -v HELPER_SCRIPTS_PATH ] || HELPER_SCRIPTS_PATH=""
export HELPER_SCRIPTS_PATH
check_runtime_bsh="${HELPER_SCRIPTS_PATH}/usr/libexec/helper-scripts/check_runtime.bsh"

if [ ! -r "${ricochet}" ]; then
   printf '%s\n' "FATAL: ricochet.anondist not readable at '${ricochet}'" >&2
   printf '%s\n' "set UWT_REPO to a uwt checkout, or install uwt" >&2
   exit 1
fi
if [ ! -r "${check_runtime_bsh}" ]; then
   printf '%s\n' "FATAL: check_runtime.bsh not readable at '${check_runtime_bsh}'" >&2
   printf '%s\n' "set HELPER_SCRIPTS_PATH to a helper-scripts checkout, or install helper-scripts" >&2
   exit 1
fi

pass=0
fail=0
check() {
   local label="$1" got="$2" want="$3"
   if [ "${got}" = "${want}" ]; then
      printf '%s\n' "PASS: ${label}"
      pass=$((pass + 1))
   else
      printf '%s\n' "FAIL: ${label} (got '${got}', want '${want}')"
      fail=$((fail + 1))
   fi
}

## Source in a subshell, override exec_uwtwrapper to emit the value main set, and
## run main. The literal __UNEXPORTED__ marks a missing export, distinct from an
## empty value. '|| ...' turns a source failure (or a regressed guard that execs
## away before main is reached) into a loud wrong value, not a crash.
host_got="$(
   # shellcheck disable=SC1090
   source "${ricochet}"
   # shellcheck disable=SC2317  # invoked indirectly by main
   exec_uwtwrapper() { printf '%s' "${TOR_CONTROL_HOST-__UNEXPORTED__}"; }
   main
)" || host_got="__SOURCE_FAILED__"
port_got="$(
   # shellcheck disable=SC1090
   source "${ricochet}"
   # shellcheck disable=SC2317  # invoked indirectly by main
   exec_uwtwrapper() { printf '%s' "${TOR_CONTROL_PORT-__UNEXPORTED__}"; }
   main
)" || port_got="__SOURCE_FAILED__"

check "ricochet exports TOR_CONTROL_HOST" "${host_got}" "127.0.0.1"
check "ricochet exports TOR_CONTROL_PORT" "${port_got}" "9151"

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "FAILED"
   exit 1
fi
printf '%s\n' "OK"
