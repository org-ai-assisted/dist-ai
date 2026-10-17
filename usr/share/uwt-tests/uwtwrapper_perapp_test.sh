#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## uwtwrapper per-application dispatch contract (compute_dispatch).
##
## Time Privacy (faketime) and stream isolation (torsocks) share ONE
## global/per-application contract; only the default of the *_global var differs
## (uwtwrapper_global on, timeprivacy_global off):
##   global="0"  -> feature OFF for every app; the per-app map is IGNORED (global
##                  disable wins; no per-app entry can re-enable).
##   global!="0" -> feature ON; a per-app entry of "0" disables that ONE app
##                  (a per-app "1" is redundant with the global default).
##
## The maps are config-file-only (not env-injectable, by security design), so
## this drives the REAL uwtwrapper by SOURCING it (sourceable: pure functions +
## was_executed-guarded main) via uwtwrapper_perapp_probe.sh and calling
## compute_dispatch with the maps set. The GLOBAL env paths (global on/off,
## UWT_DEV_PASSTHROUGH, faketime ordering) are covered by
## uwtwrapper_dispatch_test.sh; this suite owns the per-app map precedence.
##
## A missing subject / check_runtime.bsh is a REQUIRED-dependency environment
## bug -> exit 1 (FATAL), never a skip.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

tool_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
probe="${tool_dir}/uwtwrapper_perapp_probe.sh"

[ -v UWT_REPO ] || UWT_REPO=""
if [ -n "${UWT_REPO}" ]; then
   subject="${UWT_REPO}/usr/libexec/uwt/uwtwrapper"
else
   subject='/usr/libexec/uwt/uwtwrapper'
fi

[ -v HELPER_SCRIPTS_PATH ] || HELPER_SCRIPTS_PATH=""
check_runtime="${HELPER_SCRIPTS_PATH}/usr/libexec/helper-scripts/check_runtime.bsh"

if [ ! -r "${subject}" ]; then
   printf '%s\n' "FATAL: subject not readable at '${subject}'" >&2
   printf '%s\n' "set UWT_REPO to a uwt checkout, or install uwt" >&2
   exit 1
fi
if [ ! -r "${check_runtime}" ]; then
   printf '%s\n' "FATAL: check_runtime.bsh not readable at '${check_runtime}'" >&2
   printf '%s\n' "set HELPER_SCRIPTS_PATH to a helper-scripts checkout, or install helper-scripts" >&2
   exit 1
fi
if [ ! -x "${probe}" ]; then
   printf '%s\n' "FATAL: test support probe missing or not executable: '${probe}'" >&2
   exit 1
fi

pass=0
fail=0
check() {
   local label got want
   label="$1"
   got="$2"
   want="$3"
   if [ "${got}" = "${want}" ]; then
      printf '%s\n' "PASS: ${label}"
      pass=$((pass + 1))
   else
      printf '%s\n' "FAIL: ${label} (got '${got}', want '${want}')"
      fail=$((fail + 1))
   fi
}

## Run compute_dispatch for one scenario; populate the globals fake_decision
## (yes = faketime applied) and torsocks_decision (yes = stream isolation on).
## $1 timeprivacy_global, $2 uwtwrapper_global, $3 TP_ENTRY, $4 UW_ENTRY
## ('unset' = key absent). PARENT is a fixed representative app path.
fake_decision=no
torsocks_decision=no
run_dispatch() {
   local tp_global="$1" uw_global="$2" tp_entry="$3" uw_entry="$4"
   local out
   out="$(
      env \
         SUBJECT="${subject}" \
         HELPER_SCRIPTS_PATH="${HELPER_SCRIPTS_PATH}" \
         PARENT="/usr/bin/curl" \
         timeprivacy_global="${tp_global}" \
         uwtwrapper_global="${uw_global}" \
         TP_ENTRY="${tp_entry}" \
         UW_ENTRY="${uw_entry}" \
         "${probe}"
   )"
   if [ "${out}" = "FAKE=faketime TORSOCKS=torsocks" ]; then
      fake_decision=yes; torsocks_decision=yes
   elif [ "${out}" = "FAKE=faketime TORSOCKS=" ]; then
      fake_decision=yes; torsocks_decision=no
   elif [ "${out}" = "FAKE= TORSOCKS=torsocks" ]; then
      fake_decision=no; torsocks_decision=yes
   elif [ "${out}" = "FAKE= TORSOCKS=" ]; then
      fake_decision=no; torsocks_decision=no
   else
      printf '%s\n' "FATAL: unexpected probe output '${out}'" >&2
      exit 1
   fi
}

## --- Time Privacy: global authoritative, per-app may only disable. ---

## global=0 is absolute: a per-app "1" must NOT re-enable (the headline fix --
## old code let timeprivacy[app]=1 force faketime on despite the global off).
run_dispatch 0 1 1 unset
check "tp global=0 + per-app=1 -> faketime OFF (global disable wins)" "${fake_decision}" "no"

## per-app "0" disables under global on (old code ignored per-app=0 for
## timeprivacy and stayed on via the global).
run_dispatch 1 1 0 unset
check "tp global=1 + per-app=0 -> faketime OFF (per-app disable)" "${fake_decision}" "no"

## global on, no per-app entry -> on (kept behavior).
run_dispatch 1 1 unset unset
check "tp global=1 + no entry -> faketime ON" "${fake_decision}" "yes"

## global off, no per-app entry -> off (kept behavior, the default).
run_dispatch 0 1 unset unset
check "tp global=0 + no entry -> faketime OFF" "${fake_decision}" "no"

## per-app "1" under global on is redundant -> still on.
run_dispatch 1 1 1 unset
check "tp global=1 + per-app=1 -> faketime ON (redundant)" "${fake_decision}" "yes"

## --- uwt stream isolation: same contract. ---

## per-app "0" disables under global on.
run_dispatch 0 1 unset 0
check "uwt global=1 + per-app=0 -> isolation OFF (per-app disable)" "${torsocks_decision}" "no"

## global=0 is absolute: a per-app "1" must NOT re-enable.
run_dispatch 0 0 unset 1
check "uwt global=0 + per-app=1 -> isolation OFF (global disable wins)" "${torsocks_decision}" "no"

## global on, no per-app entry -> on.
run_dispatch 0 1 unset unset
check "uwt global=1 + no entry -> isolation ON" "${torsocks_decision}" "yes"

## per-app "1" under global on is redundant -> still on.
run_dispatch 0 1 unset 1
check "uwt global=1 + per-app=1 -> isolation ON (redundant)" "${torsocks_decision}" "yes"

## --- Consistency: both features obey global=0 absolutely and in lockstep. ---
run_dispatch 0 0 1 1
check "both global=0 + per-app=1: faketime OFF" "${fake_decision}" "no"
check "both global=0 + per-app=1: isolation OFF" "${torsocks_decision}" "no"

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "FAILED"
   exit 1
fi
printf '%s\n' "OK"
