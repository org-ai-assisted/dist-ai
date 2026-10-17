#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## style-ok: no-strict -- deliberately NON-strict: a sourced-driver probe that
## must not impose its own strict mode on the real uwtwrapper (SUBJECT) it
## drives. Sources the sourceable uwtwrapper (resolves check_runtime.bsh via
## HELPER_SCRIPTS_PATH); was_executed is false when sourced so main does NOT
## auto-run. Exercises the per-application dispatch contract (compute_dispatch),
## which reads the timeprivacy[]/uwtwrapper[] maps. Those maps are populated only
## from the hardcoded /etc/uwt.d config (intentionally NOT env-injectable, so a
## torification wrapper cannot be pointed at rogue config), so driving main under
## env cannot reach them -- sourcing + calling compute_dispatch directly can.
##
## The scenario arrives as env scalars:
##   PARENT               -> uwtwrapper_parent (the app path keyed into the maps)
##   timeprivacy_global   -> global time-privacy toggle
##   uwtwrapper_global    -> global uwt toggle
##   TP_ENTRY / UW_ENTRY  -> per-app map value for PARENT; literal 'unset' leaves
##                           the key absent (the normal case)
## A time_privacy function STUB replaces the real binary, so no faketime offset
## file or real time_privacy is touched. Prints exactly one line:
##   FAKE=<fake_time> TORSOCKS=<torsocks_bin>
## revealing both decisions (faketime on/off, stream isolation on/off).

# shellcheck disable=SC1090,SC1091,SC2154  # SUBJECT: the uwtwrapper path, from the env
source "${SUBJECT}"

## Declare the associative maps exactly as uwtwrapper's own preparation() does.
preparation

## uwtwrapper_parent / timeprivacy[] / uwtwrapper[] are consumed by
## compute_dispatch in the sourced SUBJECT, which shellcheck cannot follow.
# shellcheck disable=SC2034
uwtwrapper_parent="${PARENT}"
torsocks_bin="torsocks"

if [ "${TP_ENTRY}" != "unset" ]; then
  # shellcheck disable=SC2034
  timeprivacy["${PARENT}"]="${TP_ENTRY}"
fi
if [ "${UW_ENTRY}" != "unset" ]; then
  # shellcheck disable=SC2034
  uwtwrapper["${PARENT}"]="${UW_ENTRY}"
fi

## time_privacy stub: compute_dispatch captures its stdout in privacy_time.
time_privacy() {
  printf '%s\n' "-15days"
}

compute_dispatch

printf '%s\n' "FAKE=${fake_time} TORSOCKS=${torsocks_bin}"
