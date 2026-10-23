#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## vm-config-dist ships a vboxadd.service.d drop-in that makes the GA-generated
## vboxadd.service (Type=oneshot, Restart=no, TimeoutSec=5min) SELF-HEAL: under heavy
## host-CPU contention a single-vCPU hardened boot can exceed the timeout and fail with
## no retry, leaving the Guest Additions wedged (run level 0, no dynamic resize).
## Restart=on-failure + RestartSec re-attempt it; a StartLimit bounds the retries.
##
## This is the CHEAP static guard against the realistic regression -- a silent revert to
## Restart=no, or a typo -- with no systemd runner. The runtime behaviour (a oneshot with
## Restart=on-failure actually restarts on failure) is verified separately on systemd 257.
##
## No root, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v VM_CONFIG_DIST_REPO ] || VM_CONFIG_DIST_REPO=""

rel="usr/lib/systemd/system/vboxadd.service.d/30_vm-config-dist.conf"
if [ -n "${VM_CONFIG_DIST_REPO}" ]; then
   subject="${VM_CONFIG_DIST_REPO}/${rel}"
else
   subject="/${rel}"
fi

if [ ! -r "${subject}" ]; then
   printf '%s\n' "FATAL: vboxadd drop-in not found at '${subject}'" >&2
   printf '%s\n' "set VM_CONFIG_DIST_REPO to a checkout, or install the package" >&2
   exit 1
fi

pass_count=0
fail_count=0

## assert <description> <grep-args...>: PASS iff the grep MATCHES. Run in an if-condition so a
## no-match (the RED case) does not trip errexit -- a guard that aborted on a revert instead of
## FAILING would be a false green.
assert() {
   local desc="$1"
   shift
   if grep "$@" -- "${subject}"; then
      printf '%s\n' "PASS: ${desc}"
      pass_count=$(( pass_count + 1 ))
   else
      printf '%s\n' "FAIL: ${desc}"
      fail_count=$(( fail_count + 1 ))
   fi
}

## refute <description> <grep-args...>: PASS iff the grep does NOT match (the pattern is absent).
refute() {
   local desc="$1"
   shift
   if grep "$@" -- "${subject}"; then
      printf '%s\n' "FAIL: ${desc}"
      fail_count=$(( fail_count + 1 ))
   else
      printf '%s\n' "PASS: ${desc}"
      pass_count=$(( pass_count + 1 ))
   fi
}

## The self-heal directives must be present; RED if removed or typo'd.
assert "drop-in sets Restart=on-failure (self-heal, not the oneshot default Restart=no)" \
   --quiet --extended-regexp '^[[:space:]]*Restart=on-failure[[:space:]]*$'
assert "drop-in sets a numeric RestartSec" \
   --quiet --extended-regexp '^[[:space:]]*RestartSec=[0-9]'

## A revert to any other Restart= (e.g. Restart=no) defeats the self-heal: fail loud.
refute "drop-in has NO conflicting Restart= line (e.g. a reverted Restart=no)" \
   --quiet --extended-regexp '^[[:space:]]*Restart=(no|always|on-success|on-abnormal|on-abort|on-watchdog)[[:space:]]*$'

## The drop-in's original purpose -- only run vboxadd under VirtualBox -- must be preserved.
assert "drop-in keeps ConditionVirtualization=oracle" \
   --quiet --extended-regexp '^[[:space:]]*ConditionVirtualization=oracle[[:space:]]*$'

printf '%s\n' "===== vboxadd_restart_dropin: ${pass_count} pass, ${fail_count} fail ====="
if [ "${fail_count}" -gt 0 ]; then
   exit 1
fi
