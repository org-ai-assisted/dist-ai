#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Leak test: workstation ICMPv4 (ping) to the clearnet must not egress.
##
## The Whonix wiki's canonical ping leak test: Tor carries no ICMP, so a
## Workstation ping to a public IPv4 address must never leave the external
## interface. Companion to the ICMPv6 case. Positive control + permissive-forward
## canary as in the other cases.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

lib_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"
# shellcheck source=./leaktest_lib.sh
source "${lib_dir}/leaktest_lib.sh"

leaktest_preconditions
trap leaktest_teardown EXIT

rc=0
leaktest_probe_case \
   'ICMPv4 echo (ping) to clearnet' icmp4 "${INT_WS_IP4}" "${PROBE_DST_IP4}" || rc=$?
exit "${rc}"
