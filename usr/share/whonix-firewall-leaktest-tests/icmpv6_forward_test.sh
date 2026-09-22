#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Leak test: workstation ICMPv6 to the clearnet must not egress the gateway.
##
## Tor carries no ICMP; the gateway rejects forwarding, so a Workstation ping to
## a public address must never leave the external interface. A reply -- or the
## echo request itself reaching the upstream sink -- would be a non-Tor leak.
## Positive control confirms the torified TCP path still works; the canary
## (permissive forward) confirms the probe would be seen if it did leak.

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
leaktest_forward_leak_case \
   'ICMPv6 echo to clearnet' icmp6 "${PROBE_DST_IP6}" || rc=$?
exit "${rc}"
