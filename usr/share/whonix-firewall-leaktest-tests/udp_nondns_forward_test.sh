#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Leak test: workstation non-DNS UDP to the clearnet must not egress.
##
## Whonix transparently redirects Workstation UDP/53 to Tor's DnsPort, but Tor
## carries no other UDP, so any non-53 UDP (probed here on NTP/123) must be
## rejected by the gateway, not forwarded to the clearnet. The datagram reaching
## the upstream sink would be a non-Tor leak. Positive control + permissive-
## forward canary as in the other cases.

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
   'non-DNS UDP to clearnet' udp6 "${PROBE_DST_IP6}" --dport 123 || rc=$?
exit "${rc}"
