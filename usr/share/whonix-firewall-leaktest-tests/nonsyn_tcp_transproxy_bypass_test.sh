#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Leak test: a non-SYN TCP packet must not bypass the transparent proxy.
##
## The gateway redirects only TCP SYN to Tor's TransPort; a crafted non-SYN
## segment (here an ACK) is not redirected, so it must hit the forward reject and
## never reach the clearnet. If it were forwarded it would be a direct,
## non-torified TCP path (the classic FIN-ACK / RST-ACK transproxy-bypass leak).
## Positive control + permissive-forward canary as in the other cases.

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
   'non-SYN TCP (transproxy bypass) to clearnet' tcp6 "${PROBE_DST_IP6}" \
   "ip6 and host ${PROBE_DST_IP6} and tcp" --flags ack --dport 443 || rc=$?
exit "${rc}"
