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
## Several non-SYN flag combinations: only a SYN is redirected to Tor, so an ACK,
## FIN-ACK, or RST-ACK must hit the forward reject, not slip out as direct TCP.
for flags in ack finack rstack; do
   leaktest_forward_leak_case \
      "non-SYN TCP (${flags}, transproxy bypass) to clearnet" tcp6 "${PROBE_DST_IP6}" \
      "ip6 and host ${PROBE_DST_IP6} and tcp" --flags "${flags}" --dport 443 || rc=$?
done
exit "${rc}"
