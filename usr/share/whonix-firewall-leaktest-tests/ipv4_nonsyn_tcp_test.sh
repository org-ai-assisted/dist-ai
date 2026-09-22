#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Leak test: an IPv4 non-SYN TCP segment must not bypass the transparent proxy.
##
## Companion to the IPv6 non-SYN case and the wiki's FIN-ACK / RST-ACK leak test.
## Only a TCP SYN is redirected to Tor's TransPort; a crafted ACK / FIN-ACK /
## RST-ACK is not, so it must hit the forward reject, never slip out as a direct,
## non-torified IPv4 TCP path. Positive control + permissive-forward canary.

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
for flags in ack finack rstack; do
   leaktest_probe_case \
      "IPv4 non-SYN TCP (${flags}, transproxy bypass) to clearnet" tcp4 "${INT_WS_IP4}" "${PROBE_DST_IP4}" \
      --flags "${flags}" --dport 443 || rc=$?
done
exit "${rc}"
