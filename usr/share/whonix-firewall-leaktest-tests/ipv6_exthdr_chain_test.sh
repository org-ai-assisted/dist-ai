#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Leak test: IPv6 extension-header chains must not slip past the gateway.
##
## A packet whose real L4 header sits one hop down an extension-header chain
## (Routing header / Hop-by-Hop options / Destination options) is a classic
## firewall-evasion shape: a stateless filter that inspects only the first
## next-header can be tricked into a different verdict. Whonix forwards nothing
## from the Workstation to the clearnet, so each of these must hit the forward
## reject regardless of the header chain. Companion to the atomic-fragment case.
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
## Routing header type 0 (RH0) and type 4 (SRH), Hop-by-Hop options, Destination
## options: each wraps a UDP datagram, so the L4 is hidden behind the extension
## header. routing4 (SRH) guards against a future rule keyed on the RH0 type byte
## that would overlook a different routing type; today's blanket forward-drop is
## type-agnostic and must catch both.
for kind in routing routing4 hopopts dstopts; do
   leaktest_probe_case \
      "IPv6 ext-header (${kind}) to clearnet" exthdr6 "${INT_WS_IP6}" "${PROBE_DST_IP6}" \
      --exthdr "${kind}" --dport 443 || rc=$?
done
exit "${rc}"
