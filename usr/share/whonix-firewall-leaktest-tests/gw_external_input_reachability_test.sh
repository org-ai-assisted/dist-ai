#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Leak test: the Gateway's Tor-facing ports must NOT be reachable from the
## external (upstream / VBox-NAT) side (filter INPUT chain).
##
## Threat: an upstream / LAN attacker -- or a Tor port wrongly bound to 0.0.0.0 --
## reaching SocksPort / TransPort / DnsPort / ControlPort or ssh from the external
## side (open-proxy abuse, inbound deanonymisation). The shipped INPUT chain
## accepts those ports only `iifname eth1` (internal); a packet arriving on eth0
## (the upstream link, a NON-INT_IF interface) hits the policy drop.
##
## A listener is bound WIDE (0.0.0.0 / ::) on the gateway for every probed port, so
## a "not reachable" verdict measures the FIREWALL, not a dead port -- and models
## the worst case (a 0.0.0.0 bind) the static bind audit guards against.
##
## Asserts:
##   1. shipped ruleset -> SocksPort 9050, TransPort 9040, ControlPort 9051, ssh 22
##      (TCP) and DnsPort 5300 (UDP) are NOT reachable from the up namespace, both
##      families;
##   2. POSITIVE CONTROL: the legitimate internal torified path still works;
##   3. CANARY: with the firewall flushed and the SAME listener bound, every port
##      IS reachable from up -- so a "blocked" above is the firewall, not a dead
##      listener (the probe has teeth).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

lib_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"
## The nonqubes extension sources leaktest_lib.sh itself.
# shellcheck source=./leaktest_lib_nonqubes.sh
source "${lib_dir}/leaktest_lib_nonqubes.sh"

leaktest_preconditions
trap leaktest_nonqubes_cleanup EXIT

rc=0
## <proto> <port> <name> -- every port the gateway must not expose externally.
probes=(
   'tcp 9050 SocksPort'
   'tcp 9040 TransPort'
   'tcp 9051 ControlPort'
   'tcp 22 ssh'
   'udp 5300 DnsPort'
)

## 1. Shipped ruleset: none of the ports is reachable from the external side.
leaktest_setup_ext_input "${ruleset_file}"
for probe in "${probes[@]}"; do
   read -r proto port name <<< "${probe}"
   result4="$(leaktest_reach_probe up "${proto}" 4 "${EXT_GW_IP4}" "${port}")"
   leaktest_assert_unreachable "${name} ${proto}/${port} (IPv4 external)" "${result4}" || rc=1
   result6="$(leaktest_reach_probe up "${proto}" 6 "${EXT_GW_IP6}" "${port}")"
   leaktest_assert_unreachable "${name} ${proto}/${port} (IPv6 external)" "${result6}" || rc=1
done

## 2. Positive control on the same topology (the internal torified path works, so
## the drops above are not a wedged model).
if leaktest_positive_control; then
   msg 'PASS: positive control (legit torified TCP path works)'
else
   rc=1
fi

## 3. Canary: flush the firewall, keep the same wide listener -> every port now
## reachable from up, proving the probe + listener detect an exposed port.
empty="$(mktemp --suffix=.nft)"
printf '%s\n' "flush ruleset" >"${empty}"
leaktest_setup_ext_input "${empty}"
for probe in "${probes[@]}"; do
   read -r proto port name <<< "${probe}"
   result4="$(leaktest_reach_probe up "${proto}" 4 "${EXT_GW_IP4}" "${port}")"
   leaktest_assert_reachable "${name} ${proto}/${port} (IPv4, firewall flushed)" "${result4}" || rc=1
   result6="$(leaktest_reach_probe up "${proto}" 6 "${EXT_GW_IP6}" "${port}")"
   leaktest_assert_reachable "${name} ${proto}/${port} (IPv6, firewall flushed)" "${result6}" || rc=1
done

exit "${rc}"
