#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Static audit: the Non-Qubes Whonix-Workstation must declare EXACTLY ONE
## non-loopback NIC, on the internal (Gateway-only) network.
##
## Threat: a second Workstation adapter on NAT or Bridged networking bypasses the
## Gateway entirely -- the Workstation talks to the host LAN / internet directly,
## non-Tor. The shipped WS interfaces config declares only eth0 (internal static,
## 10.152.152.11 via gateway 10.152.152.10); any additional uncommented iface is a
## bypass risk.
##
## Reads the REAL shipped config (no netns, no root needed). The source checkout is
## a REQUIRED dependency: absent -> FATAL, never a skip.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

## Audit one interfaces file: exactly one non-lo iface, named eth0, internal.
## Returns 0 on pass, 1 on any violation. Reused by the canary.
audit_ws_nic() {
   local file="$1" names count
   ## Uncommented `iface <name> inet{,6} ...` stanzas, loopback excluded. A
   ## commented `#iface ... dhcp` line does not match (the `#` precedes `iface`).
   names="$(grep --extended-regexp '^[[:space:]]*iface[[:space:]]+[^[:space:]]+[[:space:]]+inet' "${file}" \
      | awk '{ print $2 }' | grep --invert-match --line-regexp --fixed-strings 'lo' | sort -u)"
   count="$(printf '%s' "${names}" | grep --count --extended-regexp '.' || true)"
   if [ "${count}" -ne 1 ]; then
      printf 'FAIL: expected exactly ONE non-loopback NIC, found %s: %s\n' \
         "${count}" "$(printf '%s' "${names}" | tr '\n' ' ')" >&2
      return 1
   fi
   if [ "${names}" != 'eth0' ]; then
      printf 'FAIL: the single NIC is not the internal eth0: %s\n' "${names}" >&2
      return 1
   fi
   if ! grep --quiet --extended-regexp '^[[:space:]]*address[[:space:]]+10\.152\.152\.11([[:space:]]|$)' "${file}"; then
      printf 'FAIL: eth0 is not on the internal network (no address 10.152.152.11)\n' >&2
      return 1
   fi
   if ! grep --quiet --extended-regexp '^[[:space:]]*gateway[[:space:]]+10\.152\.152\.10([[:space:]]|$)' "${file}"; then
      printf 'FAIL: eth0 does not route via the Whonix-Gateway (no gateway 10.152.152.10)\n' >&2
      return 1
   fi
   return 0
}

repo="${WHONIX_WS_NETWORK_CONF_REPO:-}"
if [ -z "${repo}" ]; then
   printf 'FATAL: WHONIX_WS_NETWORK_CONF_REPO unset -- the WS network config is a required source\n' >&2
   exit 1
fi
iface_file="${repo}/etc/network/interfaces.d/30_non-qubes-whonix"
if [ ! -r "${iface_file}" ]; then
   printf 'FATAL: WS interfaces file not readable: %s\n' "${iface_file}" >&2
   exit 1
fi

rc=0
if audit_ws_nic "${iface_file}"; then
   printf 'PASS: Workstation declares exactly one internal-network NIC (eth0)\n'
else
   rc=1
fi

## Canary: a second NIC must FAIL the audit, proving it has teeth.
canary="$(mktemp)"
cp -- "${iface_file}" "${canary}"
printf '%s\n' 'auto eth1' 'iface eth1 inet dhcp' >>"${canary}"
if audit_ws_nic "${canary}" 2>/dev/null; then
   printf 'FAIL: canary -- audit PASSED a config with a second NIC (no teeth)\n' >&2
   rc=1
else
   printf 'PASS: canary (second NIC rejected); audit has teeth\n'
fi

exit "${rc}"
