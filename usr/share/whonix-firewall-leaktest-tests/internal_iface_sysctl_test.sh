#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Static audit: the kernel-neighbor / router-advertisement sysctls that the
## gateway uRPF FIB depends on must be set hardened, and the internal interfaces
## must be inet6 STATIC (no SLAAC autoconf).
##
## Threat: a rogue RA/DHCP or ICMP redirect from a compromised peer on the shared
## internal LAN could poison the Gateway/Workstation FIB or neighbor table and
## redirect traffic off-Tor. security-misc ships wildcard-scoped (`.*.`) sysctls
## that disable RA, redirects and source routing and harden ARP on EVERY interface
## incl. the internal one; there is no explicit `autoconf` sysctl, so autoconf-off
## on the internal link is pinned by accept_ra=0 PLUS the iface being inet6 static.
##
## Reads the REAL shipped config (no netns, no root). The source checkouts are
## REQUIRED dependencies: absent -> FATAL, never a skip.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

## Audit the security-misc sysctl file for the hardened neighbor/RA/redirect keys.
## Returns 0 on pass, 1 on any missing/changed key. Reused by the canary.
audit_sysctl() {
   local file="$1" rc=0 key
   ## Wildcard-scoped key=value pairs required verbatim (apply to every iface).
   local required=(
      'net.ipv6.conf.*.accept_ra=0'
      'net.ipv4.conf.*.accept_redirects=0'
      'net.ipv6.conf.*.accept_redirects=0'
      'net.ipv4.conf.*.arp_filter=1'
      'net.ipv4.conf.*.accept_source_route=0'
      'net.ipv6.conf.*.accept_source_route=0'
   )
   for key in "${required[@]}"; do
      if ! grep --quiet --line-regexp --fixed-strings "${key}" "${file}"; then
         printf 'FAIL: sysctl missing or changed: %s\n' "${key}" >&2
         rc=1
      fi
   done
   ## arp_ignore must be ON: 2 is shipped, 1 is tolerated per the in-file VM note.
   if ! grep --quiet --line-regexp --extended-regexp 'net\.ipv4\.conf\.\*\.arp_ignore=[12]' "${file}"; then
      printf 'FAIL: sysctl net.ipv4.conf.*.arp_ignore not set to 1 or 2\n' >&2
      rc=1
   fi
   ## Presence is not enough: systemd-sysctl applies in order and a later
   ## assignment (a wildcard flip or a per-interface override like
   ## net.ipv6.conf.eth1.accept_ra=1) WINS. Reject ANY assignment of these keys to
   ## an insecure value, on any scope (*, all, default, or a specific interface).
   ## Tolerate the whitespace sysctl.conf allows around `=` and an optional leading
   ## `-` (systemd ignore-errors prefix), so a spaced/prefixed override cannot slip
   ## an insecure value past. Scope: dotted keys in the canonical form our file
   ## uses -- `/`-separator and VLAN-dotted (eth1.100) key spellings are not modelled.
   local bad sep='[[:space:]]*=[[:space:]]*'
   local bad_values=(
      "net\\.ipv6\\.conf\\.[^.]+\\.accept_ra${sep}[^0[:space:]]"
      "net\\.ipv4\\.conf\\.[^.]+\\.accept_redirects${sep}[^0[:space:]]"
      "net\\.ipv6\\.conf\\.[^.]+\\.accept_redirects${sep}[^0[:space:]]"
      "net\\.ipv4\\.conf\\.[^.]+\\.arp_filter${sep}[^1[:space:]]"
      "net\\.ipv4\\.conf\\.[^.]+\\.arp_ignore${sep}0"
      "net\\.ipv4\\.conf\\.[^.]+\\.accept_source_route${sep}[^0[:space:]]"
      "net\\.ipv6\\.conf\\.[^.]+\\.accept_source_route${sep}[^0[:space:]]"
   )
   for bad in "${bad_values[@]}"; do
      if grep --quiet --extended-regexp "^[[:space:]]*-?${bad}" "${file}"; then
         printf 'FAIL: sysctl sets a hardened key to an insecure value: %s\n' \
            "$(grep --extended-regexp "^[[:space:]]*-?${bad}" "${file}" | tr '\n' ' ')" >&2
         rc=1
      fi
   done
   return "${rc}"
}

## Audit that the INTERNAL interfaces are inet6 static (GW eth1, WS eth0). The GW
## external eth0 is inet6 auto by design (real clearnet IPv6) and is not asserted.
audit_internal_inet6_static() {
   local gw_file="$1" ws_file="$2" rc=0
   if ! grep --quiet --extended-regexp '^[[:space:]]*iface[[:space:]]+eth1[[:space:]]+inet6[[:space:]]+static([[:space:]]|$)' "${gw_file}"; then
      printf 'FAIL: GW internal iface eth1 is not inet6 static\n' >&2
      rc=1
   fi
   if ! grep --quiet --extended-regexp '^[[:space:]]*iface[[:space:]]+eth0[[:space:]]+inet6[[:space:]]+static([[:space:]]|$)' "${ws_file}"; then
      printf 'FAIL: WS internal iface eth0 is not inet6 static\n' >&2
      rc=1
   fi
   ## A conflicting `inet6 auto`/`dhcp` stanza on the SAME internal iface re-enables
   ## SLAAC/autoconf (accept_ra defaults back on) even beside the static one -- reject it.
   if grep --quiet --extended-regexp '^[[:space:]]*iface[[:space:]]+eth1[[:space:]]+inet6[[:space:]]+(auto|dhcp)([[:space:]]|$)' "${gw_file}"; then
      printf 'FAIL: GW internal iface eth1 has a conflicting inet6 auto/dhcp stanza\n' >&2
      rc=1
   fi
   if grep --quiet --extended-regexp '^[[:space:]]*iface[[:space:]]+eth0[[:space:]]+inet6[[:space:]]+(auto|dhcp)([[:space:]]|$)' "${ws_file}"; then
      printf 'FAIL: WS internal iface eth0 has a conflicting inet6 auto/dhcp stanza\n' >&2
      rc=1
   fi
   ## An ifupdown stanza OPTION `accept_ra`/`autoconf` set non-zero re-enables RA /
   ## SLAAC at ifup, overriding the sysctl hardening -- reject it in either file.
   local f
   for f in "${gw_file}" "${ws_file}"; do
      if grep --quiet --extended-regexp '^[[:space:]]+(accept_ra|autoconf)[[:space:]]+[^0[:space:]]' "${f}"; then
         printf 'FAIL: interfaces stanza re-enables RA/autoconf: %s\n' \
            "$(grep --extended-regexp '^[[:space:]]+(accept_ra|autoconf)[[:space:]]+[^0[:space:]]' "${f}" | tr '\n' ' ')" >&2
         rc=1
      fi
   done
   return "${rc}"
}

sm_repo="${SECURITY_MISC_REPO:-}"
gw_repo="${WHONIX_GW_NETWORK_CONF_REPO:-}"
ws_repo="${WHONIX_WS_NETWORK_CONF_REPO:-}"
if [ -z "${sm_repo}" ] || [ -z "${gw_repo}" ] || [ -z "${ws_repo}" ]; then
   printf 'FATAL: SECURITY_MISC_REPO / WHONIX_GW_NETWORK_CONF_REPO / WHONIX_WS_NETWORK_CONF_REPO must all be set (required sources)\n' >&2
   exit 1
fi
## security-misc ships this file with a literal `#security-misc-shared` suffix.
sysctl_file="${sm_repo}/usr/lib/sysctl.d/990-security-misc.conf#security-misc-shared"
gw_iface_file="${gw_repo}/etc/network/interfaces.d/30_non-qubes-whonix"
ws_iface_file="${ws_repo}/etc/network/interfaces.d/30_non-qubes-whonix"
for f in "${sysctl_file}" "${gw_iface_file}" "${ws_iface_file}"; do
   if [ ! -r "${f}" ]; then
      printf 'FATAL: required config file not readable: %s\n' "${f}" >&2
      exit 1
   fi
done

rc=0
if audit_sysctl "${sysctl_file}"; then
   printf 'PASS: internal-iface sysctls hardened (accept_ra/redirects/arp/source-route)\n'
else
   rc=1
fi
if audit_internal_inet6_static "${gw_iface_file}" "${ws_iface_file}"; then
   printf 'PASS: internal interfaces are inet6 static (no autoconf)\n'
else
   rc=1
fi

## Canary 1: drop the accept_ra line -> the sysctl audit must FAIL (teeth).
canary="$(mktemp)"
grep --invert-match --line-regexp --fixed-strings 'net.ipv6.conf.*.accept_ra=0' "${sysctl_file}" >"${canary}"
if audit_sysctl "${canary}" 2>/dev/null; then
   printf 'FAIL: canary -- sysctl audit PASSED with accept_ra removed (no teeth)\n' >&2
   rc=1
else
   printf 'PASS: canary (missing accept_ra rejected); audit has teeth\n'
fi

## Canary 2: a per-interface override re-enabling RA must FAIL (proves the
## conflicting-value teeth, not just the presence check).
canary_override="$(mktemp)"
cp -- "${sysctl_file}" "${canary_override}"
printf '%s\n' 'net.ipv6.conf.eth1.accept_ra=1' >>"${canary_override}"
if audit_sysctl "${canary_override}" 2>/dev/null; then
   printf 'FAIL: canary -- sysctl audit PASSED a per-iface accept_ra=1 override (no teeth)\n' >&2
   rc=1
else
   printf 'PASS: canary (per-iface accept_ra override rejected); audit has teeth\n'
fi

exit "${rc}"
