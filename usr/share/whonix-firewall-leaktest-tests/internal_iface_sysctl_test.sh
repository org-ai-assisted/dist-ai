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

## A hardened sysctl key is secure only when assigned EXACTLY its hardened number.
## The kernel parses the value C-style, so `01` (leading-0 octal) and `0x1` (hex)
## both store 1 -- `secure` must list every such spelling of the number. Flags any
## assignment of `key` whose value is not one of them. systemd-sysctl applies in
## order (last assignment wins) and accepts `.` or `/` as the key separator, so
## `key` matches every scope segment on both spellings. Pure grep -- no arithmetic
## eval on file content. Returns 0 on pass, 1 on any insecure assignment.
check_values() {
   local file="$1" key="$2" secure="$3"
   local sep='[[:space:]]*=[[:space:]]*' eol='([[:space:]]|$)' assign bad
   assign="^[[:space:]]*-?${key}${sep}"
   bad="$(grep --extended-regexp "${assign}" "${file}" \
      | grep --invert-match --extended-regexp "${assign}${secure}${eol}" || true)"
   if [ -n "${bad}" ]; then
      printf 'FAIL: sysctl sets a hardened key to an insecure value: %s\n' \
         "$(printf '%s' "${bad}" | tr '\n' ' ')" >&2
      return 1
   fi
   return 0
}

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
   ## Presence is not enough: a later assignment of a hardened key to an insecure
   ## value WINS (systemd-sysctl applies in order), on any scope (*, all, default,
   ## or a specific interface) and either `.` or `/` separator. Reject any such
   ## assignment, interpreting the value as the kernel does (decimal, leading-0
   ## octal, 0x hex) so 01/0x1 cannot read as 0. Per-key hardened number differs.
   ## Scope: VLAN-dotted segments (eth1.100) are not modelled (eth0/eth1 only here).
   local nz='(0+|0[xX]0+)' one='(0*1|0[xX]0*1)' onetwo='(0*[12]|0[xX]0*[12])'
   check_values "${file}" 'net[./]ipv6[./]conf[./][^./]+[./]accept_ra'           "${nz}"     || rc=1
   check_values "${file}" 'net[./]ipv4[./]conf[./][^./]+[./]accept_redirects'    "${nz}"     || rc=1
   check_values "${file}" 'net[./]ipv6[./]conf[./][^./]+[./]accept_redirects'    "${nz}"     || rc=1
   check_values "${file}" 'net[./]ipv4[./]conf[./][^./]+[./]arp_filter'          "${one}"    || rc=1
   check_values "${file}" 'net[./]ipv4[./]conf[./][^./]+[./]arp_ignore'          "${onetwo}" || rc=1
   check_values "${file}" 'net[./]ipv4[./]conf[./][^./]+[./]accept_source_route' "${nz}"     || rc=1
   check_values "${file}" 'net[./]ipv6[./]conf[./][^./]+[./]accept_source_route' "${nz}"     || rc=1
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
      ## No ifupdown command hooks ship on the internal interfaces. ANY of them is an
      ## uninterpreted escape hatch -- `up dhclient -6 eth1` re-enables DHCPv6/SLAAC,
      ## `post-up ip route add default ...` injects a non-Tor route -- so reject them
      ## all rather than chase individual commands.
      if grep --quiet --extended-regexp '^[[:space:]]*(pre-up|up|post-up|pre-down|down|post-down)[[:space:]]' "${f}"; then
         printf 'FAIL: internal interfaces file has ifupdown command hooks (unaudited bypass): %s\n' \
            "$(grep --extended-regexp '^[[:space:]]*(pre-up|up|post-up|pre-down|down|post-down)[[:space:]]' "${f}" | tr '\n' ' ')" >&2
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

## Canary 3: insecure per-iface overrides in uncommon-but-valid spellings must FAIL
## -- octal (01) and hex (0x1) both store 1, and systemd accepts a `/`-separated key.
for bad_line in \
   'net.ipv6.conf.eth1.accept_ra=01' \
   'net.ipv6.conf.eth1.accept_ra=0x1' \
   'net/ipv6/conf/eth1/accept_ra=1'; do
   canary_val="$(mktemp)"
   cp -- "${sysctl_file}" "${canary_val}"
   printf '%s\n' "${bad_line}" >>"${canary_val}"
   if audit_sysctl "${canary_val}" 2>/dev/null; then
      printf 'FAIL: canary -- sysctl audit PASSED insecure override %s (no teeth)\n' "${bad_line}" >&2
      rc=1
   else
      printf 'PASS: canary (insecure override %s rejected); audit has teeth\n' "${bad_line}"
   fi
done

## Canary 4: FALSE-POSITIVE GUARD -- arp_filter=01 is octal 1 = SECURE; the audit
## must still PASS so the octal/hex tightening does not reject a valid hardened value.
canary_ok="$(mktemp)"
cp -- "${sysctl_file}" "${canary_ok}"
printf '%s\n' 'net.ipv4.conf.eth1.arp_filter=01' >>"${canary_ok}"
if audit_sysctl "${canary_ok}" 2>/dev/null; then
   printf 'PASS: guard (arp_filter=01 is octal 1, accepted as secure)\n'
else
   printf 'FAIL: guard -- audit wrongly rejected arp_filter=01 (octal 1 = secure)\n' >&2
   rc=1
fi

## Canary 5: a dhclient command hook on the GW internal iface must FAIL -- it would
## re-enable DHCPv6 at ifup despite the inet6 static stanza.
canary_hook="$(mktemp)"
cp -- "${gw_iface_file}" "${canary_hook}"
printf '%s\n' 'up dhclient -6 eth1' >>"${canary_hook}"
if audit_internal_inet6_static "${canary_hook}" "${ws_iface_file}" 2>/dev/null; then
   printf 'FAIL: canary -- audit PASSED a dhclient command hook (no teeth)\n' >&2
   rc=1
else
   printf 'PASS: canary (dhclient command hook rejected); audit has teeth\n'
fi

exit "${rc}"
