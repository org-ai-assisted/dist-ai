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

## ifupdown directives that are uninterpreted escape hatches on these static-only
## internal interfaces: command hooks (up/*-up/*-down, run arbitrary commands incl.
## dhclient / route injection), a `mapping` script, and `source`/`source-directory`
## includes (pull in unaudited stanzas). ifupdown strips one trailing `?` from a hook
## keyword (`up?` runs as `up`), so tolerate it. Backslash line-continuations are
## rejected separately (continuation_re), so a hook split across lines (`u\`+`p ...`)
## cannot hide here.
unsafe_directive_re='^[[:space:]]*(pre-up|up|post-up|pre-down|down|post-down|mapping|source|source-directory)[?]?([[:space:]]|$)'
## ifupdown joins a line whose last non-whitespace char is `\` with the next; any
## continuation in these static files is uncommon and can splice a hook across lines,
## so reject them all (trailing whitespace after the `\` still continues).
continuation_re='\\[[:space:]]*$'

## A hardened sysctl leaf (accept_ra, ...) is secure only when assigned EXACTLY its
## hardened number. The kernel parses the value C-style, so `01` (leading-0 octal)
## and `0x1` (hex) both store 1 -- `secure` must list every such spelling. Matches the
## leaf on ANY scope and key spelling systemd-sysctl accepts: `.`/`/` separators (incl.
## mixed, e.g. a VLAN `eth1/100`) and a glob in a NON-leaf segment. `[^=]*` (not `.*`)
## spans the scope without crossing `=`, so a second leaf embedded in a value cannot
## wrongly satisfy the secure exemption. Flags every such line that is not a secure
## assignment -- INCLUDING a value-less shadow line (`-net.ipv6.conf.eth1.accept_ra`
## with no `=`), which registers an explicit key that makes the `*` wildcard skip that
## interface, leaving it at the insecure default. The leaf-terminal boundary
## (`=`/space/EOL) avoids false-matching a sub-key such as accept_ra_defrtr. A leading
## `#` comment cannot match (the `net` anchor is at line start). A glob IN the leaf
## (`accept_*`) is caught separately (see glob_leaf in audit_sysctl). Pure grep -- no
## arithmetic eval. Returns 0 on pass, 1 on any bad line.
check_values() {
   local file="$1" leaf="$2" secure="$3"
   local sep='[[:space:]]*=[[:space:]]*' eol='([[:space:]]|$)' term='([[:space:]]|=|$)'
   local key assign bad
   key="^[[:space:]]*-?net[./][^=]*[./]${leaf}"
   assign="${key}${term}"
   bad="$(grep --extended-regexp "${assign}" "${file}" \
      | grep --invert-match --extended-regexp "${key}${sep}${secure}${eol}" || true)"
   if [ -n "${bad}" ]; then
      printf 'FAIL: sysctl sets a hardened key to an insecure/missing value: %s\n' \
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
   ## value WINS (systemd-sysctl applies in order). Reject any such assignment on any
   ## scope and key spelling (see check_values), interpreting the value as the kernel
   ## does (decimal, leading-0 octal, 0x hex) so 01/0x1 cannot read as 0. Per-leaf
   ## hardened number differs; one check per leaf covers both address families.
   local nz='(0+|0[xX]0+)' one='(0*1|0[xX]0*1)' onetwo='(0*[12]|0[xX]0*[12])'
   check_values "${file}" 'accept_ra'           "${nz}"     || rc=1
   check_values "${file}" 'accept_redirects'    "${nz}"     || rc=1
   check_values "${file}" 'arp_filter'          "${one}"    || rc=1
   check_values "${file}" 'arp_ignore'          "${onetwo}" || rc=1
   check_values "${file}" 'accept_source_route' "${nz}"     || rc=1
   ## A glob in the LEAF segment expands to the hardened keys too, which a literal-leaf
   ## match cannot see: `net.ipv6.conf.eth1.accept_*=1`, `...accept_r?=1`, `...eth1.*=1`,
   ## a globbed conf/ipv segment (`net.ipv6.*.eth1.accept_*=1`, `net.ipv?.conf...`), or a
   ## brace list (`...*.{accept_ra,unused}=1`) each set accept_ra (or a sibling) insecure.
   ## Reject ANY net key whose final component carries a glob metachar (*?[{) -- a legit
   ## scope glob (`net.ipv6.conf.*.accept_ra=0`) has a LITERAL leaf and is not matched.
   ## The shipped file never globs a leaf, so this flags the whole class (even a secure
   ## value) for human review rather than resolving systemd's glob expansion (which a
   ## static audit cannot do). Residual, documented out-of-scope: a bracket class that
   ## embeds a separator (`accept_r[a/]`) -- resolving it needs a real glob(3) matcher.
   local glob_leaf='^[[:space:]]*-?net[./][^=]*[*?[{][^./=]*([[:space:]]*=|[[:space:]]|$)'
   if grep --quiet --extended-regexp "${glob_leaf}" "${file}"; then
      printf 'FAIL: sysctl globs a hardened-key leaf (can match accept_ra/etc.): %s\n' \
         "$(grep --extended-regexp "${glob_leaf}" "${file}" | tr '\n' ' ')" >&2
      rc=1
   fi
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
      ## The internal interfaces ship as plain static stanzas. Reject the whole class
      ## of uninterpreted escape hatches: command hooks (up/*-up/*-down) can run
      ## `dhclient -6`/add a non-Tor route, a `mapping` script runs an arbitrary
      ## command, and `source`/`source-directory` pulls in unaudited stanzas. Plus any
      ## backslash line-continuation (a hook split across lines).
      if grep --quiet --extended-regexp "${unsafe_directive_re}" "${f}"; then
         printf 'FAIL: internal interfaces file uses an unsafe directive (hook/mapping/source): %s\n' \
            "$(grep --extended-regexp "${unsafe_directive_re}" "${f}" | tr '\n' ' ')" >&2
         rc=1
      fi
      if grep --quiet --extended-regexp "${continuation_re}" "${f}"; then
         printf 'FAIL: internal interfaces file has a line-continuation (can splice a hook): %s\n' \
            "$(grep --extended-regexp "${continuation_re}" "${f}" | tr '\n' ' ')" >&2
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

## Canary 3: insecure per-iface overrides in every uncommon-but-valid spelling must
## FAIL -- octal (01) and hex (0x1) both store 1; systemd accepts `/`-separated,
## `.`/`/`-mixed (VLAN eth1/100), VLAN-dotted (eth1.100) and non-leaf-glob keys; a
## value-less shadow key neutralises the `*` wildcard; a glob IN the leaf (accept_*,
## accept_r?, eth1.*) expands to the hardened keys; and a second leaf embedded in a
## value must not wrongly satisfy the secure exemption.
for bad_line in \
   'net.ipv6.conf.eth1.accept_ra=01' \
   'net.ipv6.conf.eth1.accept_ra=0x1' \
   'net/ipv6/conf/eth1/accept_ra=1' \
   'net.ipv6.conf.eth1/100.accept_ra=1' \
   'net.ipv6.conf.eth1.100.accept_ra=1' \
   'net.ipv6.*.eth1.accept_ra=1' \
   '-net.ipv6.conf.eth1.accept_ra' \
   'net.ipv6.conf.eth1.accept_*=1' \
   'net.ipv6.conf.eth1.accept_r?=1' \
   'net.ipv6.conf.eth1.*=1' \
   'net.ipv6.conf.eth?.accept_r?=1' \
   'net.ipv6.*.eth1.accept_*=1' \
   'net.ipv?.conf.eth1.accept_r?=1' \
   'net.ipv6.conf.*.{accept_ra,unused}=1' \
   'net.ipv6.conf.eth1.accept_ra=1 net.ipv6.conf.all.accept_ra=0'; do
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

## Canary 4: FALSE-POSITIVE GUARDS -- the audit must still PASS on secure-but-uncommon
## spellings: arp_filter=01 is octal 1; accept_ra_defrtr is a different sub-key the
## leaf-terminal boundary must not catch; and a legitimate scope glob (secure value)
## must not trip the leaf-glob rule.
for ok_line in \
   'net.ipv4.conf.eth1.arp_filter=01' \
   'net.ipv6.conf.eth1.accept_ra_defrtr=1' \
   'net.ipv6.conf.*.accept_redirects=0'; do
   canary_ok="$(mktemp)"
   cp -- "${sysctl_file}" "${canary_ok}"
   printf '%s\n' "${ok_line}" >>"${canary_ok}"
   if audit_sysctl "${canary_ok}" 2>/dev/null; then
      printf 'PASS: guard (secure/out-of-scope line %s accepted)\n' "${ok_line}"
   else
      printf 'FAIL: guard -- audit wrongly rejected %s\n' "${ok_line}" >&2
      rc=1
   fi
done

## Canary 5: every unsafe-directive spelling on the GW internal iface must FAIL -- a
## command hook (`up dhclient -6 eth1`), a `mapping` script, a `source` include, and a
## `up\` line-continuation all re-enable DHCPv6 / pull in unaudited stanzas despite the
## inet6 static stanza.
for bad_line in \
   'up dhclient -6 eth1' \
   'up? dhclient -6 eth1' \
   'mapping eth1' \
   'source /etc/network/interfaces.d/evil' \
   $'up\\'; do
   canary_hook="$(mktemp)"
   cp -- "${gw_iface_file}" "${canary_hook}"
   printf '%s\n' "${bad_line}" >>"${canary_hook}"
   if audit_internal_inet6_static "${canary_hook}" "${ws_iface_file}" 2>/dev/null; then
      printf 'FAIL: canary -- audit PASSED unsafe directive "%s" (no teeth)\n' "${bad_line}" >&2
      rc=1
   else
      printf 'PASS: canary (unsafe directive "%s" rejected); audit has teeth\n' "${bad_line}"
   fi
done

## Canary 6: a hook SPLIT across a backslash continuation (ifupdown joins `u\`+`p ...`
## into `up dhclient -6 eth1`) must FAIL -- including the form with trailing whitespace
## after the `\`, which still continues.
for split_first in $'u\\' $'u\\  '; do
   canary_split="$(mktemp)"
   cp -- "${gw_iface_file}" "${canary_split}"
   printf '%s\n' "${split_first}" 'p dhclient -6 eth1' >>"${canary_split}"
   if audit_internal_inet6_static "${canary_split}" "${ws_iface_file}" 2>/dev/null; then
      printf 'FAIL: canary -- audit PASSED a split-line hook continuation (no teeth)\n' >&2
      rc=1
   else
      printf 'PASS: canary (split-line hook continuation rejected); audit has teeth\n'
   fi
done

exit "${rc}"
