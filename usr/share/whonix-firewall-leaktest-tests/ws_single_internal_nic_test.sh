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

## ifupdown directives that are uninterpreted escape hatches on this static-only
## internal interface: command hooks (up/*-up/*-down, run arbitrary commands incl.
## dhclient / route injection), a `mapping` script, and `source`/`source-directory`
## includes (pull in unaudited NIC-adding stanzas). ifupdown strips one trailing `?`
## from a hook keyword (`up?` runs as `up`), so tolerate it. Backslash
## line-continuations are rejected separately (continuation_re), so a hook split across
## lines (`u\`+`p ...`) cannot hide here.
unsafe_directive_re='^[[:space:]]*(pre-up|up|post-up|pre-down|down|post-down|mapping|source|source-directory)[?]?([[:space:]]|$)'
## ifupdown joins a line whose last non-whitespace char is `\` with the next; any
## continuation in this static file is uncommon and can splice a hook across lines, so
## reject them all (trailing whitespace after the `\` still continues).
continuation_re='\\[[:space:]]*$'

## Audit one interfaces file: exactly one non-lo iface, named eth0, configured
## STATIC on the internal network. Returns 0 on pass, 1 on any violation. Reused
## by the canary.
audit_ws_nic() {
   local file="$1" names count stanza
   ## Uncommented `iface <name> inet{,6} ...` stanzas, loopback excluded. A
   ## commented `#iface ... dhcp` line does not match (the `#` precedes `iface`).
   names="$(grep --extended-regexp '^[[:space:]]*iface[[:space:]]+[^[:space:]]+[[:space:]]+inet' "${file}" \
      | awk '{ print $2 }' | grep --invert-match --line-regexp --fixed-strings 'lo' | sort -u)"
   count="$(printf '%s' "${names}" | grep --count --extended-regexp '.' || true)"
   if [ "${count}" -ne 1 ]; then
      printf '%s\n' \
         "FAIL: expected exactly ONE non-loopback NIC, found ${count}: $(printf '%s' "${names}" | tr '\n' ' ')" >&2
      return 1
   fi
   if [ "${names}" != 'eth0' ]; then
      printf '%s\n' "FAIL: the single NIC is not the internal eth0: ${names}" >&2
      return 1
   fi
   ## Reject the whole class of uninterpreted escape hatches (command hooks, a
   ## `mapping` script, `source`/`source-directory` includes, and any backslash
   ## line-continuation) -- each can re-enable DHCP, inject a non-Tor route, or pull in
   ## an unaudited NIC-adding stanza this single-file audit cannot see.
   if grep --quiet --extended-regexp "${unsafe_directive_re}" "${file}"; then
      printf '%s\n' \
         "FAIL: interfaces file uses an unsafe directive (hook/mapping/source): $(grep --extended-regexp "${unsafe_directive_re}" "${file}" | tr '\n' ' ')" >&2
      return 1
   fi
   if grep --quiet --extended-regexp "${continuation_re}" "${file}"; then
      printf '%s\n' \
         "FAIL: interfaces file has a line-continuation (can splice a hook): $(grep --extended-regexp "${continuation_re}" "${file}" | tr '\n' ' ')" >&2
      return 1
   fi
   ## eth0 must be STATIC, never a DYNAMIC method (dhcp/bootp/ppp) -- any of those
   ## on a NAT/bridged eth0 installs a non-Tor default route.
   if grep --quiet --extended-regexp '^[[:space:]]*iface[[:space:]]+eth0[[:space:]]+inet[[:space:]]+(dhcp|bootp|ppp)([[:space:]]|$)' "${file}"; then
      printf '%s\n' "FAIL: eth0 uses a dynamic inet method (must be static)" >&2
      return 1
   fi
   ## Extract ONLY the `iface eth0 inet static` stanza (up to the next stanza
   ## keyword) and require the internal address + gateway WITHIN it -- so address /
   ## gateway lines parked under another stanza (e.g. lo) cannot satisfy the check.
   stanza="$(awk '
      /^[[:space:]]*iface[[:space:]]+eth0[[:space:]]+inet[[:space:]]+static([[:space:]]|$)/ { inblk = 1; print; next }
      inblk && /^[[:space:]]*(iface|mapping|auto|allow-|source|source-directory)/ { inblk = 0 }
      inblk { print }
   ' "${file}")"
   if [ -z "${stanza}" ]; then
      printf '%s\n' "FAIL: no \"iface eth0 inet static\" stanza" >&2
      return 1
   fi
   ## Exactly ONE address + ONE gateway in the stanza, each the internal value --
   ## a second (conflicting) address/gateway would otherwise ride through. The
   ## optional /CIDR suffix is accepted (the shipped form uses a separate netmask).
   if [ "$(grep --count --extended-regexp '^[[:space:]]*address[[:space:]]' <<< "${stanza}")" != '1' ] \
      || ! grep --quiet --extended-regexp '^[[:space:]]*address[[:space:]]+10\.152\.152\.11(/[0-9]+)?([[:space:]]|$)' <<< "${stanza}"; then
      printf '%s\n' "FAIL: eth0 static stanza needs exactly one internal address 10.152.152.11" >&2
      return 1
   fi
   if [ "$(grep --count --extended-regexp '^[[:space:]]*gateway[[:space:]]' <<< "${stanza}")" != '1' ] \
      || ! grep --quiet --extended-regexp '^[[:space:]]*gateway[[:space:]]+10\.152\.152\.10([[:space:]]|$)' <<< "${stanza}"; then
      printf '%s\n' "FAIL: eth0 static stanza needs exactly one gateway 10.152.152.10" >&2
      return 1
   fi
   return 0
}

repo="${WHONIX_WS_NETWORK_CONF_REPO:-}"
if [ -z "${repo}" ]; then
   printf '%s\n' "FATAL: WHONIX_WS_NETWORK_CONF_REPO unset -- the WS network config is a required source" >&2
   exit 1
fi
iface_file="${repo}/etc/network/interfaces.d/30_non-qubes-whonix"
if [ ! -r "${iface_file}" ]; then
   printf '%s\n' "FATAL: WS interfaces file not readable: ${iface_file}" >&2
   exit 1
fi

rc=0
if audit_ws_nic "${iface_file}"; then
   printf '%s\n' "PASS: Workstation declares exactly one internal-network NIC (eth0)"
else
   rc=1
fi

## Canary 1: a second NIC must FAIL the audit, proving it has teeth.
canary="$(mktemp)"
cp -- "${iface_file}" "${canary}"
printf '%s\n' 'auto eth1' 'iface eth1 inet dhcp' >>"${canary}"
if audit_ws_nic "${canary}" 2>/dev/null; then
   printf '%s\n' "FAIL: canary -- audit PASSED a config with a second NIC (no teeth)" >&2
   rc=1
else
   printf '%s\n' "PASS: canary (second NIC rejected); audit has teeth"
fi

## Canary 2: eth0 flipped to dhcp must FAIL (proves the static-method teeth).
canary_dhcp="$(mktemp)"
sed -E 's/^([[:space:]]*iface[[:space:]]+eth0[[:space:]]+inet[[:space:]]+)static/\1dhcp/' \
   "${iface_file}" >"${canary_dhcp}"
if audit_ws_nic "${canary_dhcp}" 2>/dev/null; then
   printf '%s\n' "FAIL: canary -- audit PASSED eth0 as inet dhcp (no teeth)" >&2
   rc=1
else
   printf '%s\n' "PASS: canary (eth0 dhcp rejected); audit has teeth"
fi

## Canary 3: a second `iface eth0 inet bootp` stanza beside the valid static one
## must FAIL -- bootp is a dynamic method too. Keeping the static stanza isolates the
## method-list teeth (the static-stanza check still passes), locking in that the
## check is not narrowed back to dhcp-only.
canary_bootp="$(mktemp)"
cp -- "${iface_file}" "${canary_bootp}"
printf '%s\n' 'iface eth0 inet bootp' >>"${canary_bootp}"
if audit_ws_nic "${canary_bootp}" 2>/dev/null; then
   printf '%s\n' "FAIL: canary -- audit PASSED a second eth0 inet bootp stanza (no teeth)" >&2
   rc=1
else
   printf '%s\n' "PASS: canary (eth0 bootp rejected); audit has teeth"
fi

## Canary 4: every unsafe-directive spelling hidden in the static stanza must FAIL --
## `up dhclient` re-enables DHCP, `post-up ip route add default` injects a non-Tor
## route, a `mapping` script and a `source` include pull in arbitrary commands/NICs,
## and a `up\` line-continuation hides the hook from a naive line match.
for bad_line in \
   'up dhclient eth0' \
   'up? dhclient eth0' \
   'post-up ip route add default via 10.0.2.2' \
   'mapping eth0' \
   'source /etc/network/interfaces.d/evil' \
   $'up\\'; do
   canary_hook="$(mktemp)"
   cp -- "${iface_file}" "${canary_hook}"
   printf '%s\n' "${bad_line}" >>"${canary_hook}"
   if audit_ws_nic "${canary_hook}" 2>/dev/null; then
      printf '%s\n' "FAIL: canary -- audit PASSED unsafe directive \"${bad_line}\" (no teeth)" >&2
      rc=1
   else
      printf '%s\n' "PASS: canary (unsafe directive \"${bad_line}\" rejected); audit has teeth"
   fi
done

## Canary 5: a hook SPLIT across a backslash continuation (ifupdown joins `u\`+`p ...`
## into `up dhclient eth0`) must FAIL -- including the form with trailing whitespace
## after the `\`, which still continues.
for split_first in $'u\\' $'u\\  '; do
   canary_split="$(mktemp)"
   cp -- "${iface_file}" "${canary_split}"
   printf '%s\n' "${split_first}" 'p dhclient eth0' >>"${canary_split}"
   if audit_ws_nic "${canary_split}" 2>/dev/null; then
      printf '%s\n' "FAIL: canary -- audit PASSED a split-line hook continuation (no teeth)" >&2
      rc=1
   else
      printf '%s\n' "PASS: canary (split-line hook continuation rejected); audit has teeth"
   fi
done

exit "${rc}"
