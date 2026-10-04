#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Static audit: every Tor listener the Gateway ships must bind loopback, the
## internal Gateway IP, the internal ULA, or a unix socket -- NEVER a wildcard
## (0.0.0.0 / [::]) or a routable address.
##
## Threat: a SocksPort / TransPort / DnsPort / HTTPTunnelPort / ControlPort bound
## to 0.0.0.0 is reachable from the upstream/NAT side -- an open proxy and an
## inbound deanonymisation vector. The firewall (covered by the netns INPUT test)
## is defence-in-depth; the bind address is the first line.
##
## Reads the REAL shipped torrc (base defaults + torrc.d drop-ins); no netns, no
## root. The source checkout is a REQUIRED dependency: absent -> FATAL, never skip.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

## Audit every uncommented *Port directive in the given torrc file(s). Returns 0
## if all binds are allowed, 1 on any disallowed bind. Reused by the canary.
audit_torrc_binds() {
   local rc=0 line bind addr
   while IFS= read -r line; do
      bind="$(printf '%s\n' "${line}" | awk '{ print $2 }')"
      case "${bind}" in
         unix:*)
            ## a unix-domain socket, not a TCP bind -- allowed.
            continue
            ;;
         \[*)
            ## [v6]:port -> keep the bracketed address.
            addr="${bind%%]*}]"
            ;;
         *:*)
            ## host:port -> strip the port.
            addr="${bind%:*}"
            ;;
         *)
            ## a bare port (no address) -> Tor binds localhost -- allowed.
            continue
            ;;
      esac
      case "${addr}" in
         127.0.0.1 | 10.152.152.10 | '[::1]' | '[fd19:c33d:88bc::10]')
            ;;
         *)
            printf 'FAIL: disallowed Tor bind address %s (line: %s)\n' "${addr}" "${line}" >&2
            rc=1
            ;;
      esac
   done < <(grep --no-filename --extended-regexp '^[[:space:]]*(SocksPort|TransPort|DnsPort|HTTPTunnelPort|ControlPort|NATDPort|ORPort|DirPort)[[:space:]]' "$@")
   return "${rc}"
}

repo="${ANON_GW_ANONYMIZER_CONFIG_REPO:-}"
if [ -z "${repo}" ]; then
   printf 'FATAL: ANON_GW_ANONYMIZER_CONFIG_REPO unset -- the gateway torrc is a required source\n' >&2
   exit 1
fi
base_file="${repo}/usr/share/tor/tor-service-defaults-torrc.anondist.base"
torrc_dir="${repo}/etc/torrc.d"
if [ ! -r "${base_file}" ]; then
   printf 'FATAL: gateway torrc base not readable: %s\n' "${base_file}" >&2
   exit 1
fi
if [ ! -d "${torrc_dir}" ]; then
   printf 'FATAL: torrc.d drop-in dir not found: %s\n' "${torrc_dir}" >&2
   exit 1
fi

rc=0
if audit_torrc_binds "${base_file}" "${torrc_dir}"/*.conf; then
   printf 'PASS: every Tor listener binds loopback / internal IP / ULA / unix (no wildcard)\n'
else
   rc=1
fi

## Canary: a 0.0.0.0-bound SocksPort must FAIL the audit, proving it has teeth.
canary="$(mktemp)"
cp -- "${base_file}" "${canary}"
printf '%s\n' 'SocksPort 0.0.0.0:9050' >>"${canary}"
if audit_torrc_binds "${canary}" 2>/dev/null; then
   printf 'FAIL: canary -- bind audit PASSED a 0.0.0.0 SocksPort (no teeth)\n' >&2
   rc=1
else
   printf 'PASS: canary (0.0.0.0 bind rejected); audit has teeth\n'
fi

exit "${rc}"
