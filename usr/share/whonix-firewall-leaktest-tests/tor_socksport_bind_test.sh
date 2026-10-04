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
## Tor option names are case-INSENSITIVE and may carry a leading + (append) or /
## (remove); match accordingly so a lowercase `socksport` / `+SocksPort` cannot
## evade. Scope: this is a bind-ADDRESS audit of the shipped one-line directives,
## NOT a full torrc parser -- a backslash line-continuation is not joined (its
## token is non-numeric, so it FAILS loudly rather than passing silently), and the
## PT-grammar ServerTransportListenAddr is out of scope (not shipped on a client
## gateway).
audit_torrc_binds() {
   local rc=0 line kw bind addr inspected=0
   while IFS= read -r line; do
      kw="$(printf '%s\n' "${line}" | awk '{ sub(/^[+\/]/, "", $1); print tolower($1) }')"
      bind="$(printf '%s\n' "${line}" | awk '{ print $2 }')"
      inspected=$(( inspected + 1 ))
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
            ## A bare token. A valid bare PORT is all-digits; anything else (e.g. a
            ## `\` line-continuation) is unparsable -> FAIL, never a silent pass.
            case "${bind}" in
               '' | *[!0-9]*)
                  printf 'FAIL: unparsable Tor bind token %s (line: %s)\n' "${bind:-<empty>}" "${line}" >&2
                  rc=1
                  continue
                  ;;
            esac
            ## A bare port binds localhost for the client listeners, but 0.0.0.0 /
            ## [::] for the PUBLIC listeners ORPort/DirPort -- FAIL those.
            case "${kw}" in
               orport | dirport)
                  printf 'FAIL: %s bare port binds a wildcard (public listener): %s\n' "${kw}" "${line}" >&2
                  rc=1
                  ;;
            esac
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
   done < <(grep --no-filename --ignore-case --extended-regexp '^[[:space:]]*[+/]?(SocksPort|TransPort|DnsPort|HTTPTunnelPort|ControlPort|NATDPort|ORPort|DirPort|ExtORPort|MetricsPort)[[:space:]]' "$@")
   ## Vacuous-pass guard: the shipped gateway torrc defines dozens of listeners, so
   ## inspecting zero means the scan matched nothing (empty / all-evaded) -- FAIL.
   if [ "${inspected}" -eq 0 ]; then
      printf 'FAIL: no Tor listener directives inspected -- scan matched nothing (vacuous pass)\n' >&2
      rc=1
   fi
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
## Lowercased on purpose, so the canary also exercises the case-insensitive match.
canary="$(mktemp)"
cp -- "${base_file}" "${canary}"
printf '%s\n' 'socksport 0.0.0.0:9050' >>"${canary}"
if audit_torrc_binds "${canary}" 2>/dev/null; then
   printf 'FAIL: canary -- bind audit PASSED a 0.0.0.0 SocksPort (no teeth)\n' >&2
   rc=1
else
   printf 'PASS: canary (0.0.0.0 bind rejected); audit has teeth\n'
fi

exit "${rc}"
