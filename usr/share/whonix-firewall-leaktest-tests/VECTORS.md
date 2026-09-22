# whonix-firewall leak-test vector coverage

Scope of this suite: the L3 forward-egress threat model -- a compromised
Whonix-Workstation trying to push non-Tor traffic out the Gateway's clearnet
interface. Each covered case loads the REAL generated `gateway-default.nft` in a
three-netns model (ws -> gw -> up) and asserts no probe egresses the sink, with a
POSITIVE CONTROL (a legit torified path still works) and a CANARY (the same probe
DOES egress once the relevant rule is removed, proving the harness has teeth).

## Covered (one `*_test.sh` per file, positive control + canary each)

- Forged-source IPv6 -- uRPF drop (`ipv6_forged_source_urpf_test.sh`)
- Forged-source IPv4 -- dual-stack uRPF + kernel rp_filter (`ipv4_forged_source_urpf_test.sh`)
- ICMPv6 echo (`icmpv6_forward_test.sh`), ICMPv4 ping (`icmpv4_forward_test.sh`)
- Non-DNS UDP (`udp_nondns_forward_test.sh`)
- Non-SYN TCP transproxy bypass -- ACK/FIN-ACK/RST-ACK, IPv6 and IPv4
  (`nonsyn_tcp_transproxy_bypass_test.sh`, `ipv4_nonsyn_tcp_test.sh`)
- Arbitrary IP protocols -- GRE 47, ESP 50, OSPF 89, DCCP 33, SCTP 132
  (`protocol_and_tunnel_test.sh`)
- Tunnels -- 6to4/SIT (IPv4 proto 41), Teredo (UDP/3544) (same file)
- IPv6 atomic fragment (`fragment_evasion_test.sh`)
- IPv6 extension-header chain -- Routing (RH0) / Hop-by-Hop / Destination options
  (`ipv6_exthdr_chain_test.sh`)
- Fail-closed killswitch -- Tor down => drop, not leak (`fail_closed_test.sh`)

This covers, and exceeds, every vector the Whonix wiki `Dev/Leak_Tests` (+ the
Scapy-based `Dev/Leak_Tests_Old`) documents: DNS, ICMP ping, direct/non-SYN TCP,
non-DNS UDP, torrent-UDP and the arbitrary-protocol battery all map to cases
above; the wiki does not document the IPv6, forged-source, tunnel or
extension-header vectors, which this suite adds.

## Investigated, NOT a vector (no test shipped -- documented so the gap is honest)

- IPv4 fragment evasion -- conntrack `nf_defrag_ipv4` reassembles before the
  forward chain: a lone fragment is held (never forwarded), a complete set is
  reassembled and handled as a normal packet. No fragment-specific forward leak.
- Multicast / broadcast egress -- IPv4 broadcast is link-scoped and IPv6 global
  multicast needs multicast routing the Gateway does not run; verified nothing
  egresses even under a permissive forward policy.
- conntrack ALG / related-flow -- the forward chain has no
  `ct state established,related accept` (only reject + policy drop), so a helper
  cannot open a forward hole; Whonix also disables conntrack helpers.
- Kernel reject/RST replies to a forged source -- blocked by the output
  `ct state established`-only rule; do not egress.

## Deferred to a real Non-Qubes-Whonix server (netns stub not faithful)

- UDP/53 DnsPort established-reply to a forged source -- the userspace stub
  sources its reply by routing, so conntrack never un-NATs it; real Tor DnsPort
  binding may differ. Needs a real DnsPort to test.
- accept_ra global-route-dependent timing and real Tor circuit behavior.
- Online leak-site / torrent checks (`doileak.com`, `ipleak.net`) -- require real
  clearnet + a real workstation.
