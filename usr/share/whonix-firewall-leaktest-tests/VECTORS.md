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
- Forged-source DNS -- the UDP/53 DnsPort reply to a forged source must not egress;
  uRPF drops it (`dns_forged_source_urpf_test.sh`). The DnsPort stub replies from the
  DNAT'd destination via IPV6_PKTINFO, as a real bound DnsPort does, so conntrack
  un-NATs the reply and the leak actually reproduces under the canary.
- TCP transparent-redirect port-INDEPENDENCE -- a legit clearnet TCP connection on
  ports 80/22/ephemeral is redirected + answered (`tcp_redirect_port_independence_test.sh`)
- ICMPv6 echo (`icmpv6_forward_test.sh`), ICMPv4 ping (`icmpv4_forward_test.sh`)
- Non-DNS UDP -- NTP 123, QUIC 443, WireGuard 51820, OpenVPN 1194, over BOTH IPv6
  and IPv4 (`udp_nondns_forward_test.sh`)
- DNS redirect -- UDP/53 (BOTH families) must be redirected to the Tor DnsPort and
  answered AND must not egress the gateway; canary strips the redirect and opens
  forward (`dns_redirect_positive_test.sh`)
- Non-SYN TCP transproxy bypass -- ACK/SYN-ACK/FIN-ACK/RST-ACK (only a pure SYN is
  redirected), IPv6 and IPv4
  (`nonsyn_tcp_transproxy_bypass_test.sh`, `ipv4_nonsyn_tcp_test.sh`)
- Positive control is dual-family (IPv6 AND IPv4 TransPort), so a family-scoped
  redirect breakage is caught (`leaktest_lib.sh` leaktest_positive_control)
- Arbitrary IP protocols -- broad sample (IP-in-IP 4, GRE 47, ESP 50, AH 51, OSPF
  89, DCCP 33, SCTP 132, PIM 103, VRRP 112, L2TP 115, MPLS 137, IPv6-in-IPv6 41
  for v6), as BOTH IPv6 next-headers AND IPv4-outer protocols
  (`protocol_and_tunnel_test.sh`)
- Tunnels -- 6to4/SIT (IPv4 proto 41), Teredo (UDP/3544) (same file)
- IPv6 atomic fragment (`fragment_evasion_test.sh`)
- IPv6 multi-fragment reassembly -- a UDP datagram SPLIT across two fragments
  (offset 0 M=1 + offset 8 M=0, same id) must not slip past the forward drop by
  fragmentation: `nf_defrag_ipv6` reassembles before the forward chain, so the
  ruleset acts on the reassembled datagram, which hits the drop. The permissive
  canary egresses the reassembled datagram, proving the fragments reassembled AND
  forwarded (not merely stalled in the defrag buffer -- which would be a silent
  false pass) (`ipv6_multi_fragment_test.sh`)
- IPv6 extension-header chain -- Routing (RH0) / Hop-by-Hop / Destination options
  (`ipv6_exthdr_chain_test.sh`)
- Ext-header / fragment hiding a TCP SYN -- the transparent-proxy redirect must
  walk the chain to find + redirect the SYN, not forward it un-torified
  (`ipv6_exthdr_hidden_syn_test.sh`)
- IPv4 LSRR source-route option (IHL>5) -- a source-routed packet must not egress.
  Defense-in-depth: the test flips the kernel's own source-route drop OFF
  (accept_source_route=1) to isolate the FIREWALL, proving the forward policy-drop
  blocks it even if the kernel ever honored source routes; the permissive canary
  egresses it (`ipv4_source_routing_test.sh`)
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
- IPv6 lone non-first fragment (tiny-fragment / overlap with the completing
  fragments withheld) -- `nf_defrag_ipv6` (loaded by conntrack, like its IPv4
  sibling) holds an incomplete set, so a lone non-first fragment is never
  forwarded. The COMPLETE two-fragment set IS tested and reassembles-then-drops
  (`ipv6_multi_fragment_test.sh`, Covered above); the ATOMIC fragment (offset 0,
  M=0) IS tested as a complete single-fragment datagram (`fragment_evasion_test.sh`).
  Only a deliberately-incomplete set (held indefinitely, never egresses) remains a
  non-vector.
- Multicast / broadcast egress -- IPv4 broadcast is link-scoped and IPv6 global
  multicast needs multicast routing the Gateway does not run; verified nothing
  egresses even under a permissive forward policy.
- conntrack ALG / related-flow -- the forward chain has no
  `ct state established,related accept` (only reject + policy drop), so a helper
  cannot open a forward hole; Whonix also disables conntrack helpers.
- Kernel reject/RST replies to a forged source -- blocked by the output
  `ct state established`-only rule; do not egress.

## Deferred to a real Non-Qubes-Whonix server (netns stub not faithful)

- Hostile Router-Advertisement / RA-vs-connection RACE (as opposed to the static
  accept_ra end-state the netns already models) and real Tor circuit behavior.
- Online leak-site / torrent checks (`doileak.com`, `ipleak.net`) -- require real
  clearnet + a real workstation. Their L3 reductions (DNS, STUN UDP, torrent UDP)
  ARE covered by the DNS + non-DNS-UDP cases above.

## Reviewer-identified gaps -- future work (need new tooling or a different suite)

- Rogue RA / RS / NA / NS / DHCPv6 injection FROM the Workstation toward the
  Gateway -- a DIFFERENT threat model (poisoning the Gateway's own FIB / neighbor
  cache / SLAAC config), NOT the forward-egress leak this suite's oracle detects: a
  rogue RA/ND from the Workstation creates no forwarded packet, and the forward
  policy-drop blocks egress unconditionally regardless. A netns injection test here
  would only re-exercise the Linux kernel's own RA acceptance logic (ignore when
  accept_ra=0, install when accept_ra=2), proving nothing about the Whonix
  Gateway's posture. The in-scope, meaningful assertion is that the SHIPPED gateway
  config disables accept_ra / accept_redirects / autoconf on the internal
  interface (so a rogue RA cannot rewrite the FIB the uRPF rule keys on) -- a
  STATIC audit of the real package's sysctl config, which belongs in a
  firewall-config test suite, not this netns forward-egress model that sets its own
  sysctls. (To resume as a config audit:
  `grep -r 'accept_ra\|accept_redirects' <whonix-firewall sysctl config>` and
  assert `=0` on the internal interface.)
- Tor ControlPort (9051) / wildcard SocksPort reachability from the internal
  interface -- a control-channel scoping concern, not forward egress; belongs in a
  control-port / onion-grater test, not this suite.
- Firewall rule-reload race under live traffic -- the serial setup/teardown model
  structurally cannot exercise it.
- EXHAUSTIVE protocol-number / destination-port sweeps (the wiki's 0-255 / 0-65535
  batteries) -- the suite tests a broad sample, not every value.
- Rogue-RA soundness dependency: the uRPF rule keys on the live FIB, so the
  internal-interface accept_ra / accept_redirects sysctls being off is load-bearing.
  This netns suite CANNOT assert it faithfully -- it sets its own sysctls, so a
  check here would test the netns, not the shipped config. Belongs with the RA
  config audit above.

## Known harness limitations (trust-critical -- do not silently rely on them)

- The egress oracle (`LEAKTEST_EGRESS_BPF`) EXCLUDES all multicast/broadcast so
  benign ND/MLD/RA is not miscounted. Consequence: a probe sent to a
  multicast/broadcast destination would be invisible to the oracle. This is safe
  ONLY because multicast/broadcast is a verified non-vector here (no multicast
  routing); do NOT add a multicast-destined probe expecting the shared oracle to
  catch it -- it needs its own destination-scoped capture.
- The oracle's benign-infrastructure exclusion is keyed to the external-link
  subnet `10.0.2.0/24` and the link IPv6 addresses. A future test that picks a
  probe address inside that subnet would have a real leak silently excluded -- keep
  probe addresses in RFC 5737 / RFC 3849 documentation ranges.
- The canary rule-stripping (`grep --invert-match 'fib saddr...'`, the permissive
  ruleset sed, the DNS-redirect strip) matches exact generated `.nft` wording; an
  upstream wording change makes a canary no-op, which fails LOUDLY ("canary did NOT
  reproduce"), never a false pass -- but would need re-syncing suite-wide.
