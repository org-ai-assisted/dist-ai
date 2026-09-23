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
- Non-SYN TCP transproxy bypass -- ACK/SYN-ACK/FIN-ACK/RST-ACK plus the scan/evasion
  flag combos NULL/FIN/Xmas/SYN+FIN (only a pure SYN is redirected; SYN+FIN in
  particular must not satisfy the redirect's `flags & (fin|syn|rst|ack) == syn`
  match), IPv6 and IPv4
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
  walk the chain to find + redirect the SYN, not forward it un-torified. Verified
  it REACHED the redirect (the :9040 redirect counter advanced), not merely that
  nothing egressed -- a dropped SYN and a torified one both produce zero egress, so
  the counter is what proves torification. Includes the deepest RFC 8200-conformant
  chain (hopopts, dstopts, routing, dstopts) to probe the walk depth
  (`ipv6_exthdr_hidden_syn_test.sh`)
- TCP SYN hidden by a GENUINE two-fragment IPv4 split -- the SYN is split so the TCP
  flags byte (offset 13) lands in the second fragment, so no single fragment shows a
  SYN. ip_defrag must rebuild the SYN before the nat prerouting chain and the redirect
  must torify it. Like the ext-header case, verified it REACHED the :9040 redirect
  (counter advanced), not merely that nothing egressed -- distinct from the
  multi-fragment UDP cases (forward drop only) and the ext-header/atomic-fragment
  hidden SYN (no real MF=1/MF=0 split). IPv4 only: the IPv6 equivalent truncates the
  TCP header in the first fragment, which nf_defrag_ipv6 refuses to reassemble
  (dropped as a tiny-first fragment, covered by `ipv6_fragment_tinyfirst_test.sh`) --
  a confirmed IPv4/IPv6 defrag asymmetry (`fragment_hidden_syn_test.sh`)
- IPv6 overlapping fragments -- an RFC 5722 overlapping fragment set must not
  reassemble or egress. The overlapping fragment extends past the first fragment's
  end, so nf_defrag_ipv6 classifies it IPFRAG_OVERLAP and inet_frag_kill discards the
  whole datagram (the genuine overlap-kill, not the IPFRAG_DUP a mere subset
  degenerates into). Teeth under a permissive forward: the VALID sibling set egresses
  while the overlapping one does not (`ipv6_fragment_overlap_test.sh`)
- IPv6 tiny-first-fragment (RFC 7112) -- a set whose first fragment is too small to
  hold the L4 header must not egress. Linux does NOT reassemble it (the truncated
  first fragment has an incomplete transport header, so nf_ct_frag6_gather does not
  complete; unlike a lone non-first fragment, the truncated FIRST fragment is
  forwarded as-is), so the forward chain sees the fragment, not a reassembled
  datagram, and the shipped forward drop catches it. The permissive canary egresses
  the fragment, proving the forward chain (not a defrag stall) is what blocks it
  (`ipv6_fragment_tinyfirst_test.sh`)
- IPv4 fragmented UDP -- an IPv4 UDP datagram split across two fragments must not
  egress. IPv4 defrag has a SEPARATE ENTRY (ip_defrag / nf_defrag_ipv4) from
  nf_defrag_ipv6 -- distinct trigger, header format, CVE history (FragmentSmack,
  CVE-2018-5391) -- but shares the overlap classification (inet_frag_queue_insert,
  rbtree-unified since 4.18), so it is tested empirically, not by analogy: the gateway DOES
  reassemble FORWARDED IPv4 fragments (nf_defrag_ipv4, pulled in by the ruleset's
  nat/conntrack), re-fragmenting to the original boundaries on egress -- so the
  ruleset acts on the reassembled datagram, which hits the forward drop. Confirmed
  empirically: a lone incomplete first fragment is held, never egresses. The
  permissive canary egresses the reassembled set (`ipv4_multi_fragment_test.sh`)
- IPv4 overlapping fragments -- an overlapping IPv4 fragment set must not egress. The
  overlapping fragment extends past the first fragment's end, so ip_defrag classifies
  it IPFRAG_OVERLAP and inet_frag_kill discards the whole datagram (RFC 5722) -- the
  genuine overlap-kill path, not the IPFRAG_DUP a mere subset degenerates into. Teeth
  under a permissive forward: the valid sibling set forwards while the overlapping one
  does not (`ipv4_fragment_overlap_test.sh`)
- IPv4 LSRR source-route option (IHL>5) -- a source-routed packet must not egress,
  in BOTH shapes: a COMPLETED/inert route (dst = final target, catches a rule keyed
  on IHL=5) and an ACTIVE route (dst = gateway, next hop = target -- attacker-
  directed source routing the gateway must not honor and forward). Defense-in-depth:
  the test flips the kernel's own source-route drop OFF (accept_source_route=1) to
  isolate the FIREWALL, proving the forward policy-drop blocks both even if the
  kernel ever honored source routes; the permissive canary egresses each -- for the
  active shape, only after the kernel processed the route and rewrote the
  destination (`ipv4_source_routing_test.sh`)
- Fail-closed killswitch -- Tor down => drop, not leak (`fail_closed_test.sh`)

This covers, and exceeds, every vector the Whonix wiki `Dev/Leak_Tests` (+ the
Scapy-based `Dev/Leak_Tests_Old`) documents: DNS, ICMP ping, direct/non-SYN TCP,
non-DNS UDP, torrent-UDP and the arbitrary-protocol battery all map to cases
above; the wiki does not document the IPv6, forged-source, tunnel or
extension-header vectors, which this suite adds.

## Investigated, NOT a vector (no test shipped -- documented so the gap is honest)

- IPv6 lone non-first fragment (incomplete set with the completing fragments
  withheld) -- `nf_defrag_ipv6` (loaded by conntrack, like its IPv4 sibling) holds
  an incomplete set, so a lone non-first fragment is never forwarded. The COMPLETE
  two-fragment set IS tested and reassembles-then-drops (`ipv6_multi_fragment_test.sh`);
  an OVERLAPPING set IS tested and is dropped by RFC 5722 reassembly
  (`ipv6_fragment_overlap_test.sh`); the ATOMIC fragment (offset 0, M=0) IS tested
  as a complete single-fragment datagram (`fragment_evasion_test.sh`) -- all Covered
  above. Only a deliberately-incomplete set (held indefinitely, never egresses)
  remains a non-vector.
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
- VPN-tunnel (INT_TIF != INT_IF) forged-source BEHAVIORAL test -- the uRPF fix that
  covers INT_TIF (whonix-firewall firewall-common) is guarded here only at the
  ruleset level (whonix-firewall's own `test_gateway_int_tif` dry-run assertion, the
  core guard). A netns behavioral test would fire a forged source arriving on a
  tun0 (INT_TIF) interface at the DnsPort/SocksPort and assert the uRPF drops it, with
  a canary that leaks when the INT_TIF uRPF is stripped. NOT yet built: it needs (a) a
  checked-in INT_TIF=tun0 ruleset fixture in whonix-firewall `test-output/new/`
  (generate it from the `test_gateway_int_tif` config: `whonix-gateway-firewall
  --dry-run` with `INT_IF="eth1" INT_TIF="tun0"`, commit the .nft), and (b) a
  leaktest_setup variant that adds a SECOND internal veth pair ws<->tun0(gw) alongside
  eth1, so the core setup (used by every other case) is untouched. Then a
  `ipv6_vpn_tunnel_urpf_test.sh` loads the fixture, injects a forged-source DNS packet
  on tun0, asserts no reply egress, and canaries by stripping the INT_TIF uRPF drop.
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
