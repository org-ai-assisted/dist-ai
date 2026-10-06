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
- VPN-tunnel INT_TIF forged-source -- when the Workstation reaches the Gateway over a
  VPN tunnel, the Tor DnsPort/Control/Socks are accepted DIRECTLY on the tunnel
  interface tun0 (INT_TIF), distinct from eth1 (INT_IF, the TransPort/redirect path).
  A forged-source packet arriving on tun0 at the DnsPort must be dropped by the uRPF
  that guards tun0 -- else it is accepted with no reverse-path check and the reply
  leaks to the forged clearnet source. Loads the gateway-int-tif fixture (INT_IF=eth1
  INT_TIF=tun0) and adds a second internal veth (ws<->tun0). The BEHAVIORAL companion
  to whonix-firewall's ruleset-level test_gateway_int_tif assertion. Canary strips the
  tun0 uRPF -> the DnsPort reply egresses (IPv6, whose tunnel source routes out; the
  uRPF is one dual-stack `fib saddr` rule so this establishes the teeth for the IPv4
  blocked assertions too -- a direct DnsPort reply's private IPv4 tunnel source cannot
  egress to a clearnet dst, so IPv4 is not independently canaried here)
  (`vpn_tunnel_int_tif_urpf_test.sh`)

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
- Tor ControlPort (9051) command scoping from the internal interface -- a
  control-channel concern, not forward egress: which control COMMANDS a compromised
  Workstation may smuggle through is covered by its own layer, the onion-grater profile
  tests (`onion-grater-tests`, the Python `onion_grater_profile_test.py` -- NOT the
  `anon-gw-anonymizer-config-tests/onion_grater_profile_test.sh`, which only tests the
  add/remove helpers' path-traversal). Command filtering is the wrong layer for this
  forward-egress suite and the right layer already tests it. BUT port REACHABILITY
  scoping (a SocksPort/TransPort/ControlPort bound 0.0.0.0, or reachable on a non-INT_IF
  address, from the internal OR the VBox-NAT external side) is NOT covered by onion-grater
  and REMAINS A GAP -- see the Non-Qubes-Whonix gaps section.
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
- The oracle's benign-infrastructure exclusion is the link IPv6 addresses plus, on
  IPv4, DHCP ONLY (ports 67/68) within `10.0.2.0/24` -- NOT all `/24` unicast, so a
  gw-originated unicast to a host in that subnet (e.g. the host DNS proxy `10.0.2.3`)
  is visible (see `gw_originated_nontor_egress_test.sh`). A FORWARD probe whose BOTH
  endpoints sit in `10.0.2.0/24` on udp 67/68 would still be excluded -- keep probe
  addresses in RFC 5737 / RFC 3849 documentation ranges.
- The canary rule-stripping (`grep --invert-match 'fib saddr...'`, the permissive
  ruleset sed, the DNS-redirect strip) matches exact generated `.nft` wording; an
  upstream wording change makes a canary no-op, which fails LOUDLY ("canary did NOT
  reproduce"), never a false pass -- but would need re-syncing suite-wide.

## Non-Qubes-Whonix threat model (two VMs on a VBox internal network + a host OS)

This netns suite covers L3 FORWARD egress. The full Non-Qubes-Whonix model adds
gateway-origination, external-input and static-invariant surfaces that the forward model
does not reach; those are covered as below, leaving the two LIVE `dm-whonix-pair` layers.

Covered:

- GW-ORIGINATED / host-DNS leaks (the Non-Qubes `NON_TOR_GATEWAY` exceptions): the shipped
  Gateway OUTPUT accepts + skips Tor-redirect for `10.0.2.0/24` (VBox NAT: .2 router, .3
  host DNS proxy), `192.168.0.0/24`, `192.168.1.0/24` -- EMPTY on Qubes. A Gateway process
  reaching the host DNS proxy (`10.0.2.3`) or the LAN is a real non-Tor leak (the wiki
  "Deactivate Host DNS" leak). The shared oracle (`leaktest_lib.sh` `LEAKTEST_EGRESS_BPF`)
  excludes only DHCP(67/68) on that link (NOT all `10.0.2.0/24` unicast, which would hide the
  leak), and `gw_originated_nontor_egress_test.sh` fires REAL gw-namespace sockets (the OUTPUT
  chain, which the AF_PACKET injector bypasses): clearnet is rejected, `10.0.2.3` / `192.168.x`
  egress ARE seen (teeth), DHCP stays excluded (precision).
- GW external-side INPUT exposure / port reachability: SocksPort/TransPort/DnsPort/
  ControlPort or ssh reachable from the VBox-NAT side or a non-INT_IF address (bound
  `0.0.0.0`). Covered by `gw_external_input_reachability_test.sh` (netns INPUT-chain probes
  from the upstream namespace, listener bound wide to model the 0.0.0.0 worst case) and the
  static bind audit `tor_socksport_bind_test.sh` (every Tor listener binds `10.152.152.10` /
  `127.0.0.1` / the ULA / a unix socket, never a wildcard).
- WS adapter-config invariant: a Workstation second NIC on NAT/Bridged bypasses the Gateway
  entirely. Covered by the static audit `ws_single_internal_nic_test.sh` (exactly one
  internal-network NIC, eth0, via gateway 10.152.152.10).
- GW/WS sysctl + neighbor config: `accept_ra` / `accept_redirects` / autoconf off on the
  internal interface, `arp_ignore`/`arp_filter` -- load-bearing for the uRPF FIB. CLOSED by
  the static audit `internal_iface_sysctl_test.sh` (security-misc wildcard sysctls +
  internal iface is inet6 static; there is no explicit autoconf sysctl).

Covered by the LIVE `dm-whonix-pair` (not this netns suite):

- GW-originated ALLOWLIST canary (deny-by-default): the LIVE `dm-whonix-pair` GW external-NIC
  canary permits ONLY current Tor relays + link infra (DHCP/link-local/multicast); ANY other
  clearnet dst is a LEAK. Tor-only by default, NO carve-out for the `NON_TOR_GATEWAY` host-DNS/LAN
  exception (if it fires it is a true leak). The permitted relay set is the GW's OWN cached
  consensus, read as root in the GW user session (`gw_tor_relay_ips`: every IPv4 / bracketed-IPv6
  token in `cached-microdesc-consensus` + `cached-consensus`). The FULL relay set on purpose:
  `EntryNodes` + `StrictNodes 1` pins circuit ENTRY, but Tor still opens DIRECTORY (V2Dir)
  connections to non-guard relays for descriptor/consensus fetches, so a pinned-guard-only
  allowlist would false-flag those. The canary extracts each clearnet dst from the GW nictrace
  pcap (infra excluded via `infra_bpf`) and fails if any dst is not in the consensus relay set;
  fail-closed -- an empty/unreadable relay set is SETUP, never a pass. The fixed watchlist stays
  as defense-in-depth. Two liveness signals, counted SEPARATELY (neither masks the other): (1)
  GENUINE Tor guard traffic (entry guards on their ORPorts) must clear a floor (`GUARD_MIN_PKTS`);
  (2) a deliberate POSITIVE-CONTROL emit -- the `clearnet` user opens one TCP connection to a
  RESERVED guard's real ORPort. The reserved guard is allowlisted but excluded from `EntryNodes`,
  so Tor never dials it and every packet to it is the canary (separable by host); its ORPort is
  public consensus infra, so the emit is legitimate (no abuse complaint), not an unsolicited scan.
- A second, on-the-wire oracle (`host-wire-leak-capture` in private-ai-config/ovh-server-debug)
  applies a PINNED-GUARD allowlist (read verbatim via `--print-allow-filter` / `--print-guards` /
  `--print-pc-filter`, single source) to a RAW capture of the host's physical NIC, catching egress
  the guest-NIC tap could miss. It still uses the pinned-guard basis, NOT the consensus relay set,
  so it can false-flag a legitimate directory connection -- see the Open follow-up.

App/browser layer -- LIVE-verified:

- WebRTC local-IP exposure + browser Tor-exit: the opt-in `browser-webrtc` anon-leak-test probe
  (`DM_WHONIX_PAIR_BROWSER=1`) drives the WS Tor Browser headless and asserts WebRTC exposes NO
  host-identifying address (only the WS internal net / mDNS / loopback) and, when reachable, that
  the browser exit is Tor. Pure classifier unit-tested + canaried; fail-closed to SETUP when the
  probe cannot run.
- This is the ONE assertion no other layer covers: the wire oracle sees only NON-Tor clearnet
  egress and cannot inspect an ICE candidate carried INSIDE the Tor circuit to a STUN server /
  peer, so a local IP disclosed that way is opaque to it.
- Control channel: the probe drives Tor Browser over its marionette automation port
  (127.0.0.1:2828), NOT an in-page collector -- Tor Browser routes all page traffic (incl.
  127.0.0.1) through Tor, so a localhost sink is unreachable; marionette is not page-proxied.
  `ANON_LEAK_BROWSER_TIMEOUT` makes the through-Tor `check.torproject.org` fetch deadline
  configurable (a cold circuit can exceed the default).
- Display: Tor Browser renders on the WS's real Wayland session (sysmaint) with
  `MOZ_ENABLE_WAYLAND=1`; headless/offscreen does not render firefox. Needs the
  apparmor-profile-torbrowser fix allowing firefox's native-Wayland sockets
  (`/run/user/*/wayland-[0-9]*`, `wayland-proxy-*`).
- Staging: the probe runs NON-root (Tor Browser refuses root) so cannot read the root-only
  `/mnt/shared`; `ws_browser_probe` installs the CLI + harness to a world-readable guest-local dir
  as root (explicit `install -d -m 0755`) in a SEPARATE guestcontrol call, so a staging/transport
  failure is SETUP not a false LEAK.
- Verdict source: the guestcontrol layer does not preserve the guest exit (guest 2 surfaces as 34)
  and a transport failure can surface as 1, so the battery + browser probe classify on the probe's
  `--json` (`leak_detected` / `exit_code`), absent JSON = SETUP; the GW-trace pcap canary is the
  authoritative, exit-independent leak gate.
- Live status: browser-webrtc PASSes on the OVH pair -- marionette drives Tor Browser, WebRTC is
  disabled (Tor Browser default -> no routable candidate, the secure state), and the network-layer
  tor-confirm shows a Tor exit.

Open (owned by the LIVE `dm-whonix-pair`, not this netns suite):

- Non-torified WS apps (apt/ping launched without a proxy) + DNS-prefetch -- not yet a probe
  (the gateway-craft + GW/host-NIC allowlists already catch the resulting clearnet egress).
- Bridge lane: `EntryNodes` is mutually exclusive with bridges, so the pinned-guard allowlist
  cannot cover a bridge config. A separate lane would allow the configured bridge IPs instead.
- nftables allowlist ENFORCEMENT: convert the host `ai_server_fw` OUTPUT fleet-uid rule from a
  denylist (two probe dsts) to a pinned-guard allowlist drop -- the enforcement counterpart to
  the `host-wire-leak-capture` observation.
- host-wire allowlist basis: `host-wire-leak-capture` still allows only the PINNED guards (+
  infra) via `--print-allow-filter`, while the guest-NIC canary allows the full consensus relay
  set, so the host-wire oracle can false-flag a legitimate Tor DIRECTORY (V2Dir) connection to a
  non-guard relay. Align it on the consensus relay set (single source): persist
  `gw_tor_relay_ips`'s set to a run artifact the host tool reads, or expose it via a new
  `--print-relay-ips`. Mechanism is a dwp<->host-wire contract choice; host-wire's live path is
  the `dm-release-test` root orchestration, not the `DM_WHONIX_PAIR_BROWSER` guest run.

OUT of scope (reviewer-confirmed): a second compromised Workstation SNIFFING a peer on the
shared VBox internal LAN -- Whonix does not promise WS<->WS isolation and the traffic is
still torified at the Gateway; only a rogue RA/DHCP from such a WS (FIB poisoning) matters,
which the RA sysctl audit covers. Stream-isolation / circuit correlation is a torrc audit,
not an egress leak.
