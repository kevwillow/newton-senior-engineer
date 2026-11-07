---
source: Peterson & Davie, Computer Networks: A Systems Approach (6th ed), chapter dir scaling/ ; https://github.com/SystemsApproach/book (commit 5deec5e)
license: CC BY 4.0, (c) Larry Peterson and Bruce Davie. Summarised/condensed by an AI agent; not the original text.
---

# Chapter 4: Advanced Internetworking (scaling/)

Sections: 4.1 Global Internet (areas, BGP), 4.2 IPv6, 4.3 Multicast, 4.4 MPLS, 4.5 Mobility, plus a perspective on cloud/IXPs.

## Key ideas

- Two problems in internetworking: heterogeneity (chapter 3) and scale (this chapter). Scale is "arguably the fundamental problem".
- Hierarchy plus aggregation is the one tool used everywhere: IP prefixes, CIDR, OSPF areas, autonomous systems, IPv6 provider-based prefixes, PIM shared trees.
- Scalability vs optimality trade-off (Key Takeaway): hierarchy hides information, so nodes cannot make perfect decisions. In large networks scalability beats shortest path.
- Two scaling issues: (1) routing table size / number of network numbers in routing protocols; (2) address-space utilisation.
- Autonomous System (AS): a network under one administration; also called a routing domain. Intradomain routing (IGP: RIP, OSPF, IS-IS) vs interdomain routing (EGP historically; now BGP-4).
- Intradomain optimises a scalar metric. Interdomain finds a loop-free, policy-compliant path; it advertises only reachability because metrics are not comparable across ASes.
- AS types: stub (local traffic only), multihomed stub (several links, refuses transit), transit (carries transit and local traffic).
- Identifier vs locator: an IP address does both jobs; mobility wants them split (Mobile IP home address = identifier, care-of address = locator).
- Internet shape: tier-1 providers at the top (customers and peers, no provider), customers below. Today cloud providers sit near 150+ IXPs, run private backbones, and many paths are one AS hop.

## Principles and rules of thumb

- Keep detail local: summarise at area/AS boundaries rather than flooding everything.
- Use BGP only for the number of ASes (order of ASes), IGP only for the number of networks inside one AS.
- Never inject full BGP table into the IGP; use iBGP and resolve border-router next hops via the IGP.
- Stub AS with one exit: just inject a default route from the border router.
- Policy is business: default customer/provider/peer rules decide what you advertise.
- Single-homed sites with provider-assigned prefixes must renumber when changing provider; plan for this (IPv6 same issue).
- Multicast: pick the mode by application (one-to-many -> SSM; many-to-many within a domain -> BIDIR-PIM or PIM-SM; sparse receivers -> sparse mode, never flood-and-prune).
- MPLS is no longer sold on speed; use it for traffic engineering, non-IP devices, and VPNs.
- Mobility: apps often cope themselves by re-establishing connections (HTTP) instead of the network hiding address changes.
- Wireless is not mobility. Mobility = node moving between networks while communicating.

## Techniques and protocol mechanics

### OSPF / IS-IS areas (4.1.1)
- Area = set of routers exchanging link-state info. Area 0 = backbone. Area Border Router (ABR) is in area 0 plus at least one other area. ASBR (AS border router) is a different role.
- LSAs of non-ABR routers stay in their area; flooding and SPF stay small.
- Inter-area: path = source area -> backbone -> destination area. ABRs summarise costs of one area into the other as if the networks were directly attached to the ABR.
- Two ABRs in one area: routers pick by SPF cost.
- Cost: all inter-area traffic goes via area 0 even if a shorter direct path exists.
- Virtual link: configure a router not directly attached to area 0 to exchange backbone info with one that is; cost derived from the area it crosses.

### BGP-4 (4.1.2)
- Border router: forwards between ASes. BGP speaker: router that speaks BGP to other ASes (often the same box). Runs over TCP (port 179), so no periodic refresh; sends keepalives only.
- Path-vector: advertises full AS path (list of ASes) per prefix. Gives policy control and loop detection: if own AS number appears in received path, reject.
- AS numbers are 32 bits, centrally assigned, must be unique.
- Update message carries advertisements and withdrawn routes (negative reachability).
- A speaker advertises only its single best route (by local policy) and may decline to advertise (this is how non-transit policy is done).
- Example advert: "128.96 reachable via (AS 1, AS 2)".
- Relationships and standard policies:
  - Provider to customer: send customer everything; routes learned from customer go to everyone.
  - Customer to provider: send own prefixes and customer routes to provider; accept provider routes; do NOT re-advertise one provider's routes to another provider (avoid free transit).
  - Peer to peer: send customer routes to peer; send peer routes to own customers only; never peer routes to providers or other peers.
- eBGP = between ASes. iBGP = inside an AS, full mesh among routers (here scalable alternatives exist but are out of scope) to distribute externally learned best exits.
- Forwarding in an AS = iBGP says which border router for prefix P; IGP says how to reach that border router; combine to get next hop. Example: prefix 18.0/16 via border E; IGP path to E via C; so forward to C.
- Trust: ASes cannot fully trust others' advertisements (misconfig or malice); filter, accept only expected prefixes per neighbour.
- Table size: global table exceeded 1 million prefixes by 2025; CIDR aggregation keeps it from being worse.
- Replaced EGP, which assumed a tree topology.

### IPv6 (4.2)
- 128-bit addresses (3.4 x 10^38). Classless. Header fixed at 40 bytes.
- Header fields: Version (6), TrafficClass, FlowLabel (both QoS), PayloadLen (excludes header), NextHeader, HopLimit (renamed TTL), Source (16B), Destination (16B).
- NextHeader replaces IPv4 Protocol and options. Extension headers appear in fixed order; routers mostly only look at NextHeader. Values: 6 = TCP, 44 = fragmentation header, 51 = authentication header.
- Fragmentation is an extension header, not in base header (routers do not fragment in v6; sources do, with path MTU discovery).
- No header checksum, no options limit (IPv4 options max 44 bytes).
- Address prefix assignments: 0...0 (128) unspecified; 0...1 loopback (::1); 1111 1111 (ff00::/8) multicast; 1111 1110 10 (fe80::/10) link-local unicast; everything else global unicast (allocation currently from 001 block, about 87% reserved).
- Notation: eight 16-bit hex groups; one run of zeros may be written `::` once only. Mapped form: `::FFFF:128.96.33.81` (IPv4-mapped); IPv4-compatible = zero-extended IPv4.
- Provider-based aggregation (like CIDR): provider gets a prefix, hands longer prefixes to subscribers; renumbering needed on provider change.
- Multihomed subscribers: no perfect answer. Options: take prefix from one provider (the other cannot aggregate); number from both (half the site unreachable on failure); three-prefix scheme for providers sharing many customers.
- Stateless autoconfiguration (SLAAC): (1) interface ID unique on link, derived from 48-bit MAC (link-local = fe80 prefix + zeros + ID); (2) prefix learned from router advertisements on the link. Needs no DHCP server.
- Routing header: list of nodes/areas to visit (source-directed, provider selection).
- Anycast: one address on a set of interfaces; packet goes to the nearest.
- Transition: no flag day. Hosts are IPv4-only, dual-stack, or IPv6-only for a long time. IPv4 gained most IPv6 features (security, QoS, mobility) so address space is the real driver.

### Multicast (4.3)
- Models: ASM (any source, many-to-many, original) and SSM (receiver names (S,G), one-to-many). Group = abstract address, dynamic membership; sender need not be a member.
- Host to router signalling: IGMP (IPv4) and MLD (IPv6). Router polls periodically to expire dead members.
- IPv4 multicast = class D (28 usable bits); Ethernet multicast has 23 bits; low 23 bits copied, so 32 IP groups share one MAC; IP must filter in host. Switch IGMP snooping mitigates.
- Multicast forwarding tables describe trees, not paths. Keyed by group (and source for SSM).
- DVMRP (flood-and-prune, distance-vector): Reverse Path Forwarding (RPF) = accept/forward a packet only if it arrived on the interface on the shortest path back to the source. Elect one parent router per LAN (lowest cost to source, ties by lowest address) to stop duplicates. Leaf networks without members are pruned; prune state propagates up with group info.
- PIM (Protocol Independent Multicast): uses whatever unicast routing exists. Dense mode = flood-and-prune; sparse mode (PIM-SM) is dominant.
- PIM-SM mechanics:
  1. Each group has a rendezvous point (RP); all routers in the domain agree on it.
  2. Receiver's router sends a wildcard Join toward the RP; each router on path installs (*,G) state, adds incoming interface to outgoing list, and forwards Join until it hits existing tree.
  3. Sender's designated router (DR) encapsulates data in a PIM Register message unicast to the RP; RP decapsulates onto the shared tree.
  4. RP sends source-specific Join toward the sender, building (S,G) state so the DR can send native multicast (no tunnel).
  5. Optional switch to shortest-path tree: receiver router sends (S,G) Join toward the source when traffic rate is high. Routers stay on the shared tree for new senders.
  - State trade-off: shared tree = state per group; source trees = per sender per group but shorter paths.
- MSDP: joins PIM-SM domains by peering the RPs over TCP; floods Source Active messages (source, group, originating RP) via RPF; an RP with receivers sends a source-specific Join to the source. Needed because PIM-SM's single RP violates domain autonomy.
- PIM-SSM: "channel" = (S,G); host sends IGMPv3/MLDv2 report with source; router Joins toward source; no RP, no MSDP, can be used across domains, reduces attack risk, group addresses reusable (SSM range).
- BIDIR-PIM: bidirectional shared tree; no source registration, no source-specific state, RP is just a routable address (need not be a router); traffic goes only as far up the tree as needed; within a domain only.

### MPLS (4.4)
- Label swapping with IP control plane. Labels are short, fixed-length, locally significant; 4-byte shim header inserted between L2 and L3 header (or in ATM VPI/VCI). Labels can be stacked to any depth.
- Uses: (1) IP on devices that cannot forward IP (ATM, optical, GMPLS); (2) explicit routes; (3) VPNs. Performance is NOT a current reason.
- Terms: Label Edge Router (LER) does full IP lookup and pushes label; Label Switching Router (LSR) forwards by exact-match label lookup; FEC (forwarding equivalence class) = set of packets getting the same treatment; one label per FEC.
- Destination-based: each router allocates a label per prefix and advertises (label, prefix) bindings with LDP (Label Distribution Protocol). Packet to 18.1.1.5: LER matches 18.1.1, pushes remote label 15; next router looks only at label, swaps 15 for 24, forwards. Exact match, not longest-prefix match. Path equals what IGP would pick.
- Benefit of MPLS-on-ATM vs overlay: fewer routing adjacencies (1 instead of N), edge routers see full topology.
- Explicit routing: label paths set up by RSVP (RSVP-TE) along a chosen path, like a virtual circuit. Used for traffic engineering ("fish" topology example: R1-R3-R6-R7 and R2-R3-R4-R5-R7) and fast reroute (precomputed backup path avoiding link L). CSPF (constrained shortest path first) computes paths meeting constraints such as 100 Mbps available.
- VPNs: MPLS is a 4-byte tunnel header (vs 20-byte IP). Layer 2 VPN/pseudowire: head router adds a demux label (identifies emulated circuit) then a tunnel label; transit LSRs use only the tunnel label; tail strips and uses the demux label. Layer 3 VPN: provider-run MPLS network gives each customer a private IP network with overlapping addresses; tunnels configured by BGP.

### Mobile IP (4.5)
- Entities: mobile node, correspondent node, home network/address, home agent (router on home network), foreign agent (optional), care-of address (CoA; usually the foreign agent address, or a DHCP address when the node is its own foreign agent, "co-located").
- Agent advertisements announce presence; node registers via foreign agent to home agent.
- Delivery to mobile: (1) home agent intercepts with proxy ARP and gratuitous ARP; (2) tunnels (IP-in-IP) to the CoA; (3) foreign agent strips header and delivers to the mobile's hardware address.
- Mobile to fixed: normal routing, source = home address.
- Triangle routing problem: path correspondent -> home -> mobile is longer than direct. Fix: home agent sends binding update; correspondent keeps a binding cache and tunnels directly; stale entries trigger binding warning; entries expire.
- Security: someone can claim to be the new foreign agent for your node; registration needs authentication.
- Mobile IPv6: no foreign agent; every host can get an address; optimised path uses a routing header carrying the home address instead of a tunnel (cheaper).
- Open issues: power use, ad hoc networks, sensor networks.

## Common pitfalls / anti-patterns

- Assuming BGP picks the "best" path: it picks policy-preferred, not lowest-cost, and cannot compare metrics across ASes.
- Accepting customer/peer advertisements unfiltered (leaks, hijacks).
- Re-advertising routes from one provider to another (accidental transit for free).
- Redistributing the full BGP table into an IGP.
- Using areas without noticing forced detour via area 0.
- Assuming 100% address utilisation when sizing; forgetting to plan renumbering for provider-assigned space.
- Treating IPv6 as IPv4 with bigger numbers: no router fragmentation, extension header ordering, SLAAC and router advertisements matter.
- IPv4 multicast to Ethernet mapping: 32:1 aliasing means hosts see unrelated groups.
- PIM-SM across domains without MSDP/SSM; single RP as a dependency or bottleneck.
- Mobile IP: stale binding caches; unauthenticated registration; triangle routing.
- Using MPLS to chase forwarding speed.

## Quick reference

- Which routing protocol where: IGP (OSPF/IS-IS/RIP) inside an AS; BGP-4 between ASes; iBGP inside an AS for external prefixes only.
- OSPF area roles: backbone = area 0; ABR = in area 0 and another area; ASBR = injects external routes; virtual link = tunnel to area 0.
- BGP update contents: withdrawn routes, path attributes (including AS path), reachable prefixes (NLRI).
- BGP session health: TCP connection + keepalives; lose keepalives, routes learned from that peer are invalidated.
- Route-advertising matrix (typical):
  - learned from customer: advertise to customers, peers, providers.
  - learned from peer: advertise to customers only.
  - learned from provider: advertise to customers only.
- IPv6 special prefixes: ::/128 unspecified, ::1/128 loopback, fe80::/10 link-local, ff00::/8 multicast, 2000::/3 global unicast allocation block (the book's "001").
- IPv6 vs IPv4 header: 40 bytes fixed vs 20+options; no checksum; no router fragmentation; NextHeader chain.
- Multicast protocol picker: IGMP/MLD host to router; DVMRP/PIM-DM dense flood-and-prune; PIM-SM sparse with RP; PIM-SSM one-to-many (S,G); BIDIR-PIM many-to-many in one domain; MSDP links PIM-SM domains.
- PIM state names: (*,G) shared tree rooted at RP; (S,G) source tree rooted at sender.
- MPLS terms: LER, LSR, FEC, LDP (destination-based labels), RSVP-TE (explicit paths), CSPF (path computation), label stack, shim header.
- Mobile IP terms: home address, home agent, foreign agent, care-of address, proxy ARP, gratuitous ARP, binding update, binding cache, binding warning, triangle routing.

## Relevance to managing a small OpenWrt router network

- IPv6 prefix delegation: ISP gives a PD prefix (often /56 or /60); router carves /64s per LAN and advertises via router advertisements (SLAAC) and optionally DHCPv6. Link-local fe80::/10 addresses are normal; do not filter ICMPv6 (NDP needs it).
- Provider-based addressing means prefixes change when ISP changes or lease renews; use ULA (fc00::/7) for internal stable addressing and avoid hard-coding GUAs.
- Multicast on home LAN: IGMP/MLD snooping on bridges, `igmpproxy` or `mcproxy` for IPTV; mDNS/SSDP are link-local multicast and do not cross subnets without a reflector.
- A home router is a stub AS in effect: single default route toward the ISP; BGP is irrelevant unless running a VPS/overlay with BIRD; for site-to-site, WireGuard replaces IP tunnels and MPLS.
- Remember that Mobile-IP-style roaming is not needed; use DHCP lease plus app reconnect, or WireGuard (roaming endpoint) for a stable identity.
