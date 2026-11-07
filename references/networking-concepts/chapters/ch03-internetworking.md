---
source: Peterson & Davie, Computer Networks: A Systems Approach (6th ed), chapter dir internetworking/ ; https://github.com/SystemsApproach/book (commit 5deec5e)
license: CC BY 4.0, (c) Larry Peterson and Bruce Davie. Summarised/condensed by an AI agent; not the original text.
---

# Chapter 3: Internetworking (switching, bridges/VLAN/STP, IP, ARP, DHCP, ICMP, routing)

## Key ideas

### Switch, router, and the L2 vs L3 duality
- Switch = multi-input, multi-output device moving packets from an input to one or more outputs (star topology). Adding a host to a switch does not slow others (unlike shared media) if the switch has enough aggregate capacity.
- L2 switch (bridge) interconnects links of the same type using the link-layer header and flat MAC addresses. L3 router interconnects different network types using IP.
- A point-to-point Ethernet link is both a link (between L2 switches running spanning tree) and a network (between L3 routers running IP). Pick L2 if you want a single broadcast domain; pick L3 if you want hosts on different networks.
- Forwarding (data plane, per-packet table lookup) vs routing (control plane, distributed algorithms that build the tables). Forwarding table = prefix to outgoing interface plus next-hop MAC; routing table = prefix to next hop plus how it was learned. They are often separate structures.
- Network (physical, single technology) vs internetwork (logical network built from physical networks). Routers, once "gateways".

### Three switching models
1. Datagram (connectionless): every packet carries the full destination address; each switch looks it up; packets may take different paths; no setup; sender cannot know if the destination is up. Internet/IP, Ethernet bridges.
2. Virtual circuit (connection-oriented): setup phase installs VC-table entries (incoming interface, incoming VCI, outgoing interface, outgoing VCI) in each switch; VCI is link-local; data packets carry only a small VCI (fast index lookup, small header); at least 1 RTT before first data; failure breaks the circuit. Permanent VC (admin configured) vs switched/signalled VC. Examples: X.25, Frame Relay, ATM; mostly obsolete.
3. Source routing: header lists the output port per hop (rotate, strip, or pointer variants). Strict (every hop) vs loose (waypoints). IP has a source route option.
- Hop-by-hop flow control (X.25): buffers reserved per circuit at setup; circuit rejected if buffers are lacking.
- ATM: 53-byte cells (5-byte header + 48 payload; VPI 8 bits + VCI 16 bits; 8-bit CRC "HEC" over the header only). Fixed size eases hardware parallelism and bounds voice queuing delay; "cell tax" from header overhead and padding.

### IP service model
- Best effort, connectionless datagrams, unreliable: may lose, corrupt, reorder, or duplicate. Deliberately undemanding so it runs over any link technology; keeps routers simple. Higher layers must tolerate all four failure modes.
- Two heterogeneity answers: common packet format (with fragmentation/reassembly for differing MTUs) and a global address space (with ARP for differing physical addressing).
- Scaling answer: hierarchical aggregation (network part + host part; later CIDR prefixes).

### Hierarchical aggregation
- Key scaling principle: reduce the information stored in and exchanged between nodes. Routers carry network prefixes, not host entries. Subnetting and CIDR push this further.

## Principles and rules of thumb

- Do not put per-host state in routers; aggregate by prefix. Allocate contiguous, power-of-two aligned address blocks so they summarise as one prefix.
- IP addresses belong to interfaces, not hosts. A router has one address per attached network.
- Learn, do not configure, where possible: learning bridges (source-address learning) and ARP are self-populating, and entries time out so moves heal.
- Bridge table is an optimisation, not required for correctness: unknown destination = flood on all other ports.
- Avoid IP fragmentation: use path MTU discovery; fragments are fragile (loss of one fragment loses the datagram) and reassembly state is a denial-of-service vector.
- Set initial TTL around 64 (too high = long loops, too low = unreachable).
- Layer 2 does not scale: broadcast floods everywhere, spanning tree has no hierarchy; "tens of switches" is the practical limit. Use VLANs to split broadcast domains, and routers to go beyond.
- Spanning tree gives loop freedom but not shortest paths and not load-aware paths (traffic goes up the tree and back down; blocked links carry nothing).
- Link-state converges fast with modest traffic but needs memory per node; distance-vector is simple but converges slowly and can count to infinity; both only scale to "a few hundred nodes" per domain, hence hierarchy (areas, domains).
- Static metrics are the norm: use constant / link bandwidth. Dynamic load-based metrics oscillate (ARPANET lesson).
- KISS and iterate: ship a simple design and improve it from experience.
- DHCP: configure ranges per network, not addresses per host; but dynamic binding makes locating a misbehaving host harder (keep lease logs).
- Tunnels give controlled connectivity and security (with encryption), carry non-IP protocols, or bridge islands of a feature (e.g. multicast), at the cost of added header length (fragmentation risk), router CPU, and management overhead.
- Control plane and data plane are different problems; optimise and scale them independently.

## Techniques / protocol mechanics

### IPv4 header (32-bit words, top word sent first)
- Version (4 bits, value 4) first so later versions can reinterpret the rest.
- HLen (4 bits): header length in 32-bit words; 5 = 20 bytes with no options.
- TOS (8 bits): per-packet treatment (queue selection); definition changed over time.
- Length (16 bits): bytes, including the header; max datagram 65,535 bytes.
- Ident (16 bits), Flags (includes M = more fragments), Offset (13 bits, in 8-byte units): fragmentation fields.
- TTL (8 bits): decremented per hop, drop at 0 (originally seconds, now hop count).
- Protocol (8 bits): demux key; TCP = 6, UDP = 17.
- Checksum (16 bits): Internet checksum (ones' complement sum of 16-bit words, inverted) over the header only; packets failing it are discarded because the destination address may be corrupt. Must be recomputed at each hop because TTL changes (inference; the text only says it covers the header).
- SourceAddr, DestinationAddr (32 bits each); optional Options (rare; every implementation must handle them).

### Fragmentation and reassembly
- MTU = largest IP datagram a network can carry in a frame payload (Ethernet 1500, jumbo up to 9000 payload).
- Router fragments when the outgoing MTU is smaller than the datagram; all fragments share the same Ident; every fragment is a self-contained datagram; reassembly happens only at the destination host; fragments can be re-fragmented at smaller-MTU hops; missing fragment = whole datagram discarded and no recovery.
- Worked example: 1400 bytes data + 20-byte header over MTU 532: 512 data bytes per fragment (532 - 20). Fragment 1: M=1, Offset 0, 512 bytes. Fragment 2: M=1, Offset 64 (512/8), 512 bytes. Fragment 3: M=0, Offset 128, 376 bytes. Offsets count 8-byte units, so fragment data boundaries are multiples of 8.

### Addressing
- 32 bits, written dotted decimal. Original classes: A (leading 0; 7-bit network, 24-bit host, 126 networks, about 16 million hosts), B (leading 10; 14-bit network, 16-bit host, 65,534 hosts), C (leading 110; 21-bit network, 8-bit host, 254 hosts), D multicast, E unused. Reserved host values: all-0 (not valid host) and all-1 (broadcast). Class system wasted space (a 2-host network used a whole class C; 256 hosts forced a class B at 0.39% utilisation).
- Subnetting: one network number split across subnets using a subnet mask. Host test: (destination AND mask) == my subnet number then deliver directly, else send to default router. Example: 128.96.34.15 with mask 255.255.255.128 is in subnet 128.96.34.0; 128.96.34.139 is in 128.96.34.128, a different subnet. Outside the site, the whole thing looks like one network (128.96): aggregation.
- Router table entry with subnetting: (SubnetNumber, SubnetMask, NextHop), checked by (D AND mask) == subnet number; NextHop is an interface (deliver directly) or a router.
- CIDR (classless): prefix/length notation, any length. Example: class C networks 192.4.16 through 192.4.31 (16 contiguous, power of two) share the top 20 bits, written 192.4.16/20; a single /24 is 192.4.16/24. Providers get a block and advertise one aggregate (e.g. eight adjacent /24 customer prefixes sharing 21 bits become one /21).
- Longest prefix match: if several table entries match, the longest prefix wins (171.69.10.5 matches 171.69/16 and 171.69.10/24, choose /24; 171.69.20.5 only matches /16). A default route (all addresses, shortest prefix) catches the rest. Classic data structure: PATRICIA tree; TCAM in hardware.

### Host forwarding algorithm (basic)
1. If destination network equals one of my interface networks: deliver directly on that interface (ARP for the MAC).
2. Else if destination is in my forwarding table: send to that next hop router (ARP for the router's MAC).
3. Else send to the default router.
- Host with one interface: on-link (same subnet) go direct, otherwise default router.

### ARP (IP to link-layer address)
1. Host checks its ARP cache for the next-hop IP.
2. On miss, it broadcasts an ARP query containing the target IP plus sender's IP and MAC.
3. The host owning that IP replies (unicast) with its MAC.
4. Requester caches the mapping. Entries age out (about 15 minutes, book figure).
- Side effects: every receiver refreshes an existing entry for the sender; only the target host creates a new entry from the query (it will likely need to reply); non-targets do not add entries.
- Packet fields: HardwareType, ProtocolType, HLen, PLen, Operation (request/response), sender hardware address, sender protocol address, target hardware address, target protocol address.
- ARP resolves next hop only (host or router on the local network), never the final remote host.
- The forwarding table effectively has a MAC column from ARP.

### DHCP
1. Client broadcasts DHCPDISCOVER to 255.255.255.255 (UDP; routers do not forward it).
2. A DHCP server answers (or a relay agent on the network unicasts the request to the configured server and relays the reply). Server fills yiaddr (your IP) and options (default router, etc.); client identified by chaddr (hardware address).
3. Addresses are leased for a time and must be renewed; the server returns expired addresses to its pool.
- Modes: static table keyed by client hardware address, or dynamic pool from an administrator-defined range. Derived from BOOTP.
- Gives a host: IP address, default router, plus other options.

### ICMP
- Companion to IP; reports errors to the source: destination unreachable, reassembly failed, TTL reached 0, header checksum failed.
- ICMP-Redirect: router tells a host that a better first-hop router exists for a destination; host adds a route.
- Basis for ping (ICMP echo to test reachability) and traceroute (maps routers on the path; standard technique is probing with increasing TTL and reading the TTL-exceeded replies; the chapter leaves the details to an exercise).

### Tunnels / VPN
- IP tunnel = virtual point-to-point link between two routers. Entry router wraps the original packet in a new IP header (outer dst = far router address, outer src = entry router) and forwards it; the exit router strips the header and forwards the inner packet. Tunnel appears in the forwarding table as a virtual interface (e.g. "network 2 via virtual interface 0", default via physical interface 1). Can recurse (IP over IP).
- VPN = restricted connectivity across shared infrastructure; classic version used virtual circuits; IP version uses tunnels (plus encryption).

### Learning bridge / L2 switch
- Forwarding table maps MAC address to port. Learn from the source address of every received frame: record (src MAC, ingress port), reset its timer (example constants: max 1024 entries, 120 s TTL), update the port to the most recent. Table-full: stop adding (acceptable) or evict the oldest.
- Forwarding decision: if the destination is known and on the ingress port, filter (drop); if known on another port, forward there; if unknown or broadcast, flood out all other active ports. Behaviour is a datagram model.
- Early bridges flooded everything; a bridge is not a repeater (it runs full MAC on each port, so it breaks collision-domain limits; it operates in promiscuous mode).

### Spanning Tree Protocol (Perlman; IEEE 802.1)
- Problem: a loop causes frames to circulate forever (broadcast storm). Loops come from multi-admin mistakes and, more commonly, deliberate redundancy.
- Goal: pick a subset of ports forming a tree covering all switches. Rules: switch with the smallest ID is root; each switch finds its shortest path to the root (root port); on each segment the switch closest to root is the designated switch (ties broken by smaller ID); only root ports and designated ports forward.
- Configuration message (Y, d, X): X claims root Y at distance d. Everyone starts claiming to be root with distance 0.
- "Better" message on a port: smaller root ID; or equal root and shorter distance; or equal root and distance but smaller sender ID. Adopt it, add 1 to the distance before relaying. A switch that hears a better root stops originating messages; a switch that hears it is not designated on a port stops sending on it.
- Steady state: only the root originates periodic config messages; others relay on designated ports. Failure detected by missing messages; after a timeout switches claim root again and reconverge.
- Worked trace in the book (S3 learning root S2 then S1) uses (S2,0,S2) -> (S2,1,S3) etc.
- Broadcast: flood out every active tree port except the ingress. Multicast treated as broadcast in practice (pruning proposed, not widely adopted).
- Limits: not shortest path, no load balancing, linear scaling.

### VLAN (802.1Q)
- Partition one switched network into several virtual LANs; each switch port is configured with a VLAN ID (colour); frames only forward to ports in the same VLAN; the inter-switch trunk link carries both.
- Tag: 32 bits inserted between source MAC and the original Type field: first 16 bits = Type 0x8100 (marks tagged frame), then 4 bits control (priority), then a 12-bit VID, so 4096 VLANs. Switch adds the tag on ingress from an access port and enforces VLAN boundaries on egress.
- Benefits: limits broadcast domain; change logical topology by config, not rewiring. Limit: L2 switches only work between networks sharing the same address/header format (Ethernet and Wi-Fi yes; ATM, SONET, PON, cellular no).
- Inter-VLAN traffic still needs a router.

### Distance vector (Bellman-Ford; RIP)
- Each node keeps a vector of (destination, cost, next hop), tells only its direct neighbours everything it knows. Init: neighbours cost 1, others infinity.
- Update rule: for a route heard from neighbour with advertised cost c, new cost = c + (link cost); take it if it is lower than the current cost, or if it comes from the current next hop (metrics may have changed). Refresh route timers on reconfirmation; expire routes at TTL 0 (example 120 s).
- Updates: periodic (RIP every 30 s) plus triggered on change. Failure detection: missed periodic updates, or probing.
- Convergence = all nodes consistent. Count to infinity: after A loses its link to E, A, B and C keep raising each other's distance (4, 5, ...). Mitigations: small "infinity" (RIP: 16, valid costs 1-15, so max diameter 15 hops), split horizon (do not advertise a route back to the neighbour you learned it from), split horizon with poison reverse (advertise it back as infinity), hold-down/delay (slows convergence). These only fix two-node loops.
- RIP: metric = hop count (all links 1); RIPv2 packet is a list of (address, mask, distance) with address Family; v1 was classful; v2 added masks (and simple authentication).

### Link state (OSPF)
- Each node floods a link-state packet (LSP): node ID, list of (neighbour, cost), sequence number, TTL. Everyone gets everyone's LSP and builds the full graph, then runs Dijkstra.
- Reliable flooding: hop-by-hop ACK/retransmit; on receipt, if no stored copy or higher sequence number: store and forward on all links except the one received on; equal or lower sequence number: discard. Sequence numbers do not wrap (about 64 bits). Rebooted node restarts at 0 and learns its old sequence number from neighbours' copies, then increments. LSP TTL ages and is reflooded at 0 to purge it.
- Generated on periodic timer (long, hours) or topology change (link/neighbour down). Neighbour liveness by periodic hello packets.
- Dijkstra forward search with Tentative and Confirmed lists of (Destination, Cost, NextHop): (1) put myself in Confirmed at cost 0; (2) take the LSP of the node just added; (3) for each of its neighbours compute cost = my cost to it + link cost; add to Tentative if absent, or replace if cheaper (next hop = direction toward the just-added node); (4) if Tentative is empty stop, else move the cheapest to Confirmed and repeat. Result is the forwarding table. Memory cost is one LSP per node.
- OSPF additions: authentication (type 0 none, 1 8-byte password, 2 cryptographic), areas (hierarchy), equal-cost multipath load balancing, optional TOS-based metrics (rarely deployed). Header: Version 2, Type 1-5 (1 = hello; others request, send, acknowledge link-state), SourceAddr, AreaId (32 bits), 16-bit checksum (same algorithm as IP), auth type and auth data. LSA fields: LS Age, Type (1 = router links, 2 = networks), Link State ID = Advertising Router (32-bit router ID, e.g. lowest interface address, must be unique and stable), LS sequence number, LS checksum (excludes age), Length, then per link: Link ID, Link Data, metric, type.
- Comparison: DV = tell neighbours everything you know; LS = tell everyone only what you know for sure (your direct links). LS: faster, stable, more traffic efficient, more memory.

### Metrics (ARPANET lessons)
- Hop count ignores latency and capacity (a 250 ms satellite link equals 1 ms fibre; 1 Mbps equals 10 Gbps).
- Queue-length metric was bad (steers to shortest queue, not toward destination).
- Delay metric: Delay = (DepartTime - ArrivalTime) + TransmissionTime + Latency; oscillated under heavy load (traffic flees a congested link then returns), and range was too wide (9.6 kbps loaded looked 127 times worse than 56 kbps idle).
- Revised metric: compress dynamic range (loaded link at most 3x idle cost, most expensive link at most 7x cheapest), account for link type/speed, smooth over time (average utilisation, bounded change per cycle).
- Practice today: static metrics, constant x (1 / link bandwidth).

### Software vs hardware switches
- Software switch: general CPU with NICs; packet DMA'd into main memory, CPU reads the header only, DMA out. Limits: memory bandwidth (about 100 Gbps for a 1333 MHz, 64-bit bus) and per-packet cost (pps). Example: 40 Mpps x 64 bytes x 8 = about 20 Gbps shared; 16 ports gives roughly 1 Gbps per port. Worst case is minimum-size packets.
- Per-packet work is just a table lookup; STP/RIP/OSPF/BGP run in the background (control plane) and are not on the per-packet path (data plane).
- Hardware: ASIC or programmable NPU with SRAM buffers, TCAM (ternary match with wildcards), multi-stage match-action pipeline (P4); Tbps rates; same box can be configured as L2 switch, L3 router, or both. Pluggable transceivers (SFP+).
- SDN: standard control/data plane interface (OpenFlow, then P4), logically centralised controller (Network Operating System with a network map abstraction) over a disaggregated data plane. It is an implementation strategy; shortest-path computation still exists.

## Common pitfalls / anti-patterns

- L2 loops without STP: broadcast storm, switch table thrash; a cheap unmanaged switch cabled twice into the LAN is the classic case.
- One huge flat L2 domain: broadcast load, STP convergence, limited scale; fix with VLANs plus routing.
- Mismatched masks on hosts on the same segment (a host thinks a neighbour is off-link and sends it via the router, or vice versa).
- Overlapping or non-aggregable address plans (non-contiguous or non-power-of-two blocks) that defeat route summarisation.
- Forgetting longest-prefix match: a more specific route silently overrides a default or aggregate.
- Relying on fragmentation (or silently dropping the ICMP messages that PMTUD needs); extra tunnel/PPPoE headers pushing packets over the MTU.
- Assuming IP is reliable or ordered; duplicates and reordering happen.
- RIP on a network with paths over 15 hops; slow convergence and count-to-infinity after failures.
- Duplicate router IDs or unstable router IDs in OSPF; unauthenticated routing protocols accepting bad information from a misconfigured neighbour.
- Using dynamic load-sensitive metrics (route flapping).
- Treating DHCP leases as stable identifiers; two DHCP servers on one segment; forgetting that routers do not forward DHCP broadcasts (needs a relay).
- Stale ARP entries after a host moves or a NIC is replaced (about 15 minutes of stale mapping).
- VC state left behind after a failure when connection-oriented tunnels are used (teardown needed).

## Relevance to managing a small OpenWrt router network

- Bridge and VLAN: `br-lan` is a learning bridge (bridge fdb = the learned MAC table; stale entries after a device moves); 802.1Q VLANs on DSA ports use `bridge vlan` / `/etc/config/network` bridge-vlan sections (12-bit VID, tagged vs untagged ports, trunk to another switch/AP). Inter-VLAN traffic goes through the router, firewall zones decide what is allowed.
- STP: enable `stp` on the bridge only when there is a redundant L2 path; accidental second cable between two switches/APs is a loop; check `bridge link` for blocking/forwarding states.
- IP basics on the router: subnet masks and prefix lengths on each interface (e.g. 192.168.1.1/24), default route via the WAN, longest-prefix match visible in `ip route`; `ip neigh` is the ARP cache (reachable/stale/failed); avoid overlapping subnets across VLANs and VPNs.
- DHCP: dnsmasq serves leases per interface (range, lease time, static leases by MAC = the static-table mode); DHCP broadcasts do not cross routers or VLANs; lease logs help locate hosts.
- MTU/MSS: WAN PPPoE reduces MTU to 1492; WireGuard/IPsec/GRE tunnels reduce it further; set MSS clamping on the firewall zone and rely on ICMP "fragmentation needed" being allowed; avoid IP fragmentation.
- ICMP/diagnostics: `ping` (echo) and `traceroute` (TTL-exceeded) are the first tools; do not block ICMP wholesale in firewall rules.
- Routing: a small network normally needs only static routes and a default route; use OSPF (BIRD/FRR, link-state, areas, auth) or a mesh protocol only when there are multiple routers and redundant paths; RIP's 15-hop limit and slow convergence rarely matter at this size but static routes cannot react to link failure.
- Tunnels/VPN: OpenWrt WireGuard/IPsec/GRE interfaces are the "virtual interface" in the routing table, with the added-header and MTU costs described above.
