---
source: Peterson & Davie, Computer Networks: A Systems Approach (6th ed), chapter dir foundation/ ; https://github.com/SystemsApproach/book (commit 5deec5e)
license: CC BY 4.0, (c) Larry Peterson and Bruce Davie. Summarised/condensed by an AI agent; not the original text.
---

# Chapter 1: Foundation (requirements, layering, performance)

## Key ideas

### Three stakeholders, three requirement lists
- Application programmer: wants services (delivery guarantees, ordering, mobility across connections).
- Network operator: wants easy administration (fault isolation, easy device add/config, usage accounting).
- Network designer: wants cost-effective design (efficient, fair resource use, performance).
- Most of this book is the designer view; the operator view is the one that matters for running a router.

### Network defined recursively
- Network = 2+ nodes joined by a physical link, OR 2+ networks joined by a node.
- Link: physical medium between nodes. Point-to-point (exactly 2 nodes) vs multiple-access (shared by >2; Wi-Fi, cellular, old Ethernet bus). Multiple-access links are limited in distance and node count, so they are typically the "last mile".
- Switched network: nodes attached to 2+ links run forwarding software. Two kinds: circuit switched (telephone: dedicated circuit set up first) and packet switched (computer networks).
- Switch = node inside the cloud that forwards. Host = node outside the cloud that uses the network. Router/gateway = node connecting 2+ networks (same role as a switch, one level up).
- internet (lowercase) = any internetwork; Internet (capital) = the TCP/IP global one. An internet is itself a network, so you can build internets of internets. This recursion was the fundamental Internet innovation.
- Cloud icon = any network of any technology (single link, multi-access, or switched).

### Address, routing, and cast types
- Address: byte string identifying a node. Routing: systematically deciding how to forward toward a destination based on its address.
- Unicast = one destination; broadcast = all nodes; multicast = a subset. Networks need address forms for all three.

### Multiplexing
- Multiplexing = one resource shared by multiple flows. Demultiplexing = splitting back out at the far end.
- STDM (synchronous time-division): equal time quanta round robin. FDM: each flow gets a frequency. Both waste capacity when a flow is idle, and both need a fixed, known number of flows.
- Statistical multiplexing: send on demand, packet by packet; no reserved slots. This is why packet switching is efficient.
- Bound on how much one flow sends at once = the packet (max size). Larger application message = message, which is fragmented into packets and reassembled at the receiver.
- Store-and-forward: a switch receives the whole packet, stores it, then forwards it.
- Per-packet scheduling policy: FIFO or round-robin across flows. Allocating bandwidth to particular flows = quality of service (QoS).
- Congestion: arrival rate exceeds the outgoing link rate; the switch buffers; when buffer is exhausted, packets are dropped.

### Channels and the semantic gap
- A channel = logical process-to-process pipe built on host-to-host connectivity. Application chooses the channel type that matches its needs.
- Example channel types: request/reply (reliable, exactly one copy delivered, maybe confidential/integrity-protected) and message stream (ordered, loss tolerated, one-way/two-way, multicast, delay-parameterised).
- Semantic gap = difference between what the application expects and what the underlying network gives. Channels fill it.
- "Bit pipe" design: keep switches dumb (just forward), put rich semantics in end hosts. The alternative (smart network, dumb end devices, like a telephone) is a recurring tradeoff. The Internet chose the first.
- Pitfall named in the text: with only a hammer (too few channel types), everything looks like a nail.

### Failure classes
1. Bit errors (1 flips to 0, often as burst errors). Rates: roughly 1 in 10^6 to 10^7 bits on copper, 1 in 10^12 to 10^14 on fibre. Causes: lightning, power surges, microwave ovens.
2. Packet loss: uncorrectable bit error, or (more likely) congestion drop; occasionally a software bug forwarding wrongly. Hard part: telling "lost" from "merely late".
3. Node/link failure: cut fibre, crash, power loss, misconfiguration. Hard part: telling "failed" from "slow", and "cut link" from "flaky link with many bit errors". Packet-switched nets can route around failures.

### Manageability
- Stability vs feature velocity is the core tension. "Don't touch what works" favours stability; cloud-style operation pushes for velocity plus automation.
- Scale (configuring thousands of routers) is why automation is required; one router is already an expert task.

### Layering, protocols, architecture (vocabulary to know exactly)
- Abstraction hides implementation behind an interface; layering stacks abstractions. Benefits: decomposes the problem; modular (change one layer, reuse the rest). Real systems are a graph, not a line (several alternative abstractions per level).
- Protocol: has two interfaces. Service interface (to other objects on the same machine) and peer interface (message form and meaning exchanged with the counterpart on another machine).
- Protocol specification = the abstract definition; protocol implementation = the module. Two implementations that follow the spec correctly interoperate.
- Protocol graph: nodes are protocols, edges mean "depends on". Protocol stack = a path through the graph (e.g. RRP/HHP).
- Network architecture = the set of rules governing the form and content of a protocol graph.
- Peer-to-peer communication is indirect except at the hardware level: each protocol hands messages to the one below.

### Encapsulation
- Each layer treats what it gets from above as an opaque payload and prepends its own header (rarely a trailer: control info at the end). Headers are a few bytes to a few dozen bytes.
- On receipt, each layer strips its own header, acts on it, and passes the body up. Upper layer sees exactly what the peer sent.
- Switches and routers on the path inspect only the headers at their own layer.
- A low-level protocol may transform the whole body (compress or encrypt, including upper-layer headers) without "interpreting" it.

### Demultiplexing key (demux key)
- Header field naming the next-higher protocol or application. Examples of sizes: 8-bit (256 protocols max), 16-bit, or 32-bit.
- Some protocols use one demux field (same key both sides), others a pair (each side picks its own). No uniform agreement across protocols.
- Ports (TCP/UDP) are demux keys for processes.

### OSI 7-layer reference model (terminology still used)
| # | Layer | Unit / job |
|---|-------|-----------|
| 7 | Application | HTTP etc. |
| 6 | Presentation | data format (integer size, byte order, video format) |
| 5 | Session | ties together transport streams of one application (e.g. audio plus video) |
| 4 | Transport | process-to-process channel; unit = message; end hosts only |
| 3 | Network | routing among nodes; unit = packet |
| 2 | Data link | bits grouped into frames; NIC plus driver |
| 1 | Physical | raw bits over a medium |
- Layers 1-3 run on every node, including switches/routers. Layer 4 and up run only on end hosts.
- OSI is a reference model, not a deployed stack. No OSI-based network runs today.

### Internet (TCP/IP) architecture
- Stack: various network technologies (Ethernet, 802.11, point-to-point) / IP / TCP or UDP / application protocols (HTTP, FTP, SMTP, Telnet).
- Mapping: application = L7, transport = L4, IP = L3, link/subnet = L2.
- TCP = reliable byte stream. UDP = unreliable datagram (datagram is a synonym for message). Both called end-to-end or transport protocols.
- Three highlighted properties:
  1. Not strict layering: applications may bypass transport and use IP or the link directly.
  2. Hourglass shape: wide top (many apps, many transports), narrow waist (IP only), wide bottom (many link technologies). Host-to-host delivery is fully separated from process-to-process service.
  3. IETF rule: a protocol needs a specification plus at least one (preferably two) working implementations. "Rough consensus and running code."
- Application vs application protocol: many browsers and many servers interoperate because they all speak the same HTTP.
- Bodies: IETF (TCP, UDP, IP, DNS, BGP), IEEE (802.3 Ethernet, 802.11 Wi-Fi), W3C (HTTP/HTML), 3GPP (cellular), IANA/ICANN (identifier assignment).

## Principles and rules of thumb

- Narrow waist: keep the common layer minimal so both sides can evolve independently. When adding a feature, ask whether it belongs at the waist (rarely) or above or below.
- Prefer statistical multiplexing for bursty traffic; accept that it brings congestion and fairness problems you must then handle.
- Put intelligence at end hosts unless there is a reason not to; keep forwarding nodes simple.
- Define channel semantics by asking: must delivery be guaranteed? ordered? duplicate-free? private? multicast? bounded delay?
- Do not assume a missing reply means a failure: it may be lateness, a slow node, or a flaky link.
- Stability vs velocity: pick deliberately; automate config at scale; avoid manual per-device edits when many devices exist.
- Working code beats paper spec for interop.
- Bandwidth-bound vs latency-bound rule:
  - Small transfers (1 byte, a keystroke) are latency bound: time is about RTT; link speed barely matters.
  - Large transfers (25 MB image) are bandwidth bound: RTT is negligible.
  - Medium objects (2 KB) depend: link speed matters on low-RTT paths, not on 100 ms paths.
- On high-speed paths, latency not bandwidth dominates design: 1 RTT vs 2 RTT is a 100% difference for a small file.
- Latency to remember: bandwidth rises, speed of light does not. A 1 Gbps transcontinental link still has about 100 ms RTT.
- Audio/video: care about jitter and peak/burst rate, not just average rate. Receiver playback buffer absorbs known jitter bounds; you need bounds, not zero jitter.
- Human-factors figures: about 300 ms round trip is the tolerable upper bound for a phone call; about 100 ms sounds very good. Streaming video can tolerate seconds of start-up delay; real-time cannot.

## Techniques / mechanics

### Latency model
- Latency = Propagation + Transmit + Queue
- Propagation = Distance / SpeedOfLight
- Transmit = Size / Bandwidth
- Queue = time waiting in switch buffers (variable; source of jitter)
- Speeds: 3.0e8 m/s vacuum, 2.3e8 m/s copper, 2.0e8 m/s fibre.
- Single bit on a single link: only propagation matters.
- Bit time on a link = 1 / bandwidth (10 Mbps: 0.1 microsecond per bit; 1 Mbps: 1 us; 2 Mbps: 0.5 us).
- Bandwidth (capacity, bits/s; also literally Hz of frequency band, e.g. voice 300-3300 Hz = 3000 Hz) vs throughput (measured, usually lower; e.g. 2 Mbps measured on a 10 Mbps link) vs application bandwidth requirement.

### Delay x bandwidth product (DxB)
- DxB = bits "in the pipe" = pipe volume. Length = latency, diameter = bandwidth.
- Usually use RTT x bandwidth: how much a sender can transmit before it can possibly hear back; also how much arrives after the receiver says "stop".
- If sender stops to wait for an ack before sending a full RTT x bandwidth, the link is under-used. This is the basis of window sizing in later chapters.
- Worked: 50 ms one-way x 45 Mbps = 2.25 Mbit (about 280 KB); RTT version 5.5 Mbit (about 671 KB).
- Reference table (RTT x bandwidth):
  - Wireless LAN: 54 Mbps, 50 m, 0.33 us RTT, 18 bits.
  - Satellite: 1 Gbps, 35,000 km one-way, 230 ms RTT, 230 Mb.
  - Cross-country fibre: 10 Gbps, 4,000 km, 40 ms RTT, 400 Mb.

### Effective throughput
- TransferTime = RTT + TransferSize / Bandwidth (RTT covers request plus first byte back)
- Throughput = TransferSize / TransferTime
- Worked: 1 MB over 1 Gbps with 100 ms RTT: 8 ms transmit + 100 ms = 108 ms, so 74.1 Mbps effective, not 1 Gbps.
- Each extra RTT (retransmit, handshake) hurts small transfers most. Large transfers approach link bandwidth.
- On 1 Mbps, a 1 MB file spans 80 RTTs at 100 ms (1.25% per RTT); on 1 Gbps it is under 1/12 of one RTT's pipe (DxB 12.5 MB). Analogy: 1 MB file on 1 Gbps = 1 KB packet on 1 Mbps.

### Application bandwidth example
- Uncompressed video 352x240, 24-bit colour: 247.5 KB per frame; at 30 fps the book quotes about 75 Mbps required.
- Compressed video is variable rate. Average over interval hides bursts; a channel engineered for 2 Mbps cannot absorb 3 Mb in one second. Specify peak rate, burst size, and averaging interval.

### Jitter
- Jitter = variation in per-packet delay; observe as variable inter-packet gap at the receiver (sender spacing 33 ms for 30 fps).
- Comes from variable queuing in multihop packet networks, not from a single link.
- Fix: playback buffer delay >= (max latency - min latency).

### Web page fetch message count (illustrates protocol layering cost)
- Up to 6 messages for DNS lookup, 3 for TCP setup, 4 for HTTP GET plus ack, 4 for TCP teardown: over a dozen messages per click.

### Socket API (end-host interface)
- Socket = the point where a process attaches to the network. API gives syntax; protocol gives services.
- socket(domain, type, protocol): domain PF_INET (Internet), PF_UNIX, PF_PACKET (raw interface access bypassing TCP/IP); type SOCK_STREAM (byte stream/TCP) or SOCK_DGRAM (message/UDP).
- Server (passive open): bind(addr, port) -> listen(backlog) -> accept() (blocks, returns a NEW socket per connection; original keeps listening).
- Client (active open): connect(remote addr) (returns when TCP established); OS picks an ephemeral local port.
- Data: send() and recv(). Well-known server port (example uses 5432; web uses 80). Binding to INADDR_ANY means accept on any local IP.
- Ports are demux keys.

## Common pitfalls / anti-patterns

- Confusing bandwidth with throughput; quoting link rate as achievable rate.
- Assuming a faster link fixes a latency-bound problem (small requests, chatty protocols, many sequential RTTs).
- Judging transfer time without the RTT term; forgetting setup handshakes.
- Sizing buffers or windows below RTT x bandwidth (under-utilises link) or ignoring burst size (drops).
- Treating the layered model as strict: applications and tools (raw sockets, PF_PACKET) can bypass layers; real traffic does not fit neat boxes.
- Treating OSI as how the Internet is built; the session and presentation layers have no real counterpart there.
- Declaring "link down" when it may only be slow or flaky (many CRC errors); declaring "packet lost" when it may be late.
- Too few channel abstractions forcing misfit semantics ("everything is a nail").
- Averages without burst/jitter bounds for real-time traffic.
- Manual one-off changes that cannot scale; ignoring misconfiguration as a leading failure source.
- Confusing a protocol (spec) with a module (implementation), or application with application protocol.

## Relevance to managing a small OpenWrt router network

- Layering: when debugging, walk L1 (cable/link LED, `ethtool`) -> L2 (bridge, VLAN, ARP) -> L3 (IP, route) -> L4 (ports/firewall) -> L7 (DNS, HTTP). Fault isolation is operator requirement number one.
- Failure classes map to counters: `ip -s link` shows errors (bit errors/CRC), drops (congestion); a flaky cable looks like loss, not a clean down.
- Latency vs bandwidth: a fast WAN link will not speed up many small DNS/HTTP exchanges; look at RTT with `ping`/`mtr`. Use DxB to size SQM/queue targets; bufferbloat is queue delay (the Queue term) growing; `sqm`/`fq_codel` limits it and reduces jitter for VoIP/video.
- Statistical multiplexing and QoS: the WAN uplink is the shared link; per-flow fairness and class priority are the OpenWrt QoS/SQM knobs.
- Management: prefer scripted/templated config (UCI exports, version control) over hand edits; test before applying on remote routers (stability vs velocity).
