---
source: Peterson & Davie, Computer Networks: A Systems Approach (6th ed), chapter dir e2e/ ; https://github.com/SystemsApproach/book (commit 5deec5e)
license: CC BY 4.0, (c) Larry Peterson and Bruce Davie. Summarised/condensed by an AI agent; not the original text.
---

# Chapter 5: End-to-End Protocols (e2e/)

Sections: 5.1 UDP, 5.2 TCP, 5.3 RPC (SunRPC, DCE-RPC, gRPC), 5.4 RTP/RTCP, plus perspective "HTTP is the new narrow waist".

## Key ideas

- Transport job: turn host-to-host best-effort packet delivery into process-to-process channels. Network may drop, reorder, duplicate, limit size, and delay arbitrarily; apps want guaranteed, ordered, at-most-once, large-message, flow-controlled, multiplexed delivery.
- Four representative services: simple demultiplexer (UDP), reliable byte stream (TCP), request/reply (RPC), real-time (RTP).
- End-to-end argument: a function should not be built into lower layers unless it can be completely and correctly done there. Hop-by-hop reliability does not add up to end-to-end reliability (nodes corrupt or reorder). Low-level partial help (per-hop CRC) is acceptable as an optimisation.
- Smart sender / dumb receiver rule: TCP receiver only answers segments; sender drives (zero-window probes, retransmit timers).
- Flow control (protect the receiver) vs congestion control (protect the network). Different mechanisms.
- Application Level Framing (ALF, Clark and Tennenhouse): the application knows its needs best; RTP leaves details to profile/format documents.
- Window/rate duality: rate = window / RTT (10 packets, 100 ms RTT = 100 packets/s).
- Narrow waist drift: HTTP + TLS + TCP + IP is now the shared platform (HTTP gives URIs and GET/PUT, redirects, caches, adaptive streaming; TLS security; TCP congestion control).
- Differences between link-level sliding window and TCP: explicit connection setup/teardown, varying RTT (adaptive timeout), packet reordering and maximum segment lifetime (MSL, recommended 120 s), variable receiver resources (flow control), unknown path so congestion is possible.

## Principles and rules of thumb

- Pick UDP when you need message boundaries, minimal latency, multicast, or you do your own reliability (DNS, RTP, QUIC, games, VPN tunnels like WireGuard).
- Pick TCP for reliable bulk or interactive byte streams; it is the most tuned protocol and brings congestion control for free.
- Request/reply over TCP costs at least 9 packets for a tiny exchange (3 setup, 2 data, 4 teardown); irrelevant for large transfers.
- Reliable streaming over real-time: retransmission arrives too late, so real-time apps tolerate loss and conceal it.
- Do not run many parallel TCP connections to beat congestion control; each runs its own loop (QUIC streams solve this properly).
- Window needed = delay x bandwidth. 100 ms RTT: 1.5 Mbps = 18 KB; 45 Mbps = 549 KB; 100 Mbps = 1.2 MB; 10 Gbps = 118 MB. 16-bit window (64 KB max) is not enough above roughly 5 Mbps at 100 ms without window scaling.
- Sequence-number wrap time (32 bits): 1.5 Mbps = 6.4 h; 100 Mbps = 6 min; 10 Gbps = 3 s; must be longer than MSL (120 s), hence timestamps/PAWS.
- Make idempotent RPCs where possible; then at-most-once machinery is unnecessary.
- Keep headers small for small real-time packets (audio packets are short to limit packetisation delay).
- Reuse proven solutions (HTTP/TLS/TCP) instead of reinventing RPC, security, congestion control.

## Techniques and protocol mechanics

### UDP (5.1)
- Header: SrcPort, DstPort (16 bits each), Length, Checksum. Demux key = (port, host). Up to 64K ports per host.
- Well-known ports: DNS 53, SMTP 25, port mapper 111. `/etc/services` lists them. Alternative: single well-known port mapper that returns the port for a service.
- Port implemented as a message queue; full queue drops silently; no flow control; receiver blocks when empty.
- Checksum = ones' complement sum of 16-bit words over UDP header, body, and pseudoheader (protocol number, source IP, destination IP, UDP length). Detects misdelivery. Optional in IPv4, mandatory in IPv6.

### TCP header and segment (5.2.2)
- Fields: SrcPort, DstPort, SequenceNum (32 bits, number of first byte in segment), Acknowledgement (next byte expected), HdrLen (offset, 32-bit words), Flags (SYN, FIN, RESET, PUSH, URG, ACK), AdvertisedWindow (16 bits), Checksum (with pseudoheader, mandatory in IPv4 and IPv6), UrgPtr, Options.
- Demux key: 4-tuple (SrcPort, SrcIPAddr, DstPort, DstIPAddr). Reuse of the same 4-tuple = new incarnation.
- Byte-oriented: TCP buffers bytes into segments; no record boundaries preserved.

### Connection establishment (three-way handshake)
1. Client to server: SYN, SequenceNum = x.
2. Server to client: SYN+ACK, SequenceNum = y, Ack = x+1.
3. Client to server: ACK, Ack = y+1.
- Ack means "next expected", so x+1. Initial sequence numbers are random to avoid confusion with old incarnations. Timers retransmit SYN and SYN+ACK. If the third ACK is lost, first data segment (with ACK set) completes it.
- Setup is asymmetric (passive open on server: LISTEN; active open on client). Teardown is symmetric: each side closes its own direction (half-close is possible).

### State machine
- Open: CLOSED -> (passive open) LISTEN -> (SYN rcvd) SYN_RCVD -> ESTABLISHED; client CLOSED -> SYN_SENT -> ESTABLISHED.
- Close paths: closing first: ESTABLISHED -> FIN_WAIT_1 -> FIN_WAIT_2 -> TIME_WAIT -> CLOSED. Other side closes first: ESTABLISHED -> CLOSE_WAIT -> LAST_ACK -> CLOSED. Simultaneous: FIN_WAIT_1 -> CLOSING -> TIME_WAIT -> CLOSED.
- TIME_WAIT lasts 2 x MSL (120 s per book), so a delayed FIN from an old incarnation cannot kill a new connection on the same ports.
- After retries fail, TCP gives up and returns to CLOSED. All sliding-window activity hides inside ESTABLISHED.

### Sliding window with flow control (5.2.4)
- Sender pointers: LastByteAcked <= LastByteSent <= LastByteWritten. Receiver: LastByteRead < NextByteExpected <= LastByteRcvd + 1.
- Receiver: `AdvertisedWindow = MaxRcvBuffer - ((NextByteExpected - 1) - LastByteRead)`.
- Sender: `EffectiveWindow = AdvertisedWindow - (LastByteSent - LastByteAcked)` must be > 0 to send. Also `LastByteWritten - LastByteAcked <= MaxSendBuffer`, else application write blocks.
- Slow reader -> receive buffer full -> window 0 -> sender buffer full -> writer blocks.
- Zero Window Probe: while window is 0 the sender sends 1 byte of real data every 5-60 s to get a fresh window (receiver never sends unsolicited non-data segments).
- Window scaling option left-shifts the 16-bit field; negotiated at SYN time.

### Triggering transmission (5.2.5)
- Send when: MSS bytes collected (MSS = MTU minus IP and TCP headers), application PUSH, or timer (Nagle self-clocking).
- Silly window syndrome: tiny windows or tiny segments circulate forever. Fixes: receiver, after advertising zero window, must wait for MSS of space before reopening; delayed ACKs can coalesce (partial); sender uses Nagle.
- Nagle's algorithm: if data >= MSS and window >= MSS, send a full segment; else if unACKed data in flight, buffer until ACK; else send immediately. Interactive apps disable it with socket option TCP_NODELAY.

### Adaptive retransmission (5.2.6)
- Original: `EstimatedRTT = a*EstimatedRTT + (1-a)*SampleRTT` (a 0.8-0.9), `TimeOut = 2*EstimatedRTT`.
- Karn/Partridge (1987): never sample RTT on retransmitted segments; double the timeout on each retransmission (exponential backoff).
- Jacobson/Karels (1988): `Difference = SampleRTT - EstimatedRTT; EstimatedRTT += delta*Difference; Deviation += delta*(|Difference| - Deviation); TimeOut = mu*EstimatedRTT + phi*Deviation` with delta = 1/8, mu = 1, phi = 4. Integer implementation uses shifts by 3. RFC 6298 specifies it.
- Coarse clocks (500 ms) hurt; the timestamp option fixes it.

### Record boundaries (5.2.7)
- TCP does not keep them. Tools: URG/UrgPtr (out-of-band), PUSH flag, but apps normally add a length prefix or delimiter.

### Extensions (options, negotiated at SYN) (5.2.8)
- Timestamps (32-bit; echoed by receiver; RTT measurement; no clock sync needed).
- PAWS: timestamp acts as high 32 bits to guard sequence wraparound.
- Window scale: shift count for AdvertisedWindow.
- SACK: receiver reports non-contiguous blocks; sender retransmits only gaps. Without SACK: pessimistic (retransmit everything after loss) or optimistic (one segment per RTT) strategies, both poor.

### Alternatives (5.2.10)
- SCTP: message-oriented, partially ordered, multihoming.
- Multipath TCP: multiple paths/addresses, reassembles in order for the app (hard to get right).
- QUIC (Google 2012, IETF): runs over UDP so middleboxes pass it; combines transport and TLS handshake (fast setup, 1 RTT versus about 3 for TCP+TLS); connection ID survives network changes (Wi-Fi to cellular); multiple streams in one connection avoid head-of-line blocking; keeps TCP-like congestion control; HTTP/3 uses it.
- Rate-based vs window-based: duality above.
- TCP performance: copy overhead, buffers, bandwidth-delay product matter more than protocol limits.

### RPC (5.3)
- Components: RPC protocol (message exchange) plus stub compiler (marshalling). Remote method invocation (RMI) = RPC on objects.
- Identifiers: procedure name space (flat vs hierarchical) and message ID to match reply to request. Boot ID (incremented each reboot, in nonvolatile storage) prevents a rebooted client's reused message ID from being treated as a duplicate.
- Reliability: ACK plus RETRANSMIT timer; reply is implicit ACK of the request, next request implicit ACK of the reply. Channels (concurrent logical channels) multiplex sequential transactions; channel ID in each message.
- "Are you alive?" / "I'm alive" pings distinguish slow server from dead server (server-initiated is more scalable).
- Semantics: at-most-once (server remembers last sequence number per channel; "at most" since failures can mean zero) vs zero-or-more (fine only for idempotent operations).
- Fragmentation in the RPC layer with selective ACK recovers lost fragments faster than IP reassembly.
- Synchronous vs asynchronous send: how much the sender knows when send returns; reliable datagram protocol sits in between.
- SunRPC (ONC RPC): 32-bit program number, 32-bit procedure number (plus version); NFS program x00100003 with procedures getattr 1, setattr 2, read 6, write 8. Port Mapper (program x00100000, port 111) / RPCBIND maps program to port; client caches. XID matches replies; no memory of past XIDs so no at-most-once; relies on underlying transport for reliability and size; Credentials/Verifier fields for auth.
- DCE-RPC: at-most-once by default; activity (channel) with ActivityId, SequenceNum, ServerBoot; Request/Response/Ack, Ping/Working, Quit/Quack, Reject, Nocall; fragments with FragmentNum (16 bits), Fack carrying cumulative number, SelAck bit vector (example: got 0-20, 23, 25, 26 -> Fack 20 plus bits 3, 5, 6), SelAckLen, WindowSize in fragments (TCP-like flow and congestion control). Basis of DCOM and CORBA.
- gRPC: for cloud services (call goes to a service; load balancer picks a container), runs over HTTP/2 over TLS over TCP; method as URI path, Protocol Buffers payload (`content-type = application/grpc+proto`), headers like grpc-timeout, grpc-encoding, grpc-status. Four patterns: simple, server streaming, client streaming, bidirectional streaming. Control items: Error/Status, Timeouts, PING, EOS, GOAWAY.

### RTP/RTCP (5.4)
- Requirements: negotiate coding scheme, timing (playback buffer for jitter), multimedia sync, loss indication, congestion feedback, frame/talkspurt boundary marking, friendly sender identity, small header.
- RTP normally over UDP; RTP uses even port, RTCP the next odd port. Profile (field semantics per application class) plus payload format.
- Header (12 bytes minimum): Version (2 bits, = 2), P padding, X extension, CC (4-bit CSRC count), M marker (profile-specific, e.g. talkspurt start), Payload Type (7 bits), Sequence number (increments by 1; RTP only detects loss, application decides what to do), Timestamp (tick counter of first sample; units set by profile; e.g. 125 us samples and 10 ms gap = 80 ticks), SSRC (32-bit random source ID), optional CSRC list (mixers list contributing sources).
- Payload type is not a demux key; separate media streams use separate UDP ports.
- RTCP functions: performance feedback, correlate/sync streams (CNAME such as user@host ties different SSRCs; sender report gives wall-clock time vs RTP timestamp), sender identity.
- Packet types: sender report (SR), receiver report (RR), source description (SDES, carries CNAME), application-specific. Each lower-layer PDU carries at least a report and an SDES.
- Report blocks: SSRC, fraction lost since last report, cumulative lost, extended highest sequence number, interarrival jitter, last SR timestamp, delay since last SR.
- RTCP traffic is limited to about 5% of the data bandwidth and scales back as participant count grows (more share for active senders).

## Common pitfalls / anti-patterns

- Confusing flow control with congestion control.
- Assuming a hop-by-hop reliable link means end-to-end reliable.
- Forgetting window scaling on high bandwidth-delay paths; 64 KB window caps throughput at window/RTT.
- Nagle plus delayed ACK interactions causing latency spikes for small writes; use TCP_NODELAY where latency matters.
- Treating TCP as message-oriented (no boundaries; need framing).
- Opening many TCP connections to grab bandwidth.
- RPC retries with non-idempotent operations and no duplicate suppression (SunRPC-style zero-or-more).
- Reusing message IDs after reboot without a boot ID.
- Sampling RTT on retransmits (Karn problem).
- Expecting RTP to retransmit or control congestion; it does neither.
- Killing TIME_WAIT by hand or shortening MSL without understanding old-incarnation risk.
- Using the RTP payload type to demultiplex streams.

## Quick reference

- Transport pick: UDP (datagram, 8-byte header, no state); TCP (stream, 20+ byte header, 3-way handshake); RPC (request/reply with IDs and retries); RTP (UDP + timestamps + sequence numbers + RTCP feedback); QUIC (UDP-based, streams, built-in TLS).
- TCP handshake flags: SYN (x) -> SYN+ACK (y, ack x+1) -> ACK (ack y+1).
- Teardown: FIN, ACK, FIN, ACK; initiator ends in TIME_WAIT for 2 x MSL.
- TCP sender formula set: EffectiveWindow = AdvertisedWindow - (LastByteSent - LastByteAcked); AdvertisedWindow = MaxRcvBuffer - ((NextByteExpected - 1) - LastByteRead).
- Throughput ceiling of window W at RTT R is W / R (64 KB at 100 ms = about 5.2 Mbps without window scaling).
- Timeout formula: TimeOut = EstimatedRTT + 4 x Deviation (mu = 1, phi = 4); back off x2 per retransmit; ignore RTT samples from retransmissions.
- TCP header options worth knowing: MSS, window scale, SACK-permitted/SACK, timestamps.
- RPC semantics: at-most-once (DCE-RPC default) vs zero-or-more (SunRPC); idempotent calls may use the cheaper one.
- RTP header at a glance: V=2, P, X, CC, M, PT(7), seq(16), timestamp(32), SSRC(32), optional CSRCs. RTCP share about 5% of session bandwidth.
- Pseudoheader checksum covers: source IP, destination IP, protocol number, length; protects against misdelivery (UDP and TCP).
- Well-known examples from the text: DNS 53, SMTP 25, SunRPC port mapper 111, talk 517.

## Relevance to managing a small OpenWrt router network

- MSS clamping: MSS = MTU minus IP and TCP headers (1500 - 20 - 20 = 1460 for IPv4, 1440 for IPv6); on PPPoE (MTU 1492) clamp to 1452. In OpenWrt firewall zone for WAN set `option mtu_fix '1'` (MSS clamping) to avoid black-holed large packets when path MTU discovery is blocked.
- NAT/conntrack tracks TCP states (TIME_WAIT, ESTABLISHED) and UDP flows with timeouts; long-idle UDP (VoIP, WireGuard keepalive) needs `persistent_keepalive` ~25 s to keep NAT mappings.
- UDP checksum is mandatory in IPv6; do not disable it in tunnels.
- SACK, timestamps, window scaling should stay enabled (`net.ipv4.tcp_sack`, `tcp_timestamps`, `tcp_window_scaling`) on Linux/OpenWrt; some middleboxes that strip options hurt throughput.
- QUIC runs over UDP/443: do not rate-limit or block UDP 443 blindly; fq_codel/cake treat it as flows by 5-tuple.
- RTP/VoIP: prioritise by DSCP EF (46) and port range; keep jitter low (see chapter 6).
- Port forwards: well-known ports are just conventions; match 4-tuples carefully in firewall rules.
