---
source: Peterson & Davie, Computer Networks: A Systems Approach (6th ed), chapter dir applications/ ; https://github.com/SystemsApproach/book (commit 5deec5e)
license: CC BY 4.0, (c) Larry Peterson and Bruce Davie. Summarised/condensed by an AI agent; not the original text.
---

# Chapter 9: Applications

## Key ideas

- Applications are part network protocol, part program. Anyone writing a network application is also a protocol designer.
- Distinguish application **programs** (browser, mail reader) from application **protocols** (HTTP, SMTP, IMAP). Published protocols let many programs interoperate.
- Many app protocols have a **companion format standard**: SMTP + RFC 822/MIME; HTTP + HTML. This keeps the protocol simple.
- HTTP/SMTP are request/reply protocols that reinvent simple RPC over TCP; general RPC (REST, SOAP, gRPC) is now built on top of HTTP.
- Four classes covered: traditional (email, Web, web services), multimedia (SDP/SIP/H.323, RTP), infrastructure (DNS, SNMP/OpenConfig), overlays (routing overlays, P2P, CDNs).
- **Overlay network**: logical network on top of another; nodes are also in the underlay; links are tunnels; overlays can nest. Key Takeaway: **virtualization** (virtual networks from logical resources, stacked or coexisting). Overlay addressing need not be IP (URLs, names, content).
- **Name service**: name space (flat or hierarchical), bindings, resolution mechanism, name server. Key Takeaway: three identifier levels: domain name -> (DNS) IP address -> (IP forwarding) next-hop IP -> (ARP) physical address.
- Management trend: from SNMP polling (monitor-only) to model-driven, programmatic, zero-touch configuration (YANG models, OpenConfig, gNMI/NETCONF), closed control loop and declared intent.
- Perspective: cloud is the new Internet; overlays on commodity cloud sites (about 150+ well-connected locations) give instant wide footprint for multicast trees, conferencing, and DIY CDNs. Cloud native (micro-services) vs legacy web services in a VM; REST+JSON vs gRPC+Protobufs both run on HTTP.

## Principles and rules of thumb

- Use TCP when you need reliability, flow and congestion control (HTTP does); use UDP + app-level framing for latency-sensitive media.
- Cache at every layer (browser, site proxy, ISP, CDN) and let `Expires`/cache directives control freshness; revalidate with conditional GET.
- Use persistent connections / multiplexing to avoid per-object handshakes and repeated TCP slow start; QUIC removes TCP head-of-line blocking and merges transport and TLS setup (fewer RTTs).
- Use indirection for flexibility: `CNAME` aliases, `MX` records, SIP proxies/registrars, CDN redirectors let you move servers without changing user-visible names.
- Keep DNS TTLs short only where you need fast redirection (CDNs use about 20 s); longer TTLs cut load and latency.
- Run at least two name servers per zone; clients should use a local recursive resolver that caches.
- Overlays are the way to deploy new functionality (multicast, IPv6, resilient routing) without cooperation from router vendors or ISPs.
- Resilient/N x N routing overlays trade scalability for optimality: BGP scales but finds only some route (triangle inequality may fail; policy-driven); probing every pair works for a few dozen sites. One intermediate hop is usually enough to route around Internet failures (RON: 12 nodes, recovered from 32 outages in under 20 s on average).
- Consistent hashing, not modulo hashing, whenever the node set can change: only about 1/N of objects move.
- P2P/BitTorrent need incentives: peers that do not upload get **choked**.
- Multimedia with steep utility curve (VoIP) needs admission control: better to block one call than degrade two. 64 kbps codec x 2 calls overloads a 100 kbps uplink; no queuing trick helps.
- On residential/small-office links, DiffServ on the **upstream** link alone often fixes VoIP, because the slow constrained direction is the bottleneck.
- Do not respond to loss with extra codec redundancy; reduce bitrate.
- REST vs SOAP: REST reuses HTTP (stable, scales, caches, proxies, TLS, evolvable); SOAP/WSDL is better for wrapping legacy procedural interfaces. Interop in REST depends on agreement on the state representation only.
- Management: prefer standard transport (HTTP/gRPC) and published data models; configure as well as monitor; declare network-wide intent rather than per-device CLI edits.

## Techniques and protocol mechanics

### Email (SMTP, RFC 822, MIME, IMAP)
- **RFC 822**: ASCII message = header lines (`To:`, `From:`, `Subject:`, `Date:`, `Received:`; CRLF-terminated, `Type: value`) + blank line + body.
- **MIME** adds headers `MIME-Version`, `Content-Description`, `Content-Type` (e.g. `image/jpeg`, `text/plain`, `application/postscript`, `multipart/mixed` with a `boundary`), `Content-Transfer-Encoding`. **base64**: 3 bytes -> 4 ASCII chars (6 bits each; A-Z a-z 0-9 + /).
- Actors: mail reader (UA), **message transfer agent** (MTA; sendmail, postfix), **mail gateways** (store-and-forward, disk-buffered, retry for days). One SMTP/TCP session per hop.
- **SMTP dialog**: `HELO <domain>` -> 250; `MAIL FROM:<..>` -> 250; `RCPT TO:<..>` -> 250 (or 550 no such user, 251 will forward); `DATA` -> 354; message ends with line containing only `.` (`<CRLF>.<CRLF>`) -> 250; `QUIT` -> 221. `VRFY` checks an address. The **envelope** (MAIL/RCPT) is separate from the headers.
- **IMAP** (client/server over TCP): state machine; `LOGIN`, `FETCH`, `EXPUNGE`, `LOGOUT`; responses `OK`/`NO`/`BAD`; message flags `Seen`, `Answered`, `Deleted`, `Recent` keep client and server in sync; returns message in MIME. Sending still uses SMTP (your mail server is first gateway). POP is the simpler download protocol.

### Web (HTTP, URI, caching)
- **URL** = `scheme://host/path`; URI = scheme + scheme-specific part (`mailto:`, `file:`); URIs need not be locators (XML namespaces).
- HTTP message: `START_LINE CRLF`, header lines, blank line, body. Requests: `OPTIONS GET HEAD POST PUT DELETE TRACE CONNECT`. Common headers: `Host`, `If-Modified-Since`, `Expires`, `Location`, `Content-Length`, `Last-Modified`.
- Response codes: 1xx informational, 2xx success, 3xx redirection (301 moved permanently, 302 used by CDNs), 4xx client error (404), 5xx server error.
- **HTTP/1.0**: one TCP connection per object (2 RTTs setup per object). **HTTP/1.1**: persistent connections (server needs idle timeout; either side closing is a signal to close). **HTTP/2** (2015): server push + header compression, multiple concurrent **streams** with stream IDs over one TCP connection. **HTTP/3 over QUIC**: stream multiplexing in the transport (loss affects only one stream; congestion signal applies to all); transport + TLS handshake combined; version negotiation needed for years.
- **Caching**: browser, site proxy (explicit), ISP transparent cache. Server sets `Expires`; stale entries revalidated with `HEAD` or conditional `GET` + `If-Modified-Since`; cache directives govern what can be cached and how long.

### Web services
- **SOAP architecture**: WSDL (abstract operations, Message Exchange Patterns - in practice In-Only and In-Out - XML Schema message types, then a **binding**) + SOAP (Envelope, Header with header blocks, Body; features/modules; binding to HTTP). WS-I Basic Profile forces SOAP over HTTP POST; WS-Security uses X.509/Kerberos; WS-* extras. Stack is heavy.
- **REST** (Fielding): resources identified by URI, accessed via HTTP's few methods; payload = representation of resource state (XML or JSON); send partial state, pass by reference with URIs; reuse proxies, CDNs, TLS.
- Cloud services: cloud native = micro-services built for scalable platforms vs legacy services lifted into VMs.

### DNS
- Hierarchical names read right to left; tree partitioned into **zones** (administrative authority), each served by >= 2 name servers; root zone run under ICANN; over 1200 TLDs.
- **Resource record**: `(Name, TTL, Type, Class, Value)`; Class `IN`. Types: `A` (address), `NS` (name server for domain), `CNAME` (alias), `MX` (mail exchanger). (SIP/other lookups use further types such as SRV, not in this chapter.)
- **Resolution**: client asks local (recursive) server; it walks root -> TLD -> zone servers, each returning `NS` + glue `A` records until an authoritative answer; caches every answer for its `TTL`. Root server addresses are published out of band (the bootstrap). Partial names get the local domain appended. `dig www.example.com` shows answer; `dig +trace` shows the walk.
- Early system was a flat `HOSTS.TXT` maintained by the NIC; replaced in mid-1980s.
- X.500 -> LDAP for directory info about people.

### Network management
- **SNMP**: UDP request/reply; operations `GET`, `SET`, `GET-NEXT` (walk tables). Data defined by the **MIB** (MIB-II groups: System, Interfaces, Address translation, IP, TCP, UDP, ICMP, SNMP). Variable names are ASN.1 object IDs in dotted form, e.g. `1.3.6.1.2.1.4.3` = `ipInReceives` (1.3.6.1.2.1 = MIB-II, 4 = IP group, 3 = third variable); values encoded with ASN.1 BER.
- **OpenConfig / zero-touch**: configure programmatically; **YANG** data models (a restricted schema language, usable with XML, JSON, Protobufs); **gNMI** = gRPC network management interface over HTTP/Protobufs; NETCONF is the other option. SNMP is only a transport (monitoring); OpenConfig is a model effort covering monitoring and configuration.

### Multimedia session control
- **SDP**: ASCII `<type>=<value>` lines: `v=` version, `o=` origin, `s=` name, `i=` info, `u=` URI, `e=` email, `c=` connection (multicast address/TTL), `t=` times (NTP), `m=<media> <port> <transport> <format>` (e.g. `m=audio 49170 RTP/AVP 0`; AVP profile codes, 31 = H.261). Used with SAP (announce on multicast), SIP (calls), IPTV.
- **SIP** (HTTP-like request/response): functions user location, availability, capabilities, session setup, session management. Users identified by `sip:user@domain`; **proxy** and **registrar** (`REGISTER` binds address-of-record to contact address); proxies may **fork** requests (parallel or serial). Flow: `INVITE` (SDP body) -> `100 Trying` -> `180 Ringing` -> `200 OK` (SDP answer, negotiates codecs) -> `ACK` (can go direct, bypassing proxies) -> media over RTP (separate path; call survives proxy crash) -> `BYE` -> `200 OK`. Proxy to proxy found via DNS.
- **H.323** (ITU): terminals, **gatekeepers** (address translation, call admission), **gateways** (to PSTN), H.225 call control, **H.245** codec/port negotiation (RTP/RTCP ports). Complex.
- **Resource allocation**: RTCP reports loss/delay so the app can lower bitrate; DiffServ DSCP marking (voice media EF, signalling AF; public Internet usually ignores DSCP; enterprise and the upstream of home links honour it). **Admission control**: off-path (SIP proxy/gatekeeper counts calls; fails if anything bypasses it or topology is complex) vs on-path (RSVP: PATH then RESV). SIP and RSVP interleave: exchange codecs in the first SIP messages (SDP; PRACK acknowledges provisionally) -> RSVP PATH/RESV both directions -> updated SDP -> ring only after resources reserved.

### Overlays
- **Tunnels** with inner/outer headers (`IHdr`, `OHdr`); routers in between see only the outer header. VPN = overlay using IP tunnels and normal IP forwarding. MBone (IP multicast overlay), 6-BONE (IPv6 over IPv4) as deployment vehicles.
- **End System Multicast**: hosts form a **mesh** overlay (UDP tunnels), then run a standard multicast routing algorithm (DVMRP) on the mesh. Mesh maintained by membership lists (distance-vector style), "join mesh" to any known member, keepalives, "leave mesh", partition repair by new edge. Edge add: probe random non-neighbour j, add if `utility = sum over members of (CL-NL)/CL` (for those where new latency NL < current CL) exceeds threshold. Edge drop: `cost = max(# members i routes via j, # members j routes via i)`; drop lowest if under threshold. Simple alternative: static tree on cloud VMs.
- **RON**: N x N active probing of latency, bandwidth, loss; picks best path, usually via one intermediate node; ancestor of SD-WAN.
- **P2P**: pool resources, decentralized and self-organizing. Napster was a central index plus P2P download.
  - **Gnutella** (unstructured): flood `QUERY` (query ID + TTL) to neighbours; nodes remember QID and upstream neighbour to drop duplicates and reverse-route `QUERY RESPONSE`; then `GET`/`PUT`; `PING`/`PONG` probe neighbours. Simple but unscalable.
  - **Structured overlays / DHT** (Pastry-style): **consistent hashing**: `hash(ObjectName) -> ObjectID`, `hash(IPAddr) -> NodeID` in a shared 128-bit ID circle; object lives on numerically closest node; node join/leave moves few objects. Routing: forward to a node sharing a longer ID prefix (`Route(D)`: use leaf set if D in range, else `RouteTab[l,d]` where l = shared prefix length, d = next hex digit, else any numerically closer node with >= prefix). Routing table = rows per hex digit (32) x 16 columns; **leaf set** of numerically near nodes gives final delivery and robustness. Hops bounded by log16(N). Join = route "add node" message to closest ID, learn tables along the way. Pick physically nearby entries to keep latency within a small factor of direct. Replicate on leaf set. Same overlay can carry multicast trees.
  - **BitTorrent**: file split into **pieces**; a `.torrent` metainfo file has size, piece size, SHA-1 per piece, **tracker** URL; swarm ID = SHA-1 of the info; peer contacts tracker, gets partial peer list, opens TCP connections, handshake exchanges peer ID + swarm ID, then bitmaps of pieces; `have` messages as pieces complete; **random piece order**; **choke/unchoke** for tit-for-tat fairness and connection limiting. Trackerless mode: DHT of "peer finders" (160-bit IDs over UDP, shared across swarms); find peers by iteratively querying finders closest to the swarm ID, then register yourself with the closest ones.
- **CDN**: addresses first-mile (not fixable), last mile of server, server overload, and peering-point bottlenecks. **Surrogate** servers cache static content from **backend servers** (dynamic content still goes to origin); **redirectors** choose a surrogate. Goals: low response time, high **system throughput** (flash crowds, DDoS), locality (cache hit).
  - Mechanisms: DNS-based redirection (round robin or load/proximity aware; site granularity, with URL rewriting for object granularity; hierarchical DNS with about 20 s TTLs), HTTP redirect (extra RTT, redirector can be overloaded), proxy/choke-point interception.
  - Policies: round robin/random (even load, ignores proximity and locality), **hash URL deterministically** so all redirectors agree without coordination; modulo hashing causes mass reassignment; use **consistent hashing**; **CARP** style: score `hash(URL, server)` for each server, sort, take first with `Load < threshold`, spreading load evenly when a server fails and replicating hot pages as load rises. Proximity via measured response time as load, or by restricting candidates to same ISP / few AS hops.

## Common pitfalls / anti-patterns

- Opening one TCP connection per object (HTTP/1.0 behaviour); not handling idle-connection timeouts with persistent connections.
- Assuming ASCII-safe transport: sending binary through SMTP without MIME base64.
- Treating `550`/`251` and other SMTP codes as pass/fail only; ignoring envelope vs header sender difference (spoofing, forwarding).
- POST/redirect abuse (spam; open redirects); caching the wrong thing (no `Expires`, dynamic content cached).
- Very long DNS TTLs on records you may need to move; very short TTLs everywhere (load); a single name server per zone; confusing `CNAME` with address records; DNS answers trusted without authentication (cache poisoning).
- Using modulo hashing for server selection; flooding queries in P2P at scale; random P2P overlays assumed to find rare objects.
- Using SNMP `SET`/community strings carelessly (SNMP historically weak on config and auth), or hand-editing every device CLI instead of using models.
- Letting too many VoIP calls onto a thin uplink with only DiffServ and no admission control; assuming DSCP survives the public Internet.
- Off-path admission control that is bypassed by an unauthorized app; proxy/gatekeeper assumed to know routing.
- Redundant codec FEC in response to loss; serving video over TCP interactively.
- Treating overlays as free: N x N probing from millions of RONs could swamp networks; each overlay hop may add long-haul delay if nodes are not proximity-aware.
- SOAP over-engineering where simple REST suffices; REST for legacy procedural interfaces without mapping them to resources.

## Relevance to managing a small OpenWrt router network

- DNS: run dnsmasq/unbound as the local caching resolver (TTL cache, `CNAME`/local A records, `dig +trace` and `dig` for debugging); consider DoT/DoH upstream and DNSSEC validation; static `A`/host entries for lab hosts; split-horizon names for lan vs wan.
- Management: SNMP (snmpd package) or collectd/prometheus-node-exporter exposing counters like MIB `ifInOctets`; ubus/JSON-RPC and UCI are the model-based config analogue; script configs for consistency rather than editing each router by hand.
- VPN/overlay: WireGuard or OpenVPN tunnels are the "IP tunnel overlay" of this chapter (site-to-site, road-warrior); mesh overlays like Tailscale/Nebula/ZeroTier use the same ideas (NAT traversal, direct paths, relay fallback).
- QoS: apply SQM/cake or DSCP (EF voice, AF signalling) on the upstream WAN interface (the constrained direction) for SIP/VoIP and video calls; limit call count/uplink use since there is no admission control in plain DiffServ.
- Web/caching: a local caching proxy or DNS cache helps; TLS/HTTPS for LuCI; HTTP/3 clients need UDP 443 allowed through the firewall; mail relay (msmtp/postfix) for alerts uses SMTP submission with TLS.

## Quick reference: protocol cheat sheet

| Protocol | Transport | Key facts |
|---|---|---|
| SMTP | TCP | ASCII dialog `HELO/MAIL FROM/RCPT TO/DATA/QUIT`; store-and-forward gateways; envelope vs headers |
| IMAP | TCP | Remote mailbox access, flags, `FETCH/EXPUNGE`; send still via SMTP |
| MIME | n/a | `Content-Type`, `multipart`, base64 (3 bytes -> 4 chars) |
| HTTP/1.1 | TCP | Persistent connections, `GET/HEAD/POST/PUT/DELETE`, status 1xx-5xx |
| HTTP/2 | TCP | Streams multiplexed on one connection, push, header compression |
| HTTP/3 | QUIC (UDP) | Per-stream loss recovery, transport + TLS handshake combined |
| DNS | UDP/TCP (not stated in this chapter) | RR `(Name, TTL, Type, Class, Value)`: A, NS, CNAME, MX; zones; caching by TTL |
| SNMP | UDP | `GET/SET/GET-NEXT`; MIB-II; ASN.1 OIDs and BER |
| gNMI/OpenConfig | gRPC over HTTP | YANG models, Protobufs, config + monitoring |
| SDP | n/a | `v= o= s= c= t= m=` text lines describing a session |
| SIP | UDP/TCP | `INVITE/ACK/BYE/REGISTER`, proxies, registrar, SDP bodies |
| H.323 | n/a | Gatekeeper, gateway, H.225, H.245 |
| RTP/RTCP | UDP | Media transport and quality feedback (from earlier chapter) |
| BitTorrent | TCP (+UDP for DHT) | Swarm, tracker, pieces, choking |

## Quick reference: choosing a server-selection / placement scheme

1. Static, small, rarely changing server set: round robin DNS is enough (even load, ignores proximity).
2. Caches with cacheable URLs: hash URL to a server so cache hit rate stays high.
3. Set may change (failures, scaling): consistent hashing (circle) so only neighbours' load moves.
4. Need load awareness plus locality: CARP-style score ordering with a load threshold.
5. Need proximity: restrict candidates (same ISP / few AS hops) or use measured response time as "load".
6. Need fast failover: short DNS TTL (about 20 s) on redirect records, accepting more DNS queries.

## Quick reference: when to use which overlay or distribution approach

- Want multicast without router support: end system multicast on a mesh (or a static tree on cloud VMs).
- Want resilience for a few dozen sites: RON-style probing overlay (SD-WAN today), one intermediate hop usually enough.
- Want to find objects with no central index: DHT (structured) for guaranteed lookup in about log(N) hops; Gnutella flooding only for small or popular-content cases.
- Want to distribute one big file cheaply: BitTorrent-style swarm (every downloader uploads; random piece order; choking enforces fairness).
- Want low latency web delivery for many users: CDN with DNS/URL redirection and surrogate caches; dynamic content stays at origin.
- Want to deploy a new network feature (IPv6, multicast) before routers support it: tunnelled overlay (6-BONE, MBone pattern).
