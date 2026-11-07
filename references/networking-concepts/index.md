---
source: Peterson & Davie, Computer Networks: A Systems Approach (6th ed); https://github.com/SystemsApproach/book (commit 5deec5e)
license: CC BY 4.0, (c) Larry Peterson and Bruce Davie. Condensed by an AI agent from the chapter summaries; not the original text.
---

# Networking concepts: index

Condensed reference derived from "Computer Networks: A Systems Approach". Use it for the WHY behind OpenWrt/nftables settings. Each chapter file ends its sections with a "Relevance to a small OpenWrt network" note.

| File | Topic | Frameworks / key content |
|---|---|---|
| [chapters/ch01-foundation.md](chapters/ch01-foundation.md) | layering, requirements, performance | narrow waist, end-to-end argument, statistical multiplexing, delay x bandwidth, latency- vs bandwidth-bound |
| [chapters/ch02-direct-links.md](chapters/ch02-direct-links.md) | encoding, framing, errors, Ethernet, Wi-Fi | CRC/checksum, sliding window, CSMA/CD, 802.11 CSMA/CA, rate adaptation |
| [chapters/ch03-internetworking.md](chapters/ch03-internetworking.md) | switching, IP, ARP, DHCP, ICMP, routing | learning bridges, spanning tree, VLANs, longest-prefix match, DV vs link-state, MTU/fragmentation |
| [chapters/ch04-advanced-internetworking.md](chapters/ch04-advanced-internetworking.md) | scale: CIDR, areas, BGP, IPv6, multicast, MPLS, mobility | hierarchy/aggregation, AS policy, IPv6 addressing and transition |
| [chapters/ch05-end-to-end-protocols.md](chapters/ch05-end-to-end-protocols.md) | UDP, TCP, RPC, RTP | handshake, sliding window, retransmit timers, UDP vs TCP choice |
| [chapters/ch06-congestion-control-qos.md](chapters/ch06-congestion-control-qos.md) | congestion, queueing, QoS | AIMD, slow start, FQ, RED/ECN, DiffServ, bufferbloat note |
| [chapters/ch07-end-to-end-data.md](chapters/ch07-end-to-end-data.md) | data formats, codecs | tagged vs untagged, XML/JSON/Protobuf, video frame types |
| [chapters/ch08-network-security.md](chapters/ch08-network-security.md) | crypto, auth, TLS/IPsec/SSH, firewalls | session keys, AEAD, PKI, default-deny, DMZ, 802.1X |
| [chapters/ch09-applications.md](chapters/ch09-applications.md) | HTTP, DNS, SMTP, SNMP, overlays, CDN | caching, indirection, consistent hashing, VoIP admission |
| [glossary.md](glossary.md) | terms | alphabetical definitions |
| [patterns.md](patterns.md) | design patterns and rules of thumb | cross-chapter |
| [cheatsheet.md](cheatsheet.md) | decision guides and numbers | quick lookups |

Reading order for an agent: need a number or a decision -> cheatsheet.md; need a term -> glossary.md; need the reasoning -> patterns.md; need mechanics -> the chapter.
