---
source: Peterson & Davie, Computer Networks: A Systems Approach (6th ed); https://github.com/SystemsApproach/book (commit 5deec5e)
license: CC BY 4.0, (c) Larry Peterson and Bruce Davie. Condensed by an AI agent from the chapter summaries; not the original text.
---

# Cheatsheet

## Which transport
| Need | Use |
|---|---|
| reliable bulk or interactive stream | TCP |
| message boundaries, low latency, multicast, own reliability, tunnels | UDP (DNS, RTP, QUIC, WireGuard) |
| web with fewer RTTs, no TCP head-of-line blocking | QUIC/HTTP3 |
| real-time voice/video | RTP over UDP |

## Numbers worth remembering
| Item | Value |
|---|---|
| Ethernet MTU | 1500 bytes; min frame 64; max 1518 (1522 with 802.1Q tag) |
| VLAN ID | 12 bits, 1-4094 |
| IPv4 header | 20 bytes minimum; TCP 20; UDP 8; MSS 1460 on MTU 1500 |
| PPPoE MTU | 1492 (clamp MSS to 1452) |
| IPv6 minimum MTU | 1280 |
| Initial TTL | 64 typical |
| Window needed | delay x bandwidth (100 ms RTT: 18 KB @1.5 Mbps, 1.2 MB @100 Mbps, 118 MB @10 Gbps) |
| TCP 16-bit window | 64 KB max; need window scaling above about 5 Mbps at 100 ms |
| Sequence wrap (32 bit) | 6 min @100 Mbps, 3 s @10 Gbps; MSL 120 s so timestamps needed |
| Phone call delay | about 100 ms very good, 300 ms RTT upper tolerable |
| Stop-and-wait throughput | frame size / RTT |
| AES | 128/192/256-bit key, 128-bit block |
| Collision resistance | 2^(n/2) for n-bit hash |

## Latency or bandwidth bound?
- 1 byte or keystroke: RTT decides. 2 KB: depends on RTT vs link. 25 MB: link speed decides.

## Switching decisions
| Situation | Do |
|---|---|
| separate trust zones on shared switch | VLAN per zone, tagged trunk, untagged access ports |
| more than a few dozen switches in one segment | route, not bridge |
| redundant L2 links | enable STP/RSTP; remember blocked links carry nothing |
| unknown L2 destination | switch floods; ARP/neighbor resolves L3 to L2 |

## Routing decisions
| Situation | Do |
|---|---|
| stub site, one uplink | default route |
| several internal networks | static routes or OSPF |
| multi-homed to ISPs | BGP (or policy routing for small sites) |
| change of ISP with PA prefix | renumber; use ULA plus PD for internal stability on IPv6 |

## QoS and congestion
| Symptom | Likely cause / fix |
|---|---|
| latency spikes when link saturated | bufferbloat: shape slightly below link rate with fq_codel/cake (SQM) |
| one flow hogs link | FIFO tail drop; use per-flow fair queuing |
| VoIP breaks on slow uplink | prioritise upstream, admission-limit calls |
| starvation of best effort | strict priority without cap; use weights |
| bursts dropped | buffer above RED max threshold |

## Security quick rules
- Firewall: default deny, stateful, DMZ for exposed services, one choke point.
- Wi-Fi: WPA2/WPA3, per-user 802.1X when possible, PMF on.
- VPN: modern AEAD; WireGuard or IPsec with short-lived session keys.
- Auth: nonces for replay; verify host keys out of band.
- Hashes: SHA-2/3 only. Never ECB. Use AEAD.

## DNS and DHCP
| Item | Note |
|---|---|
| record types | A, AAAA, CNAME, MX, NS, PTR, TXT, SOA |
| TTL | short (about 20 s) only for fast redirection, long to cut load |
| name servers | at least two per zone |
| DHCP | scope per network; keep lease logs; relay across routers |
