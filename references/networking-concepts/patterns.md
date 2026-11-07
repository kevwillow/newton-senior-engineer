---
source: Peterson & Davie, Computer Networks: A Systems Approach (6th ed); https://github.com/SystemsApproach/book (commit 5deec5e)
license: CC BY 4.0, (c) Larry Peterson and Bruce Davie. Condensed by an AI agent from the chapter summaries; not the original text.
---

# Design patterns and rules of thumb

Cross-chapter, decision oriented. Each line ends with the chapter that grounds it.

## Architecture
- Keep the common layer minimal (narrow waist); innovate above and below it. (ch01)
- Smart endpoints, simple forwarding core; add network help only when endpoints cannot do it. (ch01)
- Separate control plane from data plane and scale them independently. (ch03)
- Declare intent for the whole network rather than editing devices one by one; automate at scale. (ch01, ch09)
- Learn rather than configure where safe (learning bridges, ARP, DHCP); entries age out so changes self-heal. (ch03)
- KISS first, iterate from operational experience. (ch03)

## Addressing and routing
- Aggregate: contiguous power-of-two aligned prefixes summarise to one route; no per-host state in routers. (ch03, ch04)
- Addresses belong to interfaces, not hosts. (ch03)
- IGP for networks inside a domain, BGP for paths between domains; never dump the BGP table into the IGP. (ch04)
- Stub site with one exit: default route only. (ch04)
- Provider-assigned prefixes force renumbering on provider change; plan for it. (ch04)
- Layer 2 does not scale: split broadcast domains with VLANs, route beyond tens of switches. (ch03)
- Spanning tree gives loop freedom, not shortest or load-balanced paths. (ch03)
- Static link metrics beat dynamic load metrics (oscillation). (ch03)
- Avoid fragmentation; use PMTUD and clamp MSS; initial TTL about 64. (ch03)

## Transport and performance
- Window must be at least delay x bandwidth or throughput collapses to window/RTT. (ch02, ch05)
- Small transfers are latency bound; large ones are bandwidth bound; bandwidth grows, latency does not. (ch01)
- TCP for reliable bulk/interactive; UDP for message boundaries, minimal latency, own reliability. (ch05)
- Do not open many parallel TCP connections to dodge congestion control. (ch05)
- Idempotent operations remove the need for at-most-once machinery. (ch05)
- AIMD: gentle increase, aggressive decrease. (ch06)
- Early random drop (RED/ECN) beats tail drop; one drop per RTT is enough. (ch06)
- FIFO tail-drop lets non-adaptive flows steal capacity; per-flow fair queuing isolates. (ch06)
- Strict priority needs a cap and policing or it starves the rest; prefer weighted queuing. (ch06)
- Edge marks and polices, core only applies per-hop behaviour; bound EF load below the slowest link. (ch06)
- Admission control beats degrading everyone for inelastic traffic like VoIP. (ch09)
- On a constrained uplink, QoS on the upstream direction is where it matters. (ch09)

## Security
- Default deny; keep rules simple; stateful filtering for return traffic. (ch08)
- A firewall only works if it is the only path in; also cannot protect inside-to-inside. (ch08)
- Exposed services go in a DMZ that cannot reach the inside. (ch08)
- Symmetric crypto for bulk, public-key for authentication and key setup; short-lived session keys. (ch08)
- Encryption is not integrity: use AEAD or add a MAC; never ECB; avoid MD5/SHA-1. (ch08)
- Defend against replay with nonces/timestamps/challenge-response. (ch08)
- Verify the server identity out of band on first contact (SSH host key fingerprint). (ch08)
- Prefer per-user credentials (802.1X) over a shared Wi-Fi PSK. (ch08)
- Patch: breaches use old known bugs; crypto and firewalls do not fix unpatched hosts. (ch08)

## Applications and naming
- Cache at every layer; revalidate with conditional requests. (ch09)
- Use indirection (CNAME, SRV/MX, proxies) so servers move without changing names. (ch09)
- Two or more name servers per zone, local caching resolver. (ch09)
- Consistent hashing when the node set changes. (ch09)
- Overlays deploy new functionality without router vendor cooperation. (ch09)
- Never respond to loss with codec redundancy; reduce bitrate. (ch07, ch09)

## Anti-patterns
- Assuming a missing reply means failure (may be latency). (ch01)
- Raising MTU/window blindly without checking the path. (ch03, ch05)
- One broadcast domain for everything on many switches. (ch03)
- Unpoliced self-marked priority traffic. (ch06)
- Manual per-device config at scale. (ch01)
- Running a firewall with a second unfiltered path (wireless, VPN, spare uplink). (ch08)
