# references/ index

**Authoritative OpenWrt text: `openwrt/source/*.txt`.** Raw DokuWiki exports of the nine OpenWrt pages,
pulled by the maintainer in a browser on 2026-10-03 (unmodified below a one-line header). The `openwrt/*.md` files are
condensed summaries made earlier through a bot wall; use them to find your way, then quote values from
`source/`. DokuWiki markup: `====== H ======` headings, `<code>` blocks, `''inline''`, `^ header ^` / `| cell |` tables.

> **Before acting on anything here:** these docs show plain `uci commit` and service restarts.
> When changing a live device, never do that. Write the change as `uci batch` and run it through
> the change protocol in `../SKILL.md` (`scripts/owrt-change.sh`). Where a reference disagrees
> with a fact marked **(verified)** in SKILL.md, SKILL.md wins.


On-demand reference docs for the network-engineer-agent skill (OpenWrt 25.12, fw4/nftables, DSA, ubus/uci, dnsmasq/odhcpd, wpad). Retrieval date 2026-10-03.

| File | Source | License | Use |
|---|---|---|---|
| openwrt/uci.md | openwrt.org/docs/guide-user/base-system/uci | CC BY-SA 4.0 | UCI syntax and CLI workflow |
| openwrt/network.md | .../network/network_configuration | CC BY-SA 4.0 | /etc/config/network: devices, interfaces, protocols, bridge options |
| openwrt/dsa-vlans.md | .../network/dsa/start, dsa-mini-tutorial, converting-to-dsa, vlan/switch_configuration | CC BY-SA 4.0 | bridge-vlan, port flags, swconfig conversion |
| openwrt/firewall.md | .../firewall/firewall_configuration | CC BY-SA 4.0 | fw4 defaults, zones, forwardings, rules, sets, includes |
| openwrt/port-forwards.md | firewall_configuration (redirect) and .../fw3_configurations/fw3_nat | CC BY-SA 4.0 | DNAT/SNAT/masquerade/NPT recipes |
| openwrt/dhcp-dns.md | .../base-system/dhcp | CC BY-SA 4.0 | dnsmasq, odhcpd, static leases, DNS records |
| openwrt/wifi.md | .../network/wifi/basic | CC BY-SA 4.0 | wireless config, encryption, roaming, VLAN per PSK |
| openwrt/mwan3.md | .../wan/multiwan/mwan3 | CC BY-SA 4.0 | multi-WAN (iptables era, flagged LEGACY on 25.12) |
| openwrt/packages-apk.md | .../additional-software/apk and /opkg | CC BY-SA 4.0 | apk usage, opkg as LEGACY |
| nftables/quick-reference.md | wiki.nftables.org Quick_reference-nftables_in_10_minutes | GFDL 1.3+ | nft syntax, matches, statements |
| nftables/sets.md | wiki.nftables.org Sets | GFDL 1.3+ | sets, maps, verdict maps |
| nftables/nat.md | wiki.nftables.org Performing_Network_Address_Translation_(NAT) | GFDL 1.3+ | nft NAT |
| nftables/scripting.md | wiki.nftables.org Scripting | GFDL 1.3+ | nft files, includes, atomic reload |
| networking-concepts/index.md, glossary.md, patterns.md, cheatsheet.md | derived from Peterson & Davie, Computer Networks: A Systems Approach, 6th ed (github.com/SystemsApproach/book @ 5deec5e) | CC BY 4.0 | concepts, design rules, quick numbers |
| networking-concepts/chapters/ch01..ch09-*.md | same book, per chapter | CC BY 4.0 | per-chapter mechanics and rules |
| network-diagnostic.md | original Newton runguide, written from a live run on 2026-10-04 | MIT (same as SKILL.md) | speed, latency, LAN and Wi-Fi diagnostic: load-test script, run order, how to read the numbers |

## Provenance and accuracy
- nftables files: converted mechanically from the wiki's MediaWiki source (a few table cells may be imperfectly formatted).
- openwrt files: the wiki is behind an Anubis bot challenge, so pages were fetched with WebFetch, which returns a model-condensed markdown version; they were condensed again. Option names and config blocks were kept, but treat values as "verify on the live page". A few small additions from general knowledge (uci revert/rename, `bridge vlan show`, opkg-to-apk mapping, uci form of a port forward, common interface options) are marked in-line or noted here.
- networking-concepts: chapter summaries are AI-written condensations, not book text. ch06 OpenWrt notes on fq_codel/cake and the cheatsheet MTU numbers (PPPoE 1492 etc.) come from general knowledge, not the book.

## LICENSES (share-alike)
- The full licence texts are in `LICENSES/` at the repository root (REUSE layout, official texts); `REUSE.toml` assigns one to every file; `NOTICE.md` lists the obligations.
- OpenWrt wiki content: CC BY-SA 4.0 (https://openwrt.org/license). openwrt/*.md are adaptations. If the skill is published you must: keep the attribution header ("(c) OpenWrt contributors" and source URL), indicate changes were made (headers do), and release these files, and any derivative you build from them, under CC BY-SA 4.0 or a compatible licence. This share-alike applies to the adapted files; keep them in their own folder with their notices so original code/instructions in SKILL.md stay under your own licence.
- nftables wiki: GNU Free Documentation License 1.3 or later. nftables/*.md are modified versions: keep the GFDL notice, credit the wiki, state the modifications, and distribute them under GFDL terms. Do not merge GFDL and CC BY-SA content into one file; keep each under its own notice.
- Book (CC BY 4.0): attribution only; keep the headers, link the source, state that the text is condensed. Not endorsed by the authors.
- Mixed bundle: publish with this README and per-file headers intact. The skill's own SKILL.md and scripts are not covered by these licences as long as they only link to, and do not copy from, these files.
- This is a practical summary, not legal advice.
