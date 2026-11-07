# NOTICE

Newton's own code, `SKILL.md`, `scripts/`, `references/README.md` and `references/network-diagnostic.md` are MIT (see `LICENSE`).

Everything else under `references/` is third-party or derived from third-party material, keeps its own licence, and is NOT covered by MIT.

## 1. OpenWrt material in `references/openwrt/`

**Source pages** — `references/openwrt/source/*.txt` (9 files: `apk.txt`, `dhcp.txt`, `dsa_start.txt`, `firewall_configuration.txt`, `fw3_nat.txt`, `mwan3.txt`, `network_configuration.txt`, `uci.txt`, `wifi_basic.txt`).

- Attribution: (c) OpenWrt contributors.
- Verbatim raw DokuWiki exports; the only change is a one-line header comment added to each file.
- Licence: Creative Commons Attribution-ShareAlike 4.0 (CC BY-SA 4.0).
- Licence URL: https://creativecommons.org/licenses/by-sa/4.0/
- Project licence notice: https://openwrt.org/license
- Retrieval date: 2026-10-03.
- Obligations: keep the attribution and source headers, state that changes were made, and release the files and any derivative of them under CC BY-SA 4.0 or a compatible licence.

**Adapted notes** — `references/openwrt/*.md` (9 files: `dhcp-dns.md`, `dsa-vlans.md`, `firewall.md`, `mwan3.md`, `network.md`, `packages-apk.md`, `port-forwards.md`, `uci.md`, `wifi.md`; each header names its source page).

- Attribution: (c) OpenWrt contributors.
- Adapted: condensed by an AI model (page text fetched through a model-condensed view, then condensed again) with small additions from general knowledge; changes were made to the original wiki content.
- Licence: Creative Commons Attribution-ShareAlike 4.0 (CC BY-SA 4.0).
- Licence URL: https://creativecommons.org/licenses/by-sa/4.0/
- Project licence notice: https://openwrt.org/license
- Retrieval date: 2026-10-03.
- Obligations: keep the attribution header, state that changes were made (done in each header), and keep these adapted files and any derivative of them under CC BY-SA 4.0. They are not MIT.

## 2. nftables material in `references/nftables/`

Files: `nat.md`, `quick-reference.md`, `scripting.md`, `sets.md` (4 files).

- Attribution: (c) nftables wiki contributors (https://wiki.nftables.org).
- Converted mechanically from MediaWiki source to Markdown; the content itself is otherwise unmodified.
- Licence: GNU Free Documentation License, version 1.3 or any later version (GFDL-1.3+).
- Licence URL: https://www.gnu.org/licenses/fdl-1.3.html
- Retrieval date: 2026-10-03.
- Obligations: keep the GFDL notice and credit to the wiki, state the modification (done in each header), and distribute the files under GFDL terms; the full GFDL-1.3 text is shipped at `LICENSES/GFDL-1.3-or-later.txt`. Do not merge this material into a file with CC BY-SA content; keep each under its own notice.

## 3. Networking-concepts material in `references/networking-concepts/`

Files: `index.md`, `glossary.md`, `patterns.md`, `cheatsheet.md`, and chapters under `chapters/` (`ch01`..`ch09`).

- Attribution: derived from Larry Peterson and Bruce Davie, *Computer Networks: A Systems Approach*, 6th edition, https://github.com/SystemsApproach/book at commit `5deec5e`.
- AI-written condensations of the source material. Changes were made; these are not the original text and are not endorsed by the authors.
- Licence: Creative Commons Attribution 4.0 (CC BY 4.0).
- Licence URL: https://creativecommons.org/licenses/by/4.0/
- Obligations: credit Larry Peterson and Bruce Davie as the source authors; link the source; indicate that changes were made and the work is not endorsed by the original authors. CC BY 4.0 has no share-alike clause, but the attribution must travel with the files.
- Note: some specific values (the cheatsheet MTU numbers and the ch06 fq_codel/cake notes) come from general knowledge, not the book.

## Licence texts shipped

The repository follows the REUSE layout. Full texts of every licence it uses are under `LICENSES/`, named by SPDX identifier, and `REUSE.toml` assigns a licence and copyright holder to every file (`reuse lint` passes):

- `MIT.txt`: MIT (Newton's own files).
- `CC-BY-SA-4.0.txt`: Creative Commons Attribution-ShareAlike 4.0 International, from https://creativecommons.org/licenses/by-sa/4.0/legalcode.txt.
- `CC-BY-4.0.txt`: Creative Commons Attribution 4.0 International, from https://creativecommons.org/licenses/by/4.0/legalcode.txt.
- `GFDL-1.3-or-later.txt`: GNU Free Documentation License 1.3, from https://www.gnu.org/licenses/fdl-1.3.txt.

All three texts were fetched on 2026-10-25 and are byte-identical to the official files.

---

This is a practical summary of where third-party material lives in this repository and what applies to it. It is not legal advice; for binding terms consult the full licence texts linked above.