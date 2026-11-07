---
source: https://openwrt.org/docs/guide-user/additional-software/apk ; https://openwrt.org/docs/guide-user/additional-software/opkg
retrieved: 2026-10-03
license: CC BY-SA 4.0, (c) OpenWrt contributors (https://openwrt.org/license)
note: condensed markdown conversion of the wiki page (navigation dropped); verify exact values against the live page for anything critical. Items marked LEGACY are fw3/iptables/swconfig/opkg-era and differ on OpenWrt 25.12.
---

# Package management: apk (25.12+) and LEGACY opkg

OpenWrt 25.12 and newer use **apk** (from Alpine Linux, apk-tools v3) instead of opkg. Anything below marked LEGACY applies to 24.10 and earlier.

## apk
```sh
apk update                          # refresh package index
apk add <package>                   # install
apk -U add pkg1 pkg2 pkg3           # update index then install several
apk add 'pattern*'                  # glob
apk add --allow-untrusted ./pkg.apk # locally built package
apk del <package>                   # remove
apk list -I                         # installed
apk list -a ['pattern*']            # available
apk search [needle*]                # search by name
https_proxy=http://proxy:3128/ apk update   # behind a proxy
```
Feeds: `/etc/apk/repositories.d/distfeeds.list` (official). Custom feeds go in `/etc/apk/repositories.d/customfeeds.list` so they survive upgrades.

WARNING from the wiki: do NOT blindly run `apk upgrade`. It can brick the device (missing dependency specs, conflicts). The only safe way to upgrade everything is `sysupgrade` to new firmware (LuCI attended sysupgrade, ASU `auc`, or local build). Install/remove single packages only.
Known issue: `apk adbdump` may emit non-standard YAML. OpenWrt 25.12 uses apk v3.

Ready-reckoner opkg -> apk (mapping from general knowledge, not on the wiki page): `opkg update` -> `apk update`; `opkg install x` -> `apk add x`; `opkg remove x` -> `apk del x`; `opkg list-installed` -> `apk list -I`; `opkg list` -> `apk list -a`; `opkg files x`/`opkg search` -> `apk info -L x` / `apk search`.

## LEGACY: opkg (24.10 and earlier)
Config: `/etc/opkg.conf`, `/etc/opkg/distfeeds.conf`, `/etc/opkg/customfeeds.conf`. Lists cached in `/tmp/opkg-lists`.
```sh
opkg update
opkg install <pkgs|url>
opkg remove <pkgs>
opkg upgrade <pkgs>          # mass upgrade discouraged
opkg list | grep <pat>
opkg list-installed
opkg list-upgradable
opkg files <pkg>
opkg search <file>
opkg info <pkg>
opkg download <pkg>
opkg flag hold <pkg>
```
Options: `-d <dest>`, `--force-depends`, `--force-space`, `--download-only`, `-V<level>`.
