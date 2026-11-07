# Network performance diagnostic (runguide)

Original Newton content (MIT, same as SKILL.md). Every command below ran on 2026-10-04 against an OpenWrt 25.12.5
router (ASUS RT-AX57M), a Linux test host on NetworkManager, and an MT7612U USB Wi-Fi adapter. Example report:
`/home/user/docs/network-diagnostic-2026-10-04.md`.

**Use when** the user asks how fast the network or internet is, wants a speed test, ping/latency/jitter, bufferbloat,
file-transfer speed, Wi-Fi performance, or "why is it slow". Run order: inventory → latency → internet → LAN →
Wi-Fi → report.

## Rules

1. **The router stays read-only.** No packages (no iperf3 on a production router), no config changes, no Wi-Fi scan
   from the AP (a scan takes the radio off-channel and stalls its clients). Measure from a host behind it.
2. **Ask first** before a run that uses more than a few GB of internet data (the full suite used about 5 GB on a
   gigabit line; ISPs cap data), and before joining Wi-Fi (it reads the Wi-Fi key from the router).
3. **Never print a Wi-Fi key or password.** Pipe it into a 600-mode file, hand NetworkManager the file, shred it.
4. **Leave the test host as you found it:** temporary profiles deleted, the wired default route still the only default.
5. **Report on-the-wire numbers, cross-check with a second server, and list what you did not check.**

## 0. Inventory: find the ceiling first

The fastest result you can measure is the slowest link in the path. A saturated gigabit link reads 983 Mb/s on the
NIC counter (headers included), which a speed-test app shows as about 940.

```bash
# test host: wired link speed, Wi-Fi adapters, tools
cat /sys/class/net/<wired-if>/speed /sys/class/net/<wired-if>/duplex
lsusb | grep -iE 'wireless|802\.11|wlan|mediatek|realtek|ralink'
lsusb -t                                    # the adapter's line: 5000M = USB 3; 480M = USB 2, which caps a fast adapter
nmcli -t -f DEVICE,TYPE,STATE dev
for t in curl socat mtr dig ping ssh iw; do command -v $t >/dev/null && printf '%s ' $t; done; echo

# router (OpenWrt, read-only): model, WAN link speed and address, offload, LAN ports, radios
ssh <router> '
ubus call system board | jsonfilter -e "@.model" -e "@.system" -e "@.release.target"
W=$(uci -q get network.wan.device); echo "wan_dev=$W speed=$(cat /sys/class/net/$W/speed) duplex=$(cat /sys/class/net/$W/duplex)"
echo "wan_ip=$(ifstatus wan | jsonfilter -e "@[\"ipv4-address\"][0].address")"
echo "flow_offloading=$(uci -q get firewall.@defaults[0].flow_offloading) hw=$(uci -q get firewall.@defaults[0].flow_offloading_hw)"
for p in /sys/class/net/lan*; do n=${p##*/}; printf "%s:%s/%s " $n $(cat $p/speed 2>/dev/null) $(cat $p/operstate); done; echo
iwinfo | grep -E "ESSID|Channel|Bit Rate"
uci show wireless | grep -vE "\.(key|sae_password|password|auth_secret|priv_key)="'

# cable modem status page (often unreachable when the ISP router is bypassed or bridged)
curl -s -m 4 -o /dev/null -w 'modem http=%{http_code}\n' http://192.168.100.1/
```

A WAN address in 100.64.0.0/10 means carrier-grade NAT (no inbound port forwards).

## 1. Latency at idle

```bash
for t in <gateway> <lan-host> 1.1.1.1 8.8.8.8; do echo "== $t"; ping -n -q -c 30 -i 0.2 -W 2 $t | tail -2; done
mtr -n -r -w -c 10 1.1.1.1                  # per-hop loss; a hop that never answers is normal
for s in <gateway> 1.1.1.1 8.8.8.8; do for n in netflix.com github.com zz$RANDOM.example.org; do
  printf '%-15s %-22s %s\n' $s $n "$(dig +tries=1 +time=3 @$s $n A | awk '/Query time/{print $4" ms"}')"; done; done
for i in 1 2 3; do dig +tries=1 @<gateway> netflix.com A | awk '/Query time/{printf "%s ms  ", $4}'; done; echo   # cached: ~0 ms
ip -6 route show default; ping -6 -c 2 -W 2 2606:4700:4700::1111     # does the test host have IPv6?
```

The ISP's own gateway often ignores ping; that is normal.

## 2. The load-test script

Save as `/tmp/newton-loadtest.sh`, `chmod +x` it. Sections 3–5 use it.

```bash
#!/usr/bin/env bash
# newton-loadtest.sh <label> <rx|tx> <streams> <ping-target> <stream command...>
# Starts <streams> copies of the stream command (each capped at 16 s), waits 3 s for TCP ramp-up,
# then over a 10 s window reads the NIC byte counter, pings <ping-target> every 0.2 s and
# (optionally) samples the router's CPU. Prints one result line. Throughput is "on the wire".
# Env: IF        NIC to measure (required)
#      PING_IF   bind the ping to this NIC (use it for a second NIC on the same subnet)
#      WIRED_IF  leak check: also report how much moved on this NIC (should be ~0 when testing another NIC)
#      ROUTER    ssh target whose /proc/stat is sampled, e.g. root@192.168.1.1 (optional)
set -u
label=$1; dir=$2; n=$3; ptarget=$4; shift 4
IF=${IF:?set IF to the NIC to measure}
tmp=$(mktemp -d)
for _ in $(seq 1 "$n"); do timeout 16 bash -c "$*" >/dev/null 2>&1 & done
sleep 3
if [ -n "${ROUTER:-}" ]; then
  ssh -o BatchMode=yes -o ConnectTimeout=5 "$ROUTER" 'head -1 /proc/stat; sleep 10; head -1 /proc/stat' >"$tmp/cpu" 2>/dev/null &
fi
ping -n -q ${PING_IF:+-I "$PING_IF"} -i 0.2 -c 50 -W 2 "$ptarget" >"$tmp/ping" 2>&1 &
[ -n "${WIRED_IF:-}" ] && e0=$(cat "/sys/class/net/$WIRED_IF/statistics/${dir}_bytes")
b0=$(cat "/sys/class/net/$IF/statistics/${dir}_bytes"); t0=$(date +%s.%N)
sleep 10
b1=$(cat "/sys/class/net/$IF/statistics/${dir}_bytes"); t1=$(date +%s.%N)
if [ -n "${WIRED_IF:-}" ]; then
  e1=$(cat "/sys/class/net/$WIRED_IF/statistics/${dir}_bytes")
  echo "leak check: $WIRED_IF moved $(( (e1-e0)/1000000 )) MB ($dir) during the window"
fi
wait  # ping, CPU sample and stream timeouts all finish, so runs never overlap
mbps=$(awk -v b=$((b1-b0)) -v t0="$t0" -v t1="$t1" 'BEGIN{printf "%.0f", b*8/(t1-t0)/1e6}')
pl=$(awk -F'[ /,]+' '/packet loss/{for(i=1;i<=NF;i++) if($i ~ /%$/) l=$i} /^rtt/{r=$7"/"$8"/"$9"/"$10} END{print r" loss="l}' "$tmp/ping")
cpu=n/a
[ -s "$tmp/cpu" ] && cpu=$(awk 'NR==1{for(i=2;i<=9;i++)a+=$i; ai=$5+$6} NR==2{for(i=2;i<=9;i++)b+=$i; bi=$5+$6} END{if(b>a) printf "%.0f%%", 100*(1-(bi-ai)/(b-a)); else print "n/a"}' "$tmp/cpu")
rm -rf "$tmp"
printf '%-34s %5s Mb/s on %s (%s) | ping %s min/avg/max/mdev=%s | router CPU %s\n' "$label" "$mbps" "$IF" "$dir" "$ptarget" "$pl" "$cpu"
```

- On-the-wire numbers include Ethernet/IP/TCP headers. A speed-test app shows about 4% less.
- Each run takes about 17 s. Run tests one after another, never in parallel.
- The ping column is **latency under load** (bufferbloat). Compare it with the idle ping from section 1.

## 3. Internet throughput

```bash
H=https://ash-speed.hetzner.com/1GB.bin                    # Hetzner Ashburn, VA (verified); use a nearby Hetzner speed host
CF='https://speed.cloudflare.com/__down?bytes=25000000'    # keep 25 MB: 100 MB and up returns 1 byte
UP=https://speed.cloudflare.com/__up
# sanity first: both must report real byte counts (exit 28 from --max-time is fine)
curl -s -o /dev/null -m 15 -w 'cf   http=%{http_code} bytes=%{size_download}\n' "$CF"
curl -s -o /dev/null -m 6  -w 'hetz http=%{http_code} bytes=%{size_download}\n' "$H"
export IF=<wired-if> ROUTER=<router>
/tmp/newton-loadtest.sh "DOWN 1 stream (Hetzner)"     rx 1 1.1.1.1 "curl -s -o /dev/null $H"
/tmp/newton-loadtest.sh "DOWN 8 streams (Hetzner)"    rx 8 1.1.1.1 "curl -s -o /dev/null $H"
/tmp/newton-loadtest.sh "DOWN 8 streams (Cloudflare)" rx 8 1.1.1.1 "while :; do curl -s -o /dev/null '$CF'; done"
/tmp/newton-loadtest.sh "UP 4 streams (Cloudflare)"   tx 4 1.1.1.1 "while :; do head -c 50000000 /dev/zero | curl -s -o /dev/null --data-binary @- $UP; done"
/tmp/newton-loadtest.sh "UP 1 stream (Cloudflare)"    tx 1 1.1.1.1 "while :; do head -c 50000000 /dev/zero | curl -s -o /dev/null --data-binary @- $UP; done"
```

At about 1 Gb/s each download run moves 1–2 GB. On the verified line, Cloudflare's endpoint topped out at 470 Mb/s
while Hetzner filled the link: when the two disagree, the higher number bounds the line.

## 4. LAN throughput and file copies

Needs `socat` on both ends and SSH to a wired LAN server (not the router).

```bash
export IF=<wired-if>; SRV=<server-ip>
# server -> test host (download direction)
ssh <server> 'timeout 18 socat -U TCP-LISTEN:5202,reuseaddr OPEN:/dev/zero' & sleep 1.5
/tmp/newton-loadtest.sh "LAN server->host" rx 1 $SRV "socat -u TCP:$SRV:5202 OPEN:/dev/null"; wait
# test host -> server (upload direction)
ssh <server> 'timeout 18 socat -u TCP-LISTEN:5201,reuseaddr OPEN:/dev/null' & sleep 1.5
/tmp/newton-loadtest.sh "LAN host->server" tx 1 $SRV "socat -u OPEN:/dev/zero TCP:$SRV:5201"; wait
# a real file copy: choose a 2-5 GB file on purpose
SZ=$(ssh <server> "stat -c %s '<big-file>'")
t0=$(date +%s.%N); scp -q <server>:'<big-file>' /dev/null; t1=$(date +%s.%N)
awk -v s=$SZ -v a=$t0 -v b=$t1 'BEGIN{printf "%.1f s = %.0f MB/s\n", b-a, s/(b-a)/1e6}'
```

- For parallel streams, add `,fork` to the listener and raise the stream count.
- Gigabit file copies top out around 113–117 MB/s. Copying to `/dev/null` measures the network, not the disks.

## 5. Wi-Fi (USB adapter on the test host)

**Ask the user first.** This reads the Wi-Fi key from the router and joins their network.

```bash
# scan from the test host (read-only). Look for strong neighbors INSIDE the router's channel block:
# 5 GHz, 80 MHz on channel 36 covers 36-48.
nmcli -f SSID,BSSID,CHAN,RATE,SIGNAL,SECURITY dev wifi list ifname <wifi-if> --rescan yes

# join with a temporary profile: no default route, no DNS, key never printed or stored by NetworkManager
W=<wifi-if>; T=$(mktemp -d)
( umask 077; ssh <router> 'uci -q get wireless.<wifi-iface-section>.key' | sed 's/^/802-11-wireless-security.psk:/' > $T/wifi.pw )
wc -c < $T/wifi.pw                                   # size only: never cat this file
nmcli con add type wifi ifname $W con-name newton-wifitest ssid '<SSID>' 802-11-wireless.band a \
  wifi-sec.key-mgmt wpa-psk wifi-sec.psk-flags 2 connection.autoconnect no \
  ipv4.never-default yes ipv4.ignore-auto-dns yes ipv4.route-metric 900 ipv6.method disabled
nmcli con up newton-wifitest passwd-file $T/wifi.pw; shred -u $T/wifi.pw
ip route show default                                # must still show only the wired default
```

`band a` is 5 GHz (verified). `band bg` is 2.4 GHz (not yet run). `wpa-psk` joins a WPA2/WPA3-mixed (`sae-mixed`)
network.

The adapter shares the wired NIC's subnet, so **bind every test to the Wi-Fi NIC** and read the leak check:

```bash
export IF=$W PING_IF=$W WIRED_IF=<wired-if> ROUTER=<router>; SRV=<server-ip>
ping -n -q -I $W -c 30 -i 0.2 <gateway> | tail -2
ssh <server> 'timeout 18 socat -U TCP-LISTEN:5202,reuseaddr OPEN:/dev/zero' & sleep 1.5
/tmp/newton-loadtest.sh "WIFI server->host (down)" rx 1 <gateway> "socat -u TCP:$SRV:5202,so-bindtodevice=$W OPEN:/dev/null"; wait
ssh <server> 'timeout 18 socat -u TCP-LISTEN:5201,reuseaddr OPEN:/dev/null' & sleep 1.5
/tmp/newton-loadtest.sh "WIFI host->server (up)" tx 1 <gateway> "socat -u OPEN:/dev/zero TCP:$SRV:5201,so-bindtodevice=$W"; wait
```

- A leak check above a few MB means the test ran over the wire. Throw that result out.
- Binding only the source IP is not enough: Linux routes by destination, so the traffic would leave through the
  wired NIC. Bind to the device: socat `so-bindtodevice=` and `ping -I` both worked unprivileged (kernel 7.0).

If download is low but ping under load stays near idle, the flow is **loss-limited**, not congested. Find where:

```bash
# sender's TCP retransmits (Linux): read before and after a run
awk '/^Tcp:/{n++; if(n==1) for(i=1;i<=NF;i++) if($i=="RetransSegs") c=i; if(n==2) print $c}' /proc/net/snmp
# router's view of the client: signal, rates, frames it gave up on (OpenWrt, read-only)
ssh <router> 'iw dev <ap-if> station get <client-mac> | grep -E "tx packets|tx failed|signal avg|tx bitrate|rx bitrate"'
ssh <router> 'iwinfo <ap-if> assoclist'
# client side: drops and signal (dBm)
cat /sys/class/net/$W/statistics/rx_dropped; grep $W /proc/net/wireless
```

Cleanup, always:

```bash
nmcli con delete newton-wifitest; ip route show default
```

## 6. Reading the numbers (rules of thumb)

| You see | It means | Next |
|---|---|---|
| Multi-stream download at the link ceiling (983 Mb/s on the wire for 1 GbE) | The line is faster than the gear | More speed needs 2.5 GbE on the modem, the router WAN and the client |
| One stream well below many streams | Normal at 15–30 ms RTT; a big gap plus loss means trouble | Check retransmits |
| Router CPU above ~80% while downloading | NAT is CPU-bound: offload is off or unsupported | Check `flow_offloading` / `flow_offloading_hw` |
| Ping under load more than ~30 ms above idle | Bufferbloat: calls and games suffer while the line is full | SQM (cake), but flow offload can bypass it: lab-test first |
| Low throughput while ping under load stays near idle | Not congestion: the flow is loss-limited | Sender retransmits; AP `tx failed` |
| AP `tx failed` above ~1% of `tx packets` | Frames die on the air | Signal (stronger than −30 dBm = too close, weaker than −70 = too far), a neighbor inside the channel block, the client driver |
| Wi-Fi upload fine, download poor on the same link | The client's receive side or the AP's transmit side | Move the client, compare a second adapter |
| NM log `failure sending router solicitation: Operation not permitted` | A local firewall or VPN kill switch blocks outgoing ICMPv6, so that host has no IPv6 | Check that host's nftables rules |
| Cached DNS lookup through the router above 1 ms | The router's DNS cache isn't answering | Check dnsmasq |

## 7. Gotchas (measured 2026-10-04)

- Cloudflare's `__down?bytes=` answers **1 byte** for 100 MB and up (25 MB works). A run that "measured 3 Mb/s" was
  this. Check `size_download` before trusting a run.
- `curl --max-time` still prints its `-w` output (exit code 28).
- `scp ... /dev/null` ends with `local ftruncate "/dev/null": Invalid argument`. Harmless; the timing is valid.
- The `socat -U ... OPEN:/dev/zero` listener exits 1 with `Broken pipe` when the reader stops. Harmless.
- `ls -S` to grab "a big file" picked a 23.6 GB ISO (208 s). Choose the file on purpose.
- `iw` may be missing on the test host. Use `/proc/net/wireless` there and `iw`/`iwinfo` on the router.
- BusyBox `ip` has no `-s`. Read `/sys/class/net/<if>/statistics/*` on OpenWrt.
- On the MT7981 router, `iw station get` showed `tx retries` equal to `tx failed`. Treat it as failed deliveries.
- `nmcli` SIGNAL is a 0–100 scale, not dBm. dBm comes from `/proc/net/wireless` (client) or `iw station get` (router).
- `sudo` may need a password, so plan on unprivileged tools. Everything above ran without root on the test host;
  `nmcli con add/up/delete` worked because it ran as the logged-in desktop user (polkit). Over a plain SSH session
  it may be refused.

## 8. The report

Write it to the user's docs folder (for example `/home/user/docs/network-diagnostic-<date>.md`) and send it to them.
Sections, in order:

1. **Answer:** 2–3 sentences: the headline numbers and the one real problem.
2. **Setup:** when (peak or off-peak), test host and NIC speed, router model/firmware/offload, WAN (public IP or
   CGNAT, IPv6), Wi-Fi adapter, servers, method.
3. **Internet, Latency (idle and under load), DNS, LAN, Wi-Fi (plus air scan):** tables, then one "Meaning:" line each.
4. **Side findings:** numbered, each with its evidence.
5. **Not checked:** mandatory. Peak hours, IPv6, other bands and devices, modem levels, anything skipped.
6. **Footprint:** internet data used, what changed on which host, what was cleaned up.
7. **Raw result lines,** plus any run thrown out and why.
