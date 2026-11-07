#!/usr/bin/env python3
"""Pulsar Wi-Fi helper: the Panda MT7921AU's side of the p-ow-wifi-* scenarios.

Runs as root on lab-wifi (VM 9107, Ubuntu 24.04, the Panda passed through from
apollo as USB 0e8d:7961, its only radio). python3 standard library only.

    newton-wifi.py prep
        iw reg set US; rfkill unblock wifi; find the netdev by its USB id and
        print `panda IFNAME PHY`. The 5 GHz band is PASSIVE-SCAN (no-IR) under
        the world domain, so the client end needs a country too. Sets the
        radio's txpower (mBm) and ignores a failure there.

    newton-wifi.py monitor --freq MHZ --bssid AA:BB:.. --secs N [expectations]
        A monitor vif on that phy, tuned to one channel, reading frames from an
        AF_PACKET socket. Beacon and Probe Response frames from the pinned
        BSSID only are parsed (SSID, DS param, RSN, vendor WPS); every other
        frame is counted and dropped. Counts are the only thing that leaves:
        no pcap, and no BSSID, MAC or SSID but the pinned one's.

    newton-wifi.py client --mode sae|psk --ssid S --bssid AA:BB:.. --freq MHZ
                          [--ieee80211w 0|1|2] [--scan-ssid] --secs N
                          [--expect-fail]
        wpa_supplicant on one network block pinned to the BSSID and the
        channel, the key read from the 0600 file /run/newton-psk (never from
        stdin, never in argv, never printed), then DHCP and a ping of the
        gateway. Teardown always runs.

    newton-wifi.py pair --ssid S --bssid AA:BB:.. --freq MHZ [--ieee80211w N]
                        --secs N --expect-cross reachable|blocked [--count 8]
        Two stations of the one Panda on the pinned BSSID: a second managed vif
        (sta2) with a locally administered address, its own wpa_supplicant
        (own conf, own ctrl dir, own pidfile), both waited for COMPLETED, power
        save off on both (without it the latency is about a second), then one
        VRF per station, an address outside the DHCP pool in each and a
        permanent neighbour entry for the other station (broadcast ARP to the
        second vif is not reliable). The gateway is pinged from each VRF, then
        the cross ping leaves vrfa for the other station: reachable wants at
        least half of --count replies (rounded up), blocked wants none. The key
        is read from /run/newton-psk as always and reaches no argv. Teardown
        always runs.

    newton-wifi.py ap start --ssid-hex HEX --freq MHZ [--secs N]
        The Panda as an OPEN access point (wpa_supplicant mode=2,
        key_mgmt=NONE), so the router's own radio has something of ours to
        find in a scan. The SSID is given as hex (1 to 32 bytes) and must
        start with newton-test, so a quote or a markup tag in the name can
        never reach a shell word or a config quoting rule. Only the non-DFS
        5 GHz channels are allowed (5180 5200 5220 5240 5745 5765 5785 5805
        5825), the txpower is the same fixed 1 dBm the client runs at, and
        `timeout` is the watchdog: the access point cannot outlive --secs
        (120 by default, 300 at most). Prints `ap: started ssid_len=N
        freq=F`.

    newton-wifi.py ap stop
        Stop it. Idempotent: it exits 0 whether or not one was running.
        Prints `ap: stopped`.

    newton-wifi.py cleanup
        mon0, wpa_supplicant, dhcpcd, the key file and the config go, and with
        them the pair's leftovers: both of its supplicants, sta2, vrfa, vrfb
        and its conf files, pidfiles and ctrl dirs. The access point goes
        with them. Safe to run twice.

Every subcommand prints ONE summary line to stdout and everything else to
stderr, and exits 0 only if every expectation it was given holds.  The `ap`
subcommands refuse with exit 2 and print nothing on stdout: a refusal is an
answer about the request, not a failure of the box.
"""
import argparse
import os
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import time

# ---- fixed paths and the one radio ----------------------------------------

PSK_PATH = "/run/newton-psk"
CONF_PATH = "/run/newton-wpa.conf"
CTRL_DIR = "/run/newton-wpa"
PIDFILE = "/run/newton-wpa.pid"
MON_IF = "mon0"
PANDA_VID = "0e8d"
PANDA_PID = "7961"
CLIENT_NET = "192.168.152.0/24"
GATEWAY = "192.168.152.1"
TXPOWER_MBM = 100
SYSFS_NET = "/sys/class/net"
ETH_P_ALL = 0x0003

# The pair (OW-ZONE-03): two stations of the one Panda, so the second one is a
# vif we create and the addresses are ours. 192.168.152.201/.202 sit outside the
# pool the scenarios' batch hands out (.100-.149), because both stations are
# addressed by hand and never run DHCP.
PAIR_IF_B = "sta2"
PAIR_MAC_B = "02:00:00:00:00:b2"
PAIR_CONF_A = "/run/newton-pair-a.conf"
PAIR_CONF_B = "/run/newton-pair-b.conf"
PAIR_CTRL_A = "/run/newton-wpa-a"
PAIR_CTRL_B = "/run/newton-wpa-b"
PAIR_PID_A = "/run/newton-wpa-a.pid"
PAIR_PID_B = "/run/newton-wpa-b.pid"
PAIR_VRF_A = "vrfa"
PAIR_VRF_B = "vrfb"
PAIR_TABLE_A = "11"
PAIR_TABLE_B = "12"
PAIR_IP_A = "192.168.152.201"
PAIR_IP_B = "192.168.152.202"
PAIR_CIDR = "/24"
PAIR_COUNT = 8

BEACON = 0x80
PROBE_RESPONSE = 0x50

# IEEE 802.11 Table 9-149 (cipher) and 9-151 (AKM) suite types under the OUI 00-0f-ac.
CIPHER_SUITES = {
    1: "wep40", 2: "tkip", 4: "ccmp", 5: "wep104", 6: "bip-cmac-128",
    8: "gcmp-128", 9: "gcmp-256", 10: "ccmp-256", 11: "bip-gmac-128",
    12: "bip-gmac-256", 13: "bip-cmac-256",
}
AKM_SUITES = {
    1: "8021x", 2: "psk", 3: "ft-8021x", 4: "ft-psk", 5: "8021x-sha256",
    6: "psk-sha256", 7: "tdls", 8: "sae", 9: "ft-sae", 10: "ap-peek-key",
    11: "8021x-suite-b", 12: "8021x-suite-b-192", 13: "ft-8021x-sha384",
    14: "fils-sha256", 15: "fils-sha384", 16: "ft-fils-sha256",
    17: "ft-fils-sha384", 18: "owe",
}
WPS_OUI = b"\x00\x50\xf2"
WPS_TYPE = 0x04
RSN_MFPC = 0x80
RSN_MFPR = 0x40


class WifiError(Exception):
    """Anything that makes a subcommand fail loudly instead of guessing."""


def soft(argv, timeout=10):
    """run() for the paths that must not fail a run: a teardown, or the
    idempotent cleanup. A missing binary or a timeout is swallowed."""
    try:
        return run(argv, timeout=timeout)
    except WifiError as e:
        note("%s: %s" % (argv[0], e))
        return None


def note(text: str) -> None:
    """A detail line: stderr, so stdout stays the one summary line."""
    sys.stderr.write(text.rstrip("\n") + "\n")


def run(argv, timeout=30):
    """Run an external command with an argv list (never a shell string) and
    return (rc, stdout, stderr). A missing binary or a timeout is a WifiError
    at the call site, not here."""
    try:
        proc = subprocess.run(argv, capture_output=True, text=True,
                              timeout=timeout)
    except FileNotFoundError as e:
        raise WifiError("%s is not installed" % argv[0]) from e
    except subprocess.TimeoutExpired as e:
        raise WifiError("%s timed out after %ss" % (argv[0], timeout)) from e
    return proc.returncode, proc.stdout, proc.stderr


def spawn(argv):
    """Start a long-lived process and return its pid.

    The argv is a list, never a shell string, and the child gets a session of
    its own, so the access point keeps beaconing after this process has
    printed its line and exited. A missing binary is a WifiError at the call
    site, not here."""
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL,
                                start_new_session=True)
    except FileNotFoundError as e:
        raise WifiError("%s is not installed" % argv[0]) from e
    return proc.pid


# ---- the radio -------------------------------------------------------------

def _read(path: str) -> str:
    with open(path) as fh:
        return fh.read().strip()


def find_panda(sysfs: str = SYSFS_NET):
    """(netdev, phy) of the adapter with USB id 0e8d:7961, or None.

    The netdev is found by walking from /sys/class/net/<if>/device up to the
    USB device that carries idVendor/idProduct (never by the interface name,
    which the USB stack chooses), and the phy from the phy80211 link beside
    it.
    """
    try:
        names = sorted(os.listdir(sysfs))
    except OSError:
        # no sysfs at all (a container without /sys, or a wrong path): the
        # adapter is absent, which is what the caller reports
        return None
    for name in names:
        base = os.path.realpath(os.path.join(sysfs, name, "device"))
        for _ in range(4):
            vid = os.path.join(base, "idVendor")
            pid = os.path.join(base, "idProduct")
            if os.path.exists(vid) and os.path.exists(pid):
                try:
                    if (_read(vid).lower() == PANDA_VID
                            and _read(pid).lower() == PANDA_PID):
                        return name, _phy_of(sysfs, name)
                except OSError:
                    pass
                break
            parent = os.path.dirname(base)
            if parent == base:
                break
            base = parent
    return None


def _phy_of(sysfs: str, ifname: str):
    try:
        return os.path.basename(
            os.readlink(os.path.join(sysfs, ifname, "phy80211")))
    except OSError:
        return None


def require_panda():
    panda = find_panda()
    if panda is None or not panda[0] or not panda[1]:
        raise WifiError("no %s:%s adapter under %s" % (PANDA_VID, PANDA_PID,
                                                       SYSFS_NET))
    return panda


# ---- radiotap and 802.11 --------------------------------------------------

def parse_radiotap(frame):
    """The 802.11 frame after the radiotap header, or b"" when the header is
    not one (a driver can hand over a frame without it)."""
    if not isinstance(frame, (bytes, bytearray)) or len(frame) < 4:
        return b""
    it_len = struct.unpack_from("<H", frame, 2)[0]
    if it_len < 4 or it_len > len(frame):
        return b""
    return bytes(frame[it_len:])


def parse_ies(body):
    """{element id: [element bodies]} from an IE block. Element 0 is the SSID
    (a zero-length one is how a hidden network looks) and 0xFF ends the block;
    an element whose length runs past the end of the buffer stops the walk too
    (keeping what was parsed) rather than raising."""
    out: dict[int, list] = {}
    i, n = 0, len(body)
    while i + 2 <= n:
        eid = body[i]
        elen = body[i + 1]
        i += 2
        if eid == 0xFF:
            break
        if i + elen > n:
            break
        out.setdefault(eid, []).append(bytes(body[i:i + elen]))
        i += elen
    return out


def suite_type(selector: bytes) -> int:
    """The type byte of a 4-byte suite selector (OUI + type). A selector under
    another OUI than 00-0f-ac is reported as 1000 + its type, so it can never
    be mistaken for a standard suite."""
    return selector[3] if selector[:3] == b"\x00\x0f\xac" else 1000 + selector[3]


def cipher_name(number: int) -> str:
    return CIPHER_SUITES.get(number, "suite-%d" % number)


def akm_name(number: int) -> str:
    return AKM_SUITES.get(number, "suite-%d" % number)


def parse_rsn(data):
    """The RSN element as {group, pairwise, akm, mfpc, mfpr, caps}. akm holds
    the 00-0f-ac:<n> suite selectors themselves, so an expectation can be the
    exact set. Anything malformed yields what was readable so far."""
    out = {"group": None, "pairwise": [], "akm": [], "mfpc": 0, "mfpr": 0,
           "caps": None}
    if len(data) < 2:
        return out
    pos = 0

    def take(count):
        nonlocal pos
        if pos + count > len(data):
            raise ValueError("short")
        chunk = data[pos:pos + count]
        pos += count
        return chunk

    try:
        struct.unpack("<H", take(2))               # version
        out["group"] = cipher_name(suite_type(take(4)))
        count = struct.unpack("<H", take(2))[0]
        for _ in range(min(count, 64)):
            out["pairwise"].append(cipher_name(suite_type(take(4))))
        count = struct.unpack("<H", take(2))[0]
        for _ in range(min(count, 64)):
            out["akm"].append(suite_type(take(4)))
        if pos + 2 <= len(data):
            caps = struct.unpack("<H", take(2))[0]
            out["caps"] = caps
            out["mfpc"] = 1 if caps & RSN_MFPC else 0
            out["mfpr"] = 1 if caps & RSN_MFPR else 0
    except (ValueError, struct.error):
        pass
    return out


def _has_wps(ies) -> bool:
    for body in ies.get(0xDD, ()):
        if len(body) >= 4 and body[:3] == WPS_OUI and body[3] == WPS_TYPE:
            return True
    return False


def _mac_bytes(text: str):
    cleaned = str(text).replace(":", "").replace("-", "").lower()
    if len(cleaned) != 12 or re.fullmatch(r"[0-9a-f]{12}", cleaned) is None:
        raise WifiError("not a MAC address: %r" % text)
    return bytes.fromhex(cleaned)


def read_frame(frame, bssid: str):
    """The facts of one captured frame, or None when it is not a beacon or
    probe response from the pinned BSSID.

    Pure, and deliberately narrow: only the SSID bytes, the DS channel, the
    RSN suites and whether a WPS vendor IE is there. No address of any kind is
    returned, so a neighbour cannot leak through a return value.
    """
    data = parse_radiotap(frame)
    if len(data) < 24:
        return None
    fc1 = data[0]
    if fc1 & 0x03 != 0x00:                        # not a management frame
        return None
    subtype = (fc1 >> 4) & 0x0F
    if subtype not in (0x08, 0x05):
        return None
    try:
        pinned = _mac_bytes(bssid)
    except WifiError:
        return None
    if bytes(data[16:22]) != pinned:
        return None
    body = data[24:]
    if len(body) < 12:                            # timestamp, interval, caps
        return None
    ies = parse_ies(body[12:])
    ssid = ies.get(0x00, [b""])[0]
    channel = None
    if ies.get(0x03) and ies[0x03][0]:
        channel = ies[0x03][0][0]
    rsn = parse_rsn(ies[0x30][0]) if ies.get(0x30) else {}
    return {"kind": "beacon" if subtype == 0x08 else "probe-response",
            "ssid": ssid, "channel": channel, "rsn": rsn,
            "wps": _has_wps(ies)}


def escape_ssid(raw) -> str:
    """The SSID as printable ASCII, everything else as \\xNN. An empty SSID and
    an all-NUL SSID (both how a hidden network looks) print as nothing, which
    the caller calls `empty`."""
    if not raw:
        return ""
    if raw == b"\x00" * len(raw):
        return ""
    out = []
    for byte in raw:
        if 0x20 <= byte < 0x7F and byte not in (0x22, 0x5C):
            out.append(chr(byte))
        else:
            out.append("\\x%02x" % byte)
    return "".join(out)


def summarise(*, beacons, ssid, akm, mfpc, mfpr, wps, ciphers, neighbours,
              other_frames, channels) -> str:
    """The one monitor line. Counts and the pinned SSID only: neighbours are a
    distinct count, never an address."""
    return ("monitor: beacons=%d ssid=%s akm=%s mfpc=%d mfpr=%d wps=%d "
            "ciphers=%s neighbours=%d other_frames=%d channels=%d"
            % (beacons, escape_ssid(ssid) or "empty",
               ",".join(str(a) for a in sorted(akm)) or "-",
               mfpc, mfpr, 1 if wps else 0,
               ",".join(sorted(set(ciphers))) or "-",
               neighbours, other_frames, channels))


def client_line(state, address, pinged, scan_seen) -> str:
    return ("client: state=%s ip=%s ping=%s scan_ssid_seen=%d"
            % (state or "NONE", address or "none",
               "ok" if pinged else "none", 1 if scan_seen else 0))


def expected_fail_line(state) -> str:
    return "client: state=%s expected-fail=ok" % (state or "NONE")


PING_RECEIVED = re.compile(r"(?<![\d.-])(\d+)\s+received")


def parse_ping_received(text) -> int:
    """The `N received` of an iputils ping summary, or None when there is no
    summary at all (ping never got that far, or an older wording). None and 0
    are kept apart: 0 is what isolation measures, None is what nothing proved."""
    if not text:
        return None
    match = PING_RECEIVED.search(text)
    return int(match.group(1)) if match else None


def pair_line(state_a, state_b, gw_ok, received, count) -> str:
    """The one pair line: both wpa_states, whether the gateway answered from
    both VRFs, and how many of the cross pings came back."""
    return ("pair: a=%s b=%s gw=%s received=%d/%d"
            % (state_a or "NONE", state_b or "NONE",
               "ok" if gw_ok else "fail", received, count))


def pair_pass(state_a, state_b, gw_ok, received, count, expect_cross) -> bool:
    """The pair's exit rule, pure: both stations COMPLETED and the gateway
    answered, then the cross ping is the expectation. reachable wants at least
    half of count (rounded up), blocked wants not one reply. A missing summary
    is never a pass: nothing was proven."""
    if state_a != "COMPLETED" or state_b != "COMPLETED" or not gw_ok:
        return False
    if received is None:
        return False
    if expect_cross == "reachable":
        return received >= (count + 1) // 2
    if expect_cross == "blocked":
        return received == 0
    raise ValueError("expect_cross must be reachable or blocked, got %r"
                     % (expect_cross,))


# ---- expectations ----------------------------------------------------------

def check_expectations(facts, args):
    """One string per expectation that did not hold; empty means all held."""
    bad = []
    beacons = facts["beacons"]
    if beacons < args.min_beacons:
        bad.append("beacons %d is below --min-beacons %d"
                   % (beacons, args.min_beacons))
    if args.expect_akm is not None:
        want = sorted(int(a) for a in args.expect_akm.split(","))
        got = sorted(set(facts["akm"]))
        if got != want:
            bad.append("akm %s is not the expected set %s"
                       % (got, want))
    if args.expect_mfpc is not None and facts["mfpc"] != args.expect_mfpc:
        bad.append("mfpc %d != %d" % (facts["mfpc"], args.expect_mfpc))
    if args.expect_mfpr is not None and facts["mfpr"] != args.expect_mfpr:
        bad.append("mfpr %d != %d" % (facts["mfpr"], args.expect_mfpr))
    if args.expect_ssid_empty:
        if escape_ssid(facts["ssid"]):
            bad.append("ssid %r is not empty" % escape_ssid(facts["ssid"]))
    elif args.expect_ssid is not None:
        if escape_ssid(facts["ssid"]) != args.expect_ssid:
            bad.append("ssid %r != %r"
                       % (escape_ssid(facts["ssid"]), args.expect_ssid))
    if args.expect_wps and not facts["wps"]:
        bad.append("wps: no vendor ie 00:50:f2:4 in the beacons of the pinned "
                   "bssid")
    if args.expect_no_wps and facts["wps"]:
        bad.append("wps: a vendor ie 00:50:f2:4 was seen")
    if args.expect_rsn_ciphers is not None:
        want = sorted(set(args.expect_rsn_ciphers.split(",")))
        got = sorted(set(facts["ciphers"]))
        if got != want:
            bad.append("ciphers %s != %s" % (got, want))
    return bad


# ---- the wpa_supplicant config and the key --------------------------------

def _quote(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"')


def build_wpa_conf(*, ssid, bssid, freq, mode, key, ieee80211w=2,
                   scan_ssid=False, ctrl_dir=CTRL_DIR) -> str:
    """One network block, pinned to the BSSID and the channel. No debug flag
    and nothing that would let wpa_supplicant log or write the key back."""
    if mode not in ("sae", "psk"):
        raise ValueError("mode must be sae or psk, got %r" % mode)
    lines = [
        "ctrl_interface=" + ctrl_dir,
        "update_config=0",
        "ap_scan=1",
        "",
        "network={",
        '    ssid="%s"' % _quote(ssid),
        "    bssid=%s" % bssid,
        "    freq_list=%d" % int(freq),
        "    scan_freq=%d" % int(freq),
        "    key_mgmt=%s" % ("SAE" if mode == "sae" else "WPA-PSK"),
        '    %s="%s"' % ("sae_password" if mode == "sae" else "psk",
                        _quote(key)),
        "    ieee80211w=%d" % int(ieee80211w),
        "    scan_ssid=%d" % (1 if scan_ssid else 0),
        "}",
        "",
    ]
    return "\n".join(lines)


def read_key(path: str = PSK_PATH) -> str:
    """The PSK from the 0600 file the lab pushed to the VM. stdin is never a
    key source, the value never reaches argv, and it is never printed."""
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError as e:
        raise WifiError("cannot read the key file %s: %s" % (path, e)) from e
    key = raw.decode("utf-8", "replace").strip()
    if not key:
        raise WifiError("the key file %s is empty" % path)
    return key


def parse_wpa_status(text: str) -> dict:
    """wpa_cli status output as {lowercased field: value}."""
    out = {}
    for line in (text or "").splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            out[key.strip().lower()] = value.strip()
    return out


def scan_result_seen(text: str, ssid: str, bssid: str) -> bool:
    """True when wpa_cli's scan_results lists this SSID on the pinned BSSID."""
    if not text or not ssid or not bssid:
        return False
    for line in text.splitlines():
        fields = line.split("\t")
        if len(fields) < 5:
            continue
        if (fields[0].strip().lower() == bssid.lower()
                and fields[4].strip() == ssid):
            return True
    return False


def ipv4_in(address: str, cidr: str):
    """True when address is inside cidr; False for anything unparseable."""
    try:
        addr = struct.unpack("!I", socket.inet_aton(address))[0]
        network, bits = cidr.split("/")
        base = struct.unpack("!I", socket.inet_aton(network))[0]
        mask = (0xFFFFFFFF << (32 - int(bits))) & 0xFFFFFFFF
    except (OSError, ValueError):
        return False
    return (addr & mask) == (base & mask)


# ---- subcommands -----------------------------------------------------------

def cmd_prep(args) -> int:
    rc, _, err = run(["iw", "reg", "set", "US"])
    if rc != 0:
        note("prep: iw reg set US failed: %s" % err.strip()[:200])
    try:
        run(["rfkill", "unblock", "wifi"])
    except WifiError as e:
        note("prep: %s; a USB radio in a VM is not rfkill-blocked, going on" % e)
    panda = find_panda()
    if panda is None or not panda[0] or not panda[1]:
        print("panda absent")
        return 1
    ifname, phy = panda
    # 100 mBm is the lowest fixed txpower the Panda accepts; mBm, not dBm.
    rc, _, err = run(["iw", "dev", ifname, "set", "txpower", "fixed",
                      str(TXPOWER_MBM)])
    if rc != 0:
        note("prep: txpower fixed %d mBm was refused: %s"
             % (TXPOWER_MBM, err.strip()[:200]))
    print("panda %s %s" % (ifname, phy))
    return 0


def _monitor_setup(phy: str):
    soft(["ip", "link", "del", MON_IF])
    rc, _, err = run(["iw", "phy", phy, "interface", "add", MON_IF,
                      "type", "monitor"])
    if rc != 0:
        raise WifiError("cannot add the monitor vif: %s" % err.strip()[:200])


def _monitor_teardown(phy: str) -> None:
    soft(["iw", "dev", MON_IF, "del"])
    soft(["ip", "link", "del", MON_IF])
    note("monitor: %s removed from %s" % (MON_IF, phy))


def cmd_monitor(args) -> int:
    _mac_bytes(args.bssid)
    ifname, phy = require_panda()
    pinned = _mac_bytes(args.bssid)
    _monitor_setup(phy)
    sock = None
    try:
        run(["ip", "link", "set", MON_IF, "up"])
        rc, _, err = run(["iw", "dev", MON_IF, "set", "freq", str(args.freq)])
        if rc != 0:
            note("monitor: setting the frequency failed: %s" % err.strip()[:200])
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                             socket.htons(ETH_P_ALL))
        sock.bind((MON_IF, 0))
        beacons = 0
        others = 0
        neighbours = set()
        channels = set()
        facts = {"ssid": b"", "akm": [], "mfpc": 0, "mfpr": 0, "wps": False,
                 "ciphers": []}
        deadline = time.monotonic() + args.secs
        while time.monotonic() < deadline:
            sock.settimeout(0.5)
            try:
                frame = sock.recv(4096)
            except socket.timeout:
                continue
            except OSError as e:
                note("monitor: read error: %s" % e)
                break
            data = parse_radiotap(frame)
            if len(data) < 24 or data[0] & 0x03 != 0x00:
                continue
            if ((data[0] >> 4) & 0x0F) not in (0x08, 0x05):
                continue
            addr3 = bytes(data[16:22])
            if addr3 != pinned:
                others += 1
                # counted in memory only, never printed, logged or written
                neighbours.add(addr3)
                continue
            seen = read_frame(frame, args.bssid)
            if seen is None:
                continue
            beacons += 1
            if seen["channel"] is not None:
                channels.add(seen["channel"])
            if seen["kind"] == "beacon" or not facts["ssid"]:
                facts = {"ssid": seen["ssid"], "akm": seen["rsn"]["akm"],
                         "mfpc": seen["rsn"]["mfpc"], "mfpr": seen["rsn"]["mfpr"],
                         "wps": seen["wps"],
                         "ciphers": ([seen["rsn"]["group"]]
                                     if seen["rsn"]["group"] else [])
                         + list(seen["rsn"]["pairwise"])}
        facts["beacons"] = beacons
        bad = check_expectations(facts, args)
        print(summarise(beacons=beacons, neighbours=len(neighbours),
                        other_frames=others, channels=len(channels),
                        **{k: facts[k] for k in
                           ("ssid", "akm", "mfpc", "mfpr", "wps", "ciphers")}))
        for line in bad:
            note("monitor: %s" % line)
        return 1 if bad else 0
    finally:
        if sock is not None:
            sock.close()
        _monitor_teardown(phy)
        note("monitor: adapter %s left as it was found" % ifname)


def _write_conf(text: str, path: str = None) -> None:
    fd = os.open(path or CONF_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, text.encode())
    finally:
        os.close(fd)
    os.chmod(path or CONF_PATH, 0o600)


def _unlink(path: str) -> None:
    """Remove a file if it is there: a teardown never fails on what a crashed
    run left missing."""
    try:
        os.unlink(path)
    except OSError:
        pass


def _wpa_running() -> bool:
    try:
        pid = int(_read(PIDFILE))
    except (OSError, ValueError):
        return False
    return os.path.exists("/proc/%d" % pid)


def _client_teardown(ifname: str) -> None:
    try:
        pid = int(_read(PIDFILE))
    except (OSError, ValueError):
        pid = 0
    if pid:
        soft(["kill", str(pid)])
    soft(["wpa_cli", "-p", CTRL_DIR, "-i", ifname, "terminate"])
    soft(["dhcpcd", "-k", ifname], timeout=20)
    # dhcpcd's hook hands the router's DNS to systemd-resolved for this link; drop it again
    soft(["resolvectl", "revert", ifname], timeout=10)
    soft(["ip", "addr", "flush", "dev", ifname])
    for path in (CONF_PATH, PIDFILE):
        _unlink(path)
    note("client: wpa_supplicant stopped, dhcpcd released, addresses flushed")


def _wait_associated(ifname: str, bssid: str, secs: int,
                     ctrl_dir: str = CTRL_DIR):
    """(state, bssid seen) once wpa_state is COMPLETED on the pinned BSSID, or
    after secs with whatever the last state was. ctrl_dir is the one station's
    own control directory; the client subcommand's is the default."""
    state = ""
    seen = ""
    deadline = time.monotonic() + secs
    while time.monotonic() < deadline:
        rc, out, _ = run(["wpa_cli", "-p", ctrl_dir, "-i", ifname, "status"])
        if rc == 0:
            status = parse_wpa_status(out)
            state = status.get("wpa_state", "")
            seen = status.get("bssid", "")
            if state == "COMPLETED" and seen.lower() == bssid.lower():
                return state, seen
        time.sleep(1)
    return state, seen


def first_client_address(ip_addr_output: str) -> str:
    """The first address inside CLIENT_NET in `ip -4 -o addr show` output
    (`3: wlx.. inet 192.168.152.103/24 brd ...`), or "" when there is none."""
    for line in ip_addr_output.splitlines():
        parts = line.split()
        if "inet" in parts and parts.index("inet") + 1 < len(parts):
            address = parts[parts.index("inet") + 1].split("/")[0]
            if ipv4_in(address, CLIENT_NET):
                return address
    return ""


def _dhcp(ifname: str) -> str:
    """One-shot DHCPv4 on the wireless interface. No default route is wanted:
    the VM's management NIC keeps the only default route the box has, so any
    route dhcpcd adds on the wifi interface is taken away again right after."""
    run(["dhcpcd", "-4", "-1", "-A", "-t", "40", ifname], timeout=60)
    for _ in range(3):
        rc, _, _ = run(["ip", "route", "del", "default", "dev", ifname],
                       timeout=10)
        if rc != 0:
            break
    rc, out, _ = run(["ip", "-4", "-o", "addr", "show", "dev", ifname])
    return first_client_address(out)


def cmd_client(args) -> int:
    _mac_bytes(args.bssid)
    ifname, _phy = require_panda()
    key = read_key(args.psk)
    conf = build_wpa_conf(ssid=args.ssid, bssid=args.bssid, freq=args.freq,
                          mode=args.mode, key=key, ieee80211w=args.ieee80211w,
                          scan_ssid=args.scan_ssid)
    try:
        run(["wpa_cli", "-p", CTRL_DIR, "terminate"], timeout=10)
        _write_conf(conf)
        # No -d: wpa_supplicant never logs, so the key cannot end up in one.
        rc, _, err = run(["wpa_supplicant", "-B", "-i", ifname, "-c", CONF_PATH,
                          "-D", "nl80211", "-P", PIDFILE], timeout=30)
        if rc != 0:
            raise WifiError("wpa_supplicant did not start: %s" % err.strip()[:200])
        state, _seen = _wait_associated(ifname, args.bssid, args.secs)
        if args.expect_fail:
            print(expected_fail_line(state))
            if state == "COMPLETED":
                note("client: COMPLETED was reached although --expect-fail was given")
                return 1
            note("client: no association in %ss, as expected" % args.secs)
            return 0
        if state != "COMPLETED":
            print(client_line(state, "", False, False))
            note("client: wpa_state never became COMPLETED within %ss" % args.secs)
            return 1
        rc, scan_out, _ = run(["wpa_cli", "-p", CTRL_DIR, "-i", ifname,
                               "scan_results"], timeout=30)
        scan_seen = scan_result_seen(scan_out, args.ssid, args.bssid)
        address = _dhcp(ifname)
        if not address:
            print(client_line(state, "", False, scan_seen))
            note("client: no address in %s after DHCP" % CLIENT_NET)
            return 1
        rc, _, _ = run(["ping", "-c", "2", "-W", "2", GATEWAY], timeout=15)
        pinged = rc == 0
        print(client_line(state, address, pinged, scan_seen), flush=True)
        if not pinged:
            note("client: %s did not answer two pings" % GATEWAY)
            return 1
        hold = max(0, min(int(getattr(args, "hold", 0) or 0), 120))
        if hold:
            time.sleep(hold)
        return 0
    finally:
        _client_teardown(ifname)


# ---- the pair: two stations of the one Panda -------------------------------
#
# Everything below builds argv lists and nothing else, so the wiring is read
# off the code and tested offline. The mechanism is the one measured live on
# the real hardware (2026-10-23): the driver allows #{managed, P2P-client} <= 2,
# so a second managed vif on the same phy associates alongside the first, and
# the cross-station ping needs one VRF per station because a single namespace
# cannot carry it (the kernel drops or loops the local-source frames).

def pair_station_cmds(phy: str) -> list:
    """The second station: a managed vif and the locally administered address
    we give it (it has to be one, and it has to be a fixed one)."""
    return [["iw", "phy", phy, "interface", "add", PAIR_IF_B, "type",
             "managed"],
            ["ip", "link", "set", PAIR_IF_B, "address", PAIR_MAC_B]]


def pair_wpa_argv(ifname: str, conf: str, pidfile: str) -> list:
    """One supplicant per station, each with its own conf, ctrl dir (inside the
    conf) and pidfile. No -d: wpa_supplicant never logs, so the key cannot end
    up in one."""
    return ["wpa_supplicant", "-B", "-i", ifname, "-c", conf, "-D", "nl80211",
            "-P", pidfile]


def pair_network_cmds(ifname_a, ifname_b, mac_a, mac_b) -> list:
    """A VRF per station in its own table, an address in each, and a permanent
    neighbour entry for the other station both ways. The neighbour entries are
    not belt and braces: broadcast ARP to the second vif is not reliable, and
    without them the cross ping measures the neighbour cache instead of the
    air."""
    return [["ip", "link", "add", PAIR_VRF_A, "type", "vrf", "table",
             PAIR_TABLE_A],
            ["ip", "link", "set", PAIR_VRF_A, "up"],
            ["ip", "link", "set", ifname_a, "master", PAIR_VRF_A],
            ["ip", "link", "add", PAIR_VRF_B, "type", "vrf", "table",
             PAIR_TABLE_B],
            ["ip", "link", "set", PAIR_VRF_B, "up"],
            ["ip", "link", "set", ifname_b, "master", PAIR_VRF_B],
            ["ip", "addr", "add", PAIR_IP_A + PAIR_CIDR, "dev", ifname_a],
            ["ip", "addr", "add", PAIR_IP_B + PAIR_CIDR, "dev", ifname_b],
            ["ip", "neigh", "replace", PAIR_IP_B, "lladdr", mac_b, "dev",
             ifname_a, "nud", "permanent"],
            ["ip", "neigh", "replace", PAIR_IP_A, "lladdr", mac_a, "dev",
             ifname_b, "nud", "permanent"]]


def pair_gw_cmds() -> list:
    """The gateway once from each station's own VRF. gw=ok means both."""
    return [["ping", "-I", PAIR_VRF_A, "-c", "2", "-W", "2", GATEWAY],
            ["ping", "-I", PAIR_VRF_B, "-c", "2", "-W", "2", GATEWAY]]


def pair_cross_cmd(count: int) -> list:
    """The cross ping: out of vrfa at the other station's address. The interval
    is what the prototype pinged with."""
    return ["ping", "-I", PAIR_VRF_A, "-c", str(count), "-i", "0.5", "-W", "2",
            PAIR_IP_B]


def pair_teardown_cmds(ifname_a, ifname_b) -> list:
    """Both supplicants first, then the addresses, the VRF membership, the VRFs
    and the second station, so nothing is pulled out from under a link that is
    still up. Every one of these is run through soft(), so a teardown that runs
    twice (or after a run that never got that far) is a no-op."""
    return [["wpa_cli", "-p", PAIR_CTRL_A, "-i", ifname_a, "terminate"],
            ["wpa_cli", "-p", PAIR_CTRL_B, "-i", ifname_b, "terminate"],
            ["ip", "addr", "flush", "dev", ifname_a],
            ["ip", "addr", "flush", "dev", ifname_b],
            ["ip", "link", "set", ifname_a, "nomaster"],
            ["ip", "link", "set", ifname_b, "nomaster"],
            ["ip", "link", "del", PAIR_VRF_A],
            ["ip", "link", "del", PAIR_VRF_B],
            ["ip", "link", "set", PAIR_IF_B, "down"],
            ["iw", "dev", PAIR_IF_B, "del"]]


def _pair_teardown(ifname_a) -> None:
    for argv in pair_teardown_cmds(ifname_a, PAIR_IF_B):
        soft(argv)
    for path in (PAIR_CONF_A, PAIR_CONF_B, PAIR_PID_A, PAIR_PID_B):
        _unlink(path)
    for path in (PAIR_CTRL_A, PAIR_CTRL_B):
        shutil.rmtree(path, ignore_errors=True)
    note("pair: both supplicants stopped, addresses flushed, %s, %s and %s "
         "removed" % (PAIR_IF_B, PAIR_VRF_A, PAIR_VRF_B))


def _read_mac(ifname: str) -> str:
    """The address the kernel has for an interface. The neighbour entries need
    the other station's, and it is only knowable once that station is up."""
    path = os.path.join(SYSFS_NET, ifname, "address")
    try:
        return _read(path)
    except OSError as e:
        raise WifiError("cannot read the address of %s: %s" % (ifname, e)) from e


def cmd_pair(args) -> int:
    """The client isolation pair (OW-ZONE-03) as one command: two stations of
    the one Panda on the same BSSID, each in its own VRF, and the cross ping
    that says whether the AP carries station-to-station traffic."""
    _mac_bytes(args.bssid)
    ifname, phy = require_panda()
    key = read_key()
    stations = ((ifname, PAIR_CONF_A, PAIR_CTRL_A, PAIR_PID_A),
                (PAIR_IF_B, PAIR_CONF_B, PAIR_CTRL_B, PAIR_PID_B))
    states = {}
    try:
        for argv in pair_station_cmds(phy):
            rc, _, err = run(argv)
            if rc != 0:
                raise WifiError("cannot add the second station: %s"
                                % err.strip()[:200])
        for station, conf_path, ctrl_dir, pidfile in stations:
            _write_conf(build_wpa_conf(ssid=args.ssid, bssid=args.bssid,
                                       freq=args.freq, mode="sae", key=key,
                                       ieee80211w=args.ieee80211w,
                                       ctrl_dir=ctrl_dir), conf_path)
            rc, _, err = run(pair_wpa_argv(station, conf_path, pidfile),
                             timeout=30)
            if rc != 0:
                raise WifiError("wpa_supplicant did not start on %s: %s"
                                % (station, err.strip()[:200]))
        for station, _conf, ctrl_dir, _pid in stations:
            states[station], _seen = _wait_associated(station, args.bssid,
                                                      args.secs, ctrl_dir)
        if states[ifname] != "COMPLETED" or states[PAIR_IF_B] != "COMPLETED":
            print(pair_line(states[ifname], states[PAIR_IF_B], False, 0,
                            args.count))
            note("pair: the two stations did not both reach COMPLETED on %s "
                 "within %ss" % (args.bssid, args.secs))
            return 1
        for station, _conf, _ctrl, _pid in stations:
            # power save off, or the round trip is about a second: measured
            soft(["iw", "dev", station, "set", "power_save", "off"])
        soft(["modprobe", "vrf"])
        for argv in pair_network_cmds(ifname, PAIR_IF_B, _read_mac(ifname),
                                      _read_mac(PAIR_IF_B)):
            rc, _, err = run(argv, timeout=15)
            if rc != 0:
                raise WifiError("pair: %s failed: %s" % (" ".join(argv[:4]),
                                                         err.strip()[:200]))
        gw_ok = True
        for argv in pair_gw_cmds():
            rc, _, _ = run(argv, timeout=15)
            if rc != 0:
                gw_ok = False
        if not gw_ok:
            note("pair: %s did not answer from both VRFs" % GATEWAY)
        _rc, out, _err = run(pair_cross_cmd(args.count),
                             timeout=max(20, args.count * 3))
        received = parse_ping_received(out)
        if received is None:
            note("pair: the cross ping printed no summary, so nothing arrived")
        print(pair_line(states[ifname], states[PAIR_IF_B], gw_ok,
                        received if received is not None else 0, args.count))
        if not pair_pass(states[ifname], states[PAIR_IF_B], gw_ok, received,
                         args.count, args.expect_cross):
            note("pair: --expect-cross %s did not hold (received=%s of %d)"
                 % (args.expect_cross, received, args.count))
            return 1
        return 0
    finally:
        _pair_teardown(ifname)


# ---- the AP: the Panda as an open access point ----------------------------
#
# The lab's own access point, so the router's radio has something of ours to
# find in a scan.  It is OPEN (key_mgmt=NONE), it beacons on one non-DFS 5 GHz
# channel, it runs at the same fixed 1 dBm the client runs at, and it cannot
# outlive its lifetime: `timeout` is its watchdog.

AP_CONF_PATH = "/run/newton-wpa-ap.conf"
AP_CTRL_DIR = "/run/newton-wpa-ap"
AP_PIDFILE = "/run/newton-wpa-ap.pid"
AP_SSID_PREFIX = b"newton-test"
AP_HEX_RE = re.compile(r"^([0-9a-f]{2}){1,32}$")
AP_FREQS = (5180, 5200, 5220, 5240, 5745, 5765, 5785, 5805, 5825)
AP_DEFAULT_SECS = 120
AP_MAX_SECS = 300
AP_COUNTRY = "US"


class ApRefused(Exception):
    """A refusal of the AP subcommand.  The exit code is 2, not 1: a refusal
    is an answer about the request, not a failure of the box."""


def decode_ap_ssid(hex_text: str) -> bytes:
    """The SSID bytes of the access point, from their hex form.

    The name is given as hex and never as text: a quote, a backslash or a
    markup tag in the name can then never reach a shell word or a config
    quoting rule.  The hex is 1 to 32 bytes and the name must start with the
    lab's own prefix, so the helper can only ever broadcast a name this
    repository made up.
    """
    if not isinstance(hex_text, str) or not AP_HEX_RE.match(hex_text):
        raise ApRefused("the ssid must be 1 to 32 bytes of lower-case hex")
    name = bytes.fromhex(hex_text)
    if not name.startswith(AP_SSID_PREFIX):
        raise ApRefused("the ssid must start with newton-test")
    return name


def check_ap_freq(freq: int) -> int:
    """The frequency of the access point, or a refusal: only the non-DFS 5 GHz
    channels this repository measured are allowed."""
    if freq not in AP_FREQS:
        raise ApRefused("%d MHz is not one of the non-DFS 5 GHz channels"
                        % freq)
    return int(freq)


def check_ap_secs(secs: int) -> int:
    """The lifetime of the access point in seconds: at least one second and at
    most five minutes."""
    if secs < 1 or secs > AP_MAX_SECS:
        raise ApRefused("--secs must be 1 to %d" % AP_MAX_SECS)
    return int(secs)


def build_ap_conf(*, ssid_hex: str, freq: int) -> str:
    """The wpa_supplicant config of the open access point.

    The ssid is the unquoted hex form wpa_supplicant accepts, so the name
    goes through no quoting rule at all.  mode=2 is the AP mode and
    key_mgmt=NONE is an open network: this is the lab's own beacon, never a
    neighbour's.  The channel is `frequency`: `freq_list` only limits a scan,
    and an AP started with it came up on 2.4 GHz channel 11 (measured live,
    2026-10-24).
    """
    decode_ap_ssid(ssid_hex)
    check_ap_freq(freq)
    return "\n".join([
        "ctrl_interface=" + AP_CTRL_DIR,
        "update_config=0",
        "ap_scan=1",
        "",
        "network={",
        "    ssid=%s" % ssid_hex,
        "    mode=2",
        "    key_mgmt=NONE",
        "    frequency=%d" % int(freq),
        "}",
        "",
    ])


def ap_supplicant_argv(ifname: str, conf: str, pidfile: str, secs: int) -> list:
    """The argv of the access point's supplicant.

    `timeout` is the watchdog: it ends the supplicant when the lifetime is
    over, so the access point cannot stay on after this run, whatever happens
    to the process that started it.  No -d: the supplicant never logs.
    """
    return ["timeout", "--signal=TERM", "--kill-after=5", str(int(secs)),
            "wpa_supplicant", "-i", ifname, "-c", conf, "-D", "nl80211",
            "-P", pidfile]


def _ap_pid() -> int:
    """The pid of the access point's supplicant, or 0 when there is none.

    The pidfile alone is not enough: a pid can be reused, and the watchdog
    may have ended the supplicant while its pidfile stayed behind.  The
    process has to be the one that runs the access point's config.
    """
    try:
        pid = int(_read(AP_PIDFILE))
    except (OSError, ValueError):
        return 0
    if pid <= 0:
        return 0
    try:
        with open("/proc/%d/cmdline" % pid, "rb") as fh:
            cmdline = fh.read().decode("utf-8", "replace")
    except OSError:
        return 0
    return pid if AP_CONF_PATH in cmdline else 0


def ap_wait_started(pidfile: str = AP_PIDFILE, secs: int = 25,
                    ifname: str = "") -> bool:
    """True when the access point is up: the interface is in AP mode.

    wpa_supplicant does not write the pidfile of -P unless it daemonizes
    (measured live, 2026-10-24: the access point was up and the old check,
    which waited for that file, said it was not), so cmd_ap_start writes the
    pid itself and this waits for the sign that matters: `iw dev IF info`
    says `type AP`.  The first start needs a scan, so it takes several
    seconds.
    """
    deadline = time.monotonic() + secs
    while time.monotonic() < deadline:
        try:
            pid = int(_read(pidfile))
        except (OSError, ValueError):
            pid = 0
        if pid and not os.path.exists("/proc/%d" % pid):
            return False
        if pid and ifname:
            rc, out, _ = run(["iw", "dev", ifname, "info"])
            if rc == 0 and "type AP" in out:
                return True
        time.sleep(0.5)
    return False


def _ap_stop() -> None:
    """Stop the access point if one runs.  Idempotent: a stop with no access
    point is a no-op, and a stop that runs twice is the same as one."""
    pid = _ap_pid()
    if pid:
        soft(["kill", str(pid)])
    soft(["wpa_cli", "-p", AP_CTRL_DIR, "terminate"])
    for path in (AP_CONF_PATH, AP_PIDFILE):
        _unlink(path)
    shutil.rmtree(AP_CTRL_DIR, ignore_errors=True)


def cmd_ap_start(args) -> int:
    """The Panda as an open access point."""
    try:
        name = decode_ap_ssid(args.ssid_hex)
        freq = check_ap_freq(args.freq)
        secs = check_ap_secs(args.secs)
    except ApRefused as e:
        note("ap: %s" % e)
        return 2
    ifname, _phy = require_panda()
    # One access point at a time: the driver allows one, so an earlier one
    # goes first.
    _ap_stop()
    _write_conf(build_ap_conf(ssid_hex=args.ssid_hex, freq=freq), AP_CONF_PATH)
    rc, _, err = run(["iw", "reg", "set", AP_COUNTRY])
    if rc != 0:
        note("ap: iw reg set %s failed: %s" % (AP_COUNTRY, err.strip()[:200]))
    rc, _, err = run(["iw", "dev", ifname, "set", "txpower", "fixed",
                      str(TXPOWER_MBM)])
    if rc != 0:
        note("ap: txpower fixed %d mBm was refused: %s"
             % (TXPOWER_MBM, err.strip()[:200]))
    try:
        pid = spawn(ap_supplicant_argv(ifname, AP_CONF_PATH, AP_PIDFILE, secs))
    except WifiError:
        _unlink(AP_CONF_PATH)
        raise
    if pid:
        _write_conf(str(pid) + "\n", AP_PIDFILE)
    if not ap_wait_started(ifname=ifname):
        _ap_stop()
        raise WifiError("the access point did not start")
    print("ap: started ssid_len=%d freq=%d" % (len(name), freq))
    return 0


def cmd_ap_stop(args) -> int:
    """Stop the access point.  Idempotent: it exits 0 whether or not one was
    running."""
    _ap_stop()
    print("ap: stopped")
    return 0


def cmd_cleanup(args) -> int:
    """Idempotent and always exit 0: it runs after a crashed run, when some of
    these things may not exist at all."""
    panda = find_panda()
    ifname = panda[0] if panda else None
    soft(["iw", "dev", MON_IF, "del"])
    soft(["ip", "link", "del", MON_IF])
    if ifname:
        if _wpa_running():
            _client_teardown(ifname)
        else:
            soft(["dhcpcd", "-k", ifname], timeout=20)
    soft(["wpa_cli", "-p", PAIR_CTRL_A, "terminate"], timeout=10)
    soft(["wpa_cli", "-p", PAIR_CTRL_B, "terminate"], timeout=10)
    if ifname:
        soft(["ip", "addr", "flush", "dev", ifname])
        soft(["ip", "neigh", "flush", "dev", ifname])
    soft(["ip", "link", "set", PAIR_IF_B, "down"])
    soft(["iw", "dev", PAIR_IF_B, "del"])
    soft(["ip", "link", "del", PAIR_VRF_A])
    soft(["ip", "link", "del", PAIR_VRF_B])
    for path in (PAIR_CONF_A, PAIR_CONF_B, PAIR_PID_A, PAIR_PID_B):
        _unlink(path)
    for path in (PAIR_CTRL_A, PAIR_CTRL_B):
        shutil.rmtree(path, ignore_errors=True)
    _ap_stop()
    for path in (CONF_PATH, PIDFILE, PSK_PATH):
        _unlink(path)
    print("cleanup: mon0=gone wpa=stopped dhcpcd=stopped sta2=gone vrfs=gone "
          "ap=stopped psk=removed conf=removed")
    return 0


# ---- the parser ------------------------------------------------------------

def _akm_list(value: str) -> str:
    """--expect-akm as a normalised "2,8": the exact set of 00-0f-ac suite
    numbers, checked here so a typo fails at the command line, not at the
    comparison."""
    parts = [part for part in str(value).split(",") if part]
    if not parts or not all(part.isdigit() for part in parts):
        raise argparse.ArgumentTypeError(
            "AKM suites are 00-0f-ac numbers, comma separated (8, or 2,8)")
    return ",".join(str(int(part)) for part in parts)


def _positive_int(value: str) -> int:
    """A count that means something: --count 0 would ping nowhere."""
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError("%r is not a number"
                                         % (value,)) from None
    if number < 1:
        raise argparse.ArgumentTypeError("must be 1 or more, got %d" % number)
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="newton-wifi.py",
        description="Pulsar Wi-Fi helper for the lab-wifi VM (the Panda "
                    "MT7921AU passed through from apollo).")
    sub = parser.add_subparsers(dest="command", required=True)

    prep = sub.add_parser("prep", help="country, rfkill, find the radio, txpower")
    prep.set_defaults(func=cmd_prep)

    mon = sub.add_parser("monitor",
                         help="beacon parse of the pinned BSSID on one channel")
    mon.add_argument("--freq", type=int, required=True, metavar="MHZ")
    mon.add_argument("--bssid", required=True, metavar="AA:BB:CC:DD:EE:FF")
    mon.add_argument("--secs", type=int, required=True, metavar="N")
    mon.add_argument("--min-beacons", type=int, default=5, metavar="K")
    mon.add_argument("--expect-akm", type=_akm_list, metavar="N[,N]",
                     help="the exact set of 00-0f-ac AKM suite numbers")
    mon.add_argument("--expect-mfpc", type=int, choices=(0, 1))
    mon.add_argument("--expect-mfpr", type=int, choices=(0, 1))
    ssid = mon.add_mutually_exclusive_group()
    ssid.add_argument("--expect-ssid", metavar="S")
    ssid.add_argument("--expect-ssid-empty", action="store_true")
    wps = mon.add_mutually_exclusive_group()
    wps.add_argument("--expect-wps", action="store_true")
    wps.add_argument("--expect-no-wps", action="store_true")
    mon.add_argument("--expect-rsn-ciphers", metavar="NAME[,NAME]")
    mon.set_defaults(func=cmd_monitor)

    cli = sub.add_parser("client",
                         help="associate to the pinned BSSID, DHCP, ping")
    cli.add_argument("--mode", choices=("sae", "psk"), required=True)
    cli.add_argument("--ssid", required=True, metavar="S")
    cli.add_argument("--bssid", required=True, metavar="AA:BB:CC:DD:EE:FF")
    cli.add_argument("--freq", type=int, required=True, metavar="MHZ")
    cli.add_argument("--ieee80211w", type=int, choices=(0, 1, 2), default=2)
    cli.add_argument("--scan-ssid", action="store_true")
    cli.add_argument("--secs", type=int, required=True, metavar="N")
    cli.add_argument("--expect-fail", action="store_true")
    cli.add_argument("--hold", type=int, default=0, metavar="N",
                     help="keep the association up N more seconds (0-120) "
                          "after the summary line, for a load measured by "
                          "another process")
    cli.add_argument("--psk", default=PSK_PATH, metavar="PATH",
                     help="the 0600 key file (default /run/newton-psk)")
    cli.set_defaults(func=cmd_client)

    clean = sub.add_parser("cleanup", help="remove mon0, wpa_supplicant, the key")
    clean.set_defaults(func=cmd_cleanup)

    pair = sub.add_parser("pair",
                          help="two stations on the pinned BSSID, one VRF each")
    pair.add_argument("--ssid", required=True, metavar="S")
    pair.add_argument("--bssid", required=True, metavar="AA:BB:CC:DD:EE:FF")
    pair.add_argument("--freq", type=int, required=True, metavar="MHZ")
    pair.add_argument("--ieee80211w", type=int, choices=(0, 1, 2), default=1,
                      help="protected frames: 1 (optional) by default, which "
                           "is what a WPA2/WPA3 mixed AP offers")
    pair.add_argument("--secs", type=int, required=True, metavar="N",
                      help="how long each station may take to associate")
    pair.add_argument("--expect-cross", choices=("reachable", "blocked"),
                      required=True)
    pair.add_argument("--count", type=_positive_int, default=PAIR_COUNT,
                      metavar="N",
                      help="cross pings to send (default %d)" % PAIR_COUNT)
    pair.set_defaults(func=cmd_pair)

    ap = sub.add_parser("ap", help="the Panda as an open access point")
    ap_sub = ap.add_subparsers(dest="ap_command", required=True)
    ap_start = ap_sub.add_parser("start", help="start the open access point")
    ap_start.add_argument("--ssid-hex", required=True, metavar="HEX",
                           help="the SSID as 1 to 32 bytes of lower-case hex; "
                                "it must start with newton-test")
    ap_start.add_argument("--freq", type=int, required=True, metavar="MHZ",
                           help="one of the non-DFS 5 GHz channels: %s"
                                % ", ".join(str(f) for f in AP_FREQS))
    ap_start.add_argument("--secs", type=int, default=AP_DEFAULT_SECS,
                           metavar="N",
                           help="the lifetime in seconds (1 to %d, default %d)"
                                % (AP_MAX_SECS, AP_DEFAULT_SECS))
    ap_start.set_defaults(func=cmd_ap_start)
    ap_stop = ap_sub.add_parser("stop", help="stop the access point")
    ap_stop.set_defaults(func=cmd_ap_stop)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        try:
            signal.signal(sig, _raise_signal)
        except (OSError, ValueError):
            pass
    try:
        return args.func(args)
    except WifiError as e:
        note("%s: %s" % (args.command, e))
        print("%s: failed" % args.command)
        return 1
    except Exception as e:                      # never leave a vif behind
        note("%s: %s: %s" % (args.command, type(e).__name__, e))
        print("%s: failed" % args.command)
        return 1


def _raise_signal(signum, _frame):
    raise SystemExit(128 + signum)


if __name__ == "__main__":
    sys.exit(main())
