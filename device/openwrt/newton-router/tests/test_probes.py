"""Design 3.5d, 3.6, 4.3, 4.4: the probe subcommand - line grammar, probe
rules and the simple probes (fail, ping, resolve, uci, iface, sysctl,
ra-absent, root-password-class, bounds)."""

import re
import subprocess
import time

import pytest

SECRET = "SECRET-MARKER-9f1e"

# One valid argument list per probe (design 4.3); also the base for the
# arg-count cases (one field less / one more than the maximum).
PROBES = { "fail": [], "ping": ["192.0.2.1"], "resolve": ["openwrt.org"],
    "service-running": ["dropbear", "any"], "uci-equals": ["network.lan.proto", "static"],
    "uci-unset": ["network.lan.proto"], "listen": ["tcp", "any", "22", "any", "present"],
    "nft-rule": ["inet", "fw4", "ruleset", "present", "dport 2222"],
    "nft-rule-order": ["inet", "fw4", "input_wan", "Allow-DHCP-Renew", "Drop-Bogon-WAN"],
    "nft-rule-near": ["inet", "fw4", "ruleset", "limit", "3", "rate"],
    "nft-set-has": ["inet", "fw4", "nw_block", "192.0.2.1", "only"],
    "conf-has": ["dnsmasq", "line", "present", "stop-dns-rebind"],
    "proc-args": ["dropbear", "-l br-lan"], "iface-field": ["lan", "up", "true"],
    "iface-absent": ["wan6"], "sysctl-equals": ["ipv4/ip_forward", "1"], "ra-absent": ["wan"],
    "log-has": ["present", "dnsmasq["], "root-password-class": ["LOCKED"], }

MINMAX = { "fail": (0, 0), "ping": (1, 2), "resolve": (1, 2), "service-running": (2, 3),
    "uci-equals": (2, 2), "uci-unset": (1, 1), "listen": (5, 5), "nft-rule": (5, 8),
    "nft-rule-order": (5, 5), "nft-rule-near": (6, 6), "nft-set-has": (5, 5),
    "conf-has": (4, 4), "proc-args": (2, 9), "iface-field": (3, 3),
    "iface-absent": (1, 1), "sysctl-equals": (2, 2), "ra-absent": (1, 1),
    "log-has": (2, 4), "root-password-class": (1, 1), }


def probe_bytes(*fields):
    return ("\t".join(fields) + "\n").encode()


def assert_reached_probe(res, name):
    """The line reached the probe: exactly one probe answer line, empty
    stderr, exit 0 for ok and 1 for fail (design 3.5d)."""
    assert res.err == "", (name, res.err)
    m = re.fullmatch(r"probe %s (ok|fail)( [!-~]+)?" % re.escape(name), res.out.rstrip("\n"))
    assert m, (name, res.out)
    assert res.rc == (0 if m.group(1) == "ok" else 1), (name, res.rc, res.out)


def assert_refused(router, data, reason):
    res = router.probe(stdin=data)
    assert (res.rc, res.out, res.err) == (2, "", f"error bad-probe 1 {reason}\n"), \
        (data, res.rc, res.out, res.err)


def lock_is_free(router):
    lock = router.root / "tmp/newton/flock"
    res = subprocess.run( ["/usr/bin/flock", "-n", str(lock), "/bin/true"],
        capture_output=True, timeout=5, )
    return res.returncode == 0


# ---- 1. the line grammar (3.6, 4.3): ONE table --------------------------------

# (id, stdin bytes, expected reason or None for accepted)
GRAMMAR = []


def _ok(cid, fields):
    GRAMMAR.append((cid, probe_bytes(*fields), None))


def _bad(cid, data, reason):
    GRAMMAR.append((cid, data if isinstance(data, bytes) else probe_bytes(*data), reason))


for _name, _fields in PROBES.items():
    _ok(f"valid-{_name}", [_name] + _fields)

# class-valid fillers used to pad a probe line up to its argument maximum
PAD = { "ping": ["1"], "resolve": ["8.8.8.8"], "service-running": ["present"],
    "nft-rule": ["t1", "t2", "t3", "t4"],
    "proc-args": [f"~e{k}" for k in range(8)], "log-has": ["x", "y", "z"], }

# arg-count: one field less than the minimum and one more than the maximum
for _name, (_mn, _mx) in MINMAX.items():
    _fields = list(PROBES[_name])
    if len(_fields) > _mn:
        _bad(f"arg-count-{_name}-less", [_name] + _fields[:-1], "arg-count")
    _full = _fields + PAD.get(_name, [])[:max(0, _mx - len(_fields))]
    _bad(f"arg-count-{_name}-more", [_name] + _full + [PAD.get(_name, ["x"])[0]], "arg-count")

# the repeating tails (1-4 TEXTs, 1-8 SPECs, 1-3 TEXTs) at both ends
_bad("tail-nft-zero", ["nft-rule", "inet", "fw4", "ruleset", "present"], "arg-count")
_ok("tail-nft-min", ["nft-rule", "inet", "fw4", "ruleset", "present", "x"])
_ok("tail-nft-max", ["nft-rule", "inet", "fw4", "ruleset", "present", "x1", "x2", "x3", "x4"])
_bad("tail-proc-zero", ["proc-args", "ntpd"], "arg-count")
_ok("tail-proc-min", ["proc-args", "ntpd", "~x"])
_ok("tail-proc-max", ["proc-args", "ntpd"] + [f"~e{k}" for k in range(8)])
_bad("tail-log-zero", ["log-has", "present"], "arg-count")
_ok("tail-log-min", ["log-has", "present", "x"])
_ok("tail-log-max", ["log-has", "present", "x", "y", "z"])

# bad-arg-<k> at every class boundary worth naming
_bad("count-0", ["ping", "192.0.2.1", "0"], "bad-arg-2")
_ok("count-1", ["ping", "192.0.2.1", "1"])
_ok("count-3", ["ping", "192.0.2.1", "3"])
_bad("count-4", ["ping", "192.0.2.1", "4"], "bad-arg-2")
_bad("port-0", ["listen", "tcp", "any", "0", "any", "present"], "bad-arg-3")
_ok("port-1", ["listen", "tcp", "any", "1", "any", "present"])
_ok("port-65535", ["listen", "tcp", "any", "65535", "any", "present"])
_bad("port-65536", ["listen", "tcp", "any", "65536", "any", "present"], "bad-arg-3")
_bad("near-0", ["nft-rule-near", "inet", "fw4", "ruleset", "a", "0", "b"], "bad-arg-5")
_ok("near-1", ["nft-rule-near", "inet", "fw4", "ruleset", "a", "1", "b"])
_ok("near-10", ["nft-rule-near", "inet", "fw4", "ruleset", "a", "10", "b"])
_bad("near-11", ["nft-rule-near", "inet", "fw4", "ruleset", "a", "11", "b"], "bad-arg-5")
_ok("expect-eq0", ["log-has", "eq:0", "x"])
_ok("expect-eq1", ["log-has", "eq:1", "x"])
_bad("expect-eq01", ["log-has", "eq:01", "x"], "bad-arg-1")
_bad("expect-eq10000", ["log-has", "eq:10000", "x"], "bad-arg-1")
_ok("expect-min9999", ["log-has", "min:9999", "x"])
_bad("expect-bogus", ["log-has", "bogus", "x"], "bad-arg-1")
_bad("service-case", ["service-running", "Dropbear", "any"], "bad-arg-1")
_bad("service-space", ["service-running", "drop bear", "any"], "bad-arg-1")
_bad("instance", ["service-running", "dropbear", "0bad!x"], "bad-arg-2")
_bad("runstate", ["service-running", "dropbear", "any", "maybe"], "bad-arg-3")
_bad("addr-short", ["listen", "tcp", ":", "22", "any", "present"], "bad-arg-2")
_bad("addr-char", ["listen", "tcp", "tcp!1", "22", "any", "present"], "bad-arg-2")
_bad("prog", ["listen", "tcp", "any", "22", "@prog", "present"], "bad-arg-4")
_bad("proto", ["listen", "tcp6", "any", "22", "any", "present"], "bad-arg-1")
_bad("nftfam", ["nft-rule", "inetx", "fw4", "ruleset", "present", "x"], "bad-arg-1")
_bad("nftname", ["nft-rule", "inet", "fw4!", "ruleset", "present", "x"], "bad-arg-2")
_bad("chainpos", ["nft-rule", "inet", "fw4", "ruleset!", "present", "x"], "bad-arg-3")
_bad("key-dot", ["sysctl-equals", "ipv4/conf/.", "1"], "bad-arg-1")
_bad("key-dotdot", ["sysctl-equals", "ipv4/conf/..", "1"], "bad-arg-1")
_ok("key-depth5", ["sysctl-equals", "ipv4/a/b/c/d", "1"])
_ok("key-depth6", ["sysctl-equals", "ipv4/a/b/c/d/e", "1"])
_bad("key-depth7", ["sysctl-equals", "ipv4/a/b/c/d/e/f", "1"], "bad-arg-1")
_bad("key-family", ["sysctl-equals", "fs/file-max", "1"], "bad-arg-1")
_bad("element", ["nft-set-has", "inet", "fw4", "s", "!elem", "present"], "bad-arg-4")
_bad("setstate", ["nft-set-has", "inet", "fw4", "s", "1.2.3.4", "maybe"], "bad-arg-5")
_bad("field", ["iface-field", "lan", "upx", "true"], "bad-arg-2")
_bad("iface", ["iface-field", "lan!", "up", "true"], "bad-arg-1")
_bad("class", ["root-password-class", "empty"], "bad-arg-1")
_bad("mode", ["conf-has", "dnsmasq", "regex", "present", "x"], "bad-arg-2")
_bad("dnssvc", ["conf-has", "unbound", "line", "present", "x"], "bad-arg-1")
_bad("spec-bang", ["proc-args", "ntpd", "!"], "bad-arg-2")
_bad("spec-tilde", ["proc-args", "ntpd", "~"], "bad-arg-2")
_bad("spec-5", ["proc-args", "ntpd", "a b c d e"], "bad-arg-2")
_bad("host", ["ping", "-abc"], "bad-arg-1")
_bad("ucipath3-two", ["uci-equals", "network.lan", "1"], "bad-arg-1")
_bad("ucipath-one", ["uci-unset", "network"], "bad-arg-1")

# syntax, too-long, unknown-probe
_bad("syntax-backslash", b"ping\tbad\\host\n", "syntax")
_bad("syntax-cr", b"ping\t192.0.2.1\r\n", "syntax")
_bad("syntax-x01", b"ping\t\x01host\n", "syntax")
_bad("syntax-x7f", b"ping\thost\x7f\n", "syntax")
_bad("syntax-x80", b"ping\thost\x80\n", "syntax")
_bad("syntax-empty-field", b"ping\t\t192.0.2.1\n", "syntax")
_bad("syntax-empty-fields", b"a\t\tb\n", "syntax")
_bad("syntax-lead-tab", b"\tping\t192.0.2.1\n", "syntax")
_bad("syntax-trail-tab", b"ping\t192.0.2.1\t\n", "syntax")
_bad("syntax-empty-line", b"\n", "syntax")
_bad("syntax-no-lf", b"ping\t192.0.2.1", "syntax")
_bad("syntax-two-lines", b"ping\t192.0.2.1\nfail\n", "syntax")

_PREFIX = "\t".join(["nft-rule", "inet", "fw4", "ruleset", "present"])
# 4 TEXT fields of 128 bytes exactly fill a 513-byte line (513 > 512)
_T4 = 513 - len(_PREFIX) - 1 - 3 - 3 * 128
GRAMMAR.append(("too-long-line-513",
                probe_bytes("nft-rule", "inet", "fw4", "ruleset", "present",
                            "x" * 128, "x" * 128, "x" * 128, "x" * _T4), "too-long"))
_T5 = 512 - len(_PREFIX) - 1 - 3 - 3 * 128
GRAMMAR.append(("line-512-ok", probe_bytes("nft-rule", "inet", "fw4", "ruleset", "present",
                            "x" * 128, "x" * 128, "x" * 128, "x" * _T5), None))
_bad("too-long-field-129", ["uci-equals", "network.lan.proto", "x" * 129], "too-long")
_ok("field-128-ok", ["uci-equals", "network.lan.proto", "x" * 128])
_bad("unknown-probe", ["no-such-probe", "x"], "unknown-probe")
_bad("unknown-empty-name", ["!bad"], "unknown-probe")


@pytest.mark.parametrize("cid,data,reason", GRAMMAR, ids=[g[0] for g in GRAMMAR])
def test_grammar(router, cid, data, reason):
    if reason is None:
        name = data.split(b"\t")[0].decode().strip()
        assert_reached_probe(router.probe(stdin=data), name)
    else:
        assert_refused(router, data, reason)


# ---- the 43 scenario checks of design 4.6 (52 probe lines; TABs on the wire) --

SCENARIOS = [
    ["fail"],
    ["conf-has", "dnsmasq", "substr", "present", "02:00:00:00:00:77"],
    ["conf-has", "dnsmasq", "substr", "present", "02:00:00:00:00:09"],
    ["nft-rule", "inet", "fw4", "ruleset", "present", "dport 2222"],
    ["conf-has", "dnsmasq", "prefix", "present", "dhcp-range=set:lab,192.168.150.100,192.168.150.149,"],
    ["conf-has", "dnsmasq", "line", "absent", "rebind-localhost-ok"],
    ["conf-has", "dnsmasq", "line", "present", "stop-dns-rebind"],
    ["conf-has", "dnsmasq", "line", "present", "dnssec"],
    ["conf-has", "dnsmasq", "line", "present", "conf-file=/usr/share/dnsmasq/trust-anchors.conf"],
    ["log-has", "present", "dnsmasq[", "DNSSEC validation enabled"],
    ["conf-has", "dnsmasq", "line", "present", "dnssec"],  # ow-dns-04c
    ["proc-args", "https-dns-proxy", "-p 5053", "-r https://dns.quad9.net/dns-query"],
    ["nft-rule", "inet", "fw4", "dstnat_lab", "present", "ubus:https-dns-proxy"],
    ["nft-rule", "inet", "fw4", "forward_lab", "present", "ubus:https-dns-proxy"],
    ["nft-rule", "inet", "fw4", "dstnat_lab", "eq:2", "redirect to :53"],
    ["nft-rule", "inet", "fw4", "forward_lab", "present", "tcp dport 853", "jump reject_to_wan"],
    ["nft-rule", "inet", "fw4", "forward_lab", "eq:2", "dport 53 ", "jump reject_to_wan"],
    ["nft-rule", "inet", "fw4", "input_wan", "present", "jump drop_from_wan"],
    ["nft-rule", "inet", "fw4", "syn_flood", "present", "limit rate 25/second burst 50 packets return"],
    ["uci-equals", "firewall.@defaults[0].synflood_protect", "1"],
    ["nft-rule", "inet", "fw4", "ruleset", "eq:3", "invalid : drop"],
    ["nft-rule", "inet", "fw4", "input_wan", "absent", "Allow-Ping"],
    ["nft-rule", "inet", "fw4", "input_wan", "present", "Allow-DHCP-Renew"],
    ["listen", "udp", "any", "1900", "miniupnpd", "present"],
    ["nft-rule-order", "inet", "fw4", "input_wan", "Allow-DHCP-Renew", "Drop-Bogon-WAN"],
    ["nft-rule-order", "inet", "fw4", "input_wan", "Allow-Ping", "Drop-Bogon-WAN"],
    ["nft-rule", "inet", "fw4", "reject_from_wan", "present", 'log prefix "reject wan in: "'],
    ["nft-rule-near", "inet", "fw4", "ruleset", "limit wan.log_limit", "3", "rate 30/minute"],
    ["proc-args", "logread", "-r 192.0.2.10 514", "-u"],
    ["proc-args", "logd", "-S 512"],
    ["listen", "tcp", "10.109.0.11", "22", "dropbear", "present"],
    ["proc-args", "dropbear", "-l br-lan"],
    ["listen", "tcp", "10.109.0.11", "443", "uhttpd", "present"],
    ["proc-args", "uhttpd", "-q"],
    ["proc-args", "dropbear", "-I 600"],
    ["proc-args", "dropbear", "-I 20"],
    ["proc-args", "ntpd", "-l", "-I @dev:lab", "-p time.cloudflare.com", "-p time.google.com", "-p pool.ntp.org", "!~openwrt.pool.ntp.org"],
    ["nft-set-has", "inet", "fw4", "nw_block", "192.0.2.1", "only"],
    ["sysctl-equals", "ipv6/conf/@dev:lab/disable_ipv6", "1"],
    ["iface-absent", "wan6"],
    ["ra-absent", "wan"],
    ["iface-field", "guest", "up", "true"],
    ["nft-rule", "inet", "fw4", "input_guest", "present", "Allow-Guest-DHCP"],
    ["nft-rule", "inet", "fw4", "input_guest", "present", "jump reject_from_guest"],
    ["nft-rule", "inet", "fw4", "forward_guest", "present", "jump accept_to_wan"],
    ["nft-rule", "inet", "fw4", "forward_guest", "present", "jump reject_to_guest"],
    ["nft-rule", "inet", "fw4", "forward_guest", "absent", "jump accept_to_", "!accept_to_wan"],
    ["iface-field", "iot", "up", "true"],
    ["nft-rule", "inet", "fw4", "forward_lab", "present", "jump accept_to_iot"],
    ["nft-rule", "inet", "fw4", "input_iot", "present", "jump reject_from_iot"],
    ["nft-rule", "inet", "fw4", "forward_iot", "present", "jump reject_to_iot"],
    ["nft-rule", "inet", "fw4", "forward_iot", "absent", "jump accept_to_"], ]

assert len(SCENARIOS) == 52


@pytest.mark.parametrize( "fields", SCENARIOS,
    ids=[" ".join(f for f in s if " " not in f)[:60] for s in SCENARIOS])
def test_scenario_lines_accepted_by_the_grammar(router, fields):
    assert_reached_probe(router.probe(*fields), fields[0])


# ---- 2. probe rules (3.5d) ----------------------------------------------------


@pytest.mark.parametrize("name", sorted(PROBES), ids=sorted(PROBES))
def test_read_role_may_run_any_probe_but_root_password_class(router, name):
    router.write("etc/shadow", f"root:${SECRET}hash:19000:0:99999:7:::\n")
    res = router.probe(name, *PROBES[name], role="read")
    if name == "root-password-class":
        assert (res.rc, res.out, res.err) == (3, "", "error role\n")
        assert SECRET not in res.out and SECRET not in res.err
    else:
        assert_reached_probe(res, name)


def test_root_password_class_denied_to_read_role_no_shadow_access(router):
    router.write("etc/shadow", f"root:${SECRET}hash:19000:0:99999:7:::\n")
    res = router.probe("root-password-class", "HASH", role="read")
    assert (res.rc, res.out, res.err) == (3, "", "error role\n")
    assert "shadow" not in "".join(router.calls(exclude=()))


# ---- 3. the simple probes: pass, fail, exact reason, exact argv ---------------


def test_fail_never_passes(router):
    res = router.probe("fail")
    assert (res.rc, res.out, res.err) == (1, "probe fail fail planted\n", "")
    assert router.calls() == []


def test_ping_ok_default_count_one(router):
    res = router.probe("ping", "192.0.2.1")
    assert (res.rc, res.out, res.err) == (0, "probe ping ok\n", "")
    assert router.calls() == ["ping -c 1 -W 3 192.0.2.1"]


def test_ping_explicit_count(router):
    res = router.probe("ping", "openwrt.org", "3")
    assert (res.rc, res.out) == (0, "probe ping ok\n")
    assert router.calls() == ["ping -c 3 -W 3 openwrt.org"]


def test_ping_rc1_fails_with_reason_fail(router):
    router.set_fake("ping", rc=1)
    res = router.probe("ping", "192.0.2.1")
    assert (res.rc, res.out, res.err) == (1, "probe ping fail fail\n", "")


def test_resolve_default_server_is_localhost(router):
    res = router.probe("resolve", "openwrt.org")
    assert (res.rc, res.out) == (0, "probe resolve ok\n")
    assert router.calls() == ["nslookup openwrt.org 127.0.0.1"]


def test_resolve_explicit_server(router):
    res = router.probe("resolve", "openwrt.org", "10.9.0.53")
    assert (res.rc, res.out) == (0, "probe resolve ok\n")
    assert router.calls() == ["nslookup openwrt.org 10.9.0.53"]


def test_resolve_rc2_fails_with_reason_fail(router):
    router.set_fake("nslookup", rc=2)
    res = router.probe("resolve", "openwrt.org")
    assert (res.rc, res.out) == (1, "probe resolve fail fail\n")


def test_uci_equals_ok(router):
    router.set_fake("uci", out="REJECT\n")
    res = router.probe("uci-equals", "firewall.@defaults[0].input", "REJECT")
    assert (res.rc, res.out, res.err) == (0, "probe uci-equals ok\n", "")
    assert router.calls() == ["uci -q get firewall.@defaults[0].input"]


def test_uci_equals_mismatch(router):
    router.set_fake("uci", out="ACCEPT\n")
    res = router.probe("uci-equals", "firewall.@defaults[0].input", "REJECT")
    assert (res.rc, res.out) == (1, "probe uci-equals fail mismatch\n")


def test_uci_equals_unset(router):
    router.set_fake("uci", rc=1)
    res = router.probe("uci-equals", "firewall.@defaults[0].input", "REJECT")
    assert (res.rc, res.out) == (1, "probe uci-equals fail unset\n")


def test_uci_unset_present(router):
    router.set_fake("uci", out="1\n")
    res = router.probe("uci-unset", "network.lan.proto")
    assert (res.rc, res.out) == (1, "probe uci-unset fail present\n")


def test_uci_unset_ok(router):
    router.set_fake("uci", rc=1)
    res = router.probe("uci-unset", "network.lan.proto")
    assert (res.rc, res.out) == (0, "probe uci-unset ok\n")
    assert router.calls() == ["uci -q get network.lan.proto"]


def test_iface_field_ok(router):
    router.set_fake("ifstatus", out='{"up":true,"proto":"dhcp"}\n')
    res = router.probe("iface-field", "lan", "up", "true")
    assert (res.rc, res.out, res.err) == (0, "probe iface-field ok\n", "")
    calls = router.calls()
    assert "ifstatus lan" in calls
    assert any(c.startswith("jsonfilter -i ") and c.endswith(" -e @.up") for c in calls), calls


def test_iface_field_mismatch(router):
    router.set_fake("ifstatus", out='{"up":false}\n')
    res = router.probe("iface-field", "lan", "up", "true")
    assert (res.rc, res.out) == (1, "probe iface-field fail mismatch\n")


def test_iface_field_ifstatus_failing_is_error(router):
    router.set_fake("ifstatus", rc=2)
    res = router.probe("iface-field", "lan", "up", "true")
    assert (res.rc, res.out) == (1, "probe iface-field fail error\n")


def test_iface_absent_ok_when_ifstatus_fails(router):
    router.set_fake("ifstatus", rc=1)
    res = router.probe("iface-absent", "wan6")
    assert (res.rc, res.out, res.err) == (0, "probe iface-absent ok\n", "")
    assert router.calls() == ["ifstatus wan6"]


def test_iface_absent_present(router):
    router.set_fake("ifstatus", out='{"up":true}\n')
    res = router.probe("iface-absent", "wan6")
    assert (res.rc, res.out) == (1, "probe iface-absent fail present\n")


# sysctl-equals: plain key, @dev:, @l3dev:, missing file, bad device
def test_sysctl_equals_plain_ok(router):
    router.write("proc/sys/net/ipv4/ip_forward", "1\n")
    res = router.probe("sysctl-equals", "ipv4/ip_forward", "1")
    assert (res.rc, res.out, res.err) == (0, "probe sysctl-equals ok\n", "")
    assert router.calls() == []


def test_sysctl_equals_mismatch(router):
    router.write("proc/sys/net/ipv4/ip_forward", "0\n")
    res = router.probe("sysctl-equals", "ipv4/ip_forward", "1")
    assert (res.rc, res.out) == (1, "probe sysctl-equals fail mismatch\n")


def test_sysctl_equals_dev_resolution(router):
    router.set_fake("ifstatus", out='{"device":"br-lan","l3_device":"eth0"}\n')
    router.write("proc/sys/net/ipv4/conf/br-lan/forwarding", "2\n")
    res = router.probe("sysctl-equals", "ipv4/conf/@dev:lab/forwarding", "2")
    assert (res.rc, res.out) == (0, "probe sysctl-equals ok\n")
    calls = router.calls()
    assert "ifstatus lab" in calls
    assert any(c.endswith(" -e @.device") for c in calls), calls


def test_sysctl_equals_l3dev_resolution(router):
    router.set_fake("ifstatus", out='{"device":"br-lan","l3_device":"eth0"}\n')
    router.write("proc/sys/net/ipv6/conf/eth0/disable_ipv6", "1\n")
    res = router.probe("sysctl-equals", "ipv6/conf/@l3dev:wan6/disable_ipv6", "1")
    assert (res.rc, res.out) == (0, "probe sysctl-equals ok\n")
    assert any(c.endswith(" -e @.l3_device") for c in router.calls())


def test_sysctl_equals_missing_file_is_error(router):
    res = router.probe("sysctl-equals", "ipv4/ip_forward", "1")
    assert (res.rc, res.out) == (1, "probe sysctl-equals fail error\n")


# sysctl-equals: BusyBox `read` returns rc=1 when the file lacks a trailing
# newline, but it has set the variable; the probe must NOT clear it.
def test_sysctl_equals_no_trailing_newline(router):
    router.write("proc/sys/net/ipv4/ip_forward", b"1")
    res = router.probe("sysctl-equals", "ipv4/ip_forward", "1")
    assert (res.rc, res.out, res.err) == (0, "probe sysctl-equals ok\n", "")
    assert router.calls() == []


def test_sysctl_equals_no_trailing_newline_mismatch(router):
    router.write("proc/sys/net/ipv4/ip_forward", b"0")
    res = router.probe("sysctl-equals", "ipv4/ip_forward", "1")
    assert (res.rc, res.out) == (1, "probe sysctl-equals fail mismatch\n")


def test_sysctl_equals_resolved_device_outside_iface_class(router):
    router.set_fake("ifstatus", out='{"device":"bad!dev"}\n')
    res = router.probe("sysctl-equals", "ipv4/conf/@dev:lab/forwarding", "2")
    assert (res.rc, res.out) == (1, "probe sysctl-equals fail error\n")


# ra-absent: l3_device, fallback to device, ubus failing
def test_ra_absent_ok(router):
    router.set_fake("ifstatus", out='{"l3_device":"eth1","device":"eth0"}\n')
    router.set_fake("ubus", out='{"device":"eth0"}\n')
    res = router.probe("ra-absent", "wan")
    assert (res.rc, res.out, res.err) == (0, "probe ra-absent ok\n", "")
    assert "ubus call dhcp ipv6ra" in router.calls()


def test_ra_absent_present(router):
    router.set_fake("ifstatus", out='{"l3_device":"eth1"}\n')
    router.set_fake("ubus", out='{"ra":["eth1"]}\n')
    res = router.probe("ra-absent", "wan")
    assert (res.rc, res.out) == (1, "probe ra-absent fail present\n")


def test_ra_absent_fallback_to_device(router):
    router.set_fake("ifstatus", out='{"device":"eth0"}\n')
    router.set_fake("ubus", out='{"ra":["eth0"]}\n')
    res = router.probe("ra-absent", "wan")
    assert (res.rc, res.out) == (1, "probe ra-absent fail present\n")
    calls = router.calls()
    assert any(c.endswith(" -e @.l3_device") for c in calls)
    assert any(c.endswith(" -e @.device") for c in calls)


def test_ra_absent_ubus_failing_is_error(router):
    router.set_fake("ifstatus", out='{"l3_device":"eth1"}\n')
    router.set_fake("ubus", rc=2)
    res = router.probe("ra-absent", "wan")
    assert (res.rc, res.out) == (1, "probe ra-absent fail error\n")


# root-password-class: the five classes, the mismatch reason, no field leak
SHADOWS = { "EMPTY": "root::19000:0:99999:7:::\n",
    "LOCKED": "daemon:x:0:0:::\nroot:!:19000:0:99999:7:::\n",
    "HASH": f"root:${SECRET}1$abc:19000:0:99999:7:::\n", "NOROOT": "daemon:x:0:0:::\n",
    "MULTIROOT": "root:$1$a:1:0:::\nroot:$1$b:2:0:::\n", }


@pytest.mark.parametrize("cls", sorted(SHADOWS), ids=sorted(SHADOWS))
def test_root_password_class_matches(router, cls):
    router.write("etc/shadow", SHADOWS[cls])
    res = router.probe("root-password-class", cls)
    assert (res.rc, res.out, res.err) == (0, "probe root-password-class ok\n", "")


def test_root_password_class_mismatch_names_the_actual_class(router):
    router.write("etc/shadow", SHADOWS["LOCKED"])
    res = router.probe("root-password-class", "HASH")
    assert (res.rc, res.out) == (1, "probe root-password-class fail class=LOCKED\n")


def test_root_password_class_field_is_never_printed(router):
    router.write("etc/shadow", SHADOWS["HASH"])
    for cls in ("EMPTY", "LOCKED", "HASH", "NOROOT", "MULTIROOT"):
        res = router.probe("root-password-class", cls)
        assert SECRET not in res.out and SECRET not in res.err
        assert "$1$" not in res.out


# ---- 7. bounds (4.4, M17, M46): ONE slow test, about 33 s ---------------------

# SLOW: waits out the 30 s stdin bound, a 10 s ping bound and a 5 s uci bound.
@pytest.mark.slow
def test_stdin_timeout_probe_bounds_and_lock(router):
    t0 = time.monotonic()
    proc, finish = router.forced_open_stdin_start("probe")
    time.sleep(1.5)
    assert lock_is_free(router), "a probe waiting on stdin must not hold the lock"
    router.set_fake("ping", sleep=60)
    start = time.monotonic()
    res = router.probe("ping", "192.0.2.1", timeout=25)
    elapsed = time.monotonic() - start
    assert (res.rc, res.out, res.err) == (1, "probe ping fail timeout\n", "")
    assert 9 <= elapsed <= 20, elapsed
    assert lock_is_free(router)
    router.set_fake("uci", sleep=60)
    start = time.monotonic()
    res = router.probe("uci-equals", "network.lan.proto", "static", timeout=20)
    elapsed = time.monotonic() - start
    assert (res.rc, res.out) == (1, "probe uci-equals fail timeout\n")
    assert 4 <= elapsed <= 12, elapsed
    assert lock_is_free(router)
    res = finish(timeout=35)
    assert (res.rc, res.out, res.err) == (2, "", "error stdin-timeout\n")
    assert 25 <= time.monotonic() - t0 <= 36
    assert lock_is_free(router)


def test_uci_equals_compares_the_whole_value(router):
    # touch-up after a planted-defect run: a prefix is not equality
    router.set_fake("uci", out="REJECTED\n")
    res = router.probe("uci-equals", "firewall.@defaults[0].input", "REJECT")
    assert (res.rc, res.out) == (1, "probe uci-equals fail mismatch\n")
    router.set_fake("uci", out="REJ\n")
    res = router.probe("uci-equals", "firewall.@defaults[0].input", "REJECT")
    assert (res.rc, res.out) == (1, "probe uci-equals fail mismatch\n")
