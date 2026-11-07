"""Design 4.2, 4.3, 9.2 group 9: matching probes (service-running, listen,
nft-*, log-has, conf-has, proc-args), the matching rules, a failing data
command (M49) and router output never leaking (M16)."""

import os

import pytest

from test_probes import PROBES, SECRET, assert_reached_probe

UBUS_DROPPEAR = ('{"dropbear":{"instances":'
                 '{"cfg1":{"running":true},"cfg2":{"running":false}}}}\n')


# ---- service-running (4.3, through the jsonfilter fake) -----------------------


def test_service_running_present_any(router):
    router.set_fake("ubus", out=UBUS_DROPPEAR)
    res = router.probe("service-running", "dropbear", "any")
    assert (res.rc, res.out, res.err) == (0, "probe service-running ok\n", "")
    assert 'ubus call service list {"name":"dropbear"}' in router.calls()
    assert any(c.startswith("jsonfilter -i ")
               and c.endswith(' -e @["dropbear"].instances[*].running')
               for c in router.calls())


def test_service_running_no_true_line_is_absent(router):
    router.set_fake("ubus", out='{"dropbear":{"instances":' '{"cfg1":{"running":false}}}}\n')
    res = router.probe("service-running", "dropbear", "any")
    assert (res.rc, res.out) == (1, "probe service-running fail absent\n")


def test_service_running_named_instance(router):
    router.set_fake("ubus", out=UBUS_DROPPEAR)
    res = router.probe("service-running", "dropbear", "cfg1")
    assert (res.rc, res.out) == (0, "probe service-running ok\n")
    assert any(c.startswith("jsonfilter -i ")
               and c.endswith(' -e @["dropbear"].instances["cfg1"].running')
               for c in router.calls())


def test_service_running_stopped_named_instance(router):
    router.set_fake("ubus", out=UBUS_DROPPEAR)
    res = router.probe("service-running", "dropbear", "cfg2")
    assert (res.rc, res.out) == (1, "probe service-running fail absent\n")


def test_service_running_absent_state_passes_when_not_running(router):
    router.set_fake("ubus", out='{"dropbear":{"instances":' '{"cfg1":{"running":false}}}}\n')
    res = router.probe("service-running", "dropbear", "any", "absent")
    assert (res.rc, res.out) == (0, "probe service-running ok\n")


def test_service_running_absent_state_fails_when_running(router):
    router.set_fake("ubus", out=UBUS_DROPPEAR)
    res = router.probe("service-running", "dropbear", "any", "absent")
    assert (res.rc, res.out) == (1, "probe service-running fail present\n")


def test_service_running_ubus_error(router):
    router.set_fake("ubus", rc=2)
    res = router.probe("service-running", "dropbear", "any")
    assert (res.rc, res.out) == (1, "probe service-running fail error\n")


# ---- listen (4.3) --------------------------------------------------------------


def test_listen_tcp_any_and_argv(router):
    router.set_fake("netstat", out=( "tcp 0 0 10.109.0.11:22 0.0.0.0:* LISTEN 220/dropbear\n"
        "tcp 0 0 127.0.0.1:5353 0.0.0.0:* LISTEN 400/mdnsd\n"))
    res = router.probe("listen", "tcp", "any", "22", "dropbear", "present")
    assert (res.rc, res.out, res.err) == (0, "probe listen ok\n", "")
    assert router.calls() == ["netstat -lnp -t"]


def test_listen_wildcard_matches_v4_and_v6(router):
    router.set_fake("netstat", out=( "tcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN 220/dropbear\n"
        "tcp 0 0 10.0.0.5:22 0.0.0.0:* LISTEN 220/dropbear\n"
        "tcp6 0 0 :::22 :::* LISTEN 220/dropbear\n"))
    res = router.probe("listen", "tcp", "wildcard", "22", "any", "eq:2")
    assert (res.rc, res.out) == (0, "probe listen ok\n")
    res = router.probe("listen", "tcp", "wildcard", "22", "any", "eq:3")
    assert (res.rc, res.out) == (1, "probe listen fail count=2\n")


def test_listen_specific_address_and_tcp6_row(router):
    router.set_fake("netstat", out=( "tcp6 0 0 ::1:853 :::* LISTEN 500/https-dns-proxy\n"
        "tcp 0 0 0.0.0.0:853 0.0.0.0:* LISTEN 500/https-dns-proxy\n"))
    res = router.probe("listen", "tcp", "::1", "853", "https-dns-proxy", "present")
    assert (res.rc, res.out) == (0, "probe listen ok\n")
    res = router.probe("listen", "tcp", "0.0.0.0", "853", "any", "eq:1")
    assert (res.rc, res.out) == (0, "probe listen ok\n")


def test_listen_udp_and_program_after_slash(router):
    router.set_fake("netstat", out="udp 0 0 0.0.0.0:1900 0.0.0.0:* " "300/miniupnpd\n")
    res = router.probe("listen", "udp", "wildcard", "1900", "miniupnpd", "present")
    assert (res.rc, res.out) == (0, "probe listen ok\n")
    assert router.calls() == ["netstat -lnp -u"]
    res = router.probe("listen", "udp", "wildcard", "1900", "other", "present")
    assert (res.rc, res.out) == (1, "probe listen fail count=0\n")


def test_listen_min_and_absent(router):
    router.set_fake("netstat", out=( "tcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN 1/sshd\n"
        "tcp 0 0 10.0.0.5:22 0.0.0.0:* LISTEN 2/sshd\n"))
    assert router.probe("listen", "tcp", "any", "22", "any", "min:2").out == "probe listen ok\n"
    res = router.probe("listen", "tcp", "any", "22", "any", "min:3")
    assert (res.rc, res.out) == (1, "probe listen fail count=2\n")
    res = router.probe("listen", "tcp", "any", "23", "any", "absent")
    assert (res.rc, res.out) == (0, "probe listen ok\n")


def test_listen_netstat_failing_is_error(router):
    router.set_fake("netstat", rc=2)
    res = router.probe("listen", "tcp", "any", "22", "any", "present")
    assert (res.rc, res.out) == (1, "probe listen fail error\n")
# ---- nft-rule, nft-rule-order, nft-rule-near, nft-set-has (4.3) ---------------


def test_nft_rule_ordered_texts_in_order(router):
    router.set_fake("nft", out=( "ip saddr . iifname @allow_in\n"
        "tcp dport 2222 dnat to 192.168.150.10\n"
        "jump drop_from_wan\n"))
    res = router.probe("nft-rule", "inet", "fw4", "ruleset", "present", "dport 2222")
    assert (res.rc, res.out, res.err) == (0, "probe nft-rule ok\n", "")
    assert router.calls() == ["nft list ruleset"]


def test_nft_rule_uses_list_chain_for_a_named_chain(router):
    router.set_fake("nft", out="jump drop_from_wan\n")
    res = router.probe("nft-rule", "inet", "fw4", "input_wan", "present", "jump drop_from_wan")
    assert (res.rc, res.out) == (0, "probe nft-rule ok\n")
    assert router.calls() == ["nft list chain inet fw4 input_wan"]


def test_nft_rule_ordered_texts_out_of_order_do_not_match(router):
    router.set_fake("nft", out="tcp dport 2222 dnat to 192.168.150.10\n")
    res = router.probe("nft-rule", "inet", "fw4", "ruleset", "eq:1", "dnat", "tcp")
    assert (res.rc, res.out) == (1, "probe nft-rule fail count=0\n")


def test_nft_rule_ordered_texts_must_share_one_line(router):
    router.set_fake("nft", out="ip saddr . iifname @allow_in\n" "jump drop_from_wan\n")
    res = router.probe("nft-rule", "inet", "fw4", "ruleset", "present", "saddr", "jump")
    assert (res.rc, res.out) == (1, "probe nft-rule fail count=0\n")


def test_nft_rule_negative_text_removes_lines(router):
    router.set_fake("nft", out=( "jump accept_to_wan\n" "jump accept_to_iot\n"))
    # the wan line is removed by !accept_to_wan; only the iot line counts
    res = router.probe("nft-rule", "inet", "fw4", "forward_guest", "present",
                       "jump accept_to_", "!accept_to_wan")
    assert (res.rc, res.out) == (0, "probe nft-rule ok\n")
    res = router.probe("nft-rule", "inet", "fw4", "forward_guest", "eq:2",
                       "jump accept_to_", "!accept_to_wan")
    assert (res.rc, res.out) == (1, "probe nft-rule fail count=1\n")


def test_nft_rule_every_expect_form(router):
    router.set_fake("nft", out="invalid : drop\ninvalid : drop\nx\n")
    ok = router.probe("nft-rule", "inet", "fw4", "ruleset", "eq:2", "invalid : drop")
    assert ok.out == "probe nft-rule ok\n"
    for expect, reason in (("present", None), ("absent", "count=2"),
                           ("eq:3", "count=2"), ("eq:0", "count=2"),
                           ("min:2", None), ("min:3", "count=2")):
        res = router.probe("nft-rule", "inet", "fw4", "ruleset", expect, "invalid : drop")
        if reason is None:
            assert (res.rc, res.out) == (0, "probe nft-rule ok\n")
        else:
            assert (res.rc, res.out) == (1, f"probe nft-rule fail {reason}\n")


def test_nft_rule_order_ok_and_reversed(router):
    router.set_fake("nft", out="Allow-DHCP-Renew\nAllow-Ping\n" "Drop-Bogon-WAN\n")
    res = router.probe("nft-rule-order", "inet", "fw4", "input_wan",
                       "Allow-Ping", "Drop-Bogon-WAN")
    assert (res.rc, res.out) == (0, "probe nft-rule-order ok\n")
    res = router.probe("nft-rule-order", "inet", "fw4", "input_wan",
                       "Drop-Bogon-WAN", "Allow-Ping")
    assert (res.rc, res.out) == (1, "probe nft-rule-order fail order\n")


def test_nft_rule_order_missing_text_is_absent(router):
    router.set_fake("nft", out="Allow-Ping\n")
    res = router.probe("nft-rule-order", "inet", "fw4", "input_wan",
                       "Allow-Ping", "No-Such-Text")
    assert (res.rc, res.out) == (1, "probe nft-rule-order fail absent\n")


def test_nft_rule_near_boundary(router):
    router.set_fake("nft", out="l0\nA\nl2\nl3\nB\nl5\n")
    res = router.probe("nft-rule-near", "inet", "fw4", "ruleset", "A", "3", "B")
    assert (res.rc, res.out) == (0, "probe nft-rule-near ok\n")
    router.set_fake("nft", out="l0\nA\nl2\nl3\nl4\nB\n")
    res = router.probe("nft-rule-near", "inet", "fw4", "ruleset", "A", "3", "B")
    assert (res.rc, res.out) == (1, "probe nft-rule-near fail not-near\n")


def test_nft_set_has_states_and_multiline_elements(router):
    router.set_fake("nft", out=( "set nw_block {\n" "\ttype ipv4_addr\n"
        "\telements = { 192.0.2.1,\n"
        "\t\t\t198.51.100.7, 203.0.113.9 }\n"
        "}\n"))
    assert router.calls() == []
    res = router.probe("nft-set-has", "inet", "fw4", "nw_block", "198.51.100.7", "present")
    assert (res.rc, res.out, res.err) == (0, "probe nft-set-has ok\n", "")
    assert router.calls() == ["nft list set inet fw4 nw_block"]
    res = router.probe("nft-set-has", "inet", "fw4", "nw_block", "192.0.2.99", "absent")
    assert (res.rc, res.out) == (0, "probe nft-set-has ok\n")
    res = router.probe("nft-set-has", "inet", "fw4", "nw_block", "192.0.2.1", "absent")
    assert (res.rc, res.out) == (1, "probe nft-set-has fail present\n")
    res = router.probe("nft-set-has", "inet", "fw4", "nw_block", "192.0.2.1", "only")
    assert (res.rc, res.out) == (1, "probe nft-set-has fail mismatch\n")


def test_nft_set_has_only_with_one_element(router):
    router.set_fake("nft", out="set s { elements = { 192.0.2.1 } }\n")
    res = router.probe("nft-set-has", "inet", "fw4", "s", "192.0.2.1", "only")
    assert (res.rc, res.out) == (0, "probe nft-set-has ok\n")
    res = router.probe("nft-set-has", "inet", "fw4", "s", "198.51.100.1", "present")
    assert (res.rc, res.out) == (1, "probe nft-set-has fail absent\n")
# ---- log-has (4.3) -------------------------------------------------------------


def test_log_has_counts_matching_lines(router):
    router.set_fake("logread", out=( "dnsmasq[1]: DNSSEC validation enabled\n"
        "dnsmasq[1]: cache size 150\n"
        "dnsmasq[2]: DNSSEC validation enabled\n"
        "hostapd: ap0\n"))
    res = router.probe("log-has", "present", "dnsmasq[", "DNSSEC validation enabled")
    assert (res.rc, res.out, res.err) == (0, "probe log-has ok\n", "")
    assert router.calls() == ["logread "]
    res = router.probe("log-has", "eq:2", "dnsmasq[", "DNSSEC validation enabled")
    assert (res.rc, res.out) == (0, "probe log-has ok\n")
    res = router.probe("log-has", "eq:4", "dnsmasq[")
    assert (res.rc, res.out) == (1, "probe log-has fail count=3\n")
    res = router.probe("log-has", "absent", "unbound")
    assert (res.rc, res.out) == (0, "probe log-has ok\n")


# ---- conf-has (4.3) ------------------------------------------------------------


def test_conf_has_reads_the_pid_c_argument(router):
    router.set_fake("pidof", out="123\n")
    router.write("proc/123/cmdline", b"dnsmasq\x00-C\x00/var/etc/dnsmasq.conf.dhcp\x00")
    router.write("var/etc/dnsmasq.conf.dhcp", "stop-dns-rebind\nno-resolv\n")
    res = router.probe("conf-has", "dnsmasq", "line", "present", "stop-dns-rebind")
    assert (res.rc, res.out, res.err) == (0, "probe conf-has ok\n", "")
    assert "pidof dnsmasq" in router.calls()


def test_conf_has_modes_line_prefix_substr(router):
    router.set_fake("pidof", out="123\n")
    router.write("proc/123/cmdline", b"dnsmasq\x00-C\x00/var/etc/dnsmasq.conf.dhcp\x00")
    router.write("var/etc/dnsmasq.conf.dhcp",
                 "dhcp-range=set:lab,192.168.150.100,192.168.150.149,\n"
                 "no-resolv\nrebind-localhost-ok\n")
    checks = [ (["conf-has", "dnsmasq", "prefix", "present",
          "dhcp-range=set:lab,192.168.150.100,192.168.150.149,"], "ok"),
        (["conf-has", "dnsmasq", "substr", "present", "rebind"], "ok"),
        (["conf-has", "dnsmasq", "substr", "eq:2", "rebind"], "fail count=1"),
        (["conf-has", "dnsmasq", "line", "absent", "rebind-localhost-ok"], "fail count=1"),
        (["conf-has", "dnsmasq", "line", "present", "no-reslov"], None), ]
    for fields, want in checks:
        res = router.probe(*fields)
        if want is None:  # a typo'd line must not equal or prefix anything
            assert res.out == "probe conf-has fail count=0\n"
        else:
            assert res.out == f"probe conf-has {want}\n", fields


def test_conf_has_ignores_a_c_argument_outside_the_path_shape(router):
    router.set_fake("pidof", out="123\n")
    router.write("proc/123/cmdline", b"dnsmasq\x00-C\x00/etc/dnsmasq.conf\x00")
    router.write("var/etc/dnsmasq.conf.alt", "alt-line\n")
    res = router.probe("conf-has", "dnsmasq", "substr", "present", "alt-line")
    assert (res.rc, res.out) == (0, "probe conf-has ok\n")


def test_conf_has_without_pid_reads_every_var_etc_file(router):
    router.set_fake("pidof", rc=1)
    router.write("var/etc/dnsmasq.conf.a", "common\na-only\n")
    router.write("var/etc/dnsmasq.conf.b", "common\n")
    res = router.probe("conf-has", "dnsmasq", "line", "eq:2", "common")
    assert (res.rc, res.out, res.err) == (0, "probe conf-has ok\n", "")
    res = router.probe("conf-has", "dnsmasq", "line", "present", "a-only")
    assert (res.rc, res.out) == (0, "probe conf-has ok\n")
    res = router.probe("conf-has", "dnsmasq", "line", "eq:2", "a-only")
    assert (res.rc, res.out) == (1, "probe conf-has fail count=1\n")


def test_conf_has_no_file_at_all_is_error(router):
    router.set_fake("pidof", rc=1)
    router.write("var/etc/.keep", "")
    res = router.probe("conf-has", "dnsmasq", "line", "present", "x")
    assert (res.rc, res.out) == (1, "probe conf-has fail error\n")


# ---- conf-has: also counts /tmp/hosts/dhcp.<SUF> for each conf file (R3) ----


def test_conf_has_dhcp_hosts_file_substr_present_passes(router):
    router.set_fake("pidof", out="123\n")
    router.write("proc/123/cmdline",
                 b"dnsmasq\x00-C\x00/var/etc/dnsmasq.conf.cfg01411c\x00")
    router.write("var/etc/dnsmasq.conf.cfg01411c", "addn-hosts=/tmp/hosts\n")
    router.write("tmp/hosts/dhcp.cfg01411c",
                 "# auto-generated by dnsmasq\n"
                 "192.168.150.1 lab-r1\n"
                 "192.168.150.77 nas.lab\n")
    res = router.probe("conf-has", "dnsmasq", "substr", "present", "nas.lab")
    assert (res.rc, res.out, res.err) == (0, "probe conf-has ok\n", "")


def test_conf_has_dhcp_hosts_file_substr_absent_fails(router):
    router.set_fake("pidof", out="123\n")
    router.write("proc/123/cmdline",
                 b"dnsmasq\x00-C\x00/var/etc/dnsmasq.conf.cfg01411c\x00")
    router.write("var/etc/dnsmasq.conf.cfg01411c", "addn-hosts=/tmp/hosts\n")
    router.write("tmp/hosts/dhcp.cfg01411c",
                 "192.168.150.1 lab-r1\n"
                 "192.168.150.77 nas.lab\n")
    res = router.probe("conf-has", "dnsmasq", "substr", "absent", "nas.lab")
    assert (res.rc, res.out) == (1, "probe conf-has fail count=1\n")


def test_conf_has_dhcp_hosts_file_line_mode_matches_whole_line(router):
    router.set_fake("pidof", out="123\n")
    router.write("proc/123/cmdline",
                 b"dnsmasq\x00-C\x00/var/etc/dnsmasq.conf.cfg01411c\x00")
    router.write("var/etc/dnsmasq.conf.cfg01411c", "addn-hosts=/tmp/hosts\n")
    router.write("tmp/hosts/dhcp.cfg01411c",
                 "192.168.150.1 lab-r1\n"
                 "192.168.150.77 nas.lab\n")
    res = router.probe("conf-has", "dnsmasq", "line", "present",
                       "192.168.150.77 nas.lab")
    assert (res.rc, res.out) == (0, "probe conf-has ok\n")
    res = router.probe("conf-has", "dnsmasq", "line", "absent",
                       "192.168.150.77 nas.lab")
    assert (res.rc, res.out) == (1, "probe conf-has fail count=1\n")
    res = router.probe("conf-has", "dnsmasq", "line", "absent",
                       "192.168.150.77 nowhere.example")
    assert (res.rc, res.out) == (0, "probe conf-has ok\n")


def test_conf_has_dhcp_hosts_file_optional_when_missing(router):
    router.set_fake("pidof", out="123\n")
    router.write("proc/123/cmdline",
                 b"dnsmasq\x00-C\x00/var/etc/dnsmasq.conf.cfg01411c\x00")
    router.write("var/etc/dnsmasq.conf.cfg01411c", "stop-dns-rebind\n")
    res = router.probe("conf-has", "dnsmasq", "line", "present", "stop-dns-rebind")
    assert (res.rc, res.out) == (0, "probe conf-has ok\n")
    res = router.probe("conf-has", "dnsmasq", "substr", "absent", "nas.lab")
    assert (res.rc, res.out) == (0, "probe conf-has ok\n")


def test_conf_has_dhcp_hosts_file_unreadable_is_skipped(router):
    """An unreadable hosts file (mode 000) is skipped, not an error; the
    conf file is still consulted and the probe completes. When the test
    process is root (mode 000 is meaningless), a directory replaces the
    file so the read still fails."""
    router.set_fake("pidof", out="123\n")
    router.write("proc/123/cmdline",
                 b"dnsmasq\x00-C\x00/var/etc/dnsmasq.conf.cfg01411c\x00")
    router.write("var/etc/dnsmasq.conf.cfg01411c", "addn-hosts=/tmp/hosts\n")
    router.write("tmp/hosts/dhcp.cfg01411c", "192.168.150.77 nas.lab\n")
    p = router.root / "tmp/hosts/dhcp.cfg01411c"
    p.chmod(0o000)
    if os.geteuid() == 0:
        p.unlink()
        p.mkdir()
    res = router.probe("conf-has", "dnsmasq", "substr", "present", "nas.lab")
    assert (res.rc, res.out) == (1, "probe conf-has fail count=0\n")
    res = router.probe("conf-has", "dnsmasq", "substr", "present", "addn-hosts")
    assert (res.rc, res.out) == (0, "probe conf-has ok\n")


def test_conf_has_dhcp_hosts_file_different_suf_is_not_read(router):
    router.set_fake("pidof", out="123\n")
    router.write("proc/123/cmdline",
                 b"dnsmasq\x00-C\x00/var/etc/dnsmasq.conf.cfg01411c\x00")
    router.write("var/etc/dnsmasq.conf.cfg01411c", "addn-hosts=/tmp/hosts\n")
    router.write("tmp/hosts/dhcp.othersuf", "192.168.150.77 nas.lab\n")
    res = router.probe("conf-has", "dnsmasq", "substr", "present", "nas.lab")
    assert (res.rc, res.out) == (1, "probe conf-has fail count=0\n")
    res = router.probe("conf-has", "dnsmasq", "substr", "present", "addn-hosts")
    assert (res.rc, res.out) == (0, "probe conf-has ok\n")
# ---- proc-args (4.3) -----------------------------------------------------------


@pytest.fixture
def two_ntpds(router):
    router.set_fake("pidof", out="111 222\n")
    router.write("proc/111/cmdline",
                 b"ntpd\x00-l\x00-I\x00br-lan\x00-p\x00time.cloudflare.com\x00")
    router.write("proc/222/cmdline", b"ntpd\x00-q\x00")


def test_proc_args_consecutive_elements(two_ntpds, router):
    res = router.probe("proc-args", "ntpd", "-p time.cloudflare.com")
    assert (res.rc, res.out, res.err) == (0, "probe proc-args ok\n", "")
    assert router.calls() == ["pidof ntpd"]


def test_proc_args_three_consecutive_elements(two_ntpds, router):
    res = router.probe("proc-args", "ntpd", "-l -I br-lan")
    assert (res.rc, res.out) == (0, "probe proc-args ok\n")


def test_proc_args_tilde_text(two_ntpds, router):
    res = router.probe("proc-args", "ntpd", "~cloudflare")
    assert (res.rc, res.out) == (0, "probe proc-args ok\n")
    res = router.probe("proc-args", "ntpd", "~openwrt")
    assert (res.rc, res.out) == (1, "probe proc-args fail mismatch\n")


def test_proc_args_negated_spec(two_ntpds, router):
    res = router.probe("proc-args", "ntpd", "!-q")
    assert (res.rc, res.out) == (0, "probe proc-args ok\n")
    res = router.probe("proc-args", "ntpd", "!~ntpd")
    assert (res.rc, res.out) == (1, "probe proc-args fail mismatch\n")


def test_proc_args_several_pids_one_satisfies(two_ntpds, router):
    res = router.probe("proc-args", "ntpd", "-q", "!-l")
    assert (res.rc, res.out) == (0, "probe proc-args ok\n")
    res = router.probe("proc-args", "ntpd", "-l", "-q")
    assert (res.rc, res.out) == (1, "probe proc-args fail mismatch\n")


def test_proc_args_dev_resolution_in_an_element(router):
    router.set_fake("pidof", out="111\n")
    router.write("proc/111/cmdline", b"ntpd\x00-I\x00br-lan\x00")
    router.set_fake("ifstatus", out='{"device":"br-lan"}\n')
    res = router.probe("proc-args", "ntpd", "-I @dev:lab")
    assert (res.rc, res.out) == (0, "probe proc-args ok\n")
    assert "ifstatus lab" in router.calls()


def test_proc_args_no_process(router):
    router.set_fake("pidof", rc=1)
    res = router.probe("proc-args", "ntpd", "-l")
    assert (res.rc, res.out) == (1, "probe proc-args fail no-process\n")


# ---- the matching rules themselves (4.2) ---------------------------------------


@pytest.fixture
def cwd(tmp_path):
    """A working directory holding files whose names would match a globbed or
    unquoted TEXT (design 9.2 group 9)."""
    work = tmp_path / "cwd"
    work.mkdir()
    for name in ("abc", "a.c", "aXb", "a*b", "star", "x", "aab", "a|b",
                 "a?c", "[a-z]", "(x)", "^x", "a+b", "x$"):
        (work / name).write_text("x")
    return work


NOT_MATCHED = [ ("dot-not-regex", "abc", "a.c"), ("star-not-glob", "star here", "*"),
    ("star-in-text-not-glob", "ab", "a*b"), ("question-not-glob", "abc", "a?c"),
    ("class-not-glob", "m", "[a-z]"), ("caret-not-anchor", "x", "^x"),
    ("dollar-not-anchor", "x", "x$"), ("plus-not-quantifier", "aab", "a+b"),
    ("pipe-not-alternation", "a", "a|b"), ("paren-not-group", "x", "(x)"), ]


@pytest.mark.parametrize("cid,line,text", NOT_MATCHED, ids=[c[0] for c in NOT_MATCHED])
def test_text_is_a_fixed_string_not_a_pattern(router, cwd, cid, line, text):
    router.set_fake("logread", out=line + "\n")
    res = router.probe("log-has", "eq:0", text, cwd=cwd)
    assert (res.rc, res.out, res.err) == (0, "probe log-has ok\n", "")


MATCHED = [ ("dot-literal", "wait a.c ok", "a.c"), ("star-literal", "a*b here", "a*b"),
    ("question-literal", "a?c", "a?c"), ("class-literal", "x [a-z] y", "[a-z]"),
    ("caret-literal", "a ^x b", "^x"), ("dollar-literal", "pay x$ now", "x$"),
    ("plus-literal", "hit a+b now", "a+b"), ("pipe-literal", "a|b", "a|b"),
    ("paren-literal", "see (x) here", "(x)"), ]


@pytest.mark.parametrize("cid,line,text", MATCHED, ids=[c[0] for c in MATCHED])
def test_literal_special_characters_do_match(router, cwd, cid, line, text):
    router.set_fake("logread", out=line + "\n")
    res = router.probe("log-has", "present", text, cwd=cwd)
    assert (res.rc, res.out) == (0, "probe log-has ok\n")


def test_ordered_texts_need_no_overlap(router, cwd):
    router.set_fake("logread", out="abc\n")
    res = router.probe("log-has", "eq:0", "ab", "bc", cwd=cwd)
    assert (res.rc, res.out) == (0, "probe log-has ok\n")
    router.set_fake("logread", out="abbc\n")
    res = router.probe("log-has", "eq:1", "ab", "bc", cwd=cwd)
    assert (res.rc, res.out) == (0, "probe log-has ok\n")


def test_a_negative_text_removes_lines(router, cwd):
    router.set_fake("logread", out="x y\nx z\n")
    res = router.probe("log-has", "present", "x", "!y", cwd=cwd)
    assert (res.rc, res.out) == (0, "probe log-has ok\n")
    res = router.probe("log-has", "eq:2", "x", "!y", cwd=cwd)
    assert (res.rc, res.out) == (1, "probe log-has fail count=1\n")
# ---- a failing data command is never a pass (4.2, M49) -------------------------

# (id, fake to break, probe fields, expected reason or None for a pass)
FAILING_DATA = [ ("nft-present", "nft", ["nft-rule", "inet", "fw4", "ruleset", "present",
                            "x"], "error"),
    ("nft-absent", "nft", ["nft-rule", "inet", "fw4", "ruleset", "absent", "x"], "error"),
    ("nft-eq0", "nft", ["nft-rule", "inet", "fw4", "ruleset", "eq:0", "x"], "error"),
    ("nft-min0", "nft", ["nft-rule", "inet", "fw4", "ruleset", "min:0", "x"], "error"),
    ("nft-order", "nft", ["nft-rule-order", "inet", "fw4", "c", "a", "b"], "error"),
    ("nft-near", "nft", ["nft-rule-near", "inet", "fw4", "ruleset", "a", "3", "b"], "error"),
    ("nft-set-absent", "nft", ["nft-set-has", "inet", "fw4", "s", "1.2.3.4",
                               "absent"], "error"),
    ("netstat-present", "netstat", ["listen", "tcp", "any", "22", "any", "present"], "error"),
    ("netstat-absent", "netstat", ["listen", "tcp", "any", "22", "any", "absent"], "error"),
    ("logread-present", "logread", ["log-has", "present", "x"], "error"),
    ("logread-absent", "logread", ["log-has", "absent", "x"], "error"),
    ("logread-eq0", "logread", ["log-has", "eq:0", "x"], "error"),
    ("ubus-service", "ubus", ["service-running", "dropbear", "any"], "error"),
    ("ifstatus-field", "ifstatus", ["iface-field", "lan", "up", "true"], "error"),
    ("ifstatus-ra", "ifstatus", ["ra-absent", "wan"], "error"),
    # the exceptions of 4.2, where the exit is the answer
    ("ping-exit", "ping", ["ping", "192.0.2.1"], "fail"),
    ("resolve-exit", "nslookup", ["resolve", "openwrt.org"], "fail"),
    ("uci-equals-exit1", "uci", ["uci-equals", "network.lan.proto", "x"], "unset", 1),
    ("uci-unset-exit1", "uci", ["uci-unset", "network.lan.proto"], None, 1),
    ("iface-absent-exit", "ifstatus", ["iface-absent", "wan6"], None),
    ("pidof-no-process", "pidof", ["proc-args", "ntpd", "-l"], "no-process"), ]


FAILING_DATA = [row if len(row) == 5 else (*row, 2) for row in FAILING_DATA]


@pytest.mark.parametrize("cid,fake,fields,want,fake_rc", FAILING_DATA,
                         ids=[f[0] for f in FAILING_DATA])
def test_a_failing_data_command_is_never_a_pass(
        router, cid, fake, fields, want, fake_rc):
    router.set_fake(fake, out="", rc=fake_rc)
    res = router.probe(*fields)
    if want is None:
        assert res.out == f"probe {fields[0]} ok\n"
        assert res.rc == 0
    else:
        assert (res.rc, res.out, res.err) == ( 1, f"probe {fields[0]} fail {want}\n", "")


def test_uci_equals_unset_is_the_uci_exit_one_answer(router):
    router.set_fake("uci", out="", rc=1)
    res = router.probe("uci-equals", "network.lan.proto", "x")
    assert (res.rc, res.out) == (1, "probe uci-equals fail unset\n")


def test_pidof_exit_one_is_no_process_not_error(router):
    router.set_fake("pidof", out="", rc=1)
    res = router.probe("proc-args", "ntpd", "-l")
    assert (res.rc, res.out) == (1, "probe proc-args fail no-process\n")


# ---- router output never appears in program output (3.7, M16) ------------------

LOUD_LINES = [ ["fail"], ["ping", "192.0.2.1"], ["resolve", "openwrt.org"],
    ["service-running", "dropbear", "any"], ["uci-equals", "network.lan.proto", "static"],
    ["uci-unset", "network.lan.proto"], ["listen", "tcp", "any", "22", "any", "present"],
    ["nft-rule", "inet", "fw4", "ruleset", "present", "dport 2222"],
    ["nft-rule-order", "inet", "fw4", "input_wan", "a", "b"],
    ["nft-rule-near", "inet", "fw4", "ruleset", "a", "3", "b"],
    ["nft-set-has", "inet", "fw4", "nw_block", "192.0.2.1", "only"],
    ["conf-has", "dnsmasq", "line", "present", "never-matching"],
    ["proc-args", "ntpd", "~dnsmasq"], ["iface-field", "lan", "up", "true"],
    ["iface-absent", "wan6"], ["sysctl-equals", "ipv4/ip_forward", "1"], ["ra-absent", "wan"],
    ["log-has", "present", "dnsmasq["], ["root-password-class", "LOCKED"], ]


@pytest.fixture
def loud(router):
    """Every fake answers rc 0 with a SECRET marker in its output."""
    router.set_fake("ping", out=f"{SECRET} pong\n")
    router.set_fake("nslookup", out=f"{SECRET} addr\n")
    router.set_fake("uci", out=f"{SECRET}\n")
    router.set_fake("ubus", out='{"dropbear":{"instances":' '{"i1":{"running":true}},'
                                 f'"note":"{SECRET}"}}}}\n')
    router.set_fake("ifstatus", out='{"up":true,"device":"%s",'
                                    '"l3_device":"eth0"}\n' % SECRET)
    router.set_fake("netstat", out=f"tcp 0 0 0.0.0.0:22 0.0.0.0:* " f"LISTEN 1/{SECRET}\n")
    router.set_fake("nft", out=f"dport 2222 {SECRET}\na\nb\n" "elements = { 192.0.2.1 }\n")
    router.set_fake("logread", out=f"dnsmasq[1]: {SECRET}\n")
    router.set_fake("pidof", out="123\n")
    router.write("proc/123/cmdline", b"dnsmasq\x00-C\x00" b"/var/etc/dnsmasq.conf.dhcp\x00")
    router.write("var/etc/dnsmasq.conf.dhcp", f"{SECRET} line\n")
    router.write("proc/sys/net/ipv4/ip_forward", f"{SECRET}\n")
    router.write("etc/shadow", f"root:${SECRET}1$abc:19000:0:99999:7:::\n")
    return router


@pytest.mark.parametrize("fields", LOUD_LINES, ids=[f[0] for f in LOUD_LINES])
def test_no_router_output_leaks_to_stdout_or_stderr(loud, fields):
    res = loud.probe(*fields)
    assert res.out.startswith(f"probe {fields[0]} "), (fields, res.out)
    assert res.rc in (0, 1)
    assert SECRET not in res.out, fields
    assert SECRET not in res.err, fields
    assert "Terminated" not in res.err


# ---- whole-value comparisons (touch-up after a planted-defect run) ---------


def test_listen_port_address_and_program_are_compared_whole(router):
    router.set_fake("netstat", out=(
        "tcp 0 0 10.109.0.11:2222 0.0.0.0:* LISTEN 9/dropbear2\n"))
    res = router.probe("listen", "tcp", "any", "22", "any", "present")
    assert (res.rc, res.out) == (1, "probe listen fail count=0\n")
    res = router.probe("listen", "tcp", "10.109.0.1", "2222", "any", "present")
    assert (res.rc, res.out) == (1, "probe listen fail count=0\n")
    res = router.probe("listen", "tcp", "any", "2222", "dropbear", "present")
    assert (res.rc, res.out) == (1, "probe listen fail count=0\n")
    res = router.probe("listen", "tcp", "10.109.0.11", "2222", "dropbear2", "present")
    assert (res.rc, res.out) == (0, "probe listen ok\n")
