"""the safety checks that can run over the stock ACL groups.

ADR-021 point 5: a change class is only eligible for auto-apply when
every mandatory safety check of it can run over the stock groups.  This
module is the table of what can and what cannot, and the probe runner
that runs the ones that can.

The probes keep the router program's own meaning (design 4.3): the same
pass, the same fail, and "could not run" where the router program would
have had no answer at all.  The answers come from the lab measurement
(see ``noinstall_answers``); no router is contacted.
"""

from __future__ import annotations

from typing import Any

import pytest

from newton_mcp import change_classes, noinstall_checks as checks, probes
from newton_mcp import rpcd_txn
from noinstall_answers import data
from noinstall_fakes import FakeSession, exec_answers_by_command


# ---- the table -------------------------------------------------------------


def test_probe_support_covers_every_probe() -> None:
    """A new probe cannot be forgotten: the key sets must be equal."""
    assert set(checks.PROBE_SUPPORT) == set(probes.PROBE_TABLE)


def test_the_runnable_probes_are_the_ones_the_stock_groups_can_run() -> None:
    assert checks.PROBE_SUPPORT["uci-equals"] == "uci get"
    assert checks.PROBE_SUPPORT["uci-unset"] == "uci get"
    assert checks.PROBE_SUPPORT["service-running"] == "service list"
    assert checks.PROBE_SUPPORT["ping"] == "file exec /bin/ping"
    assert checks.PROBE_SUPPORT["resolve"] == "file exec /usr/bin/nslookup"
    assert checks.PROBE_SUPPORT["iface-field"] == "network.interface dump"
    assert checks.PROBE_SUPPORT["iface-absent"] == "network.interface dump"
    assert checks.PROBE_SUPPORT["sysctl-equals"] == "file read"
    assert checks.PROBE_SUPPORT["log-has"] == "log read"


def test_the_probes_the_stock_groups_cannot_run_are_marked() -> None:
    for name in (
        "listen",
        "nft-rule",
        "nft-rule-order",
        "nft-rule-near",
        "nft-set-has",
        "conf-has",
        "proc-args",
        "ra-absent",
        "root-password-class",
    ):
        assert checks.PROBE_SUPPORT[name] is None, name


def test_the_fail_probe_is_a_local_constant_failure() -> None:
    """``fail`` means "this check fails": it needs no call at all."""
    session = FakeSession()
    result = checks.run_probe(session, "fail", [])
    assert result.passed is False
    assert session.calls == []


def test_a_planted_failure_is_a_check_that_runs() -> None:
    """It needs no rpcd call, but it is not a check that cannot run."""
    check = checks.Check("planted", "fail", (), True)
    assert check.runnable is True


def test_an_unknown_probe_cannot_run() -> None:
    result = checks.run_probe(FakeSession(), "nosuchprobe", [])
    assert result.passed is None


def test_a_probe_the_stock_groups_cannot_run_says_so() -> None:
    """A known probe with no rpcd call is "could not run", not a failure."""
    result = checks.run_probe(FakeSession(), "nft-rule", ["inet", "t", "c"])
    assert result.passed is None
    assert result.detail == "the stock groups cannot run this probe"


# ---- the probes ------------------------------------------------------------


def test_ping_passes_when_the_host_answers() -> None:
    session = FakeSession({("file", "exec"): data("file.exec.ping")})
    result = checks.run_probe(session, "ping", ["127.0.0.1"])
    assert result.passed is True
    assert session.calls == [
        (
            "file",
            "exec",
            {
                "command": "/bin/ping",
                "params": ["-c", "1", "-W", "3", "127.0.0.1"],
            },
        )
    ]


def test_ping_fails_when_the_host_does_not_answer() -> None:
    session = FakeSession({("file", "exec"): data("file.exec.ping.fail")})
    result = checks.run_probe(session, "ping", ["198.51.100.1"])
    assert result.passed is False


def test_ping_takes_the_count_the_router_program_takes() -> None:
    session = FakeSession({("file", "exec"): data("file.exec.ping")})
    checks.run_probe(session, "ping", ["127.0.0.1", "3"])
    assert session.calls[0][2]["params"] == ["-c", "3", "-W", "3", "127.0.0.1"]


def test_resolve_passes_when_the_name_resolves() -> None:
    session = FakeSession({("file", "exec"): data("file.exec.nslookup")})
    result = checks.run_probe(session, "resolve", ["localhost"])
    assert result.passed is True
    assert session.calls[0][2]["command"] == "/usr/bin/nslookup"
    assert session.calls[0][2]["params"] == ["localhost", "127.0.0.1"]


def test_uci_equals_passes_on_the_same_value() -> None:
    session = FakeSession({("uci", "get"): data("uci.get.network.lan.proto")})
    result = checks.run_probe(session, "uci-equals", ["network.lan.proto", "static"])
    assert result.passed is True
    assert session.calls[0][2] == {
        "config": "network",
        "section": "lan",
        "option": "proto",
    }


def test_uci_equals_fails_on_another_value() -> None:
    session = FakeSession({("uci", "get"): data("uci.get.network.lan.proto")})
    result = checks.run_probe(session, "uci-equals", ["network.lan.proto", "dhcp"])
    assert result.passed is False
    assert result.detail.startswith("mismatch")


def test_uci_equals_fails_when_the_option_is_not_there() -> None:
    session = FakeSession({("uci", "get"): data("uci.get.missing.option")})
    result = checks.run_probe(session, "uci-equals", ["network.lan.nosuchoption", "x"])
    assert result.passed is False
    assert result.detail == "unset"


def test_uci_unset_passes_when_the_option_is_not_there() -> None:
    session = FakeSession({("uci", "get"): data("uci.get.missing.option")})
    result = checks.run_probe(session, "uci-unset", ["network.lan.nosuchoption"])
    assert result.passed is True


def test_uci_unset_passes_when_the_config_is_not_there() -> None:
    """A router without a radio answers [4]: the option is not set either."""
    session = FakeSession({("uci", "get"): 4})
    result = checks.run_probe(session, "uci-unset", ["wireless.wlan0.ssid"])
    assert result.passed is True


def test_uci_unset_fails_when_the_option_is_there() -> None:
    session = FakeSession({("uci", "get"): data("uci.get.network.lan.proto")})
    result = checks.run_probe(session, "uci-unset", ["network.lan.proto"])
    assert result.passed is False
    assert result.detail == "present"


def test_a_refused_uci_call_cannot_run() -> None:
    session = FakeSession({("uci", "get"): 6})
    result = checks.run_probe(session, "uci-unset", ["network.lan.proto"])
    assert result.passed is None


def test_service_running_passes_when_the_instance_runs() -> None:
    session = FakeSession({("service", "list"): data("service.list.dnsmasq")})
    result = checks.run_probe(
        session, "service-running", ["dnsmasq", "cfg01411c", "present"]
    )
    assert result.passed is True
    assert session.calls[0][2] == {"name": "dnsmasq"}


def test_service_running_takes_any_instance() -> None:
    session = FakeSession({("service", "list"): data("service.list.dnsmasq")})
    result = checks.run_probe(session, "service-running", ["dnsmasq", "any"])
    assert result.passed is True


def test_service_running_fails_when_the_service_is_not_there() -> None:
    session = FakeSession({("service", "list"): data("service.list.nosuchservice")})
    result = checks.run_probe(session, "service-running", ["nosuchservice", "any"])
    assert result.passed is False
    assert result.detail == "absent"


def test_service_running_passes_when_the_service_must_be_absent() -> None:
    session = FakeSession({("service", "list"): data("service.list.nosuchservice")})
    result = checks.run_probe(
        session, "service-running", ["nosuchservice", "any", "absent"]
    )
    assert result.passed is True


def test_iface_field_passes_on_the_same_value() -> None:
    session = FakeSession(
        {("network.interface", "dump"): data("network.interface.dump")}
    )
    result = checks.run_probe(session, "iface-field", ["lan", "up", "true"])
    assert result.passed is True


def test_iface_field_fails_on_another_value() -> None:
    session = FakeSession(
        {("network.interface", "dump"): data("network.interface.dump")}
    )
    result = checks.run_probe(session, "iface-field", ["lan", "up", "false"])
    assert result.passed is False
    assert result.detail.startswith("mismatch")


def test_iface_field_fails_when_the_interface_is_not_there() -> None:
    session = FakeSession(
        {("network.interface", "dump"): data("network.interface.dump")}
    )
    result = checks.run_probe(session, "iface-field", ["nosuch", "up", "true"])
    assert result.passed is False
    assert result.detail == "error"


def test_iface_absent_passes_when_the_interface_is_not_there() -> None:
    session = FakeSession(
        {("network.interface", "dump"): data("network.interface.dump")}
    )
    result = checks.run_probe(session, "iface-absent", ["nosuch"])
    assert result.passed is True


def test_iface_absent_fails_when_the_interface_is_there() -> None:
    session = FakeSession(
        {("network.interface", "dump"): data("network.interface.dump")}
    )
    result = checks.run_probe(session, "iface-absent", ["lan"])
    assert result.passed is False
    assert result.detail == "present"


def test_sysctl_equals_passes_on_the_same_value() -> None:
    session = FakeSession({("file", "read"): data("file.read.forwarding")})
    result = checks.run_probe(
        session, "sysctl-equals", ["ipv4/conf/br-lan/forwarding", "1"]
    )
    assert result.passed is True
    assert session.calls[0][2] == {
        "path": "/proc/sys/net/ipv4/conf/br-lan/forwarding"
    }


def test_sysctl_equals_fails_on_another_value() -> None:
    session = FakeSession({("file", "read"): data("file.read.forwarding")})
    result = checks.run_probe(
        session, "sysctl-equals", ["ipv4/conf/br-lan/forwarding", "0"]
    )
    assert result.passed is False
    assert result.detail.startswith("mismatch")


def test_a_sysctl_key_outside_the_conf_trees_cannot_run() -> None:
    """Only the per-interface keys are readable over the stock groups."""
    session = FakeSession({("file", "read"): data("file.read.forwarding")})
    result = checks.run_probe(session, "sysctl-equals", ["ipv4/ip_forward", "1"])
    assert result.passed is None
    assert session.calls == []


def test_log_has_passes_when_a_line_matches() -> None:
    session = FakeSession({("log", "read"): data("log.read")})
    result = checks.run_probe(session, "log-has", ["present", "odhcpd"])
    assert result.passed is True
    assert session.calls[0][2] == {"lines": 100, "stream": False}


def test_log_has_fails_when_no_line_matches() -> None:
    session = FakeSession({("log", "read"): data("log.read")})
    result = checks.run_probe(session, "log-has", ["present", "nosuchtext"])
    assert result.passed is False


def test_log_has_absent_passes_when_no_line_matches() -> None:
    """The router program's rule: ``absent`` wants a count of zero."""
    session = FakeSession({("log", "read"): data("log.read")})
    result = checks.run_probe(session, "log-has", ["absent", "nosuchtext"])
    assert result.passed is True


def test_log_has_counts_the_matching_lines() -> None:
    session = FakeSession({("log", "read"): data("log.read")})
    result = checks.run_probe(session, "log-has", ["eq:2", "dropbear"])
    assert result.passed is True
    result = checks.run_probe(session, "log-has", ["eq:3", "dropbear"])
    assert result.passed is False


def test_log_has_needs_the_texts_in_order() -> None:
    """The router program's rule: the texts must appear in order."""
    session = FakeSession({("log", "read"): data("log.read")})
    assert checks.run_probe(session, "log-has", ["present", "odhcpd", "default"]).passed is True
    assert checks.run_probe(session, "log-has", ["present", "default", "odhcpd"]).passed is False


def test_log_has_honours_a_negated_text() -> None:
    session = FakeSession({("log", "read"): data("log.read")})
    result = checks.run_probe(session, "log-has", ["present", "dropbear", "!odhcpd"])
    assert result.passed is True
    result = checks.run_probe(session, "log-has", ["present", "dropbear", "!dropbear"])
    assert result.passed is False


def test_a_probe_never_passes_on_an_error_answer() -> None:
    """A transport error is never a pass, whatever the probe."""
    from newton_mcp.adapters.openwrt_rpcd import RpcdTransportError

    for name, args in (
        ("ping", ["127.0.0.1"]),
        ("resolve", ["localhost"]),
        ("uci-equals", ["network.lan.proto", "static"]),
        ("uci-unset", ["network.lan.proto"]),
        ("service-running", ["dnsmasq", "any"]),
        ("iface-field", ["lan", "up", "true"]),
        ("iface-absent", ["lan"]),
        ("sysctl-equals", ["ipv4/conf/br-lan/forwarding", "1"]),
        ("log-has", ["present", "odhcpd"]),
    ):
        session = FakeSession(
            {("*", "*"): RpcdTransportError("the router could not be reached", sent=True)}
        )
        result = checks.run_probe(session, name, args)
        assert result.passed is not True, name


def test_a_probe_never_passes_on_an_unknown_answer() -> None:
    """An answer of a shape Newton does not know is not a pass."""
    session = FakeSession({("uci", "get"): {"nonsense": True}})
    result = checks.run_probe(session, "uci-equals", ["network.lan.proto", "static"])
    assert result.passed is not True


# ---- the review round r2 (items 1 to 6) -----------------------------------

#: Every probe that runs over the stock groups, with arguments its own
#: grammar accepts.  ``fail`` is a local constant: it makes no call, so
#: it has no answer to be wrong about.  ``uci-list`` is the one probe
#: that exists only here: the installed router program has no such
#: probe, so it has its own small grammar.
RUNNABLE_PROBES: tuple[tuple[str, list[str]], ...] = (
    ("ping", ["127.0.0.1"]),
    ("resolve", ["localhost"]),
    ("service-running", ["dnsmasq", "any"]),
    ("uci-equals", ["network.lan.proto", "static"]),
    ("uci-unset", ["network.lan.proto"]),
    ("uci-list", ["network.lan.proto", "+static"]),
    ("iface-field", ["lan", "up", "true"]),
    ("iface-absent", ["lan"]),
    ("sysctl-equals", ["ipv4/conf/br-lan/forwarding", "1"]),
    ("log-has", ["present", "odhcpd"]),
)

#: The answers that are NOT the measured shape of each probe: the wrong
#: type, a missing key, a list of non-mappings and None.  The measured
#: shapes (the empty mapping for ``uci get`` and for ``service list``,
#: the empty interface list) are not in here: they are answers.
MALFORMED_ANSWERS: dict[str, tuple[Any, ...]] = {
    "ping": ({"nonsense": True}, {}, {"code": "0"}, {"code": None}, None, [], "junk"),
    "resolve": (
        {"nonsense": True},
        {},
        {"code": "0"},
        {"code": None},
        None,
        [],
        "junk",
    ),
    "service-running": (
        None,
        [],
        "junk",
        {"dnsmasq": "junk"},
        {"dnsmasq": {"instances": "junk"}},
        {"dnsmasq": {"instances": {"cfg01411c": "junk"}}},
        {"dnsmasq": {"instances": {"cfg01411c": {"running": "yes"}}}},
    ),
    "uci-equals": (
        {"nonsense": True},
        {"value": None},
        {"values": {"lan": {"proto": "static"}}},
        None,
        [],
        "junk",
    ),
    "uci-unset": (
        {"nonsense": True},
        {"value": None},
        None,
        [],
        "junk",
    ),
    "uci-list": (
        {"nonsense": True},
        {"value": None},
        {"values": {"lan": {"proto": "static"}}},
        None,
        [],
        "junk",
    ),
    "iface-field": (
        {"nonsense": True},
        {"interface": "junk"},
        {"interface": ["junk"]},
        {"interface": [None]},
        {"interface": {"lan": {}}},
        None,
        [],
        "junk",
    ),
    "iface-absent": (
        {"nonsense": True},
        {"interface": "junk"},
        {"interface": ["junk"]},
        {"interface": [None]},
        {"interface": {"lan": {}}},
        None,
        [],
        "junk",
    ),
    "sysctl-equals": (
        {"nonsense": True},
        {"data": 5},
        {"data": None},
        None,
        [],
        "junk",
    ),
    "log-has": (
        {"nonsense": True},
        {"log": "junk"},
        {"log": [5]},
        {"log": [{"id": 1}]},
        {"log": [{"msg": 5}]},
        None,
        [],
        "junk",
    ),
}

#: The value that must never appear in a ProbeResult: the router's own
#: secret, in every answer shape that could echo it back.
CANARY = "canary-secret-value-9f2b"


@pytest.mark.parametrize("name,args", RUNNABLE_PROBES)
def test_a_probe_never_passes_on_an_unknown_answer(name, args) -> None:
    """Only the measured shapes count: anything else is "could not run".

    A probe that never saw an answer it understands must not report a
    pass: the answer shape is the measurement, and an answer Newton does
    not know is no measurement at all.
    """
    for answer in MALFORMED_ANSWERS[name]:
        session = FakeSession({("*", "*"): answer})
        result = checks.run_probe(session, name, args)
        assert result.passed is None, (name, answer, result)


@pytest.mark.parametrize("name,args", RUNNABLE_PROBES)
def test_a_probe_never_passes_on_a_refusal(name, args) -> None:
    """A refusal is not a pass, and it never escapes the runner.

    The one measured meaning a refusal has is ``uci get``'s ``[4]`` for
    ``uci-unset``: the config file is not there, so the option is not set
    either.  Every other refusal is "could not run".
    """
    for code in (4, 6):
        session = FakeSession({("*", "*"): code})
        result = checks.run_probe(session, name, args)
        if name == "uci-unset" and code == 4:
            assert result.passed is True, (name, code, result)
            continue
        assert result.passed is None, (name, code, result)
        assert result.detail, (name, code, result)


@pytest.mark.parametrize(
    "error",
    (
        ValueError("junk"),
        TypeError("junk"),
        KeyError("junk"),
        AttributeError("junk"),
    ),
)
def test_no_exception_escapes_the_probe_runner(error) -> None:
    """Whatever the session does, the runner answers "could not run"."""
    for name, args in RUNNABLE_PROBES:
        session = FakeSession({("*", "*"): error})
        result = checks.run_probe(session, name, args)
        assert result.passed is None, (name, result)


def test_a_secret_option_is_refused_without_a_call() -> None:
    """No yes/no oracle on a value the agent only ever sees redacted.

    The installed path refuses such an option with the reason
    ``secret-option``; the no-install path refuses it the same way, and
    the router is never asked.
    """
    session = FakeSession({("uci", "get"): data("uci.get.network.lan.proto")})
    result = checks.run_probe(
        session, "uci-equals", ["wireless.@wifi-iface[0].key", "synthetic"]
    )
    assert result.passed is None
    assert session.calls == []
    result = checks.run_probe(session, "uci-unset", ["wireless.@wifi-iface[0].key"])
    assert result.passed is None
    assert session.calls == []
    result = checks.run_probe(
        session, "uci-list", ["wireless.@wifi-iface[0].key", "+synthetic"]
    )
    assert result.passed is None
    assert session.calls == []


#: The answer that carries the canary for each probe: the router's own
#: value, in the shape that probe reads.
CANARY_ANSWERS: dict[str, Any] = {
    "ping": {"code": 1, "stdout": CANARY},
    "resolve": {"code": 1, "stdout": CANARY},
    "uci-equals": {"value": CANARY},
    "uci-unset": {"value": CANARY},
    "uci-list": {"value": CANARY},
    "service-running": {
        "dnsmasq": {"instances": {"cfg01411c": {"running": False, "note": CANARY}}}
    },
    "iface-field": {"interface": [{"interface": "lan", "up": CANARY}]},
    "iface-absent": {"interface": [{"interface": "lan", "note": CANARY}]},
    "sysctl-equals": {"data": CANARY + "\n"},
    "log-has": {"log": [{"msg": CANARY}]},
}


@pytest.mark.parametrize("name,args", RUNNABLE_PROBES)
def test_the_router_value_never_appears_in_a_detail(name, args) -> None:
    """A detail never carries a value the router holds.

    The router program's own probes print only the reason word, so the
    value the router holds (which may be a secret) never reaches a
    ProbeResult.
    """
    session = FakeSession({("*", "*"): CANARY_ANSWERS[name]})
    result = checks.run_probe(session, name, args)
    assert CANARY not in result.detail, (name, result)


def test_a_mismatch_says_only_mismatch() -> None:
    """The router program's own word for a value that does not match."""
    session = FakeSession({("uci", "get"): {"value": CANARY}})
    result = checks.run_probe(session, "uci-equals", ["network.lan.proto", "static"])
    assert result.passed is False
    assert result.detail == "mismatch"

    session = FakeSession(
        {
            ("network.interface", "dump"): {
                "interface": [{"interface": "lan", "up": CANARY}]
            }
        }
    )
    result = checks.run_probe(session, "iface-field", ["lan", "up", "true"])
    assert result.passed is False
    assert result.detail == "mismatch"

    session = FakeSession({("file", "read"): {"data": CANARY + "\n"}})
    result = checks.run_probe(
        session, "sysctl-equals", ["ipv4/conf/br-lan/forwarding", "1"]
    )
    assert result.passed is False
    assert result.detail == "mismatch"


@pytest.mark.parametrize(
    "name,args",
    (
        ("log-has", ["present"]),
        ("log-has", ["eq:abc", "odhcpd"]),
        ("log-has", ["eq:abc"]),
        ("ping", []),
        ("ping", ["127.0.0.1", "9"]),
        ("uci-equals", ["network.lan.proto"]),
        ("uci-unset", []),
        ("service-running", ["dnsmasq"]),
        ("iface-field", ["lan", "up"]),
        ("sysctl-equals", ["ipv4/conf/br-lan/forwarding"]),
        ("log-has", ["present", "odhcpd", "x", "y", "z"]),
    ),
)
def test_an_invalid_probe_argument_never_reaches_the_router(name, args) -> None:
    """The installed path's grammar is the only grammar there is.

    A probe whose arguments do not fit is refused before the call, so
    the router never sees it.
    """
    session = FakeSession({("*", "*"): {}})
    result = checks.run_probe(session, name, args)
    assert result.passed is None, (name, args, result)
    assert session.calls == [], (name, args, session.calls)


def test_a_sysctl_key_that_escapes_its_tree_never_reaches_the_router() -> None:
    """A ``..`` in a sysctl key is refused: the path is built from it."""
    session = FakeSession({("file", "read"): data("file.read.forwarding")})
    for key in (
        "ipv4/conf/../ip_forward",
        "ipv4/conf/./forwarding",
        "ipv4/conf/br-lan/../../ip_forward",
    ):
        result = checks.run_probe(session, "sysctl-equals", [key, "1"])
        assert result.passed is None, key
        assert session.calls == [], (key, session.calls)


def test_the_sysctl_pattern_takes_only_the_per_interface_keys() -> None:
    """The pattern itself refuses a part that is not a plain name."""
    for key in (
        "ipv4/conf/../ip_forward",
        "ipv4/conf/./forwarding",
        "ipv4/conf/br-lan/forwarding/extra",
        "ipv4/conf/br lan/forwarding",
        "ipv4/ip_forward",
    ):
        assert checks._SYSCTL_RE.fullmatch(key) is None, key
    assert checks._SYSCTL_RE.fullmatch("ipv4/conf/br-lan/forwarding")
    assert checks._SYSCTL_RE.fullmatch("ipv6/conf/eth0/forwarding")
    # a part is a plain name: letters, digits, "_", "." and "-"
    assert checks._SYSCTL_RE.fullmatch("ipv4/conf/br-lan/arp_ignore")


def test_a_list_read_back_passes_on_the_measured_list() -> None:
    """The check the table builds passes on the router's own answer."""
    session = FakeSession({("uci", "get"): {"value": ["1.1.1.1", "1.0.0.1"]}})
    result = checks.run_probe(
        session, "uci-equals", ["dhcp.@dnsmasq[0].server", "1.1.1.1 1.0.0.1"]
    )
    assert result.passed is True


def test_a_batch_with_a_change_outside_the_allowlist_is_not_eligible() -> None:
    """A batch that also holds another kind of change is not eligible.

    The allowlisted class is still named, but the batch as a whole is
    not something the stock groups may apply on their own.
    """
    batch = (
        "set dhcp.@host[0].mac='02:00:00:00:10:01'\n"
        "set dhcp.@host[0].ip='10.109.0.55'\n"
        "set firewall.wan.input='ACCEPT'\n"
    )
    results = checks.checks_for(batch)
    assert [result.name for result in results] == ["dhcp-reservations"]
    assert results[0].eligible is False
    assert results[0].reason == (
        "the batch also holds a change outside the allowlist"
    )


# ---- the class table -------------------------------------------------------


def test_the_class_table_covers_every_grantable_class() -> None:
    assert set(checks.CLASS_CHECKS) == set(change_classes.GRANTABLE_CLASSES)


def test_the_dhcp_and_dns_classes_are_eligible() -> None:
    assert checks.eligible("dhcp-reservations") is True
    assert checks.eligible("dns") is True


def test_the_hostname_class_is_not_eligible() -> None:
    """The system config is read-only for the rpcd user."""
    assert checks.eligible("hostname") is False
    assert checks.CLASS_CHECKS["hostname"].config == "system"
    assert checks.CLASS_CHECKS["hostname"].reason


def test_the_wireless_class_is_not_eligible_yet() -> None:
    """Its wireless check's answer shape is not measured."""
    assert checks.eligible("wifi-name-key") is False
    assert checks.CLASS_CHECKS["wifi-name-key"].measured is False


def test_a_class_that_is_not_in_the_table_is_not_eligible() -> None:
    assert checks.eligible("nosuchclass") is False


def test_the_writable_configs_are_the_ones_the_rpcd_user_may_write() -> None:
    assert checks.WRITABLE_CONFIGS == ("dhcp", "firewall", "network", "wireless")


def test_checks_for_a_reservation_batch_lists_the_read_back_and_the_service() -> None:
    batch = (
        "set dhcp.@host[0].mac='02:00:00:00:10:01'\n"
        "set dhcp.@host[0].ip='10.109.0.55'\n"
    )
    results = checks.checks_for(batch)
    assert [result.name for result in results] == ["dhcp-reservations"]
    result = results[0]
    assert result.eligible is True
    mandatory = [(check.kind, check.probe, check.args) for check in result.mandatory]
    assert (
        "read-back",
        "uci-equals",
        ("dhcp.@host[0].mac", "02:00:00:00:10:01"),
    ) in mandatory
    assert (
        "read-back",
        "uci-equals",
        ("dhcp.@host[0].ip", "10.109.0.55"),
    ) in mandatory
    assert (
        "service-running",
        "service-running",
        ("dnsmasq", "any", "present"),
    ) in mandatory
    assert result.optional == ()


def test_checks_for_a_dns_batch_may_resolve_the_staged_domain() -> None:
    batch = "set dhcp.@domain[0].name='example.test'\n"
    results = checks.checks_for(batch)
    assert [result.name for result in results] == ["dns"]
    result = results[0]
    assert result.eligible is True
    optional = [(check.kind, check.probe, check.args) for check in result.optional]
    assert optional == [("resolve", "resolve", ("example.test",))]


def test_checks_for_a_change_in_no_class_is_empty() -> None:
    results = checks.checks_for("set network.lan.proto='static'\n")
    assert results == []


def test_checks_for_a_hostname_batch_is_not_eligible() -> None:
    results = checks.checks_for("set system.@system[0].hostname='newname'\n")
    assert [result.name for result in results] == ["hostname"]
    assert results[0].eligible is False
    assert results[0].reason


def test_checks_for_a_wifi_batch_is_not_eligible_yet() -> None:
    results = checks.checks_for(
        "set wireless.@wifi-iface[0].ssid='newname'\n"
        "set wireless.@wifi-iface[0].key='synthetic-key'\n"
    )
    assert [result.name for result in results] == ["wifi-name-key"]
    assert results[0].eligible is False
    assert results[0].reason


def test_an_empty_batch_has_no_class() -> None:
    assert checks.checks_for("") == []


def test_a_batch_that_is_not_a_string_has_no_class() -> None:
    assert checks.checks_for(None) == []


# ---- the review round r3 (items 1, 2 and 3) -------------------------------


def test_a_service_that_the_answer_does_not_name_cannot_run() -> None:
    """Only the measured empty answer means "no such service".

    The measured answer of a service the router does not have is the
    empty mapping (the fixture ``service.list.nosuchservice`` is the
    measured ``[0]``).  A mapping that is not empty and does not carry
    the service is an answer nobody understands, so the probe could not
    run: whatever the state and whatever the instance asked for.
    """
    for state in ("present", "absent"):
        session = FakeSession({("service", "list"): {"nonsense": True}})
        result = checks.run_probe(
            session, "service-running", ["dnsmasq", "any", state]
        )
        assert result.passed is None, (state, result)


def test_a_service_with_an_unreadable_instance_cannot_run() -> None:
    """Every instance of the service is read, not only the one asked for."""
    answer = {"dnsmasq": {"instances": {"cfg01411c": "junk"}}}
    for state in ("present", "absent"):
        for instance in ("main", "any", "cfg01411c"):
            session = FakeSession({("service", "list"): answer})
            result = checks.run_probe(
                session, "service-running", ["dnsmasq", instance, state]
            )
            assert result.passed is None, (state, instance, result)


def test_an_empty_section_read_cannot_run() -> None:
    """``{"values": {}}`` is not a section: a real one carries .name/.type."""
    session = FakeSession({("uci", "get"): {"values": {}}})
    result = checks.run_probe(session, "uci-unset", ["network.lan"])
    assert result.passed is None
    assert result.detail == "the answer could not be read"


# -- the list read-back ----------------------------------------------------


def read_back_of(batch: str) -> list[checks.Check]:
    """The read-back checks of the first class of a batch."""
    results = checks.checks_for(batch)
    assert results, batch
    return [check for check in results[0].mandatory if check.kind == "read-back"]


#: A batch that only adds to a list: the list the router will hold is
#: not known, because ``add_list`` appends to what is already there.
ONLY_ADDS = (
    "add_list dhcp.@dnsmasq[0].server='1.1.1.1'\n"
    "add_list dhcp.@dnsmasq[0].server='1.0.0.1'\n"
)


def test_a_batch_that_only_adds_gets_a_list_check() -> None:
    """The check says what must be in the list, not what the list is.

    ``add_list`` appends to whatever the router already holds, so the
    list the router will hold is not known: only the values the batch
    adds are.
    """
    read_back = read_back_of(ONLY_ADDS)
    assert len(read_back) == 1, read_back
    assert read_back[0].probe == "uci-list"
    assert read_back[0].args == (
        "dhcp.@dnsmasq[0].server",
        "+1.1.1.1",
        "+1.0.0.1",
    )


def test_a_list_check_passes_when_the_router_already_holds_other_values() -> None:
    """The router holds 8.8.8.8 too: the check still passes."""
    read_back = read_back_of(ONLY_ADDS)
    session = FakeSession(
        {("uci", "get"): {"value": ["8.8.8.8", "1.1.1.1", "1.0.0.1"]}}
    )
    result = checks.run_probe(
        session, read_back[0].probe, list(read_back[0].args)
    )
    assert result.passed is True, result


def test_a_value_that_was_added_and_removed_is_not_in_the_list() -> None:
    """``add_list`` then ``del_list`` of the same value: it is gone.

    uci removes every equal item, so the value is not in the list the
    router holds after the batch.
    """
    batch = (
        "add_list dhcp.@dnsmasq[0].server='1.1.1.1'\n"
        "del_list dhcp.@dnsmasq[0].server='1.1.1.1'\n"
        "add_list dhcp.@dnsmasq[0].server='1.0.0.1'\n"
    )
    read_back = read_back_of(batch)
    assert len(read_back) == 1, read_back
    assert read_back[0].probe == "uci-list"
    assert read_back[0].args == (
        "dhcp.@dnsmasq[0].server",
        "+1.0.0.1",
        "-1.1.1.1",
    )


def test_a_value_that_was_added_and_removed_is_taken_away_for_good() -> None:
    """The value the batch removes is not in the list, whatever was there.

    ``uci`` removes every item that is equal to the value, so a value
    the batch adds and then removes is not in the list afterwards --
    not even one the router held before.  The read-back says so, and
    it says it the other way round: the value must NOT be in the list,
    and no check ever asks for it to be there.
    """
    batch = (
        "add_list dhcp.@dnsmasq[0].server='1.1.1.1'\n"
        "del_list dhcp.@dnsmasq[0].server='1.1.1.1'\n"
    )
    read_back = read_back_of(batch)
    assert len(read_back) == 1, read_back
    assert read_back[0].probe == "uci-list"
    assert read_back[0].args == ("dhcp.@dnsmasq[0].server", "-1.1.1.1")


def test_a_value_added_twice_and_removed_once_is_gone() -> None:
    """The same value added twice and removed once is not in the list."""
    batch = (
        "add_list dhcp.@dnsmasq[0].server='1.1.1.1'\n"
        "add_list dhcp.@dnsmasq[0].server='1.1.1.1'\n"
        "add_list dhcp.@dnsmasq[0].server='1.0.0.1'\n"
        "del_list dhcp.@dnsmasq[0].server='1.1.1.1'\n"
    )
    read_back = read_back_of(batch)
    assert len(read_back) == 1, read_back
    assert read_back[0].probe == "uci-list"
    assert read_back[0].args == (
        "dhcp.@dnsmasq[0].server",
        "+1.0.0.1",
        "-1.1.1.1",
    )


def test_a_set_then_an_add_is_the_exact_list() -> None:
    """A plain ``set`` rebuilds the list: the whole list is known."""
    batch = (
        "set dhcp.@dnsmasq[0].server='1.1.1.1'\n"
        "add_list dhcp.@dnsmasq[0].server='1.0.0.1'\n"
    )
    read_back = read_back_of(batch)
    assert len(read_back) == 1, read_back
    assert read_back[0].probe == "uci-equals"
    assert read_back[0].args == (
        "dhcp.@dnsmasq[0].server",
        "1.1.1.1 1.0.0.1",
    )


def test_an_empty_set_then_an_add_has_no_leading_space() -> None:
    """An empty ``set`` rebuilds the list as nothing, not as an empty value."""
    batch = (
        "set dhcp.@dnsmasq[0].server=''\n"
        "add_list dhcp.@dnsmasq[0].server='1.1.1.1'\n"
    )
    read_back = read_back_of(batch)
    assert len(read_back) == 1, read_back
    assert read_back[0].probe == "uci-equals"
    assert read_back[0].args == ("dhcp.@dnsmasq[0].server", "1.1.1.1")


def test_a_set_then_a_del_is_an_unset_check() -> None:
    """A value that is set and then removed leaves the option unset."""
    batch = (
        "set dhcp.@dnsmasq[0].server='1.1.1.1'\n"
        "del_list dhcp.@dnsmasq[0].server='1.1.1.1'\n"
    )
    read_back = read_back_of(batch)
    assert len(read_back) == 1, read_back
    assert read_back[0].probe == "uci-unset"
    assert read_back[0].args == ("dhcp.@dnsmasq[0].server",)


def test_a_section_line_does_not_change_the_staged_values() -> None:
    """A section-level line is not an operation on an option's values.

    ``touched._parse_batch_facts`` keeps the option facts of a section
    a section-level ``set`` touches (it pops only the section's own
    fact), so the option keeps the values the batch staged for it.
    """
    batch = (
        "set dhcp.@dnsmasq[0].server='1.1.1.1'\n"
        "set dhcp.@dnsmasq[0]='dnsmasq'\n"
    )
    read_back = read_back_of(batch)
    assert len(read_back) == 1, read_back
    assert read_back[0].probe == "uci-equals"
    assert read_back[0].args == ("dhcp.@dnsmasq[0].server", "1.1.1.1")


def test_a_section_list_verb_does_not_change_the_staged_values() -> None:
    """A list verb without an option is not an operation on an option."""
    batch = (
        "add_list dhcp.@dnsmasq[0].server='1.1.1.1'\n"
        "del_list dhcp.@dnsmasq[0]='dnsmasq'\n"
    )
    read_back = read_back_of(batch)
    assert len(read_back) == 1, read_back
    assert read_back[0].probe == "uci-list"
    assert read_back[0].args == ("dhcp.@dnsmasq[0].server", "+1.1.1.1")


# -- the uci-list check ----------------------------------------------------


def test_the_list_check_is_a_no_install_only_probe() -> None:
    """It exists only here: the installed router program has no such probe."""
    assert "uci-list" not in probes.PROBE_TABLE
    assert "uci-list" not in checks.PROBE_SUPPORT
    assert set(checks.PROBE_SUPPORT) == set(probes.PROBE_TABLE)
    check = checks.Check("read-back", "uci-list", ("network.lan.proto", "+x"), True)
    assert check.runnable is True


def test_a_list_check_passes_when_every_added_value_is_there() -> None:
    session = FakeSession({("uci", "get"): {"value": ["1.1.1.1", "1.0.0.1"]}})
    result = checks.run_probe(
        session, "uci-list", ["dhcp.@dnsmasq[0].server", "+1.1.1.1", "+1.0.0.1"]
    )
    assert result.passed is True, result


def test_a_list_check_fails_when_an_added_value_is_not_there() -> None:
    session = FakeSession({("uci", "get"): {"value": ["8.8.8.8"]}})
    result = checks.run_probe(
        session, "uci-list", ["dhcp.@dnsmasq[0].server", "+1.1.1.1"]
    )
    assert result.passed is False
    assert result.detail == "mismatch"


def test_a_list_check_fails_when_a_removed_value_is_still_there() -> None:
    session = FakeSession({("uci", "get"): {"value": ["1.1.1.1", "8.8.8.8"]}})
    result = checks.run_probe(
        session, "uci-list", ["dhcp.@dnsmasq[0].server", "-1.1.1.1"]
    )
    assert result.passed is False
    assert result.detail == "mismatch"


def test_a_list_check_reads_one_value_as_a_one_item_list() -> None:
    session = FakeSession({("uci", "get"): {"value": "1.1.1.1"}})
    result = checks.run_probe(
        session, "uci-list", ["dhcp.@dnsmasq[0].server", "+1.1.1.1"]
    )
    assert result.passed is True, result


def test_a_list_check_reads_a_missing_option_as_the_empty_list() -> None:
    """The measured empty answer is the empty list, not a missing answer."""
    session = FakeSession({("uci", "get"): {}})
    result = checks.run_probe(
        session, "uci-list", ["dhcp.@dnsmasq[0].server", "+1.1.1.1"]
    )
    assert result.passed is False, result
    result = checks.run_probe(
        session, "uci-list", ["dhcp.@dnsmasq[0].server", "-1.1.1.1"]
    )
    assert result.passed is True, result


def test_a_list_check_never_passes_on_a_refusal() -> None:
    for code in (4, 6):
        session = FakeSession({("*", "*"): code})
        result = checks.run_probe(
            session, "uci-list", ["dhcp.@dnsmasq[0].server", "+1.1.1.1"]
        )
        assert result.passed is None, (code, result)


def test_a_list_check_never_passes_on_an_unknown_answer() -> None:
    for answer in (
        {"nonsense": True},
        {"value": None},
        {"values": {"lan": {"proto": "static"}}},
        None,
        [],
        "junk",
    ):
        session = FakeSession({("*", "*"): answer})
        result = checks.run_probe(
            session, "uci-list", ["dhcp.@dnsmasq[0].server", "+1.1.1.1"]
        )
        assert result.passed is None, (answer, result)


def test_a_secret_option_is_refused_before_a_list_check_calls_the_router() -> None:
    """No yes/no oracle on a value the agent only ever sees redacted."""
    session = FakeSession({("uci", "get"): data("uci.get.network.lan.proto")})
    result = checks.run_probe(
        session, "uci-list", ["wireless.@wifi-iface[0].key", "+synthetic"]
    )
    assert result.passed is None
    assert session.calls == []


def test_the_router_value_never_appears_in_a_list_detail() -> None:
    session = FakeSession({("uci", "get"): {"value": [CANARY]}})
    result = checks.run_probe(
        session, "uci-list", ["dhcp.@dnsmasq[0].server", "+1.1.1.1"]
    )
    assert result.passed is False
    assert CANARY not in result.detail


@pytest.mark.parametrize(
    "args",
    (
        ["network.lan.proto"],
        ["network.lan", "+static"],
        ["network.lan.proto", "static"],
        ["network.lan.proto", "+"],
        ["network.lan.proto", ""],
        ["network.lan.proto", "+static", ""],
        [],
    ),
)
def test_an_invalid_list_check_argument_never_reaches_the_router(args) -> None:
    """The no-install-only probe keeps its own small grammar."""
    session = FakeSession({("*", "*"): {}})
    result = checks.run_probe(session, "uci-list", args)
    assert result.passed is None, (args, result)
    assert session.calls == [], (args, session.calls)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q", "-p", "no:cacheprovider"]))


def test_a_local_or_no_install_probe_counts_as_supported():
    """``fail`` (a planted failure, no call) and
    ``uci-list`` (no-install only) run on this path, so a claim that
    uses them must run at verify time and can block the confirm; only a
    probe the stock groups cannot run is skipped."""
    assert checks.probe_supported("fail")
    assert checks.probe_supported("uci-list")
    assert checks.probe_supported("uci-equals")
    assert not checks.probe_supported("nft-rule")
    assert not checks.probe_supported("no-such-probe")


# ---- the third review, defect 2: a batch that only takes settings away ----


def _service_check(results):
    """The service check of the first class check, as a triple."""
    return [
        (check.kind, check.probe, check.args)
        for check in results[0].mandatory
        if check.probe == "service-running"
    ]


def test_checks_for_a_del_list_batch_lists_the_dnsmasq_service() -> None:
    """A batch that only takes a DNS server away is still a DNS change.

    A del_list stages no value, so the batch holds no fact: without the
    delete the change had no class at all, and the mandatory check of
    the dns class (the dnsmasq service must be running) never ran.
    """
    results = checks.checks_for("del_list dhcp.@dnsmasq[0].server='1.1.1.1'")
    assert [result.name for result in results] == ["dns"]
    assert _service_check(results) == [
        ("service-running", "service-running", ("dnsmasq", "any", "present"))
    ]


def test_checks_for_a_delete_of_a_dns_option_lists_the_dnsmasq_service() -> None:
    """The same for a delete of one option of a DNS section."""
    results = checks.checks_for("delete dhcp.@dnsmasq[0].server")
    assert [result.name for result in results] == ["dns"]
    assert _service_check(results) == [
        ("service-running", "service-running", ("dnsmasq", "any", "present"))
    ]


def test_a_set_of_an_existing_reservation_then_its_delete_still_lists_the_dnsmasq_service() -> None:
    """A `set SEC=TYPE` on a section the router already has does not
    create it, so its later delete is still the delete of a reservation."""
    results = checks.checks_for(
        "set dhcp.myhost=host\ndelete dhcp.myhost",
        types={("dhcp", "myhost"): "host"},
    )
    assert ("service-running", "service-running", ("dnsmasq", "any", "present")) in _service_check(results)


def test_checks_for_a_delete_of_a_reservation_lists_the_dnsmasq_service() -> None:
    """A whole reservation that is taken away is still a reservation.

    The type of the section comes from the router: without it the
    change has no class, and the check of the class never ran.
    """
    results = checks.checks_for(
        "delete dhcp.myhost", types={("dhcp", "myhost"): "host"}
    )
    assert [result.name for result in results] == ["dhcp-reservations"]
    assert _service_check(results) == [
        ("service-running", "service-running", ("dnsmasq", "any", "present"))
    ]


def test_a_delete_of_a_section_without_a_type_has_no_class() -> None:
    """A section nobody says the type of is never classified."""
    assert checks.checks_for("delete dhcp.myhost") == []


# ---- the allowlist ---------------------------------------------

#: A DHCP reservation: the class Newton may apply itself.
RESERVATION = (
    "set dhcp.@host[0].mac='02:00:00:00:10:01'\n"
    "set dhcp.@host[0].ip='10.109.0.55'\n"
)

#: A DNS entry: the other class Newton may apply itself.
DNS_ENTRY = "set dhcp.@domain[0].name='example.test'\n"

#: A Wi-Fi name: never auto-applied on a no-install router.
WIFI_NAME = "set wireless.@wifi-iface[0].ssid='newname'\n"

#: A change outside the allowlist.
LAN_ADDRESS = "set network.lan.proto='static'\n"

#: A HIGH change (management access).
MANAGEMENT = "set uhttpd.main.listen_http='0.0.0.0:80'\n"


def test_the_auto_apply_list_is_the_two_classes_newton_may_apply() -> None:
    """ONE list of the classes Newton may apply itself."""
    assert checks.AUTO_APPLY == ("dhcp-reservations", "dns")


def test_a_dhcp_reservation_is_applied_by_newton_itself() -> None:
    auto, reason = checks.auto_apply_decision(RESERVATION, None, risk="low")
    assert auto is True
    assert reason == "Newton applies this itself"


def test_a_dns_change_is_applied_by_newton_itself() -> None:
    auto, reason = checks.auto_apply_decision(DNS_ENTRY, None, risk="low")
    assert auto is True
    assert reason == "Newton applies this itself"


def test_a_wifi_change_is_an_owner_script() -> None:
    """a Wi-Fi change is never applied by Newton itself."""
    auto, reason = checks.auto_apply_decision(WIFI_NAME, None, risk="low")
    assert auto is False
    assert reason.startswith("this needs an owner script because ")
    assert "wifi-name-key" in reason


def test_a_change_outside_the_allowlist_is_an_owner_script() -> None:
    auto, reason = checks.auto_apply_decision(LAN_ADDRESS, None, risk="low")
    assert auto is False
    assert reason.startswith("this needs an owner script because ")


def test_a_high_change_is_an_owner_script() -> None:
    auto, reason = checks.auto_apply_decision(MANAGEMENT, None, risk="low")
    assert auto is False
    assert reason.startswith("this needs an owner script because ")


def test_a_critical_change_is_an_owner_script() -> None:
    auto, reason = checks.auto_apply_decision(RESERVATION, None, risk="critical")
    assert auto is False
    assert "critical" in reason


def test_an_unjudged_change_is_not_applied_by_newton_itself() -> None:
    """The policy needs the router's diff, so a change the policy has
    not judged is never applied by itself."""
    auto, reason = checks.auto_apply_decision(RESERVATION, None)
    assert auto is False
    assert reason.startswith("this needs an owner script because ")


def test_a_config_newton_may_not_write_is_an_owner_script() -> None:
    """The system config is read-only for the rpcd user."""
    batch = (
        "set dhcp.@host[0].ip='10.109.0.55'\n"
        "set system.@system[0].hostname='newname'\n"
    )
    auto, reason = checks.auto_apply_decision(batch, None, risk="low")
    assert auto is False
    assert reason.startswith("this needs an owner script because ")


def test_an_empty_change_is_an_owner_script() -> None:
    auto, reason = checks.auto_apply_decision("", None, risk="low")
    assert auto is False
    assert reason.startswith("this needs an owner script because ")


def test_a_change_that_is_not_text_is_an_owner_script() -> None:
    auto, reason = checks.auto_apply_decision(None, None, risk="low")
    assert auto is False
    assert reason.startswith("this needs an owner script because ")


# ---- a whole section delete ------------------------------------


def test_a_whole_section_delete_gets_a_read_back_of_the_section() -> None:
    """A reservation that is taken away whole is read back as gone.

    The batch names no option of the section, so the option checks say
    nothing about it: the check that says the SECTION is not set is the
    one that proves the change.
    """
    results = checks.checks_for(
        "delete dhcp.myhost", types={("dhcp", "myhost"): "host"}
    )

    assert [result.name for result in results] == ["dhcp-reservations"]
    read_back = [
        (check.kind, check.probe, check.args)
        for check in results[0].mandatory
        if check.kind == "read-back"
    ]
    assert read_back == [("read-back", "uci-unset", ("dhcp.myhost",))], read_back
    # the class checks of the class still run
    assert _service_check(results) == [
        ("service-running", "service-running", ("dnsmasq", "any", "present"))
    ]


def test_a_whole_section_delete_keeps_the_read_back_of_its_options() -> None:
    """The options the batch named are read back as gone as well."""
    results = checks.checks_for(
        "set dhcp.myhost.ip='10.0.0.5'\ndelete dhcp.myhost",
        types={("dhcp", "myhost"): "host"},
    )

    read_back = [
        (check.kind, check.probe, check.args)
        for check in results[0].mandatory
        if check.kind == "read-back"
    ]
    assert ("read-back", "uci-unset", ("dhcp.myhost",)) in read_back, read_back
    assert ("read-back", "uci-unset", ("dhcp.myhost.ip",)) in read_back, read_back


# ---- the internet check (the installed program's own check) -----------------


def test_the_internet_check_passes_when_the_router_has_the_internet() -> None:
    """Both probes answer: the router has the internet.

    The probes are the ones the installed router program runs before
    every confirm (``cmd_verify`` of ``newton-router``): ping
    1.1.1.1, and openwrt.org resolved by the router itself.
    """
    session = FakeSession({("file", "exec"): {"code": 0}})
    assert checks.check_internet(session) is None
    assert [call[2]["command"] for call in session.calls] == [
        "/bin/ping",
        "/usr/bin/nslookup",
    ], session.calls


def test_the_internet_check_fails_when_the_router_has_no_internet() -> None:
    session = FakeSession({("file", "exec"): {"code": 1}})
    assert checks.check_internet(session) == "the internet check failed"


def test_the_internet_check_could_not_run() -> None:
    """An answer Newton cannot read is not a failed check."""
    session = FakeSession({("file", "exec"): {}})
    assert checks.check_internet(session) == "the internet check could not run"


def test_the_internet_check_fails_when_the_ping_works_and_the_name_does_not(
) -> None:
    """The ping is not the internet check: the name has to resolve too.

    The installed router program runs a ping and a lookup before every
    confirm, so a router that answers the ping and cannot resolve a
    name has no working internet.
    """
    session = FakeSession(
        {
            ("file", "exec"): exec_answers_by_command(
                {"/usr/bin/nslookup": {"code": 1}}
            )
        }
    )
    assert checks.check_internet(session) == "the internet check failed"


def test_the_internet_probes_are_the_ones_the_router_program_runs() -> None:
    assert checks.INTERNET_PROBES == (
        ("ping", "1.1.1.1"),
        ("resolve", "openwrt.org", "127.0.0.1"),
    )


# ---- the internet check waits for the router's own reload ------------------


class _Clock:
    """The clock of the test: it moves only when the test sleeps."""

    def __init__(self, start: float = 1_000.0) -> None:
        self.value = float(start)
        self.slept: list[float] = []

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        """Move the clock without a sleep: the test moves it itself."""
        self.value += seconds

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.value += seconds


def _ping_answers(codes: list[int]):
    """A router whose ping answers the next code of the list.

    The last code of the list is the answer of every try after the
    list runs out.  The name lookup always works: the ping is the
    probe that fails.
    """
    state = {"calls": 0}

    def answer(obj: str, fn: str, args: dict[str, Any]) -> Any:
        command = str(args.get("command", ""))
        if command != "/bin/ping":
            return {"code": 0}
        index = min(state["calls"], len(codes) - 1)
        state["calls"] += 1
        return {"code": codes[index]}

    return answer


def test_the_internet_check_waits_for_the_routers_own_reload() -> None:
    """The first probe runs after the settle, and only then.

    ``uci apply`` returns before the router's network reload is done:
    a probe that runs right after the apply asks a router that has not
    taken the uplinks down yet (measured on the real router: the check
    ran about a second after the apply, and the uplinks were still up).
    """
    clock = _Clock()
    session = FakeSession({("file", "exec"): {"code": 0}})
    assert (
        checks.wait_for_internet(
            session,
            applied_at=clock.value,
            deadline=clock.value + 180,
            now=clock,
            sleep=clock.sleep,
        )
        is None
    )
    assert clock.slept == [10.0], clock.slept
    assert len(session.calls) == 2, session.calls


def test_the_internet_check_retries_until_the_router_has_the_internet() -> None:
    """Fail, fail, pass: three tries, five seconds apart."""
    clock = _Clock()
    session = FakeSession({("file", "exec"): _ping_answers([1, 1, 0])})
    assert (
        checks.wait_for_internet(
            session,
            applied_at=clock.value,
            deadline=clock.value + 180,
            now=clock,
            sleep=clock.sleep,
        )
        is None
    )
    # the settle, then one wait between every try
    assert clock.slept == [10.0, 5.0, 5.0], clock.slept
    pings = [
        call for call in session.calls if call[2].get("command") == "/bin/ping"
    ]
    assert len(pings) == 3, session.calls


def test_the_internet_check_gives_up_when_the_budget_is_gone() -> None:
    """A router without the internet: the tries stop at the budget.

    The reason of the last try is the one that counts, and the wait
    never runs past the deadline.
    """
    clock = _Clock()
    applied_at = clock.value
    deadline = applied_at + 180
    session = FakeSession({("file", "exec"): _ping_answers([1])})
    reason = checks.wait_for_internet(
        session,
        applied_at=applied_at,
        deadline=deadline,
        now=clock,
        sleep=clock.sleep,
    )
    assert reason == "the internet check failed", reason
    budget_end = min(
        applied_at + checks.INTERNET_SETTLE_S + checks.INTERNET_WAIT_MAX_S,
        deadline - rpcd_txn.RESOLVE_MARGIN_S - checks.INTERNET_RESERVE_S,
    )
    # the last try is inside the budget, and never past the deadline
    assert clock.value <= budget_end, (clock.value, budget_end)
    assert clock.value <= deadline - rpcd_txn.RESOLVE_MARGIN_S
    assert sum(clock.slept) <= (
        checks.INTERNET_WAIT_MAX_S + checks.INTERNET_SETTLE_S
    ), clock.slept
    pings = [
        call for call in session.calls if call[2].get("command") == "/bin/ping"
    ]
    assert len(pings) == 13, len(pings)


def test_the_internet_check_does_not_probe_when_the_budget_is_gone() -> None:
    """No time left before the settle is over: no probe runs at all."""
    clock = _Clock()
    applied_at = clock.value
    session = FakeSession({("file", "exec"): {"code": 0}})
    reason = checks.wait_for_internet(
        session,
        applied_at=applied_at,
        deadline=applied_at + 12,
        now=clock,
        sleep=clock.sleep,
    )
    assert reason == "the internet check could not run", reason
    assert session.calls == [], session.calls
    assert clock.slept == [], clock.slept


def test_the_internet_check_runs_no_probe_when_the_read_back_starts_late(
) -> None:
    """A read-back that starts after the budget runs no probe at all.

    The budget is the clock's, not the schedule's: when the read-back
    starts after the window's own margin is gone, there is no time to
    probe at all, and the reason says the check could not run.
    """
    clock = _Clock()
    applied_at = clock.value
    deadline = applied_at + 30
    session = FakeSession({("file", "exec"): {"code": 0}})
    # the read-back starts 20 s after the apply: the budget is gone
    clock.advance(20)
    reason = checks.wait_for_internet(
        session,
        applied_at=applied_at,
        deadline=deadline,
        now=clock,
        sleep=clock.sleep,
    )
    assert reason == "the internet check could not run", reason
    assert session.calls == [], session.calls
    assert clock.slept == [], clock.slept


def test_the_internet_check_spaces_the_tries_when_the_probes_are_slow() -> None:
    """A slow probe does not make the tries fire back-to-back.

    The gap between two tries is counted from the END of the last try,
    so a probe that takes 8 s still leaves the retry spacing between
    them, and no try starts after the budget is gone.
    """
    clock = _Clock()
    applied_at = clock.value
    deadline = applied_at + 180
    tries: list[float] = []

    def slow_probe(obj: str, fn: str, args: dict[str, Any]) -> Any:
        # every probe takes 8 s, and the ping is the one that fails
        tries.append(clock.value)
        clock.advance(8)
        return {"code": 1}

    session = FakeSession({("file", "exec"): slow_probe})
    reason = checks.wait_for_internet(
        session,
        applied_at=applied_at,
        deadline=deadline,
        now=clock,
        sleep=clock.sleep,
    )
    assert reason == "the internet check failed", reason
    # the settle, then one retry spacing between every two tries
    assert clock.slept == [10.0] + [5.0] * (len(tries) - 1), clock.slept
    # no two tries fire back-to-back, and none starts after the budget
    gaps = [after - before for before, after in zip(tries, tries[1:])]
    assert all(gap >= checks.INTERNET_RETRY_S for gap in gaps), gaps
    budget_end = min(
        applied_at + checks.INTERNET_SETTLE_S + checks.INTERNET_WAIT_MAX_S,
        deadline - rpcd_txn.RESOLVE_MARGIN_S - checks.INTERNET_RESERVE_S,
    )
    assert max(tries) <= budget_end, (tries, budget_end)


def test_the_internet_check_probes_a_bounded_number_of_times() -> None:
    """A wait that barely moves the clock cannot make the check probe for ever.

    The tries are spaced by the clock, so a sleep that does not move
    the clock would let the tries run without end.  The number of
    tries is bounded, so the check always ends.
    """
    clock = _Clock()

    def slow_sleep(seconds: float) -> None:
        clock.advance(0.01)

    session = FakeSession({("file", "exec"): {"code": 1}})
    reason = checks.wait_for_internet(
        session,
        applied_at=clock.value,
        deadline=clock.value + 180,
        now=clock,
        sleep=slow_sleep,
    )
    assert reason == "the internet check failed", reason
    pings = [
        call for call in session.calls if call[2].get("command") == "/bin/ping"
    ]
    assert len(pings) == checks.INTERNET_MAX_TRIES, len(pings)


# ---- the reason a change is an owner script --------------------------------


def test_a_removal_says_it_removes_a_setting() -> None:
    """A removal is an owner script, and the reason says what it does."""
    auto, reason = checks.auto_apply_decision(
        "delete dhcp.myhost", None, risk="low"
    )
    assert auto is False
    assert reason == (
        checks.OWNER_SCRIPT_REASON
        + "it removes a setting, and Newton never removes settings by itself"
    )


def test_a_change_that_is_not_on_the_list_says_so() -> None:
    """A change that is not on the list says so, in the same words."""
    auto, reason = checks.auto_apply_decision(LAN_ADDRESS, None, risk="low")
    assert auto is False
    assert reason == (
        checks.OWNER_SCRIPT_REASON
        + "it holds a change that is not on the list Newton applies by itself"
    )
