"""The host side of the client-vantage outcome checks.

A plan may claim what a
CLIENT sees, not only what the router reports.  Router-side verify cannot see
that, so a client claim is checked from a registered inside vantage, through a
second forced-command key, and any FAIL or NOT-TESTED of a claimed check stops
the confirm.

This module covers the host-side pieces only:

* VC-04 the one place ``OWRT_LOCAL_CHECK`` is built (``local_check_string``);
* VC-05 the plan-time refusals that live below ``server.py`` (the agent may
  not supply targets, the stored form re-parses, a changed claim changes the
  plan hash);
* VC-08 the router addresses a blocked claim is checked against;
* VC-09 which vantage serves which zone;
* VC-10 the router probe list ignores client claims;
* VC-11 a failed client claim is read from the local-check block of the log;
* VC-12 the two new inventory keys (``zones``, ``check_targets``);
* VC-13 the two places that print a claim in words.
* VC-18 the second cold review: the default allow-list of the forced
  command, the write of the spec and the verify budget.

Nothing here reaches a device, a router or a vantage: no ssh, no network.
"""

from __future__ import annotations

import ast
import ipaddress
import json
import re
from pathlib import Path

import pytest

from exhelp import make_explanation, record_fields_display
from newton_mcp import approve as approve_module
from newton_mcp import change_receipt as receipt_module
from newton_mcp import client_checks as cc
from newton_mcp import explanation as ex
from newton_mcp import scans
from newton_mcp.plan import compute_plan_hash

SID = "0123456789abcdef0123456789abcdef"
OTHER_SID = "f" * 32
BATCH = "set dhcp.skilltest=host\nset dhcp.skilltest.name='skilltest'"

RUN_PATH = Path("/opt/newton/scripts/newton-vantage-run")

C_UCI = {"kind": "uci_equals", "path": "dhcp.skilltest.name", "equals": "skilltest"}
C_PROBE = {"kind": "probe", "probe": ["iface-absent", "guestx"]}
C_DNS = {"kind": "client_dns", "zone": "guest"}
C_DHCP = {"kind": "client_dhcp", "zone": "guest"}
C_INTERNET = {"kind": "client_internet", "zone": "guest"}
C_BLOCKED_ROUTER = {"kind": "client_blocked", "zone": "guest", "to": "router"}
C_BLOCKED_INTERNET = {"kind": "client_blocked", "zone": "guest", "to": "internet"}

# A router dump as ``ubus call network.interface dump`` gives it: every
# interface with its IPv4 addresses.  10/8 and 192.168/16 are private,
# 100.64/10 is the CGNAT range, the rest are public and are dropped.
DUMP = {
    "interface": [
        {"interface": "loopback", "up": True, "ipv4-address": [{"address": "127.0.0.1", "mask": 8}]},
        {
            "interface": "lan",
            "up": True,
            "ipv4-address": [{"address": "192.168.1.1", "mask": 24}],
        },
        {
            "interface": "guest",
            "up": True,
            "ipv4-address": [
                {"address": "10.0.0.1", "mask": 8},
                {"address": "10.0.0.9", "mask": 8},
            ],
        },
        {
            "interface": "wan",
            "up": True,
            "ipv4-address": [{"address": "198.51.100.9", "mask": 24}],
        },
    ]
}


def stored_expect(expect):
    """The plan-time stored form: client claims carry the targets Newton derived."""
    parsed = ex.parse_explanation(make_explanation(BATCH, expect=expect), change_lines=2)
    return cc.fill_targets(parsed["expect"], lambda: DUMP)


def local_check_log(lines, *, sid=SID, stage="local-check", round_number=3, exit_code=1):
    """An apply log with one VERIFY DETAIL block of the given stage."""
    out = [
        f"APPLYING session={sid}",
        f"VERIFY FAILED session={sid} - not confirming; waiting for automatic rollback",
        f"VERIFY DETAIL session={sid} round={round_number} exit={exit_code} stage={stage} "
        "(last failed round; stderr and stdout follow, each last 20 lines, at most 2 KB)",
    ]
    out += [f"VERIFY STDERR session={sid}: {line}" for line in lines]
    out.append(f"ROLLBACK WINDOW PASSED session={sid} rolled back by the guard")
    return "\n".join(out) + "\n"


def plan_record(expect):
    """A minimal plan record for the hash test (the fields the identity needs)."""
    return {
        "device": "lab1",
        "host": "192.0.2.1",
        "session_id": SID,
        "uci_batch": BATCH,
        "diff": "dhcp.skilltest='host'",
        "probes": [],
        "timeout_s": 300,
        "base_hash": "b" * 64,
        "requires_approval": False,
        "router_digest": "d" * 64,
        "explanation": make_explanation(BATCH, expect=expect),
        "owner_confirmed_in_chat": True,
        "staged_at": "2026-10-25T09:00:00+00:00",
        **record_fields_display(),
    }


def a_vantage(*, name="inside-a", role="inside", devices=("lab1",), zones=("guest",)):
    """A Vantage built by hand (no inventory file, no key on disk)."""
    zone_rows = tuple(
        scans.VantageZone(
            name=zone,
            src="192.0.2.50",
            canary_ip="192.0.2.1",
            canary_port=53,
            iface="eth0.30",
            netns="guest",
        )
        for zone in zones
    )
    return scans.Vantage(
        name=name,
        host="vantage.example.invalid",
        user="newton",
        key_file=Path("/tmp/newton-scan.key"),
        known_hosts=Path("/tmp/newton-known-hosts"),
        proxy_command=None,
        role=role,
        devices=tuple(devices),
        zones=zone_rows,
    )


# ---- VC-04: the one place OWRT_LOCAL_CHECK is built --------------------------------


def test_vc04_01_the_local_check_string_is_the_quoted_path_and_the_session_id():
    value = cc.local_check_string(RUN_PATH, SID)
    assert value == f"'/opt/newton/scripts/newton-vantage-run' {SID}"
    assert cc.LOCAL_CHECK_RE.fullmatch(value)


def test_vc04_02_the_pinned_regex_accepts_only_a_quoted_run_path_and_a_hex_session_id():
    assert cc.LOCAL_CHECK_RE.pattern == r"^'/[A-Za-z0-9_./-]+/newton-vantage-run' [0-9a-f]{32}$"
    assert cc.LOCAL_CHECK_RE.fullmatch(f"'/x/newton-vantage-run' {SID}")
    assert not cc.LOCAL_CHECK_RE.fullmatch(f"/x/newton-vantage-run {SID}")
    assert not cc.LOCAL_CHECK_RE.fullmatch(f"'/x/newton-vantage-run' {SID.upper()}")
    assert not cc.LOCAL_CHECK_RE.fullmatch(f"'/x/newton-vantage-run' {SID} ")


@pytest.mark.parametrize(
    "path",
    [
        "/opt/newton scripts/newton-vantage-run",   # a space
        "/opt/newton/scripts/newton-vantage-run;reboot",   # a semicolon
        "/opt/newton/scripts/newton-vantage-run$IFS",     # a dollar sign
        "/opt/newton/scripts/newton-vantage-run\nx",       # a newline
        "/opt/newton/scripts/newton-vantage-run'x",       # a quote
        '/opt/newton/scripts/newton-vantage-run"x',        # a double quote
        "opt/newton/scripts/newton-vantage-run",          # not absolute
        "/opt/newton/scripts/other-name",                 # not the run script
        "/opt/newton/scripts/newton-vantage-run/x",       # not the run script
        "/opt/newton/scripts/newton-vantage-run;ls -l",   # two commands
    ],
)
def test_vc04_03_a_path_with_a_quote_space_semicolon_dollar_or_newline_is_refused(path):
    with pytest.raises(cc.ClientCheckError):
        cc.local_check_string(Path(path), SID)


@pytest.mark.parametrize(
    "sid",
    [
        "",
        "0123456789abcdef",                  # too short
        SID + "0",                           # too long
        SID.upper(),                         # not lowercase
        "g" * 32,                            # not hex
        SID[:-1] + " ",                      # a space
        SID[:-1] + ";",                      # a semicolon
        SID[:-1] + "$",                      # a dollar sign
        SID[:-1] + "\n",                     # a newline
    ],
)
def test_vc04_04_a_session_id_that_is_not_32_lowercase_hex_is_refused(sid):
    with pytest.raises(cc.ClientCheckError):
        cc.local_check_string(RUN_PATH, sid)


def test_vc04_05_the_refusal_text_never_echoes_the_bad_value():
    with pytest.raises(cc.ClientCheckError) as err:
        cc.local_check_string(Path("/opt/newton/$(reboot)/newton-vantage-run"), SID)
    assert "$(" not in str(err.value)


# ---- VC-05: the plan-time refusals that live below server.py ----------------------


def test_vc05_01_the_agent_may_not_supply_targets():
    raw = make_explanation(
        BATCH,
        expect=[{"kind": "client_blocked", "zone": "guest", "to": "router",
                 "targets": ["10.0.0.1:22"]}],
    )
    with pytest.raises(ex.ExplanationError) as err:
        ex.parse_explanation(raw, change_lines=2)
    assert "targets" in str(err.value)
    assert "derived by Newton" in str(err.value)


def test_vc05_02_the_stored_form_re_parses_with_allow_targets_and_not_without():
    filled = stored_expect([C_UCI, C_BLOCKED_ROUTER])
    assert filled[1]["targets"] == [
        "10.0.0.1:22", "10.0.0.1:443", "10.0.0.1:80",
        "10.0.0.9:22", "10.0.0.9:443", "10.0.0.9:80",
        "192.168.1.1:22", "192.168.1.1:443", "192.168.1.1:80",
    ]
    again = ex.parse_explanation(
        {"intent": "i", "steps": ["a", "b"], "expect": filled, "risk": "r"},
        change_lines=2,
        allow_targets=True,
    )
    assert again["expect"] == filled
    with pytest.raises(ex.ExplanationError):
        ex.parse_explanation(
            {"intent": "i", "steps": ["a", "b"], "expect": filled, "risk": "r"},
            change_lines=2,
        )


def test_vc05_03_a_stored_client_blocked_claim_without_targets_is_refused():
    stored = {
        "intent": "i",
        "steps": ["a", "b"],
        "expect": [{"kind": "client_blocked", "zone": "guest", "to": "router"}],
        "risk": "r",
    }
    with pytest.raises(ex.ExplanationError):
        ex.parse_explanation(stored, change_lines=2, allow_targets=True)


@pytest.mark.parametrize(
    "claim",
    [
        {"kind": "client_dns", "zone": "Guest"},
        {"kind": "client_dns", "zone": ""},
        {"kind": "client_dns", "zone": "guest zone"},
        {"kind": "client_dns", "zone": "guest;ls"},
        {"kind": "client_dns", "zone": 7},
        {"kind": "client_dns"},
        {"kind": "client_dns", "zone": "guest", "extra": "x"},
        {"kind": "client_blocked", "zone": "guest"},
        {"kind": "client_blocked", "zone": "guest", "to": "internet "},
        {"kind": "client_blocked", "zone": "guest", "to": "router", "extra": "x"},
        {"kind": "client_dns", "zone": "a" * 33},
        {"kind": "client_dns", "zone": "9guest"},
    ],
)
def test_vc05_04_a_client_claim_outside_the_grammar_is_refused(claim):
    raw = make_explanation(BATCH, expect=[claim])
    with pytest.raises(ex.ExplanationError):
        ex.parse_explanation(raw, change_lines=2)


def test_vc05_05_a_changed_claim_changes_the_plan_hash():
    base = plan_record([C_UCI, C_DNS])
    other = plan_record([C_UCI, C_DHCP])
    assert compute_plan_hash(base) != compute_plan_hash(other)
    assert compute_plan_hash(base) == compute_plan_hash(plan_record([C_UCI, C_DNS]))


def test_vc05_06_the_derived_targets_are_part_of_the_hash_bound_explanation():
    agent_form = plan_record([C_UCI, C_BLOCKED_ROUTER])
    stored_form = plan_record([C_UCI, C_BLOCKED_ROUTER])
    stored_form["explanation"]["expect"] = stored_expect([C_UCI, C_BLOCKED_ROUTER])
    assert compute_plan_hash(agent_form) != compute_plan_hash(stored_form)


# ---- VC-08: the router addresses a blocked claim is checked against ----------------


def test_vc08_01_only_private_router_addresses_become_targets():
    dump = {
        "interface": [
            {"interface": "lan", "up": True, "ipv4-address": [{"address": "192.168.1.1", "mask": 24}]},
            {"interface": "wan", "up": True, "ipv4-address": [{"address": "198.51.100.9", "mask": 24}]},
            {"interface": "loopback", "up": True, "ipv4-address": [{"address": "127.0.0.1", "mask": 8}]},
            {"interface": "test", "up": True, "ipv4-address": [{"address": "192.0.2.1", "mask": 24}]},
        ]
    }
    assert cc.derive_router_targets(dump) == [
        "192.168.1.1:22", "192.168.1.1:443", "192.168.1.1:80",
    ]


def test_vc08_02_the_cgnat_range_counts_as_private():
    dump = {"interface": [{"interface": "wan", "up": True,
                           "ipv4-address": [{"address": "100.64.0.1", "mask": 10}]}]}
    assert cc.derive_router_targets(dump) == [
        "100.64.0.1:22", "100.64.0.1:443", "100.64.0.1:80",
    ]


def test_vc08_03_the_targets_are_sorted_by_address_then_port():
    assert cc.derive_router_targets(DUMP) == [
        "10.0.0.1:22", "10.0.0.1:443", "10.0.0.1:80",
        "10.0.0.9:22", "10.0.0.9:443", "10.0.0.9:80",
        "192.168.1.1:22", "192.168.1.1:443", "192.168.1.1:80",
    ]


def test_vc08_04_the_same_address_on_two_interfaces_is_one_target_set():
    dump = {
        "interface": [
            {"interface": "lan", "up": True, "ipv4-address": [{"address": "192.168.1.1", "mask": 24}]},
            {"interface": "guest", "up": True, "ipv4-address": [{"address": "192.168.1.1", "mask": 24}]},
        ]
    }
    assert cc.derive_router_targets(dump) == [
        "192.168.1.1:22", "192.168.1.1:443", "192.168.1.1:80",
    ]


def test_vc08_05_more_than_twenty_four_targets_is_refused():
    addresses = [f"10.0.{index}.1" for index in range(9)]
    dump = {"interface": [{"interface": "lan", "up": True,
                           "ipv4-address": [{"address": a, "mask": 8} for a in addresses]}]}
    with pytest.raises(cc.ClientCheckError) as err:
        cc.derive_router_targets(dump)
    assert "too many router addresses" in str(err.value)


def test_vc08_06_a_router_with_no_private_address_is_refused():
    dump = {"interface": [{"interface": "wan", "up": True,
                           "ipv4-address": [{"address": "198.51.100.9", "mask": 24}]}]}
    with pytest.raises(cc.ClientCheckError) as err:
        cc.derive_router_targets(dump)
    assert "no private address" in str(err.value)


def test_vc08_07_an_empty_or_broken_dump_is_refused():
    for dump in ({}, {"interface": []}, {"interface": "lan"}, {"interface": [{"interface": "lan"}]}):
        with pytest.raises(cc.ClientCheckError):
            cc.derive_router_targets(dump)


def test_vc08_08_the_dump_is_read_once_and_only_when_a_router_block_is_claimed():
    calls: list[int] = []

    def loader():
        calls.append(1)
        return DUMP

    cc.fill_targets([C_DNS], loader)
    assert calls == []
    cc.fill_targets([C_BLOCKED_INTERNET], loader)
    assert calls == []
    filled = cc.fill_targets([C_BLOCKED_ROUTER, C_BLOCKED_ROUTER], loader)
    assert len(calls) == 1
    assert filled[0]["targets"] == filled[1]["targets"]


def test_vc08_09_an_internet_block_is_exactly_the_two_public_resolvers():
    filled = cc.fill_targets([C_BLOCKED_INTERNET], lambda: DUMP)
    assert filled[0]["targets"] == ["1.1.1.1:443", "9.9.9.9:443"]
    assert cc.INTERNET_TARGETS == ("1.1.1.1:443", "9.9.9.9:443")


def test_vc08_10_filling_targets_does_not_change_the_claim_it_was_given():
    claims = [dict(C_BLOCKED_ROUTER)]
    cc.fill_targets(claims, lambda: DUMP)
    assert claims == [C_BLOCKED_ROUTER]


# ---- VC-09: which vantage serves which zone ---------------------------------------


def test_vc09_01_the_one_inside_vantage_that_serves_the_zone_is_found():
    vantages = {"inside-a": a_vantage()}
    assert cc.vantage_for_zone(vantages, "lab1", "guest") is vantages["inside-a"]


def test_vc09_02_no_vantage_for_the_zone_is_refused():
    with pytest.raises(cc.ClientCheckError) as err:
        cc.vantage_for_zone({"inside-a": a_vantage()}, "lab1", "other")
    assert "no inside vantage serves zone other" in str(err.value)


def test_vc09_03_a_vantage_of_role_outside_cannot_serve_a_client_claim():
    vantages = {"outside-a": a_vantage(name="outside-a", role="outside")}
    with pytest.raises(cc.ClientCheckError) as err:
        cc.vantage_for_zone(vantages, "lab1", "guest")
    assert "no inside vantage serves zone guest" in str(err.value)


def test_vc09_04_a_vantage_for_another_device_cannot_serve_the_claim():
    with pytest.raises(cc.ClientCheckError) as err:
        cc.vantage_for_zone({"inside-a": a_vantage(devices=("other",))}, "lab1", "guest")
    assert "no inside vantage serves zone guest" in str(err.value)


def test_vc09_05_two_vantages_for_the_same_zone_are_refused():
    vantages = {"inside-a": a_vantage(), "inside-b": a_vantage(name="inside-b")}
    with pytest.raises(cc.ClientCheckError) as err:
        cc.vantage_for_zone(vantages, "lab1", "guest")
    assert "more than one inside vantage serves zone guest" in str(err.value)


# ---- VC-10: the router probe list ignores client claims ----------------------------


def test_vc10_01_claim_probes_carry_the_router_claims_only():
    parsed = ex.parse_explanation(
        make_explanation(BATCH, expect=[C_UCI, C_DNS, C_PROBE]), change_lines=2
    )
    assert ex.claim_probes(parsed) == [
        ["uci-equals", "dhcp.skilltest.name", "skilltest"],
        ["iface-absent", "guestx"],
    ]


def test_vc10_02_a_client_claim_is_not_a_router_probe():
    with pytest.raises(ex.ExplanationError):
        ex.claim_to_probe(C_DNS)
    with pytest.raises(ex.ExplanationError):
        ex.claim_to_probe(C_BLOCKED_ROUTER)


def test_vc10_03_the_probe_tail_is_compared_with_the_router_claims_only():
    parsed = ex.parse_explanation(
        make_explanation(BATCH, expect=[C_UCI, C_DNS]), change_lines=2
    )
    probes = [["uci-equals", "dhcp.skilltest.name", "skilltest"]]
    assert ex.claims_match_probes(probes, parsed) is True
    assert ex.claims_match_probes([], parsed) is False
    assert ex.claims_match_probes([["iface-absent", "guestx"]], parsed) is False


def test_vc10_04_client_claims_are_found_by_their_number_in_expect():
    parsed = ex.parse_explanation(
        make_explanation(BATCH, expect=[C_UCI, C_DNS, C_BLOCKED_ROUTER]), change_lines=2
    )
    assert cc.client_claims(parsed["expect"]) == [(2, C_DNS), (3, C_BLOCKED_ROUTER)]


# ---- VC-11: a failed client claim is read from the local-check block --------------


def test_vc11_01_a_failed_client_claim_names_the_claim_and_the_word():
    expect = stored_expect([C_UCI, C_BLOCKED_ROUTER])
    probes = [["uci-equals", "dhcp.skilltest.name", "skilltest"]]
    log = local_check_log(["vantage-check: claim 2 FAIL open"])
    out = ex.failed_claim(log, SID, probes, expect)
    assert out == {
        "claim": 2,
        "text": (
            "expect claim 2 failed: client in zone guest cannot reach router "
            "addresses (9 targets) (open)"
        ),
    }


def test_vc11_02_a_claim_that_could_not_be_tested_is_not_a_pass():
    expect = stored_expect([C_UCI, C_DNS])
    probes = [["uci-equals", "dhcp.skilltest.name", "skilltest"]]
    log = local_check_log(["vantage-check: claim 2 NOT-TESTED unreachable"])
    out = ex.failed_claim(log, SID, probes, expect)
    assert out == {
        "claim": 2,
        "text": "expect claim 2 could not be tested: unreachable",
    }


def test_vc11_03_a_passing_claim_names_nothing():
    expect = stored_expect([C_UCI, C_DNS])
    probes = [["uci-equals", "dhcp.skilltest.name", "skilltest"]]
    log = local_check_log(["vantage-check: claim 2 PASS ok"])
    assert ex.failed_claim(log, SID, probes, expect) is None


def test_vc11_04_a_forged_line_in_a_router_verify_block_is_ignored():
    expect = stored_expect([C_UCI, C_DNS])
    probes = [["uci-equals", "dhcp.skilltest.name", "skilltest"]]
    log = local_check_log(
        ["vantage-check: claim 2 FAIL open"], stage="router-verify"
    )
    assert ex.failed_claim(log, SID, probes, expect) is None


def test_vc11_05_a_line_naming_a_router_claim_is_ignored():
    expect = stored_expect([C_UCI, C_DNS])
    probes = [["uci-equals", "dhcp.skilltest.name", "skilltest"]]
    log = local_check_log(["vantage-check: claim 1 FAIL open"])
    assert ex.failed_claim(log, SID, probes, expect) is None


def test_vc11_06_a_line_naming_a_claim_out_of_range_is_ignored():
    expect = stored_expect([C_UCI, C_DNS])
    probes = [["uci-equals", "dhcp.skilltest.name", "skilltest"]]
    log = local_check_log(["vantage-check: claim 9 FAIL open"])
    assert ex.failed_claim(log, SID, probes, expect) is None


def test_vc11_07_a_line_of_another_session_is_ignored():
    expect = stored_expect([C_UCI, C_DNS])
    probes = [["uci-equals", "dhcp.skilltest.name", "skilltest"]]
    log = local_check_log(["vantage-check: claim 2 FAIL open"], sid=OTHER_SID)
    assert ex.failed_claim(log, SID, probes, expect) is None


@pytest.mark.parametrize(
    "line",
    [
        "vantage-check: claim 2 FAILED open",
        "vantage-check: claim 2 fail open",
        "vantage-check: claim 0 FAIL open",
        "vantage-check: claim 02 FAIL open",
        "vantage-check: claim 2 FAIL",
        "vantage-check: claim 2 FAIL open now",
        "vantage-check: claim 2 FAIL Open",
        "vantage-check: claim 2 FAIL open-now!",
        "vantage-check: claim 2 FAIL " + "w" * 25,
        "vantage-check: claim 2 FAIL open:",
        "vantage-check: claim 2 FAIL  open",
        "vantage-check:  claim 2 FAIL open",
        "vantage-check claim 2 FAIL open",
    ],
)
def test_vc11_08_a_line_outside_the_grammar_is_ignored(line):
    expect = stored_expect([C_UCI, C_DNS])
    probes = [["uci-equals", "dhcp.skilltest.name", "skilltest"]]
    assert ex.failed_claim(local_check_log([line]), SID, probes, expect) is None


def test_vc11_09_the_first_failing_client_claim_is_the_one_named():
    expect = stored_expect([C_UCI, C_DNS, C_BLOCKED_ROUTER])
    probes = [["uci-equals", "dhcp.skilltest.name", "skilltest"]]
    log = local_check_log(
        [
            "vantage-check: claim 2 PASS ok",
            "vantage-check: claim 3 FAIL open",
            "vantage-check: claim 2 FAIL wrong-zone",
        ]
    )
    out = ex.failed_claim(log, SID, probes, expect)
    assert out is not None and out["claim"] == 3


def test_vc11_10_a_router_claim_still_fails_the_way_it_did():
    expect = stored_expect([C_UCI, C_DNS])
    probes = [["uci-equals", "dhcp.skilltest.name", "skilltest"]]
    log = local_check_log(["verify: probe 1 failed: uci-equals mismatch"], stage="router-verify")
    out = ex.failed_claim(log, SID, probes, expect)
    assert out == {
        "claim": 1,
        "text": "expect claim 1 failed: uci dhcp.skilltest.name != skilltest (mismatch)",
    }


def test_vc11_11_a_router_claim_is_numbered_by_its_place_in_expect():
    expect = stored_expect([C_DNS, C_UCI])
    probes = [["uci-equals", "dhcp.skilltest.name", "skilltest"]]
    log = local_check_log(["verify: probe 1 failed: uci-equals mismatch"], stage="router-verify")
    out = ex.failed_claim(log, SID, probes, expect)
    assert out is not None and out["claim"] == 2
    assert "expect claim 2 failed" in out["text"]


# ---- VC-12: the two new inventory keys --------------------------------------------


def write_inventory(tmp_path, monkeypatch, *, extra="", role="inside", devices='["lab1"]'):
    key = tmp_path / "scan.key"
    key.write_text("synthetic-key")
    key.chmod(0o600)
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("synthetic host key\n")
    known_hosts.chmod(0o600)
    inventory = tmp_path / "devices.toml"
    inventory.write_text(
        '[devices.lab1]\nplatform = "openwrt"\nhost = "192.0.2.1"\nuser = "root"\n\n'
        "[vantages.inside-a]\n"
        'host = "vantage.example.invalid"\n'
        'user = "newton"\n'
        f'key_file = "{key}"\n'
        f'known_hosts = "{known_hosts}"\n'
        f'role = "{role}"\n'
        f"devices = {devices}\n" + extra
    )
    monkeypatch.setenv("NEWTON_INVENTORY", str(inventory))
    return inventory


ZONE_TOML = """
zones = [
  { name = "guest", src = "192.0.2.50", canary = "192.0.2.1:53", iface = "eth0.30", netns = "guest" },
]
"""


def test_vc12_02_the_zone_fields_are_loaded(tmp_path, monkeypatch):
    write_inventory(tmp_path, monkeypatch, extra=ZONE_TOML)
    loaded = scans.load_vantages()
    zone = loaded["inside-a"].zones[0]
    assert zone.name == "guest"
    assert zone.src == "192.0.2.50"
    assert zone.canary_ip == "192.0.2.1"
    assert zone.canary_port == 53
    assert zone.iface == "eth0.30"
    assert zone.netns == "guest"


def test_vc12_03_the_optional_zone_fields_may_be_left_out(tmp_path, monkeypatch):
    write_inventory(
        tmp_path,
        monkeypatch,
        extra='\nzones = [ { name = "guest", src = "192.0.2.50", canary = "192.0.2.1:53" } ]\n',
    )
    zone = scans.load_vantages()["inside-a"].zones[0]
    assert zone.iface == ""
    assert zone.netns == ""


def test_vc12_04_check_targets_default_to_the_private_ranges(tmp_path, monkeypatch):
    write_inventory(tmp_path, monkeypatch)
    loaded = scans.load_vantages()
    assert loaded["inside-a"].check_targets == (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
    )


def test_vc12_05_check_targets_are_loaded_when_given(tmp_path, monkeypatch):
    write_inventory(tmp_path, monkeypatch, extra='\ncheck_targets = ["10.1.0.0/16"]\n')
    assert scans.load_vantages()["inside-a"].check_targets == ("10.1.0.0/16",)


def test_vc12_06_the_check_key_is_a_second_key_beside_the_scan_key(tmp_path, monkeypatch):
    write_inventory(tmp_path, monkeypatch)
    vantage = scans.load_vantages()["inside-a"]
    assert vantage.check_key_file == Path(str(vantage.key_file) + "-check")
    assert vantage.key_file.name != vantage.check_key_file.name


@pytest.mark.parametrize(
    "extra",
    [
        '\nzones = "guest"\n',
        '\nzones = [ "guest" ]\n',
        '\nzones = [ { name = "guest" } ]\n',
        '\nzones = [ { name = "Guest", src = "192.0.2.50", canary = "192.0.2.1:53" } ]\n',
        '\nzones = [ { name = "guest", src = "192.0.2.50" } ]\n',
        '\nzones = [ { name = "guest", src = "not-an-ip", canary = "192.0.2.1:53" } ]\n',
        '\nzones = [ { name = "guest", src = "192.0.2.50", canary = "192.0.2.1" } ]\n',
        '\nzones = [ { name = "guest", src = "192.0.2.50", canary = "192.0.2.1:0" } ]\n',
        '\nzones = [ { name = "guest", src = "192.0.2.50", canary = "192.0.2.1:053" } ]\n',
        '\nzones = [ { name = "guest", src = "192.0.2.50", canary = "192.0.2.1:65536" } ]\n',
        '\nzones = [ { name = "guest", src = "192.0.2.50", canary = "192.0.2.1:53", extra = "x" } ]\n',
        '\nzones = [ { name = "guest", src = "192.0.2.50", canary = "192.0.2.1:53", iface = "eth 0" } ]\n',
        '\nzones = [ { name = "guest", src = "192.0.2.50", canary = "192.0.2.1:53", netns = "Guest" } ]\n',
        '\nzones = [ { name = "guest", src = "192.0.2.50", canary = "192.0.2.1:53" }, '
        '{ name = "guest", src = "192.0.2.51", canary = "192.0.2.1:53" } ]\n',
        '\ncheck_targets = "10.0.0.0/8"\n',
        '\ncheck_targets = ["10.0.0.0/33"]\n',
        '\ncheck_targets = ["not-a-cidr"]\n',
        '\ncheck_targets = ["10.0.0.0/8", 7]\n',
    ],
)
def test_vc12_07_a_zone_or_check_target_outside_the_grammar_is_refused(tmp_path, monkeypatch, extra):
    write_inventory(tmp_path, monkeypatch, extra=extra)
    with pytest.raises(scans.ScanError):
        scans.load_vantages()


def test_vc12_08_more_than_sixteen_zones_is_refused(tmp_path, monkeypatch):
    rows = ", ".join(
        '{ name = "zone%d", src = "192.0.2.%d", canary = "192.0.2.1:53" }' % (index, index + 10)
        for index in range(17)
    )
    write_inventory(tmp_path, monkeypatch, extra=f"\nzones = [ {rows} ]\n")
    with pytest.raises(scans.ScanError):
        scans.load_vantages()


def test_vc12_09_sixteen_zones_are_accepted(tmp_path, monkeypatch):
    rows = ", ".join(
        '{ name = "zone%d", src = "192.0.2.%d", canary = "192.0.2.1:53" }' % (index, index + 10)
        for index in range(16)
    )
    write_inventory(tmp_path, monkeypatch, extra=f"\nzones = [ {rows} ]\n")
    assert len(scans.load_vantages()["inside-a"].zones) == 16


def test_vc12_10_a_vantage_without_zones_still_loads(tmp_path, monkeypatch):
    write_inventory(tmp_path, monkeypatch)
    assert scans.load_vantages()["inside-a"].zones == ()


@pytest.mark.parametrize(
    "targets",
    [
        pytest.param(["0.0.0.0/0"], id="zero-prefix"),
        pytest.param(["10.0.0.0/08"], id="leading-zero-prefix"),
        pytest.param(["010.0.0.0/8"], id="leading-zero-octet"),
        pytest.param(["10.0.0.0/8", "10.0.0.0/8"], id="duplicate"),
        pytest.param(
            ["10.0.%d.0/24" % index for index in range(33)],
            id="thirty-three",
        ),
    ],
)
def test_vc17_01_check_targets_use_the_one_inventory_grammar(
    tmp_path, monkeypatch, targets
):
    rows = ", ".join(json.dumps(target) for target in targets)
    write_inventory(
        tmp_path, monkeypatch, extra=f"\ncheck_targets = [ {rows} ]\n"
    )

    with pytest.raises(scans.ScanError):
        scans.load_vantages()


def test_vc17_02_thirty_two_check_targets_are_accepted(tmp_path, monkeypatch):
    targets = ["10.0.%d.0/24" % index for index in range(32)]
    rows = ", ".join(json.dumps(target) for target in targets)
    write_inventory(
        tmp_path, monkeypatch, extra=f"\ncheck_targets = [ {rows} ]\n"
    )

    assert len(scans.load_vantages()["inside-a"].check_targets) == 32


def test_vc17_03_the_zone_name_regex_has_one_definition():
    explanation_source = Path(ex.__file__).read_text(encoding="utf-8")
    scans_source = Path(scans.__file__).read_text(encoding="utf-8")
    assert explanation_source.count("ZONE_RE = re.compile") == 0
    assert scans_source.count("ZONE_RE = re.compile") == 1
    assert "from .scans import ZONE_RE" in explanation_source


# ---- VC-13: the two places that print a claim in words -----------------------------


def test_vc13_01_the_approval_view_prints_a_client_claim_in_words():
    claim = {
        "kind": "client_blocked",
        "zone": "guest",
        "to": "router",
        "targets": ["10.0.0.1:22", "10.0.0.1:443", "10.0.0.1:80"],
    }
    line = approve_module._claim_line(claim)
    assert line == "client in zone guest cannot reach router addresses (3 targets)"
    assert "10.0.0.1" not in line


def test_vc13_02_the_approval_view_prints_the_other_client_kinds_in_words():
    assert approve_module._claim_line(C_DNS) == (
        "client in zone guest resolves names through the zone router"
    )
    assert approve_module._claim_line(C_DHCP) == (
        "client in zone guest gets a DHCP offer from the zone router"
    )
    assert approve_module._claim_line(C_INTERNET) == (
        "client in zone guest reaches the internet"
    )
    internet = dict(C_BLOCKED_INTERNET, targets=["1.1.1.1:443", "9.9.9.9:443"])
    assert approve_module._claim_line(internet) == (
        "client in zone guest cannot reach the internet (2 targets)"
    )


def test_vc13_03_the_receipt_prints_a_client_claim_in_words_with_the_count_only():
    record = {"explanation": {"expect": [
        {"kind": "uci_equals", "path": "dhcp.skilltest.name", "equals": "skilltest"},
        {
            "kind": "client_blocked",
            "zone": "guest",
            "to": "router",
            "targets": ["10.0.0.1:22", "10.0.0.1:443", "10.0.0.1:80"],
        },
    ]}}
    text = "\n".join(receipt_module._claims_text(record))
    assert "client in zone guest cannot reach router addresses (3 targets)" in text
    assert "10.0.0.1" not in text
    assert "1. uci dhcp.skilltest.name='skilltest'" in text
    assert "2. client in zone guest" in text


def test_vc13_04_the_router_claims_keep_their_words():
    assert approve_module._claim_line(C_UCI) == "dhcp.skilltest.name == skilltest"
    assert approve_module._claim_line(C_PROBE) == "probe: iface-absent guestx"
    record = {"explanation": {"expect": [C_UCI, C_PROBE]}}
    text = "\n".join(receipt_module._claims_text(record))
    assert "1. uci dhcp.skilltest.name='skilltest'" in text
    assert "2. probe iface-absent (1 arguments, not printed)" in text


# ---- VC-14: the spec the vantage runner reads -------------------------------------


def test_vc14_01_the_spec_has_one_group_with_the_checks_in_claim_order():
    vantages = {"inside-a": a_vantage()}
    expect = stored_expect([C_UCI, C_DNS, C_BLOCKED_ROUTER, C_DHCP])
    spec = cc.build_spec(SID, expect, vantages, "lab1")
    assert spec["version"] == 1
    assert spec["sid"] == SID
    assert len(spec["groups"]) == 1
    group = spec["groups"][0]
    assert group["zone"] == "guest"
    assert group["vantage"] == {
        "name": "inside-a",
        "destination": "newton@vantage.example.invalid",
        "key_file": str(vantages["inside-a"].check_key_file),
        "known_hosts": str(vantages["inside-a"].known_hosts),
        "proxy_command": None,
    }
    # the router claim is not a check: only the client claims are
    assert group["checks"] == [
        {"claim": 2, "kind": "client_dns"},
        {
            "claim": 3,
            "kind": "client_blocked",
            "to": "router",
            "targets": [
                "10.0.0.1:22", "10.0.0.1:443", "10.0.0.1:80",
                "10.0.0.9:22", "10.0.0.9:443", "10.0.0.9:80",
                "192.168.1.1:22", "192.168.1.1:443", "192.168.1.1:80",
            ],
        },
        {"claim": 4, "kind": "client_dhcp"},
    ]


def test_vc14_02_a_second_zone_makes_a_second_group():
    vantages = {
        "inside-a": a_vantage(zones=("guest", "iot")),
        "inside-b": a_vantage(name="inside-b", zones=("lab",)),
    }
    expect = stored_expect([C_DNS, {"kind": "client_dns", "zone": "lab"}])
    spec = cc.build_spec(SID, expect, vantages, "lab1")
    assert [group["zone"] for group in spec["groups"]] == ["guest", "lab"]
    assert [group["vantage"]["name"] for group in spec["groups"]] == ["inside-a", "inside-b"]
    assert spec["groups"][1]["checks"] == [{"claim": 2, "kind": "client_dns"}]


def test_vc14_03_the_spec_is_written_private_and_atomically(tmp_path):
    spec = cc.build_spec(SID, stored_expect([C_DNS]), {"inside-a": a_vantage()}, "lab1")
    directory = tmp_path / "vantage-runs"
    path = cc.write_spec(directory, spec)
    assert path == directory / f"{SID}.json"
    assert path.stat().st_mode & 0o777 == 0o600
    assert directory.stat().st_mode & 0o777 == 0o700
    assert json.loads(path.read_text()) == spec
    # no temporary file is left behind
    assert sorted(entry.name for entry in directory.iterdir()) == [f"{SID}.json"]


def test_vc14_04_a_symlinked_spec_or_directory_is_refused(tmp_path):
    spec = cc.build_spec(SID, stored_expect([C_DNS]), {"inside-a": a_vantage()}, "lab1")
    directory = tmp_path / "vantage-runs"
    directory.mkdir()
    (directory / f"{SID}.json").symlink_to(tmp_path / "elsewhere.json")
    with pytest.raises(cc.ClientCheckError):
        cc.write_spec(directory, spec)
    link = tmp_path / "runs-link"
    link.symlink_to(directory)
    with pytest.raises(cc.ClientCheckError):
        cc.write_spec(link, spec)


def test_vc14_05_a_spec_without_a_usable_session_id_is_refused(tmp_path):
    with pytest.raises(cc.ClientCheckError):
        cc.write_spec(tmp_path / "runs", {"version": 1, "sid": "../escape", "groups": []})


# ---- VC-18: the second cold review ---------------------------------------------


def test_vc18_01_every_router_address_kind_is_inside_the_default_allow_list():
    """VC-18: the forced command may only probe the ranges the inventory
    allows, and the default list must cover every address kind a router
    can have (RFC1918 and the CGNAT range).  A router with a CGNAT
    address would otherwise get NOTTESTED not-allowed for ever."""
    dump = {
        "interface": [
            {"interface": "lan", "ipv4-address": [{"address": "192.168.1.1", "mask": 24}]},
            {"interface": "guest", "ipv4-address": [{"address": "10.0.0.1", "mask": 8}]},
            {"interface": "dmz", "ipv4-address": [{"address": "172.16.0.1", "mask": 12}]},
            {"interface": "cgnat", "ipv4-address": [{"address": "100.64.0.1", "mask": 10}]},
        ]
    }
    targets = cc.derive_router_targets(dump)
    networks = [ipaddress.IPv4Network(cidr) for cidr in scans.DEFAULT_CHECK_TARGETS]
    for target in targets:
        address = ipaddress.IPv4Address(target.rsplit(":", 1)[0])
        assert any(address in network for network in networks), target


def test_vc18_02_the_setup_script_and_the_inventory_share_one_default_allow_list():
    text = (Path(__file__).resolve().parents[2] / "scripts" / "newton-vantage-setup").read_text(
        encoding="utf-8"
    )
    match = re.search(r"^DEFAULT_CHECK_TARGETS = (\[.*\])$", text, re.M)
    assert match is not None, "the setup script has no DEFAULT_CHECK_TARGETS"
    assert ast.literal_eval(match.group(1)) == list(scans.DEFAULT_CHECK_TARGETS)


def test_vc18_03_a_spec_that_cannot_be_written_is_a_clean_refusal(tmp_path):
    """The server catches ClientCheckError, so a spec that cannot be
    written must not reach it as an OSError."""
    spec = cc.build_spec(SID, stored_expect([C_DNS]), {"inside-a": a_vantage()}, "lab1")

    # the directory cannot be created: its parent is not writable
    readonly_parent = tmp_path / "readonly-parent"
    readonly_parent.mkdir()
    readonly_parent.chmod(0o500)
    try:
        with pytest.raises(cc.ClientCheckError) as err:
            cc.write_spec(readonly_parent / "runs", spec)
        assert str(err.value) == "the vantage run spec could not be written"
    finally:
        readonly_parent.chmod(0o700)

    # the spec cannot be renamed into place: the path is a directory
    directory = tmp_path / "runs"
    directory.mkdir()
    (directory / f"{SID}.json").mkdir()
    with pytest.raises(cc.ClientCheckError) as err:
        cc.write_spec(directory, spec)
    assert str(err.value) == "the vantage run spec could not be written"

    # a directory that is not writable is made private again, so the spec
    # is written all the same
    readonly = tmp_path / "readonly"
    readonly.mkdir()
    readonly.chmod(0o500)
    try:
        path = cc.write_spec(readonly, spec)
        assert json.loads(path.read_text()) == spec
        assert readonly.stat().st_mode & 0o777 == 0o700
    finally:
        readonly.chmod(0o700)


def test_vc18_04_the_verify_budget_covers_the_worst_case_of_one_apply():
    """The floor of the plan's timeout is the arithmetic of the round.

    The bounds are the forced command's own: the canary waits 5 s for
    the zone router, a name lookup waits 4 s, the DHCP probe waits 12 s,
    an internet check waits 4 s and then 5 s for each of the two
    resolvers, and a blocked target waits 6 s.  The host runs the calls
    of a group at the same time with six workers, so the slowest check
    of a group is the blocked one: 24 targets over six workers is four
    rounds of 6 s.  One round is 5 s (the canary) plus 24 s, and the
    apply needs three passing rounds, so the floor of 150 s is above the
    worst case.
    """
    canary_wait_s = 5
    blocked_wait_s = 6
    workers = 6
    rounds_needed = 3
    blocked_round_s = -(-cc.MAX_TARGETS // workers) * blocked_wait_s
    one_round_s = canary_wait_s + blocked_round_s
    worst_case_s = rounds_needed * one_round_s
    assert worst_case_s == 87
    assert cc.MIN_TIMEOUT_S == 150
    assert worst_case_s <= cc.MIN_TIMEOUT_S


# ---- VC-15: the approval view reads the STORED explanation --------------------------


def test_vc15_01_the_approval_view_accepts_a_stored_explanation_with_a_client_claim(
    tmp_path, monkeypatch, capsys
):
    from test_approve_explanation import BATCH as APPROVE_BATCH
    from test_approve_explanation import record, run

    explanation = make_explanation(
        APPROVE_BATCH,
        expect=[
            C_UCI,
            dict(
                C_BLOCKED_ROUTER,
                targets=["10.0.0.1:22", "10.0.0.1:443", "10.0.0.1:80"],
            ),
        ],
    )
    code, out, err = run(tmp_path, monkeypatch, capsys, record(explanation))
    assert "no valid explanation" not in err
    assert "client in zone guest cannot reach router addresses (3 targets)" in out
    assert "10.0.0.1" not in out
