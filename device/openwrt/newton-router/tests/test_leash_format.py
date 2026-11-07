"""Design 3.5b step 9 + 5.2: seal stdout ordering and format, router-derived
field sanitisation, fail-safe `section-unidentified` lookups, and secret
suppression. These tests build by hand (the `raw()` helper) rather than via
`leash_model.Scenario` so they can test the program's behavior on inputs a
clean scenario cannot produce.
"""
import json
import re
from types import SimpleNamespace

import pytest

from leash_corpus import base_config
from leash_model import Scenario, Sec

FIELD_RE = re.compile(r"^[A-Za-z0-9_.@:\[\]-]*$")


def raw(changes, staged=None, committed=None, full_firewall=None, profile="lab", zones=None):
    """A hand-built uci answer set in place of a Scenario: router.sealed_scenario(raw([...])) runs seal on it."""
    z = {"mgmt-interface": "lan", "mgmt-zone": "lan", "wan-zone": ["wan"]}
    z.update(zones or {})
    built = dict(changes=changes, staged=staged or {}, committed=committed or {}, full_firewall=full_firewall or [])
    return SimpleNamespace(profile=profile, zones=z, build=lambda: built)


def seal(router, scn):
    router.use_leash_uci()
    return router.sealed_scenario(scn)


def lines_of(res, prefix):
    return [l for l in res.out.splitlines() if l.startswith(prefix)]


def test_output_order_and_format(router):
    scn = Scenario(base_config(), [
        ("set", "dropbear", "@dropbear[0]", "Port", "2222"),
        ("newsec", "firewall", Sec("zone", None, name="iot",
            input="REJECT", output="ACCEPT", forward="REJECT"), "iotzone"),
    ])
    res = seal(router, scn)
    assert (res.rc, res.err) == (0, "")
    lines = res.out.splitlines()
    prefixes = [l.split()[0] for l in lines if l.strip()]
    # the first five: base, diff, probes, t, profile, all in that order
    assert prefixes[:5] == ["base", "diff", "probes", "t", "profile"], prefixes
    # the last two: approval then digest
    assert prefixes[-2:] == ["approval", "digest"], prefixes
    # section <cfg> <section> <type|-> <name|->  in order of first appearance
    # dropbear is touched first (set), firewall.iotzone is touched second
    section_lines = [l[len("section "):] for l in lines if l.startswith("section ")]
    # dropbear has no `name` option: name -> `-` per router_field rule
    assert section_lines == [
        "dropbear @dropbear[0] dropbear -",
        "firewall iotzone zone iot",
    ], section_lines
    # every leash <code> <where>
    leash_lines = [l[len("leash "):] for l in lines if l.startswith("leash ")]
    assert leash_lines, "no leash lines"
    # each leash <where> matches <cfg>.<section>[.<option>]
    where_re = re.compile(r"^[A-Za-z0-9_.@:\[\]-]+(\.[A-Za-z0-9_]+)?$")
    for entry in leash_lines:
        _, where = entry.split(" ", 1)
        assert where_re.match(where), where
    # no duplicate leash line (program dedup on code+where)
    assert len(leash_lines) == len(set(leash_lines)), leash_lines
    # approval required (lab profile with at least one code)
    assert lines[-2] == "approval required"
    # digest is exactly 64 hex
    digest = lines[-1].split()[1]
    assert re.fullmatch(r"[0-9a-f]{64}", digest), digest


@pytest.mark.parametrize("bad", [
    "not a uci line",
    "firewall",
    "x.y.z.w=1",
])
def test_unparsed_change_lines_fire_unparsed_change(router, bad):
    res = seal(router, raw([bad]))
    assert (res.rc, res.err) == (0, "")
    lines = res.out.splitlines()
    # at least one `leash unparsed-change <where>` line where the field is cleaned
    parsed = [l for l in lines if l.startswith("leash unparsed-change ")]
    assert parsed, f"expected leash unparsed-change for {bad!r}"
    # the where is the cleaned raw line (router_field rule: bad bytes -> _, max 64)
    where = parsed[0].split(" ", 2)[2]
    assert len(where) <= 64
    assert FIELD_RE.fullmatch(where), where
    # approval required because at least one code fired
    assert [l for l in lines if l.startswith("approval ")] == ["approval required"]


@pytest.mark.parametrize("name", ["weird'quote", "with space", "semi;colon", "ctl\x01byte", "no\xe4scii", "x" * 100])
def test_router_fields_are_sanitised(router, name):
    # an option whose option-name is the bad string
    changes = ["dropbear.@dropbear[0]." + name + "='1'"]
    res = seal(router, raw(changes))
    assert (res.rc, res.err) == (0, "")
    seen_names = []
    for l in res.out.splitlines():
        if l.startswith("section ") or l.startswith("leash "):
            for field in l.split()[1:]:
                if field == name:
                    pytest.fail(f"unsanitised field in {l!r}")
                seen_names.append(field)
                assert FIELD_RE.fullmatch(field), field
                assert len(field) <= 64, field
    assert seen_names, "no section/leash lines"


def test_secret_value_never_appears(router):
    marker = "SECRETMARK9"
    # wireless section with `key` option
    wireless_staged = {"wireless.cfg0392bd": [
        "wireless.cfg0392bd=wifi-iface",
        "wireless.cfg0392bd.device='radio0'",
        f"wireless.cfg0392bd.key='{marker}'",
    ]}
    # rpcd section with `password`
    rpcd_staged = {"rpcd.cfg0392bd": [
        "rpcd.cfg0392bd=login",
        "rpcd.cfg0392bd.username='root'",
        f"rpcd.cfg0392bd.password='{marker}'",
    ]}
    changes = [
        f"wireless.cfg0392bd.key='{marker}'",
        f"rpcd.cfg0392bd.password='{marker}'",
    ]
    scn = raw(changes, staged=wireless_staged | rpcd_staged, committed={}, full_firewall=[])
    res = seal(router, scn)
    assert (res.rc, res.err) == (0, "")
    assert marker not in res.out, f"marker leaked to stdout: {res.out!r}"
    assert marker not in res.err, f"marker leaked to stderr: {res.err!r}"


def test_fail_safe_section_unidentified_empty_views(router):
    changes = [
        "firewall.cfg0392bd.input='ACCEPT'",
        "network.cfg0392bd.proto='dhcp'",
    ]
    res = seal(router, raw(changes, staged={}, committed={}, full_firewall=[]))
    assert (res.rc, res.err) == (0, "")
    lines = res.out.splitlines()
    # both: section-unidentified (both firewall and network)
    sec = [l for l in lines if l.startswith("leash section-unidentified ")]
    where = sorted(l.rsplit(" ", 1)[-1] for l in sec)
    # where is cleaned (`-` when empty) -> two distinct where strings
    assert len(where) == 2, where
    # approval required
    assert [l for l in lines if l.startswith("approval ")] == ["approval required"]


def test_fail_safe_no_type_line(router):
    # firewall.cfg0392bd has view lines, but none starts with `firewall.cfg0392bd=...` (no type)
    views = {"firewall.cfg0392bd": ["firewall.cfg0392bd.input='ACCEPT'"]}
    changes = ["firewall.cfg0392bd.input='ACCEPT'"]
    res = seal(router, raw(changes, staged={}, committed=views, full_firewall=[]))
    assert (res.rc, res.err) == (0, "")
    assert any(l.startswith("leash section-unidentified ") for l in res.out.splitlines())


def test_fail_safe_zone_no_name(router):
    # a firewall zone without any non-empty `name` option: section-unidentified
    # so that it cannot escape the zone name test
    view = {"firewall.cfg0392bd": [
        "firewall.cfg0392bd=zone",
        "firewall.cfg0392bd.network='nameless'",
        "firewall.cfg0392bd.input='ACCEPT'",
        "firewall.cfg0392bd.output='ACCEPT'",
        "firewall.cfg0392bd.forward='REJECT'",
    ]}
    changes = ["firewall.cfg0392bd.input='ACCEPT'"]
    res = seal(router, raw(changes, staged={}, committed=view, full_firewall=[]))
    assert (res.rc, res.err) == (0, "")
    assert any(l.startswith("leash section-unidentified ") for l in res.out.splitlines())


def test_fail_safe_anonymous_network_section(router):
    # network @type[N] where the real name cannot be learned (views lack the type line)
    # also fires section-unidentified
    changes = ["network.@interface[3].proto='static'"]
    # staged + committed both empty -> type can't be learned
    res = seal(router, raw(changes, staged={}, committed={}, full_firewall=[]))
    assert (res.rc, res.err) == (0, "")
    lines = res.out.splitlines()
    assert any(l.startswith("leash section-unidentified ") for l in lines), lines
