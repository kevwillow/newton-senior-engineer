"""Design 2.1, 2.2, 5.2, 5.3: zones-file parsing, profile selection, the sealed
`leash` file in the txn dir, robustness on large change sets, and determinism.

Each test calls `router.sealed_scenario(scn)` after `router.use_leash_uci()`, then
inspects stdout and the txn-dir files. The `raw()` helper produces the same shape
of object that `leash_model.Scenario.build()` returns, so the leash uci fake can
serve it (design 5.2: the program asks for staged and committed views of every
touched (config, section) pair). The `lines_of()` helper filters stdout by prefix.
"""
import json
import os
import re
import time
from types import SimpleNamespace

import pytest

from conftest import SID
from leash_corpus import SCENARIOS, SCENARIO_IDS, base_config
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


def _scenario_by_name(name):
    return SCENARIOS[SCENARIO_IDS.index(name)]


def _reseal_after_zone_change(router, scn):
    """Run `sealed_scenario` once to build a real txn dir, then delete the zones
    file (or rewrite it) and re-seal so the program's zones-file read happens on
    the freshly written file."""
    seal(router, scn)
    txn = router.txn()
    txdir = txn.parent
    for name in ("sealed", "t", "base", "diff", "probes", "probes-sha",
                 "profile", "leash", "digest"):
        p = txn / name
        if p.exists():
            p.unlink()
    zones_path = router.root / "etc/newton/zones"
    if zones_path.exists():
        zones_path.unlink()
    return router.seal(SID, 90)


def _zview(zones):
    """Compose the text content of etc/newton/zones from a dict."""
    lines = [f"mgmt-interface {zones['mgmt-interface']}\n",
             f"mgmt-zone {zones['mgmt-zone']}\n"]
    lines.extend(f"wan-zone {w}\n" for w in zones["wan-zone"])
    return "".join(lines)


# ============================================================================
# Test 1: zones file (design 2.1)
# ============================================================================

def test_zones_mgmt_interface_name_drives_mgmt_interface_code(router):
    """Custom mgmt-interface in /etc/newton/zones moves the `mgmt-interface`
    code onto the named interface: changing `guest` (the new mgmt interface)
    fires `mgmt-interface`."""
    scn = Scenario(base_config(), [
        ("set", "network", "guest", "ipaddr", "192.168.7.1"),
    ], zones={"mgmt-interface": "guest", "mgmt-zone": "lan", "wan-zone": ["wan"]})
    res = seal(router, scn)
    assert (res.rc, res.err) == (0, "")
    codes = {l.split()[1] for l in lines_of(res, "leash ")}
    assert "mgmt-interface" in codes, codes


def test_zones_mgmt_interface_loses_code_when_not_lan(router):
    """When mgmt-interface is `guest`, changing `lan`'s ipaddr does NOT fire
    `mgmt-interface` (the design names `guest`, not `lan`, as the mgmt iface)."""
    scn = Scenario(base_config(), [
        ("set", "network", "lan", "ipaddr", "192.168.9.1"),
    ], zones={"mgmt-interface": "guest", "mgmt-zone": "lan", "wan-zone": ["wan"]})
    res = seal(router, scn)
    assert (res.rc, res.err) == (0, "")
    codes = {l.split()[1] for l in lines_of(res, "leash ")}
    assert "mgmt-interface" not in codes, codes


def test_zones_mgmt_zone_name_drives_mgmt_zone_code(router):
    """Custom mgmt-zone moves `mgmt-zone` to the zone named after the mgmt zone
    value; a change to the (now ordinary) lan zone does NOT fire `mgmt-zone`."""
    scn = Scenario(base_config(), [
        ("set", "firewall", "@zone[0]", "masq", "1"),
    ], zones={"mgmt-interface": "lan", "mgmt-zone": "mgmt2", "wan-zone": ["wan"]})
    res = seal(router, scn)
    assert (res.rc, res.err) == (0, "")
    codes = {l.split()[1] for l in lines_of(res, "leash ")}
    assert "mgmt-zone" in codes, codes


def test_zones_four_wan_zone_lines_all_count(router):
    """All four wan-zone lines count: changing a zone whose real name appears
    in the wan-zone list (the 4th entry, `mgmt2`) fires `wan-zone`."""
    zones = {"mgmt-interface": "lan", "mgmt-zone": "lan",
             "wan-zone": ["wan", "wan6", "guest", "mgmt2"]}
    scn = Scenario(base_config(), [
        ("set", "firewall", "@zone[4]", "input", "ACCEPT"),
    ], zones=zones)
    res = seal(router, scn)
    assert (res.rc, res.err) == (0, "")
    codes = {l.split()[1] for l in lines_of(res, "leash ")}
    assert "wan-zone" in codes, codes


def test_zones_fifth_wan_zone_line_is_ignored(router):
    """A fifth wan-zone line is silently dropped (design 2.1: up to 4)."""
    zones = {"mgmt-interface": "lan", "mgmt-zone": "lan",
             "wan-zone": ["wan", "wan6", "guest", "mgmt2", "lan"]}
    scn = Scenario(base_config(), [
        ("set", "firewall", "@zone[0]", "masq", "1"),
    ], zones=zones)
    res = seal(router, scn)
    assert (res.rc, res.err) == (0, "")
    codes = {l.split()[1] for l in lines_of(res, "leash ")}
    assert "mgmt-zone" in codes, codes


@pytest.mark.parametrize("bad_name", ["", "has space", "semi;colon", "x" * 33])
def test_zones_bad_name_line_is_ignored(router, bad_name):
    """A line with empty, spaced, `;`-bearing or 33-character name is ignored:
    the defaults `lan/lan/wan` remain in effect."""
    path = router.root / "etc/newton/zones"
    base = "mgmt-interface lan\nmgmt-zone lan\nwan-zone wan\n"
    if bad_name == "":
        content = base + "wan-zone \n"
    else:
        content = base + f"wan-zone {bad_name}\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    scn = Scenario(base_config(), [
        ("set", "firewall", "@zone[0]", "masq", "1"),
    ])
    res = seal(router, scn)
    assert (res.rc, res.err) == (0, "")
    codes = {l.split()[1] for l in lines_of(res, "leash ")}
    assert "mgmt-zone" in codes, codes


def test_zones_missing_file_means_defaults(router):
    """A missing zones file falls back to mgmt-interface=lan, mgmt-zone=lan,
    wan-zone=wan; the lan-zone masq change fires `mgmt-zone`."""
    _, ops, expect, _, zones = _scenario_by_name("lan zone masq")
    scn = Scenario(base_config(), ops, zones=zones or None)
    res = _reseal_after_zone_change(router, scn)
    assert (res.rc, res.err) == (0, "")
    codes = {l.split()[1] for l in lines_of(res, "leash ")}
    assert "mgmt-zone" in codes, codes


# ============================================================================
# Test 2: the profile file (design 2.1 line 93)
# ============================================================================

def test_profile_prod_empty_change_set_fires_profile_prod(router):
    """Empty change set, profile prod: `leash profile-prod -` and approval required."""
    res = seal(router, raw([], profile="prod"))
    assert (res.rc, res.err) == (0, "")
    leash = lines_of(res, "leash ")
    assert leash == ["leash profile-prod -"], leash
    assert lines_of(res, "approval ") == ["approval required"]


def test_profile_lab_empty_change_set_fires_no_leash_line(router):
    """Empty change set, profile lab: no leash line and approval not-required."""
    res = seal(router, raw([], profile="lab"))
    assert (res.rc, res.err) == (0, "")
    assert lines_of(res, "leash ") == []
    assert lines_of(res, "approval ") == ["approval not-required"]


def test_profile_missing_file_means_prod(router):
    """Missing /etc/newton/profile falls back to prod; an empty change set under
    prod still fires `profile-prod` and requires approval."""
    scn = raw([], profile="prod")
    seal(router, scn)
    txn = router.txn()
    for name in ("sealed", "t", "base", "diff", "probes", "probes-sha",
                 "profile", "leash", "digest"):
        p = txn / name
        if p.exists():
            p.unlink()
    profile_path = router.root / "etc/newton/profile"
    if profile_path.exists():
        profile_path.unlink()
    res = router.seal(SID, 90)
    assert (res.rc, res.err) == (0, "")
    assert lines_of(res, "leash ") == ["leash profile-prod -"]
    assert lines_of(res, "approval ") == ["approval required"]


def test_profile_junk_content_means_prod(router):
    """Anything other than `lab` or `prod` in /etc/newton/profile fails closed to prod."""
    profile_path = router.root / "etc/newton/profile"
    profile_path.write_text("whatever-this-is\n")
    res = seal(router, raw([], profile="prod"))
    assert (res.rc, res.err) == (0, "")
    assert lines_of(res, "leash ") == ["leash profile-prod -"]
    assert lines_of(res, "approval ") == ["approval required"]


# ============================================================================
# Test 3: the sealed `leash` and `profile` txn files (design 2.2)
# ============================================================================

def _collect_scn_lines(res):
    """All `section ` and `leash ` lines of stdout, in order."""
    return [l for l in res.out.splitlines()
            if l.startswith("section ") or l.startswith("leash ")]


def test_txn_leash_file_holds_stdout_leash_lines_after_two_codes(router):
    """After a seal that fires two leash codes, `<SID>.txn/leash` is exactly the
    block between `profile <p>` and `approval`/`digest` on stdout (section lines
    first, then leash lines, each on its own line)."""
    scn = Scenario(base_config(), [
        ("set", "dropbear", "@dropbear[0]", "Port", "2222"),
        ("set", "firewall", "@zone[0]", "masq", "1"),
    ])
    res = seal(router, scn)
    assert (res.rc, res.err) == (0, "")
    lines = res.out.splitlines()
    block = lines[5:-2]
    txn_leash = (router.txn() / "leash").read_text().splitlines()
    assert txn_leash == block, (txn_leash, block)
    leash_only = [l for l in block if l.startswith("leash ")]
    assert len(leash_only) == 2, leash_only


def test_txn_leash_file_is_empty_when_no_codes(router):
    """An empty change set under lab writes an empty leash file (no touched
    sections, no codes fired)."""
    res = seal(router, raw([], profile="lab"))
    assert (res.rc, res.err) == (0, "")
    txn_leash = (router.txn() / "leash").read_text()
    assert txn_leash == "", repr(txn_leash)


def test_txn_profile_file_holds_the_profile_word(router):
    """`<SID>.txn/profile` is the resolved profile word (design 2.2), one word per line."""
    res = seal(router, raw([], profile="lab"))
    assert (res.rc, res.err) == (0, "")
    assert (router.txn() / "profile").read_text() == "lab\n"
    res = seal(router, raw([], profile="prod"))
    assert (res.rc, res.err) == (0, "")
    assert (router.txn() / "profile").read_text() == "prod\n"


# ============================================================================
# Test 4: robustness under large change sets
# ============================================================================

def _set_n_ops(n):
    """Build n small `set` ops, each on a different (cfg, sec) of base_config()."""
    ops = []
    base = base_config()
    for cfg, secs in base.items():
        for i, s in enumerate(secs):
            if not s.name:
                ref = f"@{s.type}[{i}]"
            else:
                ref = s.name
            for opt in s.opts:
                ops.append(("set", cfg, ref, opt, s.opts[opt]))
                if len(ops) >= n:
                    return ops
    return ops


def test_robustness_forty_touched_sections_in_under_twenty_seconds(router):
    """A 40-touch seal exits 0 in under 20s (no quadratic blow-up).

    40 change lines spread across four different sections; each line names a
    distinct change to a fresh token so the parser sees a realistic-sized input."""
    changes = []
    for i in range(10):
        changes.append(f"dropbear.@dropbear[0].PasswordAuth='on'")
        changes.append(f"uhttpd.main.listen_http='0.0.0.0:{8000 + i}'")
        changes.append(f"dhcp.lan.start='{100 + i}'")
        changes.append(f"system.@system[0].zonename='utc{i}'")
    assert len(changes) == 40
    t0 = time.monotonic()
    res = seal(router, raw(changes))
    elapsed = time.monotonic() - t0
    assert res.rc == 0, (res.rc, res.err)
    assert elapsed < 20.0, f"seal took {elapsed:.2f}s"
    codes = {l.split()[1] for l in lines_of(res, "leash ")}
    assert "mgmt-config" in codes, codes


def test_robustness_two_hundred_raw_change_lines_does_not_crash(router):
    """200 raw change lines exit 0 (any code set; the parser survives)."""
    changes = [
        f"dropbear.@dropbear[0].Port='{2200 + (i % 10)}'"
        for i in range(200)
    ]
    res = seal(router, raw(changes))
    assert res.rc == 0, (res.rc, res.err)
    assert lines_of(res, "approval ") == ["approval required"]


# ============================================================================
# Test 5: determinism (same scenario, fresh txn dir, identical block)
# ============================================================================

def _reseal_clean(router, scn):
    """Re-seal a fresh transaction for the same scenario, keeping the zones and
    profile files unchanged but emptying the txn dir of seal-written files."""
    seal(router, scn)
    txn = router.txn()
    for name in ("sealed", "t", "base", "diff", "probes", "probes-sha",
                 "profile", "leash", "digest"):
        p = txn / name
        if p.exists():
            p.unlink()
    return router.seal(SID, 90)


def test_determinism_section_and_leash_lines_identical_on_replay(router):
    """The same scenario sealed twice (fresh transaction each time) prints
    identical `section` and `leash` lines (same code set, same ordering)."""
    scn = Scenario(base_config(), [
        ("set", "dropbear", "@dropbear[0]", "Port", "2222"),
        ("set", "firewall", "@zone[0]", "masq", "1"),
    ])
    first = seal(router, scn)
    second = _reseal_clean(router, scn)
    assert (first.rc, second.rc) == (0, 0)
    first_block = _collect_scn_lines(first)
    second_block = _collect_scn_lines(second)
    assert first_block == second_block, (first_block, second_block)
