"""Getter data files, grammar checks, and slot filling."""

from __future__ import annotations

import json
import random
import re
from dataclasses import FrozenInstanceError
from pathlib import Path
from types import MappingProxyType
from typing import Any

import pytest

from newton_mcp.adapters import registry
from newton_mcp.adapters import getters
from newton_mcp.adapters.getters import (
    DENY_TOKENS,
    GETTER_IDS,
    SHARED_ERROR_MARKERS,
    Getter,
    GetterError,
    check_command,
    check_param_pattern,
    enabled_getters,
    fill_command,
    load_getters,
)


ADAPTERS = Path(__file__).parents[1] / "newton_mcp" / "adapters"
BACKSTOP = re.compile(r"^[A-Za-z0-9][A-Za-z0-9/._:-]{0,63}$")
GOOD_PARAM = r"^[A-Za-z0-9][A-Za-z0-9/._:]{0,63}$"


def _value(value: Any) -> str:
    """Render a small JSON-compatible test value as TOML."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return json.dumps(value)
    if isinstance(value, list):
        return "[" + ", ".join(_value(item) for item in value) + "]"
    if isinstance(value, dict):
        return "{" + ", ".join(
            json.dumps(str(key)) + " = " + _value(item)
            for key, item in value.items()
        ) + "}"
    raise TypeError(f"unsupported test TOML value: {type(value).__name__}")


def write_getters(
    path: Path,
    platform: str,
    rows: list[dict[str, Any]],
    *,
    top_level: str | None = None,
) -> Path:
    """Write a synthetic getter file without using production loading code."""
    lines = [f"platform = {json.dumps(platform)}" if top_level is None else top_level]
    for row in rows:
        lines.append("")
        lines.append("[[getter]]")
        lines.extend(f"{key} = {_value(value)}" for key, value in row.items())
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def base_row(**changes: Any) -> dict[str, Any]:
    """Return a valid RouterOS row, overridden by ``changes``."""
    row: dict[str, Any] = {
        "id": "version",
        "command": "/system resource print",
        "enabled": True,
        "verified": "unverified",
        "why": "Synthetic test row.",
        "expect": ["Synthetic"],
    }
    row.update(changes)
    return row


def load_one(
    tmp_path: Path, row: dict[str, Any], platform: str = "routeros"
) -> dict[str, Getter]:
    """Load exactly one row from an isolated TOML file."""
    path = write_getters(tmp_path / "getters.toml", platform, [row])
    return load_getters(platform, path)


def test_mv1_4_01_valid_routeros_and_junos_files_load(tmp_path: Path) -> None:
    """Valid files load defaults in file order immutably."""
    routeros_path = write_getters(
        tmp_path / "routeros.toml",
        "routeros",
        [
            base_row(id="interfaces", command="/interface/print"),
            base_row(id="routes", command="/ip route print"),
        ],
    )
    routeros = load_getters("routeros", routeros_path)
    assert list(routeros) == ["interfaces", "routes"]
    getter = routeros["interfaces"]
    assert getter.params == {}
    assert getter.timeout_s == 15
    assert getter.max_bytes == 65536
    assert getter.secret_bearing is True
    assert [marker.pattern for marker in getter.error_markers] == list(
        SHARED_ERROR_MARKERS
    )
    assert getter.why == "Synthetic test row."
    assert getter.os_range == ""
    assert getter.source == ""
    assert getter.ledger == ""
    with pytest.raises(FrozenInstanceError):
        getter.enabled = False
    with pytest.raises(TypeError):
        getter.params["iface"] = "^x$"
    assert isinstance(getter.params, MappingProxyType)

    junos_path = write_getters(
        tmp_path / "junos.toml",
        "junos",
        [
            {
                "id": "interfaces",
                "command": "show interfaces {iface} | no-more",
                "params": {"iface": GOOD_PARAM},
                "enabled": True,
                "verified": "unverified",
                "why": "Synthetic test row.",
                "expect": ["Synthetic"],
            }
        ],
    )
    junos = load_getters("junos", junos_path)
    assert list(junos) == ["interfaces"]
    assert junos["interfaces"].params == MappingProxyType({"iface": GOOD_PARAM})


@pytest.mark.parametrize(
    "label,row",
    [
        ("rule-1-unknown-id", base_row(id="bogus")),
        ("rule-2-empty-command", base_row(command="")),
        ("rule-2-long-command", base_row(command="/system " + "a" * 193)),
        ("rule-2-non-ascii", base_row(command="/system résumé")),
        ("rule-2-leading-space", base_row(command=" /system resource print")),
        ("rule-2-trailing-space", base_row(command="/system resource print ")),
        ("rule-2-double-space", base_row(command="/system  resource print")),
        ("rule-2-control-character", base_row(command="/system\tresource print")),
        ("rule-3-enabled-int", base_row(enabled=1)),
        (
            "rule-3-secret-int",
            base_row(secret_bearing=1, verified="lab:fixture:routeros7:2026-10-01"),
        ),
        (
            "rule-3-secret-unverified",
            base_row(secret_bearing=False, verified="unverified"),
        ),
        (
            "rule-3-running-config",
            base_row(
                id="running_config",
                command="/export",
                secret_bearing=False,
                verified="lab:fixture:routeros7:2026-10-01",
            ),
        ),
        ("rule-4-timeout-zero", base_row(timeout_s=0)),
        ("rule-4-timeout-high", base_row(timeout_s=31)),
        ("rule-4-timeout-bool", base_row(timeout_s=True)),
        ("rule-4-bytes-low", base_row(max_bytes=1023)),
        ("rule-4-bytes-high", base_row(max_bytes=262145)),
        ("rule-4-bytes-bool", base_row(max_bytes=False)),
        ("rule-5-verified-shape", base_row(verified="guessing")),
        ("rule-5-verified-date", base_row(verified="lab:f:r:2026-13-01")),
        ("rule-6-os-range", base_row(os_range="routeros;7")),
        ("rule-6-source-http", base_row(source="http://example.test/x")),
        ("rule-6-source-space", base_row(source="https://example.test/a b")),
        ("rule-6-source-long", base_row(source="https://example.test/" + "a" * 300)),
        ("rule-6-ledger", base_row(ledger="lowercase")),
        ("rule-7-marker-type", base_row(error_markers=[1])),
        ("rule-7-marker-long", base_row(error_markers=["x" * 201])),
        ("rule-7-marker-compile", base_row(error_markers=["["])),
        ("rule-7-marker-count", base_row(error_markers=["x"] * 17)),
        ("rule-8-slot-missing", base_row(command="show {iface}", params={})),
        (
            "rule-8-slot-extra",
            base_row(params={"iface": GOOD_PARAM}),
        ),
        ("rule-8-slot-name", base_row(command="show {Iface}", params={"Iface": GOOD_PARAM})),
        ("rule-8-pattern-type", base_row(command="show {iface}", params={"iface": 1})),
        (
            "rule-8-pattern-broad",
            base_row(command="show {iface}", params={"iface": r"^.*$"}),
        ),
    ],
)
def test_mv1_4_02_every_row_rule_refuses(
    tmp_path: Path, label: str, row: dict[str, Any]
) -> None:
    """Each row rule 1-8 has a failing synthetic case."""
    platform = "junos" if "{" in row["command"] else "routeros"
    if platform == "junos":
        row.setdefault("command", "show interfaces {iface}")
    with pytest.raises(GetterError) as raised:
        load_one(tmp_path, row, platform)
    message = str(raised.value)
    assert platform in message
    assert "getter" in message
    assert label not in message


def test_mv1_4_03_structural_files_fail_closed(tmp_path: Path) -> None:
    """Top-level shape, duplicates, size, and paths are strict."""
    unknown_top = tmp_path / "unknown-top.toml"
    unknown_top.write_text(
        'platform = "routeros"\nextra = true\n[[getter]]\n'
        'id = "version"\ncommand = "/system resource print"\n'
        'enabled = true\nverified = "unverified"\n'
        'why = "x"\nexpect = ["^x"]\n',
        encoding="utf-8",
    )
    with pytest.raises(GetterError):
        load_getters("routeros", unknown_top)

    mismatch = write_getters(
        tmp_path / "mismatch.toml",
        "junos",
        [base_row(id="version", command="show version")],
        top_level='platform = "junos"',
    )
    mismatch.write_text(
        mismatch.read_text().replace('platform = "junos"', 'platform = "eos"')
    )
    with pytest.raises(GetterError) as raised:
        load_getters("junos", mismatch)
    assert "getter file platform does not match the requested platform" in str(
        raised.value
    )

    single = tmp_path / "single.toml"
    single.write_text(
        'platform = "routeros"\n[getter]\nid = "version"\n'
        'command = "/system resource print"\nenabled = true\n'
        'verified = "unverified"\nwhy = "x"\nexpect = ["^x"]\n',
        encoding="utf-8",
    )
    with pytest.raises(GetterError):
        load_getters("routeros", single)

    duplicate = write_getters(
        tmp_path / "duplicate.toml",
        "routeros",
        [base_row(), base_row(id="version", command="/export")],
    )
    with pytest.raises(GetterError):
        load_getters("routeros", duplicate)

    oversized = tmp_path / "oversized.toml"
    valid_prefix = (
        'platform = "routeros"\n[[getter]]\nid = "version"\n'
        'command = "/system resource print"\nenabled = true\n'
        'verified = "unverified"\nwhy = "x"\nexpect = ["^x"]\n#'
    ).encode("utf-8")
    oversized.write_bytes(valid_prefix + b"a" * (262145 - len(valid_prefix)))
    with pytest.raises(GetterError):
        load_getters("routeros", oversized)

    with pytest.raises(GetterError):
        load_getters("routeros", tmp_path / "missing.toml")


@pytest.mark.parametrize(
    "platform,command",
    [
        ("junos", "show version"),
        ("junos", "show route | display json | no-more"),
        ("eos", "show ip route | json"),
        ("iosxe", "show running-config"),
        ("vyos", "show interfaces"),
        ("fortios", "get system status"),
        ("routeros", "/system resource print"),
        ("routeros", "/ip/route/print detail"),
        ("routeros", "/ip firewall filter print terse without-paging"),
        ("routeros", "/export hide-sensitive"),
        ("routeros", "/ip firewall export terse"),
    ],
)
def test_mv1_4_04_positive_grammar_accepts(
    platform: str, command: str
) -> None:
    """Only documented positive read-only forms pass."""
    check_command(platform, command)


@pytest.mark.parametrize(
    "platform,command",
    [
        ("junos", "configure terminal"),
        ("junos", "show version | save x"),
        ("junos", "show route | display set"),
        ("junos", "show version | include x"),
        ("junos", "show version|no-more"),
        ("junos", "show version | no-more | no-more"),
        ("junos", "request system reboot"),
        ("junos", "show tech-support"),
        ("junos", "show monitor interface"),
        ("junos", "show log x;reboot"),
        ("junos", "show version > x"),
        ("junos", 'show "x"'),
        ("junos", "show $x"),
        ("junos", "show {Iface}"),
        ("junos", "show {iface} {iface}"),
        ("junos", "{iface} show"),
        ("eos", "show running-config | no-more"),
        ("iosxe", "copy running-config tftp:x"),
        ("iosxe", "show file=x"),
        ("fortios", "execute reboot"),
        ("fortios", "diagnose sys top"),
        ("fortios", "config system admin"),
        ("routeros", "/system reboot"),
        ("routeros", "/system/script/run"),
        ("routeros", "/export file=x"),
        ("routeros", "/export show-sensitive"),
        ("routeros", "/ip route print where x"),
        ("routeros", "/ip route print {x}"),
        ("routeros", "/print"),
        ("routeros", "/ip route print | json"),
        ("routeros", "/IP route print"),
        ("routeros", "system resource print"),
        ("openwrt", "show version"),
        ("acme", "show version"),
        ("junos", "show  version"),
        ("junos", "show version "),
        ("junos", "show\tversion"),
        ("junos", "show version\n"),
        ("junos", "/" + "a" * 200),
        ("junos", "/system résumé"),
    ],
)
def test_mv1_4_05_grammar_and_deny_list_refuse(
    platform: str, command: str
) -> None:
    """Malformed, non-read-only, and unknown platform commands fail."""
    with pytest.raises(GetterError) as raised:
        check_command(platform, command)
    assert platform in str(raised.value)


def test_mv1_4_06_deny_list_token_check_is_distinct() -> None:
    """A positive-grammar command can still fail a deny token."""
    with pytest.raises(GetterError) as raised:
        check_command("junos", "show monitor interface")
    assert "deny-list token" in str(raised.value)


@pytest.mark.parametrize(
    "pattern",
    [
        r"abc$",
        r"^abc",
        r"^[A-Za-z0-9-]+$",
        r"^abc\$",
        r"^.*$",
        r"^[A-Za-z0-9 ]{1,64}$",
        r"^[A-Za-z0-9]+$",
        r"^[A-Za-z0-9;]{1,64}$",
        r"^(?m)[A-Za-z0-9]{1,64}$",
        r"^[",
        "^" + "A" * 199 + "$",
    ],
)
def test_mv1_4_07_param_pattern_probes_refuse(pattern: str) -> None:
    """Broad, unsafe, invalid, or oversized patterns fail."""
    with pytest.raises(GetterError) as raised:
        check_param_pattern("junos", "interfaces", "iface", pattern)
    message = str(raised.value)
    assert "junos" in message
    assert "interfaces" in message
    assert "iface" in message


def test_mv1_4_08_design_example_param_pattern_passes() -> None:
    """The design's safe interface-name pattern is accepted."""
    check_param_pattern("junos", "interfaces", "iface", GOOD_PARAM)


def slot_getter(pattern: str = GOOD_PARAM) -> Getter:
    """Return a synthetic one-slot getter used by fill tests."""
    return Getter(
        id="interfaces",
        command="show interfaces {iface} | no-more",
        params=MappingProxyType({"iface": pattern}),
        timeout_s=15,
        max_bytes=65536,
        secret_bearing=True,
        enabled=True,
        error_markers=(),
        why="Synthetic test row.",
        expect=(),
        verified="unverified",
        os_range="",
        source="",
        ledger="",
    )


def test_mv1_4_09_fill_command_replaces_whole_slot_only() -> None:
    """Filling preserves every other token and pipe segment."""
    assert fill_command(slot_getter(), {"iface": "eth0"}) == (
        "show interfaces eth0 | no-more"
    )


@pytest.mark.parametrize(
    "params",
    [
        {},
        {"iface": "eth0", "extra": "x"},
        {"iface": 7},
        {"iface": ""},
        {"iface": "-"},
        {"iface": "-x"},
        {"iface": "-a1"},
        {"iface": "a;b"},
        {"iface": "a|b"},
        {"iface": "a&b"},
        {"iface": "a$b"},
        {"iface": "a\\b"},
        {"iface": "a>b"},
        {"iface": "a<b"},
        {"iface": "a(b"},
        {"iface": "a)b"},
        {"iface": "a*b"},
        {"iface": "a?b"},
        {"iface": "a`b"},
        {"iface": "a b"},
        {"iface": "a\nb"},
        {"iface": "a\rb"},
        {"iface": "a\tb"},
        {"iface": "a\n"},
        {"iface": "a{b"},
        {"iface": "a}b"},
        {"iface": "a'b"},
        {"iface": 'a"b'},
        {"iface": "a=b"},
        {"iface": "x" * 65},
        {"iface": "eth0 | save"},
        {"iface": "eth0;reboot"},
        {"iface": "{iface}"},
        {"iface": "eth0\n"},
        {"iface": "-eth0"},
        {"iface": "EVILVALUE;x"},
    ],
)
def test_mv1_4_10_fill_command_refuses_bad_values(params: dict[str, Any]) -> None:
    """Exact slot sets, pattern, and hard backstop are enforced."""
    with pytest.raises(GetterError) as raised:
        fill_command(slot_getter(), params)
    message = str(raised.value)
    rejected = params.get("iface")
    if isinstance(rejected, str) and len(rejected) >= 3:
        assert rejected not in message


def test_mv1_4_11_random_values_never_change_template_structure() -> None:
    """Random input either refuses or changes exactly one token."""
    alphabet = (
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        r"-_./:;|&$\><()*?" + "`" + " {}'=\"\n"
    )
    rng = random.Random(4)
    template = "show interfaces {iface} | no-more"
    for _ in range(2000):
        candidate = "".join(
            rng.choice(alphabet) for _ in range(rng.randrange(0, 71))
        )
        try:
            filled = fill_command(slot_getter(), {"iface": candidate})
        except GetterError:
            continue
        filled_tokens = filled.split(" ")
        template_tokens = template.split(" ")
        assert len(filled_tokens) == len(template_tokens)
        changed = [
            (old, new)
            for old, new in zip(template_tokens, filled_tokens)
            if old != new
        ]
        assert [old for old, _ in changed] == ["{iface}"]
        assert len(changed) == 1
        assert BACKSTOP.fullmatch(changed[0][1]) is not None


@pytest.mark.parametrize("platform", sorted(registry.PLATFORMS - {"openwrt"}))
def test_mv1_4_12_missing_default_files_serve_no_getters(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, platform: str
) -> None:
    """Even when a default file exists, an empty override directory forces an empty mapping."""
    monkeypatch.setattr(getters, "__file__", str(tmp_path / "getters.py"))
    assert load_getters(platform) == {}


def test_mv1_4_13_every_shipped_getters_file_loads_clean() -> None:
    """All future shipped per-vendor getter files are gated."""
    for path in sorted(ADAPTERS.glob("*/getters.toml")):
        assert isinstance(load_getters(path.parent.name, path), dict)


def test_mv1_4_14_platform_and_enabled_filters(tmp_path: Path) -> None:
    """OpenWrt is refused and disabled rows are omitted."""
    with pytest.raises(GetterError):
        load_getters("openwrt", tmp_path / "ignored.toml")
    path = write_getters(
        tmp_path / "routeros.toml",
        "routeros",
        [
            base_row(id="version", command="/system resource print"),
            base_row(
                id="routes",
                command="/ip route print",
                enabled=False,
            ),
        ],
    )
    assert list(enabled_getters("routeros", path)) == ["version"]


def test_mv1_4_15_source_has_no_template_or_shell_execution() -> None:
    """Hard rule 3 forbids format calls and shell execution."""
    source = (ADAPTERS / "getters.py").read_text(encoding="utf-8")
    assert ".format(" not in source
    assert "shell=True" not in source


# ---------------------------------------------------------------------------
# enforce the value backstop, the getter pattern, and the
# deny-list substring check with direct black-box probes against the unfilled
# checks that each of those three protections is responsible for.  The
# already exercised the union; these tests isolate each layer so that a later
# regression in any one layer becomes visible by itself.
# ---------------------------------------------------------------------------


def test_mv1_4_21_backstop_refuses_values_the_pattern_admits() -> None:
    """``fill_command`` enforces the hard value backstop alone.

    Construct a Getter whose parameter pattern ``r"(?s)^.*$"`` admits
    every raw probe here (including the trailing newline), so that the
    only check left in ``fill_command`` that can refuse them is the hard
    backstop ``_VALUE_BACKSTOP_RE``.  Without the backstop line, every
    bad probe slips through into the filled command, polluting the
    executed command.
    """
    getter = slot_getter(r"(?s)^.*$")
    accepted = fill_command(getter, {"iface": "ge-0/0/0"})
    assert accepted == "show interfaces ge-0/0/0 | no-more"
    for bad in ("a;b", "a b", "-x", "a|b", "x" * 65, "eth0\n"):
        with pytest.raises(GetterError) as raised:
            fill_command(getter, {"iface": bad})
        assert "hard backstop" in str(raised.value)


def test_mv1_4_22_pattern_refuses_values_the_backstop_admits() -> None:
    """``fill_command`` enforces the getter pattern alone.

    Use a tight pattern ``r"^eth[0-9]$"`` whose refused values all still
    satisfy the hard backstop, so only the getter-pattern fullmatch can
    refuse them.  Without the pattern line, both probes slip past the
    backstop and produce a malformed filled command.
    """
    getter = slot_getter(r"^eth[0-9]$")
    accepted = fill_command(getter, {"iface": "eth3"})
    assert accepted == "show interfaces eth3 | no-more"
    for bad in ("ge-0/0/0", "eth10"):
        with pytest.raises(GetterError) as raised:
            fill_command(getter, {"iface": bad})
        assert "getter pattern" in str(raised.value)


@pytest.mark.parametrize(
    "substring,platform,command",
    [
        # ``tftp:`` is reachable on junos because the head-token grammar
        # allows a colon inside a token (e.g. ``tftp:x``) and no DENY_TOKENS
        # entry shares the substring.
        ("tftp:", "junos", "show tftp:x"),
        ("scp:", "junos", "show scp:x"),
        ("ftp:", "junos", "show ftp:x"),
        ("http:", "junos", "show http:x"),
        ("https:", "junos", "show https:x"),
        # ``show-sensitive`` is reachable on junos because the token
        # ``show-sensitive`` is not in DENY_TOKENS (only ``tech-support``
        # is, by full token).  The head grammar forbids leading hyphens
        # but ``show-sensitive`` after the ``show`` head is fine.
        ("show-sensitive", "junos", "show show-sensitive"),
        # ``tech-support`` overlaps with a DENY_TOKEN of the same shape, so
        # pick a containing token that the positive grammar still admits
        # and that no DENY_TOKEN matches as a whole token.
        ("tech-support", "junos", "show tech-support-info"),
    ],
)
def test_mv1_4_23_deny_substring_refuses_per_substring(
    substring: str, platform: str, command: str
) -> None:
    """``check_command`` enforces every deny-list substring alone.

    Each probe passes the positive grammar, splits into tokens that share
    no entry with ``DENY_TOKENS``, and yet contains exactly one entry of
    ``DENY_SUBSTRINGS``.  Removing the substring loop must leave them all
    accepted, so the assertion below flips from refused to OK on mutation.
    """
    with pytest.raises(GetterError) as raised:
        check_command(platform, command)
    assert "deny-list substring" in str(raised.value)


def test_mv1_4_23_deny_substring_file_equals_is_unreachable_after_grammar() -> None:
    """``file=`` cannot reach the substring check on any platform.

    The literal substring ``file=`` contains ``=``, which is rejected by
    ``_HEAD_TOKEN_RE`` on every non-RouterOS platform and by
    ``_ROUTEROS_WORD_RE`` on RouterOS.  No grammar-valid command can ever
    contain ``file=``, so the deny-list substring test cannot exercise it;
    the protection is meaningful only as defence-in-depth and is noted
    here so a future grammar widening is forced to revisit the substring.
    """
    checked: list[tuple[str, str]] = []
    for head in (
        "show file=x",
        "show file=secret",
        "show a file=b",
        "get file=secret",
        "show x.file=y",
    ):
        for platform in sorted(registry.PLATFORMS - {"openwrt"}):
            with pytest.raises(GetterError) as raised:
                check_command(platform, head)
            checked.append((platform, head))
            assert "deny-list substring" not in str(raised.value)
    for platform in ("routeros",):
        for command in (
            "/file print file=x",
            "/system resource print file=secret",
        ):
            with pytest.raises(GetterError) as raised:
                check_command(platform, command)
            checked.append((platform, command))
            assert "deny-list substring" not in str(raised.value)
    assert checked


@pytest.mark.parametrize(
    "platform,command",
    [
        ("iosxe", "show tech"),
        ("iosxe", "show tech detail"),
        ("eos", "show tech"),
    ],
)
def test_mv1_4_24_show_tech_abbreviation_is_refused(
    platform: str, command: str
) -> None:
    """IOS and EOS cannot abbreviate ``show tech-support``."""
    with pytest.raises(GetterError) as raised:
        check_command(platform, command)
    assert "deny-list token" in str(raised.value)


@pytest.mark.parametrize(
    "value,rule",
    [
        ("tftp://x", "deny-list substring"),
        ("https://x", "deny-list substring"),
        ("tech-support", "deny-list token"),
        ("reboot", "deny-list token"),
    ],
)
def test_mv1_4_25_fill_command_runs_the_deny_list(value: str, rule: str) -> None:
    """Safe-looking slots cannot synthesize a denied command."""
    pattern = r"^[A-Za-z0-9][A-Za-z0-9/._:-]{0,63}$"
    getter = slot_getter(pattern)
    check_command("junos", getter.command)
    with pytest.raises(GetterError) as raised:
        fill_command(getter, {"iface": value})
    assert rule in str(raised.value)


def test_mv1_4_25_fill_command_accepts_a_safe_interface_name() -> None:
    """Deny-list filling leaves accepted values byte-identical."""
    pattern = r"^[A-Za-z0-9][A-Za-z0-9/._:-]{0,63}$"
    assert fill_command(slot_getter(pattern), {"iface": "ge-0/0/0"}) == (
        "show interfaces ge-0/0/0 | no-more"
    )


def test_mv1_4_26_loader_refuses_unknown_row_keys(tmp_path: Path) -> None:
    """A structurally valid row cannot smuggle unknown TOML keys."""
    with pytest.raises(GetterError) as raised:
        load_one(tmp_path, base_row(shell=True))
    assert "getter row contains an unknown key" in str(raised.value)


DESIGN_DENY_TOKENS = (
    "request clear execute diagnose configure debug copy save start bash run generate"
    " install write reload delete set commit monitor tech tech-support reboot shutdown"
).split()


@pytest.mark.parametrize("token", DESIGN_DENY_TOKENS)
def test_mv1_4_27_every_deny_token_is_reachable_after_junos_grammar(
    token: str,
) -> None:
    """Each current token is grammar-valid and independently denied.

    Every current token contains only letters and an optional hyphen, so
    ``show <token> x`` passes the Junos head-token grammar for all of them.
    """
    with pytest.raises(GetterError) as raised:
        check_command("junos", f"show {token} x")
    assert "deny-list token" in str(raised.value)


@pytest.mark.parametrize("token", ["request", "run"])
def test_mv1_4_27_required_deny_tokens_cannot_be_dropped(token: str) -> None:
    """Named design tokens stay present and reachable."""
    assert token in DENY_TOKENS
    with pytest.raises(GetterError) as raised:
        check_command("junos", f"show {token} x")
    assert "deny-list token" in str(raised.value)


def test_mv1_4_28_deny_token_matching_is_case_insensitive() -> None:
    """Mixed-case deny tokens cannot evade the token check."""
    with pytest.raises(GetterError) as raised:
        check_command("junos", "show MONITOR interface")
    assert "deny-list token" in str(raised.value)


@pytest.mark.parametrize(
    "pattern",
    [
        r"^[A-Za-z0-9-]{1,64}$",
        r"^-?[a-z]{1,8}$",
    ],
)
def test_mv1_4_29_param_patterns_cannot_admit_leading_dashes(pattern: str) -> None:
    """Otherwise-class-safe patterns still reject option-like values."""
    with pytest.raises(GetterError) as raised:
        check_param_pattern("junos", "interfaces", "iface", pattern)
    assert "parameter pattern admits an unsafe probe" in str(raised.value)


@pytest.mark.parametrize(
    "platform,command",
    [
        ("iosxe", "show tec"),
        ("iosxe", "show tech-s"),
        ("eos", "show tech-sup"),
        ("eos", "show TEC"),
    ],
)
def test_mv1_4_30_tech_support_prefixes_are_refused(
    platform: str, command: str
) -> None:
    """Unambiguous ``tech-support`` prefixes cannot get through."""
    with pytest.raises(GetterError) as raised:
        check_command(platform, command)
    assert "deny-list token" in str(raised.value)

    for positive in ("show interfaces", "show version"):
        check_command(platform, positive)


def test_mv1_4_31_fill_command_refuses_a_tech_support_prefix() -> None:
    """A filled slot cannot supply a ``tech-support`` prefix."""
    getter = slot_getter(r"^[a-z][a-z-]{0,15}$")
    check_command("junos", getter.command)
    with pytest.raises(GetterError) as raised:
        fill_command(getter, {"iface": "tec"})
    assert "deny-list" in str(raised.value)


@pytest.mark.parametrize(
    "platform,command",
    [
        ("iosxe", "show {x}"),
        ("eos", "show {x}"),
        ("fortios", "get {x}"),
    ],
)
def test_mv1_4_32_command_head_cannot_be_a_slot(
    tmp_path: Path, platform: str, command: str
) -> None:
    """The model picks a getter, not the command object."""
    message = "command head must name an object before any slot"
    with pytest.raises(GetterError) as raised:
        check_command(platform, command)
    assert message in str(raised.value)

    row = {
        "id": "version",
        "command": command,
        "params": {"x": r"^[a-z][a-z-]{0,15}$"},
        "enabled": True,
        "verified": "unverified",
        "why": "Synthetic test row.",
        "expect": ["Synthetic"],
    }
    with pytest.raises(GetterError) as raised:
        load_one(tmp_path, row, platform)
    assert message in str(raised.value)

    positive = {
        "iosxe": "show interfaces {iface}",
        "eos": "show interfaces {iface}",
        "fortios": "get system {x}",
    }[platform]
    check_command(platform, positive)


@pytest.mark.parametrize("case", ["routeros-path", "filled-slot"])
def test_mv1_4_33_deny_tokens_split_on_routeros_slashes(case: str) -> None:
    """Slash-joined RouterOS paths and filled values still tokenize."""
    if case == "routeros-path":
        with pytest.raises(GetterError) as raised:
            check_command("routeros", "/system/reboot/print")
        assert "deny-list token" in str(raised.value)
        return

    getter = slot_getter(GOOD_PARAM)
    with pytest.raises(GetterError) as raised:
        fill_command(getter, {"iface": "x/reboot"})
    assert "deny-list" in str(raised.value)
