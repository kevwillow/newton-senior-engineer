"""Non-OpenWrt interview mappings (profiles/<platform>/intents.toml).



The six non-OpenWrt platforms ship an intents file alongside their notes;
each file carries ten entries in a fixed order, in the
``{id, explanation, doc, ledger, audit, check, good, snippet, confirm}``
schema (snippet/confirm optional but paired), and ``audit`` references
enabled getters of the platform. The v2 record adds an eighth key,
``suggestion``; the OpenWrt record stays byte-identical to the v2 interview record.
The tests never contact a device, never call ssh, and never touch any
real ``profiles/<platform>/intents.toml`` in a mutable way (the file
paths are read-only here).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

import newton_mcp.guided as guided
import newton_mcp.redact as redact
from newton_mcp.adapters.getters import enabled_getters


REPO_ROOT = Path(__file__).resolve().parents[2]
PROFILES_ROOT = REPO_ROOT / "profiles"
FIXTURES_DIR = Path(__file__).parent / "fixtures" / "guided"

VENDOR_PLATFORMS: tuple[str, ...] = (
    "routeros",
    "vyos",
    "junos",
    "eos",
    "iosxe",
    "fortios",
)

# The ten intent ids every non-openwrt intents file must carry,
# in this exact order.
VENDOR_TEN_IDS: tuple[str, ...] = (
    "INT-MGMT-SRC",
    "INT-MGMT-NO-TELNET",
    "INT-MGMT-NO-WEB",
    "INT-MGMT-NO-API",
    "INT-SNMP-V3-ONLY",
    "INT-SNMP-OFF",
    "INT-SSH-KEYS-ONLY",
    "INT-INBOUND-NONE",
    "INT-LOG-REMOTE",
    "INT-NTP-SERVERS",
)

# Only these four intents may carry a ``snippet`` / ``confirm`` pair.
SERVICE_OFF_INTENTS: frozenset[str] = frozenset({
    "INT-MGMT-NO-TELNET",
    "INT-MGMT-NO-WEB",
    "INT-MGMT-NO-API",
    "INT-SNMP-OFF",
})

# Banned words inside any snippet body (case-insensitive, whole word).
# Mirrors the prompt's allow-list complement; ``ip`` alone is fine (only
# ipsec is banned), ``set`` is fine.
_BANNED_WORDS_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9])("
    r"user|username|password|secret|key|keys|authentication|"
    r"privilege|role|community|permit|allow|allowaccess|accept|"
    r"forward|nat|vip|vpn|ipsec|tunnel|wireguard|trusthost|"
    r"address|source|interface|route"
    r")(?![A-Za-z0-9])"
)
_IPV4_LITERAL_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# Compressed (``fe80::1``) or fully specified 8-group form
# (``fe80:0:0:0:0:0:0:1``). A lone ``00:10:00`` must NOT match --
# ``commit timer 00:10:00`` is a legit timer, not an IPv6.
_IPV6_LITERAL_RE = re.compile(
    r"\b"
    r"(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F:]+\b"
    r"|::[0-9a-fA-F:]+\b"
    r"|\b[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){7}\b"
)
_ANGLE_PLACEHOLDER_RE = re.compile(r"<[^>\n]+>")


# Per-platform snippet wrappers (exact lines).
WRAPPERS: dict[str, tuple[str, ...]] = {
    # python triple-quote multi-line string templated here
    "junos": (
        "configure",
        "<BODY>",
        "commit confirmed 10",
    ),
    "eos": (
        "configure session newton-<short>",
        "<BODY>",
        "commit timer 00:10:00",
    ),
    "iosxe": (
        "configure terminal revert timer 10",
        "<BODY>",
        "end",
    ),
    "vyos": (
        "configure",
        "<BODY>",
        "commit-confirm 10",
        "exit",
    ),
    "fortios": (
        "config system global",
        "set cfg-save revert",
        "set cfg-revert-timeout 600",
        "end",
        "<BODY>",
    ),
    "routeros": (
        "# press Ctrl-X to enter Safe Mode before pasting",
        "<BODY>",
    ),
}


def _profiles_dir_for(platform: str) -> Path:
    """Return ``<repo>/profiles/<platform>`` for the real on-disk path."""
    return PROFILES_ROOT / platform





@pytest.fixture(scope="session")
def profile_sibling_for_real_intents(tmp_path_factory):
    """Create a single per-session ``tmp`` directory tree that mirrors
    the real ``profiles/<platform>/intents.toml`` files via symlinks,
    so ``load_intents(platform=..., directory=sibling)`` resolves the
    real on-disk file without polluting the repo with a side dir."""
    sibling = tmp_path_factory.mktemp("newton_intents_session")
    for platform in VENDOR_PLATFORMS:
        platform_target = sibling.parent / platform
        platform_target.mkdir(exist_ok=True)
        link = platform_target / "intents.toml"
        if link.is_symlink() or link.exists():
            link.unlink()
        real = _profiles_dir_for(platform) / "intents.toml"
        if real.exists():
            link.symlink_to(real)
    return sibling


def _load_real_intents(
    platform: str, sibling: Path,
) -> dict[str, dict]:
    """Load the real on-disk intents file for the platform via the
    sibling-directory probe trick the interview tests use. The
    ``sibling`` is provided by the ``profile_sibling_for_real_intents``
    session fixture so no side dir is created under the repo."""
    return guided.load_intents(platform=platform, directory=sibling)


# ---- real files load with the ten ids in order -----------------


@pytest.mark.parametrize("platform", VENDOR_PLATFORMS)
def test_mv1_10_01_real_intents_file_loads_ten_ids_in_order(platform, profile_sibling_for_real_intents):
    """Each non-OpenWrt intents file loads through
    ``load_intents(platform=...)`` with the real profile directory,
    carries the ten ids in the order fixed by the design, and every
    entry has only the allowed non-OpenWrt keys."""
    intents = _load_real_intents(platform, profile_sibling_for_real_intents)
    assert list(intents.keys()) == list(VENDOR_TEN_IDS), (
        platform,
        list(intents.keys()),
    )
    allowed = {
        "id", "explanation", "doc", "ledger", "audit",
        "check", "good", "snippet", "confirm",
    }
    forbidden = {
        "control_id", "tier", "form_of",
    }
    for entry in intents.values():
        assert set(entry.keys()) <= allowed, (
            platform,
            entry["id"],
            sorted(set(entry.keys()) - allowed),
        )
        assert not (set(entry.keys()) & forbidden), (
            platform,
            entry["id"],
            sorted(set(entry.keys()) & forbidden),
        )


# ---- audit ids are enabled getters of the platform ------------


@pytest.mark.parametrize("platform", VENDOR_PLATFORMS)
def test_mv1_10_02_audit_ids_are_enabled_getters(platform, profile_sibling_for_real_intents):
    """Every audit id is an enabled getter of its platform.
    FortiOS has no enabled getter, so every FortiOS audit list is empty."""
    intents = _load_real_intents(platform, profile_sibling_for_real_intents)
    enabled = set(enabled_getters(platform).keys())
    for entry in intents.values():
        audit = entry.get("audit") or []
        for gid in audit:
            assert gid in enabled, (
                platform,
                entry["id"],
                gid,
                sorted(enabled),
            )


def test_mv1_10_03_load_intents_refuses_disabled_getter_in_audit(tmp_path):
    """A temp file naming a disabled getter
    (iosxe ``running_config``) is refused by ``load_intents``."""
    sibling = tmp_path / "sibling"
    sibling.mkdir()
    iosxe = tmp_path / "iosxe"
    iosxe.mkdir()
    (iosxe / "intents.toml").write_text(
        "[[intent]]\n"
        "id = 'INT-MGMT-SRC'\n"
        "explanation = 'x'\n"
        "doc = ''\n"
        "ledger = ''\n"
        "audit = ['running_config']\n"
        "check = 'x'\n"
        "good = 'x'\n",
        encoding="utf-8",
    )
    with pytest.raises(guided.GuidedError):
        guided.load_intents(platform="iosxe", directory=sibling)


def test_mv1_10_04_load_intents_refuses_unknown_getter_in_audit(tmp_path):
    """A temp file naming an unknown getter id is refused."""
    sibling = tmp_path / "sibling"
    sibling.mkdir()
    iosxe = tmp_path / "iosxe"
    iosxe.mkdir()
    (iosxe / "intents.toml").write_text(
        "[[intent]]\n"
        "id = 'INT-MGMT-SRC'\n"
        "explanation = 'x'\n"
        "doc = ''\n"
        "ledger = ''\n"
        "audit = ['totally_unknown']\n"
        "check = 'x'\n"
        "good = 'x'\n",
        encoding="utf-8",
    )
    with pytest.raises(guided.GuidedError):
        guided.load_intents(platform="iosxe", directory=sibling)


# ---- snippet/confirm pairing + service-off-only restriction ----


@pytest.mark.parametrize(
    "case_id,extra,snippet_present,confirm_present",
    [
        ("snippet_without_confirm", "snippet = 'a'\n", True, False),
        ("confirm_without_snippet", "confirm = 'b'\n", False, True),
        ("control_id_present", "control_id = 'OW-WIFI-02'\n", False, False),
        (
            # A perfectly-wrapped vyos snippet on a NON-service-off
            # intent (INT-MGMT-SRC picked below). With the
            # service-off-only check in place, this is refused with
            # a service-off message; with the check dropped, the
            # wrapper check passes and the entry loads -- so
            # removing the rule turns the loader's refusal
            # message from "service-off" to None, and any test
            # that depends on the refusal goes red. The wrapper
            # spans real newlines here so the entry is well-formed
            # TOML and the test does not hinge on the wrapper
            # check.
            "snippet_outside_service_off",
            (
                "snippet = \"\"\"configure\n"
                "delete service telnet\n"
                "commit-confirm 10\n"
                "exit\"\"\"\n"
                "confirm = 'Run configure then confirm within 10 minutes'\n"
            ),
            True,
            True,
        ),
    ],
)
def test_mv1_10_05_loader_pairing_and_service_off_only(
    tmp_path, case_id, extra, snippet_present, confirm_present,
):
    """Snippet without confirm, confirm without snippet, a
    ``control_id`` field, and a ``snippet``/``confirm`` pair outside the
    four service-off intents are all refused by the loader; the last
    case proves the loader enforces service-off-only itself."""
    sibling = tmp_path / case_id / "sibling"
    sibling.mkdir(parents=True)
    profile = tmp_path / case_id / "vyos"
    profile.mkdir(parents=True)
    # Pick the intent under test based on case.
    if case_id == "snippet_outside_service_off":
        intent_id = "INT-MGMT-SRC"
    else:
        intent_id = "INT-MGMT-NO-TELNET"
    (profile / "intents.toml").write_text(
        "[[intent]]\n"
        f"id = '{intent_id}'\n"
        "explanation = 'vendor-neutral'\n"
        "doc = ''\n"
        "ledger = ''\n"
        "audit = []\n"
        "check = 'x'\n"
        "good = 'x'\n"
        f"{extra}",
        encoding="utf-8",
    )
    if case_id == "snippet_outside_service_off":
        # The confirm 'Run configure then confirm within 10 minutes'
        # contains the word 'confirm' (per the vyos confirm-text
        # rule), so the vyos confirm check is happy and the only
        # reason the loader refuses is the service-off-only rule.
        with pytest.raises(guided.GuidedError, match="service-off"):
            guided.load_intents(platform="vyos", directory=sibling)
    else:
        with pytest.raises(guided.GuidedError):
            guided.load_intents(platform="vyos", directory=sibling)


# ---- snippets match the wrapper, have body, no banned word ----


@pytest.mark.parametrize("platform", VENDOR_PLATFORMS)
def test_mv1_10_06_snippet_shape(platform, profile_sibling_for_real_intents):
    """Every snippet starts and ends with its platform's
    wrapper exactly, has at least one body line, contains none of the
    banned words, has no IPv4/IPv6 literal, and survives redaction
    unchanged."""
    intents = _load_real_intents(platform, profile_sibling_for_real_intents)
    wrapper = WRAPPERS[platform]
    for entry in intents.values():
        snippet = entry.get("snippet")
        if snippet is None:
            continue
        lines = snippet.splitlines()
        body_index = wrapper.index("<BODY>")
        prefix = list(wrapper[:body_index])
        suffix = list(wrapper[body_index + 1:])
        from newton_mcp.guided import _wrapper_line_matches
        for tmpl, line in zip(prefix, lines[: len(prefix)]):
            assert _wrapper_line_matches(tmpl, line), (
                platform, entry["id"], tmpl, line,
            )
        end_slice = lines[len(lines) - len(suffix):] if suffix else []
        for tmpl, line in zip(suffix, end_slice):
            assert _wrapper_line_matches(tmpl, line), (
                platform, entry["id"], tmpl, line,
            )
        body_lines = (
            lines[len(prefix): len(lines) - len(suffix)]
            if suffix else lines[len(prefix):]
        )
        assert body_lines, (platform, entry["id"], "no body line")
        joined = "\n".join(lines)
        assert _BANNED_WORDS_RE.search(joined) is None, (
            platform, entry["id"], joined,
        )
        assert not _IPV4_LITERAL_RE.search(joined), (
            platform, entry["id"], joined,
        )
        assert not _IPV6_LITERAL_RE.search(joined), (
            platform, entry["id"], joined,
        )
        assert not _ANGLE_PLACEHOLDER_RE.search(joined), (
            platform, entry["id"], joined,
        )
        assert redact.redact_value(snippet) == snippet, (
            platform, entry["id"], joined,
        )


# ---- v2 record shape across all six platforms ----------------


def _v2_answers_for_service_off_set(
    admin_access: list[str], *,
    snmp_v3_only: bool,
    with_hosts: bool,
    with_inbound_list: bool,
) -> dict[str, object]:
    """One answer set covering as many of the ten intents as possible;
    INT-SNMP-V3-ONLY and INT-SNMP-OFF are mutually exclusive by design
    so the caller picks which one to produce via ``snmp_v3_only``."""
    out: dict[str, object] = {
        "device_kind": "home_router",
        "strictness": "normal",
        "admin_source": "lan_only",
        "admin_access": admin_access,
        "ssh_password_off": "yes",
        "inbound_services": [] if not with_inbound_list else ["tcp/443"],
        "upnp": "no",
        "segments": [],
        "wifi_wpa2": "all_wpa3",
        "dns": [],
        "ipv6_off": "yes",
        "remote_vpn": "none",
        "log_time_hosts": (
            {"syslog": ["192.0.2.10"], "ntp": ["pool.ntp.org"]}
            if with_hosts else {"syslog": [], "ntp": []}
        ),
        "fw_update_check": "yes",
    }
    return out


@pytest.mark.parametrize("platform", VENDOR_PLATFORMS)
def test_mv1_10_07_v2_record_shape_for_each_platform(platform, profile_sibling_for_real_intents):
    """V2 answers that produce the ten intents (the
    snmp-v3-only/off pair is split into two answer sets) report
    ``suggestion.status == "UNVERIFIED"`` on mapped records and
    ``suggestion is None`` with explanation
    ``no guidance for <platform> yet`` on the unmapped ones."""
    sibling = profile_sibling_for_real_intents
    # Two answer sets so both V3-ONLY and OFF are covered.
    answers_v3 = _v2_answers_for_service_off_set(
        ["ssh", "snmp_v3"], snmp_v3_only=True, with_hosts=True,
        with_inbound_list=False,
    )
    answers_off = _v2_answers_for_service_off_set(
        ["ssh"], snmp_v3_only=False, with_hosts=True,
        with_inbound_list=False,
    )
    records: dict[str, dict] = {}
    for ans in (answers_v3, answers_off):
        report = guided.recommend(ans, platform=platform, directory=sibling)
        for record in report["intents"]:
            records[record["id"]] = record
    # INT-SEG-GUEST is produced with segments=['guest']; verify the
    # unmapped branch via a third answer set:
    report_unmapped = guided.recommend(
        {
            "device_kind": "home_router",
            "strictness": "normal",
            "admin_source": "lan_only",
            "segments": ["guest"],
        },
        platform=platform,
        directory=sibling,
    )
    seg_guest = next(
        r for r in report_unmapped["intents"] if r["id"] == "INT-SEG-GUEST"
    )
    expected_keys = {
        "id", "guidance", "explanation", "audit", "control_id",
        "doc", "ledger", "suggestion",
    }
    assert set(seg_guest.keys()) == expected_keys, sorted(seg_guest.keys())
    assert seg_guest["suggestion"] is None
    assert seg_guest["explanation"] == f"no guidance for {platform} yet"
    # Every mapped record from the union of answer sets has the eight
    # keys and a ``suggestion`` dict with status UNVERIFIED.
    for intent_id in VENDOR_TEN_IDS:
        record = records[intent_id]
        assert set(record.keys()) == expected_keys, (
            platform, intent_id, sorted(record.keys()),
        )
        assert record["suggestion"] is not None, (platform, intent_id)
        assert record["suggestion"]["status"] == "UNVERIFIED", (
            platform, intent_id,
        )
        assert "check" in record["suggestion"]
        assert "good" in record["suggestion"]
        # snippet / confirm are either both set or both None:
        snip = record["suggestion"].get("snippet")
        conf = record["suggestion"].get("confirm")
        assert (snip is None) == (conf is None), (platform, intent_id)


# ---- OpenWrt record shape is unchanged -----------------------


def test_mv1_10_08_openwrt_record_shape_unchanged():
    """The same v2 answers on OpenWrt give records with
    exactly the seven keys of the v2 record; the dump computed from the live
    code equals the HEAD-pinned fixture captured before the vendor mappings
    edited ``guided.py``."""
    answers = _v2_answers_for_service_off_set(
        ["ssh"], snmp_v3_only=False, with_hosts=True,
        with_inbound_list=False,
    )
    report = guided.recommend(answers)
    records = report["intents"]
    expected = {
        "id", "guidance", "explanation", "audit",
        "control_id", "doc", "ledger",
    }
    for record in records:
        assert set(record.keys()) == expected, (
            record["id"], sorted(set(record.keys()) - expected),
        )
    fixture = FIXTURES_DIR / "openwrt_intents_v3_HEAD.json"
    assert fixture.is_file(), fixture
    pinned = json.loads(fixture.read_text(encoding="utf-8"))
    assert records == pinned, (
        "openwrt record shape drifted from HEAD; the v2 path went\n"
        "through the suggest-fork by accident — confirm guided.py\n"
        "is the only edit site and call out the diff."
    )


# ---- check and good required, non-empty, no newline -----------


_BOTH_REQUIRED_CASES: tuple[tuple[str, str, str], ...] = (
    # (case_id, bad_field, "missing" | "empty" | "newline" | "non_string")
    ("missing_check", "check", "missing"),
    ("empty_check", "check", "empty"),
    ("newline_check", "check", "newline"),
    ("non_string_check", "check", "non_string"),
    ("missing_good", "good", "missing"),
    ("empty_good", "good", "empty"),
    ("newline_good", "good", "newline"),
    ("non_string_good", "good", "non_string"),
)


def _text_for_required_case(
    bad_field: str, reason: str,
) -> str:
    """Build a TOML [[intent]] body for ``INT-MGMT-SRC`` with one of
    ``check`` / ``good`` missing, empty, multi-line or non-string; the
    other field stays a clean one-line string so the loader can refuse
    the right one."""
    parts: list[str] = [
        "[[intent]]",
        "id = 'INT-MGMT-SRC'",
        "explanation = 'x'",
        "doc = ''",
        "ledger = ''",
        "audit = []",
    ]
    for field in ("check", "good"):
        if field == bad_field:
            if reason == "missing":
                continue
            if reason == "empty":
                parts.append(f"{field} = ''")
            elif reason == "newline":
                # TOML triple-quoted literal string carries an
                # actual newline; this is exactly the shape the
                # loader is being asked to refuse.
                                parts.append(
                    f"{field} = '''" + chr(10)
                    + "first line" + chr(10)
                    + "second line'''"
                )
            elif reason == "non_string":
                parts.append(f"{field} = 5")
            else:  # pragma: no cover - test param coverage
                raise AssertionError(reason)
        else:
            parts.append(f"{field} = 'one line'")
    return "\n".join(parts) + "\n"


@pytest.mark.parametrize(
    "case_id,bad_field,reason",
    _BOTH_REQUIRED_CASES,
    ids=[c[0] for c in _BOTH_REQUIRED_CASES],
)
def test_mv1_10_40_check_and_good_required(
    tmp_path, case_id, bad_field, reason,
):
    """On a non-OpenWrt entry both ``check`` and ``good``
    must be present, non-empty strings with no newline; a missing,
    empty, multi-line or non-string value is refused with a
    ``GuidedError`` from ``_raise``. Temp file under a sibling dir as
    the pairing test does."""
    sibling = tmp_path / case_id / "sibling"
    sibling.mkdir(parents=True)
    profile = tmp_path / case_id / "vyos"
    profile.mkdir(parents=True)
    (profile / "intents.toml").write_text(
        _text_for_required_case(bad_field, reason),
        encoding="utf-8",
    )
    with pytest.raises(guided.GuidedError):
        guided.load_intents(platform="vyos", directory=sibling)


# ---- non-string snippet and confirm refused with GuidedError ----


def test_mv1_10_41_non_string_snippet_is_refused(tmp_path):
    """``snippet = 5`` paired with a string ``confirm`` on a
    service-off intent must be refused with ``GuidedError``; the bug
    is that today the loader raises ``AttributeError`` from
    ``5.splitlines()`` instead."""
    sibling = tmp_path / "snippet_int" / "sibling"
    sibling.mkdir(parents=True)
    profile = tmp_path / "snippet_int" / "vyos"
    profile.mkdir(parents=True)
    (profile / "intents.toml").write_text(
        "[[intent]]\n"
        "id = 'INT-MGMT-NO-TELNET'\n"
        "explanation = 'x'\n"
        "doc = ''\n"
        "ledger = ''\n"
        "audit = []\n"
        "check = 'x'\n"
        "good = 'x'\n"
        "snippet = 5\n"
        "confirm = 'press Ctrl-X again'\n",
        encoding="utf-8",
    )
    with pytest.raises(guided.GuidedError):
        guided.load_intents(platform="vyos", directory=sibling)


def test_mv1_10_41_non_string_confirm_is_refused(tmp_path):
    """``snippet = <good string>`` paired with ``confirm = 5``
    must be refused with ``GuidedError`` before any wrapper check; the
    bug is that today the confirm value is never type-checked."""
    sibling = tmp_path / "confirm_int" / "sibling"
    sibling.mkdir(parents=True)
    profile = tmp_path / "confirm_int" / "vyos"
    profile.mkdir(parents=True)
    (profile / "intents.toml").write_text(
        "[[intent]]\n"
        "id = 'INT-MGMT-NO-TELNET'\n"
        "explanation = 'x'\n"
        "doc = ''\n"
        "ledger = ''\n"
        "audit = []\n"
        "check = 'x'\n"
        "good = 'x'\n"
        "snippet = \"\"\"\\\n"
        "# press Ctrl-X to enter Safe Mode before pasting\n"
        "/ip service set telnet disabled=yes\"\"\"\n"
        "confirm = 5\n",
        encoding="utf-8",
    )
    with pytest.raises(guided.GuidedError):
        guided.load_intents(platform="vyos", directory=sibling)


# ---- confirm text names the platform's confirm command ---------


# Per-platform rules. Real-file tests pin the existing files; the
# loader itself enforces the rule for future files (so a future
# edit that drops the wording fails the next loader call).
_PLATFORM_CONFIRM_RULES: tuple[dict, ...] = (
    {
        "platform": "junos",
        "snippet_intent_ids": (
            "INT-MGMT-NO-TELNET",
            "INT-MGMT-NO-WEB",
            "INT-MGMT-NO-API",
            "INT-SNMP-OFF",
        ),
        "required_substring": "commit",
        "forbidden_substring": "commit confirmed",
    },
    {
        "platform": "iosxe",
        "snippet_intent_ids": (
            "INT-MGMT-NO-WEB",
            "INT-SNMP-OFF",
        ),
        "required_substring": "configure confirm",
        "forbidden_substring": None,
    },
    {
        "platform": "vyos",
        "snippet_intent_ids": ("INT-MGMT-NO-TELNET", "INT-SNMP-OFF"),
        "required_substring": "confirm",
        "forbidden_substring": None,
    },
    {
        "platform": "routeros",
        "snippet_intent_ids": (
            "INT-MGMT-NO-TELNET",
            "INT-MGMT-NO-WEB",
            "INT-MGMT-NO-API",
            "INT-SNMP-OFF",
        ),
        "required_substring": "Ctrl-X",
        "forbidden_substring": None,
    },
)


@pytest.mark.parametrize(
    "rule",
    _PLATFORM_CONFIRM_RULES,
    ids=[r["platform"] for r in _PLATFORM_CONFIRM_RULES],
)
def test_mv1_10_42_confirm_text_names_platform_command(
    rule, profile_sibling_for_real_intents,
):
    """For every entry that ships a snippet, ``confirm``
    contains the platform's confirm command (and for junos, does not
    contain ``commit confirmed`` which would re-arm the wrapper's own
    rollback)."""
    intents = _load_real_intents(rule["platform"], profile_sibling_for_real_intents)
    required = rule["required_substring"]
    forbidden = rule["forbidden_substring"]
    for intent_id in rule["snippet_intent_ids"]:
        entry = intents[intent_id]
        confirm = entry.get("confirm") or ""
        assert required in confirm, (
            rule["platform"], intent_id, required, confirm,
        )
        if forbidden is not None:
            assert forbidden not in confirm, (
                rule["platform"], intent_id, forbidden, confirm,
            )


_EOS_SESSION_NAME_RE = re.compile(
    r"^configure session newton-(\S+)$"
)


def test_mv1_10_42_eos_confirm_names_match_snippet(
    profile_sibling_for_real_intents,
):
    """For EOS the confirm text names the session created
    on the snippet's first line (``configure session newton-<name>``);
    exiting the session without naming it is what the review called
    out as the bug."""
    intents = _load_real_intents("eos", profile_sibling_for_real_intents)
    for intent_id, entry in intents.items():
        snippet = entry.get("snippet")
        if snippet is None:
            continue
        first_line = snippet.splitlines()[0]
        m = _EOS_SESSION_NAME_RE.match(first_line)
        assert m is not None, (intent_id, first_line)
        name = m.group(1)
        confirm = entry.get("confirm") or ""
        required = f"configure session newton-{name} commit"
        assert required in confirm, (
            intent_id, required, confirm,
        )


@pytest.mark.parametrize(
    "platform,snippet,confirm,reason",
    [
        # junos: must contain "commit" but not "commit confirmed"
        (
            "junos",
            "configure\ndelete system services telnet\ncommit confirmed 10",
            "Run exit within 10 minutes",
            "missing_commit",
        ),
        (
            "junos",
            "configure\ndelete system services telnet\ncommit confirmed 10",
            "Run commit confirmed 5 within 10 minutes",
            "contains_commit_confirmed",
        ),
        # eos: must contain "configure session newton-<name> commit"
        (
            "eos",
            "configure session newton-snmp\nno snmp-server\ncommit timer 00:10:00",
            "Exit configure session within 10 minutes",
            "missing_session_commit",
        ),
        (
            "eos",
            "configure session newton-snmp\nno snmp-server\ncommit timer 00:10:00",
            "Run configure session newton-other commit within 10 minutes",
            "wrong_session_name",
        ),
        # iosxe: must contain "configure confirm"
        (
            "iosxe",
            "configure terminal revert timer 10\nno snmp-server\nend",
            "Exit within 10 minutes",
            "missing_configure_confirm",
        ),
        # vyos: must contain "confirm"
        (
            "vyos",
            "configure\ndelete service telnet\ncommit-confirm 10\nexit",
            "Run exit within 10 minutes",
            "missing_confirm",
        ),
        # fortios: must contain "execute cfg save" (FortiOS audit is
        # always [] and no entry ships a snippet today; this pins the
        # loader rule against a future file edit that drops the word).
        (
            "fortios",
            "config system global\nset cfg-save revert\nset cfg-revert-timeout 600\nend\nconfig system snmp sysinfo\nset status disable\nend",
            "Exit within 10 minutes",
            "missing_cfg_save",
        ),
        # routeros: must contain "Ctrl-X"
        (
            "routeros",
            "# press Ctrl-X to enter Safe Mode before pasting\n/ip service set telnet disabled=yes",
            "Press X to confirm",
            "missing_ctrl_x",
        ),
    ],
    ids=[
        "junos_no_commit", "junos_has_commit_confirmed",
        "eos_no_session_commit", "eos_wrong_session",
        "iosxe_no_configure_confirm", "vyos_no_confirm",
        "fortios_no_cfg_save", "routeros_no_ctrl_x",
    ],
)
def test_mv1_10_42b_loader_refuses_bad_confirm_text(
    tmp_path, platform, snippet, confirm, reason,
):
    """Loader rule: ``confirm`` must contain the
    platform's commit-step keyword (or for EOS, the right
    ``configure session newton-<name> commit``); a future file edit
    that drops the wording is refused with ``GuidedError``. Junos
    additionally must not contain ``commit confirmed`` because that
    re-arms the wrapper's own rollback."""
    sibling = tmp_path / reason / "sibling"
    sibling.mkdir(parents=True)
    profile = tmp_path / reason / platform
    profile.mkdir(parents=True)
    (profile / "intents.toml").write_text(
        "[[intent]]\n"
        "id = 'INT-MGMT-NO-TELNET'\n"
        "explanation = 'x'\n"
        "doc = ''\n"
        "ledger = ''\n"
        "audit = []\n"
        "check = 'x'\n"
        "good = 'x'\n"
        "snippet = \"\"\"" + snippet + "\"\"\"\n"
        "confirm = '" + confirm + "'\n",
        encoding="utf-8",
    )
    with pytest.raises(guided.GuidedError):
        guided.load_intents(platform=platform, directory=sibling)


# ---- routeros NO-WEB and NO-API disable both www/api and ssl --


def test_mv1_10_43_routeros_no_web_body_disables_www_and_www_ssl(
    profile_sibling_for_real_intents,
):
    """Routeros INT-MGMT-NO-WEB snippet disables both
    ``www`` and ``www-ssl``; the bug was that only ``www`` was
    disabled and the HTTPS UI stayed on."""
    intents = _load_real_intents("routeros", profile_sibling_for_real_intents)
    entry = intents["INT-MGMT-NO-WEB"]
    snippet = entry["snippet"]
    assert "/ip service set www disabled=yes" in snippet
    assert "/ip service set www-ssl disabled=yes" in snippet


def test_mv1_10_43_routeros_no_api_body_disables_api_and_api_ssl(
    profile_sibling_for_real_intents,
):
    """Routeros INT-MGMT-NO-API snippet disables both
    ``api`` and ``api-ssl``; the bug was that only ``api`` was
    disabled and the TLS API stayed on."""
    intents = _load_real_intents("routeros", profile_sibling_for_real_intents)
    entry = intents["INT-MGMT-NO-API"]
    snippet = entry["snippet"]
    assert "/ip service set api disabled=yes" in snippet
    assert "/ip service set api-ssl disabled=yes" in snippet


# ---- routeros SNMP-OFF and SSH-KEYS-ONLY rework -----------------


def test_mv1_10_44_routeros_snmp_off_audit_empty_and_snmp_print_in_text(
    profile_sibling_for_real_intents,
):
    """Routeros INT-SNMP-OFF has ``audit = []`` because
    ``/ip service print`` does not show SNMP, and its ``check`` /
    ``good`` text names ``/snmp print`` showing ``enabled: no``
    (unconfirmed)."""
    intents = _load_real_intents("routeros", profile_sibling_for_real_intents)
    entry = intents["INT-SNMP-OFF"]
    assert entry["audit"] == [], entry["audit"]
    assert "/snmp print" in entry["check"]
    assert "enabled: no" in entry["check"]
    assert "/snmp print" in entry["good"]
    assert "enabled: no" in entry["good"]


def test_mv1_10_44_routeros_ssh_keys_only_check_is_neutral(
    profile_sibling_for_real_intents,
):
    """Routeros INT-SSH-KEYS-ONLY ``check`` text does not
    name the bogus ``allow-none`` setting; it describes the actual
    intent (every admin account has a public key imported and SSH
    password login is refused). Field names stay unconfirmed until
    a lab capture measures them on a CHR."""
    intents = _load_real_intents("routeros", profile_sibling_for_real_intents)
    entry = intents["INT-SSH-KEYS-ONLY"]
    assert "allow-none" not in entry["check"]
    assert "public key" in entry["check"]
    assert "password" in entry["check"]


# ---- junos INT-MGMT-NO-WEB body removes both http and https -


def test_mv1_10_45_junos_no_web_body_removes_full_subtree(
    profile_sibling_for_real_intents,
):
    """Junos INT-MGMT-NO-WEB snippet body is exactly
    ``delete system services web-management`` so the change kills
    both the plain HTTP and the HTTPS web-management subtree; the bug
    was that only the ``https`` leaf was removed."""
    intents = _load_real_intents("junos", profile_sibling_for_real_intents)
    entry = intents["INT-MGMT-NO-WEB"]
    # Body lines are everything between the platform wrapper prefix
    # and suffix; pull them out and strip.
    snippet = entry["snippet"]
    lines = snippet.splitlines()
    body_lines = lines[1:-1]  # wrapper is 3 lines: configure / <body> / commit confirmed 10
    assert body_lines == ["delete system services web-management"], body_lines


# ---- iosxe INT-MGMT-NO-WEB body disables both http and https -


def test_mv1_10_45b_iosxe_no_web_body_disables_http_and_https(
    profile_sibling_for_real_intents,
):
    """iosxe INT-MGMT-NO-WEB snippet body is exactly
    ``no ip http server`` followed by ``no ip http secure-server``
    so the change kills both the plain HTTP and the HTTPS web
    server; the bug was that only ``no ip http secure-server``
    ran and the plain ``ip http server`` listener stayed on. The
    check / good text must name both ``ip http server`` and
    ``ip http secure-server`` and say neither is active."""
    intents = _load_real_intents("iosxe", profile_sibling_for_real_intents)
    entry = intents["INT-MGMT-NO-WEB"]
    snippet = entry["snippet"]
    lines = snippet.splitlines()
    # iosxe wrapper is 3 lines: configure terminal revert timer 10 /
    # <body> / end
    body_lines = lines[1:-1]
    assert body_lines == [
        "no ip http server",
        "no ip http secure-server",
    ], body_lines
    check = entry["check"]
    assert "ip http server" in check, check
    assert "ip http secure-server" in check, check
    good = entry["good"]
    assert "HTTP" in good or "http" in good, good
    assert "HTTPS" in good or "https" in good, good
    # Good must say neither is in the active configuration.
    assert (
        "Neither the HTTP nor the HTTPS web server is in the active configuration"
        in good
    ), good


# ---- clock-drift good and lab-verified check rewrite ----------


_NTP_GOOD_TEXT = (
    "At least one configured NTP server is reachable and the device "
    "reports its clock as synchronised."
)
_FORBIDDEN_NTP_GOOD_FRAGMENTS = (
    "tens of milliseconds",
    "auth checks that depend on the clock succeed",
)
_FORBIDDEN_LAB_VERIFIED_FRAGMENTS = (
    "lab-verified role",
    "lab-verified accprofile",
)


@pytest.mark.parametrize("platform", VENDOR_PLATFORMS)
def test_mv1_10_46_ntp_good_text_rewritten(
    platform, profile_sibling_for_real_intents,
):
    """Every non-OpenWrt ``INT-NTP-SERVERS`` ``good`` text
    is the single safe sentence about reachability + clock-sync; the
    older "tens of milliseconds ... auth checks ... succeed" claim is
    gone (unsupported)."""
    intents = _load_real_intents(platform, profile_sibling_for_real_intents)
    entry = intents["INT-NTP-SERVERS"]
    assert _NTP_GOOD_TEXT in entry["good"], (platform, entry["good"])
    for fragment in _FORBIDDEN_NTP_GOOD_FRAGMENTS:
        assert fragment not in entry["good"], (
            platform, fragment, entry["good"],
        )


@pytest.mark.parametrize("platform", VENDOR_PLATFORMS)
def test_mv1_10_46_no_lab_verified_role_or_accprofile_in_check(
    platform, profile_sibling_for_real_intents,
):
    """No check text references a lab-verified role or accprofile; the loader rule rewrites each one as 'Check the running configuration on the device console for SERVICE; no enabled getter shows it yet.' with the service named."""
    intents = _load_real_intents(platform, profile_sibling_for_real_intents)
    for intent_id, entry in intents.items():
        check = entry["check"]
        for fragment in _FORBIDDEN_LAB_VERIFIED_FRAGMENTS:
            assert fragment not in check, (
                platform, intent_id, fragment, check,
            )


# ---- per-rule loader refusal + positive control -----------


# A clean vyos body line, free of any banned word, IP literal, or
# angle placeholder, used to build a well-formed INT-MGMT-NO-TELNET
# entry as the positive control for the rules below.
_CLEAN_VYOS_BODY_LINE = "set service telnet disable"
_CLEAN_VYOS_SNIPPET = (
    "configure\n"
    f"{_CLEAN_VYOS_BODY_LINE}\n"
    "commit-confirm 10\n"
    "exit"
)
_CLEAN_VYOS_CONFIRM = "Run configure then confirm within 10 minutes"


def _write_vyos_intents_file(
    tmp_path: Path, case_id: str, snippet: str, confirm: str = _CLEAN_VYOS_CONFIRM,
) -> Path:
    """Write a tmp_path vyos intents.toml with one INT-MGMT-NO-TELNET
    entry whose snippet / confirm are caller-controlled. Returns the
    sibling directory ``load_intents`` expects."""
    sibling = tmp_path / case_id / "sibling"
    sibling.mkdir(parents=True)
    profile = tmp_path / case_id / "vyos"
    profile.mkdir(parents=True)
    (profile / "intents.toml").write_text(
        "[[intent]]\n"
        "id = 'INT-MGMT-NO-TELNET'\n"
        "explanation = 'x'\n"
        "doc = ''\n"
        "ledger = ''\n"
        "audit = []\n"
        "check = 'x'\n"
        "good = 'x'\n"
        f"snippet = \"\"\"{snippet}\"\"\"\n"
        f"confirm = '{confirm}'\n",
        encoding="utf-8",
    )
    return sibling


# Per-rule cases. Each tuple is (case_id, mutated snippet, match regex).
# The positive control (well-formed snippet) is tested once at the end
# via a single shared assertion so a per-rule control row is not
# duplicated.
_CASES: tuple[tuple[str, str, str], ...] = (
    (
        # banned word in the body. The vyos wrapper
        # spans real newlines; "user" is a banned whole word and
        # trips the banned-word rule.
        "banned_word",
        (
            "configure\n"
            "delete user admin\n"
            "commit-confirm 10\n"
            "exit"
        ),
        "banned word",
    ),
    (
        # IPv4 literal in the body. ``192.0.2.1`` is a
        # synthetic address from TEST-NET-1; the IPv4 regex matches
        # the four-group dotted form anywhere in the snippet. The
        # body avoids the word ``address`` (also banned) so the
        # banned-word rule does not fire first.
        "ipv4_literal",
        (
            "configure\n"
            "set rule 192.0.2.1\n"
            "commit-confirm 10\n"
            "exit"
        ),
        "IPv4 literal",
    ),
    (
        # IPv6 literal in the body. ``fe80::1`` is the
        # compressed form; the IPv6 regex matches it as ``::``
        # followed by hex groups. The body is just the literal so
        # no banned word fires first.
        "ipv6_literal",
        (
            "configure\n"
            "fe80::1\n"
            "commit-confirm 10\n"
            "exit"
        ),
        "IPv6 literal",
    ),
    (
        # angle-bracket placeholder in the body. The
        # ``<name>`` token is a real placeholder and would let an
        # unfinished value into the device. The body is just the
        # placeholder so no banned word fires first.
        "angle_placeholder",
        (
            "configure\n"
            "<name>\n"
            "commit-confirm 10\n"
            "exit"
        ),
        "angle-bracket placeholder",
    ),
    (
        # wrong opening wrapper line. The vyos wrapper
        # must start with ``configure``; ``configure terminal`` is
        # an IOS XE idiom and the loader refuses it as a wrapper
        # mismatch. The body itself is a clean line so the
        # banned-word / IP / angle rules do not fire first.
        "wrong_opening_wrapper",
        (
            "configure terminal\n"
            f"{_CLEAN_VYOS_BODY_LINE}\n"
            "commit-confirm 10\n"
            "exit"
        ),
        "opening wrapper does not match",
    ),
    (
        # wrong closing wrapper line. The vyos wrapper
        # ends with ``commit-confirm 10`` then ``exit``; an extra
        # line ``END`` (uppercase) between the body and the
        # actual closing wrapper breaks the suffix match. The
        # body itself is a clean line so the banned-word / IP /
        # angle rules do not fire first.
        "wrong_closing_wrapper",
        (
            "configure\n"
            f"{_CLEAN_VYOS_BODY_LINE}\n"
            "END\n"
            "exit"
        ),
        "closing wrapper does not match",
    ),
    (
        # empty body. vyos has prefix=1 line, suffix=2
        # lines, so a 3-line snippet with no body between the
        # wrapper lines trips the empty-body rule. The line count
        # still passes the too-few-lines check.
        "empty_body",
        (
            "configure\n"
            "commit-confirm 10\n"
            "exit"
        ),
        "body is empty",
    ),
)


@pytest.mark.parametrize(
    "case_id,snippet,match_re",
    _CASES,
    ids=[c[0] for c in _CASES],
)
def test_mv1_10_50_loader_rule_per_rule(
    tmp_path, case_id, snippet, match_re,
):
    """each loader rule (banned word, IPv4, IPv6,
    angle placeholder, opening wrapper, closing wrapper, empty
    body) refuses a vyos entry whose snippet is well-formed in
    every respect EXCEPT the one rule under test. The error
    message must contain the rule's specific substring. A shared
    positive control below proves the well-formed variant loads."""
    sibling = _write_vyos_intents_file(tmp_path, case_id, snippet)
    with pytest.raises(guided.GuidedError, match=match_re):
        guided.load_intents(platform="vyos", directory=sibling)


@pytest.mark.parametrize(
    "case_id,snippet,match_re",
    _CASES,
    ids=[c[0] for c in _CASES],
)
def test_mv1_10_50_loader_rule_per_rule_positive_control(
    tmp_path, case_id, snippet, match_re,
):
    """Positive control: the well-formed vyos snippet
    (clean body, no IPs, no angle placeholders, exact wrapper,
    non-empty body) loads without ``GuidedError``. Parametrised
    over the same case_id list as the refusal test so every rule
    case has a green counterpart, proving the test setup itself
    is well-formed when the offending part is removed."""
    sibling = _write_vyos_intents_file(tmp_path, case_id, _CLEAN_VYOS_SNIPPET)
    loaded = guided.load_intents(platform="vyos", directory=sibling)
    assert "INT-MGMT-NO-TELNET" in loaded, sorted(loaded)


def test_mv1_10_50_openwrt_intents_with_vendor_keys_is_refused(tmp_path):
    """An OpenWrt ``intents.toml`` carrying ``snippet``
    and ``confirm`` keys is refused with the unknown-key error
    because the OpenWrt entry shape is
    ``_INTENTS_ALLOWED_KEYS - _INTENTS_VENDOR_EXTRA`` and the four
    vendor-only keys are not in the OpenWrt set. (Per the
    existing OpenWrt loader rule: ``allowed_keys = _INTENTS_ALLOWED_KEYS
    - _INTENTS_VENDOR_EXTRA`` on the openwrt branch.)"""
    d = tmp_path / "openwrt"
    d.mkdir()
    (d / "intents.toml").write_text(
        "[[intent]]\n"
        "id = 'INT-MGMT-NO-TELNET'\n"
        "explanation = 'x'\n"
        "doc = ''\n"
        "ledger = ''\n"
        "audit = []\n"
        "snippet = 'unused'\n"
        "confirm = 'unused'\n",
        encoding="utf-8",
    )
    with pytest.raises(guided.GuidedError, match="unknown key"):
        guided.load_intents(platform="openwrt", directory=d)


def test_mv1_10_50_openwrt_intents_positive_control(tmp_path):
    """Positive control: an OpenWrt ``intents.toml``
    without the vendor-only keys (and with a known OpenWrt-only
    id that the loader accepts) loads without error. Pins the
    fixture is well-formed when the offending keys are removed."""
    d = tmp_path / "openwrt_clean"
    d.mkdir()
    (d / "intents.toml").write_text(
        "[[intent]]\n"
        "id = 'INT-WIFI-WPA2-COMPAT'\n"
        "explanation = 'x'\n"
        "doc = ''\n"
        "ledger = ''\n"
        "audit = []\n"
        "control_id = 'OW-WIFI-02'\n"
        "tier = 'standard'\n"
        "form_of = ''\n",
        encoding="utf-8",
    )
    loaded = guided.load_intents(platform="openwrt", directory=d)
    assert "INT-WIFI-WPA2-COMPAT" in loaded, sorted(loaded)
