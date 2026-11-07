"""Per-platform getter data files (IOS XE, FortiOS), synthetic fixtures, profile notes."""

from __future__ import annotations

from pathlib import Path

from newton_mcp.adapters import ssh_cli
from newton_mcp.adapters.getters import SHARED_ERROR_MARKERS, check_command, load_getters
from newton_mcp.adapters.getters import enabled_getters

from test_fixture_secret_scan import scan as scan_vendor_fixtures


REPO_ROOT = Path(__file__).parents[2]
FIXTURES = Path(__file__).parents[1] / "tests" / "fixtures" / "vendors"
PROFILES = REPO_ROOT / "profiles"

IOSXE_DOC_ROOT = "https://www.cisco.com/c/en/us/support/ios-nx-os-software/ios-xe-17/series.html"
FORTIOS_DOC_ROOT = "https://docs.fortinet.com/product/fortigate"

IOSXE_ROWS = (
    ("version", "show version", True),
    ("interfaces", "show ip interface brief", True),
    ("routes", "show ip route", True),
    ("running_config", "show running-config", False),
)
FORTIOS_ROWS = (
    ("version", "get system status", False),
    ("interfaces", "get system interface physical", False),
    ("routes", "get router info routing-table all", False),
    ("firewall_policy", "show firewall policy", False),
    ("nat", "show firewall vip", False),
    ("ntp", "show system ntp", False),
    ("logging", "show log syslogd setting", False),
    ("vpn", "show vpn ipsec phase1-interface", False),
    ("running_config", "show full-configuration", False),
)

IOSXE_OWN_MARKERS = (
    "% Incomplete command",
    "% Ambiguous command",
    "Command authorization failed",
    "% Unrecognized command",
)
FORTIOS_OWN_MARKERS = (
    "Command fail\\. Return code",
    "Unknown action",
    "command parse error",
    "(?m)^Permission denied",
)

IOSXE_ERROR_FIXTURES = (
    "error-invalid-input.txt",
    "error-authorization.txt",
)
FORTIOS_ERROR_FIXTURES = (
    "error-parse.txt",
    "error-unknown-action.txt",
)

_LOADER_DEFAULT_TIMEOUT_S = 15
_LOADER_DEFAULT_MAX_BYTES = 65536

_ABBREVIATIONS = (
    "sh",
    "int",
    "conf",
    "config",
    "run",
    "ver",
    "ro",
    "rou",
    "inter",
    "sys",
    "stat",
    "fw",
    "rout",
    "full-conf",
)


def _own_marker_patterns(getter) -> tuple[str, ...]:
    shared_count = len(list(SHARED_ERROR_MARKERS))
    return tuple(m.pattern for m in getter.error_markers[shared_count:])


def _all_command_words(getter) -> list[str]:
    return getter.command.split(" ")


def test_mv1_9_01_iosxe_loader_returns_pinned_table() -> None:
    """IOS XE loader pins ids, commands and enabled flags in order."""
    getters = load_getters("iosxe")
    assert list(getters) == [row[0] for row in IOSXE_ROWS]
    for getter_id, command, enabled in IOSXE_ROWS:
        getter = getters[getter_id]
        assert getter.command == command, getter_id
        assert getter.enabled is enabled, getter_id


def test_mv1_9_02_fortios_loader_returns_pinned_table() -> None:
    """FortiOS loader pins ids, commands and enabled flags in order."""
    getters = load_getters("fortios")
    assert list(getters) == [row[0] for row in FORTIOS_ROWS]
    for getter_id, command, enabled in FORTIOS_ROWS:
        getter = getters[getter_id]
        assert getter.command == command, getter_id
        assert getter.enabled is enabled, getter_id


def test_mv1_9_03_each_row_carries_defaults_and_doc_source() -> None:
    """Every shipped row is unverified with defaults and the doc root."""
    cases = (
        ("iosxe", IOSXE_DOC_ROOT, IOSXE_ROWS),
        ("fortios", FORTIOS_DOC_ROOT, FORTIOS_ROWS),
    )
    for platform, doc_root, rows in cases:
        getters = load_getters(platform)
        for getter_id, _command, _enabled in rows:
            getter = getters[getter_id]
            assert getter.verified == "unverified", (platform, getter_id)
            assert getter.os_range == "", (platform, getter_id)
            assert dict(getter.params) == {}, (platform, getter_id)
            assert getter.secret_bearing is True, (platform, getter_id)
            assert getter.source == doc_root, (platform, getter_id)
            assert getter.ledger == "", (platform, getter_id)
            assert getter.timeout_s == _LOADER_DEFAULT_TIMEOUT_S, (platform, getter_id)
            assert getter.max_bytes == _LOADER_DEFAULT_MAX_BYTES, (platform, getter_id)
            assert getter.why != "", (platform, getter_id)


def test_mv1_9_04_each_platform_owns_a_consistent_marker_list() -> None:
    """Own markers equal the platform list, in order, on every row."""
    cases = (
        ("iosxe", IOSXE_OWN_MARKERS, IOSXE_ROWS),
        ("fortios", FORTIOS_OWN_MARKERS, FORTIOS_ROWS),
    )
    for platform, markers, rows in cases:
        getters = load_getters(platform)
        assert len(getters) == len(rows), platform
        for getter in getters.values():
            assert _own_marker_patterns(getter) == markers, (platform, getter.id)


def test_mv1_9_05_enabled_set_and_disabled_running_config() -> None:
    """IOS XE enabled set is {version, interfaces, routes}; FortiOS enabled_getters == {}; running_config disabled+secret-bearing on both; no admins row."""
    iosxe_getters = load_getters("iosxe")
    iosxe_enabled = {gid for gid, getter in iosxe_getters.items() if getter.enabled}
    assert iosxe_enabled == {"version", "interfaces", "routes"}, iosxe_enabled
    assert "running_config" in iosxe_getters
    assert iosxe_getters["running_config"].enabled is False
    assert iosxe_getters["running_config"].secret_bearing is True
    assert "admins" not in iosxe_getters

    fortios_getters = load_getters("fortios")
    assert enabled_getters("fortios") == {}, "fortios has no enabled getters"
    for getter in fortios_getters.values():
        assert getter.enabled is False, ("fortios", getter.id)
    assert "running_config" in fortios_getters
    assert fortios_getters["running_config"].enabled is False
    assert fortios_getters["running_config"].secret_bearing is True
    assert "admins" not in fortios_getters


def test_mv1_9_06_commands_are_full_words_and_pass_check_command() -> None:
    """No pipe suffixes, no slots, no abbreviations; check_command passes."""
    for platform, rows in (
        ("iosxe", IOSXE_ROWS),
        ("fortios", FORTIOS_ROWS),
    ):
        getters = load_getters(platform)
        for getter_id, command, _enabled in rows:
            getter = getters[getter_id]
            assert " | " not in getter.command, (platform, getter_id)
            assert "{" not in getter.command, (platform, getter_id)
            for word in _all_command_words(getter):
                assert word not in _ABBREVIATIONS, (
                    platform,
                    getter_id,
                    word,
                )
            assert getter.command == command, (platform, getter_id)
            check_command(platform, getter.command)


def test_mv1_9_07_status_fixtures_classify_as_ok() -> None:
    """Iosxe status fixtures (version/interfaces/routes) and fortios status fixtures (version/interfaces/routes) classify ok."""
    cases = (
        ("iosxe", ("version", "interfaces", "routes")),
        ("fortios", ("version", "interfaces", "routes")),
    )
    for platform, getter_ids in cases:
        getters = load_getters(platform)
        for getter_id in getter_ids:
            fixture = FIXTURES / platform / f"{getter_id}.txt"
            assert fixture.is_file(), fixture
            lines = fixture.read_text(encoding="utf-8").splitlines()
            assert lines and lines[0] == "# synthetic", fixture
            body = "\n".join(lines[1:])
            status, disable = ssh_cli._result_status(
                getters[getter_id], body, "", 0, False, False
            )
            assert (status, disable) == ("ok", False), (platform, getter_id)


def test_mv1_9_08_error_fixtures_classify_as_device_error() -> None:
    """Each error fixture forces device_error on every getter of the platform."""
    cases = {
        "iosxe": IOSXE_ERROR_FIXTURES,
        "fortios": FORTIOS_ERROR_FIXTURES,
    }
    for platform, fixture_names in cases.items():
        getters = load_getters(platform)
        for fixture_name in fixture_names:
            fixture = FIXTURES / platform / fixture_name
            assert fixture.is_file(), fixture
            lines = fixture.read_text(encoding="utf-8").splitlines()
            assert lines and lines[0] == "# synthetic", fixture
            body = "\n".join(lines[1:])
            for getter in getters.values():
                status, disable = ssh_cli._result_status(
                    getter, body, "", 0, False, False
                )
                assert (status, disable) == ("device_error", False), (
                    platform,
                    fixture_name,
                    getter.id,
                )


def test_mv1_9_09_benign_device_text_does_not_trigger_markers() -> None:
    """Benign interface lines classify as ok on every getter of their platform."""
    iosxe_lines = (
        "GigabitEthernet1 is up, line protocol is up\n"
        "  0 input errors, 0 CRC, 0 frame\n"
    )
    fortios_lines = (
        "Permission: read\n"
        "admin access Permission denied count 0\n"
        "status: up\n"
    )
    cases = (
        ("iosxe", iosxe_lines),
        ("fortios", fortios_lines),
    )
    for platform, line in cases:
        getters = load_getters(platform)
        for getter in getters.values():
            status, disable = ssh_cli._result_status(
                getter, line, "", 0, False, False
            )
            assert (status, disable) == ("ok", False), (platform, getter.id)


def test_mv1_9_10_fixture_directory_is_locked_and_scans_clean() -> None:
    """Every shipped fixture for iosxe/fortios is in the expected set; scanner is clean."""
    expected = {
        "iosxe": {"version.txt", "interfaces.txt", "routes.txt"} | set(IOSXE_ERROR_FIXTURES),
        "fortios": {"version.txt", "interfaces.txt", "routes.txt"} | set(FORTIOS_ERROR_FIXTURES),
    }
    for platform, allowed in expected.items():
        directory = FIXTURES / platform
        assert directory.is_dir(), directory
        seen: set[str] = set()
        for path in sorted(directory.iterdir()):
            if not path.is_file() or path.suffix != ".txt":
                raise AssertionError(f"unexpected entry: {path}")
            seen.add(path.name)
        assert seen == allowed, (platform, seen, allowed)
    assert scan_vendor_fixtures(FIXTURES) == []


def test_mv1_9_11_profile_notes_cover_setup_and_lab_gaps() -> None:
    """Notes exist, are under 80 lines, and cover the setup recipe."""
    iosxe_notes_path = PROFILES / "iosxe" / "notes.md"
    fortios_notes_path = PROFILES / "fortios" / "notes.md"
    iosxe_notes = iosxe_notes_path.read_text(encoding="utf-8")
    fortios_notes = fortios_notes_path.read_text(encoding="utf-8")

    iosxe_lines = iosxe_notes.splitlines()
    fortios_lines = fortios_notes.splitlines()
    assert len(iosxe_lines) < 80, len(iosxe_lines)
    assert len(fortios_lines) < 80, len(fortios_lines)

    for needle in ("UNVERIFIED", "experimental_readonly = true", "known_hosts", "doc-claim", "unconfirmed"):
        assert needle in iosxe_notes, ("iosxe", needle)
        assert needle in fortios_notes, ("fortios", needle)

    for needle in ("parser view", "aaa new-model", "IOL"):
        assert needle in iosxe_notes, ("iosxe", needle)

    for needle in ("accprofile", "execute", "trusthost", "system-diagnostics"):
        assert needle in fortios_notes, ("fortios", needle)
