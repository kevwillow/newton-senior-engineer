"""Per-platform getter data files (Junos, Arista EOS), synthetic fixtures, profile notes."""

from __future__ import annotations

from pathlib import Path

from newton_mcp.adapters import ssh_cli
from newton_mcp.adapters.getters import SHARED_ERROR_MARKERS, check_command, load_getters

from test_fixture_secret_scan import scan as scan_vendor_fixtures


REPO_ROOT = Path(__file__).parents[2]
FIXTURES = Path(__file__).parents[1] / "tests" / "fixtures" / "vendors"
PROFILES = REPO_ROOT / "profiles"

JUNOS_DOC_ROOT = "https://www.juniper.net/documentation/"
EOS_DOC_ROOT = "https://www.arista.com/en/um-eos"

JUNOS_ROWS = (
    ("version", "show version", True),
    ("interfaces", "show interfaces terse", True),
    ("routes", "show route", True),
    ("running_config", "show configuration", False),
)
EOS_ROWS = (
    ("version", "show version", True),
    ("interfaces", "show ip interface brief", True),
    ("routes", "show ip route", True),
    ("running_config", "show running-config sanitized", False),
)

JUNOS_OWN_MARKERS = (
    "unknown command",
    "(?m)^error: ",
    "is ambiguous",
)
EOS_OWN_MARKERS = (
    "% Incomplete command",
    "% Ambiguous command",
    "% Authorization denied",
    "% Unavailable command",
)

JUNOS_ERROR_FIXTURES = (
    "error-unknown-command.txt",
    "error-permission.txt",
)
EOS_ERROR_FIXTURES = (
    "error-invalid-input.txt",
    "error-authorization.txt",
)

# Default values from getters.py (constants for the loader; pins the test to
# current loader defaults so a future change forces the test to be updated).
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
)


def _own_marker_patterns(getter) -> tuple[str, ...]:
    """Return the platform's own error markers as raw pattern sources."""
    shared_count = len(list(SHARED_ERROR_MARKERS))
    return tuple(m.pattern for m in getter.error_markers[shared_count:])


def _all_command_words(getter) -> list[str]:
    return getter.command.split(" ")


def test_mv1_8_01_junos_loader_returns_pinned_table() -> None:
    """Junos loader pins ids, commands and enabled flags in order."""
    getters = load_getters("junos")
    assert list(getters) == [row[0] for row in JUNOS_ROWS]
    for getter_id, command, enabled in JUNOS_ROWS:
        getter = getters[getter_id]
        assert getter.command == command, getter_id
        assert getter.enabled is enabled, getter_id


def test_mv1_8_02_eos_loader_returns_pinned_table() -> None:
    """EOS loader pins ids, commands and enabled flags in order."""
    getters = load_getters("eos")
    assert list(getters) == [row[0] for row in EOS_ROWS]
    for getter_id, command, enabled in EOS_ROWS:
        getter = getters[getter_id]
        assert getter.command == command, getter_id
        assert getter.enabled is enabled, getter_id


def test_mv1_8_03_each_row_carries_defaults_and_doc_source() -> None:
    """Every shipped row is unverified (Junos enabled rows: lab receipt) with defaults and the doc root."""
    cases = (
        ("junos", JUNOS_DOC_ROOT, JUNOS_ROWS),
        ("eos", EOS_DOC_ROOT, EOS_ROWS),
    )
    for platform, doc_root, rows in cases:
        getters = load_getters(platform)
        for getter_id, _command, enabled in rows:
            getter = getters[getter_id]
            if platform == "junos" and enabled:
                # lab receipts on vJunos 26.2R1.7.
                assert getter.verified == "lab:vjunos:26.2R1.7:2026-10-18", getter_id
                assert getter.os_range == "26.2R1.7", getter_id
            else:
                assert getter.verified == "unverified", (platform, getter_id)
                assert getter.os_range == "", (platform, getter_id)
            assert dict(getter.params) == {}, (platform, getter_id)
            assert getter.secret_bearing is True, (platform, getter_id)
            assert getter.source == doc_root, (platform, getter_id)
            assert getter.ledger == "", (platform, getter_id)
            assert getter.timeout_s == _LOADER_DEFAULT_TIMEOUT_S, (platform, getter_id)
            assert getter.max_bytes == _LOADER_DEFAULT_MAX_BYTES, (platform, getter_id)
            assert getter.why != "", (platform, getter_id)


def test_mv1_8_04_each_platform_owns_a_consistent_marker_list() -> None:
    """Own markers equal the platform list, in order, on every row."""
    cases = (
        ("junos", JUNOS_OWN_MARKERS, JUNOS_ROWS),
        ("eos", EOS_OWN_MARKERS, EOS_ROWS),
    )
    for platform, markers, rows in cases:
        getters = load_getters(platform)
        assert len(getters) == len(rows), platform
        for getter in getters.values():
            assert _own_marker_patterns(getter) == markers, (platform, getter.id)


def test_mv1_8_05_enabled_set_and_disabled_running_config() -> None:
    """Enabled set is {version, interfaces, routes} and running_config is disabled+secret-bearing on both."""
    for platform, rows in (
        ("junos", JUNOS_ROWS),
        ("eos", EOS_ROWS),
    ):
        getters = load_getters(platform)
        enabled_set = {gid for gid, getter in getters.items() if getter.enabled}
        assert enabled_set == {"version", "interfaces", "routes"}, (platform, enabled_set)
        running_config = getters["running_config"]
        assert running_config.enabled is False, (platform, "running_config")
        assert running_config.secret_bearing is True, (platform, "running_config")


def test_mv1_8_06_commands_are_full_words_and_pass_check_command() -> None:
    """No pipe suffixes, no slots, no abbreviations; check_command passes."""
    for platform, rows in (
        ("junos", JUNOS_ROWS),
        ("eos", EOS_ROWS),
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
            # The pinned command matches the row exactly.
            assert getter.command == command, (platform, getter_id)
            # Loader grammar accepts the command.
            check_command(platform, getter.command)


def test_mv1_8_07_enabled_fixtures_classify_as_ok() -> None:
    """Every enabled getter has a fixture whose body is classified ok."""
    cases = (
        ("junos", JUNOS_ROWS),
        ("eos", EOS_ROWS),
    )
    for platform, rows in cases:
        getters = load_getters(platform)
        for getter_id, _command, enabled in rows:
            if not enabled:
                continue
            fixture = FIXTURES / platform / f"{getter_id}.txt"
            assert fixture.is_file(), fixture
            lines = fixture.read_text(encoding="utf-8").splitlines()
            assert lines and lines[0] == "# synthetic", fixture
            body = "\n".join(lines[1:])
            status, disable = ssh_cli._result_status(
                getters[getter_id], body, "", 0, False, False
            )
            assert (status, disable) == ("ok", False), (platform, getter_id)


def test_mv1_8_08_error_fixtures_classify_as_device_error() -> None:
    """Each error fixture forces device_error on every getter of the platform."""
    cases = {
        "junos": JUNOS_ERROR_FIXTURES,
        "eos": EOS_ERROR_FIXTURES,
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


def test_mv1_8_09_benign_device_text_does_not_trigger_markers() -> None:
    """A real interface line classifies as ok on every getter of its platform."""
    junos_line = (
        "  Logical interface ge-0/0/0.0 (Index 70) (SNMP ifIndex 521)\n"
        "    Input errors: 0, Output errors: 0\n"
    )
    eos_line = "Ethernet1 is up, line protocol is up (connected)\n"
    cases = (
        ("junos", junos_line),
        ("eos", eos_line),
    )
    for platform, line in cases:
        getters = load_getters(platform)
        for getter in getters.values():
            status, disable = ssh_cli._result_status(
                getter, line, "", 0, False, False
            )
            assert (status, disable) == ("ok", False), (platform, getter.id)


def test_mv1_8_10_fixture_directory_is_locked_and_scans_clean() -> None:
    """Only enabled-getter fixtures and error fixtures; scanner is clean."""
    enabled_ids = {
        "junos": {f"{row[0]}.txt" for row in JUNOS_ROWS if row[2]},
        "eos": {f"{row[0]}.txt" for row in EOS_ROWS if row[2]},
    }
    error_fixtures = {
        "junos": set(JUNOS_ERROR_FIXTURES),
        "eos": set(EOS_ERROR_FIXTURES),
    }
    for platform, allowed in enabled_ids.items():
        directory = FIXTURES / platform
        assert directory.is_dir(), directory
        seen: set[str] = set()
        for path in sorted(directory.iterdir()):
            if path == directory / "recorded" and path.is_dir():
                continue
            if not path.is_file() or path.suffix != ".txt":
                raise AssertionError(f"unexpected entry: {path}")
            seen.add(path.name)
            if path.name in allowed:
                continue
            if not path.name.startswith("error-"):
                raise AssertionError(
                    f"stray fixture for a disabled or unknown getter: {path}"
                )
        assert seen == allowed | error_fixtures[platform], (platform, seen, allowed)
    assert scan_vendor_fixtures(FIXTURES) == []


def test_mv1_8_11_profile_notes_cover_setup_and_lab_gaps() -> None:
    """Notes exist, are under 80 lines, and cover the setup recipe."""
    junos_notes_path = PROFILES / "junos" / "notes.md"
    eos_notes_path = PROFILES / "eos" / "notes.md"
    junos_notes = junos_notes_path.read_text(encoding="utf-8")
    eos_notes = eos_notes_path.read_text(encoding="utf-8")

    junos_lines = junos_notes.splitlines()
    eos_lines = eos_notes.splitlines()
    assert len(junos_lines) < 80, len(junos_lines)
    assert len(eos_lines) < 80, len(eos_lines)

    for needle in ("UNVERIFIED", "experimental_readonly = true", "known_hosts", "doc-claim", "unconfirmed"):
        assert needle in eos_notes, ("eos", needle)
    # Junos notes are lab-observed, with a scope paragraph.
    for needle in (
        "lab-observed on vJunos 26.2R1.7",
        "Verification scope",
        "ACCESS-DENIED",
        "experimental_readonly = true",
        "known_hosts",
    ):
        assert needle in junos_notes, ("junos", needle)

    # Junos class flags that must NOT be granted.
    for flag in ("secret", "shell", "maintenance", "network"):
        assert flag in junos_notes, ("junos", flag)

    # EOS-specific tokens.
    assert "network-operator" in eos_notes, "eos network-operator"
    assert "tech-support" in eos_notes, "eos tech-support"
