"""Per-platform getter data files (RouterOS, VyOS), synthetic fixtures, profile notes."""

from __future__ import annotations

from pathlib import Path

from newton_mcp.adapters import ssh_cli
from newton_mcp.adapters.getters import SHARED_ERROR_MARKERS, load_getters

from test_fixture_secret_scan import scan as scan_vendor_fixtures


REPO_ROOT = Path(__file__).parents[2]
ADAPTERS = Path(__file__).parents[1] / "newton_mcp" / "adapters"
FIXTURES = Path(__file__).parents[1] / "tests" / "fixtures" / "vendors"
PROFILES = REPO_ROOT / "profiles"

ROUTEROS_DOC_ROOT = "https://help.mikrotik.com/docs/"
VYOS_DOC_ROOT = "https://docs.vyos.io/en/latest/"

ROUTEROS_ROWS = (
    ("version", "/system resource print", True),
    ("interfaces", "/interface print", True),
    ("routes", "/ip route print", True),
    ("firewall_policy", "/ip firewall filter print", True),
    ("nat", "/ip firewall nat print", True),
    ("mgmt_services", "/ip service print", True),
    ("admins", "/user print", False),
    ("logging", "/system logging print", True),
    ("ntp", "/system ntp client print", True),
    ("vpn", "/ip ipsec active-peers print", True),
    ("running_config", "/export", False),
)
VYOS_ROWS = (
    ("version", "show version", True),
    ("interfaces", "show interfaces", True),
    ("routes", "show ip route", True),
    ("firewall_policy", "show firewall", True),
    ("nat", "show nat source rules", True),
    ("ntp", "show ntp", True),
    ("vpn", "show vpn ipsec sa", True),
    ("running_config", "show configuration commands", False),
)

ROUTEROS_OWN_MARKERS = (
    "bad command name",
    "expected end of command",
    "not enough permissions",
    "no such item",
)
VYOS_OWN_MARKERS = (
    "Invalid command",
    "Incomplete command",
    "Ambiguous command",
    "command not found",
)


def _own_marker_patterns(getter) -> tuple[str, ...]:
    """Return the platform's own error markers as raw pattern sources."""
    shared_count = len(list(SHARED_ERROR_MARKERS))
    return tuple(m.pattern for m in getter.error_markers[shared_count:])


def test_mv1_7_01_routeros_loader_returns_pinned_table() -> None:
    """RouterOS loader pins ids, commands and enabled flags in order."""
    getters = load_getters("routeros")
    assert list(getters) == [row[0] for row in ROUTEROS_ROWS]
    for getter_id, command, enabled in ROUTEROS_ROWS:
        getter = getters[getter_id]
        assert getter.command == command, getter_id
        assert getter.enabled is enabled, getter_id


def test_mv1_7_02_vyos_loader_returns_pinned_table() -> None:
    """VyOS loader pins ids, commands and enabled flags in order."""
    getters = load_getters("vyos")
    assert list(getters) == [row[0] for row in VYOS_ROWS]
    for getter_id, command, enabled in VYOS_ROWS:
        getter = getters[getter_id]
        assert getter.command == command, getter_id
        assert getter.enabled is enabled, getter_id


def test_mv1_7_03_each_row_carries_defaults_and_doc_source() -> None:
    """Unlabbed rows keep verification defaults; all keep row defaults."""
    cases = (
        ("routeros", ROUTEROS_DOC_ROOT, ROUTEROS_ROWS),
        ("vyos", VYOS_DOC_ROOT, VYOS_ROWS),
    )
    for platform, doc_root, rows in cases:
        getters = load_getters(platform)
        for getter_id, _command, enabled in rows:
            getter = getters[getter_id]
            if not enabled:
                assert getter.verified == "unverified", (platform, getter_id)
                assert getter.os_range == "", (platform, getter_id)
            assert dict(getter.params) == {}, (platform, getter_id)
            assert getter.secret_bearing is True, (platform, getter_id)
            assert getter.source == doc_root, (platform, getter_id)


def test_mv1_7_04_each_platform_owns_a_consistent_marker_list() -> None:
    """Own markers equal the platform list, in order, on every row."""
    cases = (
        ("routeros", ROUTEROS_OWN_MARKERS, ROUTEROS_ROWS),
        ("vyos", VYOS_OWN_MARKERS, VYOS_ROWS),
    )
    for platform, markers, rows in cases:
        getters = load_getters(platform)
        assert len(getters) == len(rows), platform
        for getter in getters.values():
            assert _own_marker_patterns(getter) == markers, (platform, getter.id)


def test_mv1_7_05_enabled_fixtures_classify_as_ok() -> None:
    """Every enabled getter has a fixture whose body is classified ok."""
    cases = (
        ("routeros", ROUTEROS_ROWS),
        ("vyos", VYOS_ROWS),
    )
    for platform, rows in cases:
        getters = load_getters(platform)
        for getter_id, _command, enabled in rows:
            if not enabled:
                continue
            fixtures = [FIXTURES / platform / f"{getter_id}.txt"]
            recorded = FIXTURES / platform / "recorded" / f"{getter_id}.txt"
            if recorded.exists():
                fixtures.append(recorded)
            for fixture in fixtures:
                assert fixture.is_file(), fixture
                lines = fixture.read_text(encoding="utf-8").splitlines()
                assert lines, fixture
                assert lines[0] == "# synthetic" or lines[0].startswith(
                    "# recorded lab:"
                ), fixture
                body = "\n".join(lines[1:])
                status, disable = ssh_cli._result_status(
                    getters[getter_id], body, "", 0, False, False
                )
                # RouterOS prints nothing for an empty peer table; VyOS prints
                # "IPsec not initialized", which is ok output.
                expected = (
                    "empty"
                    if fixture == recorded
                    and platform == "routeros"
                    and getter_id == "vpn"
                    else "ok"
                )
                assert (status, disable) == (expected, False), (
                    platform,
                    getter_id,
                    fixture,
                )


def test_mv1_7_06_error_fixtures_classify_as_device_error() -> None:
    """Each error fixture forces device_error on every getter of the platform."""
    cases = {
        "routeros": ("error-bad-command.txt", "error-permissions.txt"),
        "vyos": ("error-invalid-command.txt", "error-incomplete-command.txt"),
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


def test_mv1_7_07_fixture_directory_is_locked_and_scans_clean() -> None:
    """Only enabled-getter fixtures and shared scanner returns no findings."""
    enabled_ids = {
        "routeros": {f"{row[0]}.txt" for row in ROUTEROS_ROWS if row[2]},
        "vyos": {f"{row[0]}.txt" for row in VYOS_ROWS if row[2]},
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
        expected = (
            allowed | {"error-bad-command.txt", "error-permissions.txt"}
            if platform == "routeros"
            else allowed | {"error-invalid-command.txt", "error-incomplete-command.txt"}
        )
        assert seen == expected, (platform, seen, expected)
    assert scan_vendor_fixtures(FIXTURES) == []


def test_mv1_7_08_profile_notes_cover_setup_and_lab_gaps() -> None:
    """Profile notes state lab status and cover the setup policies."""
    routeros_notes = (PROFILES / "routeros" / "notes.md").read_text(
        encoding="utf-8"
    )
    vyos_notes = (PROFILES / "vyos" / "notes.md").read_text(encoding="utf-8")

    assert "lab-observed on CHR 7.24.5 (2026-10-18)" in routeros_notes
    for policy in ("reboot", "sensitive", "write", "policy", "test", "sniff", "romon"):
        assert policy in routeros_notes, policy

    assert "lab-observed on VyOS 2026.10.01-0035-rolling" in vyos_notes
    assert "lab = true" in vyos_notes


def test_mv1_7_09_profile_notes_round_1b_corrections() -> None:
    """The corrections remove the wrong fields and add the right ones."""
    routeros_notes = (PROFILES / "routeros" / "notes.md").read_text(
        encoding="utf-8"
    )
    vyos_notes = (PROFILES / "vyos" / "notes.md").read_text(encoding="utf-8")

    # Each notes file stays within the 80-line limit.
    lines_routeros = (PROFILES / "routeros" / "notes.md").read_text(
        encoding="utf-8"
    ).splitlines()
    lines_vyos = (PROFILES / "vyos" / "notes.md").read_text(
        encoding="utf-8"
    ).splitlines()
    assert len(lines_routeros) < 80, len(lines_routeros)
    assert len(lines_vyos) < 80, len(lines_vyos)

    # Forbidden tokens from the review must be gone from both files.
    forbidden = (
        "host_role_enforced",
        "vyatta-shell",
        "loadkey",
        "neighbour discovery",
        "profile = lab",
    )
    for token in forbidden:
        assert token not in routeros_notes, ("routeros", token)
        assert token not in vyos_notes, ("vyos", token)

    # Both inventory recipes name the accepted boolean field and the
    # per-device known_hosts path.
    for needle in ("experimental_readonly = true", "known_hosts"):
        assert needle in routeros_notes, ("routeros", needle)
        assert needle in vyos_notes, ("vyos", needle)

    # VyOS inventory always sets lab = true.
    assert "lab = true" in vyos_notes
