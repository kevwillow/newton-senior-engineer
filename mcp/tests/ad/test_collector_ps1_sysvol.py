"""The SYSVOL scan of the Windows collector, run in PowerShell.

The collector runs on a Windows domain controller, but its scan of the
Policies folder is plain file and folder access.  The probe defines the
functions of ``collector.ps1`` in PowerShell 7 and scans a synthetic
Policies folder of a temporary directory with ``Get-PolicyFileResults``.

The counts of the scan follow SPEC-1.3 section 5 and the Samba
collector: a file or a folder that could not be read is counted in
``skipped_special``, a file that was read and could not be used is
counted in ``parse_refused``, and a check that reads a section with
either count answers UNKNOWN, never PASS.  The path of an item is built
from the fixed names of the spec, never from the names on the disk.

A file the test user cannot read is made with ``chmod 000``, so the
tests that need one are skipped under root, who reads every file.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os
import re
import subprocess
from pathlib import Path

import pytest

from newton_mcp.ad import wire
from pwsh_path import PWSH

AD_DIR = Path(__file__).resolve().parent
PROBE = AD_DIR / "collector_sysvol_probe.ps1"
COLLECTOR = AD_DIR.parents[1] / "newton_mcp" / "ad" / "collector" / "collector.ps1"

GPO = "{31B2F340-016D-11D2-945F-00C04FB984F9}"
GROUPS_XML = (
    '<?xml version="1.0" encoding="utf-8"?>\n'
    '<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">'
    '<User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="svc">'
    '<Properties action="U" userName="svc" cpassword="AAAA"/>'
    "</User></Groups>\n"
)
GPTTMPL = (
    "[Unicode]\r\nUnicode=yes\r\n"
    "[System Access]\r\nMinimumPasswordLength = 7\r\n"
    "[Version]\r\nsignature=\"$CHICAGO$\"\r\nRevision=1\r\n"
)


def _require_pwsh() -> None:
    if not PWSH.is_file():
        pytest.skip(f"PowerShell 7.4 is not installed at {PWSH}")


def _require_not_root() -> None:
    if os.geteuid() == 0:
        pytest.skip("root reads a file whatever its mode")


def _policies(root: Path) -> Path:
    """A Policies folder with one GPO, one Groups.xml and one template."""
    policies = root / "Policies"
    gpo = policies / GPO
    groups = gpo / "Machine" / "Preferences" / "Groups"
    groups.mkdir(parents=True)
    (groups / "Groups.xml").write_text(GROUPS_XML, encoding="utf-8")
    secedit = gpo / "Machine" / "Microsoft" / "Windows NT" / "SecEdit"
    secedit.mkdir(parents=True)
    (secedit / "GptTmpl.inf").write_bytes(b"\xff\xfe" + GPTTMPL.encode("utf-16-le"))
    return policies


def _scan(policies: Path) -> dict:
    _require_pwsh()
    finished = subprocess.run(
        [
            str(PWSH),
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(PROBE),
            str(COLLECTOR),
            str(policies),
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert finished.returncode == 0, finished.stderr
    return json.loads(finished.stdout)


@pytest.fixture
def denied(tmp_path: Path):
    """Paths made unreadable by a test, given their mode back at the end."""
    made: list[Path] = []

    def deny(path: Path) -> None:
        _require_not_root()
        path.chmod(0)
        made.append(path)

    yield deny
    for path in made:
        path.chmod(0o755)


def test_a_readable_sysvol_is_scanned_with_no_counts(tmp_path: Path) -> None:
    files = _scan(_policies(tmp_path))
    assert files["gpp"]["status"] == "ok"
    assert files["gpp"]["items"] == [
        {
            "gpo": GPO,
            "path": "Machine/Preferences/Groups/Groups.xml",
            "kind": "cpassword",
            "count": 1,
        }
    ]
    assert files["gpttmpl"]["items"] == [
        {
            "gpo": GPO,
            "section": "System Access",
            "key": "MinimumPasswordLength",
            "value": "7",
        }
    ]
    for section in ("gpp", "gpttmpl"):
        assert files[section]["parse_refused"] == 0
        assert files[section]["skipped_special"] == 0


def test_an_unreadable_preferences_file_is_counted(tmp_path: Path, denied) -> None:
    policies = _policies(tmp_path)
    denied(policies / GPO / "Machine" / "Preferences" / "Groups" / "Groups.xml")
    files = _scan(policies)
    assert files["gpp"]["items"] == []
    assert files["gpp"]["skipped_special"] == 1
    section = wire._parse_file_section(files["gpp"], kind="gpp")
    assert section.skipped_special == 1


def test_an_unlistable_preferences_folder_is_counted(tmp_path: Path, denied) -> None:
    policies = _policies(tmp_path)
    denied(policies / GPO / "Machine" / "Preferences" / "Groups")
    files = _scan(policies)
    assert files["gpp"]["items"] == []
    assert files["gpp"]["skipped_special"] == 1


def test_an_unlistable_gpo_folder_is_counted_in_both_sections(
    tmp_path: Path, denied
) -> None:
    policies = _policies(tmp_path)
    denied(policies / GPO)
    files = _scan(policies)
    for section in ("gpp", "gpttmpl"):
        assert files[section]["items"] == []
        assert files[section]["skipped_special"] == 1


def test_an_unreadable_template_is_counted(tmp_path: Path, denied) -> None:
    policies = _policies(tmp_path)
    denied(
        policies / GPO / "Machine" / "Microsoft" / "Windows NT" / "SecEdit" / "GptTmpl.inf"
    )
    files = _scan(policies)
    assert files["gpttmpl"]["items"] == []
    assert files["gpttmpl"]["skipped_special"] == 1
    section = wire._parse_file_section(files["gpttmpl"], kind="gpttmpl")
    assert section.skipped_special == 1


def test_an_unlistable_template_folder_is_counted(tmp_path: Path, denied) -> None:
    policies = _policies(tmp_path)
    denied(policies / GPO / "Machine" / "Microsoft" / "Windows NT" / "SecEdit")
    files = _scan(policies)
    assert files["gpttmpl"]["items"] == []
    assert files["gpttmpl"]["skipped_special"] == 1


def test_a_preferences_file_over_the_size_cap_is_refused(tmp_path: Path) -> None:
    policies = _policies(tmp_path)
    big = policies / GPO / "Machine" / "Preferences" / "Groups" / "Groups.xml"
    big.write_text(GROUPS_XML + " " * (4 * 1024 * 1024), encoding="utf-8")
    files = _scan(policies)
    assert files["gpp"]["items"] == []
    assert files["gpp"]["parse_refused"] == 1


def test_a_file_name_off_the_table_is_reported_as_other_xml(tmp_path: Path) -> None:
    """SPEC-1.3 section 5: the path is built from fixed names only."""
    policies = _policies(tmp_path)
    odd = policies / GPO / "Machine" / "Preferences" / "Name Of The DC"
    odd.mkdir()
    (odd / "Chosen By The DC.xml").write_text(GROUPS_XML, encoding="utf-8")
    files = _scan(policies)
    paths = sorted(item["path"] for item in files["gpp"]["items"])
    assert paths == [
        "Machine/Preferences/Groups/Groups.xml",
        "Machine/Preferences/other.xml",
    ]


def test_the_path_is_in_the_spelling_of_the_table(tmp_path: Path) -> None:
    """Folders and files of any case and depth report the fixed path."""
    policies = _policies(tmp_path)
    drives = policies / GPO / "USER" / "preferences" / "drives" / "nested"
    drives.mkdir(parents=True)
    (drives / "DRIVES.XML").write_text(GROUPS_XML, encoding="utf-8")
    files = _scan(policies)
    paths = sorted(item["path"] for item in files["gpp"]["items"])
    assert paths == [
        "Machine/Preferences/Groups/Groups.xml",
        "User/Preferences/Drives/Drives.xml",
    ]


def test_the_name_table_is_the_one_of_the_samba_collector() -> None:
    """Both collectors report the same fixed paths for the same files."""
    samba_path = COLLECTOR.with_name("newton-ad-samba")
    loader = importlib.machinery.SourceFileLoader("newton_ad_samba_table", str(samba_path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    script = COLLECTOR.read_text(encoding="utf-8")
    block = script.split("$script:GppFiles = @{", 1)[1].split("\n}", 1)[0]
    table = {
        key: (folder, name)
        for key, folder, name in re.findall(
            r"'([a-z]+\.xml)' = @\('([A-Za-z]+)', '([A-Za-z]+\.xml)'\)", block
        )
    }
    assert table == module.GPO_FILES
    assert f"$script:OtherFileName = '{module.OTHER_FILE_NAME}'" in script
    assert f"$script:MaxFileBytes = {module.MAX_FILE_BYTES}" in script


def _gpo(policies: Path, guid: str) -> Path:
    gpo = policies / guid
    gpo.mkdir(parents=True)
    return gpo


def test_a_gpo_without_a_template_or_a_machine_folder_is_scanned(tmp_path: Path) -> None:
    """Most GPOs of a domain hold no template: the scan goes on, with no count."""
    policies = _policies(tmp_path)
    user_only = _gpo(policies, "{6AC1786C-016F-11D2-945F-00C04FB984F9}")
    (user_only / "User" / "Preferences").mkdir(parents=True)
    no_secedit = _gpo(policies, "{11111111-2222-3333-4444-555555555555}")
    (no_secedit / "Machine" / "Microsoft").mkdir(parents=True)
    files = _scan(policies)
    assert [item["gpo"] for item in files["gpp"]["items"]] == [GPO]
    assert [item["gpo"] for item in files["gpttmpl"]["items"]] == [GPO]
    for section in ("gpp", "gpttmpl"):
        assert files[section]["parse_refused"] == 0
        assert files[section]["skipped_special"] == 0


def test_every_case_variant_of_a_template_folder_is_read(tmp_path: Path) -> None:
    policies = _policies(tmp_path)
    variant = policies / GPO / "MACHINE" / "microsoft" / "windows nt" / "secedit"
    variant.mkdir(parents=True)
    text = "[System Access]\r\nPasswordHistorySize = 24\r\n"
    (variant / "gpttmpl.inf").write_bytes(b"\xff\xfe" + text.encode("utf-16-le"))
    files = _scan(policies)
    keys = sorted(item["key"] for item in files["gpttmpl"]["items"])
    assert keys == ["MinimumPasswordLength", "PasswordHistorySize"]
    assert files["gpttmpl"]["skipped_special"] == 0


def test_a_linked_folder_under_preferences_is_counted_and_not_followed(
    tmp_path: Path,
) -> None:
    policies = _policies(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "Groups.xml").write_text(GROUPS_XML, encoding="utf-8")
    (policies / GPO / "Machine" / "Preferences" / "Linked").symlink_to(outside)
    files = _scan(policies)
    assert len(files["gpp"]["items"]) == 1
    assert files["gpp"]["skipped_special"] == 1


def test_a_linked_preferences_file_is_counted_and_not_read(tmp_path: Path) -> None:
    policies = _policies(tmp_path)
    groups = policies / GPO / "Machine" / "Preferences" / "Groups" / "Groups.xml"
    outside = tmp_path / "outside.xml"
    outside.write_text(GROUPS_XML, encoding="utf-8")
    groups.unlink()
    groups.symlink_to(outside)
    files = _scan(policies)
    assert files["gpp"]["items"] == []
    assert files["gpp"]["skipped_special"] == 1


def test_a_linked_template_folder_is_counted_and_not_followed(tmp_path: Path) -> None:
    policies = _policies(tmp_path)
    windows_nt = policies / GPO / "Machine" / "Microsoft" / "Windows NT"
    (windows_nt / "SecEdit").rename(tmp_path / "SecEditOutside")
    (windows_nt / "SecEdit").symlink_to(tmp_path / "SecEditOutside")
    files = _scan(policies)
    assert files["gpttmpl"]["items"] == []
    assert files["gpttmpl"]["skipped_special"] == 1


def test_a_preferences_walk_deeper_than_the_cap_is_counted(tmp_path: Path) -> None:
    policies = _policies(tmp_path)
    deep = policies / GPO / "Machine" / "Preferences"
    for level in range(10):
        deep = deep / f"d{level}"
    deep.mkdir(parents=True)
    (deep / "Groups.xml").write_text(GROUPS_XML, encoding="utf-8")
    files = _scan(policies)
    assert len(files["gpp"]["items"]) == 1
    assert files["gpp"]["skipped_special"] == 1


def test_a_utf8_template_is_read(tmp_path: Path) -> None:
    """The encoding of a template comes from its byte order mark, as on Samba."""
    policies = _policies(tmp_path)
    inf = policies / GPO / "Machine" / "Microsoft" / "Windows NT" / "SecEdit" / "GptTmpl.inf"
    inf.write_bytes(GPTTMPL.encode("utf-8"))
    files = _scan(policies)
    assert [item["key"] for item in files["gpttmpl"]["items"]] == ["MinimumPasswordLength"]


def test_a_linked_gpo_folder_is_counted_and_not_followed(tmp_path: Path) -> None:
    """A link at the Policies root is counted in the gpp section, as on Samba."""
    policies = _policies(tmp_path)
    outside = tmp_path / "outside-gpo"
    groups = outside / "Machine" / "Preferences" / "Groups"
    groups.mkdir(parents=True)
    (groups / "Groups.xml").write_text(GROUPS_XML, encoding="utf-8")
    (policies / "{22222222-2222-3333-4444-555555555555}").symlink_to(outside)
    files = _scan(policies)
    assert [item["gpo"] for item in files["gpp"]["items"]] == [GPO]
    assert files["gpp"]["skipped_special"] == 1
    assert files["gpp"]["skipped_nonguid"] == 0


def test_a_link_of_any_name_is_counted_in_every_section_that_lists_it(
    tmp_path: Path,
) -> None:
    """Every listing counts its links, whatever their names, as on Samba."""
    policies = _policies(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    machine = policies / GPO / "Machine"
    (machine / "Scripts").symlink_to(outside)
    files = _scan(policies)
    # Machine is listed by the walk of the preferences and of the template.
    assert files["gpp"]["skipped_special"] == 1
    assert files["gpttmpl"]["skipped_special"] == 1


def test_a_link_in_the_template_chain_is_counted_in_the_template_only(
    tmp_path: Path,
) -> None:
    policies = _policies(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (policies / GPO / "Machine" / "Microsoft" / "GPMC").symlink_to(outside)
    files = _scan(policies)
    assert files["gpp"]["skipped_special"] == 0
    assert files["gpttmpl"]["skipped_special"] == 1
