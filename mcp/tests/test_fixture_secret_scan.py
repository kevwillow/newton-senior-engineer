"""Gate synthetic vendor fixtures before any recorded output is added."""

from __future__ import annotations

import re
from pathlib import Path

import pytest


VENDOR_FIXTURES = Path(__file__).parent / "fixtures" / "vendors"

_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----", re.IGNORECASE
)
_JUNOS_9_RE = re.compile(r"\$9\$\S")
_CRYPT_RE = re.compile(r"\$(1|2[aby]?|5|6|7|8|9)\$\S")
_IOS_TYPE_7_RE = re.compile(
    r"\b(password|secret|key) 7 [0-9a-f]{4,}", re.IGNORECASE
)
_FORTIOS_ENC_RE = re.compile(r"\bENC \S", re.IGNORECASE)
_KEYWORD_RE = re.compile(
    r"\b(?:password|passwd|secret|psksecret|pre-shared-key|key-string|"
    r"community|authentication-key|encrypted-password|private-key|psk|"
    r"passphrase|wpa-psk)\b"
    r"(?:[ =:\"']+)?(?:\d )?(?P<value>\S+)",
    re.IGNORECASE,
)
_KEYWORD_PLACEHOLDER_RE = re.compile(
    r"\b(?:password|passwd|secret|psksecret|pre-shared-key|key-string|"
    r"community|authentication-key|encrypted-password|private-key|psk|"
    r"passphrase|wpa-psk)\b"
    r"(?:[ =:\"']+)?(?:\d )?"
    r"(?:<redacted:[0-9a-f]{8}>|<redacted>|\*{3,}|\"\")",
    re.IGNORECASE,
)
_MARKER_RE = re.compile(
    r"^# recorded lab:[A-Za-z0-9._-]+:"
    r"[A-Za-z0-9._-]+:\d{4}-\d{2}-\d{2}$"
)


def _line_rule(line: str) -> str | None:
    """Return the strongest secret rule matching one line, if any."""
    if _PRIVATE_KEY_RE.search(line):
        return "private-key"
    if _JUNOS_9_RE.search(line):
        return "junos-9"
    if _CRYPT_RE.search(line):
        return "crypt"
    if _IOS_TYPE_7_RE.search(line):
        return "ios-type7"
    if _FORTIOS_ENC_RE.search(line):
        return "fortios-enc"
    for match in _KEYWORD_RE.finditer(line):
        if _KEYWORD_PLACEHOLDER_RE.match(line, match.start()) is None:
            return "keyword"
    return None


def scan(root: Path) -> list[str]:
    """Scan a fixture tree without ever returning matched text."""
    if not root.exists():
        return []
    findings: list[str] = []
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        relpath = path.relative_to(root).as_posix()
        if path.suffix not in {".txt", ".json"}:
            findings.append(f"{relpath}:1:suffix")
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            findings.append(f"{relpath}:1:binary")
            continue
        first = text.splitlines()[0] if text else ""
        if first != "# synthetic" and _MARKER_RE.fullmatch(first) is None:
            findings.append(f"{relpath}:1:marker")
        for lineno, line in enumerate(text.splitlines(), start=1):
            rule = _line_rule(line)
            if rule is not None:
                findings.append(f"{relpath}:{lineno}:{rule}")
    return findings


def test_mv1_4_16_real_vendor_fixture_directory_scans_clean() -> None:
    """The real vendor directory is absent today and remains clean."""
    assert scan(VENDOR_FIXTURES) == []


def test_mv1_4_17_missing_vendor_fixture_directory_scans_clean(tmp_path: Path) -> None:
    """A missing directory is not an error while the fixtures are pending."""
    assert scan(tmp_path / "vendors") == []


@pytest.mark.parametrize(
    "rule,name,data",
    [
        (
            "private-key",
            "private.txt",
            "# synthetic\n-----BEGIN OPENSSH PRIVATE KEY-----\n",
        ),
        ("junos-9", "junos.txt", "# synthetic\nset key $9$abcdEFGH\n"),
        (
            "crypt",
            "ios.txt",
            "# synthetic\nenable secret 5 $1$abcd$xyz\n",
        ),
        (
            "ios-type7",
            "type7.txt",
            "# synthetic\npassword 7 0822455D0A16\n",
        ),
        (
            "fortios-enc",
            "fortios.txt",
            "# synthetic\nset psksecret ENC abcdEFGH\n",
        ),
        (
            "keyword",
            "snmp.txt",
            "# synthetic\nsnmp-server community notpublic RO\n",
        ),
        ("keyword", "mixed.txt", "# synthetic\npassword <redacted:0a1b2c3d> secret notreal9\n"),
        ("suffix", "capture.pdf", b"% synthetic\n"),
        ("suffix", "page.html", b"<html>synthetic</html>\n"),
        ("suffix", "page.htm", b"<html>synthetic</html>\n"),
        ("marker", "unmarked.txt", b"interface eth0\n"),
        ("binary", "capture.txt", b"\xff\xfe\x00binary\n"),
    ],
)
def test_mv1_4_18_each_fixture_rule_is_reported_without_secret_text(
    tmp_path: Path, rule: str, name: str, data: bytes | str
) -> None:
    """Planted synthetic examples produce exactly one finding."""
    root = tmp_path / "vendors"
    root.mkdir()
    target = root / name
    if isinstance(data, str):
        target.write_text(data, encoding="utf-8")
    else:
        target.write_bytes(data)
    expected = f"{name}:1:{rule}" if rule in {"suffix", "marker", "binary"} else (
        f"{name}:2:{rule}"
    )
    assert scan(root) == [expected]


def test_mv1_4_19_placeholders_and_clean_synthetic_files_pass(tmp_path: Path) -> None:
    """Approved placeholders and ordinary synthetic text are clean."""
    root = tmp_path / "vendors"
    root.mkdir()
    (root / "placeholders.txt").write_text(
        "# synthetic\n"
        "password <redacted:0a1b2c3d>\n"
        "secret ***\n"
        'community ""\n',
        encoding="utf-8",
    )
    (root / "clean.json").write_text(
        "# synthetic\n{\"interface\":\"eth0\",\"mtu\":1500}\n", encoding="utf-8"
    )
    assert scan(root) == []


def test_mv1_4_20_nested_fixture_files_are_scanned(tmp_path: Path) -> None:
    """Findings remain stable in nested directories."""
    root = tmp_path / "vendors"
    nested = root / "junos" / "recorded"
    nested.mkdir(parents=True)
    (nested / "record.txt").write_text(
        "# recorded lab:fixture.name:junos22.4:2026-10-01\n"
        "snmp community EVILVALUE\n",
        encoding="utf-8",
    )
    assert scan(root) == ["junos/recorded/record.txt:2:keyword"]
