"""Structured verification probes (design 3.6, 4.1-4.3) and manifest checks (4.8).

grammar.tsv holds only the 24 subcommand rows (the `probe` row is one line),
so the per-probe field rules of design 4.3 live here as an explicit TABLE,
pinned to the real router program by the SHARED VECTORS in
device/openwrt/newton-router/tests/probe_cases.json: the router test
test_probe_vectors.py runs every vector through the program's `probe`
subcommand (and `seal` for the multi-line limits), and the MCP test
mcp/tests/test_probe_vectors.py runs the same vectors through
``validate_probes``.  A disagreement is a program-versus-design mismatch;
the program is never changed here.

``validate_probes`` enforces exactly the router's rules (design 3.6): a
probe line is fields separated by ONE TAB, 1-128 bytes of 0x20-0x7e except
backslash each, the whole line at most 512 bytes, at most 32 lines and 4096
bytes total, field counts and classes per the 4.3 table.  Refusal reasons
use the router's names: ``syntax``, ``unknown-probe``, ``arg-count``,
``bad-arg-<k>`` (k counts from 1 after the probe name), ``too-long``,
``too-many``; the NewtonError message names the 1-based probe number.

One EXTRA host-side rule: ``uci-equals`` and ``uci-unset`` are REFUSED with
reason ``secret-option`` when the option part of the UCIPATH is flagged by
``redact._looks_like_secret_option`` (the same catalog redact.py loads), so
the agent gets no yes/no oracle on a value it only ever sees redacted.
"""

from __future__ import annotations

import os
import re
import tempfile
import tomllib
from pathlib import Path
from typing import Any

from .redact import _looks_like_secret_option


class _ProbeError(Exception):
    """Internal: (probe number, router reason)."""

    def __init__(self, number: int, reason: str):
        super().__init__(f"probe {number}: {reason}")
        self.number = number
        self.reason = reason


def _bad(number: int, reason: str) -> None:
    raise _ProbeError(number, reason)


# ---- field classes (design 3.3 / 4.3, mirroring the program's probe_arg_ok) --

_CFG_RE = re.compile(r"[a-z0-9_-]{1,32}")
_SECTION_NAMED_RE = re.compile(r"[A-Za-z0-9_]{1,64}")
_SECTION_ANON_RE = re.compile(r"@([A-Za-z0-9_-]{1,32})\[(-?[0-9]{1,3})\]")
_OPTION_RE = re.compile(r"[A-Za-z0-9_]{1,64}")
_HOST_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,252}")
_IFACE_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}")
_NFTFAM = frozenset({"inet", "ip", "ip6", "arp", "bridge", "netdev"})
_NFTNAME_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}")
_EXPECT_RE = re.compile(r"present|absent|eq:(?:0|[1-9][0-9]{0,3})|min:(?:0|[1-9][0-9]{0,3})")
_SERVICE_RE = re.compile(r"[a-z0-9][a-z0-9_.-]{0,31}")
_ADDR_RE = re.compile(r"[0-9a-fA-F.:]{2,45}")
_PORT_RE = re.compile(r"[1-9][0-9]{0,4}")
_PROG_RE = re.compile(r"[A-Za-z0-9_.-]{1,32}")
_PROC_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}")
_FIELD_WORDS = frozenset({
    "up", "available", "pending", "autostart", "dynamic", "proto", "device", "l3_device",
})
_CLASS_WORDS = frozenset({"EMPTY", "LOCKED", "HASH", "NOROOT", "MULTIROOT"})
_ELEMENT_RE = re.compile(r"[A-Za-z0-9_.:/-]{1,64}")
_KEY_FAMILY = frozenset({"core", "ipv4", "ipv6", "bridge", "netfilter"})
_KEY_PART_RE = re.compile(r"[A-Za-z0-9_.@:-]{1,64}")


def _is_ucipath(value: str) -> bool:
    parts = value.split(".")
    if len(parts) not in (2, 3):
        return False
    if not _CFG_RE.fullmatch(parts[0]):
        return False
    if not (_SECTION_NAMED_RE.fullmatch(parts[1]) or _SECTION_ANON_RE.fullmatch(parts[1])):
        return False
    if len(parts) == 3 and not _OPTION_RE.fullmatch(parts[2]):
        return False
    return True


def _spec_ok(value: str) -> bool:
    # iterative: count the leading '!' negations, then check the remaining
    # spec; this makes RecursionError impossible for any input
    i = 0
    while i < len(value) and value[i] == "!":
        i += 1
    if i >= len(value):
        return False
    rest = value[i:]
    if rest.startswith("~"):
        return len(rest) >= 2
    elements = rest.split(" ")
    if not 1 <= len(elements) <= 4:
        return False
    return all(1 <= len(element) <= 64 for element in elements)


def _key_ok(value: str) -> bool:
    parts = value.split("/")
    if not 2 <= len(parts) <= 6:
        return False
    if parts[0] not in _KEY_FAMILY:
        return False
    for part in parts[1:]:
        if part in (".", "..") or not _KEY_PART_RE.fullmatch(part):
            return False
    return True


def _class_ok(name: str, value: str) -> bool:
    if name == "HOST":
        return bool(_HOST_RE.fullmatch(value))
    if name == "IFACE":
        return bool(_IFACE_RE.fullmatch(value))
    if name == "NFTFAM":
        return value in _NFTFAM
    if name == "NFTNAME":
        return bool(_NFTNAME_RE.fullmatch(value))
    if name == "UCIPATH":
        return _is_ucipath(value)
    if name == "UCIPATH3":
        return value.count(".") == 2 and _is_ucipath(value)
    if name == "EXPECT":
        return bool(_EXPECT_RE.fullmatch(value))
    if name == "TEXT":
        return True
    if name == "COUNT":
        return value in ("1", "2", "3")
    if name == "SERVICE":
        return bool(_SERVICE_RE.fullmatch(value))
    if name == "INSTANCE":
        return value == "any" or bool(_IFACE_RE.fullmatch(value))
    if name == "ADDR":
        return value in ("any", "wildcard") or bool(_ADDR_RE.fullmatch(value))
    if name == "PORT":
        return bool(_PORT_RE.fullmatch(value)) and int(value) <= 65535
    if name == "PROG":
        return value == "any" or bool(_PROG_RE.fullmatch(value))
    if name == "PROC":
        return bool(_PROC_RE.fullmatch(value))
    if name == "SPEC":
        return _spec_ok(value)
    if name == "FIELD":
        return value in _FIELD_WORDS
    if name == "KEY":
        return _key_ok(value)
    if name == "CLASS":
        return value in _CLASS_WORDS
    if name == "PROTO":
        return value in ("tcp", "udp")
    if name == "RUNSTATE":
        return value in ("present", "absent")
    if name == "CHAINPOS":
        return value == "ruleset" or bool(_NFTNAME_RE.fullmatch(value))
    if name == "NEAR":
        return bool(re.fullmatch(r"[1-9]|10", value))
    if name == "ELEMENT":
        return bool(_ELEMENT_RE.fullmatch(value))
    if name == "SETSTATE":
        return value in ("present", "absent", "only")
    if name == "DNSSVC":
        return value == "dnsmasq"
    if name == "CMODE":
        return value in ("line", "prefix", "substr")
    return False


# ---- the probe table (design 4.3): name -> (min, max, classes) ---------------
# Classes are the per-position field classes after the name; a class ending
# in "+" repeats for every remaining argument.

PROBE_TABLE: dict[str, tuple[int, int, tuple[str, ...]]] = {
    "fail": (0, 0, ()),
    "ping": (1, 2, ("HOST", "COUNT")),
    "resolve": (1, 2, ("HOST", "HOST")),
    "service-running": (2, 3, ("SERVICE", "INSTANCE", "RUNSTATE")),
    "uci-equals": (2, 2, ("UCIPATH3", "TEXT")),
    "uci-unset": (1, 1, ("UCIPATH",)),
    "listen": (5, 5, ("PROTO", "ADDR", "PORT", "PROG", "EXPECT")),
    "nft-rule": (5, 8, ("NFTFAM", "NFTNAME", "CHAINPOS", "EXPECT", "TEXT+")),
    "nft-rule-order": (5, 5, ("NFTFAM", "NFTNAME", "NFTNAME", "TEXT", "TEXT")),
    "nft-rule-near": (6, 6, ("NFTFAM", "NFTNAME", "CHAINPOS", "TEXT", "NEAR", "TEXT")),
    "nft-set-has": (5, 5, ("NFTFAM", "NFTNAME", "NFTNAME", "ELEMENT", "SETSTATE")),
    "conf-has": (4, 4, ("DNSSVC", "CMODE", "EXPECT", "TEXT")),
    "proc-args": (2, 9, ("PROC", "SPEC+")),
    "iface-field": (3, 3, ("IFACE", "FIELD", "TEXT")),
    "iface-absent": (1, 1, ("IFACE",)),
    "sysctl-equals": (2, 2, ("KEY", "TEXT")),
    "ra-absent": (1, 1, ("IFACE",)),
    "log-has": (2, 4, ("EXPECT", "TEXT+")),
    "root-password-class": (1, 1, ("CLASS",)),
}

PROBE_NAMES = tuple(sorted(PROBE_TABLE))

MAX_PROBES_BYTES = 4096
MAX_PROBE_LINES = 32
MAX_PROBE_LINE_BYTES = 512
MAX_PROBE_FIELD_BYTES = 128


def _check_one_probe(number: int, fields: list[str]) -> None:
    """One probe line against 3.6 and the 4.3 table, in the router's order."""
    # per-field length first (no encode of a huge string; ASCII printable
    # fields have char length == byte length; a non-ASCII field still refuses
    # with the syntax check below because ord(ch) > 0x7E)
    for field in fields:
        if len(field) > MAX_PROBE_FIELD_BYTES:
            _bad(number, "too-long")
    # line length: the per-field cap above bounds any valid combination, so
    # len(line) is enough without encoding
    line = "\t".join(fields)
    if len(line) > MAX_PROBE_LINE_BYTES:
        _bad(number, "too-long")
    # syntax: no empty field (an empty fields list is an empty line), no TAB
    # or LF inside a field, no backslash, only 0x20-0x7e
    if not fields or any(
        not field or any(ord(ch) < 0x20 or ord(ch) > 0x7E or ch == "\\" for ch in field)
        for field in fields
    ):
        _bad(number, "syntax")
    name = fields[0]
    spec = PROBE_TABLE.get(name)
    if spec is None:
        _bad(number, "unknown-probe")
    minimum, maximum, classes = spec
    nargs = len(fields) - 1
    if not minimum <= nargs <= maximum:
        _bad(number, "arg-count")
    positions = []
    for position, class_name in enumerate(classes):
        if class_name.endswith("+"):
            positions.extend([class_name[:-1]] * (nargs - position))
            break
        positions.append(class_name)
    for index, (field, class_name) in enumerate(zip(fields[1:], positions), start=1):
        if not _class_ok(class_name, field):
            _bad(number, f"bad-arg-{index}")
    # host-only: no yes/no oracle on a value the agent only sees redacted
    if name in ("uci-equals", "uci-unset") and fields[1].count(".") == 2:
        option = fields[1].rsplit(".", 1)[1]
        if _looks_like_secret_option(option):
            _bad(number, "secret-option")


def validate_probes(probes: Any) -> list[list[str]]:
    """Validate a probe list (each probe its list of fields); return it normalized.

    Raises NewtonError whose message names the 1-based probe number and the
    router's reason (syntax, unknown-probe, arg-count, bad-arg-<k>, too-long,
    too-many), or the host-only reason secret-option.
    """
    from .server import NewtonError

    if probes is None:
        probes = []
    if not isinstance(probes, list):
        raise NewtonError("probes must be a list of probe field lists")
    # early cap: a list with more than MAX_PROBE_LINES entries is refused
    # BEFORE we copy or inspect any element, so a 1M-entry list fails fast
    # and allocates no per-element copies
    if len(probes) > MAX_PROBE_LINES:
        raise NewtonError(f"probe {MAX_PROBE_LINES + 1}: too-many")
    normalized: list[list[str]] = []
    for index, probe in enumerate(probes, start=1):
        if not isinstance(probe, list) or not all(isinstance(f, str) for f in probe):
            raise NewtonError(f"probe {index}: syntax")
        normalized.append(list(probe))
    # whole-set limits first, in the router's seal order (design 3.6)
    try:
        total = 0
        for index, probe in enumerate(normalized, start=1):
            # per-field length check fires before any encode or join so a
            # single huge field fails fast without a 100MB allocation
            for field in probe:
                if len(field) > MAX_PROBE_FIELD_BYTES:
                    _bad(index, "too-long")
            # sum of fields + tabs + LF matches "\t".join + 1 for ASCII fields
            total += sum(len(field) for field in probe) + max(0, len(probe) - 1) + 1
            if total > MAX_PROBES_BYTES:
                _bad(index, "too-long")
        if len(normalized) > MAX_PROBE_LINES:
            _bad(MAX_PROBE_LINES + 1, "too-many")
        for index, probe in enumerate(normalized, start=1):
            _check_one_probe(index, probe)
    except _ProbeError as exc:
        raise NewtonError(str(exc)) from exc
    return normalized


def probe_file_bytes(probes: list[list[str]]) -> bytes:
    """The probe file the router expects: fields joined by ONE TAB, LF per line."""
    return b"".join(
        ("\t".join(fields)).encode("utf-8", "surrogateescape") + b"\n"
        for fields in probes
    )


def write_probe_file(probes: list[list[str]]) -> str:
    """Write the probe file to a 0600 temp file; the caller deletes it."""
    fd, filename = tempfile.mkstemp(prefix="newton-probes-", suffix=".txt")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(probe_file_bytes(probes))
    except BaseException:
        try:
            os.unlink(filename)
        except OSError:
            pass
        raise
    return filename


# ---- manifest checks by id (design 4.8) ---------------------------------------

CONTROL_ID_RE = re.compile(r"[A-Za-z0-9_.-]{1,64}")


def _safe(value: object) -> str:
    text = str(value)
    cleaned = "".join(" " if (ord(ch) < 0x20 or ord(ch) == 0x7F) else ch for ch in text)
    return cleaned[:120]


def manifest_path() -> Path:
    override = os.environ.get("NEWTON_MANIFEST")
    if override:
        return Path(override).expanduser()
    home = os.environ.get("NEWTON_HOME")
    if home:
        return Path(home).expanduser() / "profiles/openwrt/manifest.toml"
    return Path(__file__).resolve().parents[2] / "profiles/openwrt/manifest.toml"


def _load_controls(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        raise _ManifestError(f"manifest not found: {path}")
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, tomllib.TOMLDecodeError) as exc:
        raise _ManifestError(f"invalid manifest: {exc}") from exc
    controls = data.get("control", [])
    if not isinstance(controls, list) or not all(isinstance(c, dict) for c in controls):
        raise _ManifestError("invalid manifest: [[control]] entries")
    return controls


class _ManifestError(Exception):
    pass


def expand_manifest_checks(manifest_checks: Any) -> list[list[str]]:
    """Expand control ids to probe lists (design 4.8); the ids stay in the record.

    Refused with a clear error: an id that is not ^[A-Za-z0-9_.-]{1,64}$, the
    same id twice, a missing manifest, an unknown id, and - today every
    control - an id whose check has no probe form yet (check_host lab/none
    or not yet converted).  The manifest's probes come before the caller's.
    """
    from .server import NewtonError

    try:
        ids: list[str] = []
        if manifest_checks is None:
            manifest_checks = []
        if not isinstance(manifest_checks, list):
            raise _ManifestError("manifest_checks must be a list of control ids")
        for control_id in manifest_checks:
            if not isinstance(control_id, str) or not CONTROL_ID_RE.fullmatch(control_id):
                raise _ManifestError(f"invalid manifest check id: {_safe(control_id)}")
            if control_id in ids:
                raise _ManifestError(f"manifest check id given twice: {control_id}")
            ids.append(control_id)
        expanded: list[list[str]] = []
        if not ids:
            return expanded
        controls = _load_controls(manifest_path())
        for control_id in ids:
            matches = [c for c in controls if c.get("id") == control_id]
            if not matches:
                raise _ManifestError(f"unknown manifest check id: {control_id}")
            if len(matches) > 1:
                raise _ManifestError(
                    f"manifest check id matches more than one control: {control_id}"
                )
            control = matches[0]
            if "probes" not in control:
                host = control.get("check_host") or "none"
                raise _ManifestError(
                    f"manifest check {control_id} has no probe form yet "
                    f"(check_host {host} or not yet converted)"
                )
            probes = control["probes"]
            if not isinstance(probes, list) or not all(
                isinstance(probe, list)
                and all(isinstance(field, str) for field in probe)
                for probe in probes
            ):
                raise _ManifestError(
                    f"manifest check {control_id} has an invalid probes entry"
                )
            # same early cap as validate_probes: a single manifest control
            # whose expansion would cross the probe-line cap is refused, so a
            # control with 1,000,000 probes cannot allocate 1M copies
            for probe in probes:
                if len(expanded) >= MAX_PROBE_LINES:
                    raise _ManifestError(
                        f"manifest check {control_id} expansion exceeds the "
                        f"{MAX_PROBE_LINES}-probe cap"
                    )
                expanded.append(list(probe))
        return expanded
    except _ManifestError as exc:
        raise NewtonError(str(exc)) from exc
