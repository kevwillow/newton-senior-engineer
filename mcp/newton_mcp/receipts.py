"""Field receipts: one local line per getter run, no device output.

A receipt says "this getter, on this platform and OS version, gave a result of
this shape on this date". It is field evidence that tells a human where to
look; it never promotes a getter to `verified`. The line holds only values
Newton chose from fixed sets, plus the OS version string, which comes from the
device and is therefore accepted only when it fits a strict safe pattern.
No hostname, address, device name or output text is stored.

The file lives in the state directory (mode 0600, state dir 0700) like the
audit log. The state directory must already be a real (non-symlink) directory
owned by the user running the MCP server and not group- or world-writable; a
state directory this code itself creates is forced to 0700 (matching the audit
log's pattern in ``server.write_audit``). It is capped: when the next line
would pass MAX_BYTES, the file is renamed to `<name>.1` (replacing the older
copy) and a new file starts, so total size is at most 2 x MAX_BYTES. Appends
and rotation run under an flock on a separate lock file, so concurrent calls
(threads or processes) neither tear lines nor lose them. Every failure is
returned as False; callers must not let a receipt problem fail a read.
"""

from __future__ import annotations

import fcntl
import json
import os
import re
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .adapters.getters import GETTER_IDS
from .adapters.registry import PLATFORMS

RECEIPT_FILE = "field-receipts.jsonl"
LOCK_FILE = "field-receipts.lock"
MAX_BYTES = 512 * 1024
MAX_OS_SHOWN = 8
SHAPES = ("matched", "mismatch", "not_checked")
UNKNOWN = "unknown"

# An OS version must be one of these release shapes or it is "unknown".
# kiss: an allow-list, not a block-list; device text such as an address,
# hostname or serial cannot fit 1-2 digit segments. Widen per vendor only
# with a lab capture.
_VERSION_RE = re.compile(
    r"[0-9]{1,2}(?:\.[0-9]{1,2}){1,2}"  # 7.24.5, 17.12.04, 1.4.0
    r"(?:[A-Za-z]{1,4}(?:[0-9]{1,2}(?:\.[0-9]{1,2})?)?)?"  # 26.2R1.7, 4.30.3F, 7.16rc2
    r"(?:-S[0-9]{1,2}(?:\.[0-9]{1,2})?)?"  # 21.4R3-S5.4
    r"|[0-9]{4}\.[0-9]{2}\.[0-9]{2}-[0-9]{4}-rolling"  # 2026.10.01-0035-rolling
)
MAX_LINE = 512
_STATUS_RE = re.compile(r"[a-z_]{1,24}")
_DATE_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
_FIELDS = frozenset({"v", "date", "platform", "os", "getter", "status", "shape"})

# The documented version line of each platform's `version` getter.
_VERSION_LINES: dict[str, re.Pattern[str]] = {
    "vyos": re.compile(r"^Version:\s+VyOS\s+(\S{1,64})", re.M),
    "junos": re.compile(r"^Junos:\s+(\S{1,64})", re.M),
    "iosxe": re.compile(r"Cisco IOS XE Software, Version\s+(\S{1,64})"),
    "eos": re.compile(r"^Software image version:\s+(\S{1,64})", re.M),
    "fortios": re.compile(r"^Version:\s+Forti\S*\s+v([^\s,]{1,64})", re.M),
    "routeros": re.compile(r"^\s*version:\s+(\S{1,64})", re.M),
}


def enabled() -> bool:
    """Receipts are on unless NEWTON_FIELD_RECEIPTS is 0, off, false or no."""
    return os.environ.get("NEWTON_FIELD_RECEIPTS", "1").strip().lower() not in (
        "0", "off", "false", "no",
    )


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


# Capture the real ``os.geteuid`` at import time so a later
# ``monkeypatch.setattr(os, "geteuid", ...)`` cannot silently change what
# the state-dir check sees; tests use the same pattern with
# ``inventory_file``.
_geteuid = os.geteuid


def _effective_uid() -> int:
    return _geteuid()


def check_state_dir(path: Path) -> str | None:
    """Return a refusal message, or ``None`` if the path is acceptable or missing.

    A missing path is *not* a refusal here -- the caller owns the "missing
    state directory" case and creates it (chmod 0700, mirroring
    ``server.write_audit``). The check uses ``lstat`` so a symlink is
    rejected without being followed; an existing directory must be
    owned by the user running the MCP server and have no group- or
    world-writable bits (mode & 0o022). The refusal wording mirrors
    ``newton_mcp.inventory_file.check`` so the two surfaces read the
    same way to a human.
    """
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        return f"state directory cannot be inspected: {exc.strerror}"
    if stat.S_ISLNK(info.st_mode):
        return "state directory must not be a symlink"
    if not stat.S_ISDIR(info.st_mode):
        return "state directory must be a directory"
    mode = stat.S_IMODE(info.st_mode)
    if mode & 0o022:
        return f"state directory must not be group- or world-writable (run: chmod go-w {path})"
    if info.st_uid != _effective_uid():
        return "state directory must be owned by the user running the MCP server"
    return None


def check_state_dir_parent(path: Path) -> str | None:
    """Return a refusal if ``path``'s parent (one level up) is group- or world-writable without the sticky bit.

    The state directory itself is checked by ``check_state_dir``; this
    helper covers the parent because the parent is where an attacker
    with shell access could place a symlink that ``mkdir -p`` followed
    by the caller (or by ``chmod`` before this code ran) would then use
    as the real state directory.  The check follows the parent (uses
    ``os.stat``, not ``lstat``) -- if the parent is itself a symlink
    pointing into a tighter directory that is fine; only the resolved
    directory matters.  The state-dir lstat policy stays in
    ``check_state_dir``.

    A missing parent returns ``None`` (no refusal): the caller's
    ``mkdir(parents=True, exist_ok=True)`` is what creates it under the
    process umask, and the sticky-bit rule cannot apply to a directory
    whose ownership the caller just chose.
    """
    parent = path.parent
    try:
        info = os.stat(parent)
    except FileNotFoundError:
        return None
    except OSError as exc:
        return f"state directory parent cannot be inspected: {exc.strerror}"
    mode = stat.S_IMODE(info.st_mode)
    if (mode & 0o022) and not (info.st_mode & stat.S_ISVTX):
        return (
            f"state directory parent {parent} is group- or world-writable without the sticky bit"
        )
    return None


def check_state_write_path(path: Path, state_root: Path) -> str | None:
    """Return a refusal if a caller may not create or write *path* under *state_root*.

    Every state-dir write site calls this before its ``mkdir``: the state
    dir itself goes through :func:`check_state_dir` (lstat: not a symlink,
    owned by us, not group- or world-writable) and *path*'s parent through
    :func:`check_state_dir_parent` (stat: group- or world-writable without
    the sticky bit is refused).  Either may report ``None`` for a path that
    does not exist yet -- the caller's ``mkdir`` then creates it under the
    process umask.
    """
    return check_state_dir(state_root) or check_state_dir_parent(path)


def sanitize_version(value: Any) -> str:
    """Return value when it is a known release shape, else "unknown"."""
    if type(value) is not str or not _VERSION_RE.fullmatch(value):
        return UNKNOWN
    return value


def extract_version(platform: str, stdout: str) -> str:
    """Read the OS version from a `version` getter's output; "unknown" if unsafe or absent."""
    pattern = _VERSION_LINES.get(platform)
    if pattern is None or type(stdout) is not str:
        return UNKNOWN
    found = pattern.search(stdout)
    if found is None:
        return UNKNOWN
    return sanitize_version(found.group(1).rstrip(",;"))


def _open_regular(path: Path, flags: int, mode: int = 0o600) -> int:
    """Open without following symlinks or blocking; refuse anything but a regular file.

    O_NONBLOCK keeps a planted FIFO from hanging the open; it is a no-op for
    regular files. Writable opens are forced to mode 0600.
    """
    fd = os.open(str(path), flags | os.O_NOFOLLOW | os.O_NONBLOCK, mode)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise OSError("receipt path is not a regular file")
        if flags & (os.O_WRONLY | os.O_RDWR):
            os.fchmod(fd, 0o600)
    except BaseException:
        os.close(fd)
        raise
    return fd


def record(
    state: Path,
    platform: str,
    getter_id: str,
    status: str,
    shape: str,
    os_version: str,
) -> bool:
    """Append one receipt; return False (never raise) when it was not recorded."""
    try:
        if (
            platform not in PLATFORMS
            or getter_id not in GETTER_IDS
            or shape not in SHAPES
            or not _STATUS_RE.fullmatch(status)
        ):
            return False
        line = (
            json.dumps(
                {
                    "v": 1,
                    "date": _today(),
                    "platform": platform,
                    "os": sanitize_version(os_version),
                    "getter": getter_id,
                    "status": status,
                    "shape": shape,
                },
                separators=(",", ":"),
            )
            + "\n"
        ).encode("ascii")
        root = Path(state)
        refusal = check_state_write_path(root, root)
        if refusal is not None:
            return False
        try:
            root.lstat()
        except FileNotFoundError:
            root.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.chmod(root, 0o700)
        path = root / RECEIPT_FILE
        lock_fd = _open_regular(root / LOCK_FILE, os.O_RDWR | os.O_CREAT)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            try:
                size = os.lstat(path).st_size
            except FileNotFoundError:
                size = 0
            if size + len(line) > MAX_BYTES and size > 0:
                if not stat.S_ISREG(os.lstat(path).st_mode):
                    return False
                os.chmod(path, 0o600)
                os.replace(path, root / (RECEIPT_FILE + ".1"))
            fd = _open_regular(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT)
            try:
                view = memoryview(line)
                while view:
                    written = os.write(fd, view)
                    if written <= 0:
                        return False
                    view = view[written:]
            finally:
                os.close(fd)
        finally:
            os.close(lock_fd)  # closing releases the flock
        return True
    except (OSError, ValueError, UnicodeError):
        return False


def _read_lines(path: Path) -> list[str]:
    """Read at most 2 x MAX_BYTES of a regular file; unreadable means no lines."""
    try:
        fd = _open_regular(path, os.O_RDONLY)
    except OSError:
        return []
    try:
        data = b""
        while len(data) < 2 * MAX_BYTES:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            data += chunk
    except OSError:
        return []
    finally:
        os.close(fd)
    return data.decode("utf-8", errors="replace").splitlines()


def _valid(raw: str, platform: str) -> dict[str, str] | None:
    if len(raw) > MAX_LINE:
        return None
    try:
        rec = json.loads(raw)
    except Exception:  # RecursionError, MemoryError-like surprises: skip the line
        return None
    if type(rec) is not dict or set(rec) != _FIELDS or type(rec["v"]) is not int or rec["v"] != 1:
        return None
    if any(type(rec[k]) is not str for k in _FIELDS - {"v"}):
        return None
    if (
        rec["platform"] != platform
        or rec["getter"] not in GETTER_IDS
        or rec["shape"] not in SHAPES
        or not _STATUS_RE.fullmatch(rec["status"])
        or not _DATE_RE.fullmatch(rec["date"])
        or (rec["os"] != UNKNOWN and sanitize_version(rec["os"]) != rec["os"])
    ):
        return None
    return rec


def summarise(state: Path, platform: str) -> dict[str, dict[str, Any]]:
    """Count receipts for one platform: {getter: {"by_os": {os: counts}, "omitted": n}}.

    Malformed, forged or other-platform lines are skipped. The shown OS versions
    are the MAX_OS_SHOWN with the most receipts; `omitted` counts the rest.
    """
    root = Path(state)
    tally: dict[str, dict[str, dict[str, Any]]] = {}
    for name in (RECEIPT_FILE + ".1", RECEIPT_FILE):
        for raw in _read_lines(root / name):
            rec = _valid(raw, platform)
            if rec is None:
                continue
            counts = tally.setdefault(rec["getter"], {}).setdefault(
                rec["os"], {"matched": 0, "mismatch": 0, "not_checked": 0, "last_date": ""}
            )
            counts[rec["shape"]] += 1
            counts["last_date"] = max(counts["last_date"], rec["date"])
    out: dict[str, dict[str, Any]] = {}
    for getter_id, by_os in tally.items():
        ranked = sorted(
            by_os.items(),
            key=lambda item: (
                -(item[1]["matched"] + item[1]["mismatch"] + item[1]["not_checked"]),
                item[0],
            ),
        )
        out[getter_id] = {
            "by_os": dict(ranked[:MAX_OS_SHOWN]),
            "omitted": max(0, len(ranked) - MAX_OS_SHOWN),
        }
    return out
