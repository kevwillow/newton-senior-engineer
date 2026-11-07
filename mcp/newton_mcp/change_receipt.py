"""Change receipts: one readable Markdown file per finished change.

A receipt is built from records that already exist and is never a second source
of truth: the plan record, the claimed approval, and the audit lines the host
script wrote for the session.  ``regenerate`` rebuilds the same text from those
records alone.  These are not the getters' field receipts (``receipts.py``).

Files live in ``<state>/receipts`` (dir 0700, files 0600, written through the
same state-path checks as the other state writes).  Every text is redacted and
stripped of control characters.  The approval token is never read into a
receipt, and the backup's content is never shown: only its name and sha256.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import explanation as _explanation
from . import receipts as _receipts
from . import redact as _redact
from .client_checks import CLIENT_KINDS


OUTCOME_WORDS = {"confirmed": "CONFIRMED", "rolled_back": "ROLLED BACK", "unknown": "UNKNOWN"}
RECEIPT_DIR = "receipts"
BACKUP_DIR = "backups"
_AUDIT_PREFIX = re.compile(r"^\S+ \S+ (?P<msg>.*)$")
_SID_RE = re.compile(r"^[0-9a-f]{32}$")
_DEVICE_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_RECEIPT_AUDIT_RE = re.compile(r"(?:^|\s)(?:tool=)?newton_receipt(?:\s|$)")
_LIMIT = 400
_COPY_CHUNK = 64 * 1024
_MAX_BACKUP_BYTES = 64 * 1024 * 1024


def audit_log_path() -> Path:
    """Where owrt-change.sh writes its audit lines (same rule as the script)."""
    explicit = os.environ.get("OWRT_AUDIT_LOG")
    if explicit:
        return Path(explicit)
    base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(base) / "network-agent" / "audit.log"


def _clean(value: Any, limit: int = _LIMIT) -> str:
    """One masked line: control characters become spaces, secrets are redacted."""
    text = value if isinstance(value, str) else str(value)
    text = "".join(
        " " if (ord(ch) < 0x20 or ord(ch) == 0x7F or ch in "\u0085  ") else ch for ch in text
    )
    return _redact.redact_text(text[:limit])


def _block(lines: list[str]) -> str:
    """Router or script text, quoted as data: masked, one fence, no way to close it early."""
    body = "\n".join(_clean(line).replace("```", "'''") for line in lines) if lines else "(none)"
    return "```text\n" + body + "\n```"


def _session_re(sid: str) -> re.Pattern[str]:
    return re.compile(rf"session={re.escape(sid)}(?![0-9a-f])")


def audit_lines(sid: str) -> list[str]:
    """The messages of the audit log lines for this session (date and router stripped)."""
    path = audit_log_path()
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    pattern = _session_re(sid)
    out: list[str] = []
    for line in raw.split("\n"):
        if not pattern.search(line):
            continue
        match = _AUDIT_PREFIX.match(line)
        out.append(match["msg"] if match else line)
    return out


def output_lines(sid: str, text: str) -> list[str]:
    """The same messages taken from the apply output, when the audit log has none."""
    pattern = _session_re(sid)
    return [
        line.removesuffix("\r") for line in str(text).split("\n")
        if pattern.search(line) or "OUTCOME UNKNOWN" in line
    ]


def outcome_from_lines(lines: list[str], sid: str) -> str | None:
    """Re-derive the outcome from a session's audit messages, as classify_apply does from the final line."""
    pattern = _session_re(sid)
    for line in reversed(lines):
        if re.match(r"^CONFIRMED ", line) and pattern.search(line):
            return "confirmed"
        if re.match(r"^ROLLBACK WINDOW PASSED ", line) and pattern.search(line):
            return "rolled_back"
        if re.match(r"^(ALERT|APPLIED|APPLYING) ", line) or "OUTCOME UNKNOWN" in line:
            return "unknown"
    return None


def _timestamps(sid: str) -> tuple[str, str]:
    """First APPLIED and last audit timestamps of the session, or empty strings."""
    path = audit_log_path()
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return "", ""
    pattern = _session_re(sid)
    first = last = ""
    for line in raw.split("\n"):
        if not pattern.search(line) or _RECEIPT_AUDIT_RE.search(line):
            continue
        stamp = line.split(" ", 1)[0]
        if not first and " APPLIED " in line:
            first = stamp
        last = stamp
    return first, last


def _approval_text(state: Path, record: dict[str, Any], sid: str) -> str:
    if record.get("requires_approval") is not True:
        return "No approval needed: this is a lab device and the plan said none was required."
    approvals = state / "approvals"
    for suffix in ("used", "claimed", "json"):
        path = approvals / f"{sid}.{suffix}"
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(data, dict):
            continue
        who = data.get("approved_by")
        who = who if isinstance(who, str) and who.strip() else "unknown"
        state_word = {"used": "used by this apply", "claimed": "claimed, not settled", "json": "not used"}[suffix]
        return (
            "Approved out of band with `newton-approve` in the owner's own terminal.\n"
            f"- Approval record: {state_word}\n"
            f"- Approved by: {_clean(who, 64)}\n"
            f"- Approval created: {_clean(data.get('created_at', 'unknown'), 40)}\n"
            f"- Approval window ended: {_clean(data.get('expires_at', 'unknown'), 40)}\n"
            "- The approval was bound to this plan's hash; the token is not recorded here."
        )
    return "The plan required approval but no approval record was found."


def _claims_text(record: dict[str, Any]) -> list[str]:
    explanation = record.get("explanation")
    expect = explanation.get("expect") if isinstance(explanation, dict) else None
    out: list[str] = []
    for index, claim in enumerate(expect if isinstance(expect, list) else [], start=1):
        if not isinstance(claim, dict):
            continue
        if claim.get("kind") == "uci_equals":
            # one string, so the redactor sees the path=value form it knows
            out.append(f"{index}. uci " + _clean(f"{claim.get('path')}='{claim.get('equals')}'", 260))
        elif claim.get("kind") == "probe" and isinstance(claim.get("probe"), list) and claim["probe"]:
            name = _clean(claim["probe"][0], 40)
            out.append(f"{index}. probe {name} ({len(claim['probe']) - 1} arguments, not printed)")
        elif claim.get("kind") in CLIENT_KINDS:
            # a client claim is printed in words, with the number of targets
            # and never the targets themselves
            out.append(f"{index}. " + _clean(_explanation.describe_claim(claim), 260))
    return out


def _probe_names(record: dict[str, Any]) -> str:
    probes = record.get("probes")
    counts: dict[str, int] = {}
    for probe in probes if isinstance(probes, list) else []:
        if isinstance(probe, list) and probe and isinstance(probe[0], str):
            counts[probe[0]] = counts.get(probe[0], 0) + 1
    names = ", ".join(f"{_clean(n, 40)} x{c}" if c > 1 else _clean(n, 40) for n, c in sorted(counts.items()))
    total = sum(counts.values())
    return f"{total} sealed probes ({names})" if total else "no sealed probes"


def _staged_text(record: dict[str, Any]) -> str:
    staged = record.get("staged_check")
    if not isinstance(staged, dict):
        return "Staged config check: not recorded (this plan was made before the check existed)."
    parts = [f"{_clean(k, 24)}: {_clean(v, 60)}" for k, v in sorted(staged.items()) if k != "not_checked"]
    missing = staged.get("not_checked")
    text = "Staged config check: " + ("; ".join(parts) if parts else "none")
    if isinstance(missing, list) and missing:
        text += "; NOT CHECKED: " + ", ".join(_clean(m, 24) for m in missing)
    return text


def _backup_name(record: dict[str, Any]) -> str:
    raw = record.get("backup_path")
    return _clean(Path(raw).name, 120) if isinstance(raw, str) and raw else "unknown"


def _open_backup_source(path: Path) -> tuple[int | None, str]:
    """Open one bounded regular file without following a symlink."""
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None, "backup file not found"
    except OSError:
        return None, "source could not be inspected"
    if not stat.S_ISREG(info.st_mode):
        return None, "source is not a regular file"
    if info.st_size > _MAX_BACKUP_BYTES:
        return None, "source is larger than the 64 MiB limit"
    try:
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return None, "source could not be opened without following symlinks"
    try:
        opened = os.fstat(fd)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino)
        ):
            os.close(fd)
            return None, "source changed while it was opened"
        if opened.st_size > _MAX_BACKUP_BYTES:
            os.close(fd)
            return None, "source is larger than the 64 MiB limit"
        return fd, ""
    except OSError:
        os.close(fd)
        return None, "source could not be opened without following symlinks"


def _stream_hash(fd: int, target_fd: int | None = None) -> tuple[str, str]:
    """Hash at most 64 MiB from fd, optionally copying the same chunks to target_fd."""
    digest = hashlib.sha256()
    total = 0
    while True:
        chunk = os.read(fd, _COPY_CHUNK)
        if not chunk:
            return digest.hexdigest(), ""
        total += len(chunk)
        if total > _MAX_BACKUP_BYTES:
            return "", "source grew larger than the 64 MiB limit while being copied"
        digest.update(chunk)
        if target_fd is not None:
            remaining = memoryview(chunk)
            while remaining:
                written = os.write(target_fd, remaining)
                if written == 0:
                    raise OSError("short backup write")
                remaining = remaining[written:]


def _hash_backup(path: Path) -> tuple[str, str]:
    fd, reason = _open_backup_source(path)
    if fd is None:
        return "", reason
    try:
        return _stream_hash(fd)
    except OSError:
        return "", "source could not be read"
    finally:
        os.close(fd)


def backup_info(state: Path, record: dict[str, Any], sid: str) -> tuple[str, str, str]:
    """(name, sha256 or '', copy note) for the pre-change backup."""
    raw = record.get("backup_path")
    name = _backup_name(record)
    copy = state / RECEIPT_DIR / BACKUP_DIR / f"{sid}.tar.gz"
    digest, _ = _hash_backup(copy)
    if digest:
        return name, digest, f"off-device copy: receipts/{BACKUP_DIR}/{sid}.tar.gz"
    if not isinstance(raw, str) or not raw:
        return name, "", "off-device copy: none (backup was not copied: backup path not recorded)"
    digest, reason = _hash_backup(Path(raw))
    if digest:
        return name, digest, "off-device copy: none (backup was not copied)"
    return name, "", f"off-device copy: none (backup was not copied: {reason})"


def render(
    state: Path,
    record: dict[str, Any],
    outcome: str,
    lines: list[str],
    source: str,
    backup: tuple[str, str, str] | None = None,
) -> str:
    sid = str(record.get("session_id", ""))
    explanation = record.get("explanation") if isinstance(record.get("explanation"), dict) else {}
    undo_of = record.get("undo_of")
    undo_line = (
        f"Undo of: {undo_of}"
        if isinstance(undo_of, str) and _SID_RE.fullmatch(undo_of)
        else None
    )
    applied_at, finished_at = _timestamps(sid)
    name, digest, copy_note = backup if backup is not None else backup_info(state, record, sid)
    word = OUTCOME_WORDS[outcome]
    diff_lines = str(record.get("diff", "")).split("\n")
    removed = sum(1 for l in diff_lines if l.startswith("-"))
    verify = [l for l in lines if l.startswith(("CONFIRMED", "VERIFY", "ROLLBACK", "ALERT", "CONFIRM", "APPLIED"))]
    failed = _explanation.failed_claim(
        "\n".join(lines), sid,
        record.get("probes") if isinstance(record.get("probes"), list) else [],
        explanation.get("expect") if isinstance(explanation.get("expect"), list) else [],
    )
    out = [
        f"# Change receipt: {_clean(record.get('device'), 64)} {sid}",
        "",
        f"Outcome: {word}",
        f"Device: {_clean(record.get('device'), 64)} ({_clean(record.get('host'), 64)})",
        f"Session: {sid}",
        *([undo_line] if undo_line is not None else []),
        f"Plan hash: {_clean(record.get('plan_hash'), 64)}",
        f"Planned: {_clean(record.get('created_at', 'unknown'), 40)}",
        f"Applied: {_clean(applied_at or 'not in the apply output', 40)}",
        f"Finished: {_clean(finished_at or 'not in the apply output', 40)}",
        f"Source of the checks below: {source}",
        "",
        "## Intent",
        "",
        _clean(explanation.get("intent", "(none recorded)"), 300),
        "",
        "## What changed",
        "",
        f"{len(diff_lines)} diff lines, {removed} of them removals. Lines starting with `-` were removed; the rest were set or added.",
        "",
        _block(diff_lines),
        "",
        "## Who approved and how",
        "",
        _approval_text(state, record, sid),
        "",
        "## Checks",
        "",
        _staged_text(record),
        f"Verification: {_probe_names(record)}.",
    ]
    auto = record.get("manifest_checks_auto")
    if isinstance(auto, list) and auto:
        out.append("Touched controls checked: " + ", ".join(_clean(a, 24) for a in auto) + ".")
    claims = _claims_text(record)
    out += ["Agent's claims (checked after apply):"] + (["- " + c for c in claims] if claims else ["- none"])
    if failed:
        out.append(f"FAILED: {_clean(failed['text'], 300)}")
    out += ["", "Script log for this session (masked):", "", _block(verify)]
    out += [
        "",
        "## Backup",
        "",
        f"- File: {name}",
        f"- sha256: {digest or 'not available'}",
        f"- {copy_note}",
        "- The backup holds the router's full config including secrets; keep it private. It is not shown here.",
        "",
        "## How to undo",
        "",
    ]
    if outcome == "rolled_back":
        out.append("Nothing to undo: the router rolled the change back and is at its state before the plan.")
    elif outcome == "unknown":
        out.append(
            "The outcome is not certain. First run `newton_change_status` for this session before anything else. "
            f"If the change turns out to be live and must go, restore backup {name} from a wired client with `sysupgrade -r`."
        )
    else:
        out.append(
            f"The change is live. To go back, restore the backup named above ({name}) from a wired client "
            "with `sysupgrade -r`, or in LuCI under System > Backup. Restoring is a whole-config restore and "
            "also undoes any later change. Config only: packages, passwords, reboots and client leases are not undone."
        )
    return "\n".join(out) + "\n"


def _load_record(state: Path, sid: str) -> dict[str, Any]:
    if not _SID_RE.fullmatch(sid):
        raise ValueError("bad session id")
    data = json.loads((state / "plans" / f"{sid}.json").read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("bad plan record")
    return data


def _safe_dir(path: Path, state: Path) -> bool:
    if _receipts.check_state_write_path(path, state) is not None:
        return False
    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            return False
        if info.st_uid != os.geteuid():
            return False
        fd = os.open(str(path), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            opened = os.fstat(fd)
            if (
                not stat.S_ISDIR(opened.st_mode)
                or opened.st_uid != os.geteuid()
                or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino)
            ):
                return False
            os.fchmod(fd, 0o700)
        finally:
            os.close(fd)
        return True
    except OSError:
        return False


def _copy_backup(state: Path, record: dict[str, Any], sid: str) -> tuple[str, str, str]:
    raw = record.get("backup_path")
    name = _backup_name(record)
    if not isinstance(raw, str) or not raw:
        return name, "", "off-device copy: none (backup was not copied: backup path not recorded)"
    dest_dir = state / RECEIPT_DIR / BACKUP_DIR
    if not _safe_dir(dest_dir, state):
        return name, "", "off-device copy: none (backup was not copied: backup directory was refused)"
    src = Path(raw)
    dest = dest_dir / f"{sid}.tar.gz"
    tmp = dest.with_suffix(".tmp")
    source_fd, reason = _open_backup_source(src)
    if source_fd is None:
        return name, "", f"off-device copy: none (backup was not copied: {reason})"
    try:
        target_fd = os.open(
            str(tmp),
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_NONBLOCK,
            0o600,
        )
        try:
            opened = os.fstat(target_fd)
            if not stat.S_ISREG(opened.st_mode):
                raise OSError("temporary backup is not a regular file")
            os.fchmod(target_fd, 0o600)
            digest, reason = _stream_hash(source_fd, target_fd)
        finally:
            os.close(target_fd)
        if not digest:
            tmp.unlink()
            return name, "", f"off-device copy: none (backup was not copied: {reason})"
        tmp.replace(dest)
        return name, digest, f"off-device copy: receipts/{BACKUP_DIR}/{sid}.tar.gz"
    except OSError:
        try:
            tmp.unlink()
        except OSError:
            pass
        return name, "", "off-device copy: none (backup was not copied: source could not be read)"
    finally:
        os.close(source_fd)


def write_receipt(state: Path, record: dict[str, Any], outcome: str, apply_output: str) -> Path | None:
    """Write the receipt for a finished apply; None when the state dir cannot be trusted."""
    sid = str(record.get("session_id", ""))
    device = str(record.get("device", ""))
    if outcome not in OUTCOME_WORDS or not _SID_RE.fullmatch(sid) or not _DEVICE_RE.fullmatch(device):
        return None
    lines = audit_lines(sid)
    source = "the host audit log"
    if not lines:
        lines = output_lines(sid, apply_output)
        source = "the apply output (the audit log had no lines for this session)"
    directory = state / RECEIPT_DIR
    if not _safe_dir(directory, state):
        return None
    backup = _copy_backup(state, record, sid)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    target = directory / f"{stamp}-{device}-{sid}.md"
    tmp = target.with_suffix(".md.tmp")
    text = render(state, record, outcome, lines, source, backup)
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    os.chmod(tmp, 0o600)
    tmp.replace(target)
    return target


def regenerate(state: Path, sid: str) -> str:
    """Rebuild a receipt's text from the plan record, approval and audit lines alone."""
    record = _load_record(state, sid)
    lines = audit_lines(sid)
    source = "the host audit log"
    if not lines:
        existing = sorted((state / RECEIPT_DIR).glob(f"*-{sid}.md"))
        raise ValueError("no audit lines for this session" + (" (receipt was built from the apply output)" if existing else ""))
    outcome = outcome_from_lines(lines, sid)
    if outcome is None:
        raise ValueError("audit lines name no outcome")
    return render(state, record, outcome, lines, source)
