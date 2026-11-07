"""the host-side backup of a no-install router's readable UCI.

ADR-021 point 7 and the design: before Newton asks the owner to run
a script, Newton keeps a copy of the settings the script touches on the
Newton computer.  That copy is what the read-back compares against and
what the restore script is built from.

What this backup IS, and what it is not:

  * it is a STRUCTURED copy of the sections and options the router's
    own web API answered -- not a byte copy of ``/etc/config``.  The
    rpcd user cannot read those files, so Newton never has them;
  * it has no comments, because the web API does not answer with them;
  * it does not cover ``rpcd``, ``uhttpd`` or ``dropbear``: Newton
    cannot read those configs at all.

The backup holds Wi-Fi keys, so it never leaves this module in a
message, a log line, an audit line or an exception.  Only its name and
its sha256 do.

The files live under ``<state>/owner-scripts/<sid>/backup/``, one
canonical JSON file per config, plus a manifest with the sha256 of
each file.  They stay until the device's ``uninstall`` removes them.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from . import noinstall_read
from . import receipts as _receipts
from . import rpcd_txn
from .adapters import openwrt_rpcd as rpcd
from .adapters.openwrt_rpcd import RpcdCallFailed, RpcdError
from .rpcd_txn import RpcdTransaction


class BackupError(Exception):
    """A refusal of the backup.

    The message names a config or a file, never a value: the backup
    holds Wi-Fi keys.
    """


#: The session a backup asks for: long enough for the reads, short
#: enough that a forgotten session dies on its own.
LOGIN_TIMEOUT_S = 30

#: The directory the owner scripts and their backups live in.
OWNER_DIR = "owner-scripts"

#: The name of the manifest inside a backup directory.
MANIFEST_NAME = "manifest.json"


@dataclass(frozen=True)
class Backup:
    """A structured copy of the readable UCI of one router.

    ``configs`` maps a config name to its sections, and a section name
    to the answer the router gave for it (the ``.type``, the ``.name``,
    the ``.index`` and the options).  A list option is the list the
    router answered.
    """

    configs: dict[str, dict[str, dict[str, Any]]]
    board: str = ""
    sid: str = ""
    missing: tuple[str, ...] = ()

    def with_sid(self, sid: str) -> "Backup":
        """The same backup, bound to a plan id."""
        return replace(self, sid=sid)

    def section(self, config: str, name: str) -> Mapping[str, Any] | None:
        """One section of the backup, or None."""
        sections = self.configs.get(config)
        if not isinstance(sections, Mapping):
            return None
        entry = sections.get(name)
        return entry if isinstance(entry, Mapping) else None


# ---- the taking ------------------------------------------------------------


def _password(device: Any) -> str:
    """The rpcd password, from the device's own password file.

    The password never appears in a message: every failure says what
    went wrong with the FILE, not what is in it.  The rule is the read's own
    (``noinstall_read._password``); this module must not grow a second
    one.
    """
    return noinstall_read._password(device)


def read_config(
    session: Any, config: str
) -> tuple[dict[str, dict[str, Any]] | None, str | None]:
    """One config, or (None, the reason it could not be read).

    This is the ONE rule for what an answer of the router's own web API
    may look like.  The read-back uses it too: an answer this refuses
    is an answer Newton cannot read, and an answer Newton cannot read
    is never a proven absence.
    """
    try:
        answer = session.call("uci", "get", {"config": config})
    except RpcdCallFailed as exc:
        if exc.code == 4:
            return None, "missing"
        return None, "refused"
    except RpcdError:
        return None, "unreachable"
    if not isinstance(answer, Mapping):
        return None, "malformed"
    sections = answer.get("values")
    if not isinstance(sections, Mapping):
        return None, "malformed"
    clean: dict[str, dict[str, Any]] = {}
    for name, entry in sections.items():
        if not isinstance(entry, Mapping):
            return None, "malformed"
        clean[str(name)] = {str(key): value for key, value in entry.items()}
    return clean, None


def _read_board(session: Any) -> str:
    """The board name, or an empty string when it cannot be read."""
    try:
        answer = session.call("system", "board", {})
    except RpcdError:
        return ""
    if not isinstance(answer, Mapping):
        return ""
    name = answer.get("board_name")
    return name if isinstance(name, str) else ""


class _Reader:
    """A limited session's read calls, made through its client."""

    def __init__(self, client: Any, session: Any) -> None:
        self._client = client
        self._session = session

    def call(self, obj: str, fn: str, args: dict[str, Any]) -> Any:
        return self._client.call(self._session, obj, fn, args)


def take(
    client_factory: Callable[[Any], Any],
    device: Any,
    configs: Sequence[str],
    *,
    creates: Sequence[str] = (),
) -> Backup:
    """The backup of the named configs, from one fresh limited session.

    The session is read-only and short.  A window that is open on the
    router refuses the backup: a change that is waiting for
    confirmation means the router is not in the state the plan was made
    against.

    A config the router does not have (the answer ``[4]``) is only
    allowed when the change creates that config's first section;
    otherwise there is nothing to back up and nothing to check.
    """
    wanted = [config for config in dict.fromkeys(configs)]
    if not wanted:
        raise BackupError("there is nothing to back up")
    password = _password(device)
    client = client_factory(device)
    try:
        session = client.login(rpcd.RPCD_USER, password, LOGIN_TIMEOUT_S)
    except RpcdCallFailed:
        raise BackupError("the router refused the login") from None
    except RpcdError:
        raise BackupError("the router could not be reached") from None
    try:
        transaction = RpcdTransaction(client)
        try:
            entries = transaction.pending_entries(session)
        except RpcdError:
            raise BackupError(
                "the pending state of the router cannot be read"
            ) from None
        if entries:
            # An undo file the router forgot about (its web service
            # restarted, measured a4m-02) is still refused, but the
            # message says how the owner gets rid of it.
            age = rpcd_txn.undo_file_age(entries)
            if age is not None and age >= rpcd_txn.LEFTOVER_UNDO_AGE_S:
                raise BackupError(rpcd_txn.leftover_undo_message(age))
            raise BackupError(rpcd_txn.PENDING_WINDOW_MESSAGE)
        # The real RpcdSession has no ``call``: every call goes through
        # the client.
        reader = _Reader(client, session)
        values: dict[str, dict[str, dict[str, Any]]] = {}
        missing: list[str] = []
        for config in wanted:
            sections, problem = read_config(reader, config)
            if problem == "missing":
                if config not in creates:
                    raise BackupError(
                        f"the router has no {config} config and the change does "
                        "not create one: there is nothing to back up"
                    )
                missing.append(config)
                continue
            if problem is not None:
                raise BackupError(f"the {config} config cannot be read from the router")
            assert sections is not None
            values[config] = sections
        board = _read_board(reader)
    finally:
        session.mark_spent()
    return Backup(configs=values, board=board, missing=tuple(missing))


# ---- the writing -----------------------------------------------------------


def _canonical(payload: Any) -> bytes:
    """The one byte form of a JSON document."""
    return json.dumps(
        payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _atomic_write(path: Path, data: bytes) -> None:
    """Write the bytes the way the plan records are written.

    A fresh mkstemp file (mode 0600 from the start, never a fixed name
    an attacker can plant), an fsync, and an atomic replace.
    """
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def backup_dir(state: Path, sid: str) -> Path:
    """The directory a backup of one plan lives in."""
    return Path(state) / OWNER_DIR / sid / "backup"


def write(state: Path, sid: str, backup: Backup) -> dict[str, Any]:
    """Write the backup and its manifest; return the manifest.

    The files are mode 0600 in a mode 0700 directory.  Every file is
    read back and its sha256 compared with the one that was written, so
    a truncated or swapped file is caught here and not at the read-back.
    """
    root = Path(state) / OWNER_DIR / sid
    refusal = _receipts.check_state_write_path(root, Path(state))
    if refusal is not None:
        raise BackupError(refusal)
    directory = backup_dir(state, sid)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    # every directory the backup lives in is private: the backup holds
    # Wi-Fi keys, so a directory that anyone may list is a directory
    # that names them.
    os.chmod(Path(state) / OWNER_DIR, 0o700)
    os.chmod(Path(state) / OWNER_DIR / sid, 0o700)
    os.chmod(directory, 0o700)
    files: dict[str, dict[str, Any]] = {}
    for config, sections in backup.configs.items():
        payload = _canonical({"values": sections})
        target = directory / f"{config}.json"
        _atomic_write(target, payload)
        os.chmod(target, 0o600)
        written = target.read_bytes()
        if _sha256(written) != _sha256(payload):
            raise BackupError(f"the {config} backup could not be written")
        files[config] = {"sha256": _sha256(written), "bytes": len(written)}
    manifest = {
        "sid": sid,
        "board": backup.board,
        "count": len(files),
        "files": files,
        "missing": list(backup.missing),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    payload = _canonical(manifest)
    target = directory / MANIFEST_NAME
    _atomic_write(target, payload)
    os.chmod(target, 0o600)
    if _sha256(target.read_bytes()) != _sha256(payload):
        raise BackupError("the backup manifest could not be written")
    return manifest


def load(state: Path, sid: str) -> Backup:
    """The backup of one plan, with every sha256 checked.

    A file whose sha256 does not match the manifest is refused: the
    read-back compares against this copy, so a changed copy would make
    the read-back prove nothing.
    """
    directory = backup_dir(state, sid)
    manifest_path = directory / MANIFEST_NAME
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        raise BackupError("the backup of this plan is missing") from None
    if not isinstance(manifest, dict) or not isinstance(manifest.get("files"), dict):
        raise BackupError("the backup of this plan is missing")
    values: dict[str, dict[str, dict[str, Any]]] = {}
    for config, entry in manifest["files"].items():
        if not isinstance(entry, dict):
            raise BackupError(f"the {config} backup is not readable")
        path = directory / f"{config}.json"
        try:
            data = path.read_bytes()
        except OSError:
            raise BackupError(f"the {config} backup is missing") from None
        if _sha256(data) != entry.get("sha256"):
            raise BackupError(f"the {config} backup does not match its manifest")
        try:
            answer = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise BackupError(f"the {config} backup is not readable") from None
        sections = answer.get("values") if isinstance(answer, Mapping) else None
        if not isinstance(sections, Mapping):
            raise BackupError(f"the {config} backup is not readable")
        values[str(config)] = {
            str(name): dict(section) for name, section in sections.items()
        }
    board = manifest.get("board")
    missing = manifest.get("missing")
    return Backup(
        configs=values,
        board=board if isinstance(board, str) else "",
        sid=str(manifest.get("sid", sid)),
        missing=tuple(missing) if isinstance(missing, list) else (),
    )
