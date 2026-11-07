"""the owner-script records on disk, and the scripts they bind.

The approval dialogs (``approve.py``, ``elicit_approval.py``), the
setup CLI (``rpcd_cli.py``) and the read-back (``owner_verify.py``)
all need the same three things: where a plan record lives, where its
script lives, and whether the script on disk is still the one the
record binds.

That check is the point of this module.  A record binds its scripts
through ``router_digest``: the sha256 of the apply script and the
sha256 of the restore script, with the kind in front of each.  A
script that was edited on disk no longer matches, so the owner would be
approving bytes nobody checked.  Every surface that shows a script
checks the digest first and refuses when it does not match.

This module reads files and computes hashes.  It never writes and it
never touches a router.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Mapping

from . import owner_script


class RecordError(Exception):
    """A refusal of a record or of the script it binds.

    The message names a file or a plan, never a value: a script holds
    the router's own values.
    """


#: The directory the owner scripts, their backups and their run records
#: live in, under the state directory.
OWNER_DIR = "owner-scripts"

#: The name of the script inside a plan's directory.
SCRIPT_NAME = "script.sh"

#: The name of the run record inside a plan's directory.
RUN_NAME = "run.json"

#: The leash codes of the two owner-script records.
OWNER_LEASHES = ("owner-script", "owner-script-restore")


def is_owner_record(record: Mapping[str, Any]) -> bool:
    """True when a record is one of the owner-script records."""
    return record.get("router_leash") in OWNER_LEASHES


def plan_path(state: Path, sid: str) -> Path:
    """Where a plan record lives."""
    return Path(state) / "plans" / f"{sid}.json"


def script_path(state: Path, sid: str) -> Path:
    """Where the script of a plan lives."""
    return Path(state) / OWNER_DIR / sid / SCRIPT_NAME


def run_path(state: Path, sid: str) -> Path:
    """Where the run record of a plan lives."""
    return Path(state) / OWNER_DIR / sid / RUN_NAME


def load_record(state: Path, sid: str) -> dict[str, Any]:
    """The plan record of a plan id."""
    try:
        raw = plan_path(state, sid).read_bytes()
    except OSError:
        raise RecordError(f"there is no plan record for {sid}") from None
    try:
        record = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise RecordError(f"the plan record of {sid} cannot be read") from None
    if not isinstance(record, dict):
        raise RecordError(f"the plan record of {sid} cannot be read")
    return record


def read_script(state: Path, sid: str) -> bytes:
    """The script of a plan, byte for byte."""
    try:
        return script_path(state, sid).read_bytes()
    except OSError:
        raise RecordError(f"the script of plan {sid} is missing") from None


def script_sha(state: Path, sid: str) -> str:
    """The sha256 of the script of a plan."""
    return owner_script.script_sha256(read_script(state, sid))


def expected_digest(
    record: Mapping[str, Any], apply_sha: str, restore_sha: str
) -> str:
    """The digest a record binds, from the two script hashes.

    An apply record binds both scripts; a restore record binds only
    the restore script.
    """
    digest = hashlib.sha256()
    if record.get("router_leash") == "owner-script":
        digest.update(b"apply:" + apply_sha.encode("utf-8") + b"\n")
        digest.update(b"restore:" + restore_sha.encode("utf-8") + b"\n")
    else:
        digest.update(b"restore:" + restore_sha.encode("utf-8") + b"\n")
    return digest.hexdigest()


def script_hashes(state: Path, record: Mapping[str, Any]) -> tuple[str, str]:
    """The two script hashes a record binds.

    The apply record binds its own script and the script of the plan
    it restores; a restore record binds only its own.
    """
    sid = str(record.get("session_id", ""))
    own = script_sha(state, sid)
    if record.get("router_leash") == "owner-script":
        other = str(record.get("restore_sid", ""))
        if not other:
            raise RecordError("the plan record names no restore plan")
        return own, script_sha(state, other)
    return own, own


def check_scripts(state: Path, record: Mapping[str, Any]) -> tuple[str, str]:
    """Check the scripts of a record against the digest it binds.

    Returns the two hashes.  Raises ``RecordError`` when a script is
    missing, when it cannot be read, or when the digest does not match:
    the owner must never approve bytes nobody checked.
    """
    apply_sha, restore_sha = script_hashes(state, record)
    digest = expected_digest(record, apply_sha, restore_sha)
    bound = record.get("router_digest")
    if not isinstance(bound, str) or bound != digest:
        raise RecordError(
            "the script of this plan does not match the digest the plan binds; "
            "plan it again"
        )
    declared = record.get("script_sha256")
    if isinstance(declared, str):
        sid = str(record.get("session_id", ""))
        if declared != script_sha(state, sid):
            raise RecordError(
                "the script of this plan does not match the hash the plan "
                "records; plan it again"
            )
    return apply_sha, restore_sha


def read_run(state: Path, sid: str) -> dict[str, Any]:
    """The run record of a plan, or an empty one."""
    try:
        raw = run_path(state, sid).read_bytes()
    except OSError:
        return {}
    try:
        run = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {}
    return run if isinstance(run, dict) else {}


def write_run(state: Path, sid: str, run: Mapping[str, Any]) -> Path:
    """Write the run record of a plan: mode 0600, atomically."""
    directory = Path(state) / OWNER_DIR / sid
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(Path(state) / OWNER_DIR, 0o700)
    os.chmod(directory, 0o700)
    target = directory / RUN_NAME
    payload = json.dumps(dict(run), sort_keys=True).encode("utf-8")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{RUN_NAME}.", dir=directory)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    return target


def grouped_sha(value: str) -> str:
    """A sha256 in groups of eight hex characters, for a human to read."""
    return " ".join(
        value[index:index + 8] for index in range(0, len(value), 8)
    )
