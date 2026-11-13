"""The state directory of the AD write path.

The plans, the approvals and the receipts live under the state directory
of Newton, in directories of their own.  Every file is written atomically
and with mode 0600, and the write goes through the state-path check of
the repository, so a plan can never land outside the state directory or
in a place another user may read.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

from ... import receipts as _receipts


#: The plan id of an AD change: 32 lowercase hexadecimal characters.
PLAN_ID_RE = re.compile(r"^[0-9a-f]{32}$")


def state_dir() -> Path:
    """The state directory of Newton."""
    return Path(
        os.environ.get("NEWTON_STATE_DIR", "~/.local/state/newton")
    ).expanduser()


def plans_dir() -> Path:
    """The directory the AD plans live in."""
    return state_dir() / "ad-plans"


def receipts_dir() -> Path:
    """The directory the AD receipts live in."""
    return state_dir() / "ad-receipts"


def _checked_id(plan_id: str) -> str:
    """The plan id, when it may be used as a file name."""
    if not isinstance(plan_id, str) or PLAN_ID_RE.fullmatch(plan_id) is None:
        raise ValueError(
            "the plan id must be 32 lowercase hexadecimal characters"
        )
    return plan_id


def plan_path(plan_id: str) -> Path:
    """The path of one plan."""
    return plans_dir() / f"{_checked_id(plan_id)}.json"


def approval_path(plan_id: str) -> Path:
    """The path of the approval of one plan, beside the plan."""
    return plans_dir() / f"{_checked_id(plan_id)}.approval.json"


def receipt_path(plan_id: str) -> Path:
    """The path of the receipt of one plan."""
    return receipts_dir() / f"{_checked_id(plan_id)}.json"


def write_json(path: Path, value: Any) -> None:
    """Write one JSON file atomically, with mode 0600."""
    refusal = _receipts.check_state_write_path(path, state_dir())
    if refusal is not None:
        raise OSError(refusal)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def read_json(path: Path) -> Any:
    """Read one JSON file."""
    return json.loads(path.read_text(encoding="utf-8"))
