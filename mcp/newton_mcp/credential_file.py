"""The one check for a file that holds a credential.

``load_inventory`` (server.py) and the no-install setup CLI
(rpcd_cli.py) both take a password file from the operator.  The rule is
the key_file rule the inventory already enforces: ``lstat`` (a symlink
is not followed), a regular file, mode 0600 and owned by the user
running the process.

The module is a leaf: it imports nothing from ``newton_mcp``, so either
side can call it without an import cycle.  It returns the refusal
message (or ``None`` on success) and the caller raises.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path


def check(path: Path, what: str = "password file") -> str | None:
    """Return a refusal message, or ``None`` when the path is acceptable.

    ``what`` names the file in the message ("password file",
    "rpcd_password_file"), so both callers say the same thing.
    """
    try:
        info = path.lstat()
    except FileNotFoundError:
        return f"{what} not found: {path}"
    except OSError as exc:
        return f"{what} cannot be inspected: {exc.strerror}"
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        return f"{what} must be a regular file, not a symlink"
    if stat.S_IMODE(info.st_mode) != 0o600:
        return f"{what} must have mode 0600"
    if info.st_uid != os.geteuid():
        return f"{what} must be owned by the server user"
    return None
