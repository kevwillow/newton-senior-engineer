"""Filesystem checks for the inventory file itself.

``load_inventory`` (server.py) and ``load_vantages`` (scans.py) both
read the same ``devices.toml``.  Before opening it, the loader must
confirm that the path is a regular file (not a symlink), is not group-
or world-writable, and is owned by the user running the MCP server.

The check is intentionally a leaf: no imports from ``server`` or
``scans``, so either side can call it without an import cycle.  Each
loader passes its own exception class and the helper returns the
refusal message (or ``None`` on success); the loader raises.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

# Capture the real ``os.geteuid`` at import time so a later
# ``monkeypatch.setattr(os, "geteuid", ...)`` (which replaces the
# attribute on the ``os`` module) cannot silently change what the
# inventory check sees -- the inventory and the per-device key_file
# check live in different test sites and only one of them should be
# influenced by a given patch.
_geteuid = os.geteuid


def _effective_uid() -> int:
    return _geteuid()


def check(path: Path) -> str | None:
    """Return a refusal message, or ``None`` if the path is acceptable.

    The check uses ``lstat`` so a symlink is rejected without being
    followed.  The mode check refuses any group- or world-writable
    bits; ``0600`` is accepted alongside ``0644`` because the inventory
    file contains only the device table (hostnames, ports, public
    proxy_command strings), not credentials.

    A missing path is *not* a refusal here -- the caller owns the
    "inventory file not found" message so its wording stays the same.
    """
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        return f"inventory file cannot be inspected: {exc.strerror}"
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        return "inventory file must be a regular file, not a symlink"
    if stat.S_IMODE(info.st_mode) & 0o022:
        return f"inventory file must not be group- or world-writable (run: chmod go-w {path})"
    if info.st_uid != _effective_uid():
        return "inventory file must be owned by the user running the MCP server"
    return None