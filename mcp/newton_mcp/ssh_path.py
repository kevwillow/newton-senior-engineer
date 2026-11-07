"""Resolve ``ssh`` to an absolute path without consulting ``PATH``.

Newton's Python code only ever spawns ssh from a small fixed allowlist
(``/usr/bin/ssh`` first, then ``/bin/ssh``).  A fake ``ssh`` placed on
``PATH`` by an operator mistake, an installer, or a hostile
``~/.bashrc`` export must never be reached, so the resolver checks the
two candidates in order and refuses when neither exists.  No
``shutil.which`` and no fall-through to anything else.

The first successful resolution is cached for the rest of the process,
so every spawn site pays one disk lookup at most.  The cache is exposed
so tests can reset it between cases (``reset_cache()`` or the standard
``functools.cache.cache_clear()`` on the function attribute).
"""

from __future__ import annotations

import functools
import os


SSH_CANDIDATES: tuple[str, ...] = ("/usr/bin/ssh", "/bin/ssh")


class SshNotFound(RuntimeError):
    """No installed ssh exists in the small, fixed allowlist."""


@functools.cache
def resolve_ssh() -> str:
    """Return the first ``SSH_CANDIDATES`` entry that is an executable regular file.

    The result is cached on first success; subsequent calls return the
    same value.  A missing candidate is not an error on its own -- only
    a fully empty list (or every candidate failing the X_OK + isfile
    check) raises ``SshNotFound``.
    """
    for candidate in SSH_CANDIDATES:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    raise SshNotFound(
        "ssh not found in /usr/bin/ssh or /bin/ssh; refusing to look it up through PATH"
    )


def reset_cache() -> None:
    """Drop the cached resolution so the next call re-scans the candidates."""
    resolve_ssh.cache_clear()
