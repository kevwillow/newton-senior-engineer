"""The PowerShell the Active Directory tests drive the helpers with.

The path is the one of the machine of the tests, and the environment
variable ``NEWTON_PWSH`` names another one when the tests run somewhere
else.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest


PWSH = Path(os.environ.get("NEWTON_PWSH") or Path.home() / ".local/opt/pwsh-7.4.6/pwsh")


def require_pwsh(path: Path, what: str) -> str:
    """The shell at ``path``, or a failure: the PowerShell tests are a
    release gate, so a missing shell fails them.  Only
    ``NEWTON_PWSH_SKIP=1``, set on purpose on a dev box, makes it a skip.
    """
    if not path.is_file():
        reason = f"PowerShell 7.4 is not installed at {path}: {what} cannot be exercised"
        if os.environ.get("NEWTON_PWSH_SKIP") == "1":
            pytest.skip(reason + " (NEWTON_PWSH_SKIP=1)")
        pytest.fail(
            reason + "; install it, point NEWTON_PWSH at it, or set "
            "NEWTON_PWSH_SKIP=1 on a dev box to skip this gate"
        )
    return str(path)
