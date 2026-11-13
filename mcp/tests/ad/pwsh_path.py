"""The PowerShell the Active Directory tests drive the helpers with.

The path is the one of the machine of the tests, and the environment
variable ``NEWTON_PWSH`` names another one when the tests run somewhere
else.
"""

from __future__ import annotations

import os
from pathlib import Path


PWSH = Path(os.environ.get("NEWTON_PWSH") or Path.home() / ".local/opt/pwsh-7.4.6/pwsh")
