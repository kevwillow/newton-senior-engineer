"""Which plans need out-of-band approval.

Every change needs the owner to run ``newton-approve`` in their own terminal.
The one exception, and the only place it lives, is the lab carve-out below:
a device that is both flagged ``lab = true`` and set to ``profile = "lab"``
keeps the older rule (approval only when the router or the leash says so), so
automated lab scenarios keep running.  Production devices, and any device that
is not BOTH lab-flagged and lab-profiled, always require approval.

The carve-out is OFF unless the lab turns it on.  It applies only when all of
these hold:

* ``LAB_APPROVAL_CARVEOUT`` is True (the code switch; set it to False and
  every device requires approval);
* the server runs from a source checkout (the lab's dev tree), never from an
  installed (non-editable) build: an installed build refuses the carve-out
  whatever its environment says;
* the environment sets ``NEWTON_LAB_APPROVAL_CARVEOUT=1`` exactly.

A plan the carve-out frees says ``approval: lab carve-out`` in its result.

No lab credential is read or accepted here.  The host never mints or verifies
an approval token; the router checks the token against its own key, and a
production device's key is derived from its own name and passphrase.
"""

from __future__ import annotations

import os
import tomllib
from pathlib import Path
from typing import Any

LAB_APPROVAL_CARVEOUT = True
LAB_SWITCH_ENV = "NEWTON_LAB_APPROVAL_CARVEOUT"
CARVE_OUT_NOTE = "approval: lab carve-out"
_PROJECT_NAME = "newton-mcp"


def running_from_source_checkout(module_file: str | os.PathLike[str] | None = None) -> bool:
    """True when this package is Newton's own source tree, not an installed build.

    A source checkout has Newton's ``pyproject.toml`` (project name
    ``newton-mcp``) next to the package directory.  An installed build sits
    in site-packages, where no such file is; a stray ``pyproject.toml`` of
    another project there does not count.
    """
    path = Path(module_file if module_file is not None else __file__).resolve()
    pyproject = path.parent.parent / "pyproject.toml"
    try:
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
        return False
    project = data.get("project")
    return isinstance(project, dict) and project.get("name") == _PROJECT_NAME


def lab_carve_out_applies(device: Any) -> bool:
    """True when this device may skip approval for a plan nothing else flags."""
    return (
        LAB_APPROVAL_CARVEOUT
        and os.environ.get(LAB_SWITCH_ENV) == "1"
        and getattr(device, "lab", False) is True
        and getattr(device, "profile", "prod") == "lab"
        and running_from_source_checkout()
    )


def plan_requires_approval(device: Any, *, router_requires: bool, policy_requires: bool) -> bool:
    """The approval decision for a plan on ``device``."""
    if lab_carve_out_applies(device):
        return bool(router_requires or policy_requires)
    return True
