"""Which plans need out-of-band approval.

Every change needs the owner to run ``newton-approve`` in their own terminal.
The one exception, and the only place it lives, is the lab carve-out below:
a device that is both flagged ``lab = true`` and set to ``profile = "lab"``
keeps the older rule (approval only when the router or the leash says so), so
automated lab scenarios keep running.  Production devices, and any device that
is not BOTH lab-flagged and lab-profiled, always require approval.

The carve-out is PENDING the maintainer's confirmation (adr-ex3-proposal.md).  To remove
it, set ``LAB_APPROVAL_CARVEOUT = False``; every device then requires approval
and nothing else changes.

No lab credential is read or accepted here.  The host never mints or verifies
an approval token; the router checks the token against its own key, and a
production device's key is derived from its own name and passphrase.
"""

from __future__ import annotations

from typing import Any

LAB_APPROVAL_CARVEOUT = True


def lab_carve_out_applies(device: Any) -> bool:
    """True when this device may skip approval for a plan nothing else flags."""
    return (
        LAB_APPROVAL_CARVEOUT
        and getattr(device, "lab", False) is True
        and getattr(device, "profile", "prod") == "lab"
    )


def plan_requires_approval(device: Any, *, router_requires: bool, policy_requires: bool) -> bool:
    """The approval decision for a plan on ``device``."""
    if lab_carve_out_applies(device):
        return bool(router_requires or policy_requires)
    return True
