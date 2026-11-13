"""The check modules of the AD audit.

The three modules hold the checks of the catalogue: accounts and
delegation, domain policy, and ACLs.

The submodules import ``Check`` from ``newton_mcp.ad.catalogue`` and the
catalogue imports them back, so the catalogue is imported here first: the
class exists before any submodule body runs, whichever module a caller
imports first.
"""

from __future__ import annotations

from .. import catalogue as _catalogue  # noqa: F401  (breaks the cycle)
from . import accounts  # noqa: F401
from . import acl  # noqa: F401
from . import domain  # noqa: F401

__all__ = ["accounts", "acl", "domain"]
