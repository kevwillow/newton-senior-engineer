"""The Newton side of the guarded Active Directory writes (SPEC-1.4).

The package holds the request contract (``request``), the transport to
the write helper (``transport``), the plan (``plan``), the apply, the
status and the abort (``apply``) and the inventory rules of the write
entries (``inventory``).

Nothing in the package opens a socket by itself: every device call goes
through ``transport``, which uses the locked ssh runner of the
repository.
"""

from __future__ import annotations
