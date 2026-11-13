"""The check catalogue: the checks the runner runs.

A check is a pure function.  It reads the collector document and returns
a ``CheckResult``; it never opens a socket, never runs a command and
never writes to the directory.

A check also declares what it needs, so the runner can prove that the
audit was allowed to see the data before the check runs:

- ``queries``: the queries the check reads;
- ``lookups``: the queries the check reads only to resolve principals
  and memberships (the users, computers, groups and foreign principals
  of ``members.Directory``).  The runner proves their status, their
  emptiness and their sentinel as it does for ``queries``; the required
  attributes are about the rows of ``queries`` only, because a
  foreign principal carries no account name;
- ``files``: the file sections of the document the check reads (``gpp``
  and ``gpttmpl``); a section whose status is not ``ok`` makes the check
  UNKNOWN with the reason of that status;
- ``sentinels``: the queries whose sentinel rule the check depends on (a
  sentinel that fails means the collector could not read what an
  ordinary read must return, so the check is UNKNOWN and never PASS);
- ``required_attrs``: the attributes every readable object always has; a
  row without one of them makes the check UNKNOWN too.

The checks live in the three modules under ``checks/`` (accounts,
domain and ACL); ``CHECKS`` below joins them in that order.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .model import CheckResult, Fix, Severity
from .wire import Document


@dataclass(frozen=True)
class Check:
    """One check of the catalogue."""

    id: str
    title: str
    severity: Severity
    evaluate: Callable[[Document], CheckResult]
    queries: tuple[str, ...] = ()
    lookups: tuple[str, ...] = ()
    files: tuple[str, ...] = ()
    required_attrs: tuple[str, ...] = ()
    sentinels: tuple[str, ...] = ()
    maps_to: tuple[str, ...] = ()
    fix: Fix | None = None
    # The inventory platforms the check runs on.  The default is both
    # AD platforms; a check that only one of them can answer says so.
    platforms: tuple[str, ...] = ("ad-windows", "ad-samba")


# The catalogue is the three modules of the checks, in the order of the
# spec: accounts, domain, ACLs.  The import is at the bottom of this
# module on purpose: the check modules import ``Check`` from here, so the
# class has to exist before their bodies run.
from .checks import accounts as _accounts  # noqa: E402
from .checks import acl as _acl  # noqa: E402
from .checks import domain as _domain  # noqa: E402

CHECKS: list[Check] = [
    *_accounts.CHECKS,
    *_domain.CHECKS,
    *_acl.CHECKS,
]
