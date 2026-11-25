"""Stage 10 of an AD build, the acceptance (the maintainer's decision R2, 2026-11-15;
DESIGN-1.5 "Decided" and the stage table, row 10).

Stage 10 reads through the read-only ``newton-audit`` login of the 1.3
collector: not newton-ops (stage 8's write login) and not the build helper
(stage 9 removed it).  The read is the chain of the 1.3 audit tool
(``newton_mcp.ad.tools.audit``): the collector document over the locked ssh
session, ``wire.parse`` against the query set, ``runner.run`` with its
identity guard (a privileged audit key stops it), and the catalogue.  From
that one document the acceptance answers:

- ``build_account``: ``present`` when the users query holds a
  ``sAMAccountName`` that is ``newton-build`` (case-folded, as the
  directory compares it), else ``absent``;
- ``findings``: the ids of the checks that answered FINDING;
- ``unknown``: the ids of the checks that could not prove anything
  (UNKNOWN).

A read that cannot prove the build account's absence is never ``absent``:
a session that failed, a document that is not the collector's, another
domain's document, a users query that is not ``ok`` or a privileged audit
key raise ``AcceptanceUnavailable`` (the runner stops
``acceptance_unavailable``).  Nothing of the device reaches a message: the
messages are fixed words.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .. import queryset as _queryset
from .. import runner as _audit_runner
from .. import transport as _ad_transport
from .. import wire as _wire
from ..model import Status

#: The build account (``bootstrap.BUILD_USER``).
BUILD_ACCOUNT = "newton-build"

#: The 1.3 collector's account (``setupgen``): the audit login.
AUDIT_ACCOUNT = "newton-audit"

#: The platform of the 1.3 Windows collector.
AUDIT_PLATFORM = "ad-windows"

#: The wait of the stage 9 cleanup task before its deletions
#: (``build.ps1`` CleanupDelaySeconds): the runner's wait for the account to
#: go must be longer than it (``run.ACCEPTANCE_WAIT_S``).
CLEANUP_DELAY_S = 15


class AcceptanceUnavailable(Exception):
    """The newton-audit read could not prove anything.  The message is fixed
    and holds no device text."""


@dataclass(frozen=True)
class AuditTarget:
    """The newton-audit login of DC1, as the owner's build config names it.

    It has the fields ``SshSessionRunner`` reads; the user is the 1.3
    collector's account of the plan's domain (``with_domain``)."""

    host: str
    port: int
    key_file: Path
    known_hosts: Path
    user: str = AUDIT_ACCOUNT
    name: str = "ad-build-audit"
    platform: str = AUDIT_PLATFORM
    auth: str = "key"
    password_file: Path | None = None
    proxy_command: str | None = None

    def with_domain(self, dns_name: str) -> "AuditTarget":
        return AuditTarget(
            host=self.host,
            port=self.port,
            key_file=self.key_file,
            known_hosts=self.known_hosts,
            user=f"{AUDIT_ACCOUNT}@{dns_name}",
        )


def _fetch(target: Any) -> bytes:
    """The collector document of the newton-audit login (the 1.3 fetch)."""
    return _ad_transport.fetch(target)


def read_acceptance(raw: bytes, built: Mapping[str, Any]) -> dict[str, Any]:
    """The acceptance read of one collector document of the plan's domain."""
    try:
        document = _wire.parse(raw, _queryset.load())
    except _wire.WireError:
        raise AcceptanceUnavailable("the newton-audit document is not a collector document") from None
    domain = built.get("domain")
    dns_name = domain.get("dns_name") if isinstance(domain, Mapping) else None
    if not isinstance(dns_name, str) or document.domain.dns.casefold() != dns_name.casefold():
        raise AcceptanceUnavailable("the newton-audit document is of another domain")
    users = document.queries.get("users")
    if users is None or users.status != "ok":
        raise AcceptanceUnavailable("the newton-audit document holds no readable users query")
    present = False
    for row in users.rows:
        for name in row.a.get("sAMAccountName", ()):
            if isinstance(name, str) and name.casefold() == BUILD_ACCOUNT:
                present = True
    try:
        report = _audit_runner.run(document, AUDIT_PLATFORM)
    except (_audit_runner.PrivilegedKey, _audit_runner.CollectorMismatch):
        raise AcceptanceUnavailable("the newton-audit read was refused by the audit's own guards") from None
    findings = sorted({result.check_id for result in report.results if result.status == Status.FINDING})
    unknown = sorted({result.check_id for result in report.results if result.status == Status.UNKNOWN})
    return {"build_account": "present" if present else "absent", "findings": findings, "unknown": unknown}


def audit_acceptance(
    target: AuditTarget,
    *,
    fetch: Callable[[Any], bytes] | None = None,
) -> Callable[[Mapping[str, Any], Mapping[str, Any]], dict[str, Any]]:
    """The acceptance callable of the runner (``run.Acceptance``): one
    newton-audit read of DC1 each call."""

    def accept(built: Mapping[str, Any], server: Mapping[str, Any]) -> dict[str, Any]:
        domain = built.get("domain")
        dns_name = domain.get("dns_name") if isinstance(domain, Mapping) else None
        if not isinstance(dns_name, str) or server.get("role") != "dc1":
            raise AcceptanceUnavailable("stage 10 reads DC1 of the plan's domain")
        reader = fetch if fetch is not None else _fetch
        try:
            raw = reader(target.with_domain(dns_name))
        except (_ad_transport.AdTransportError, OSError):
            raise AcceptanceUnavailable("the newton-audit login did not answer") from None
        return read_acceptance(raw, built)

    return accept
