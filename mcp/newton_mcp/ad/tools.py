"""The two MCP tools of the Active Directory audit (SPEC-1.3 section 9).

The audit is read-only and it is one chain: the collector document is
fetched over ssh, validated against the collector contract, run over
by the catalogue, and rendered for the model.  Every step that fails
refuses with a fixed message: nothing of the device ever reaches a log
or a model.

The tools read ``catalogue.CHECKS`` at call time, so the checks in
the catalogue are the checks that run.
"""

from __future__ import annotations

from typing import Any, NoReturn

from . import catalogue, queryset, render, runner, transport, wire


# The platforms an AD device may have.  The names are the inventory
# platform names, so the owner can match a check against a device.
PLATFORMS: tuple[str, ...] = ("ad-windows", "ad-samba")

# The checks the spec defers to the change release (SPEC-1.3 section 8),
# spelled as the spec spells them.
DEFERRED: tuple[str, ...] = (
    "15",
    "28",
    "29",
    "39-42",
    "47",
    "49",
    "50",
    "54 (file half)",
    "56",
    "58",
    "59",
    "61-66",
    "67 (host half)",
    "68-80",
    "82",
    "83",
    "AD CS",
)


def _error(message: str) -> NoReturn:
    """Refuse with a message the model may read."""
    from ..server import NewtonError

    raise NewtonError(message)


def select_checks(
    checks: list[str] | None,
) -> list[catalogue.Check] | None:
    """The checks the caller asked for, or every check of the catalogue.

    An id the catalogue does not hold is a refusal.  The message says
    how many ids were not known and names none of them: the ids are
    caller text and never reach a message.
    """
    if checks is None:
        return None
    if not isinstance(checks, list) or any(type(one) is not str for one in checks):
        _error("checks must be a list of check ids")
    known = {check.id: check for check in catalogue.CHECKS}
    selected: list[catalogue.Check] = []
    unknown = 0
    for check_id in checks:
        check = known.get(check_id)
        if check is None:
            unknown += 1
            continue
        if check not in selected:
            selected.append(check)
    if unknown:
        _error(f"{unknown} of {len(checks)} check ids are not known")
    return selected


def audit(device: Any, checks: list[str] | None = None) -> dict[str, Any]:
    """Run the audit on one AD device and return the rendered report.

    The device must be an AD device: the server resolves it through the
    capability gate before this runs.
    """
    selected = select_checks(checks)
    try:
        raw = transport.fetch(device)
    except transport.AdTransportError as exc:
        _error(str(exc))
    try:
        document = wire.parse(raw, queryset.load())
    except wire.WireError as exc:
        _error(str(exc))
    try:
        report = runner.run(document, device.platform, checks=selected)
    except (runner.PrivilegedKey, runner.CollectorMismatch) as exc:
        _error(str(exc))
    try:
        rendered = render.render(report)
    except render.RenderError:
        _error("the report could not be rendered safely")
    return {"result": "ok", **rendered}


def list_checks() -> dict[str, Any]:
    """The catalogue of the audit and the deferred list of the spec."""
    return {
        "result": "ok",
        "checks": [
            {
                "id": check.id,
                "title": check.title,
                "severity": check.severity.value,
                "platforms": list(getattr(check, "platforms", PLATFORMS)),
            }
            for check in catalogue.CHECKS
        ],
        "deferred": list(DEFERRED),
    }
