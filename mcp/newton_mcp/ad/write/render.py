"""The rendering of the AD write results for the model.

Every string the directory gave goes through the untrusted envelope and
through the redactor, exactly as the strings of the audit do: the model
reads them as data and never as an instruction.

The values Newton chose itself (the plan id, the verb, the risk, the
window, the name of a DC) stay plain: they are not directory strings.
"""

from __future__ import annotations

from typing import Any, Mapping

from ... import envelope as _envelope
from ... import redact as _redact


#: The source of the envelopes of the write results.
ENVELOPE_SOURCE = "ad:write"


def wrap(text: str) -> dict[str, str]:
    """One directory string in the untrusted envelope."""
    result = _envelope.sanitise(
        ENVELOPE_SOURCE,
        text,
        redact=_redact.redact_text,
    )
    return result.envelope


def values(values: Mapping[str, Any]) -> dict[str, Any]:
    """Every string of an object in the envelope; the ints stay ints."""
    return {
        key: wrap(value) if isinstance(value, str) else value
        for key, value in values.items()
    }


def plan(plan: Mapping[str, Any]) -> dict[str, Any]:
    """The plan of a change, for the model."""
    return {
        "result": "ok",
        "plan_id": plan["plan_id"],
        "txid": plan["txid"],
        "device": plan["device"],
        "verb": plan["verb"],
        "risk": plan["risk"],
        "window": plan["window"],
        "target": values(plan["target"]),
        "before": values(plan["before"]),
        "after": values(plan["after"]),
        # The DC names are inventory names and the warning is Newton's
        # own text: neither comes from the directory.
        "dcs": [str(name) for name in plan.get("dcs", [])],
        "warning": str(plan.get("warning", "")),
    }


def applied(result: Mapping[str, Any]) -> dict[str, Any]:
    """The result of an apply, a status or an abort, for the model."""
    out: dict[str, Any] = {
        "result": result.get("result", "ok"),
        "plan_id": result.get("plan_id"),
        "txid": result.get("txid"),
        "state": result.get("state"),
    }
    code = result.get("code")
    if isinstance(code, str):
        out["code"] = wrap(code)
    if "undo_at" in result:
        undo_at = result["undo_at"]
        is_int = isinstance(undo_at, int) and not isinstance(undo_at, bool)
        out["undo_at"] = undo_at if is_int else None
    if "restored" in result:
        restored = result["restored"]
        out["restored"] = restored if isinstance(restored, bool) else None
    if "conflicts" in result:
        # The names of the conflicts come from the directory: every one
        # goes into the envelope, whatever its type.
        conflicts = result["conflicts"]
        if isinstance(conflicts, list):
            out["conflicts"] = [wrap(str(one)) for one in conflicts]
        else:
            out["conflicts"] = None
    message = result.get("message")
    if isinstance(message, str):
        # Newton's own text (apply.CONFIRMED_ABORT_MESSAGE), never the directory's
        out["message"] = message
    dcs = result.get("dcs")
    if isinstance(dcs, dict):
        rendered: dict[str, Any] = {}
        for name, one in dcs.items():
            if not isinstance(one, dict):
                rendered[name] = one
                continue
            entry: dict[str, Any] = {"state": one.get("state")}
            live = one.get("live")
            if isinstance(live, dict):
                entry["live"] = values(live)
            rendered[name] = entry
        out["dcs"] = rendered
    return out
