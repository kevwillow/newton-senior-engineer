"""The MCP tools of the AD build (PLAN-1.5 task 8): ``newton_ad_build_plan``,
``newton_ad_build_run`` and ``newton_ad_build_status``.

The plan tool only plans.  Its default mode is ``scripts`` (DESIGN-1.5
"Decided", 2026-11-08: without the owner's opt-in Newton writes the
stages as owner-run scripts): it returns the checked plan and the stages
the owner runs, and no bootstrap, so nothing on a server can take a
request from Newton.  ``mode="agent"`` is build mode: the plan is stored
for ``newton-approve ad-build`` and each server's bootstrap is written
under the state directory (mode 0600) for the owner to run.  No tool
approves anything: approvals are ``newton-approve`` in the owner's
terminal.

Every string a helper answered (a code, a check's name or detail) is
inside an untrusted-device-data envelope in what these tools return.
"""

from __future__ import annotations

import json
import secrets
from collections.abc import Mapping
from typing import Any

from ... import approve as _approve
from ... import envelope as _envelope
from . import bootstrap as _bootstrap
from . import plan as _plan
from . import run as _run

#: The modes of the plan tool.
MODES: tuple[str, ...] = ("scripts", "agent")


class BuildToolError(Exception):
    """A refusal the model may read: fixed words, no caller or device text."""


def _find_run_of(digest: str) -> str | None:
    """The run id of the stored plan whose digest is ``digest``: a resume
    plan keeps the run of the plan it continues (the helper's journal holds
    one run)."""
    directory = _approve.build_plan_dir()
    if not directory.is_dir():
        return None
    for path in sorted(directory.glob("*.json")):
        name = path.name[: -len(".json")]
        if _approve.PLAN_ID_RE.fullmatch(name) is None:
            continue
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
            if _plan.digest(record) != digest:
                continue
        except (OSError, ValueError, _plan.BuildPlanRefused):
            continue
        try:
            state = _approve._load_build_run_state(name)
        except _approve.ApprovalRefused:
            return name
        run = state.get("run", name)
        return run if isinstance(run, str) and _approve.PLAN_ID_RE.fullmatch(run) else name
    return None


def _stages(built: Mapping[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for server in built["servers"]:
        for stage in _plan.stage_graph(built, server):
            out.append({"device": server["device"], "stage": stage, "kind": _plan.STAGE_KINDS[stage]})
    return out


def installed_write_helper_sha256() -> str:
    """The sha256 of the 1.4 write helper of the installed Newton: the
    bytes stage 8 installs (the maintainer's decision R1, 2026-11-15)."""
    import hashlib

    from .. import setupgen_write as _setupgen_write

    try:
        return hashlib.sha256(_setupgen_write.WRITE_HELPER_PATH.read_bytes()).hexdigest()
    except OSError:
        raise BuildToolError("the installed Newton holds no write helper for stage 8") from None


def _with_installed_write_helper(inputs: Mapping[str, Any]) -> dict[str, Any]:
    """The inputs with ``ops.write_helper_sha256`` the installed Newton's.

    The model names the newton-ops public key; the sha256 of the write
    helper is the installed one's, filled in here, and a value the model
    gave that is not it is refused (the stage would refuse those bytes)."""
    out = dict(inputs)
    ops = inputs.get("ops")
    if not isinstance(ops, Mapping):
        return out
    installed = installed_write_helper_sha256()
    given = ops.get("write_helper_sha256", installed)
    if given != installed:
        raise BuildToolError("the write helper sha256 is not the installed Newton's")
    out["ops"] = dict(ops, write_helper_sha256=installed)
    return out


def _plan_of(digest: str) -> Mapping[str, Any] | None:
    """The stored plan whose digest is ``digest``, or None."""
    directory = _approve.build_plan_dir()
    if not directory.is_dir():
        return None
    for path in sorted(directory.glob("*.json")):
        name = path.name[: -len(".json")]
        if _approve.PLAN_ID_RE.fullmatch(name) is None:
            continue
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
            if _plan.digest(record) == digest:
                return record
        except (OSError, ValueError, _plan.BuildPlanRefused):
            continue
    return None


def _with_secrets_from(inputs: Mapping[str, Any], mode: str) -> dict[str, Any]:
    """The inputs with the salt of the build's derived secrets (DESIGN-1.5
    open point 71): a resume plan keeps the DSRM and the admin password of
    the build's first plan, so its ``secrets_from`` is the one of the plan it
    resumes, or that plan's own digest when it is the first.  It comes from
    the plans on record, never from the model: a value the model gave that
    is not it is refused.  A script-tier resume of a plan that is not on
    record keeps the value given (the plan model checks its grammar)."""
    out = dict(inputs)
    resume_from = inputs.get("resume_from")
    if not isinstance(resume_from, str):
        return out
    resumed = _plan_of(resume_from)
    if resumed is None:
        if mode == "agent":
            raise BuildToolError("the plan it resumes is not on record")
        return out
    expected = resumed.get("secrets_from", resume_from)
    given = inputs.get("secrets_from", expected)
    if given != expected:
        raise BuildToolError("secrets_from is not the digest of the build's first plan on record")
    out["secrets_from"] = expected
    return out


def plan_build(inputs: Any, mode: str = "scripts") -> dict[str, Any]:
    """Plan one build."""
    if mode not in MODES:
        raise BuildToolError("mode must be scripts or agent")
    if not isinstance(inputs, Mapping):
        raise BuildToolError("inputs must be an object")
    inputs = _with_installed_write_helper(inputs)
    inputs = _with_secrets_from(inputs, mode)
    try:
        built = _plan.plan_build(inputs)
        digest = _plan.digest(built)
    except _plan.BuildPlanRefused as exc:
        raise BuildToolError(f"the plan was refused: {exc.code}") from None
    if mode == "scripts":
        return {
            "result": "ok",
            "mode": "scripts",
            "digest": digest[:12],
            "plan": built,
            "stages": _stages(built),
            "bootstrap": None,
            "scripts": [],
            "note": (
                "script tier: the owner runs each stage on the server; no "
                "bootstrap is made, so no server takes a request from Newton. "
                "The owner-run stage scripts are not rendered by this build yet."
            ),
        }
    plan_id = secrets.token_hex(16)
    run = plan_id
    if "resume_from" in built:
        found = _find_run_of(built["resume_from"])
        if found is None:
            raise BuildToolError("the plan it resumes is not on record")
        run = found
    try:
        _approve._atomic_write(_approve.build_plan_path(plan_id), built)
        _approve._atomic_write(
            _approve.build_run_state_path(plan_id),
            {"plan_id": plan_id, "plan_digest": digest, "run": run, "state": "planned", "servers": {}},
        )
        bootstraps: dict[str, str] = {}
        for server in built["servers"]:
            text = _bootstrap.render_bootstrap(built, server)
            path = _approve.build_plan_dir() / f"{plan_id}.bootstrap-{server['device']}.ps1"
            _write_private(path, text)
            bootstraps[server["device"]] = str(path)
    except _bootstrap.BootstrapRefused as exc:
        raise BuildToolError(f"the bootstrap was refused: {exc.code}") from None
    except OSError:
        raise BuildToolError("the plan could not be written under the state directory") from None
    return {
        "result": "ok",
        "mode": "agent",
        "plan_id": plan_id,
        "digest": digest[:12],
        "plan": built,
        "stages": _stages(built),
        "bootstrap": bootstraps,
        "next": _approve.build_plan_approve_command(plan_id),
        "note": (
            "build mode: the owner runs each bootstrap on its server, at the "
            "server's console or in an interactive ssh session (ssh -tt) "
            "because it asks for the passphrase. Before stage 0, set the "
            "server's DNS client to a resolver that answers before stage 0 "
            "(stage 0 refuses a DNS check that gets no answer). Then the "
            "owner approves the plan in a terminal with the command in `next`; this "
            "tool approves nothing."
        ),
    }


def _write_private(path: Any, text: str) -> None:
    import os

    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(text)


def _wrap(source: str, value: Any) -> Any:
    return _envelope.envelope(source, value if isinstance(value, str) else "")


def render_state(plan_id: str, state: Mapping[str, Any]) -> dict[str, Any]:
    """The run state for the model: helper text inside envelopes."""
    source = f"ad-build:{plan_id}"
    out: dict[str, Any] = {
        "result": "ok",
        "plan_id": plan_id,
        "state": state.get("state"),
        "stage": state.get("stage", ""),
        "device": state.get("device", ""),
        "reason": _wrap(source, state.get("reason", "")),
        "detail": _wrap(source, state.get("detail", "")),
        "finished": state.get("finished", {}),
    }
    if state.get("state") == _run.STOPPED_FOR_APPROVAL and isinstance(state.get("stage"), str):
        out["next"] = _approve.build_stage_approve_command(plan_id, state["stage"])
        out["checkpoints"] = {
            device: {
                "stage": entry.get("stage"),
                "kind": entry.get("checkpoint_kind"),
                "name": _wrap(source, (entry.get("checkpoint") or {}).get("name", "")),
            }
            for device, entry in (state.get("servers") or {}).items()
            if isinstance(entry, dict) and entry.get("state") == _run.STOPPED_FOR_APPROVAL
        }
    receipts = []
    for receipt in (state.get("receipts") or [])[-20:]:
        if not isinstance(receipt, dict):
            continue
        receipts.append(
            {
                "device": receipt.get("device"),
                "stage": receipt.get("stage"),
                "action": receipt.get("action"),
                "status": _wrap(source, receipt.get("status") or ""),
                "code": _wrap(source, receipt.get("code") or ""),
                "checks": [
                    {"name": _wrap(source, c.get("name", "")), "ok": c.get("ok") is True, "detail": _wrap(source, c.get("detail", ""))}
                    for c in receipt.get("checks", []) or []
                    if isinstance(c, dict)
                ],
            }
        )
    out["receipts"] = receipts
    return out


def run(plan_id: str) -> dict[str, Any]:
    if not isinstance(plan_id, str) or _approve.PLAN_ID_RE.fullmatch(plan_id) is None:
        raise BuildToolError("plan_id must be 32 lowercase hexadecimal characters")
    return render_state(plan_id, _run.run_build(plan_id))


def status(plan_id: str) -> dict[str, Any]:
    if not isinstance(plan_id, str) or _approve.PLAN_ID_RE.fullmatch(plan_id) is None:
        raise BuildToolError("plan_id must be 32 lowercase hexadecimal characters")
    return render_state(plan_id, _run.run_status(plan_id))
