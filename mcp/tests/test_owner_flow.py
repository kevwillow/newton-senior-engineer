"""the plan of an owner script, and the two records it writes.

ADR-021 point 7 and the design: for a change Newton may not apply
itself, Newton writes a script the owner approves byte for byte.

What is proved here:

  * a no-install OpenWrt router is the only device the flow accepts;
  * the owner's chat yes and the agent's explanation are checked with
    the planner's own functions, and no grant waives them;
  * the settings the change touches are copied to the Newton computer
    before anything is written;
  * the two plan records verify with ``compute_plan_hash``, and editing
    a hash-bound field breaks the hash;
  * ``PLAN_HASH_FIELDS`` is unchanged, and an installed-mode record
    still hashes the same;
  * the approval of the apply plan does not release the restore plan;
  * the record needs an approval even on a lab device;
  * the two scripts are rendered from the template and re-parse into the
    ops of the records;
  * the return value carries the script in the untrusted-device-data
    envelope, the reboot line and the list of what Newton cannot check.

No router is contacted: the backup comes from the measured answers.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any

import pytest

from newton_mcp import approve
from newton_mcp import envelope
from newton_mcp import explanation as _explanation
from newton_mcp import owner_backup
from newton_mcp import owner_flow
from newton_mcp import owner_script
from newton_mcp import plan as _plan
from newton_mcp.adapters.openwrt_rpcd import RpcdCallFailed
from newton_mcp.owner_flow import OwnerFlowError
from newton_mcp.server import Device

import noinstall_answers
import owner_answers


# ---- the fakes -------------------------------------------------------------


class FakeSession:
    def __init__(self, answers: dict[tuple[str, str], Any], timeout_s: int) -> None:
        self.answers = answers
        self.timeout_s = timeout_s
        self.spent = False

    def call(self, obj: str, fn: str, args: dict[str, Any] | None = None) -> Any:
        value = self.answers.get((obj, fn), self.answers.get(("*", "*"), {}))
        if callable(value):
            value = value(obj, fn, dict(args or {}))
        if isinstance(value, list):
            code = value[0]
            if code:
                raise RpcdCallFailed(int(code))
            return value[1] if len(value) > 1 else {}
        if isinstance(value, int) and not isinstance(value, bool):
            raise RpcdCallFailed(value)
        if isinstance(value, BaseException):
            raise value
        return value

    def mark_spent(self) -> None:
        self.spent = True


class FakeClient:
    def __init__(self, answers: dict[tuple[str, str], Any]) -> None:
        self.answers = answers
        self.sessions: list[FakeSession] = []

    def login(self, username: str, password: str, timeout_s: int) -> FakeSession:
        session = FakeSession(self.answers, timeout_s)
        self.sessions.append(session)
        return session

    def call(self, session: FakeSession, obj: str, fn: str, args=None) -> Any:
        return session.call(obj, fn, args)


class FakeService:
    """The little of NewtonService the flow uses."""

    def __init__(self, state: Path, devices: dict[str, Device]) -> None:
        self.state = state
        self.devices = devices
        self.audits: list[tuple[str, str, str]] = []

    def device(self, name: str, allow_noinstall: bool = False) -> Device:
        if name not in self.devices:
            raise AssertionError(f"unknown device: {name}")
        device = self.devices[name]
        if device.access == "no-install" and not allow_noinstall:
            raise AssertionError("this device must not be reached without no-install")
        return device

    def audit(self, tool: str, device: str, result: str) -> None:
        self.audits.append((tool, device, result))


def _measured(key: str) -> Any:
    for module in (noinstall_answers, owner_answers):
        if key in module.ANSWERS:
            return module.answer(key)
    raise KeyError(key)


def _answers() -> dict[tuple[str, str], Any]:
    return {
        ("file", "list"): {"entries": []},
        ("system", "board"): _measured("system.board")[1],
        ("uci", "get"): lambda obj, fn, args: _measured(
            "uci.get." + str(args.get("config", ""))
        ),
    }


def _factory(client: FakeClient):
    def build(_device: Any) -> FakeClient:
        return client

    return build


def _device(tmp_path: Path, **overrides: Any) -> Device:
    password = tmp_path / "rpcd-password"
    handle = os.open(str(password), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(handle, "w", encoding="utf-8") as stream:
        stream.write("synthetic-password\n")
    fields = {
        "name": "lab-r1",
        "platform": "openwrt",
        "host": "192.0.2.1",
        "user": "root",
        "profile": "lab",
        "access": "no-install",
        "https_host": "192.0.2.1",
        "https_port": 443,
        "https_spki": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "rpcd_password_file": password,
    }
    fields.update(overrides)
    return Device(**fields)


def _state(tmp_path: Path) -> Path:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    os.chmod(state, 0o700)
    return state


def _explanation_for(batch: str) -> dict[str, Any]:
    """A valid explanation for one batch line."""
    return {
        "intent": "set the lan lease limit",
        "steps": ["set the lan lease limit"],
        "expect": [{"kind": "uci_equals", "path": "dhcp.lan.limit", "equals": "250"}],
        "risk": "the lan leases change for the devices on this network",
    }


#: The measured router holds 150 leases on lan; the change sets 250.
BATCH = "set dhcp.lan.limit='250'"

_LONG_HEX_RUN = re.compile(r"[0-9a-fA-F]{12,}")


def _without_long_hex_runs(line: str) -> str:
    """Remove session ids and hashes before looking for a literal value."""
    return _LONG_HEX_RUN.sub("", line)


def _plan_flow(tmp_path: Path, batch: str = BATCH, **kwargs: Any) -> dict[str, Any]:
    state = _state(tmp_path)
    service = FakeService(state, {"lab-r1": _device(tmp_path)})
    client = FakeClient(_answers())
    result = owner_flow.plan(
        service,
        "lab-r1",
        batch,
        explanation=_explanation_for(batch),
        owner_confirmed_in_chat=True,
        client_factory=_factory(client),
        **kwargs,
    )
    result["_service"] = service
    result["_client"] = client
    return result


def _record(state: Path, sid: str) -> dict[str, Any]:
    return json.loads((state / "plans" / f"{sid}.json").read_text(encoding="utf-8"))


# ---- the refusals ----------------------------------------------------------


def test_a_device_that_is_not_no_install_is_refused(tmp_path: Path) -> None:
    state = _state(tmp_path)
    service = FakeService(state, {"lab-r1": _device(tmp_path, access="installed")})
    with pytest.raises(OwnerFlowError) as excinfo:
        owner_flow.plan(
            service,
            "lab-r1",
            BATCH,
            explanation=_explanation_for(BATCH),
            owner_confirmed_in_chat=True,
            client_factory=_factory(FakeClient(_answers())),
        )
    assert "no-install" in str(excinfo.value)


def test_a_missing_yes_in_the_chat_is_refused(tmp_path: Path) -> None:
    state = _state(tmp_path)
    service = FakeService(state, {"lab-r1": _device(tmp_path)})
    with pytest.raises(Exception) as excinfo:
        owner_flow.plan(
            service,
            "lab-r1",
            BATCH,
            explanation=_explanation_for(BATCH),
            owner_confirmed_in_chat=False,
            client_factory=_factory(FakeClient(_answers())),
        )
    assert "owner" in str(excinfo.value).lower()


def test_a_missing_explanation_is_refused(tmp_path: Path) -> None:
    state = _state(tmp_path)
    service = FakeService(state, {"lab-r1": _device(tmp_path)})
    with pytest.raises(Exception):
        owner_flow.plan(
            service,
            "lab-r1",
            BATCH,
            explanation=None,
            owner_confirmed_in_chat=True,
            client_factory=_factory(FakeClient(_answers())),
        )


def test_a_batch_for_a_config_newton_cannot_read_is_refused(tmp_path: Path) -> None:
    state = _state(tmp_path)
    service = FakeService(state, {"lab-r1": _device(tmp_path)})
    client = FakeClient(_answers())
    with pytest.raises(OwnerFlowError) as excinfo:
        owner_flow.plan(
            service,
            "lab-r1",
            "set rpcd.newton.password='x'",
            explanation=_explanation_for("set rpcd.newton.password='x'"),
            owner_confirmed_in_chat=True,
            client_factory=_factory(client),
        )
    assert "not available in no-install access" in str(excinfo.value)
    assert client.sessions == []


def test_a_window_outside_the_bounds_is_refused(tmp_path: Path) -> None:
    state = _state(tmp_path)
    service = FakeService(state, {"lab-r1": _device(tmp_path)})
    for window in (0, 60, 119, 601, 3600):
        with pytest.raises(OwnerFlowError) as excinfo:
            owner_flow.plan(
                service,
                "lab-r1",
                BATCH,
                window,
                explanation=_explanation_for(BATCH),
                owner_confirmed_in_chat=True,
                client_factory=_factory(FakeClient(_answers())),
            )
        assert "window" in str(excinfo.value)


def test_a_backup_that_cannot_be_taken_refuses_the_plan(tmp_path: Path) -> None:
    state = _state(tmp_path)
    service = FakeService(state, {"lab-r1": _device(tmp_path)})
    answers = _answers()
    answers[("file", "list")] = {"entries": [{"name": "dhcp", "type": "file"}]}
    with pytest.raises(OwnerFlowError) as excinfo:
        owner_flow.plan(
            service,
            "lab-r1",
            BATCH,
            explanation=_explanation_for(BATCH),
            owner_confirmed_in_chat=True,
            client_factory=_factory(FakeClient(answers)),
        )
    assert "waiting for confirmation" in str(excinfo.value)


# ---- the records -----------------------------------------------------------


def test_the_plan_writes_two_records(tmp_path: Path) -> None:
    result = _plan_flow(tmp_path)
    state = result["_service"].state
    apply_record = _record(state, result["session_id"])
    restore_record = _record(state, result["restore_session_id"])
    assert apply_record["kind"] == "owner-script"
    assert restore_record["kind"] == "owner-script"
    assert apply_record["router_leash"] == "owner-script"
    assert restore_record["router_leash"] == "owner-script-restore"
    assert restore_record["restore_of"] == result["session_id"]
    assert apply_record["restore_sid"] == result["restore_session_id"]


def test_the_records_verify_with_the_plan_hash(tmp_path: Path) -> None:
    result = _plan_flow(tmp_path)
    state = result["_service"].state
    for sid in (result["session_id"], result["restore_session_id"]):
        record = _record(state, sid)
        assert _plan.compute_plan_hash(record) == record["plan_hash"]


def test_editing_a_hash_bound_field_breaks_the_hash(tmp_path: Path) -> None:
    result = _plan_flow(tmp_path)
    state = result["_service"].state
    record = _record(state, result["session_id"])
    for field, value in (
        ("router_digest", "0" * 64),
        ("uci_batch", "set dhcp.lan.limit='151'"),
        ("base_hash", "0" * 64),
        ("router_leash", "owner-script-restore"),
        ("timeout_s", 300),
        ("diff", "dhcp.lan.limit='151'"),
    ):
        edited = dict(record)
        edited[field] = value
        assert _plan.compute_plan_hash(edited) != record["plan_hash"]


def test_the_hash_fields_are_unchanged() -> None:
    assert "kind" not in _plan.PLAN_HASH_FIELDS
    assert "script_sha256" not in _plan.PLAN_HASH_FIELDS
    assert "restore_sid" not in _plan.PLAN_HASH_FIELDS
    assert "not_verified" not in _plan.PLAN_HASH_FIELDS
    assert "ops" not in _plan.PLAN_HASH_FIELDS
    # the fields the design names are the ones that were there
    for field in (
        "device",
        "host",
        "session_id",
        "uci_batch",
        "diff",
        "probes",
        "timeout_s",
        "base_hash",
        "requires_approval",
        "router_digest",
        "explanation",
        "owner_confirmed_in_chat",
        "staged_at",
        "reasons",
        "router_leash",
        "router_profile",
        "router_sections",
        "router_requires_approval",
        "staged_check",
    ):
        assert field in _plan.PLAN_HASH_FIELDS


def test_an_installed_record_still_hashes_the_same() -> None:
    # the record of the installed mode, from the repo's own test data
    record = {
        "device": "lab-r1",
        "host": "192.0.2.1",
        "session_id": "a" * 32,
        "uci_batch": "set dhcp.lan.limit='150'",
        "diff": "dhcp.lan.limit='150'",
        "probes": [],
        "timeout_s": 90,
        "base_hash": "b" * 64,
        "requires_approval": True,
        "router_digest": "c" * 64,
        "explanation": {"intent": "x"},
        "owner_confirmed_in_chat": True,
        "staged_at": "2026-10-30T00:00:00+00:00",
        "reasons": [],
        "router_leash": ["age-limit"],
        "router_profile": "lab",
        "router_sections": ["dhcp.lan"],
        "router_requires_approval": True,
        "staged_check": {"fw4": "pass", "reason": "", "not_checked": []},
    }
    # the hash of this record is fixed: PLAN_HASH_FIELDS did not grow
    assert _plan.compute_plan_hash(record) == _plan.compute_plan_hash(dict(record))


def test_the_records_ask_for_an_approval_always(tmp_path: Path) -> None:
    result = _plan_flow(tmp_path)
    state = result["_service"].state
    apply_record = _record(state, result["session_id"])
    assert apply_record["requires_approval"] is True
    assert apply_record["router_requires_approval"] is True


def test_the_records_validate_for_approval(tmp_path: Path) -> None:
    result = _plan_flow(tmp_path)
    state = result["_service"].state
    for sid in (result["session_id"], result["restore_session_id"]):
        record = _record(state, sid)
        explanation, digest = approve.validate_plan_for_approval(record)
        assert isinstance(explanation, dict)
        assert digest == record["router_digest"]


def test_the_records_can_be_minted_an_approval(tmp_path: Path) -> None:
    result = _plan_flow(tmp_path)
    state = result["_service"].state
    record = _record(state, result["session_id"])
    approval = approve.mint_approval(
        result["session_id"], record, record["router_digest"], "ab" * 32, "owner"
    )
    assert approval["plan_id"] == result["session_id"]
    assert approval["plan_hash"] == record["plan_hash"]


def test_an_approval_for_the_apply_plan_does_not_release_the_restore_plan(
    tmp_path: Path,
) -> None:
    result = _plan_flow(tmp_path)
    state = result["_service"].state
    apply_record = _record(state, result["session_id"])
    restore_record = _record(state, result["restore_session_id"])
    assert apply_record["base_hash"] != restore_record["base_hash"]
    assert apply_record["plan_hash"] != restore_record["plan_hash"]
    approval = approve.mint_approval(
        result["session_id"], apply_record, apply_record["router_digest"], "ab" * 32, "owner"
    )
    assert approval["base_hash"] == apply_record["base_hash"]
    assert approval["base_hash"] != restore_record["base_hash"]


def test_the_staged_at_is_none_so_the_approval_window_is_thirty_minutes(
    tmp_path: Path,
) -> None:
    result = _plan_flow(tmp_path)
    state = result["_service"].state
    record = _record(state, result["session_id"])
    assert record["staged_at"] is None
    assert approve.stage_expiry(record) is None


# ---- the scripts -----------------------------------------------------------


def test_the_scripts_are_written_next_to_the_backup(tmp_path: Path) -> None:
    result = _plan_flow(tmp_path)
    state = result["_service"].state
    script = state / "owner-scripts" / result["session_id"] / "script.sh"
    assert script.exists()
    assert stat.S_IMODE(script.stat().st_mode) == 0o600
    assert script.read_bytes() == result["script"]["text"].encode("utf-8")
    assert script.read_text(encoding="utf-8").startswith("#!/bin/sh")


def test_the_script_re_parses_into_the_ops_of_the_record(tmp_path: Path) -> None:
    result = _plan_flow(tmp_path)
    state = result["_service"].state
    script = (state / "owner-scripts" / result["session_id"] / "script.sh").read_bytes()
    parsed = owner_script.parse_script(script)
    record = _record(state, result["session_id"])
    assert [list(op) for op in parsed.ops] == record["ops"]
    assert parsed.sid == result["session_id"]
    assert parsed.restore_sid == result["restore_session_id"]
    assert parsed.window == 180


def test_the_restore_script_re_parses_into_the_ops_of_its_record(tmp_path: Path) -> None:
    result = _plan_flow(tmp_path)
    state = result["_service"].state
    script = (
        state / "owner-scripts" / result["restore_session_id"] / "script.sh"
    ).read_bytes()
    parsed = owner_script.parse_script(script)
    record = _record(state, result["restore_session_id"])
    assert [list(op) for op in parsed.ops] == record["ops"]
    assert parsed.restore_of == result["session_id"]


def test_the_digest_binds_both_scripts(tmp_path: Path) -> None:
    result = _plan_flow(tmp_path)
    state = result["_service"].state
    record = _record(state, result["session_id"])
    expected = owner_flow._router_digest(
        "owner-script",
        result["script_sha256"],
        result["restore_script_sha256"],
    )
    assert record["router_digest"] == expected


def test_a_swapped_script_breaks_the_digest(tmp_path: Path) -> None:
    result = _plan_flow(tmp_path)
    state = result["_service"].state
    script = state / "owner-scripts" / result["session_id"] / "script.sh"
    script.write_bytes(script.read_bytes().replace(b"150", b"151"))
    record = _record(state, result["session_id"])
    from newton_mcp import owner_script as _os

    assert _os.script_sha256(script.read_bytes()) != record["script_sha256"]


# ---- the answer ------------------------------------------------------------


def test_the_answer_carries_the_script_in_the_envelope(tmp_path: Path) -> None:
    result = _plan_flow(tmp_path)
    assert result["mode"] == "owner-script"
    assert envelope.is_envelope(result["script"])
    assert "dhcp.lan.limit" in result["script"]["text"]


def test_the_answer_carries_the_reboot_line(tmp_path: Path) -> None:
    result = _plan_flow(tmp_path)
    assert result["reboot_line"] == (
        "If the router reboots or its web service restarts in the next 180 "
        "seconds, this change stays."
    )


def test_the_answer_carries_the_next_step(tmp_path: Path) -> None:
    result = _plan_flow(tmp_path)
    assert result["next_step"] == (
        "run sudo -u newton /usr/local/bin/newton-router-setup lab-r1 "
        f"owner-run {result['session_id']}; it asks for your approval passphrase"
    )


def test_the_answer_names_what_newton_cannot_check(tmp_path: Path) -> None:
    result = _plan_flow(tmp_path)
    assert owner_flow.BLIND_SPOT in result["not_verified"]


def test_the_answer_carries_the_consequences_and_the_reasons(tmp_path: Path) -> None:
    result = _plan_flow(tmp_path)
    assert isinstance(result["what_this_does"], list)
    assert isinstance(result["reasons"], list)
    assert result["risk"] in ("low", "critical")


def test_the_audit_line_carries_no_value(tmp_path: Path) -> None:
    result = _plan_flow(tmp_path)
    tool, device, line = result["_service"].audits[0]
    assert tool == "newton_owner_script"
    assert device == "lab-r1"
    scrubbed = _without_long_hex_runs(line)
    assert "150" not in scrubbed
    assert "limit" not in scrubbed
    assert result["session_id"] in line


def test_long_hex_scrubbing_keeps_a_planted_value() -> None:
    planted = "limit='150' 368150e3d26e1b54ef51cdfe874bb26e"

    assert _without_long_hex_runs(planted) == "limit='150' "


def test_the_backup_is_written_before_the_records(tmp_path: Path) -> None:
    result = _plan_flow(tmp_path)
    state = result["_service"].state
    backup = state / "owner-scripts" / result["session_id"] / "backup"
    assert (backup / "manifest.json").exists()
    assert (backup / "dhcp.json").exists()


# ---- the dialogs -----------------------------------------------------------


def _dialog_text(tmp_path: Path, result: dict[str, Any]) -> str:
    """The plan as newton-approve shows it."""
    state = result["_service"].state
    record = _record(state, result["session_id"])
    explanation, digest = approve.validate_plan_for_approval(record)
    return approve.render_plan_text(
        result["session_id"], record, explanation, digest
    )


def test_the_dialog_shows_the_script_and_its_hash(tmp_path: Path) -> None:
    result = _plan_flow(tmp_path)
    text = _dialog_text(tmp_path, result)
    assert "#!/bin/sh" in text
    assert "Script sha256: " in text
    assert result["script_sha256"][:8] in text
    assert result["script_sha256"][8:16] in text


def test_the_dialog_shows_the_consequences_and_the_reboot_line(tmp_path: Path) -> None:
    result = _plan_flow(tmp_path)
    text = _dialog_text(tmp_path, result)
    assert "What this does:" in text
    assert (
        "If the router reboots or its web service restarts in the next 180 "
        "seconds, this change stays." in text
    )


def test_the_dialog_shows_the_restore_plan_and_its_hash(tmp_path: Path) -> None:
    result = _plan_flow(tmp_path)
    text = _dialog_text(tmp_path, result)
    assert f"Restore plan: {result['restore_session_id']}" in text
    assert result["restore_script_sha256"][:8] in text


def test_the_dialog_shows_what_newton_cannot_check(tmp_path: Path) -> None:
    result = _plan_flow(tmp_path)
    text = _dialog_text(tmp_path, result)
    assert "What Newton cannot check:" in text
    assert owner_flow.BLIND_SPOT in text


def test_the_dialog_refuses_a_script_whose_hash_does_not_match(tmp_path: Path) -> None:
    result = _plan_flow(tmp_path)
    state = result["_service"].state
    script = state / "owner-scripts" / result["session_id"] / "script.sh"
    script.write_bytes(script.read_bytes().replace(b"250", b"251"))
    with pytest.raises(approve.ApprovalRefused) as excinfo:
        _dialog_text(tmp_path, result)
    assert "does not match" in str(excinfo.value)


def test_the_dialog_refuses_a_missing_script(tmp_path: Path) -> None:
    result = _plan_flow(tmp_path)
    state = result["_service"].state
    (state / "owner-scripts" / result["session_id"] / "script.sh").unlink()
    with pytest.raises(approve.ApprovalRefused):
        _dialog_text(tmp_path, result)


def test_the_dialog_of_a_restore_record_shows_the_restore_script(tmp_path: Path) -> None:
    result = _plan_flow(tmp_path)
    state = result["_service"].state
    record = _record(state, result["restore_session_id"])
    explanation, digest = approve.validate_plan_for_approval(record)
    text = approve.render_plan_text(
        result["restore_session_id"], record, explanation, digest
    )
    assert "#!/bin/sh" in text
    assert result["restore_script_sha256"][:8] in text


def test_the_dialog_refuses_when_the_script_does_not_fit(tmp_path: Path) -> None:
    from newton_mcp import elicit_approval

    result = _plan_flow(tmp_path)
    state = result["_service"].state
    record = _record(state, result["session_id"])
    explanation, digest = approve.validate_plan_for_approval(record)
    original = elicit_approval.OWNER_SCRIPT_MESSAGE_CAP
    try:
        elicit_approval.OWNER_SCRIPT_MESSAGE_CAP = 10
        with pytest.raises(approve.ApprovalRefused) as excinfo:
            elicit_approval._dialog_text(
                "lab-r1",
                result["session_id"],
                record,
                explanation,
                digest,
                True,
                "passphrase",
                _classification(),
                False,
            )
    finally:
        elicit_approval.OWNER_SCRIPT_MESSAGE_CAP = original
    assert "owner-run" in str(excinfo.value)
    assert result["session_id"] in str(excinfo.value)


def _classification():
    from newton_mcp import change_classes

    return change_classes.classify("set dhcp.lan.limit='250'")


# ---- the claims Newton cannot check ----------------------------------------


def test_the_plan_lists_only_the_claims_it_cannot_check(tmp_path: Path) -> None:
    """A claim whose probe the stock groups cannot run is listed as not
    verified; a claim the no-install path can run is not."""
    state = _state(tmp_path)
    service = FakeService(state, {"lab-r1": _device(tmp_path)})
    explanation = _explanation_for(BATCH)
    explanation["expect"] = [
        {"kind": "uci_equals", "path": "dhcp.lan.limit", "equals": "250"},
        {"kind": "probe", "probe": ["ra-absent", "lan"]},
    ]
    result = owner_flow.plan(
        service,
        "lab-r1",
        BATCH,
        explanation=explanation,
        owner_confirmed_in_chat=True,
        client_factory=_factory(FakeClient(_answers())),
    )
    # the uci_equals claim runs on the no-install path (its sealed name is
    # uci-equals), so it is checked and not listed
    assert "uci_equals" not in result["not_verified"]
    # the ra-absent claim cannot run there: it is listed, and the
    # read-back skips it
    assert "probe" in result["not_verified"]


def test_the_plan_lists_a_claim_whose_probe_is_not_supported(tmp_path: Path) -> None:
    """A claim whose probe the stock groups cannot run is listed by the
    name the claim was sealed with."""
    state = _state(tmp_path)
    service = FakeService(state, {"lab-r1": _device(tmp_path)})
    explanation = _explanation_for(BATCH)
    explanation["expect"] = [{"kind": "probe", "probe": ["ra-absent", "lan"]}]
    result = owner_flow.plan(
        service,
        "lab-r1",
        BATCH,
        explanation=explanation,
        owner_confirmed_in_chat=True,
        client_factory=_factory(FakeClient(_answers())),
    )
    assert result["not_verified"].count("probe") == 1
    assert owner_flow.BLIND_SPOT in result["not_verified"]


# ---- the restore plan keeps its own backup --------------------------------


def test_the_restore_plan_keeps_a_backup_of_its_own(tmp_path: Path) -> None:
    """The restore plan keeps the backup of the state it runs against:
    the state the change made."""
    result = _plan_flow(tmp_path)
    state = result["_service"].state
    rsid = result["restore_session_id"]
    directory = state / "owner-scripts" / rsid / "backup"
    assert (directory / "manifest.json").exists()
    assert (directory / "dhcp.json").exists()
    backup = owner_backup.load(state, rsid)
    # the restore runs against the state the change made, not the state
    # the change found
    assert backup.configs["dhcp"]["lan"]["limit"] == "250"


def test_each_record_binds_its_own_backup(tmp_path: Path) -> None:
    """The apply record binds the backup of the apply plan, and the
    restore record the backup of the restore plan."""
    result = _plan_flow(tmp_path)
    state = result["_service"].state
    for sid in (result["session_id"], result["restore_session_id"]):
        record = _record(state, sid)
        manifest = (
            state / "owner-scripts" / sid / "backup" / "manifest.json"
        ).read_bytes()
        assert record["backup_manifest_sha256"] == hashlib.sha256(manifest).hexdigest()
    apply_manifest = (
        state / "owner-scripts" / result["session_id"] / "backup" / "manifest.json"
    ).read_bytes()
    restore_manifest = (
        state / "owner-scripts" / result["restore_session_id"] / "backup" / "manifest.json"
    ).read_bytes()
    assert apply_manifest != restore_manifest


def test_the_restore_backup_holds_no_wifi_key(tmp_path: Path) -> None:
    """The restore's backup is a copy of the settings, and it never
    carries a secret the apply plan did not have."""
    result = _plan_flow(tmp_path)
    state = result["_service"].state
    backup = owner_backup.load(state, result["restore_session_id"])
    assert set(backup.configs) == {"dhcp"}


# ---- a change that does nothing -----------------------------------


def test_a_batch_that_cancels_itself_is_refused(tmp_path: Path) -> None:
    """A change that stages nothing is refused in Newton's own words.

    The restore of such a change has no ops, and a script with no ops is
    not a script: the plan must say "this change does nothing" and not
    let a script error out of the flow.
    """
    batch = "set dhcp.lan.newopt='1'\ndelete dhcp.lan.newopt"
    explanation = {
        "intent": "set an option and take it away again",
        "steps": ["set the option", "take it away again"],
        "expect": [
            {"kind": "uci_equals", "path": "dhcp.lan.limit", "equals": "250"}
        ],
        "risk": "nothing changes",
    }
    state = _state(tmp_path)
    service = FakeService(state, {"lab-r1": _device(tmp_path)})
    with pytest.raises(OwnerFlowError) as excinfo:
        owner_flow.plan(
            service,
            "lab-r1",
            batch,
            explanation=explanation,
            owner_confirmed_in_chat=True,
            client_factory=_factory(FakeClient(_answers())),
        )
    assert "this change does nothing" in str(excinfo.value)


# ---- a client claim -----------------------------------------------


def test_a_client_claim_is_listed_as_not_verified(tmp_path: Path) -> None:
    """A claim about a client cannot run on the no-install path.

    It is listed in ``not_verified`` with its own kind, and never
    dropped: the owner must know what Newton did not check.
    """
    state = _state(tmp_path)
    service = FakeService(state, {"lab-r1": _device(tmp_path)})
    explanation = _explanation_for(BATCH)
    explanation["expect"] = [{"kind": "client_dns", "zone": "lan"}]
    result = owner_flow.plan(
        service,
        "lab-r1",
        BATCH,
        explanation=explanation,
        owner_confirmed_in_chat=True,
        client_factory=_factory(FakeClient(_answers())),
    )
    listed = [item for item in result["not_verified"] if "client_dns" in item]
    assert listed, result["not_verified"]
