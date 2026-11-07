"""Vendor plan, apply, status, abort and backup through NewtonService.

Every device interaction is a scripted fake.  
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import stat
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

import newton_mcp.server as server
from newton_mcp import explanation as ex
from newton_mcp.plan import compute_plan_hash
from newton_mcp.vendor_change import RunOut


RELOAD_LINE = "set system config-management commit-confirm action 'reload'"
BASE_CONFIG = "\n".join(
    [
        RELOAD_LINE,
        "set system host-name 'base-router'",
        "set system description 'baseline'",
    ]
)
CHANGED_CONFIG = "\n".join(
    [
        RELOAD_LINE,
        "set system host-name 'lab-router'",
        "set system description 'baseline'",
    ]
)
CHANGE_TEXT = "set system host-name 'lab-router'"
CANONICAL_CHANGE = "set system host-name lab-router"
PING_HOST = "192.0.2.10"


def _ok(stdout: str = "", exit_code: int = 0) -> RunOut:
    return RunOut(
        status="ok",
        stdout=stdout,
        stderr="",
        exit_code=exit_code,
    )


def _phase(spec: Any, applied: bool) -> str:
    if spec.remote == "systemctl is-active commit-confirm.timer":
        return "verify timer" if applied else "preflight timer"
    if spec.remote == "/opt/vyatta/bin/vyatta-op-cmd-wrapper show configuration commands":
        return "verify config" if applied else "preflight config"
    if spec.remote.startswith("ping "):
        return "ping"
    lines = spec.stdin.splitlines()
    if any(line.startswith("commit-confirm ") for line in lines):
        return "apply"
    if "compare saved" in lines:
        return "verify saved" if applied else "preflight saved"
    if "discard" in lines:
        return "stage"
    if "revert_soft" in spec.stdin:
        return "abort"
    if "confirm" in lines:
        return "confirm"
    if "save" in lines:
        return "save"
    raise AssertionError(f"unknown session kind: {spec.remote!r}")


class ScriptedRunner:
    """A fake VyOS device that records fresh sessions and changes state."""

    def __init__(self) -> None:
        self.config = BASE_CONFIG
        self.initial_config = BASE_CONFIG
        self.pending = "idle"
        self.ping_result = True
        self.raise_at: str | None = None
        self.timer_answer: str | None = None
        self.calls: list[tuple[str, Any]] = []
        self.target: Any = None

    def __call__(self, spec: Any) -> RunOut:
        applied = self.pending == "pending"
        phase = _phase(spec, applied)
        self.calls.append((phase, spec))
        if self.raise_at == phase:
            raise RuntimeError(f"{phase} stopped")

        if phase == "preflight config" or phase == "verify config":
            return _ok(self.config)
        if phase == "preflight timer" or phase == "verify timer":
            if self.timer_answer is not None:
                return _ok(self.timer_answer)
            return _ok("active\n" if self.pending == "pending" else "inactive\n")
        if phase == "preflight saved" or phase == "verify saved":
            return _ok(
                "NEWTON-BEGIN-SAVED\n"
                "No changes between working and saved configurations.\n"
                "NEWTON-END-SAVED\n"
            )
        if phase == "stage":
            return _ok(
                "NEWTON-BEGIN-DIFF\n[edit system host-name]\n"
                "+host-name 'lab-router'\nNEWTON-END-DIFF\n"
            )
        if phase == "apply":
            self.config = CHANGED_CONFIG
            self.pending = "pending"
            return _ok("NEWTON-COMMITTED rc=0\n")
        if phase == "ping":
            return _ok("", 0 if self.ping_result else 1)
        if phase == "confirm":
            self.pending = "idle"
            return _ok("NEWTON-CONFIRMED rc=0\n")
        if phase == "abort":
            self.config = self.initial_config
            self.pending = "idle"
            return _ok("NEWTON-ABORT revert_rc=0\n")
        if phase == "save":
            return _ok("NEWTON-SAVED rc=0\n")
        raise AssertionError(f"unhandled phase: {phase}")


@dataclass
class VendorLab:
    service: server.NewtonService
    runner: ScriptedRunner
    state: Path


@pytest.fixture
def vendor_lab(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> VendorLab:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text(
        "192.0.2.9 ssh-ed25519 "
        "AAAAC3NzaC1lZDI1NTE5AAAAIFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE\n",
        encoding="utf-8",
    )
    key_file = tmp_path / "newton-key"
    key_file.write_text("FAKE-KEY-FOR-TESTS\n", encoding="utf-8")
    key_file.chmod(0o600)
    inventory = tmp_path / "devices.toml"
    inventory.write_text(
        '[devices.vy1]\n'
        'platform = "vyos"\n'
        'host = "192.0.2.9"\n'
        'user = "newton"\n'
        'auth = "key"\n'
        'profile = "lab"\n'
        "vendor_write = true\n"
        "lab = true\n"
        f'key_file = "{key_file}"\n'
        f'known_hosts = "{known_hosts}"\n',
        encoding="utf-8",
    )
    state = tmp_path / "state"
    monkeypatch.setenv("NEWTON_INVENTORY", str(inventory))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(state))
    runner = ScriptedRunner()

    class FakeRunnerFactory:
        def __call__(self, target: Any) -> ScriptedRunner:
            runner.target = target
            return runner

    monkeypatch.setattr(server.vendor_flow, "SshSessionRunner", FakeRunnerFactory())
    return VendorLab(server.NewtonService(), runner, state)


def _explanation(kind: str = "config_has") -> dict[str, Any]:
    expect: list[dict[str, Any]]
    if kind == "ping":
        expect = [{"kind": "ping", "host": PING_HOST}]
    else:
        expect = [{"kind": "config_has", "line": CHANGE_TEXT}]
    return {
        "intent": "Set the lab router host name.",
        "steps": ["Set the requested host name."],
        "expect": expect,
        "risk": "The management name changes if the device rejects it.",
    }


def _plan(lab: VendorLab, explanation: dict[str, Any] | None = None) -> dict[str, Any]:
    return lab.service.plan(
        "vy1",
        CHANGE_TEXT,
        150,
        explanation=_explanation() if explanation is None else explanation,
        owner_confirmed_in_chat=True,
    )


def _record(lab: VendorLab, session_id: str) -> dict[str, Any]:
    return json.loads(
        (lab.state / "plans" / f"{session_id}.json").read_text(encoding="utf-8")
    )


def _write_approval(
    lab: VendorLab,
    session_id: str,
    record: dict[str, Any],
) -> Path:
    approvals = lab.state / "approvals"
    approvals.mkdir(mode=0o700, parents=True, exist_ok=True)
    created = datetime.now(timezone.utc)
    expires = created + timedelta(minutes=10)
    value = {
        "plan_id": session_id,
        "plan_hash": record["plan_hash"],
        "device": "vy1",
        "base_hash": record["base_hash"],
        "created_at": created.isoformat(),
        "expires_at": expires.isoformat(),
        "not_before": int(created.timestamp()),
        "not_after": int(expires.timestamp()),
        "token": "a" * 64,
    }
    path = approvals / f"{session_id}.json"
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
    path.chmod(0o600)
    return path


def test_plan_writes_a_valid_vendor_record(vendor_lab: VendorLab) -> None:
    """Plan persists a valid record with the claims as last probes."""
    result = _plan(vendor_lab)

    assert set(result) == {
        "session_id",
        "plan_hash",
        "base_hash",
        "touched_configs",
        "requires_approval",
        "approval_required",
        "risk",
        "diff",
        "backup_path",
    }
    assert result["touched_configs"] == []
    assert result["requires_approval"] is True
    assert result["approval_required"] is True
    assert result["risk"] == "medium"
    assert result["backup_path"] == ""
    assert result["diff"]["kind"] == "untrusted-device-data"

    record = _record(vendor_lab, result["session_id"])
    assert record["plan_hash"] == compute_plan_hash(record)
    assert record["plan_hash"] == result["plan_hash"]
    assert record["staged_check"]["fw4"] == "not-checked"
    assert record["staged_check"]["reason"] == "vendor-platform"
    assert record["device"] == "vy1"
    assert record["host"] == "192.0.2.9"
    assert record["uci_batch"] == CANONICAL_CHANGE
    assert record["probes"] == [["config_has", CANONICAL_CHANGE]]
    assert ex.claims_match_probes(record["probes"], record["explanation"])
    assert record["owner_confirmed_in_chat"] is True
    assert record["reasons"] == ["vendor change on vyos"]
    assert record["router_leash"] == "vendor"
    assert record["router_profile"] == "lab"
    assert record["router_requires_approval"] is True
    assert record["router_sections"] == []
    expected_digest = hashlib.sha256(
        (record["diff"] + record["base_hash"]).encode("utf-8")
    ).hexdigest()
    assert record["router_digest"] == expected_digest
    assert datetime.fromisoformat(record["staged_at"]) <= datetime.fromisoformat(
        record["created_at"]
    )
    mode = stat.S_IMODE(
        (vendor_lab.state / "plans" / f"{result['session_id']}.json").stat().st_mode
    )
    assert mode == 0o600


@pytest.mark.parametrize(
    ("explanation", "owner_confirmed"),
    [
        (None, True),
        (_explanation(), False),
    ],
)
def test_plan_refuses_before_any_device_call(
    vendor_lab: VendorLab,
    explanation: dict[str, Any] | None,
    owner_confirmed: bool,
) -> None:
    """Missing explanation or owner confirmation contacts no device."""
    with pytest.raises(server.NewtonError):
        vendor_lab.service.plan(
            "vy1",
            CHANGE_TEXT,
            150,
            explanation=explanation,
            owner_confirmed_in_chat=owner_confirmed,
        )
    assert vendor_lab.runner.calls == []


def test_vendor_claim_kinds_are_platform_checked(
    vendor_lab: VendorLab,
) -> None:
    """OpenWrt claim kinds are refused on a vendor plan."""
    explanation = _explanation()
    explanation["expect"] = [
        {"kind": "uci_equals", "path": "system.hostname", "equals": "lab-router"}
    ]
    with pytest.raises(server.NewtonError, match="not available"):
        vendor_lab.service.plan(
            "vy1",
            CHANGE_TEXT,
            150,
            explanation=explanation,
            owner_confirmed_in_chat=True,
        )
    assert vendor_lab.runner.calls == []


def test_apply_without_approval_makes_no_device_call(
    vendor_lab: VendorLab,
) -> None:
    """A missing approval stops apply before preflight."""
    planned = _plan(vendor_lab)
    vendor_lab.runner.calls.clear()

    with pytest.raises(server.NewtonError, match="approval required"):
        vendor_lab.service.apply("vy1", planned["session_id"])

    assert vendor_lab.runner.calls == []


def test_apply_with_approval_confirms_in_the_safe_order(
    vendor_lab: VendorLab,
) -> None:
    """A good approval confirms after preflight, apply and fresh verify."""
    planned = _plan(vendor_lab)
    record = _record(vendor_lab, planned["session_id"])
    _write_approval(vendor_lab, planned["session_id"], record)
    vendor_lab.runner.calls.clear()

    result = vendor_lab.service.apply("vy1", planned["session_id"])

    assert result["result"] == "confirmed"
    assert result["lost_out_of_band"] is False
    assert "failed_claim" not in result
    assert result["log"]["kind"] == "untrusted-device-data"
    phases = [phase for phase, _ in vendor_lab.runner.calls]
    assert phases.index("preflight config") < phases.index("apply")
    assert phases.index("apply") < phases.index("verify config")
    assert phases.index("verify config") < phases.index("confirm")
    approvals = vendor_lab.state / "approvals"
    assert (approvals / f"{planned['session_id']}.used").exists()
    assert not (approvals / f"{planned['session_id']}.json").exists()


def test_stale_base_hash_is_an_error_before_apply(
    vendor_lab: VendorLab,
) -> None:
    """A changed device base hash is stale and never applies."""
    planned = _plan(vendor_lab)
    record = _record(vendor_lab, planned["session_id"])
    _write_approval(vendor_lab, planned["session_id"], record)
    vendor_lab.runner.config = CHANGED_CONFIG
    vendor_lab.runner.calls.clear()

    with pytest.raises(server.NewtonError, match="changed after the plan was staged"):
        vendor_lab.service.apply("vy1", planned["session_id"])

    assert not any(phase == "apply" for phase, _ in vendor_lab.runner.calls)


def test_verify_exception_leaves_pending_and_consumes_approval(
    vendor_lab: VendorLab,
) -> None:
    """A verify exception cannot confirm and the approval is spent."""
    planned = _plan(vendor_lab)
    record = _record(vendor_lab, planned["session_id"])
    _write_approval(vendor_lab, planned["session_id"], record)
    vendor_lab.runner.raise_at = "verify config"
    vendor_lab.runner.calls.clear()

    with pytest.raises((RuntimeError, server.NewtonError)):
        vendor_lab.service.apply("vy1", planned["session_id"])

    assert vendor_lab.runner.pending == "pending"
    assert not any(phase == "confirm" for phase, _ in vendor_lab.runner.calls)
    approvals = vendor_lab.state / "approvals"
    assert (approvals / f"{planned['session_id']}.used").exists()
    assert not (approvals / f"{planned['session_id']}.json").exists()


def test_failed_ping_rolls_back_and_names_the_claim(
    vendor_lab: VendorLab,
) -> None:
    """A failed ping claim rolls back and names claim one."""
    planned = _plan(vendor_lab, _explanation("ping"))
    record = _record(vendor_lab, planned["session_id"])
    _write_approval(vendor_lab, planned["session_id"], record)
    vendor_lab.runner.ping_result = False
    vendor_lab.runner.calls.clear()

    result = vendor_lab.service.apply("vy1", planned["session_id"])

    assert result["result"] == "rolled_back"
    assert result["failed_claim"]["claim"] == 1
    assert PING_HOST in result["failed_claim"]["text"]
    assert not any(phase == "confirm" for phase, _ in vendor_lab.runner.calls)


def test_tampered_record_is_refused_without_device_calls(
    vendor_lab: VendorLab,
) -> None:
    """Changing the stored plan invalidates it before any device call."""
    planned = _plan(vendor_lab)
    record = _record(vendor_lab, planned["session_id"])
    _write_approval(vendor_lab, planned["session_id"], record)
    record["base_hash"] = "0" * 64
    path = vendor_lab.state / "plans" / f"{planned['session_id']}.json"
    path.write_text(json.dumps(record, sort_keys=True), encoding="utf-8")
    vendor_lab.runner.calls.clear()

    with pytest.raises(server.NewtonError, match="modified or is invalid"):
        vendor_lab.service.apply("vy1", planned["session_id"])

    assert vendor_lab.runner.calls == []


def test_read_only_vendor_device_refuses_plan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A read-only VyOS device never reaches the vendor flow."""
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("key ssh-ed25519 synthetic\n", encoding="utf-8")
    readonly = server.Device(
        name="vy1",
        platform="vyos",
        host="192.0.2.9",
        user="newton",
        profile="lab",
        experimental_readonly=True,
        lab=True,
        known_hosts=known_hosts,
    )
    monkeypatch.setattr(server, "load_inventory", lambda: {"vy1": readonly})
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))
    service = server.NewtonService()

    with pytest.raises(server.NewtonError, match="read-only"):
        service.plan(
            "vy1",
            CHANGE_TEXT,
            150,
            explanation=_explanation(),
            owner_confirmed_in_chat=True,
        )


def test_status_and_abort_never_confirm(vendor_lab: VendorLab) -> None:
    """Status only reads and abort only reverts."""
    planned = _plan(vendor_lab)
    vendor_lab.runner.pending = "pending"
    vendor_lab.runner.calls.clear()

    status = vendor_lab.service.status("vy1", planned["session_id"])
    assert status["exit_code"] in (0, 1)
    assert status["log"]["kind"] == "untrusted-device-data"
    assert not any(phase == "confirm" for phase, _ in vendor_lab.runner.calls)

    aborted = vendor_lab.service.abort("vy1", planned["session_id"])
    assert aborted["exit_code"] == 0
    assert vendor_lab.runner.pending == "idle"
    assert not any(phase == "confirm" for phase, _ in vendor_lab.runner.calls)


def test_backup_is_redacted_and_private(vendor_lab: VendorLab) -> None:
    """Backup stores a redacted running config with mode 0600."""
    vendor_lab.runner.config = (
        BASE_CONFIG + "\nset system login user 'newton' password 'synthetic-secret'\n"
    )

    result = vendor_lab.service.backup("vy1")

    assert result["config_files"] == ["running-config"]
    assert result["backup_path"]["kind"] == "untrusted-device-data"
    path = Path(result["backup_path"]["text"])
    assert path.parent == vendor_lab.state / "backups"
    assert path.name.startswith("vy1-")
    assert path.suffix == ".txt"
    assert "synthetic-secret" not in path.read_text(encoding="utf-8")
    assert "<redacted>" in path.read_text(encoding="utf-8")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_non_openwrt_tools_never_use_run_script(
    vendor_lab: VendorLab,
) -> None:
    """Every vendor write dispatch bypasses the OpenWrt script path."""
    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("OpenWrt run_script path was used")

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(vendor_lab.service, "run_script", forbidden)
    try:
        planned = _plan(vendor_lab)
        record = _record(vendor_lab, planned["session_id"])
        _write_approval(vendor_lab, planned["session_id"], record)
        applied = vendor_lab.service.apply("vy1", planned["session_id"])
        status = vendor_lab.service.status("vy1", planned["session_id"])
        aborted = vendor_lab.service.abort("vy1", planned["session_id"])
        backup = vendor_lab.service.backup("vy1")
    finally:
        monkeypatch.undo()

    assert applied["result"] == "confirmed"
    assert status["exit_code"] in (0, 1)
    assert aborted["exit_code"] == 0
    assert backup["config_files"] == ["running-config"]

    with pytest.raises(server.NewtonError, match="OpenWrt"):
        vendor_lab.service.run_script(
            vendor_lab.runner.target,
            "status",
            vendor_lab.runner.target.destination,
            planned["session_id"],
        )


def test_vendor_flow_source_has_no_transport_or_direct_confirm(
    vendor_lab: VendorLab,
) -> None:
    """Vendor_flow owns no subprocess and never confirms directly."""
    source_path = Path(server.__file__).with_name("vendor_flow.py")
    source = source_path.read_text(encoding="utf-8")
    assert "import subprocess" not in source
    assert "os.system" not in source
    assert "shell=True" not in source

    tree = ast.parse(source)
    direct_confirm = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "confirm"
    ]
    assert direct_confirm == []
    apply_plan_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and (
            (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "apply_plan"
            )
            or (isinstance(node.func, ast.Name) and node.func.id == "apply_plan")
        )
    ]
    assert apply_plan_calls


def _tamper_explanation(record: dict[str, Any]) -> None:
    """Give the stored explanation a step count the batch cannot match."""
    record["explanation"]["steps"] = [
        "Set the requested host name.",
        "Also do something the plan never said.",
    ]


def _tamper_owner(record: dict[str, Any]) -> None:
    """Take the owner's chat yes off the stored record."""
    record["owner_confirmed_in_chat"] = False


def _tamper_claims(record: dict[str, Any]) -> None:
    """Swap the claims of the stored record for other claims."""
    record["explanation"]["expect"] = [{"kind": "ping", "host": PING_HOST}]


@pytest.mark.parametrize(
    ("tamper", "expected"),
    [
        (_tamper_explanation, "invalid explanation"),
        (_tamper_owner, "owner_confirmed_in_chat"),
        (_tamper_claims, "expect claims"),
    ],
)
def test_a_tampered_record_is_refused_before_any_device_call(
    vendor_lab: VendorLab,
    tamper: Any,
    expected: str,
) -> None:
    """A tampered record is refused even with a recomputed hash."""
    planned = _plan(vendor_lab)
    record = _record(vendor_lab, planned["session_id"])
    _write_approval(vendor_lab, planned["session_id"], record)
    tamper(record)
    # The hash is recomputed, so the plan-hash check passes and the record
    # has to be refused by the checks that read the record itself.
    record["plan_hash"] = compute_plan_hash(record)
    path = vendor_lab.state / "plans" / f"{planned['session_id']}.json"
    path.write_text(json.dumps(record, sort_keys=True), encoding="utf-8")
    vendor_lab.runner.calls.clear()

    with pytest.raises(server.NewtonError, match=expected):
        vendor_lab.service.apply("vy1", planned["session_id"])

    assert vendor_lab.runner.calls == []


@pytest.mark.parametrize("timeout_s", [59, 601, True, "150"])
def test_a_timeout_outside_60_600_is_refused(
    vendor_lab: VendorLab,
    timeout_s: Any,
) -> None:
    """A timeout outside 60..600 is refused before any device call."""
    with pytest.raises(server.NewtonError, match="timeout_s must be an integer 60..600"):
        vendor_lab.service.plan(
            "vy1",
            CHANGE_TEXT,
            timeout_s,
            explanation=_explanation(),
            owner_confirmed_in_chat=True,
        )

    assert vendor_lab.runner.calls == []


@pytest.mark.parametrize(
    ("timer", "expected_pending", "expected_exit"),
    [
        ("inactive\n", "idle", 0),
        ("active\n", "pending", 0),
        ("rolled-back\n", "unknown", 1),
    ],
)
def test_the_status_exit_code_is_exact_per_state(
    vendor_lab: VendorLab,
    timer: str,
    expected_pending: str,
    expected_exit: int,
) -> None:
    """The status exit code is 0 for a known state and 1 for unknown."""
    planned = _plan(vendor_lab)
    vendor_lab.runner.timer_answer = timer

    status = vendor_lab.service.status("vy1", planned["session_id"])

    assert status["exit_code"] == expected_exit
    assert json.loads(status["log"]["text"])["pending"] == expected_pending


def test_the_status_exit_code_is_one_when_the_device_does_not_answer(
    vendor_lab: VendorLab,
) -> None:
    """A status read that fails is exit code one, not zero."""
    planned = _plan(vendor_lab)
    vendor_lab.runner.raise_at = "preflight timer"

    status = vendor_lab.service.status("vy1", planned["session_id"])

    assert status["exit_code"] == 1
    assert json.loads(status["log"]["text"])["pending"] == "unknown"
