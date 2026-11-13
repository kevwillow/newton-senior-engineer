"""The undo server path and CONFIGHASH capture.

Test IDs: UN-01..UN-06. Every fixture is local and synthetic: real plan
records, audit lines, receipts and tar.gz backups, with a fake script runner.
"""

from __future__ import annotations

import io
import json
import subprocess
import tarfile
from pathlib import Path
from typing import Any

import pytest

from exhelp import make_explanation, record_fields_display

import newton_mcp.change_receipt as change_receipt
import newton_mcp.explanation as explanation
import newton_mcp.server as server
import newton_mcp.undo as undo
import newton_mcp.undo_plan as undo_plan
from newton_mcp.plan import compute_plan_hash
from newton_mcp.server import NewtonError


SID = "fd595e20f2cd6c2b928fe3156f82d5db"
UNDO_SID = "3c595e20f2cd6c2b928fe3156f82d5db"
DEVICE = "quasar"
LAB_DEVICE = "lab-router"
HOST = "192.0.2.1"
LAB_HOST = "192.0.2.2"
BASE_HASH = "8" * 64
ROUTER_DIGEST = "3" * 64
PROBES_SHA = "1" * 64

BEFORE = "config dhcp 'lan'\n\toption ignore '0'\n"
AFTER = "config dhcp 'lan'\n\toption ignore '1'\n"
EDITED = "config dhcp 'lan'\n\toption ignore '2'\n"
DIFF = "dhcp.lan.ignore='1'"
UNDO_DIFF = "dhcp.lan.ignore='0'"

AGENT = {
    "intent": "Put the DHCP setting back the way the owner had it.",
    "risk": "A wrong value could break DHCP for the owner.",
}


@pytest.fixture
def configured(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    inventory = tmp_path / "devices.toml"
    inventory.write_text(
        '[devices.quasar]\n'
        'platform = "openwrt"\n'
        'host = "192.0.2.1"\n'
        'user = "root"\n'
        '\n'
        '[devices.lab-router]\n'
        'platform = "openwrt"\n'
        'host = "192.0.2.2"\n'
        'user = "root"\n'
        'profile = "lab"\n'
        'lab = true\n'
    )
    inventory.chmod(0o644)
    monkeypatch.setenv("NEWTON_INVENTORY", str(inventory))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("OWRT_AUDIT_LOG", str(tmp_path / "audit.log"))
    return tmp_path


def _tarball(path: Path, configs: dict[str, str]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(path, "w:gz") as archive:
        for name, text in configs.items():
            data = text.encode("utf-8")
            info = tarfile.TarInfo(f"etc/config/{name}")
            info.size = len(data)
            info.mode = 0o600
            archive.addfile(info, io.BytesIO(data))
    return path


def _audit(root: Path, *lines: str) -> None:
    with (root / "audit.log").open("a", encoding="utf-8") as handle:
        for line in lines:
            handle.write(f"2026-10-24T15:01:00-04:00 root@192.0.2.1 {line}\n")


def _confirmed_change(
    root: Path,
    *,
    device: str = DEVICE,
    host: str = HOST,
    outcome: str = "confirmed",
    package: str = "dhcp",
    before: str = BEFORE,
    after: str = AFTER,
    diff: str = DIFF,
    uci_batch: str = "set dhcp.lan.ignore='1'\n",
) -> tuple[dict[str, Any], Path]:
    state = root / "state"
    plans = state / "plans"
    plans.mkdir(parents=True, exist_ok=True, mode=0o700)
    state.chmod(0o700)
    backup = _tarball(
        root / "backups" / f"{SID}.tar.gz",
        {package: before},
    )
    current = _tarball(
        root / "current" / f"{SID}.tar.gz",
        {package: after},
    )
    agent_explanation = make_explanation(uci_batch)
    record: dict[str, Any] = {
        "device": device,
        "host": host,
        "session_id": SID,
        "uci_batch": uci_batch,
        "diff": diff,
        "probes": [["fail"]] + explanation.claim_probes(agent_explanation),
        "timeout_s": 90,
        "base_hash": undo.config_base_hash(backup),
        "requires_approval": True,
        "router_digest": ROUTER_DIGEST,
        "explanation": agent_explanation,
        "owner_confirmed_in_chat": True,
        **record_fields_display(),
        "created_at": "2026-10-24T15:00:00+00:00",
        "staged_at": "2026-10-24T15:00:00+00:00",
        "backup_path": str(backup),
        "after_hash": {package: undo.md5_hex(after.encode("utf-8"))},
    }
    record["plan_hash"] = compute_plan_hash(record)
    (plans / f"{SID}.json").write_text(json.dumps(record, sort_keys=True))
    if outcome == "confirmed":
        _audit(
            root,
            f"APPLIED session={SID} rollback=90s",
            f"CONFIRMED session={SID} (3 consecutive passes)",
        )
    elif outcome == "rolled_back":
        _audit(
            root,
            f"APPLIED session={SID} rollback=90s",
            f"ROLLBACK WINDOW PASSED session={SID} - router reachable; rolled back by rpcd",
        )
    else:
        _audit(
            root,
            f"APPLIED session={SID} rollback=90s",
            f"ALERT session={SID} status=confirmed after the rollback window",
        )
    receipt = change_receipt.write_receipt(state, record, outcome, "")
    assert receipt is not None
    return record, current


def _apply_record(root: Path) -> dict[str, Any]:
    state = root / "state"
    plans = state / "plans"
    plans.mkdir(parents=True, exist_ok=True, mode=0o700)
    state.chmod(0o700)
    backup = _tarball(
        root / "backups" / f"{SID}.tar.gz",
        {"dhcp": BEFORE},
    )
    agent_explanation = make_explanation("set dhcp.lan.ignore='1'\n")
    record: dict[str, Any] = {
        "device": LAB_DEVICE,
        "host": LAB_HOST,
        "session_id": SID,
        "uci_batch": "set dhcp.lan.ignore='1'\n",
        "diff": DIFF,
        "probes": [["fail"]] + explanation.claim_probes(agent_explanation),
        "timeout_s": 90,
        "base_hash": BASE_HASH,
        "requires_approval": False,
        "router_digest": ROUTER_DIGEST,
        "explanation": agent_explanation,
        "owner_confirmed_in_chat": True,
        **record_fields_display(),
        "created_at": "2026-10-24T15:00:00+00:00",
        "staged_at": "2026-10-24T15:00:00+00:00",
        "backup_path": str(backup),
    }
    record["plan_hash"] = compute_plan_hash(record)
    (plans / f"{SID}.json").write_text(json.dumps(record, sort_keys=True))
    return record


def _plan_output(
    backup_path: Path,
    profile: str,
    approval: str,
    *,
    diff: str = UNDO_DIFF,
    section: str = "SECTION dhcp lan dnsmasq dnsmasq",
) -> str:
    return (
        f"BACKUP {backup_path} (1 config files)\n"
        f"STAGED session={UNDO_SID}\n"
        f"BASEHASH {BASE_HASH}\n"
        f"PROBES 1 {PROBES_SHA}\n"
        f"PROFILE {profile}\n"
        f"{section}\n"
        f"APPROVAL {approval}\n"
        f"PLANDIGEST {ROUTER_DIGEST}\n"
        "----- diff -----\n"
        f"{diff}\n"
        "----------------\n"
    )


def _install_fake_script(
    monkeypatch: pytest.MonkeyPatch,
    current_backup: Path,
    *,
    plan_backup: Path | None = None,
    apply_stdout: str = "",
    apply_returncode: int = 0,
    plan_diff: str = UNDO_DIFF,
    plan_section: str = "SECTION dhcp lan dnsmasq dnsmasq",
) -> list[tuple[str, tuple[Any, ...], dict[str, Any]]]:
    calls: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []

    def fake_run(
        self: server.NewtonService,
        device: server.Device,
        *args: str,
        **kwargs: Any,
    ) -> subprocess.CompletedProcess[str]:
        calls.append((device.name, args, kwargs))
        verb = args[0]
        returncode = 0
        if verb == "backup":
            stdout = f"BACKUP {current_backup} (1 config files)\n"
        elif verb == "plan":
            approval = "required" if device.profile == "prod" else "not-required"
            stdout = _plan_output(
                plan_backup or current_backup,
                device.profile,
                approval,
                diff=plan_diff,
                section=plan_section,
            )
        elif verb == "abort":
            stdout = ""
        elif verb == "apply":
            stdout = apply_stdout
            returncode = apply_returncode
        else:
            raise AssertionError(f"unexpected script verb: {verb}")
        return subprocess.CompletedProcess(list(args), returncode, stdout, "")

    monkeypatch.setattr(server.NewtonService, "run_script", fake_run)
    return calls


def _verbs(calls: list[tuple[str, tuple[Any, ...], dict[str, Any]]]) -> list[str]:
    return [str(args[0]) for _device, args, _kwargs in calls]


def _receipts(root: Path) -> list[Path]:
    directory = root / "state" / "receipts"
    return sorted(directory.glob("*.md")) if directory.is_dir() else []


def test_un01_plan_undo_happy_path(configured: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _original, current = _confirmed_change(configured)
    calls = _install_fake_script(monkeypatch, current)

    result = server.NewtonService().plan_undo(DEVICE, SID, AGENT, True)

    assert result["undo_of"] == SID
    assert result["packages"] == ["dhcp"]
    assert result["not_undone"] == list(undo_plan.NOT_UNDONE)
    assert result["session_id"] == UNDO_SID
    assert _verbs(calls) == ["backup", "plan"]

    record_path = configured / "state" / "plans" / f"{UNDO_SID}.json"
    record = json.loads(record_path.read_text(encoding="utf-8"))
    assert record["undo_of"] == SID
    assert compute_plan_hash(record) == record["plan_hash"]
    draft = undo_plan.draft_undo(
        configured / "state", DEVICE, HOST, SID, current, AGENT
    )
    assert record["uci_batch"] == draft.batch


def test_un01_receipt_names_the_original_change(
    configured: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _original, current = _confirmed_change(configured)
    _install_fake_script(monkeypatch, current)
    server.NewtonService().plan_undo(DEVICE, SID, AGENT, True)

    record_path = configured / "state" / "plans" / f"{UNDO_SID}.json"
    record = json.loads(record_path.read_text(encoding="utf-8"))
    receipt = change_receipt.write_receipt(
        configured / "state",
        record,
        "confirmed",
        f"CONFIRMED session={UNDO_SID}\n",
    )
    assert receipt is not None
    text = receipt.read_text(encoding="utf-8")
    assert f"Undo of: {SID}" in text
    assert "Outcome: CONFIRMED" in text
    assert "## Backup" in text

    record["undo_of"] = "not-a-session-id"
    plain = change_receipt.render(
        configured / "state",
        record,
        "confirmed",
        [f"CONFIRMED session={UNDO_SID}"],
        "the apply output",
    )
    assert "Undo of:" not in plain


def test_un01_tool_is_registered_for_openwrt_only() -> None:
    assert len(server.TOOL_NAMES) == 23
    assert "newton_plan_undo" in server.TOOL_NAMES
    assert "newton_plan_undo" in server.registry.capabilities("openwrt").tools
    for platform in ("routeros", "vyos", "junos", "eos", "iosxe", "fortios"):
        assert "newton_plan_undo" not in server.registry.capabilities(platform).tools


def test_un01_plan_error_is_returned_unchanged(
    configured: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _original, current = _confirmed_change(configured)
    calls = _install_fake_script(monkeypatch, current)

    def fake_plan(
        self: server.NewtonService,
        *args: Any,
        **kwargs: Any,
    ) -> dict[str, Any]:
        return {"error": "state write refused"}

    monkeypatch.setattr(server.NewtonService, "plan", fake_plan)
    result = server.NewtonService().plan_undo(DEVICE, SID, AGENT, True)

    assert result == {"error": "state write refused"}
    assert _verbs(calls) == ["backup"]


def test_un01_plan_undo_passes_committed_values_to_policy(
    configured: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # the change added the option, so the undo deletes it
    _original, current = _confirmed_change(
        configured,
        before="config dhcp 'lan'\n",
    )
    _install_fake_script(monkeypatch, current, plan_diff="-dhcp.lan.ignore")
    seen: dict[str, object] = {}
    real_classify = server.classify

    def capture_classify(*args: object, **kwargs: object) -> dict[str, object]:
        seen["deleted_values"] = kwargs.get("deleted_values")
        return real_classify(*args, **kwargs)

    monkeypatch.setattr(server, "classify", capture_classify)

    server.NewtonService().plan_undo(DEVICE, SID, AGENT, True)

    assert seen["deleted_values"] == {("dhcp", "lan", "ignore"): "1"}


def _pulsar_change(configured: Path, value: str) -> Path:
    """A confirmed change on the lab device that sets an anonymous option.

    The change added an option to the anonymous ``system`` section, so the
    undo deletes it; the change's own diff names the section the way the
    router does (``cfg01e48a``).
    """
    _original, current = _confirmed_change(
        configured,
        device=LAB_DEVICE,
        host=LAB_HOST,
        package="system",
        before="config system\n\toption hostname 'p'\n",
        after=(
            "config system\n"
            "\toption hostname 'p'\n"
            f"\toption description '{value}'\n"
        ),
        diff=f"system.cfg01e48a.description='{value}'",
        uci_batch=f"set system.@system[0].description='{value}'\n",
    )
    return current


def test_un01_an_anonymous_undo_of_a_plain_value_is_not_critical(
    configured: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The undo of an anonymous option's plain value needs no approval.

    The value the change set was plain text, so the policy has nothing to
    fail safe about and the undo is not critical.

    The shape is measured: on Pulsar (2026-11-04) the original change diff
    was ``system.cfg01e48a.description='dialog test'`` and the plan_undo diff
    was ``-system.cfg01e48a.description``, the same cfg id.
    """
    current = _pulsar_change(configured, "dialog test")
    _install_fake_script(
        monkeypatch,
        current,
        plan_diff="-system.cfg01e48a.description",
        plan_section="SECTION system cfg01e48a system -",
    )

    result = server.NewtonService().plan_undo(LAB_DEVICE, SID, AGENT, True)

    assert "error" not in result
    assert result["risk"] != "critical"
    assert not any(
        reason.startswith("path-option") for reason in result["approval_reasons"]
    )
    record = json.loads(
        (configured / "state" / "plans" / f"{UNDO_SID}.json").read_text(encoding="utf-8")
    )
    assert record["risk"] != "critical"
    assert not any(reason.startswith("path-option") for reason in record["reasons"])


def test_un01_an_anonymous_undo_of_a_path_value_is_critical(
    configured: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The undo of an anonymous option that held a path fails safe."""
    current = _pulsar_change(configured, "/etc/foo")
    _install_fake_script(
        monkeypatch,
        current,
        plan_diff="-system.cfg01e48a.description",
        plan_section="SECTION system cfg01e48a system -",
    )

    result = server.NewtonService().plan_undo(LAB_DEVICE, SID, AGENT, True)

    assert "error" not in result
    assert result["risk"] == "critical"
    assert any(
        reason.startswith("path-option") for reason in result["approval_reasons"]
    )
    record = json.loads(
        (configured / "state" / "plans" / f"{UNDO_SID}.json").read_text(encoding="utf-8")
    )
    assert record["risk"] == "critical"
    assert any(reason.startswith("path-option") for reason in record["reasons"])


def test_un02_refused_undo_never_plans(
    configured: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _original, _current = _confirmed_change(configured)
    edited = _tarball(configured / "edited.tar.gz", {"dhcp": EDITED})
    calls = _install_fake_script(monkeypatch, edited)

    with pytest.raises(NewtonError) as excinfo:
        server.NewtonService().plan_undo(DEVICE, SID, AGENT, True)

    assert "changed since this change" in str(excinfo.value)
    assert "plan" not in _verbs(calls)


def test_un03_verify_failure_aborts_the_new_session(
    configured: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _original, current = _confirmed_change(configured)
    changed_plan_backup = _tarball(
        configured / "changed-plan.tar.gz", {"dhcp": EDITED}
    )
    calls = _install_fake_script(
        monkeypatch, current, plan_backup=changed_plan_backup
    )

    with pytest.raises(NewtonError) as excinfo:
        server.NewtonService().plan_undo(DEVICE, SID, AGENT, True)

    assert "changed while the undo was being planned" in str(excinfo.value)
    assert _verbs(calls) == ["backup", "plan", "abort"]
    abort_call = next(args for _device, args, _kwargs in calls if args[0] == "abort")
    assert abort_call == ("abort", f"root@{HOST}", UNDO_SID)


def test_un04_unconfirmed_change_is_refused_before_planning(
    configured: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _original, current = _confirmed_change(configured, outcome="rolled_back")
    calls = _install_fake_script(monkeypatch, current)

    with pytest.raises(NewtonError) as excinfo:
        server.NewtonService().plan_undo(DEVICE, SID, AGENT, True)

    assert "only a change that ended CONFIRMED" in str(excinfo.value)
    assert "ROLLED BACK" in str(excinfo.value)
    assert "plan" not in _verbs(calls)


def test_un05_non_lab_undo_requires_approval(
    configured: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _original, current = _confirmed_change(configured)
    _install_fake_script(monkeypatch, current)

    planned = server.NewtonService().plan_undo(DEVICE, SID, AGENT, True)
    assert planned["requires_approval"] is True

    applied = server.newton_apply_change(DEVICE, UNDO_SID)
    assert "approval required" in applied["error"]
    assert "newton-approve" in applied["error"]


def test_un05_lab_undo_keeps_the_lab_approval_carveout(
    configured: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _original, current = _confirmed_change(
        configured, device=LAB_DEVICE, host=LAB_HOST
    )
    _install_fake_script(
        monkeypatch,
        current,
        apply_stdout=f"CONFIRMED session={UNDO_SID}\n",
    )

    planned = server.NewtonService().plan_undo(LAB_DEVICE, SID, AGENT, True)
    assert planned["requires_approval"] is False

    applied = server.newton_apply_change(LAB_DEVICE, UNDO_SID)
    assert applied["result"] == "confirmed"


def test_un06_confighash_is_stored_and_hidden(
    configured: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    record = _apply_record(configured)
    before_hash = record["plan_hash"]
    stdout = (
        f"APPLYING session={SID}\n"
        f"CONFIGHASH {'a' * 32} dhcp\n"
        f"CONFIGHASH {'b' * 32} network\n"
        f"CONFIRMED session={SID}\n"
    )

    def fake_run(
        self: server.NewtonService,
        device: server.Device,
        *args: str,
        **kwargs: Any,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(list(args), 0, stdout, "")

    monkeypatch.setattr(server.NewtonService, "run_script", fake_run)
    result = server.newton_apply_change(LAB_DEVICE, SID)

    assert result["result"] == "confirmed"
    stored = json.loads(
        (configured / "state" / "plans" / f"{SID}.json").read_text(encoding="utf-8")
    )
    assert stored["after_hash"] == {"dhcp": "a" * 32, "network": "b" * 32}
    assert compute_plan_hash(stored) == before_hash
    assert "CONFIGHASH" not in result["log"]["text"]
    assert "a" * 32 not in result["log"]["text"]
    receipt = _receipts(configured)[0]
    receipt_text = receipt.read_text(encoding="utf-8")
    assert "CONFIGHASH" not in receipt_text
    assert "a" * 32 not in receipt_text


def test_un06_bad_confighash_stores_nothing(
    configured: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _apply_record(configured)
    stdout = (
        f"APPLYING session={SID}\n"
        "CONFIGHASH not-an-md5 dhcp\n"
        f"CONFIRMED session={SID}\n"
    )

    def fake_run(
        self: server.NewtonService,
        device: server.Device,
        *args: str,
        **kwargs: Any,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(list(args), 0, stdout, "")

    monkeypatch.setattr(server.NewtonService, "run_script", fake_run)
    result = server.newton_apply_change(LAB_DEVICE, SID)

    assert result["result"] == "confirmed"
    stored = json.loads(
        (configured / "state" / "plans" / f"{SID}.json").read_text(encoding="utf-8")
    )
    assert "after_hash" not in stored


def test_un06_no_confighash_stores_nothing(
    configured: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _apply_record(configured)
    stdout = f"APPLYING session={SID}\nCONFIRMED session={SID}\n"

    def fake_run(
        self: server.NewtonService,
        device: server.Device,
        *args: str,
        **kwargs: Any,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(list(args), 0, stdout, "")

    monkeypatch.setattr(server.NewtonService, "run_script", fake_run)
    result = server.newton_apply_change(LAB_DEVICE, SID)

    assert result["result"] == "confirmed"
    stored = json.loads(
        (configured / "state" / "plans" / f"{SID}.json").read_text(encoding="utf-8")
    )
    assert "after_hash" not in stored


def test_un06_confighash_storage_failure_does_not_change_the_result(
    configured: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _apply_record(configured)
    stdout = (
        f"APPLYING session={SID}\n"
        f"CONFIGHASH {'a' * 32} dhcp\n"
        f"CONFIRMED session={SID}\n"
    )

    def fake_run(
        self: server.NewtonService,
        device: server.Device,
        *args: str,
        **kwargs: Any,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(list(args), 0, stdout, "")

    def fail_record(*args: Any, **kwargs: Any) -> bool:
        raise RuntimeError("storage failed")

    monkeypatch.setattr(server.NewtonService, "run_script", fake_run)
    monkeypatch.setattr(undo_plan, "record_after_hash", fail_record)
    result = server.newton_apply_change(LAB_DEVICE, SID)

    assert result["result"] == "confirmed"
    stored = json.loads(
        (configured / "state" / "plans" / f"{SID}.json").read_text(encoding="utf-8")
    )
    assert "after_hash" not in stored


def test_un06_rolled_back_apply_never_stores_confighash(
    configured: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _apply_record(configured)
    stdout = (
        f"APPLYING session={SID}\n"
        f"CONFIGHASH {'a' * 32} dhcp\n"
        f"ROLLBACK WINDOW PASSED session={SID} - router reachable; rolled back by rpcd\n"
    )

    def fake_run(
        self: server.NewtonService,
        device: server.Device,
        *args: str,
        **kwargs: Any,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(list(args), 1, stdout, "")

    monkeypatch.setattr(server.NewtonService, "run_script", fake_run)
    result = server.newton_apply_change(LAB_DEVICE, SID)

    assert result["result"] == "rolled_back"
    stored = json.loads(
        (configured / "state" / "plans" / f"{SID}.json").read_text(encoding="utf-8")
    )
    assert "after_hash" not in stored


@pytest.mark.parametrize("owner", [None, False, "yes"])
def test_un01_owner_yes_is_checked_before_any_device_contact(
    configured: Path, monkeypatch: pytest.MonkeyPatch, owner: object
) -> None:
    _original, current = _confirmed_change(configured)
    calls = _install_fake_script(monkeypatch, current)

    with pytest.raises(NewtonError):
        server.NewtonService().plan_undo(DEVICE, SID, AGENT, owner)

    assert calls == []
