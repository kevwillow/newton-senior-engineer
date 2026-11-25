"""The stage approval's ``not_before`` from the helper's journal (PLAN-1.5
task 8; DESIGN-1.5 "Checkpoints"; open point 3 of task 7) and the
``newton-approve ad-build`` and ``ad-build-stage`` subcommands.

``approve_ad_build_stage`` reads each waiting server's journal itself,
through the helper transport (a status of stage 0 under that server's
plan token), and passes ``not_before`` = max(plan approval NBF, the
previous stage's recorded completion on that server) to the adapter.  It
never takes the bound from the runner's state file, and it refuses when the
read fails, the journal records no completion of the previous stage, or
the time is not a UTC second.
"""

from __future__ import annotations

import base64
import io
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from newton_mcp import approve
from newton_mcp.ad.build import checkpoint as build_checkpoint
from newton_mcp.ad.build import plan
from test_build_approve import (  # type: ignore[import-not-found]
    CHECKPOINT_ID,
    CHECKPOINT_NAME,
    NOW,
    PASSPHRASE,
    PLAN_ID,
    FakeVerifier,
    JournalTransport,
    _approve_build,
    _approve_stage,
    _key,
    _stage_approval_path,
    _write_run_state,
    built_plan,  # noqa: F401  (fixtures)
    state_dir,  # noqa: F401
    stored_plan,  # noqa: F401
)


def _nbf() -> int:
    record = json.loads((approve.build_plan_dir() / f"{PLAN_ID}.approval.json").read_text())
    return int(record["nbf"])


def test_the_bound_is_the_previous_stage_completion_in_the_journal(
    stored_plan: Path, state_dir: Path, built_plan: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Stage 2 of build1 is bounded by stage 1's completion on build1, when
    it is later than the plan approval's NBF."""
    _write_run_state(state_dir, built_plan)
    assert _approve_build(monkeypatch) == 0
    later = _nbf() + 600
    journal = JournalTransport({"0": _nbf() + 60, "1": later})
    verifier = FakeVerifier()
    assert _approve_stage(monkeypatch, "2", verifier=verifier, transport=journal) == 0
    assert verifier.bounds == [later]


def test_the_bound_is_the_plan_nbf_when_the_completion_is_older(
    stored_plan: Path, state_dir: Path, built_plan: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_run_state(state_dir, built_plan)
    assert _approve_build(monkeypatch) == 0
    journal = JournalTransport({"0": _nbf() - 7200, "1": _nbf() - 3600})
    verifier = FakeVerifier()
    assert _approve_stage(monkeypatch, "2", verifier=verifier, transport=journal) == 0
    assert verifier.bounds == [_nbf()]


def test_the_journal_is_read_through_a_status_under_the_plan_token(
    stored_plan: Path, state_dir: Path, built_plan: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    run = "c3" * 16
    path = _write_run_state(state_dir, built_plan)
    state = json.loads(path.read_text())
    state["run"] = run
    path.write_text(json.dumps(state))
    assert _approve_build(monkeypatch) == 0
    journal = JournalTransport()
    assert _approve_stage(monkeypatch, "2", transport=journal) == 0
    assert len(journal.requests) == 1
    device, request = journal.requests[0]
    record = json.loads((approve.build_plan_dir() / f"{PLAN_ID}.approval.json").read_text())
    assert device == "build1"
    assert request == {
        "run": run,
        "plan": base64.b64encode(plan.canonical_bytes(built_plan)).decode("ascii"),
        "stage": "0",
        "action": "status",
        "token": record["tokens"]["build1"],
        "nbf": record["nbf"],
        "exp": record["exp"],
    }
    assert request["token"] == plan.plan_token(_key("build1"), plan.digest(built_plan), record["nbf"], record["exp"])


@pytest.mark.parametrize(
    "completed",
    [
        {"0": 1797000000},  # no completion of stage 1
        {"0": 1797000000, "1": "1797000000"},
        {"0": 1797000000, "1": True},
        {"0": 1797000000, "1": 99},
        {"0": 1797000000, "1": 1797000000.5},
        {"0": 1797000000, "1": 1797000000, "11": 1797000000},
    ],
)
def test_a_journal_without_a_readable_previous_completion_is_refused(
    completed: dict[str, Any],
    stored_plan: Path,
    state_dir: Path,
    built_plan: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _write_run_state(state_dir, built_plan)
    assert _approve_build(monkeypatch) == 0
    capsys.readouterr()
    verifier = FakeVerifier()
    assert _approve_stage(monkeypatch, "2", verifier=verifier, transport=JournalTransport(completed)) == 1
    assert verifier.calls == []
    assert not _stage_approval_path("2").exists()
    assert "checkpoint_unverified" in capsys.readouterr().err


@pytest.mark.parametrize(
    "answer",
    [
        {"ok": False, "status": "refused", "code": "bad_token", "checks": []},
        # a refused read is refused even if it carried completions
        {"ok": False, "status": "refused", "code": "expired", "checks": [], "completed": {"0": 1797000000, "1": 1797000000}},
        {"ok": True, "status": "done", "code": "", "checks": []},
        {"ok": True, "status": "done", "code": "", "checks": [], "completed": []},
    ],
)
def test_a_refused_or_shapeless_journal_read_is_refused(
    answer: dict[str, Any],
    stored_plan: Path,
    state_dir: Path,
    built_plan: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _write_run_state(state_dir, built_plan)
    assert _approve_build(monkeypatch) == 0
    capsys.readouterr()
    verifier = FakeVerifier()
    assert _approve_stage(monkeypatch, "2", verifier=verifier, transport=JournalTransport(answer=answer)) == 1
    assert verifier.calls == []
    assert "checkpoint_unverified" in capsys.readouterr().err


def test_the_approval_refuses_without_a_transport(
    stored_plan: Path,
    state_dir: Path,
    built_plan: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _write_run_state(state_dir, built_plan)
    assert _approve_build(monkeypatch) == 0
    capsys.readouterr()
    monkeypatch.setattr(approve, "_getpass", lambda prompt: PASSPHRASE)
    monkeypatch.setattr("sys.stdin", io.StringIO(f"approve stage 2 of {PLAN_ID[:8]}\n"))
    verifier = FakeVerifier()
    assert approve.approve_ad_build_stage(PLAN_ID, "2", verifier=verifier, transport=None, now=NOW) == 1
    assert verifier.calls == []
    assert "checkpoint_unverified" in capsys.readouterr().err


def test_the_run_state_never_feeds_the_bound(
    stored_plan: Path, state_dir: Path, built_plan: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A run state that claims a bound, or completions, is not read for
    them: the adapter gets the journal's."""
    path = _write_run_state(state_dir, built_plan)
    state = json.loads(path.read_text())
    state["not_before"] = 1000000001
    state["completed"] = {"1": 1000000001}
    state["servers"]["build1"]["not_before"] = 1000000001
    state["servers"]["build1"]["completed"] = {"1": 1000000001}
    path.write_text(json.dumps(state))
    assert _approve_build(monkeypatch) == 0
    journal_time = _nbf() + 900
    verifier = FakeVerifier()
    assert _approve_stage(monkeypatch, "2", verifier=verifier, transport=JournalTransport({"0": _nbf(), "1": journal_time})) == 0
    assert verifier.bounds == [journal_time]


# --------------------------------------------------------------------------
# the real Hyper-V adapter, with a fake host and a fake journal
# --------------------------------------------------------------------------


def _hv_adapters(created: str, argvs: list[list[str]]) -> Any:
    listing = json.dumps(
        [{"name": CHECKPOINT_NAME, "id": CHECKPOINT_ID, "created": created, "vm": "BUILD1", "checkpoint_type": "ProductionOnly"}]
    )

    def run(argv: list[str]) -> tuple[int, str]:
        argvs.append(list(argv))
        return 0, listing

    hyperv = build_checkpoint.HyperVAdapter(
        {"build1": build_checkpoint.HyperVTarget(ssh=("ssh", "hv@hvhost.example.test"), vm="BUILD1")},
        run=run,
        read_genid=lambda server_cfg: "",
        read_showbackup=lambda server_cfg: build_checkpoint.ShowbackupRead("", 0),
    )
    return build_checkpoint.CheckpointAdapters({"hyperv": hyperv})


def _utc(text: str) -> int:
    return int(datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp())


def test_a_checkpoint_older_than_the_journal_completion_is_refused_by_the_real_adapter(
    stored_plan: Path,
    state_dir: Path,
    built_plan: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The checkpoint was taken before stage 1 completed on build1: the
    real adapter, given the journal's bound, refuses it."""
    _write_run_state(state_dir, built_plan)
    monkeypatch.setattr(approve, "_getpass", lambda prompt: PASSPHRASE)
    monkeypatch.setattr("sys.stdin", io.StringIO(f"approve {PLAN_ID[:8]}\n"))
    assert approve.approve_ad_build(PLAN_ID, now=datetime(2026, 12, 31, 22, tzinfo=timezone.utc)) == 0
    capsys.readouterr()
    created = "2026-12-31T23:50:00Z"
    argvs: list[list[str]] = []
    journal = JournalTransport({"0": _utc("2026-12-31T23:00:00Z"), "1": _utc("2026-12-31T23:55:00Z")})
    assert _approve_stage(monkeypatch, "2", verifier=_hv_adapters(created, argvs), transport=journal) == 1
    assert len(argvs) == 1
    assert not _stage_approval_path("2").exists()
    assert "checkpoint_unverified" in capsys.readouterr().err


def test_a_checkpoint_after_the_journal_completion_verifies_through_the_real_adapter(
    stored_plan: Path, state_dir: Path, built_plan: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_run_state(state_dir, built_plan)
    monkeypatch.setattr(approve, "_getpass", lambda prompt: PASSPHRASE)
    monkeypatch.setattr("sys.stdin", io.StringIO(f"approve {PLAN_ID[:8]}\n"))
    assert approve.approve_ad_build(PLAN_ID, now=datetime(2026, 12, 31, 22, tzinfo=timezone.utc)) == 0
    argvs: list[list[str]] = []
    journal = JournalTransport({"0": _utc("2026-12-31T23:00:00Z"), "1": _utc("2026-12-31T23:40:00Z")})
    assert _approve_stage(monkeypatch, "2", verifier=_hv_adapters("2026-12-31T23:50:00Z", argvs), transport=journal) == 0
    assert argvs == [["ssh", "hv@hvhost.example.test", "list", "BUILD1"]]
    assert _stage_approval_path("2").exists()


def test_a_checkpoint_of_an_earlier_run_is_refused_by_the_plan_nbf(
    stored_plan: Path,
    state_dir: Path,
    built_plan: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The journal's completion is old (an earlier run), and the
    checkpoint predates this plan's approval: the NBF refuses it."""
    _write_run_state(state_dir, built_plan)
    monkeypatch.setattr(approve, "_getpass", lambda prompt: PASSPHRASE)
    monkeypatch.setattr("sys.stdin", io.StringIO(f"approve {PLAN_ID[:8]}\n"))
    assert approve.approve_ad_build(PLAN_ID, now=datetime(2026, 12, 31, 23, 55, tzinfo=timezone.utc)) == 0
    argvs: list[list[str]] = []
    journal = JournalTransport({"0": _utc("2026-12-30T23:00:00Z"), "1": _utc("2026-12-30T23:40:00Z")})
    assert _approve_stage(monkeypatch, "2", verifier=_hv_adapters("2026-12-31T23:50:00Z", argvs), transport=journal) == 1
    assert not _stage_approval_path("2").exists()


# --------------------------------------------------------------------------
# the subcommands
# --------------------------------------------------------------------------


class _Tty(io.StringIO):
    def isatty(self) -> bool:
        return True


def test_the_reapproval_command_of_an_expired_plan_is_a_real_subcommand(monkeypatch: pytest.MonkeyPatch) -> None:
    """The expired-approval text names ``newton-approve ad-build <id>``;
    ``main`` runs the plan approval for it."""
    command = approve.build_plan_approve_command(PLAN_ID)
    assert command in approve._plan_approval_expired_text(PLAN_ID)
    words = command.split()
    assert words[0] == "newton-approve"
    seen: list[str] = []
    monkeypatch.setattr(approve, "approve_ad_build", lambda plan_id: seen.append(plan_id) or 0)
    monkeypatch.setattr("sys.stdin", _Tty(""))
    assert approve.main(words[1:]) == 0
    assert seen == [PLAN_ID]


def test_the_ad_build_subcommand_needs_a_terminal_and_a_plan_id(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(approve, "approve_ad_build", lambda plan_id: pytest.fail("approved"))
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    assert approve.main(["ad-build", PLAN_ID]) == 1
    monkeypatch.setattr("sys.stdin", _Tty(""))
    assert approve.main(["ad-build", "nothex"]) == 2
    assert approve.main(["ad-build"]) == 2


def test_the_ad_build_stage_subcommand_refuses_without_a_build_config(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("NEWTON_AD_BUILD_CONFIG", str(tmp_path / "absent.toml"))
    monkeypatch.setattr(approve, "approve_ad_build_stage", lambda *a, **k: pytest.fail("approved"))
    monkeypatch.setattr("sys.stdin", _Tty(""))
    assert approve.main(["ad-build-stage", PLAN_ID, "2"]) == 1
    err = capsys.readouterr().err
    assert "checkpoint_unverified" in err and "no token was written" in err


def test_the_ad_build_stage_subcommand_builds_the_adapters_and_the_transport_from_the_config(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from newton_mcp.ad.build import config as build_config
    from newton_mcp.ad.build import transport as build_transport

    path = tmp_path / "ad-build.toml"
    path.write_text(
        "version = 1\n[servers.build1]\nhost = \"192.0.2.11\"\nport = 22\n"
        f"key_file = \"{tmp_path}/k\"\nknown_hosts = \"{tmp_path}/kh\"\n",
        encoding="utf-8",
    )
    path.chmod(0o600)
    monkeypatch.setenv("NEWTON_AD_BUILD_CONFIG", str(path))
    seen: list[tuple[Any, ...]] = []

    def fake(plan_id: str, stage: str, *, verifier: Any, transport: Any) -> int:
        seen.append((plan_id, stage, verifier, transport))
        return 0

    monkeypatch.setattr(approve, "approve_ad_build_stage", fake)
    monkeypatch.setattr("sys.stdin", _Tty(""))
    assert approve.main(["ad-build-stage", PLAN_ID, "3"]) == 0
    (plan_id, stage, verifier, transport), = seen
    assert (plan_id, stage) == (PLAN_ID, "3")
    assert isinstance(verifier, build_checkpoint.CheckpointAdapters)
    assert isinstance(transport, build_transport.SshHelperTransport)
    assert build_config.config_path() == path


def test_the_ad_build_stage_subcommand_takes_only_a_stage_of_the_design(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.stdin", _Tty(""))
    assert approve.main(["ad-build-stage", PLAN_ID, "2;x"]) == 2
    assert approve.main(["ad-build-stage", PLAN_ID]) == 2
