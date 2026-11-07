"""Generic vendor change driver and VyOS operations.

The driver is pure orchestration over an injected runner.  These tests pin the
session order, the refusal paths, rollback-first recovery, fresh-session
verification, and the meta checks that catch plausible driver defects.


"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from typing import Any

import pytest

from newton_mcp import vendor_change as vc
from newton_mcp.adapters import routeros_write as rw
from newton_mcp.adapters import vendor_write as vw


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
BASE_HASH = hashlib.sha256(BASE_CONFIG.encode()).hexdigest()


def _ok(stdout: str = "", exit_code: int = 0) -> vc.RunOut:
    return vc.RunOut(
        status="ok",
        stdout=stdout,
        stderr="",
        exit_code=exit_code,
    )


def _plan(
    *,
    text: str = CHANGE_TEXT,
    base_hash: str = BASE_HASH,
    probes: list[list[str]] | None = None,
    timeout_s: int = 150,
) -> dict[str, Any]:
    return {
        "uci_batch": text,
        "base_hash": base_hash,
        "timeout_s": timeout_s,
        "probes": [] if probes is None else probes,
    }


def _kind(spec: vw.SessionSpec) -> str:
    if spec.remote == vw.read_config_command().remote:
        return "read config"
    if spec.remote == vw.status_command().remote:
        return "timer"
    if spec.remote.startswith("ping "):
        return "ping"
    lines = spec.stdin.splitlines()
    if "compare saved" in lines:
        return "saved check"
    if "save" in lines:
        return "save script"
    if any(line.startswith("commit-confirm ") for line in lines):
        return "apply script"
    if "confirm" in lines:
        return "confirm script"
    if "revert_soft" in spec.stdin:
        return "abort script"
    if "discard" in lines:
        return "stage script"
    raise AssertionError(f"unknown session kind: {spec.remote!r}")


class FakeRunner:
    """A scripted VyOS device that records every fresh session."""

    def __init__(
        self,
        *,
        config: str = BASE_CONFIG,
        changed_config: str = CHANGED_CONFIG,
        saved_clean: bool = True,
        pending: str = "idle",
        stage_result: vw.StageResult | None = None,
        stage_output: str | None = None,
        apply_result: str = "committed",
        apply_line_error: int = 2,
        confirm_result: bool = True,
        abort_result: bool = True,
        ping_result: bool = True,
        save_result: bool = True,
        read_outcomes: list[vc.RunOut | None] | None = None,
        overrides: Mapping[int, vc.RunOut | BaseException] | None = None,
        unreachable_after_abort: bool = False,
        config_after_line_error: str | None = None,
    ) -> None:
        self.config = config
        self.initial_config = config
        self.changed_config = changed_config
        self.saved_clean = saved_clean
        self.pending = pending
        self.stage_result = stage_result
        self.stage_output = stage_output
        self.apply_result = apply_result
        self.apply_line_error = apply_line_error
        self.confirm_result = confirm_result
        self.abort_result = abort_result
        self.ping_result = ping_result
        self.save_result = save_result
        self.read_outcomes = list(read_outcomes or [])
        self.overrides = dict(overrides or {})
        self.unreachable_after_abort = unreachable_after_abort
        self.config_after_line_error = config_after_line_error
        self.calls: list[vw.SessionSpec] = []
        self.armed = pending == "pending"
        self.abort_seen = False

    def __call__(self, spec: vw.SessionSpec) -> vc.RunOut:
        self.calls.append(spec)
        override = self.overrides.get(len(self.calls))
        if isinstance(override, BaseException):
            raise override
        if override is not None:
            return override
        kind = _kind(spec)
        if kind == "read config":
            if self.abort_seen and self.unreachable_after_abort:
                return vc.RunOut(
                    status="unreachable",
                    stdout="",
                    stderr="unreachable",
                    exit_code=None,
                )
            if self.read_outcomes:
                scripted = self.read_outcomes.pop(0)
                if scripted is not None:
                    return scripted
            return _ok(self.config)
        if kind == "timer":
            if self.pending == "pending":
                return _ok("active\n")
            if self.pending == "idle":
                return _ok("inactive\n")
            return _ok("unknown\n")
        if kind == "saved check":
            if self.saved_clean:
                return _ok(
                    "NEWTON-BEGIN-SAVED\n"
                    "No changes between working and saved configurations.\n"
                    "NEWTON-END-SAVED\n"
                )
            return _ok("NEWTON-BEGIN-SAVED\n[edit system]\nNEWTON-END-SAVED\n")
        if kind == "stage script":
            if self.stage_output is not None:
                return _ok(self.stage_output)
            if self.stage_result is not None:
                if self.stage_result.bad_line is not None:
                    return _ok(f"NEWTON-LINE-ERROR {self.stage_result.bad_line}\n")
                return _ok(
                    "NEWTON-BEGIN-DIFF\n[edit system host-name]\n"
                    "+host-name 'lab-router'\nNEWTON-END-DIFF\n"
                )
            return _ok(
                "NEWTON-BEGIN-DIFF\n[edit system host-name]\n"
                "+host-name 'lab-router'\nNEWTON-END-DIFF\n"
            )
        if kind == "apply script":
            if self.apply_result == "committed":
                self.config = self.changed_config
                self.pending = "pending"
                self.armed = True
                return _ok("NEWTON-COMMITTED rc=0\n")
            if self.apply_result == "line_error":
                if self.config_after_line_error is not None:
                    self.config = self.config_after_line_error
                    self.pending = "pending"
                    self.armed = True
                return _ok(f"NEWTON-LINE-ERROR {self.apply_line_error}\n")
            self.config = self.changed_config
            self.pending = "pending"
            self.armed = True
            return _ok("device rejected the change\n")
        if kind == "confirm script":
            if self.confirm_result:
                self.pending = "idle"
                self.armed = False
                return _ok("NEWTON-CONFIRMED rc=0\n")
            return _ok("NEWTON-CONFIRMED rc=1\n")
        if kind == "abort script":
            self.abort_seen = True
            if self.abort_result:
                self.config = self.initial_config
                self.pending = "idle"
                self.armed = False
                return _ok("NEWTON-ABORT revert_rc=0\n")
            return _ok("NEWTON-ABORT revert_rc=1\n")
        if kind == "save script":
            if self.save_result:
                return _ok("NEWTON-SAVED rc=0\n")
            return _ok("NEWTON-SAVED rc=1\n")
        if kind == "ping":
            return _ok("", 0 if self.ping_result else 1)
        raise AssertionError(f"unhandled session kind: {kind}")


class FakeOps:
    """A vendor operation set with explicit, inspectable state."""

    platform = "vyos"

    def __init__(
        self,
        *,
        snapshots: list[vc.Snapshot],
        stage_result: vw.StageResult | None = None,
        apply_result: str = "committed",
        confirm_result: bool = True,
        abort_result: bool = True,
        pending_result: str = "idle",
        pending_results: list[str] | None = None,
        ping_result: bool = True,
        has_line_result: bool = True,
        save_result: bool = True,
    ) -> None:
        self.snapshots = list(snapshots)
        self.stage_result = stage_result or vw.StageResult(ok=True, diff="diff", bad_line=None)
        self.apply_result = apply_result
        self.confirm_result = confirm_result
        self.abort_result = abort_result
        self.pending_result = pending_result
        self.pending_results = list(pending_results or [])
        self.ping_result = ping_result
        self.has_line_result = has_line_result
        self.save_result = save_result
        self.events: list[str] = []

    def snapshot(self, run: vc.Run) -> vc.Snapshot:
        self.events.append("snapshot")
        index = min(self.events.count("snapshot") - 1, len(self.snapshots) - 1)
        return self.snapshots[index]

    def stage(self, run: vc.Run, stmts: list[list[str]]) -> vw.StageResult:
        self.events.append("stage")
        return self.stage_result

    def apply(self, run: vc.Run, stmts: list[list[str]], timeout_s: int) -> str:
        self.events.append("apply")
        return self.apply_result

    def confirm(self, run: vc.Run) -> bool:
        self.events.append("confirm")
        return self.confirm_result

    def save(self, run: vc.Run) -> bool:
        self.events.append("save")
        return self.save_result

    def abort(self, run: vc.Run) -> bool:
        self.events.append("abort")
        return self.abort_result

    def pending(self, run: vc.Run) -> str:
        self.events.append("pending")
        if self.pending_results:
            value = self.pending_results[0]
            if len(self.pending_results) > 1:
                self.pending_results.pop(0)
            return value
        return self.pending_result

    def probe_ping(self, run: vc.Run, host: str) -> bool:
        self.events.append("ping")
        return self.ping_result

    def has_line(self, snapshot_text: str, rendered_line: str) -> bool:
        self.events.append("has_line")
        return self.has_line_result


def _snapshot(text: str, *, pending: str = "idle") -> vc.Snapshot:
    return vc.Snapshot(
        text=text,
        base_hash=hashlib.sha256(text.encode()).hexdigest(),
        reload_ok=True,
        saved_clean=True,
        pending=pending,
    )


def test_happy_path_uses_the_exact_session_sequence() -> None:
    """Preflight, apply, fresh verify, probe, confirm and timer."""
    runner = FakeRunner()
    outcome = vc.apply_plan(
        vw.VyosOps(),
        runner,
        _plan(),
        [["ping", "192.0.2.1"]],
    )

    assert outcome.result == "confirmed"
    assert outcome.failed_probe is None
    assert outcome.lost_out_of_band is False
    assert [_kind(spec) for spec in runner.calls] == [
        "read config",
        "saved check",
        "timer",
        "apply script",
        "read config",
        "saved check",
        "timer",
        "ping",
        "confirm script",
        "timer",
        "save script",
    ]
    apply_index = next(
        index for index, spec in enumerate(runner.calls) if _kind(spec) == "apply script"
    )
    confirm_index = next(
        index for index, spec in enumerate(runner.calls) if _kind(spec) == "confirm script"
    )
    assert apply_index != confirm_index
    assert all(index > apply_index for index in range(apply_index + 1, len(runner.calls)))


def test_arm_and_change_share_one_apply_session() -> None:
    """The apply session carries both the change and commit-confirm."""
    runner = FakeRunner()
    staged = vc.stage_plan(vw.VyosOps(), runner, CHANGE_TEXT, 150)
    assert staged.lines == ["set system host-name lab-router"]
    assert staged.base_hash == BASE_HASH

    outcome = vc.apply_plan(vw.VyosOps(), runner, _plan(), [])
    assert outcome.result == "confirmed"

    stage_calls = [spec for spec in runner.calls if _kind(spec) == "stage script"]
    apply_calls = [spec for spec in runner.calls if _kind(spec) == "apply script"]
    assert len(stage_calls) == 1
    assert len(apply_calls) == 1
    stage_lines = stage_calls[0].stdin.splitlines()
    assert stage_lines[-2:] == ["discard", "exit"]
    assert not any(line == "commit" for line in stage_lines)
    assert not any(line.startswith("commit-confirm ") for line in stage_lines)
    assert "set system host-name lab-router" in apply_calls[0].stdin
    assert "commit-confirm 3 no-prompt" in apply_calls[0].stdin
    apply_index = runner.calls.index(apply_calls[0])
    for spec in runner.calls[:apply_index]:
        if _kind(spec) == "stage script":
            continue
        assert "set " not in spec.stdin
        assert "delete " not in spec.stdin


def test_stage_refusals_have_the_exact_client_safe_messages() -> None:
    """Reload mode, saved state, pending state and bad line refuse."""
    reload_runner = FakeRunner(
        config="\n".join(
            [
                "set system host-name 'base-router'",
                "set system description 'baseline'",
            ]
        )
    )
    with pytest.raises(vc.VendorRefusal) as reload_excinfo:
        vc.stage_plan(vw.VyosOps(), reload_runner, CHANGE_TEXT, 150)
    reload_message = str(reload_excinfo.value)
    assert "set system config-management commit-confirm action reload" in reload_message
    assert "then commit and save" in reload_message
    assert not any(_kind(spec) == "stage script" for spec in reload_runner.calls)

    dirty_runner = FakeRunner(saved_clean=False)
    with pytest.raises(vc.VendorRefusal) as dirty_excinfo:
        vc.stage_plan(vw.VyosOps(), dirty_runner, CHANGE_TEXT, 150)
    assert str(dirty_excinfo.value) == (
        "running config differs from saved; save or discard first"
    )
    assert not any(_kind(spec) == "stage script" for spec in dirty_runner.calls)

    pending_runner = FakeRunner(pending="pending")
    with pytest.raises(vc.VendorRefusal) as pending_excinfo:
        vc.stage_plan(vw.VyosOps(), pending_runner, CHANGE_TEXT, 150)
    assert str(pending_excinfo.value) == (
        "a commit-confirm is already pending on this device"
    )
    assert not any(_kind(spec) == "stage script" for spec in pending_runner.calls)

    bad_runner = FakeRunner(
        stage_result=vw.StageResult(ok=False, diff="device detail", bad_line=2)
    )
    with pytest.raises(vc.VendorRefusal) as bad_excinfo:
        vc.stage_plan(vw.VyosOps(), bad_runner, CHANGE_TEXT, 150)
    assert str(bad_excinfo.value) == "statement 2 was rejected by the device"
    assert "device detail" not in str(bad_excinfo.value)


def test_stale_base_hash_refuses_before_apply() -> None:
    """A changed base hash is stale and makes no apply call."""
    runner = FakeRunner()
    outcome = vc.apply_plan(
        vw.VyosOps(),
        runner,
        _plan(base_hash="0" * 64),
        [],
    )

    assert outcome.result == "stale"
    assert not any(_kind(spec) == "apply script" for spec in runner.calls)


def test_preflight_refusals_make_no_apply_call() -> None:
    """Reload, unsaved and pending preflights refuse before apply."""
    cases = (
        _snapshot(BASE_CONFIG).__class__(
            text=BASE_CONFIG,
            base_hash=BASE_HASH,
            reload_ok=False,
            saved_clean=True,
            pending="idle",
        ),
        _snapshot(BASE_CONFIG).__class__(
            text=BASE_CONFIG,
            base_hash=BASE_HASH,
            reload_ok=True,
            saved_clean=False,
            pending="idle",
        ),
        _snapshot(BASE_CONFIG).__class__(
            text=BASE_CONFIG,
            base_hash=BASE_HASH,
            reload_ok=True,
            saved_clean=True,
            pending="pending",
        ),
    )
    for snapshot in cases:
        ops = FakeOps(snapshots=[snapshot])
        outcome = vc.apply_plan(ops, FakeRunner(), _plan(), [])
        assert outcome.result == "refused"
        assert "apply" not in ops.events


def test_line_error_is_rolled_back_without_confirm() -> None:
    """A rejected apply line discards the candidate and never confirms."""
    runner = FakeRunner(apply_result="line_error", apply_line_error=2)
    outcome = vc.apply_plan(vw.VyosOps(), runner, _plan(), [])

    assert outcome.result == "rolled_back"
    assert "statement 2" in outcome.log
    assert not any(_kind(spec) == "confirm script" for spec in runner.calls)
    assert not any(_kind(spec) == "abort script" for spec in runner.calls)


def test_failed_apply_takes_the_recover_path() -> None:
    """A failed apply aborts first and restores the base hash."""
    runner = FakeRunner(apply_result="failed")
    outcome = vc.apply_plan(vw.VyosOps(), runner, _plan(), [])

    assert outcome.result == "rolled_back"
    kinds = [_kind(spec) for spec in runner.calls]
    assert "abort script" in kinds
    abort_index = kinds.index("abort script")
    assert kinds.index("apply script") < abort_index
    assert kinds[abort_index + 1 :] == ["read config", "saved check", "timer"]
    assert not any(kind == "confirm script" for kind in kinds)


def test_probe_failure_aborts_before_any_confirm() -> None:
    """A failed ping aborts and rolls back, with no confirm call."""
    ops = FakeOps(
        snapshots=[
            _snapshot(BASE_CONFIG),
            _snapshot(CHANGED_CONFIG),
            _snapshot(BASE_CONFIG),
        ],
        ping_result=False,
    )
    outcome = vc.apply_plan(
        ops,
        FakeRunner(),
        _plan(),
        [["ping", "192.0.2.1"]],
    )

    assert outcome.result == "rolled_back"
    assert outcome.failed_probe == ["ping", "192.0.2.1"]
    assert "confirm" not in ops.events
    assert ops.events.index("apply") < ops.events.index("abort")


def test_failed_abort_is_unknown() -> None:
    """A false abort never becomes a rolled_back claim."""
    ops = FakeOps(
        snapshots=[
            _snapshot(BASE_CONFIG),
            _snapshot(CHANGED_CONFIG),
            _snapshot(BASE_CONFIG),
        ],
        ping_result=False,
        abort_result=False,
    )
    outcome = vc.apply_plan(
        ops,
        FakeRunner(),
        _plan(),
        [["ping", "192.0.2.1"]],
    )

    assert outcome.result == "unknown"
    assert "abort" in ops.events


def test_unreachable_recovery_snapshot_is_unknown() -> None:
    """An unreachable recovery snapshot is polled, then unknown."""
    runner = FakeRunner(ping_result=False, unreachable_after_abort=True)
    waits: list[float] = []

    def no_op_wait(seconds: float) -> None:
        waits.append(seconds)

    outcome = vc.apply_plan(
        vw.VyosOps(),
        runner,
        _plan(),
        [["ping", "192.0.2.1"]],
        wait=no_op_wait,
        recover_wait_s=10,
    )

    assert outcome.result == "unknown"
    assert waits == [5, 5]


def test_timed_out_verify_run_is_a_failure() -> None:
    """A verify RunOut with timed_out status triggers recovery."""
    runner = FakeRunner(
        read_outcomes=[
            None,
            vc.RunOut(
                status="timed_out",
                stdout="",
                stderr="timed out",
                exit_code=None,
            ),
        ]
    )
    outcome = vc.apply_plan(vw.VyosOps(), runner, _plan(), [])

    assert outcome.result == "rolled_back"
    assert not any(_kind(spec) == "confirm script" for spec in runner.calls)
    assert any(_kind(spec) == "abort script" for spec in runner.calls)


def test_false_confirm_takes_the_recover_path() -> None:
    """A false confirm aborts and restores the base hash."""
    ops = FakeOps(
        snapshots=[
            _snapshot(BASE_CONFIG),
            _snapshot(CHANGED_CONFIG),
            _snapshot(BASE_CONFIG),
        ],
        confirm_result=False,
    )
    outcome = vc.apply_plan(ops, FakeRunner(), _plan(), [])

    assert outcome.result == "rolled_back"
    assert ops.events.index("confirm") < ops.events.index("abort")


def test_withheld_confirm_leaves_the_revert_armed() -> None:
    """An exception after apply stops before abort or confirm."""
    runner = FakeRunner(overrides={5: RuntimeError("verify stopped")})

    with pytest.raises(RuntimeError, match="verify stopped"):
        vc.apply_plan(vw.VyosOps(), runner, _plan(), [])

    assert len(runner.calls) == 5
    assert runner.armed is True
    assert not any(_kind(spec) == "abort script" for spec in runner.calls)
    assert not any(_kind(spec) == "confirm script" for spec in runner.calls)

    status = vc.change_status(vw.VyosOps(), runner)
    assert status == {
        "pending": "pending",
        "config_matches_base": None,
        "saved": True,
    }
    assert not any(_kind(spec) == "abort script" for spec in runner.calls)
    assert not any(_kind(spec) == "confirm script" for spec in runner.calls)


def test_vyos_abort_reverts_before_stopping_the_timer() -> None:
    """The revert comes first; a failed revert leaves the timer armed."""
    runner = FakeRunner(abort_result=False, pending="pending")
    aborted = vw.VyosOps().abort(runner)

    assert aborted is False
    assert len(runner.calls) == 1
    script = runner.calls[0].stdin
    assert script.index("revert_soft") < script.index(
        "systemctl stop commit-confirm.timer"
    )
    assert 'if [ "$NEWTON_ABORT_RC" -eq 0 ]; then' in script
    assert runner.pending == "pending"
    assert runner.armed is True


def test_claims_run_config_has_and_ping() -> None:
    """Config_has normalises quotes and ping runs on a fresh call."""
    runner = FakeRunner()
    claims = [
        ["config_has", "set system host-name 'lab-router'"],
        ["ping", "192.0.2.1"],
    ]
    outcome = vc.apply_plan(vw.VyosOps(), runner, _plan(), claims)

    assert outcome.result == "confirmed"
    kinds = [_kind(spec) for spec in runner.calls]
    assert kinds.index("ping") > kinds.index("apply script")
    assert kinds.index("confirm script") > kinds.index("ping")
    assert vw.VyosOps().has_line(CHANGED_CONFIG, "set system host-name lab-router")
    assert not vw.VyosOps().has_line(CHANGED_CONFIG, "set system host-name other-router")


def test_abort_change_reports_aborted_and_restored() -> None:
    """Abort_change aborts first, then checks the restored hash."""
    runner = FakeRunner()
    result = vc.abort_change(vw.VyosOps(), runner, BASE_HASH)

    assert result == {"aborted": True, "restored": True}
    kinds = [_kind(spec) for spec in runner.calls]
    assert kinds[0] == "abort script"
    assert kinds[1:] == ["read config", "saved check", "timer"]


def _assert_no_confirm_before_verify(
    apply_plan: Callable[..., vc.ApplyOutcome],
    ops: FakeOps,
) -> None:
    outcome = apply_plan(ops, FakeRunner(), _plan(), [])
    assert outcome.result == "confirmed"
    snapshot_indexes = [
        index for index, event in enumerate(ops.events) if event == "snapshot"
    ]
    confirm_indexes = [index for index, event in enumerate(ops.events) if event == "confirm"]
    assert len(snapshot_indexes) == 2
    assert len(confirm_indexes) == 1
    assert confirm_indexes[0] > snapshot_indexes[1]


def test_meta_confirm_before_verify_is_caught() -> None:
    """A driver that confirms before verify fails the ordering test."""
    ops = FakeOps(
        snapshots=[_snapshot(BASE_CONFIG), _snapshot(CHANGED_CONFIG)],
        pending_result="idle",
    )
    _assert_no_confirm_before_verify(vc.apply_plan, ops)

    def wrong_apply_plan(
        wrong_ops: vc.VendorOps,
        run: vc.Run,
        plan: Mapping[str, Any],
        claims: list[list[str]],
    ) -> vc.ApplyOutcome:
        wrong_ops.confirm(run)
        return vc.apply_plan(wrong_ops, run, plan, claims)

    wrong_ops = FakeOps(
        snapshots=[_snapshot(BASE_CONFIG), _snapshot(CHANGED_CONFIG)],
        pending_result="idle",
    )
    with pytest.raises(AssertionError):
        _assert_no_confirm_before_verify(wrong_apply_plan, wrong_ops)


def _assert_verify_uses_a_fresh_snapshot(
    apply_plan: Callable[..., vc.ApplyOutcome],
    ops: FakeOps,
) -> None:
    outcome = apply_plan(ops, FakeRunner(), _plan(), [])
    assert outcome.result == "confirmed"
    assert ops.events.count("snapshot") == 2
    assert ops.events.index("apply") < ops.events.index("snapshot", ops.events.index("apply") + 1)
    assert ops.events.index("confirm") > ops.events.index(
        "snapshot", ops.events.index("apply") + 1
    )


def test_meta_reusing_the_apply_call_for_verify_is_caught() -> None:
    """Verify must take a new snapshot after apply."""
    ops = FakeOps(
        snapshots=[_snapshot(BASE_CONFIG), _snapshot(CHANGED_CONFIG)],
        pending_result="idle",
    )
    _assert_verify_uses_a_fresh_snapshot(vc.apply_plan, ops)

    def wrong_apply_plan(
        wrong_ops: vc.VendorOps,
        run: vc.Run,
        plan: Mapping[str, Any],
        claims: list[list[str]],
    ) -> vc.ApplyOutcome:
        wrong_ops.snapshot(run)
        wrong_ops.apply(run, [["set", "system", "host-name", "lab-router"]], 150)
        wrong_ops.confirm(run)
        wrong_ops.pending(run)
        return vc.ApplyOutcome(
            result="confirmed",
            log="",
            failed_probe=None,
            lost_out_of_band=False,
            saved=None,
        )

    wrong_ops = FakeOps(
        snapshots=[_snapshot(BASE_CONFIG), _snapshot(CHANGED_CONFIG)],
        pending_result="idle",
    )
    with pytest.raises(AssertionError):
        _assert_verify_uses_a_fresh_snapshot(wrong_apply_plan, wrong_ops)


def _assert_rollback_requires_the_base_hash(
    apply_plan: Callable[..., vc.ApplyOutcome],
    ops: FakeOps,
) -> None:
    outcome = apply_plan(ops, FakeRunner(), _plan(), [])
    assert outcome.result == "unknown"


def test_meta_rollback_without_the_hash_check_is_caught() -> None:
    """Rolled_back is never claimed without the restored base hash."""
    ops = FakeOps(
        snapshots=[
            _snapshot(BASE_CONFIG),
            _snapshot(CHANGED_CONFIG),
        ],
        apply_result="failed",
        abort_result=True,
    )
    _assert_rollback_requires_the_base_hash(vc.apply_plan, ops)

    def wrong_apply_plan(
        wrong_ops: vc.VendorOps,
        run: vc.Run,
        plan: Mapping[str, Any],
        claims: list[list[str]],
    ) -> vc.ApplyOutcome:
        wrong_ops.snapshot(run)
        wrong_ops.apply(run, [["set", "system", "host-name", "lab-router"]], 150)
        wrong_ops.abort(run)
        wrong_ops.snapshot(run)
        return vc.ApplyOutcome(
            result="rolled_back",
            log="",
            failed_probe=None,
            lost_out_of_band=False,
            saved=None,
        )

    wrong_ops = FakeOps(
        snapshots=[
            _snapshot(BASE_CONFIG),
            _snapshot(CHANGED_CONFIG),
        ],
        apply_result="failed",
        abort_result=True,
    )
    with pytest.raises(AssertionError):
        _assert_rollback_requires_the_base_hash(wrong_apply_plan, wrong_ops)


# ---- review fixes ------------------------


def test_the_save_runs_after_the_confirm_in_its_own_session() -> None:
    """The save is a fresh session that comes after the confirm."""
    runner = FakeRunner()
    outcome = vc.apply_plan(vw.VyosOps(), runner, _plan(), [])

    assert outcome.result == "confirmed"
    kinds = [_kind(spec) for spec in runner.calls]
    assert kinds.count("save script") == 1
    confirm_index = kinds.index("confirm script")
    save_index = kinds.index("save script")
    assert save_index > confirm_index
    assert kinds[confirm_index + 1 : save_index] == ["timer"]


def test_a_confirmed_change_is_saved_and_the_log_says_so() -> None:
    """The confirmed outcome says the change was saved."""
    outcome = vc.apply_plan(vw.VyosOps(), FakeRunner(), _plan(), [])

    assert outcome.result == "confirmed"
    assert outcome.log == "the change was verified, confirmed and saved"


def test_a_failed_save_keeps_the_result_and_warns() -> None:
    """A save that failed is in the log, not in the result."""
    runner = FakeRunner(save_result=False)
    outcome = vc.apply_plan(vw.VyosOps(), runner, _plan(), [])

    assert outcome.result == "confirmed"
    assert outcome.log == (
        "the change was verified and confirmed, but it was not saved: "
        "lost on reboot"
    )
    assert any(_kind(spec) == "save script" for spec in runner.calls)


def _assert_save_after_confirm(
    apply_plan: Callable[..., vc.ApplyOutcome],
    ops: FakeOps,
) -> None:
    outcome = apply_plan(ops, FakeRunner(), _plan(), [])
    assert outcome.result == "confirmed"
    assert ops.events.count("save") == 1
    assert ops.events.index("save") > ops.events.index("confirm")


def test_meta_a_save_before_the_confirm_is_caught() -> None:
    """A driver that saves before it confirms fails the ordering test.

    The assertion is written as a function so it can be run twice: once on
    the real driver, and once on a driver that saves before it confirms.
    The second run must raise, or the test proves nothing.
    """
    ops = FakeOps(
        snapshots=[_snapshot(BASE_CONFIG), _snapshot(CHANGED_CONFIG)],
        pending_result="idle",
    )
    _assert_save_after_confirm(vc.apply_plan, ops)

    def wrong_apply_plan(
        wrong_ops: vc.VendorOps,
        run: vc.Run,
        plan: Mapping[str, Any],
        claims: list[list[str]],
    ) -> vc.ApplyOutcome:
        wrong_ops.snapshot(run)
        wrong_ops.apply(run, [["set", "system", "host-name", "lab-router"]], 150)
        wrong_ops.save(run)
        wrong_ops.confirm(run)
        wrong_ops.pending(run)
        return vc.ApplyOutcome(
            result="confirmed",
            log="",
            failed_probe=None,
            lost_out_of_band=False,
            saved=None,
        )

    wrong_ops = FakeOps(
        snapshots=[_snapshot(BASE_CONFIG), _snapshot(CHANGED_CONFIG)],
        pending_result="idle",
    )
    with pytest.raises(AssertionError):
        _assert_save_after_confirm(wrong_apply_plan, wrong_ops)


def test_an_unknown_pending_state_is_refused_before_any_change() -> None:
    """Only "idle" passes the preflight; "unknown" and junk do not."""
    for pending in ("unknown", "weird", "", "IDLE"):
        ops = FakeOps(snapshots=[_snapshot(BASE_CONFIG, pending=pending)])
        outcome = vc.apply_plan(ops, FakeRunner(), _plan(), [])
        assert outcome.result == "refused", pending
        assert "apply" not in ops.events, pending

        stage_ops = FakeOps(snapshots=[_snapshot(BASE_CONFIG, pending=pending)])
        with pytest.raises(vc.VendorRefusal) as excinfo:
            vc.stage_plan(stage_ops, FakeRunner(), CHANGE_TEXT, 150)
        assert str(excinfo.value) == (
            "a commit-confirm is already pending on this device"
        )
        assert "stage" not in stage_ops.events, pending


def test_an_unknown_pending_state_is_refused_by_the_vyos_ops() -> None:
    """The real VyOS adapter reports the same refusal."""
    runner = FakeRunner(pending="unknown")
    outcome = vc.apply_plan(vw.VyosOps(), runner, _plan(), [])

    assert outcome.result == "refused"
    assert not any(_kind(spec) == "apply script" for spec in runner.calls)

    stage_runner = FakeRunner(pending="unknown")
    with pytest.raises(vc.VendorRefusal):
        vc.stage_plan(vw.VyosOps(), stage_runner, CHANGE_TEXT, 150)
    assert not any(_kind(spec) == "stage script" for spec in stage_runner.calls)


def test_a_stored_text_that_does_not_pass_the_lint_is_refused() -> None:
    """A stored change text that breaks the lint is refused."""
    runner = FakeRunner()
    outcome = vc.apply_plan(
        vw.VyosOps(),
        runner,
        _plan(text="set system host-name 'x; reboot'"),
        [],
    )

    assert outcome.result == "refused"
    assert runner.calls == []


def test_an_invalid_stored_probe_is_refused() -> None:
    """A malformed stored probe is refused before any session."""
    bad_probes = (
        [["ping"]],
        [["ping", "192.0.2.1", "extra"]],
        [["nmap", "192.0.2.1"]],
        [["ping", ""]],
        [["", "192.0.2.1"]],
    )
    for probes in bad_probes:
        runner = FakeRunner()
        outcome = vc.apply_plan(vw.VyosOps(), runner, _plan(probes=probes), [])
        assert outcome.result == "refused", probes
        assert runner.calls == [], probes

    not_a_list = dict(_plan())
    not_a_list["probes"] = "ping"
    runner = FakeRunner()
    outcome = vc.apply_plan(vw.VyosOps(), runner, not_a_list, [])
    assert outcome.result == "refused"
    assert runner.calls == []


def test_a_stored_timeout_outside_the_range_is_refused() -> None:
    """A timeout of zero or less is refused before any session."""
    for timeout_s in (0, -1, -600):
        runner = FakeRunner()
        outcome = vc.apply_plan(vw.VyosOps(), runner, _plan(timeout_s=timeout_s), [])
        assert outcome.result == "refused", timeout_s
        assert runner.calls == [], timeout_s

    runner = FakeRunner()
    outcome = vc.apply_plan(vw.VyosOps(), runner, _plan(timeout_s=True), [])
    assert outcome.result == "refused"
    assert runner.calls == []


def test_the_stored_probes_are_really_run() -> None:
    """A stored probe is run, and its failure rolls the change back."""
    ops = FakeOps(
        snapshots=[
            _snapshot(BASE_CONFIG),
            _snapshot(CHANGED_CONFIG),
            _snapshot(BASE_CONFIG),
        ],
        ping_result=False,
    )
    outcome = vc.apply_plan(
        ops,
        FakeRunner(),
        _plan(probes=[["ping", "192.0.2.1"]]),
        [],
    )

    assert outcome.result == "rolled_back"
    assert outcome.failed_probe == ["ping", "192.0.2.1"]
    assert "ping" in ops.events
    assert "confirm" not in ops.events

    line_ops = FakeOps(
        snapshots=[
            _snapshot(BASE_CONFIG),
            _snapshot(CHANGED_CONFIG),
            _snapshot(BASE_CONFIG),
        ],
        has_line_result=False,
    )
    outcome = vc.apply_plan(
        line_ops,
        FakeRunner(),
        _plan(probes=[["config_has", "set system host-name 'lab-router'"]]),
        [],
    )

    assert outcome.result == "rolled_back"
    assert outcome.failed_probe == ["config_has", "set system host-name 'lab-router'"]
    assert "has_line" in line_ops.events


def test_the_stage_plan_branches_refuse_with_their_own_reason() -> None:
    """An unreachable snapshot, a failed stage and a bad line refuse."""
    unreachable = FakeRunner(
        overrides={
            1: vc.RunOut(
                status="unreachable",
                stdout="",
                stderr="no route to host",
                exit_code=None,
            )
        }
    )
    with pytest.raises(vc.VendorRefusal) as excinfo:
        vc.stage_plan(vw.VyosOps(), unreachable, CHANGE_TEXT, 150)
    assert str(excinfo.value) == "the device is unreachable"

    failed_stage = FakeRunner(
        overrides={
            4: vc.RunOut(
                status="unreachable",
                stdout="",
                stderr="no route to host",
                exit_code=None,
            )
        }
    )
    with pytest.raises(vc.VendorRefusal) as excinfo:
        vc.stage_plan(vw.VyosOps(), failed_stage, CHANGE_TEXT, 150)
    assert str(excinfo.value) == "the candidate stage did not complete"

    for bad_line in (1, 2, 3):
        rejected = FakeRunner(
            stage_result=vw.StageResult(ok=False, diff="device detail", bad_line=bad_line)
        )
        with pytest.raises(vc.VendorRefusal) as excinfo:
            vc.stage_plan(vw.VyosOps(), rejected, CHANGE_TEXT, 150)
        assert str(excinfo.value) == f"statement {bad_line} was rejected by the device"
        assert "device detail" not in str(excinfo.value)

    not_accepted = FakeRunner(overrides={4: _ok("compare said nothing useful")})
    with pytest.raises(vc.VendorRefusal) as excinfo:
        vc.stage_plan(vw.VyosOps(), not_accepted, CHANGE_TEXT, 150)
    assert str(excinfo.value) == "the device rejected the candidate configuration"


class _RaisingAbortOps(FakeOps):
    """An ops whose abort raises, as a broken transport would."""

    def abort(self, run: vc.Run) -> bool:
        self.events.append("abort")
        raise RuntimeError("the abort session exploded")


def test_an_abort_that_raises_in_recover_is_unknown() -> None:
    """An exception in the recovery abort does not escape."""
    ops = _RaisingAbortOps(
        snapshots=[
            _snapshot(BASE_CONFIG),
            _snapshot(CHANGED_CONFIG),
            _snapshot(BASE_CONFIG),
        ],
        ping_result=False,
    )
    outcome = vc.apply_plan(ops, FakeRunner(), _plan(), [["ping", "192.0.2.1"]])

    assert outcome.result == "unknown"
    assert outcome.log == "the rollback state is unknown"
    assert "abort" in ops.events


def test_an_abort_that_raises_in_abort_change_is_reported() -> None:
    """Abort_change reports the failure instead of raising."""
    ops = _RaisingAbortOps(snapshots=[_snapshot(BASE_CONFIG)])
    result = vc.abort_change(ops, FakeRunner(), BASE_HASH)

    assert result == {"aborted": False, "restored": None}


def test_the_vyos_save_reads_the_saved_marker() -> None:
    """The VyOS save is true only when the device printed the marker."""
    runner = FakeRunner(save_result=True)
    assert vw.VyosOps().save(runner) is True
    assert [_kind(spec) for spec in runner.calls] == ["save script"]

    failed = FakeRunner(save_result=False)
    assert vw.VyosOps().save(failed) is False

    unreachable = FakeRunner(
        overrides={
            1: vc.RunOut(
                status="unreachable",
                stdout="",
                stderr="no route to host",
                exit_code=None,
            )
        }
    )
    assert vw.VyosOps().save(unreachable) is False


def test_a_save_that_raises_is_reported_as_not_saved() -> None:
    """An exception in the save does not lose the confirmed change."""

    class _RaisingSaveOps(FakeOps):
        def save(self, run: vc.Run) -> bool:
            self.events.append("save")
            raise RuntimeError("the save session exploded")

    ops = _RaisingSaveOps(
        snapshots=[_snapshot(BASE_CONFIG), _snapshot(CHANGED_CONFIG)],
        pending_result="idle",
    )
    outcome = vc.apply_plan(ops, FakeRunner(), _plan(), [])

    assert outcome.result == "confirmed"
    assert outcome.log == (
        "the change was verified and confirmed, but it was not saved: "
        "lost on reboot"
    )


def test_the_docstring_says_the_withheld_confirm_proof_is_a_lab_test() -> None:
    """CS-06 is a lab test; a fake runner cannot model the timer."""
    docstring = vc.__doc__
    assert docstring is not None
    assert "CS-06" in docstring
    assert "LAB" in docstring


# ---- review fixes ------------


class _FlakyPendingOps(FakeOps):
    """An ops whose pending read fails the first ``failures`` times.

    A broken transport is what the pending read after the confirm has to
    survive: the change is already confirmed by then.
    """

    def __init__(self, *args: Any, failures: int = 1, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.failures = failures

    def pending(self, run: vc.Run) -> str:
        self.events.append("pending")
        if self.failures > 0:
            self.failures -= 1
            raise RuntimeError("the pending session exploded")
        return self.pending_result


class _RaisingReadbackOps(FakeOps):
    """An ops whose read-back snapshot raises, as a broken transport would."""

    def snapshot(self, run: vc.Run) -> vc.Snapshot:
        self.events.append("snapshot")
        if self.events.count("snapshot") > 1:
            raise RuntimeError("the read session exploded")
        return self.snapshots[0]


def test_a_pending_read_after_the_confirm_is_retried() -> None:
    """A pending read that fails is retried, then the change confirms.

    The confirm already succeeded, so a failed timer read is a transport
    problem, not a lost change: the driver waits the same bounded way
    ``_recover`` does and the outcome stays confirmed.
    """
    ops = _FlakyPendingOps(
        snapshots=[_snapshot(BASE_CONFIG), _snapshot(CHANGED_CONFIG)],
        failures=1,
    )
    waits: list[float] = []

    outcome = vc.apply_plan(
        ops,
        FakeRunner(),
        _plan(),
        [],
        wait=waits.append,
        recover_wait_s=10,
    )

    assert outcome.result == "confirmed"
    assert outcome.saved is True
    assert waits == [5]
    assert "idle commit-confirm timer" not in outcome.log


def test_a_pending_read_that_never_settles_keeps_the_confirmed_result() -> None:
    """Past the bound the change stays confirmed, with the problem noted."""
    ops = _FlakyPendingOps(
        snapshots=[_snapshot(BASE_CONFIG), _snapshot(CHANGED_CONFIG)],
        failures=99,
    )
    waits: list[float] = []

    outcome = vc.apply_plan(
        ops,
        FakeRunner(),
        _plan(),
        [],
        wait=waits.append,
        recover_wait_s=10,
    )

    assert outcome.result == "confirmed"
    assert outcome.saved is True
    assert waits == [5, 5]
    assert "the device did not report an idle commit-confirm timer" in outcome.log


def test_a_line_error_is_a_rollback_only_when_the_hash_reads_back() -> None:
    """The line-error branch reads the configuration hash back.

    A line error on its own is device text.  Only a configuration hash
    that reads back as the base hash says that nothing was committed.
    """
    restored = FakeOps(
        snapshots=[_snapshot(BASE_CONFIG), _snapshot(BASE_CONFIG)],
        apply_result="line_error",
    )
    outcome = vc.apply_plan(restored, FakeRunner(), _plan(), [])
    assert outcome.result == "rolled_back"
    assert outcome.saved is None

    changed = FakeOps(
        snapshots=[_snapshot(BASE_CONFIG), _snapshot(CHANGED_CONFIG)],
        apply_result="line_error",
    )
    outcome = vc.apply_plan(changed, FakeRunner(), _plan(), [])
    assert outcome.result == "unknown"

    unreadable = _RaisingReadbackOps(
        snapshots=[_snapshot(BASE_CONFIG)],
        apply_result="line_error",
    )
    waits: list[float] = []
    outcome = vc.apply_plan(
        unreadable,
        FakeRunner(),
        _plan(),
        [],
        wait=waits.append,
        recover_wait_s=10,
    )
    assert outcome.result == "unknown"
    # the read that cannot reach the device is retried with the bounded
    # wait loop the recovery uses, and it never turns into a rollback.
    assert waits == [5, 5]


def test_a_forged_line_error_with_a_changed_config_is_not_a_rollback() -> None:
    """A line-error marker with a changed configuration is unknown."""
    runner = FakeRunner(
        apply_result="line_error",
        apply_line_error=2,
        config_after_line_error=CHANGED_CONFIG,
    )
    outcome = vc.apply_plan(vw.VyosOps(), runner, _plan(), [])

    assert outcome.result == "unknown"
    assert outcome.saved is None
    assert not any(_kind(spec) == "confirm script" for spec in runner.calls)


def test_the_outcome_carries_the_saved_state() -> None:
    """Saved is True, False or None; a failed save keeps confirmed."""
    saved = vc.apply_plan(vw.VyosOps(), FakeRunner(), _plan(), [])
    assert saved.result == "confirmed"
    assert saved.saved is True

    not_saved = vc.apply_plan(vw.VyosOps(), FakeRunner(save_result=False), _plan(), [])
    assert not_saved.result == "confirmed"
    assert not_saved.saved is False

    stale = vc.apply_plan(vw.VyosOps(), FakeRunner(), _plan(base_hash="0" * 64), [])
    assert stale.result == "stale"
    assert stale.saved is None


def test_the_status_carries_the_saved_state() -> None:
    """Change_status says whether the running configuration is saved."""
    state = vc.change_status(vw.VyosOps(), FakeRunner())
    assert state["pending"] == "idle"
    assert state["saved"] is True
    assert vc.plan_status_text(state) == "pending: idle; saved"

    dirty = vc.change_status(vw.VyosOps(), FakeRunner(saved_clean=False))
    assert dirty["saved"] is False
    assert "not saved: lost on reboot" in vc.plan_status_text(dirty)


def test_the_status_does_not_confirm_or_abort() -> None:
    """The status only reads, it never confirms or reverts."""
    runner = FakeRunner(pending="pending")
    state = vc.change_status(vw.VyosOps(), runner)
    assert state["pending"] == "pending"
    assert not any(_kind(spec) == "confirm script" for spec in runner.calls)
    assert not any(_kind(spec) == "abort script" for spec in runner.calls)


# ---- a VyOS line error is not in the exit status ---------------------


def test_a_line_error_from_the_device_refuses_the_plan() -> None:
    """The marker the stderr guard writes refuses the plan.

    VyOS reports a refused path on stderr and exits zero, so the script
    writes the marker itself when the error file is not empty.  The plan
    is refused and the statement that failed is named.
    """
    runner = FakeRunner(stage_output="NEWTON-LINE-ERROR 1\n")

    with pytest.raises(vc.VendorRefusal) as excinfo:
        vc.stage_plan(vw.VyosOps(), runner, CHANGE_TEXT, 150)

    assert str(excinfo.value) == "statement 1 was rejected by the device"
    assert any(_kind(spec) == "stage script" for spec in runner.calls)


def test_an_empty_staged_diff_refuses_the_plan() -> None:
    """A staged diff with nothing to change refuses the plan.

    There is nothing to change, so the plan is refused before it is
    written.  The refusal is a short reason and carries no device text.
    """
    runner = FakeRunner(
        stage_output=(
            "NEWTON-BEGIN-DIFF\n"
            "No changes between working and active configurations\n"
            "NEWTON-END-DIFF\n"
        )
    )

    with pytest.raises(vc.VendorRefusal) as excinfo:
        vc.stage_plan(vw.VyosOps(), runner, CHANGE_TEXT, 150)

    assert str(excinfo.value) == (
        "the candidate configuration is the same as the running one; "
        "nothing to change"
    )


def test_a_statement_that_writes_stderr_takes_the_line_error_path() -> None:
    """The apply stops at the line error and never confirms.

    The statement that writes to stderr is caught before the commit, so
    the change is not committed and the device is back at the base
    configuration.
    """
    runner = FakeRunner(apply_result="line_error", apply_line_error=1)

    outcome = vc.apply_plan(vw.VyosOps(), runner, _plan(), [])

    assert outcome.result == "rolled_back"
    assert "statement 1" in outcome.log
    assert not any(_kind(spec) == "confirm script" for spec in runner.calls)

    apply_script = next(
        spec.stdin for spec in runner.calls if _kind(spec) == "apply script"
    )
    lines = apply_script.splitlines()
    checks = [
        index
        for index, line in enumerate(lines)
        if line.startswith('if [ "$NEWTON_RC" ')
    ]
    assert checks
    assert checks[-1] < lines.index("commit-confirm 3 no-prompt")


# ---- the generic driver over a RouterOS CHR -------------------------
#
# A CHR has no native revert: the driver arms a backup plus a scheduler
# entry that loads the backup when it fires.  The device-side objects are
# therefore the state of the fake, and the tests below read that state
# instead of a marker in the output.


CHR_BASE_CONFIG = "\n".join(
    [
        "# 2026-10-24 10:00:00 by RouterOS 7.24.5",
        "/system identity",
        "set name=chr-baseline",
    ]
)
CHR_CHANGED_CONFIG = "\n".join(
    [
        "# 2026-10-24 10:00:00 by RouterOS 7.24.5",
        "/system identity",
        "set name=p11-chr",
    ]
)
CHR_CHANGE_TEXT = "/system identity set name=p11-chr"
# Two lines: the second one is only reached when the first one ran.
CHR_TWO_LINES = (
    "/system identity set name=p11-chr\n"
    "/ip address add address=198.51.100.7/24 interface=bridge"
)
CHR_BASE_HASH = rw.config_hash(CHR_BASE_CONFIG)
CHR_PING_OK = (
    "    sent=3 received=3 packet-loss=0% min-rtt=0ms avg-rtt=0ms max-rtt=0ms"
)
CHR_PING_LOST = (
    "    sent=3 received=0 packet-loss=100% min-rtt=0ms avg-rtt=0ms max-rtt=0ms"
)


def _chr_plan(
    *,
    text: str = CHR_CHANGE_TEXT,
    base_hash: str = CHR_BASE_HASH,
    probes: list[list[str]] | None = None,
    timeout_s: int = 150,
) -> dict[str, Any]:
    return {
        "uci_batch": text,
        "base_hash": base_hash,
        "timeout_s": timeout_s,
        "probes": [] if probes is None else probes,
    }


class FakeChrRunner:
    """A scripted RouterOS CHR for the generic driver.

    The fake holds the state the CHR holds: the configuration, the
    newton-revert scheduler entry and the newton-revert.backup file.  The
    arm creates them, the statements change the configuration, the load
    restores the configuration of the backup and removes them again.

    The counters make the device misbehave the way a device misbehaves: the
    arm can fail, the export can be unreachable while the device reboots,
    the scheduler entry can vanish in the middle of the change and the
    load can drop its session.
    """

    def __init__(
        self,
        *,
        config: str = CHR_BASE_CONFIG,
        statement_failures: Mapping[str, vc.RunOut] | None = None,
        ping_result: bool = True,
        confirm_ok: bool = True,
        fail_after: int | None = None,
        arm_ok: bool = True,
        arm_output: str = "Configuration backup saved\narmed for 23:31:23",
        config_after_arm: str | None = None,
        export_failures: int = 0,
        export_failures_after: int = 0,
        load_status: str = "ok",
        load_exit_code: int | None = 0,
        load_reboots: bool = True,
        scheduler_vanishes_after: int | None = None,
    ) -> None:
        self.config = config
        self.initial_config = config
        self.statement_failures = dict(statement_failures or {})
        self.ping_result = ping_result
        self.confirm_ok = confirm_ok
        self.fail_after = fail_after
        self.arm_ok = arm_ok
        self.arm_output = arm_output
        self.config_after_arm = config_after_arm
        self.export_failures = export_failures
        self.export_failures_after = export_failures_after
        self.load_status = load_status
        self.load_exit_code = load_exit_code
        self.load_reboots = load_reboots
        self.scheduler_vanishes_after = scheduler_vanishes_after
        self.calls: list[vw.SessionSpec] = []
        self.scheduler_present = False
        self.backup_present = False
        self.loaded = False
        self.stated = False
        self.exports = 0
        self.scheduler_reads = 0
        self.loads = 0

    @property
    def remotes(self) -> list[str]:
        return [spec.remote for spec in self.calls]

    def __call__(self, spec: vw.SessionSpec) -> vc.RunOut:
        self.calls.append(spec)
        if self.fail_after is not None and len(self.calls) > self.fail_after:
            raise RuntimeError("the verify session exploded")
        remote = spec.remote
        if remote == rw.export_command().remote:
            self.exports += 1
            if (
                self.export_failures_after
                < self.exports
                <= self.export_failures_after + self.export_failures
            ):
                return vc.RunOut(
                    status="unreachable",
                    stdout="",
                    stderr="connection timed out during banner exchange",
                    exit_code=255,
                )
            return _ok(self.config)
        if remote == rw.scheduler_count_command().remote:
            self.scheduler_reads += 1
            if (
                self.scheduler_vanishes_after is not None
                and self.scheduler_reads > self.scheduler_vanishes_after
            ):
                self.scheduler_present = False
            return _ok("1" if self.scheduler_present else "0")
        if remote == rw.backup_count_command().remote:
            return _ok("1" if self.backup_present else "0")
        if remote == rw.scheduler_detail_command().remote:
            return _ok(
                '0  name="newton-revert" start-date=2026-10-24 start-time=23:31:23 '
                "interval=0s\n"
                '   on-event=/system backup load name=newton-revert password=""\n'
                "   next-run=2026-10-24 23:31:23\n"
            )
        if remote == rw.scheduler_remove_command().remote:
            self.scheduler_present = False
            return _ok("") if self.confirm_ok else _ok("", 1)
        if remote == rw.backup_remove_command().remote:
            self.backup_present = False
            return _ok("")
        if remote == rw.load_command().remote:
            self.loaded = True
            self.loads += 1
            if self.load_reboots:
                self.scheduler_present = False
                self.backup_present = False
                self.config = self.initial_config
            if self.load_status != "ok":
                return vc.RunOut(
                    status=self.load_status,  # type: ignore[arg-type]
                    stdout="",
                    stderr="connection timed out during banner exchange",
                    exit_code=self.load_exit_code,
                )
            return _ok(
                "System configuration restored, rebooting now",
                exit_code=self.load_exit_code,
            )
        if remote == rw.uptime_command().remote:
            return _ok("00:00:30")
        if remote.startswith(":put "):
            return _ok(remote[6:-1])
        if remote.startswith(":local t ("):
            if "/system scheduler add" in remote:
                if self.config_after_arm is not None:
                    self.config = self.config_after_arm
                if not self.arm_ok:
                    return _ok("failure: cannot save the backup", 1)
                self.scheduler_present = True
                self.backup_present = True
                return _ok(self.arm_output)
            if "/system scheduler set" in remote:
                if not self.scheduler_present:
                    return _ok("no such item (4)", 1)
                return _ok("")
            raise AssertionError(f"unknown session: {remote!r}")
        if remote.startswith("/ping "):
            return _ok(CHR_PING_OK if self.ping_result else CHR_PING_LOST)
        scripted = self.statement_failures.get(remote)
        if scripted is not None:
            return scripted
        if remote == CHR_CHANGE_TEXT:
            self.stated = True
            self.config = CHR_CHANGED_CONFIG
            return _ok("")
        return _ok("")


def test_the_chr_happy_path_is_confirmed() -> None:
    """The CHR change is armed, verified and confirmed."""
    runner = FakeChrRunner()
    outcome = vc.apply_plan(
        rw.RouterosOps(),
        runner,
        _chr_plan(),
        [["ping", "192.0.2.1"]],
    )

    assert outcome.result == "confirmed"
    assert outcome.saved is True
    assert outcome.failed_probe is None
    remotes = runner.remotes
    # the arm comes before the change, and the confirm after the probe
    assert remotes.index(rw.arm_command(150).remote) < remotes.index(
        CHR_CHANGE_TEXT
    )
    assert remotes.index(CHR_CHANGE_TEXT) < remotes.index(
        rw.ping_command("192.0.2.1").remote
    )
    assert remotes.index(rw.ping_command("192.0.2.1").remote) < remotes.index(
        rw.scheduler_remove_command().remote
    )
    # the confirm removed both device-side objects
    assert runner.scheduler_present is False
    assert runner.backup_present is False


def test_a_failed_probe_rolls_the_chr_change_back() -> None:
    """A failed ping loads the backup and the hash comes back."""
    runner = FakeChrRunner(ping_result=False)
    outcome = vc.apply_plan(
        rw.RouterosOps(),
        runner,
        _chr_plan(),
        [["ping", "192.0.2.1"]],
    )

    assert outcome.result == "rolled_back"
    assert outcome.failed_probe == ["ping", "192.0.2.1"]
    remotes = runner.remotes
    assert rw.load_command().remote in remotes
    assert remotes.index(rw.load_command().remote) < remotes.index(
        rw.scheduler_remove_command().remote
    )
    assert runner.config == CHR_BASE_CONFIG


def test_a_bad_line_rolls_the_chr_change_back() -> None:
    """A bad line is a line error and the change is rolled back."""
    runner = FakeChrRunner(
        statement_failures={
            CHR_CHANGE_TEXT: vc.RunOut(
                status="ok",
                stdout="invalid value for argument name (/system/identity/set; "
                "line 1)",
                stderr="",
                exit_code=1,
            )
        }
    )
    outcome = vc.apply_plan(rw.RouterosOps(), runner, _chr_plan(), [])

    assert outcome.result == "rolled_back"
    assert "statement 1" in outcome.log
    assert rw.load_command().remote in runner.remotes
    assert runner.config == CHR_BASE_CONFIG


def test_a_withheld_confirm_leaves_the_chr_revert_armed() -> None:
    """Hard rule 6, the revert stays armed when the confirm is missed."""
    runner = FakeChrRunner(fail_after=6)
    with pytest.raises(RuntimeError, match="the verify session exploded"):
        vc.apply_plan(rw.RouterosOps(), runner, _chr_plan(), [])

    assert runner.scheduler_present is True
    assert runner.backup_present is True
    assert rw.load_command().remote not in runner.remotes
    assert rw.scheduler_remove_command().remote not in runner.remotes


def test_the_line_error_read_back_waits_for_the_device() -> None:
    """A CHR abort reboots, so the hash read is retried.

    The first two reads after the line error cannot reach the device: it is
    still rebooting.  The driver waits for it, the way the recovery does,
    and only then reads the hash back.  The test drives the real CHR
    operations, so a change in ``RouterosOps`` cannot hide here.
    """
    runner = FakeChrRunner(
        statement_failures={CHR_CHANGE_TEXT: _chr_line_failure()},
        export_failures=2,
        export_failures_after=1,
    )
    waits: list[float] = []

    outcome = vc.apply_plan(
        rw.RouterosOps(wait=lambda seconds: None),
        runner,
        _chr_plan(),
        [],
        wait=waits.append,
        recover_wait_s=10,
    )

    assert outcome.result == "rolled_back"
    assert waits == [5, 5]


def test_a_read_back_that_never_comes_is_unknown() -> None:
    """Past the bound the rollback state stays unknown."""
    runner = FakeChrRunner(
        statement_failures={CHR_CHANGE_TEXT: _chr_line_failure()},
        export_failures=99,
        export_failures_after=1,
    )
    waits: list[float] = []

    outcome = vc.apply_plan(
        rw.RouterosOps(wait=lambda seconds: None),
        runner,
        _chr_plan(),
        [],
        wait=waits.append,
        recover_wait_s=10,
    )

    assert outcome.result == "unknown"
    assert waits == [5, 5]


def _chr_line_failure() -> vc.RunOut:
    """The answer of a CHR that refused a line."""
    return vc.RunOut(
        status="ok",
        stdout="invalid value for argument name (/system/identity/set; line 1)",
        stderr="",
        exit_code=1,
    )


# ---- review fixes ------------------------
#
# The review found an arm guard with no test, a driver that loaded a backup
# the ops had just deleted, a dropped abort session that forced a second
# load, and a recovery that gave up on a read that raised.  The tests below
# are the fixes.


def test_the_armed_failed_branch_reads_the_hash_back() -> None:
    """An armed_failed means no change line ran: nothing changed.

    The ops deleted the backup when it could not arm the revert, so the
    driver must not load it: the hash is read back and the base hash says
    that nothing was committed.
    """
    runner = FakeChrRunner(arm_ok=False)
    outcome = vc.apply_plan(rw.RouterosOps(), runner, _chr_plan(), [])

    assert outcome.result == "rolled_back"
    assert outcome.log == "the revert could not be armed; nothing was changed"
    assert rw.load_command().remote not in runner.remotes
    assert runner.scheduler_present is False
    assert runner.backup_present is False


def test_an_armed_failed_that_cannot_be_proven_is_unknown() -> None:
    """A hash that is not the base hash is unknown, not a rollback."""
    changed = FakeChrRunner(arm_ok=False, config_after_arm=CHR_CHANGED_CONFIG)
    outcome = vc.apply_plan(rw.RouterosOps(), changed, _chr_plan(), [])
    assert outcome.result == "unknown"

    unreadable = FakeChrRunner(
        arm_ok=False, export_failures=99, export_failures_after=1
    )
    waits: list[float] = []
    outcome = vc.apply_plan(
        rw.RouterosOps(),
        unreadable,
        _chr_plan(),
        [],
        wait=waits.append,
        recover_wait_s=10,
    )
    assert outcome.result == "unknown"
    assert waits == [5, 5]


class _WordOps:
    """An ops that remembers the word its apply returned."""

    def __init__(self, ops: Any) -> None:
        self._ops = ops
        self.word: str | None = None

    def __getattr__(self, name: str) -> Any:
        return getattr(self._ops, name)

    def apply(self, run: vc.Run, statements: list[list[str]], timeout_s: int) -> str:
        self.word = self._ops.apply(run, statements, timeout_s)
        return self.word


def test_the_revert_lost_case_takes_the_recover_path() -> None:
    """A change that ran a line is undone by the recover path.

    The scheduler vanished after the first line, so the change is not an
    "armed_failed": the driver aborts and reads the hash back.
    """
    runner = FakeChrRunner(scheduler_vanishes_after=2)
    ops = _WordOps(rw.RouterosOps())
    outcome = vc.apply_plan(ops, runner, _chr_plan(text=CHR_TWO_LINES), [])

    assert ops.word == "revert_lost"
    assert rw.load_command().remote in runner.remotes
    assert outcome.result == "rolled_back"
    assert outcome.log == "the device restored the base configuration"


def test_a_dropped_load_session_sends_the_load_once() -> None:
    """A dropped abort session must not force a second load.

    The device reboots into the backup and the session of the load drops.
    That is the load, not a failure: the ops proves it on the device and
    the driver reads the hash back.  A second load would reboot a device
    that is already back at the base configuration.
    """
    runner = FakeChrRunner(
        statement_failures={CHR_CHANGE_TEXT: _chr_line_failure()},
        load_status="unreachable",
        load_exit_code=255,
    )
    outcome = vc.apply_plan(rw.RouterosOps(), runner, _chr_plan(), [])

    assert runner.remotes.count(rw.load_command().remote) == 1
    assert outcome.result == "rolled_back"
    assert "statement 1" in outcome.log


def test_the_recover_waits_for_a_read_that_raised() -> None:
    """The recover retries the read that raised.

    The CHR reboots into the backup, so the first read of the recovery can
    fail while the device is down.  The read is retried the way the
    read-back after a line error is retried.
    """

    class _RaisingOnceOps(FakeOps):
        """An ops whose second snapshot raises, as a broken transport would."""

        def snapshot(self, run: vc.Run) -> vc.Snapshot:
            self.events.append("snapshot")
            index = self.events.count("snapshot")
            if index == 2:
                raise RuntimeError("the read session exploded")
            return self.snapshots[min(index - 1, len(self.snapshots) - 1)]

    ops = _RaisingOnceOps(
        snapshots=[_snapshot(BASE_CONFIG), _snapshot(BASE_CONFIG)],
        apply_result="failed",
    )
    waits: list[float] = []

    outcome = vc.apply_plan(
        ops,
        FakeRunner(),
        _plan(),
        [],
        wait=waits.append,
        recover_wait_s=10,
    )

    assert outcome.result == "rolled_back"
    assert waits == [5]


# ---- review fixes ------------------------
#
# The review found two blockers against the Junos path of the driver:
#
# the confirm did not prove that the change was still on the device.
#     The armed revert can fire between the verify and the confirm, and
#     the driver then confirmed a device that held the base
#     configuration.  The ops that stage a candidate know the hash of
#     that candidate, so the driver reads a fresh snapshot after the
#     confirm and compares it with the candidate.
# a session that died while it held the exclusive lock leaves the
#     database of the device locked, and every abort after it was refused
#     with "configuration database locked".  The abort is retried with
#     the bounded wait of the recovery.


class _CandidateOps(FakeOps):
    """An ops that stages a candidate and knows its hash, like a Junos."""

    platform = "junos"

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.expected_hash: str | None = None


def _candidate_ops(*snapshots: vc.Snapshot) -> _CandidateOps:
    """An ops whose candidate is the hash of the configuration it staged."""
    ops = _CandidateOps(snapshots=list(snapshots))
    ops.expected_hash = hashlib.sha256(CHANGED_CONFIG.encode()).hexdigest()
    return ops


def test_the_confirm_is_proved_by_a_fresh_snapshot() -> None:
    """The confirm does not prove that the change is still there.

    The ops that stage a candidate know the hash of that candidate.  The
    driver reads a fresh snapshot after the confirm: when the
    configuration that comes back is not the candidate, the result is
    unknown and never confirmed.
    """
    ops = _candidate_ops(
        _snapshot(BASE_CONFIG),
        _snapshot(CHANGED_CONFIG),
        _snapshot(BASE_CONFIG),
    )
    outcome = vc.apply_plan(ops, FakeRunner(), _plan(), [])

    assert outcome.result == "unknown"
    assert outcome.log == (
        "the device differs from the verified change after the confirm"
    )
    assert outcome.saved is None


def test_a_confirmed_change_that_is_still_there_is_confirmed() -> None:
    """The candidate that comes back after the confirm confirms."""
    ops = _candidate_ops(
        _snapshot(BASE_CONFIG),
        _snapshot(CHANGED_CONFIG),
        _snapshot(CHANGED_CONFIG),
    )
    outcome = vc.apply_plan(ops, FakeRunner(), _plan(), [])

    assert outcome.result == "confirmed"
    assert outcome.saved is True


class _LockedAbortOps(FakeOps):
    """An ops whose abort session is refused by a locked database.

    A Junos keeps the configuration database locked when the session
    that held it died, and every session after it is refused with
    "configuration database locked" until the device lets go of the lock.

    The revert of the change is still armed while the device is locked,
    so the pending read of the ops says "pending": the abort may run
    again when the device lets go of the lock.
    """

    def __init__(self, **kwargs: Any) -> None:
        kwargs.setdefault("pending_result", "pending")
        super().__init__(**kwargs)
        self.lock_failures = 0
        self.abort_calls = 0

    def abort(self, run: vc.Run) -> bool:
        self.events.append("abort")
        self.abort_calls += 1
        if self.abort_calls <= self.lock_failures:
            run(vw.SessionSpec(remote="vbash -s", stdin="revert_soft\n"))
            return False
        return super().abort(run)


def _locked_runner(calls: int = 1, message: str | None = None) -> FakeRunner:
    """A runner whose first sessions are refused with a lock message."""
    text = message or "error: configuration database locked by user 'admin'\n"
    return FakeRunner(
        overrides={
            index: _ok(text) for index in range(1, calls + 1)
        }
    )


@pytest.mark.parametrize(
    "message",
    (
        "error: configuration database locked\n",
        "error: the exclusive lock is held by another session\n",
        "error: configuration database locked by user 'admin'\n",
    ),
)
def test_an_abort_that_the_device_refuses_with_a_lock_is_retried(
    message: str,
) -> None:
    """The abort waits for the lock of the device to go away.

    The retry is the bounded wait of the recovery: a step of five
    seconds and the same bound.
    """
    ops = _LockedAbortOps(
        snapshots=[
            _snapshot(BASE_CONFIG),
            _snapshot(CHANGED_CONFIG),
            _snapshot(BASE_CONFIG),
        ],
        ping_result=False,
    )
    ops.lock_failures = 1
    waits: list[float] = []

    outcome = vc.apply_plan(
        ops,
        _locked_runner(1, message),
        _plan(),
        [["ping", "192.0.2.1"]],
        wait=waits.append,
        recover_wait_s=10,
    )

    assert waits == [5]
    assert ops.abort_calls == 2
    assert outcome.result == "rolled_back"


def test_a_lock_that_never_goes_away_is_unknown() -> None:
    """Past the bound the rollback state stays unknown."""
    ops = _LockedAbortOps(
        snapshots=[
            _snapshot(BASE_CONFIG),
            _snapshot(CHANGED_CONFIG),
            _snapshot(BASE_CONFIG),
        ],
        ping_result=False,
    )
    ops.lock_failures = 99
    waits: list[float] = []

    outcome = vc.apply_plan(
        ops,
        _locked_runner(3),
        _plan(),
        [["ping", "192.0.2.1"]],
        wait=waits.append,
        recover_wait_s=10,
    )

    assert waits == [5, 5]
    assert outcome.result == "unknown"


def test_the_abort_change_waits_for_the_lock_as_well() -> None:
    """The abort of the tool waits for the lock of the device."""
    ops = _LockedAbortOps(snapshots=[_snapshot(BASE_CONFIG)])
    ops.lock_failures = 1
    waits: list[float] = []

    state = vc.abort_change(
        ops,
        _locked_runner(),
        BASE_HASH,
        wait=waits.append,
        recover_wait_s=10,
    )

    assert waits == [5]
    assert ops.abort_calls == 2
    assert state["aborted"] is True


# ---- review fixes ---
#
# MAJOR 3: the lock of the configuration database was recognised by a
#     bare phrase anywhere in the session, so a configuration value that
#     held the phrase ("locked by") made the driver retry the abort.  The
#     check is now on the refusal of the device: a line that starts with
#     "error:" and carries one of the three things the device says when
#     its database is locked.
#
# The retry also ran the whole abort again.  When the pending read says
#     that the revert is not armed any more, the device rolled back by
#     itself and a second "rollback 1" would roll back the commit of
#     somebody else: the abort is not run again.


def test_a_value_that_holds_the_lock_phrase_is_not_a_lock() -> None:
    """The phrase in the data of a session is not a lock.

    The abort of a device whose configuration holds the phrase (a
    description that says who holds the lock) is not a refusal of the
    device: the abort is not retried.
    """
    ops = _LockedAbortOps(
        snapshots=[_snapshot(BASE_CONFIG), _snapshot(CHANGED_CONFIG)],
        ping_result=False,
    )
    ops.lock_failures = 1
    waits: list[float] = []

    outcome = vc.apply_plan(
        ops,
        _locked_runner(1, "set system description 'locked by the lab'\n"),
        _plan(),
        [["ping", "192.0.2.1"]],
        wait=waits.append,
        recover_wait_s=10,
    )

    assert ops.abort_calls == 1
    assert waits == []
    assert outcome.result == "unknown"


def test_the_abort_is_not_run_again_when_the_revert_is_gone() -> None:
    """The abort is not run again when the revert is gone.

    The device refused the abort because its database was locked, and
    the pending read says that no revert is armed any more: the device
    rolled back by itself.  The abort must not run again.
    """
    ops = _LockedAbortOps(
        snapshots=[_snapshot(BASE_CONFIG), _snapshot(CHANGED_CONFIG)],
        ping_result=False,
        pending_result="idle",
    )
    ops.lock_failures = 1
    waits: list[float] = []

    outcome = vc.apply_plan(
        ops,
        _locked_runner(1),
        _plan(),
        [["ping", "192.0.2.1"]],
        wait=waits.append,
        recover_wait_s=10,
    )

    assert ops.abort_calls == 1
    assert waits == []
    assert outcome.result == "unknown"


@pytest.mark.parametrize(
    "message",
    (
        "error: configuration database locked\n",
        "error: the exclusive lock is held by another session\n",
        "error: configuration database locked by user 'admin'\n",
    ),
)
def test_a_refusal_that_carries_the_phrase_is_a_lock(
    message: str,
) -> None:
    """The refusal of the device is a lock.

    The three things the device says when its configuration database is
    locked are all a lock, as long as the refusal is a line of its own
    that starts with "error:".
    """
    ops = _LockedAbortOps(
        snapshots=[_snapshot(BASE_CONFIG), _snapshot(CHANGED_CONFIG)],
        ping_result=False,
    )
    ops.lock_failures = 1
    waits: list[float] = []

    outcome = vc.apply_plan(
        ops,
        _locked_runner(1, message),
        _plan(),
        [["ping", "192.0.2.1"]],
        wait=waits.append,
        recover_wait_s=10,
    )

    assert ops.abort_calls == 2
    assert waits == [5]
    assert outcome.result == "unknown"
