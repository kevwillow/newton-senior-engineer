"""controller loss in the middle of a vendor change (rule 10).

Rule 10 of the change protocol: when the controller is lost in the
middle of a change, the device ends in the pre-change state or in the
confirmed state, never in between.

The controller of the vendor modes is the MCP process: it drives the
device over ssh, and the device holds the revert while the change waits
for the confirmation:

  * a VyOS holds it in its own commit-confirm timer;
  * a Junos holds it in the commit it made with "commit confirmed";
  * a CHR holds it in a backup and a scheduler entry that loads the
    backup when it fires.

Here the controller is LOST at an exact point of one apply run: the
fake device raises ``KeyboardInterrupt`` -- an exception that nothing
catches -- at that point, so the flow stops there with no clean-up of
its own, the way the process stops when it is killed.  The device-side
revert is then left to the device: the timer of the device is advanced
by the test and the device puts the change back by itself.

The points that are proved, per device:

  (a) right after the change is applied on the device, before the first
      verify: the change is on the device, the revert is armed, and the
      device puts the change back when its timer fires;
  (b) after the verify passed, before the confirm was sent: the same,
      the confirm never reached the device;
  (c) after the confirm was sent and answered: the device confirmed, so
      the change stays and no revert is armed any more.

Every device here is the fake of its own mode: the VyOS and the Junos
fakes of the vendor tests, and a CHR fake that arms the backup and the
scheduler entry and fires the entry on its own.  No device is contacted.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

import newton_mcp.server as server
from newton_mcp.adapters import junos_write
from newton_mcp.adapters import routeros_write
from newton_mcp.adapters import vendor_write
from newton_mcp.vendor_change import RunOut

from test_junos_flow import BASE_CONFIG as JUNOS_BASE_CONFIG
from test_junos_flow import CONFIG_COMMAND as JUNOS_CONFIG_COMMAND
from test_junos_flow import PENDING_COMMAND as JUNOS_PENDING_COMMAND
from test_junos_flow import ScriptedJunos
from test_vendor_flow import BASE_CONFIG as VYOS_BASE_CONFIG
from test_vendor_flow import CHANGED_CONFIG as VYOS_CHANGED_CONFIG
from test_vendor_flow import ScriptedRunner as VyosRunner
from test_vendor_flow import _phase as vyos_phase


# =========================================================================
# THE CLOCK OF THE DEVICE
# =========================================================================


class Clock:
    """The clock of the test: the device reads it and the test moves it.

    The revert of a device runs on the clock of the device, so the test
    moves that clock and not the clock of the host.
    """

    def __init__(self) -> None:
        self.value = time.time()

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


def _ok(stdout: str = "", exit_code: int = 0) -> RunOut:
    return RunOut(status="ok", stdout=stdout, stderr="", exit_code=exit_code)


# =========================================================================
# THE LAB OF A VENDOR DEVICE
# =========================================================================


def _inventory(tmp_path: Path, platform: str, name: str) -> Path:
    """An inventory with one vendor write device."""
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text(
        "192.0.2.9 ssh-ed25519 "
        "AAAAC3NzaC1lZDI1NTE5AAAAIFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE\n",
        encoding="utf-8",
    )
    key_file = tmp_path / "newton-key"
    key_file.write_text("FAKE-KEY-FOR-TESTS\n", encoding="utf-8")
    key_file.chmod(0o600)
    password_file = tmp_path / "pw"
    password_file.write_text("synthetic-password\n", encoding="utf-8")
    password_file.chmod(0o600)
    body = [
        f"[devices.{name}]",
        f'platform = "{platform}"',
        'host = "192.0.2.9"',
        'user = "newton"',
        'auth = "key"',
        'profile = "lab"',
        "vendor_write = true",
        "lab = true",
        f'key_file = "{key_file}"',
        f'known_hosts = "{known_hosts}"',
        f'password_file = "{password_file}"',
    ]
    inventory = tmp_path / "devices.toml"
    inventory.write_text("\n".join(body) + "\n", encoding="utf-8")
    return inventory


@dataclass
class VendorLab:
    """A service, a device behind it and the clock of that device."""

    service: server.NewtonService
    runner: Any
    state: Path
    clock: Clock
    name: str


def _lab(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    platform: str,
    name: str,
    runner: Any,
    clock: Clock,
) -> VendorLab:
    """The service of a vendor device, with a scripted device behind it."""
    inventory = _inventory(tmp_path, platform, name)
    state = tmp_path / "state"
    monkeypatch.setenv("NEWTON_INVENTORY", str(inventory))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(state))

    class FakeRunnerFactory:
        def __call__(self, target: Any) -> Any:
            return runner

    monkeypatch.setattr(server.vendor_flow, "SshSessionRunner", FakeRunnerFactory())
    return VendorLab(server.NewtonService(), runner, state, clock, name)


def _record(lab: VendorLab, session_id: str) -> dict[str, Any]:
    return json.loads(
        (lab.state / "plans" / f"{session_id}.json").read_text(encoding="utf-8")
    )


def _write_approval(lab: VendorLab, session_id: str, record: dict[str, Any]) -> None:
    """The approval the owner made in their own terminal."""
    created = datetime.now(timezone.utc)
    expires = created + timedelta(minutes=10)
    value = {
        "plan_id": session_id,
        "plan_hash": record["plan_hash"],
        "device": lab.name,
        "base_hash": record["base_hash"],
        "created_at": created.isoformat(),
        "expires_at": expires.isoformat(),
        "not_before": int(created.timestamp()),
        "not_after": int(expires.timestamp()),
        "token": "a" * 64,
    }
    approvals = lab.state / "approvals"
    approvals.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = approvals / f"{session_id}.json"
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
    path.chmod(0o600)


def _explain(*expect: dict[str, Any]) -> dict[str, Any]:
    """An explanation whose claims are the probes of the plan."""
    return {
        "intent": "Change one setting of the lab device.",
        "steps": ["Set the value the owner asked for."],
        "expect": list(expect),
        "risk": "The setting of the lab device changes; nothing else does.",
    }


# =========================================================================
# THE VYOS: THE COMMIT-CONFIRM TIMER
# =========================================================================


class LossVyOS(VyosRunner):
    """The fake VyOS whose commit-confirm timer fires on its own.

    The revert of a VyOS is its own commit-confirm timer: the timer is
    armed by the apply and the device puts the change back when the
    timer fires and nobody confirmed.  This fake has that timer: the
    clock is the test's, and the timer fires when the clock passes the
    window that the apply armed.

    The kill is an exception that nothing catches (``KeyboardInterrupt``):
    ``kill_before`` is the session that never reaches the device and
    ``kill_after`` the session the device already answered.  The flow
    stops at the raise, with no clean-up of its own.
    """

    def __init__(self, clock: Clock) -> None:
        super().__init__()
        self.clock = clock
        self.window_ends_at: float | None = None
        self.kill_before: str | None = None
        self.kill_after: str | None = None
        #: the phase of every session, in the order they ran
        self.phases: list[str] = []

    def _fire_the_timer(self) -> None:
        """The timer of the device fires: the device puts the change back."""
        if self.pending != "pending" or self.window_ends_at is None:
            return
        if self.clock() < self.window_ends_at:
            return
        self.config = self.initial_config
        self.pending = "idle"
        self.window_ends_at = None

    def _arm_the_timer(self, spec: Any) -> None:
        """The apply armed the commit-confirm timer of the device."""
        found = re.search(r"commit-confirm (\d+) no-prompt", spec.stdin)
        assert found is not None, spec.stdin
        self.window_ends_at = self.clock() + int(found.group(1)) * 60

    def __call__(self, spec: Any) -> RunOut:
        self._fire_the_timer()
        phase = vyos_phase(spec, self.pending == "pending")
        if self.kill_before == phase:
            raise KeyboardInterrupt(f"the controller was lost before the {phase}")
        self.phases.append(phase)
        answer = super().__call__(spec)
        if phase == "apply":
            self._arm_the_timer(spec)
        if self.kill_after == phase:
            raise KeyboardInterrupt(f"the controller was lost after the {phase}")
        return answer

    def read_config(self) -> str:
        """The running configuration of the device, in a fresh session."""
        return self(vendor_write.read_config_command()).stdout


def _vyos_lab(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> VendorLab:
    clock = Clock()
    return _lab(tmp_path, monkeypatch, "vyos", "vy1", LossVyOS(clock), clock)


def _vyos_plan(lab: VendorLab) -> dict[str, Any]:
    return lab.service.plan(
        "vy1",
        "set system host-name 'lab-router'",
        150,
        explanation=_explain(
            {"kind": "config_has", "line": "set system host-name 'lab-router'"}
        ),
        owner_confirmed_in_chat=True,
    )


# =========================================================================
# THE JUNOS: THE COMMIT OF THE DEVICE
# =========================================================================


def _junos_phase(spec: Any) -> str:
    """The phase of one session of a Junos.

    Every session of a Junos is a session of the CLI: the login shell of
    the device is the CLI, so the reads are scripts as well.
    """
    remote = spec.remote
    if remote.startswith("ping "):
        return "ping"
    lines = [line.strip() for line in spec.stdin.splitlines()]
    first = lines[0] if lines else ""
    if first == JUNOS_CONFIG_COMMAND:
        return "config"
    if first == JUNOS_PENDING_COMMAND:
        return "commit list"
    if any(line.startswith("commit confirmed ") for line in lines):
        return "apply"
    if "rollback 1" in lines:
        return "abort"
    if "commit" in lines and "configure" in lines:
        return "confirm"
    if "show | compare | no-more" in lines:
        return "stage"
    return "other"


class LossJunos(ScriptedJunos):
    """The fake Junos whose commit-confirm timer fires on its own.

    The revert of a Junos is its own commit: the apply commits with
    "commit confirmed N" and the device rolls that commit back when
    nobody confirms it.  This fake has that timer: the clock is the
    test's, and the device rolls the commit back when the clock passes
    the window that the commit armed.
    """

    def __init__(self, clock: Clock) -> None:
        super().__init__()
        self.clock = clock
        self.window_ends_at: float | None = None
        self.kill_before: str | None = None
        self.kill_after: str | None = None
        self.phases: list[str] = []

    def _fire_the_timer(self) -> None:
        """The timer of the device fires: the device rolls the commit back."""
        if not self.pending or self.window_ends_at is None:
            return
        if self.clock() < self.window_ends_at:
            return
        self.committed = list(self.previous)
        self.pending = False
        self.window_ends_at = None

    def _arm_the_timer(self, spec: Any) -> None:
        """The commit armed the revert of the device."""
        found = re.search(r"commit confirmed (\d+)", spec.stdin)
        assert found is not None, spec.stdin
        self.window_ends_at = self.clock() + int(found.group(1)) * 60

    def __call__(self, spec: Any) -> RunOut:
        self._fire_the_timer()
        phase = _junos_phase(spec)
        if self.kill_before == phase:
            raise KeyboardInterrupt(f"the controller was lost before the {phase}")
        self.phases.append(phase)
        answer = super().__call__(spec)
        if phase == "apply":
            self._arm_the_timer(spec)
        if self.kill_after == phase:
            raise KeyboardInterrupt(f"the controller was lost after the {phase}")
        return answer

    def read_config(self) -> str:
        """The running configuration of the device, in a fresh session."""
        out = self(junos_write.config_command())
        return junos_write.config_text(out.stdout)


def _junos_lab(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> VendorLab:
    clock = Clock()
    return _lab(tmp_path, monkeypatch, "junos", "jn1", LossJunos(clock), clock)


def _junos_plan(lab: VendorLab) -> dict[str, Any]:
    return lab.service.plan(
        "jn1",
        "set interfaces lo0 description lab-shape-01",
        150,
        explanation=_explain(
            {
                "kind": "config_has",
                "line": "set interfaces lo0 description lab-shape-01",
            }
        ),
        owner_confirmed_in_chat=True,
    )


# =========================================================================
# THE CHR: THE SCHEDULER ENTRY OF THE DEVICE
# =========================================================================


CHR_BASE_CONFIG = "\n".join(
    [
        "# jan/01/2026 12:00:00 by RouterOS 7.24.5",
        "/ip address",
        "add address=10.109.0.21/24 interface=ether1 network=10.109.0.0",
        "/system identity",
        "set name=lab-chr",
        "",
    ]
)

CHR_CHANGE = "/system identity set name=lab-chr-shape-01"
CHR_PING_HOST = "10.109.0.10"


def _chr_phase(spec: Any) -> str:
    """The phase of one session of a CHR."""
    remote = spec.remote
    if remote == "/export":
        return "export"
    if remote.startswith("/system scheduler print count-only"):
        return "scheduler count"
    if remote.startswith("/file print count-only"):
        return "backup count"
    if remote.startswith("/system scheduler print detail"):
        return "scheduler detail"
    if remote == "/system clock print":
        return "clock"
    if remote.startswith(":local t ("):
        if "/system scheduler add" in remote:
            return "arm"
        if "/system scheduler set" in remote:
            return "refresh"
    if remote.startswith("/system scheduler remove"):
        return "confirm scheduler"
    if remote.startswith("/file remove"):
        return "confirm backup"
    if remote.startswith("/system backup load"):
        return "load"
    if remote.startswith(":put [/system resource get uptime]"):
        return "uptime"
    if remote.startswith("/ping "):
        return "ping"
    if remote.startswith(':put "NEWTON-LINE-ERROR'):
        return "marker"
    return "statement"


class LossChr:
    """The fake CHR whose scheduler entry fires on its own.

    The revert of a CHR is a backup and a scheduler entry: the entry
    loads the backup when it fires, so the device reboots into the
    configuration it had before the change.  This fake has that timer:
    the clock of the device is the test's, and the entry fires when the
    clock passes the window that was armed.

    The kill is an exception that nothing catches (``KeyboardInterrupt``):
    ``kill_before`` is the session that never reaches the device and
    ``kill_after`` the session the device already answered.
    """

    def __init__(self) -> None:
        self.config = CHR_BASE_CONFIG
        #: the configuration the backup of the revert holds
        self.backup: str | None = None
        #: the scheduler entry of the revert is armed
        self.armed = False
        #: the clock of the device
        self.device_time = datetime(2026, 10, 23, 23, 29, 23)
        #: when the armed entry fires
        self.window_ends_at: datetime | None = None
        self.kill_before: str | None = None
        self.kill_after: str | None = None
        self.phases: list[str] = []

    # -- the clock of the device --------------------------------------------

    def advance(self, seconds: float) -> None:
        """Move the clock of the device."""
        self.device_time = self.device_time + timedelta(seconds=seconds)

    def _fire_the_timer(self) -> None:
        """The entry fires: the device reboots into the backup."""
        if not self.armed or self.window_ends_at is None:
            return
        if self.device_time < self.window_ends_at:
            return
        if self.backup is not None:
            self.config = self.backup
        self.armed = False
        self.backup = None
        self.window_ends_at = None

    # -- the device ---------------------------------------------------------

    def export(self) -> str:
        """The /export of the device, the armed entry included."""
        lines = self.config.splitlines()
        if self.armed and self.window_ends_at is not None:
            lines.append("/system scheduler")
            lines.append(
                '  add name=newton-revert interval=0s next-run='
                + self.window_ends_at.strftime("%Y-%m-%d %H:%M:%S")
            )
        return "\n".join(lines) + "\n"

    def _detail(self) -> str:
        """The receipt of the armed entry, as the device prints it."""
        assert self.window_ends_at is not None
        stamp = self.window_ends_at.strftime("%Y-%m-%d %H:%M:%S")
        start = self.window_ends_at.strftime("%H:%M:%S")
        day = self.window_ends_at.strftime("%Y-%m-%d")
        return "\n".join(
            [
                f'0  name="newton-revert" start-date={day} start-time={start} '
                "interval=0s",
                '   on-event=/system backup load name=newton-revert password="" '
                'owner="newton"',
                "   policy=ftp,reboot,read,write,policy,test,password,sensitive "
                "run-count=0",
                f"   next-run={stamp}",
            ]
        )

    def _clock(self) -> str:
        """The clock of the device, as "/system clock print" prints it."""
        months = (
            "jan", "feb", "mar", "apr", "may", "jun",
            "jul", "aug", "sep", "oct", "nov", "dec",
        )
        return (
            f"time: {self.device_time.strftime('%H:%M:%S')}\n"
            f"date: {months[self.device_time.month - 1]}/"
            f"{self.device_time.strftime('%d/%Y')}\n"
        )

    def _arm(self, remote: str) -> None:
        """The arm: the backup is saved and the entry is added."""
        found = re.search(r"\+ (\d{2}):(\d{2}):(\d{2})\)", remote)
        assert found is not None, remote
        hours, minutes, seconds = (int(part) for part in found.groups())
        window = hours * 3600 + minutes * 60 + seconds
        self.backup = self.config
        self.armed = True
        self.window_ends_at = self.device_time + timedelta(seconds=window)

    def _refresh(self, remote: str) -> None:
        """The refresh: the start time of the entry moves in place."""
        found = re.search(r"\+ (\d{2}):(\d{2}):(\d{2})\)", remote)
        assert found is not None, remote
        hours, minutes, seconds = (int(part) for part in found.groups())
        window = hours * 3600 + minutes * 60 + seconds
        self.window_ends_at = self.device_time + timedelta(seconds=window)

    def _statement(self, remote: str) -> None:
        """One change line of the plan runs on the device."""
        found = re.fullmatch(r"/system identity set name=(\S+)", remote)
        if found is None:
            return
        self.config = re.sub(
            r"(?m)^set name=.*$", "set name=" + found.group(1), self.config
        )

    def __call__(self, spec: Any) -> RunOut:
        self._fire_the_timer()
        phase = _chr_phase(spec)
        if self.kill_before == phase:
            raise KeyboardInterrupt(f"the controller was lost before the {phase}")
        self.phases.append(phase)
        answer = self._answer(spec)
        if self.kill_after == phase:
            raise KeyboardInterrupt(f"the controller was lost after the {phase}")
        return answer

    def _answer(self, spec: Any) -> RunOut:
        """The answer of the device to one session."""
        remote = spec.remote
        if remote == "/export":
            return _ok(self.export())
        if remote.startswith("/system scheduler print count-only"):
            return _ok("1\n" if self.armed else "0\n")
        if remote.startswith("/file print count-only"):
            return _ok("1\n" if self.backup is not None else "0\n")
        if remote.startswith("/system scheduler print detail"):
            return _ok(self._detail())
        if remote == "/system clock print":
            return _ok(self._clock())
        if remote.startswith(":local t ("):
            if "/system scheduler add" in remote:
                self._arm(remote)
                return _ok("armed for 23:31:53\n")
            self._refresh(remote)
            return _ok("")
        if remote.startswith("/system scheduler remove"):
            self.armed = False
            return _ok("")
        if remote.startswith("/file remove"):
            self.backup = None
            return _ok("")
        if remote.startswith("/system backup load"):
            if self.backup is not None:
                self.config = self.backup
            self.armed = False
            self.backup = None
            return _ok("System configuration restored, rebooting now\n")
        if remote.startswith(":put [/system resource get uptime]"):
            return _ok("00:00:23\n")
        if remote.startswith("/ping "):
            return _ok("received=3 packets\n")
        if remote.startswith(':put "NEWTON-LINE-ERROR'):
            return _ok("")
        self._statement(remote)
        return _ok("")

    def read_config(self) -> str:
        """The running configuration of the device, in a fresh session."""
        return self(routeros_write.export_command()).stdout


def _chr_lab(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> VendorLab:
    clock = Clock()
    return _lab(tmp_path, monkeypatch, "routeros", "chr1", LossChr(), clock)


def _chr_plan(lab: VendorLab) -> dict[str, Any]:
    return lab.service.plan(
        "chr1",
        CHR_CHANGE,
        150,
        explanation=_explain({"kind": "ping", "host": CHR_PING_HOST}),
        owner_confirmed_in_chat=True,
    )


# =========================================================================
# TESTS: THE VYOS
# =========================================================================


def test_a_vyos_controller_lost_after_the_apply_before_the_first_verify(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The controller dies right after the change is applied on the VyOS.

    The device holds the change and its commit-confirm timer is armed.
    Nothing verified it and nothing confirmed it, so the timer fires and
    the device puts the change back: the device is in the pre-change
    state, the state rule 10 allows.
    """
    lab = _vyos_lab(tmp_path, monkeypatch)
    planned = _vyos_plan(lab)
    record = _record(lab, planned["session_id"])
    _write_approval(lab, planned["session_id"], record)
    # only the sessions of the apply count from here on
    lab.runner.phases.clear()
    lab.runner.kill_after = "apply"

    with pytest.raises(KeyboardInterrupt):
        lab.service.apply("vy1", planned["session_id"])

    # the change is on the device and the timer of the device is armed
    assert lab.runner.config == VYOS_CHANGED_CONFIG
    assert lab.runner.pending == "pending"
    # the first verify never ran and no confirm was sent
    assert "verify config" not in lab.runner.phases
    assert "confirm" not in lab.runner.phases

    # the timer of the device fires by itself
    lab.clock.advance(600)

    # the device is back in the pre-change state
    assert lab.runner.read_config() == VYOS_BASE_CONFIG
    assert lab.runner.pending == "idle"


def test_a_vyos_controller_lost_after_the_verify_before_the_confirm(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The controller dies after the verify and before the confirm.

    The verify passed: the flow only reaches the confirm when every
    check passed, so the loss at the confirm proves it.  The confirm
    never reached the device, so the change is not confirmed and the
    timer of the device puts it back.
    """
    lab = _vyos_lab(tmp_path, monkeypatch)
    planned = _vyos_plan(lab)
    record = _record(lab, planned["session_id"])
    _write_approval(lab, planned["session_id"], record)
    # only the sessions of the apply count from here on
    lab.runner.phases.clear()
    lab.runner.kill_before = "confirm"

    with pytest.raises(KeyboardInterrupt):
        lab.service.apply("vy1", planned["session_id"])

    # the verify ran and the confirm never reached the device
    assert "verify config" in lab.runner.phases
    assert "confirm" not in lab.runner.phases
    # the change is on the device and the timer of the device is armed
    assert lab.runner.config == VYOS_CHANGED_CONFIG
    assert lab.runner.pending == "pending"

    # the timer of the device fires by itself
    lab.clock.advance(600)

    # the device is back in the pre-change state
    assert lab.runner.read_config() == VYOS_BASE_CONFIG
    assert lab.runner.pending == "idle"


def test_a_vyos_controller_lost_after_the_confirm_stays_confirmed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The controller dies after the confirm was sent and answered.

    The device confirmed the change, so the change is the confirmed
    state: the device holds it, no revert is armed any more, and the
    timer that would have fired later changes nothing.
    """
    lab = _vyos_lab(tmp_path, monkeypatch)
    planned = _vyos_plan(lab)
    record = _record(lab, planned["session_id"])
    _write_approval(lab, planned["session_id"], record)
    # only the sessions of the apply count from here on
    lab.runner.phases.clear()
    lab.runner.kill_after = "confirm"

    with pytest.raises(KeyboardInterrupt):
        lab.service.apply("vy1", planned["session_id"])

    # the confirm reached the device and was answered
    assert "confirm" in lab.runner.phases
    # the change is on the device
    assert lab.runner.config == VYOS_CHANGED_CONFIG
    # no revert is armed any more
    assert lab.runner.pending == "idle"

    # the timer that would have fired later changes nothing
    lab.clock.advance(600)
    assert lab.runner.read_config() == VYOS_CHANGED_CONFIG
    assert lab.runner.pending == "idle"


# =========================================================================
# TESTS: THE JUNOS
# =========================================================================


def test_a_junos_controller_lost_after_the_apply_before_the_first_verify(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The controller dies right after the change is applied on the Junos.

    The commit of the device holds the change and the revert with it, so
    the device rolls the commit back when its timer fires: the device
    is in the pre-change state.
    """
    lab = _junos_lab(tmp_path, monkeypatch)
    planned = _junos_plan(lab)
    record = _record(lab, planned["session_id"])
    _write_approval(lab, planned["session_id"], record)
    # only the sessions of the apply count from here on
    lab.runner.phases.clear()
    lab.runner.kill_after = "apply"

    with pytest.raises(KeyboardInterrupt):
        lab.service.apply("jn1", planned["session_id"])

    # the change is on the device and the revert is armed
    assert "set interfaces lo0 description lab-shape-01" in lab.runner.committed
    assert lab.runner.pending is True
    # the first verify never ran and no confirm was sent
    assert lab.runner.phases.count("config") == 1, lab.runner.phases
    assert "confirm" not in lab.runner.phases

    # the timer of the device fires by itself
    lab.clock.advance(600)

    # the device is back in the pre-change state
    assert lab.runner.read_config() == "\n".join(JUNOS_BASE_CONFIG.splitlines())
    assert lab.runner.pending is False


def test_a_junos_controller_lost_after_the_verify_before_the_confirm(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The controller dies after the verify and before the confirm.

    The verify passed: the flow only reaches the confirm when every
    check passed, so the loss at the confirm proves it.  The confirm
    never reached the device, so the change is not confirmed and the
    commit of the device rolls it back when its timer fires.
    """
    lab = _junos_lab(tmp_path, monkeypatch)
    planned = _junos_plan(lab)
    record = _record(lab, planned["session_id"])
    _write_approval(lab, planned["session_id"], record)
    # only the sessions of the apply count from here on
    lab.runner.phases.clear()
    lab.runner.kill_before = "confirm"

    with pytest.raises(KeyboardInterrupt):
        lab.service.apply("jn1", planned["session_id"])

    # the verify ran and the confirm never reached the device
    assert lab.runner.phases.count("config") == 2, lab.runner.phases
    assert "confirm" not in lab.runner.phases
    # the change is on the device and the revert is armed
    assert "set interfaces lo0 description lab-shape-01" in lab.runner.committed
    assert lab.runner.pending is True

    # the timer of the device fires by itself
    lab.clock.advance(600)

    # the device is back in the pre-change state
    assert lab.runner.read_config() == "\n".join(JUNOS_BASE_CONFIG.splitlines())
    assert lab.runner.pending is False


def test_a_junos_controller_lost_after_the_confirm_stays_confirmed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The controller dies after the confirm was sent and answered.

    The device confirmed the commit, so the change is the confirmed
    state: the device holds it, the revert is not armed any more, and
    the timer that would have fired later changes nothing.
    """
    lab = _junos_lab(tmp_path, monkeypatch)
    planned = _junos_plan(lab)
    record = _record(lab, planned["session_id"])
    _write_approval(lab, planned["session_id"], record)
    # only the sessions of the apply count from here on
    lab.runner.phases.clear()
    lab.runner.kill_after = "confirm"

    with pytest.raises(KeyboardInterrupt):
        lab.service.apply("jn1", planned["session_id"])

    # the confirm reached the device and was answered
    assert "confirm" in lab.runner.phases
    # the change is on the device
    assert "set interfaces lo0 description lab-shape-01" in lab.runner.committed
    # no revert is armed any more
    assert lab.runner.pending is False

    # the timer that would have fired later changes nothing: the device is
    # read again after the advance, so the timer of the device runs
    lab.clock.advance(600)
    config = lab.runner.read_config()
    assert "set interfaces lo0 description lab-shape-01" in config
    assert lab.runner.pending is False


# =========================================================================
# TESTS: THE CHR
# =========================================================================


def test_a_chr_controller_lost_after_the_apply_before_the_first_verify(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The controller dies right after the change is applied on the CHR.

    The change is on the device and the revert is armed: the backup and
    the scheduler entry that loads it.  Nothing verified it and nothing
    confirmed it, so the entry fires and the device reboots into the
    backup: the device is in the pre-change state.
    """
    lab = _chr_lab(tmp_path, monkeypatch)
    planned = _chr_plan(lab)
    record = _record(lab, planned["session_id"])
    _write_approval(lab, planned["session_id"], record)
    # only the sessions of the apply count from here on
    lab.runner.phases.clear()
    lab.runner.kill_after = "statement"

    with pytest.raises(KeyboardInterrupt):
        lab.service.apply("chr1", planned["session_id"])

    # the change is on the device and the revert is armed
    assert "set name=lab-chr-shape-01" in lab.runner.config
    assert lab.runner.armed is True
    assert lab.runner.backup == CHR_BASE_CONFIG
    # the first verify never ran and no confirm was sent
    assert lab.runner.phases.count("export") == 1, lab.runner.phases
    assert "confirm scheduler" not in lab.runner.phases

    # the entry of the device fires by itself
    lab.runner.advance(600)

    # the device rebooted into the backup: the pre-change state
    assert lab.runner.read_config() == CHR_BASE_CONFIG
    assert lab.runner.armed is False
    assert lab.runner.backup is None


def test_a_chr_controller_lost_after_the_verify_before_the_confirm(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The controller dies after the verify and before the confirm.

    The verify passed: the flow only reaches the confirm when every
    check passed, so the loss at the confirm proves it.  The confirm
    never reached the device, so the entry of the revert is still armed
    and the device reboots into the backup when it fires.
    """
    lab = _chr_lab(tmp_path, monkeypatch)
    planned = _chr_plan(lab)
    record = _record(lab, planned["session_id"])
    _write_approval(lab, planned["session_id"], record)
    # only the sessions of the apply count from here on
    lab.runner.phases.clear()
    lab.runner.kill_before = "confirm scheduler"

    with pytest.raises(KeyboardInterrupt):
        lab.service.apply("chr1", planned["session_id"])

    # the verify ran and the confirm never reached the device
    assert lab.runner.phases.count("export") == 2, lab.runner.phases
    assert "confirm scheduler" not in lab.runner.phases
    # the change is on the device and the revert is armed
    assert "set name=lab-chr-shape-01" in lab.runner.config
    assert lab.runner.armed is True

    # the entry of the device fires by itself
    lab.runner.advance(600)

    # the device rebooted into the backup: the pre-change state
    assert lab.runner.read_config() == CHR_BASE_CONFIG
    assert lab.runner.armed is False
    assert lab.runner.backup is None


def test_a_chr_controller_lost_after_the_confirm_stays_confirmed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The controller dies after the confirm was sent and answered.

    The confirm removed the scheduler entry and the backup of the
    revert, so the device confirmed the change: the device holds it, no
    revert is armed any more, and the entry that would have fired later
    changes nothing.
    """
    lab = _chr_lab(tmp_path, monkeypatch)
    planned = _chr_plan(lab)
    record = _record(lab, planned["session_id"])
    _write_approval(lab, planned["session_id"], record)
    # only the sessions of the apply count from here on
    lab.runner.phases.clear()
    lab.runner.kill_after = "confirm backup"

    with pytest.raises(KeyboardInterrupt):
        lab.service.apply("chr1", planned["session_id"])

    # the confirm reached the device and was answered
    assert "confirm scheduler" in lab.runner.phases
    assert "confirm backup" in lab.runner.phases
    # the change is on the device
    assert "set name=lab-chr-shape-01" in lab.runner.config
    # no revert is armed any more
    assert lab.runner.armed is False
    assert lab.runner.backup is None

    # the entry that would have fired later changes nothing: the device is
    # read again after the advance, so the entry of the device runs
    lab.runner.advance(600)
    config = lab.runner.read_config()
    assert "set name=lab-chr-shape-01" in config
    assert lab.runner.armed is False
