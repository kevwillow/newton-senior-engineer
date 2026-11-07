"""The Junos in the flow, the claims, the approval and the backup.

Every device interaction is a scripted fake Junos: the display-set
configuration, the commit list, the CLI sessions and the ping.  No device
is contacted.


"""

from __future__ import annotations

import io
import json
import stat
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

import newton_mcp.approve as approve
import newton_mcp.server as server
from newton_mcp.adapters import base, registry
from newton_mcp.adapters.junos_write import CANDIDATE_COMMAND, JunosOps
from newton_mcp.adapters.vendor_write import VyosOps
from newton_mcp.plan import compute_plan_hash
from newton_mcp.vendor_change import RunOut


SID = "0123456789abcdef0123456789abcdef"
DIGEST = "d" * 64
CHANGE_TEXT = "set interfaces lo0 description lab-shape-01"
CLAIM_LINE = "set interfaces lo0 description lab-shape-01"
PING_HOST = "10.109.0.10"

# The two exec sessions of a Junos, pinned as the adapter pins them.
CONFIG_COMMAND = "show configuration | display set | no-more"
PENDING_COMMAND = "show system commit | no-more"

# The configuration of the device, as the device shows it.
BASE_CONFIG = "\n".join(
    [
        "set version 26.2R1.7",
        "set system host-name lab-junos",
        "set interfaces lo0 unit 0 family inet address 198.51.100.1/32",
    ]
)

PING_OK = "\n".join(
    [
        "PING 10.109.0.10 (10.109.0.10): 56 data bytes",
        "--- 10.109.0.10 ping statistics ---",
        "3 packets transmitted, 3 packets received, 0% packet loss",
    ]
)
PING_LOST = "\n".join(
    [
        "PING 10.109.0.10 (10.109.0.10): 56 data bytes",
        "--- 10.109.0.10 ping statistics ---",
        "3 packets transmitted, 0 packets received, 100% packet loss",
    ]
)

PROMPT = "newton@lab-junos"


def _ok(stdout: str = "", exit_code: int = 0) -> RunOut:
    return RunOut(
        status="ok",
        stdout=stdout,
        stderr="",
        exit_code=exit_code,
    )


class ScriptedJunos:
    """A fake Junos: the configuration, the commit list, the CLI and the ping.

    The fake answers every session with the text the device shows: the
    two reads with the block of the CLI that carries the answer, and the
    sessions of the change with the transcript of the device.  A read may
    be an exec session or a session of the CLI, and the fake answers both
    the same way, so the ops are read exactly as they would be read on a
    Junos.
    """

    def __init__(self, *, config: str = BASE_CONFIG, ping_ok: bool = True,
                 refused: tuple[str, ...] = ()) -> None:
        self.committed = config.splitlines()
        self.previous = list(self.committed)
        self.pending = False
        self.ping_ok = ping_ok
        self.refused = set(refused)
        self.calls: list[str] = []
        self.scripts: list[str] = []

    def __call__(self, spec: Any) -> RunOut:
        remote = spec.remote
        script = spec.stdin
        first = script.splitlines()[0].strip() if script else ""
        self.calls.append(remote or first)
        if remote == CONFIG_COMMAND:
            return _ok("\n".join(self.committed))
        if remote == PENDING_COMMAND:
            return _ok("\n".join(self._commit_list()))
        if remote == "":
            if first == CONFIG_COMMAND:
                return _ok(self._read(CONFIG_COMMAND, self.committed))
            if first == PENDING_COMMAND:
                return _ok(self._read(PENDING_COMMAND, self._commit_list()))
            if first.startswith("ping "):
                return _ok(PING_OK if self.ping_ok else PING_LOST)
            self.scripts.append(script)
            return _ok(self._cli(script))
        if remote.startswith("ping "):
            return _ok(PING_OK if self.ping_ok else PING_LOST)
        raise AssertionError(f"unknown session: {remote!r}")

    def _read(self, command: str, lines: list[str]) -> str:
        """The transcript of a read: the echo of the command and its block."""
        out = [f"{PROMPT}> {command} "]
        out.extend(lines)
        out.append(f"{PROMPT}> exit ")
        return "\n".join(out) + "\n"

    def _commit_list(self) -> list[str]:
        if self.pending:
            return [
                "0   2026-10-24 12:00:00 UTC by newton via cli commit confirmed, "
                "rollback in 2mins comment newton-pending",
                "    rollback pending",
                "1   2026-10-24 11:00:00 UTC by root via cli",
            ]
        return [
            "0   2026-10-24 12:00:01 UTC by newton via cli",
            "1   2026-10-24 11:00:00 UTC by root via cli",
        ]

    def _apply(self, candidate: list[str], command: str) -> list[str]:
        """Put one statement into the candidate configuration."""
        words = command.split(" ")
        key = " ".join(words[:-1])
        value = words[-1]
        for index, line in enumerate(candidate):
            if " ".join(line.split(" ")[:-1]) == key:
                candidate[index] = f"{key} {value}"
                return candidate
        candidate.append(command)
        return candidate

    def _compare(self, candidate: list[str]) -> list[str]:
        """The diff of the candidate against the committed configuration."""
        added = [line for line in candidate if line not in self.committed]
        if not added:
            return []
        out = ["[edit interfaces lo0]"]
        for line in added:
            out.append(f"+    {line.split(' ', 2)[-1]}")
        return out

    def _cli(self, script: str) -> str:
        """Answer one CLI session the way the device does."""
        out: list[str] = []
        mode = "op"
        candidate: list[str] = []
        notice = ""
        for raw in script.splitlines():
            command = raw.strip()
            out.append(f"{PROMPT}{'>' if mode == 'op' else '#'} {command} ")
            if command in ("configure", "configure exclusive"):
                mode = "config"
                candidate = list(self.committed)
                out.append("Entering configuration mode")
            elif command.startswith(("set ", "delete ", "activate ", "deactivate ")):
                if command in self.refused:
                    out.append("syntax error.")
                else:
                    candidate = self._apply(candidate, command)
            elif command == "show | compare | no-more":
                out.extend(self._compare(candidate))
            elif command == CANDIDATE_COMMAND:
                out.extend(candidate)
            elif command == CONFIG_COMMAND:
                out.extend(candidate)
            elif command == "rollback 0":
                candidate = list(self.committed)
                out.append("load complete")
            elif command == "rollback 1":
                candidate = list(self.previous)
                out.append("load complete")
            elif command.startswith("commit confirmed "):
                minutes = command.split(" ")[2]
                out.append(
                    "commit confirmed will be automatically rolled back in "
                    f"{minutes} minutes unless confirmed"
                )
                out.append("commit complete")
                notice = f"# commit confirmed will be rolled back in {minutes} minutes"
                self._commit(candidate, confirmed=False)
            elif command == "commit":
                out.append("commit complete")
                self._commit(candidate, confirmed=True)
            elif command == "exit":
                if mode == "config":
                    mode = "op"
                    out.append("Exiting configuration mode")
            else:
                raise AssertionError(f"unknown command: {command!r}")
            if mode == "config":
                out.append("")
                if notice:
                    out.append(notice)
                out.append("[edit]")
            elif notice and mode == "op":
                out.append("")
                out.append(notice)
        return "\n".join(out) + "\n"

    def _commit(self, candidate: list[str], *, confirmed: bool) -> None:
        self.previous = list(self.committed)
        self.committed = list(candidate)
        self.pending = not confirmed


@dataclass
class JunosLab:
    service: server.NewtonService
    runner: ScriptedJunos
    state: Path


def _inventory(tmp_path: Path, platform: str = "junos", **fields: str) -> Path:
    """An inventory with one vendor write device.

    The keyword arguments replace the default fields of the device, so a
    test can break one of them (a wrong auth, no key file, no lab flag).
    """
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
    values: dict[str, str] = {
        "platform": f'"{platform}"',
        "host": '"192.0.2.9"',
        "user": '"newton"',
        "auth": '"key"',
        "profile": '"lab"',
        "vendor_write": "true",
        "lab": "true",
        "key_file": f'"{key_file}"',
        "known_hosts": f'"{known_hosts}"',
        "password_file": f'"{password_file}"',
    }
    values.update(fields)
    body = ["[devices.jn1]"]
    body.extend(f"{name} = {value}" for name, value in values.items())
    inventory = tmp_path / "devices.toml"
    inventory.write_text("\n".join(body) + "\n", encoding="utf-8")
    return inventory


@pytest.fixture
def junos_lab(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> JunosLab:
    """A service with one writing Junos and a scripted device behind it."""
    inventory = _inventory(tmp_path)
    state = tmp_path / "state"
    monkeypatch.setenv("NEWTON_INVENTORY", str(inventory))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(state))
    runner = ScriptedJunos()

    class FakeRunnerFactory:
        def __call__(self, target: Any) -> ScriptedJunos:
            return runner

    monkeypatch.setattr(server.vendor_flow, "SshSessionRunner", FakeRunnerFactory())
    return JunosLab(server.NewtonService(), runner, state)


def _explanation(**over: Any) -> dict[str, Any]:
    explanation: dict[str, Any] = {
        "intent": "Set the description of the loopback of the lab Junos.",
        "steps": ["Set the loopback description."],
        "expect": [{"kind": "config_has", "line": CLAIM_LINE}],
        "risk": "The description of the loopback changes; nothing else does.",
    }
    explanation.update(over)
    return explanation


def _plan(lab: JunosLab, timeout_s: int = 150, **over: Any) -> dict[str, Any]:
    return lab.service.plan(
        "jn1",
        CHANGE_TEXT,
        timeout_s,
        explanation=_explanation(**over),
        owner_confirmed_in_chat=True,
    )


def _record(lab: JunosLab, session_id: str) -> dict[str, Any]:
    return json.loads(
        (lab.state / "plans" / f"{session_id}.json").read_text(encoding="utf-8")
    )


def _write_approval(lab: JunosLab, session_id: str, record: dict[str, Any]) -> Path:
    approvals = lab.state / "approvals"
    approvals.mkdir(mode=0o700, parents=True, exist_ok=True)
    created = datetime.now(timezone.utc)
    value = {
        "plan_id": session_id,
        "plan_hash": record["plan_hash"],
        "device": "jn1",
        "base_hash": record["base_hash"],
        "created_at": created.isoformat(),
        "expires_at": (created + timedelta(minutes=10)).isoformat(),
        "not_before": int(created.timestamp()),
        "not_after": int((created + timedelta(minutes=10)).timestamp()),
        "token": "a" * 64,
    }
    path = approvals / f"{session_id}.json"
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
    path.chmod(0o600)
    return path


# ---- the registry and the inventory ------------------------------------------------


def test_junos_is_a_t1_write_platform() -> None:
    """Junos writes, with the commit-confirm revert."""
    caps = registry.capabilities("junos")

    assert caps.tier == "T1"
    assert caps.writes is True
    assert caps.native_revert == "commit confirmed"
    assert caps.tools == registry.VENDOR_WRITE_TOOLS
    assert caps.tools == base.READ_ONLY_TOOLS | frozenset(
        {
            "newton_backup",
            "newton_plan_change",
            "newton_apply_change",
            "newton_change_status",
            "newton_abort_change",
        }
    )
    # VyOS keeps its own revert.
    assert registry.capabilities("vyos").native_revert == "commit-confirm"
    # The CHR keeps its reboot-into-backup revert.
    assert registry.capabilities("routeros").native_revert == "reboot-into-backup"
    # The other vendors are still read-only.
    for platform in ("eos", "iosxe", "fortios"):
        other = registry.capabilities(platform)
        assert other.writes is False
        assert other.tools == base.READ_ONLY_TOOLS


def test_a_junos_vendor_write_device_loads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Vendor_write = true on a lab Junos device loads."""
    inventory = _inventory(tmp_path)
    monkeypatch.setenv("NEWTON_INVENTORY", str(inventory))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))

    device = server.load_inventory()["jn1"]

    assert device.platform == "junos"
    assert device.vendor_write is True
    assert device.experimental_readonly is False
    assert device.lab is True
    assert device.profile == "lab"
    assert device.auth == "key"
    assert device.key_file is not None
    assert device.known_hosts is not None


@pytest.mark.parametrize(
    ("platform", "fields", "expected"),
    [
        (
            "junos",
            {"lab": "false"},
            "junos devices are lab-only in this release",
        ),
        (
            "junos",
            {"auth": '"password"'},
            "vendor_write requires auth = 'key'",
        ),
        (
            "junos",
            {"key_file": '""'},
            "vendor_write requires key_file",
        ),
        (
            "junos",
            {"experimental_readonly": "true"},
            "mutually exclusive",
        ),
        (
            "eos",
            {},
            "vendor_write is not available yet for platform eos",
        ),
    ],
)
def test_the_refusal_text_names_the_platform(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    platform: str,
    fields: dict[str, str],
    expected: str,
) -> None:
    """Every refusal of a vendor write device says what is wrong."""
    inventory = _inventory(tmp_path, platform=platform, **fields)
    monkeypatch.setenv("NEWTON_INVENTORY", str(inventory))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))

    with pytest.raises(server.NewtonError) as caught:
        server.load_inventory()

    message = str(caught.value)
    assert expected in message
    assert "jn1" in message


def test_a_junos_device_without_vendor_write_stays_read_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A Junos without vendor_write may be read and not written."""
    inventory = _inventory(tmp_path)
    inventory.write_text(
        inventory.read_text(encoding="utf-8").replace(
            "vendor_write = true", "experimental_readonly = true"
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("NEWTON_INVENTORY", str(inventory))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))
    service = server.NewtonService()

    device = service.devices["jn1"]
    assert device.vendor_write is False
    assert device.experimental_readonly is True
    # the read tools are open
    assert service.device_for("newton_get_state", "jn1") is device
    # the write tools are not
    for tool in (
        "newton_backup",
        "newton_plan_change",
        "newton_apply_change",
        "newton_change_status",
        "newton_abort_change",
    ):
        with pytest.raises(server.NewtonError) as caught:
            service.device_for(tool, "jn1")
        assert str(caught.value) == (
            "device jn1 is read-only; vendor_write is not enabled"
        )


# ---- the flow ----------------------------------------------------------------------


def test_the_flow_uses_the_junos_operations(junos_lab: JunosLab) -> None:
    """The plan of a Junos speaks Junos, not VyOS."""
    planned = _plan(junos_lab)

    assert CONFIG_COMMAND in junos_lab.runner.calls
    assert not any("vyatta" in call for call in junos_lab.runner.calls)
    record = _record(junos_lab, planned["session_id"])
    assert record["platform"] == "junos"
    assert record["uci_batch"] == CHANGE_TEXT
    assert record["reasons"] == ["vendor change on junos"]
    assert record["probes"] == [["config_has", CLAIM_LINE]]


def test_the_plan_reply_says_the_window_and_has_no_undo(
    junos_lab: JunosLab,
) -> None:
    """A Junos plan says how long the revert is armed.

    A Junos has no undo to describe: its revert is its own commit
    confirmed, so the reply carries the window and no undo.
    """
    planned = _plan(junos_lab, timeout_s=150)

    assert "undo" not in planned
    assert planned["revert_window_minutes"] == 3


def test_the_window_is_the_timeout_in_minutes(
    junos_lab: JunosLab,
) -> None:
    """The revert window is the timeout, rounded up to the minute."""
    short = _plan(junos_lab, timeout_s=60)
    middle = _plan(junos_lab, timeout_s=90)
    long = _plan(junos_lab, timeout_s=600)

    assert short["revert_window_minutes"] == 1
    assert middle["revert_window_minutes"] == 2
    assert long["revert_window_minutes"] == 10
    # the timeout of the plan itself is unchanged
    assert _record(junos_lab, short["session_id"])["timeout_s"] == 60
    assert _record(junos_lab, long["session_id"])["timeout_s"] == 600


def test_a_vyos_plan_reply_has_no_junos_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The window key is new for Junos only."""
    inventory = _inventory(tmp_path, platform="vyos")
    monkeypatch.setenv("NEWTON_INVENTORY", str(inventory))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))

    class VyRunner:
        def __init__(self) -> None:
            self.calls: list[str] = []

        def __call__(self, spec: Any) -> RunOut:
            self.calls.append(spec.remote)
            if spec.remote.startswith("/opt/vyatta"):
                return _ok(
                    "set system config-management commit-confirm action 'reload'\n"
                    "set system host-name 'lab-router'\n"
                )
            if spec.remote == "systemctl is-active commit-confirm.timer":
                return _ok("inactive\n")
            if spec.remote.startswith("ping "):
                return _ok("")
            if "discard" in spec.stdin:
                return _ok(
                    "NEWTON-BEGIN-DIFF\n[edit system host-name]\n"
                    "+host-name 'lab-router'\nNEWTON-END-DIFF\n"
                )
            return _ok(
                "NEWTON-BEGIN-SAVED\n"
                "No changes between working and saved configurations.\n"
                "NEWTON-END-SAVED\n"
            )

    runner = VyRunner()

    class FakeRunnerFactory:
        def __call__(self, target: Any) -> VyRunner:
            return runner

    monkeypatch.setattr(server.vendor_flow, "SshSessionRunner", FakeRunnerFactory())
    service = server.NewtonService()

    planned = service.plan(
        "jn1",
        "set system host-name 'lab-router'",
        150,
        explanation={
            "intent": "Set the host name of the lab device.",
            "steps": ["Set the host name."],
            "expect": [{"kind": "ping", "host": PING_HOST}],
            "risk": "The name of the lab device changes.",
        },
        owner_confirmed_in_chat=True,
    )

    assert "undo" not in planned
    assert "revert_window_s" not in planned
    assert "revert_window_minutes" not in planned


def test_the_operations_come_from_the_platform() -> None:
    """The flow picks the operations of the device's platform."""
    from newton_mcp import vendor_flow

    assert set(vendor_flow.OPS_BY_PLATFORM) == {"vyos", "routeros", "junos"}
    assert vendor_flow.OPS_BY_PLATFORM["vyos"] is VyosOps
    assert vendor_flow.OPS_BY_PLATFORM["junos"] is JunosOps
    assert isinstance(vendor_flow.OPS_BY_PLATFORM["junos"](), JunosOps)


def test_the_apply_of_a_junos_confirms_through_its_own_operations(
    junos_lab: JunosLab,
) -> None:
    """The whole Junos path stages, commits with the revert and confirms."""
    planned = _plan(junos_lab)
    record = _record(junos_lab, planned["session_id"])
    _write_approval(junos_lab, planned["session_id"], record)
    junos_lab.runner.calls.clear()

    applied = junos_lab.service.apply("jn1", planned["session_id"])

    assert applied["result"] == "confirmed"
    assert junos_lab.runner.pending is False
    # the change is on the device
    assert CLAIM_LINE in junos_lab.runner.committed
    # the revert was armed in the same commit as the change
    assert any(
        "commit confirmed" in script for script in junos_lab.runner.scripts
    )


# ---- the claims --------------------------------------------------------------------


def test_a_junos_plan_carries_the_two_vendor_claims(
    junos_lab: JunosLab,
) -> None:
    """A Junos plan carries a config_has claim and a ping claim."""
    planned = _plan(
        junos_lab,
        expect=[
            {"kind": "config_has", "line": CLAIM_LINE},
            {"kind": "ping", "host": PING_HOST},
        ],
    )

    assert planned["session_id"]
    record = _record(junos_lab, planned["session_id"])
    assert record["explanation"]["expect"] == [
        {"kind": "config_has", "line": CLAIM_LINE},
        {"kind": "ping", "host": PING_HOST},
    ]
    assert record["probes"] == [
        ["config_has", CLAIM_LINE],
        ["ping", PING_HOST],
    ]


def test_a_config_has_claim_is_read_with_the_junos_grammar(
    junos_lab: JunosLab,
) -> None:
    """A claim line the Junos lint refuses is refused at the plan.

    The claim of a Junos is checked with the Junos grammar: a line the
    vendor's own lint refuses cannot be a claim the vendor can check.
    """
    with pytest.raises(server.NewtonError) as caught:
        _plan(
            junos_lab,
            expect=[
                {"kind": "config_has", "line": "set system services web-management http"}
            ],
        )

    message = str(caught.value)
    assert "junos" in message
    assert junos_lab.runner.calls == []


def test_the_config_has_probe_carries_the_junos_line(
    junos_lab: JunosLab,
) -> None:
    """The probe carries the line the Junos grammar reads.

    The line is re-rendered from its tokens with the Junos tokenizer, so
    the device is compared with the text the Junos writes.
    """
    planned = _plan(
        junos_lab,
        expect=[
            {
                "kind": "config_has",
                "line": "set interfaces lo0 description 'lab shape 01'",
            }
        ],
    )

    record = _record(junos_lab, planned["session_id"])
    assert record["probes"] == [
        ["config_has", "set interfaces lo0 description 'lab shape 01'"]
    ]


# ---- newton-approve ----------------------------------------------------------------


def _approve_record(**over: Any) -> dict[str, Any]:
    record: dict[str, Any] = {
        "device": "jn1",
        "host": "10.109.0.41",
        "session_id": SID,
        "uci_batch": CHANGE_TEXT,
        "diff": CHANGE_TEXT,
        "probes": [["config_has", CLAIM_LINE]],
        "timeout_s": 120,
        "base_hash": "a" * 64,
        "requires_approval": True,
        "router_digest": DIGEST,
        "router_profile": "lab",
        "router_leash": [],
        "router_sections": [],
        "staged_check": {"fw4": "pass", "reason": "", "not_checked": []},
        "router_requires_approval": True,
        "reasons": ["vendor change on junos"],
        "created_at": "2026-10-18T12:00:00+00:00",
        "staged_at": datetime.now(timezone.utc).isoformat(),
        "explanation": _explanation(),
        "owner_confirmed_in_chat": True,
        "platform": "junos",
    }
    record.update(over)
    record["plan_hash"] = compute_plan_hash(record)
    return record


class TTY(io.StringIO):
    def isatty(self) -> bool:
        return True


def _run_approve(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys,
                 record: dict[str, Any]) -> tuple[int, str, str]:
    state = tmp_path / "state"
    (state / "plans").mkdir(parents=True, exist_ok=True)
    (state / "plans" / f"{SID}.json").write_text(json.dumps(record))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(state))
    monkeypatch.setattr(approve.sys, "stdin", TTY("no\n"))
    monkeypatch.setattr(approve, "_getpass", lambda p: pytest.fail("not reached"))
    code = approve.main([SID])
    out = capsys.readouterr()
    return code, out.out, out.err


def test_the_approval_says_the_host_checks_the_approval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    """The owner is told the device does not re-check the approval."""
    code, out, err = _run_approve(
        tmp_path, monkeypatch, capsys, _approve_record()
    )

    assert "Type 'approve" in out
    assert (
        "approval is checked by the Newton host only; the device does not "
        "re-check it" in out
    )
    # a Junos has no undo to describe: the header does not name one
    assert "RouterOS has no soft revert" not in out


def test_the_approval_shows_the_junos_claim_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    """The owner sees the claim line as the Junos reads it."""
    record = _approve_record(
        explanation=_explanation(
            expect=[
                {
                    "kind": "config_has",
                    "line": "set interfaces lo0 description 'lab shape 01'",
                }
            ]
        ),
    )

    code, out, err = _run_approve(tmp_path, monkeypatch, capsys, record)

    assert "Type 'approve" in out
    assert "config has: set interfaces lo0 description 'lab shape 01'" in out


def test_an_openwrt_record_shows_neither_vendor_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    """The vendor lines are for the vendor platforms only."""
    record = _approve_record(
        platform="openwrt",
        explanation={
            "intent": "Set the identity of the lab router.",
            "steps": ["Set the identity name."],
            "expect": [{"kind": "probe", "probe": ["iface-absent", "guestx"]}],
            "risk": "The identity of the lab device changes.",
        },
        probes=[["probe", "iface-absent", "guestx"]],
    )

    code, out, err = _run_approve(tmp_path, monkeypatch, capsys, record)

    assert "Type 'approve" in out
    assert "RouterOS has no soft revert" not in out
    assert "the device does not re-check it" not in out


# ---- the backup --------------------------------------------------------------------


def test_the_backup_of_a_junos_hides_the_secrets(
    junos_lab: JunosLab,
) -> None:
    """The backup of a Junos keeps no secret of the configuration."""
    junos_lab.runner.committed = [
        "set version 26.2R1.7",
        "set system host-name lab-junos",
        'set system root-authentication encrypted-password "$9$synthetic-hash"',
        'set system login user newton authentication encrypted-password "$6$synthetic-six"',
        'set snmp community public authentication secret "$9$synthetic-secret"',
        'set system services ssh host-key lab "ssh-ed25519 AAAASYNTHETICKEYBODY"',
    ]

    result = junos_lab.service.backup("jn1")

    path = Path(result["backup_path"]["text"])
    text = path.read_text(encoding="utf-8")
    assert "synthetic-hash" not in text
    assert "synthetic-six" not in text
    assert "synthetic-secret" not in text
    assert "AAAASYNTHETICKEYBODY" not in text
    assert "<redacted>" in text
    assert "encrypted-password" in text
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
