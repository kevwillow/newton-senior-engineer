"""RouterOS CHR in the flow, the claims, the approval and the backup.

Every device interaction is a scripted fake CHR: the export, the scheduler
count, the backup count, the arm, the statements, the ping.  No device is
contacted.


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
from newton_mcp.adapters.routeros_write import RouterosOps
from newton_mcp.adapters.vendor_write import VyosOps
from newton_mcp.plan import compute_plan_hash
from newton_mcp.vendor_change import RunOut


SID = "0123456789abcdef0123456789abcdef"
DIGEST = "d" * 64
CHANGE_TEXT = "/system/identity set name=lab-chr-shape-01"
PING_HOST = "10.109.0.10"

CHR_CONFIG = "\n".join(
    [
        "# jan/01/2026 12:00:00 by RouterOS 7.24.5",
        "/ip address add address=10.109.0.21/24 interface=ether1 network=10.109.0.0",
        "/system identity set name=lab-chr",
        "",
    ]
)


def _ok(stdout: str = "", exit_code: int = 0) -> RunOut:
    return RunOut(
        status="ok",
        stdout=stdout,
        stderr="",
        exit_code=exit_code,
    )


class ScriptedChr:
    """A fake CHR: the export, the two counts, the arm and the statements."""

    def __init__(self) -> None:
        self.config = CHR_CONFIG
        self.scheduler = 0
        self.backups = 0
        self.calls: list[str] = []
        self.ping_ok = True
        self.statement_fails = False

    def __call__(self, spec: Any) -> RunOut:
        remote = spec.remote
        self.calls.append(remote)
        if remote == "/export":
            return _ok(self.config)
        if remote.startswith("/system scheduler print count-only"):
            return _ok(f"{self.scheduler}\n")
        if remote.startswith("/file print count-only"):
            return _ok(f"{self.backups}\n")
        if remote.startswith("/system scheduler print detail"):
            return _ok(
                "  name=newton-revert\n"
                "  next-run=jan/01/2026 12:02:00\n"
                '  on-event="/system backup load name=newton-revert password=\\"\\""\n'
            )
        if "/system backup save" in remote:
            # the arm: the backup and the scheduler entry are made
            self.scheduler = 1
            self.backups = 1
            return _ok("armed for 00:02:00\n")
        if "/system scheduler set" in remote:
            return _ok("")
        if remote.startswith("/system scheduler remove"):
            self.scheduler = 0
            return _ok("")
        if remote.startswith("/file remove"):
            self.backups = 0
            return _ok("")
        if remote.startswith("/system backup load"):
            self.config = CHR_CONFIG
            self.scheduler = 0
            self.backups = 0
            return _ok("System configuration restored, rebooting now\n")
        if remote.startswith(":put [/system resource get uptime"):
            return _ok("1d02:03:04\n")
        if remote.startswith("/ping "):
            return _ok("received=3 packets\n" if self.ping_ok else "received=0\n")
        if remote.startswith(':put "NEWTON-LINE-ERROR'):
            return _ok("")
        if self.statement_fails:
            return _ok("failure: unknown parameter\n", 1)
        return _ok("")


@dataclass
class ChrLab:
    service: server.NewtonService
    runner: ScriptedChr
    state: Path


def _inventory(tmp_path: Path, platform: str = "routeros", **fields: str) -> Path:
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
    body = ["[devices.chr1]"]
    body.extend(f"{name} = {value}" for name, value in values.items())
    inventory = tmp_path / "devices.toml"
    inventory.write_text("\n".join(body) + "\n", encoding="utf-8")
    return inventory


@pytest.fixture
def chr_lab(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ChrLab:
    """A service with one writing CHR and a scripted device behind it."""
    inventory = _inventory(tmp_path)
    state = tmp_path / "state"
    monkeypatch.setenv("NEWTON_INVENTORY", str(inventory))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(state))
    runner = ScriptedChr()

    class FakeRunnerFactory:
        def __call__(self, target: Any) -> ScriptedChr:
            return runner

    monkeypatch.setattr(server.vendor_flow, "SshSessionRunner", FakeRunnerFactory())
    return ChrLab(server.NewtonService(), runner, state)


def _explanation(**over: Any) -> dict[str, Any]:
    explanation: dict[str, Any] = {
        "intent": "Set the identity of the lab CHR.",
        "steps": ["Set the identity name."],
        "expect": [{"kind": "ping", "host": PING_HOST}],
        "risk": "The identity of the lab device changes; nothing else does.",
    }
    explanation.update(over)
    return explanation


def _plan(lab: ChrLab, timeout_s: int = 150, **over: Any) -> dict[str, Any]:
    return lab.service.plan(
        "chr1",
        CHANGE_TEXT,
        timeout_s,
        explanation=_explanation(**over),
        owner_confirmed_in_chat=True,
    )


def _record(lab: ChrLab, session_id: str) -> dict[str, Any]:
    return json.loads(
        (lab.state / "plans" / f"{session_id}.json").read_text(encoding="utf-8")
    )


def _write_approval(lab: ChrLab, session_id: str, record: dict[str, Any]) -> Path:
    approvals = lab.state / "approvals"
    approvals.mkdir(mode=0o700, parents=True, exist_ok=True)
    created = datetime.now(timezone.utc)
    value = {
        "plan_id": session_id,
        "plan_hash": record["plan_hash"],
        "device": "chr1",
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


def test_routeros_is_a_t2_write_platform() -> None:
    """RouterOS writes, with the reboot-into-backup revert."""
    caps = registry.capabilities("routeros")

    assert caps.tier == "T2"
    assert caps.writes is True
    assert caps.native_revert == "reboot-into-backup"
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
    # The other vendors are still read-only.  The Junos writes since
    # it is a T1 with its own commit-confirm revert.
    for platform in ("eos", "iosxe", "fortios"):
        other = registry.capabilities(platform)
        assert other.writes is False
        assert other.tools == base.READ_ONLY_TOOLS
    junos = registry.capabilities("junos")
    assert junos.tier == "T1"
    assert junos.writes is True
    assert junos.native_revert == "commit confirmed"


def test_a_routeros_vendor_write_device_loads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Vendor_write = true on a lab CHR device loads."""
    inventory = _inventory(tmp_path)
    monkeypatch.setenv("NEWTON_INVENTORY", str(inventory))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))

    device = server.load_inventory()["chr1"]

    assert device.platform == "routeros"
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
            "routeros",
            {"lab": "false"},
            "routeros devices are lab-only in this release",
        ),
        (
            "routeros",
            {"auth": '"password"'},
            "vendor_write requires auth = 'key'",
        ),
        (
            "routeros",
            {"key_file": '""'},
            "vendor_write requires key_file",
        ),        (
            "routeros",
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
    assert "chr1" in message


def test_a_routeros_device_without_vendor_write_stays_read_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A CHR without vendor_write may be read and not written."""
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

    device = service.devices["chr1"]
    assert device.vendor_write is False
    assert device.experimental_readonly is True
    # the read tools are open
    assert service.device_for("newton_get_state", "chr1") is device
    # the write tools are not
    for tool in (
        "newton_backup",
        "newton_plan_change",
        "newton_apply_change",
        "newton_change_status",
        "newton_abort_change",
    ):
        with pytest.raises(server.NewtonError) as caught:
            service.device_for(tool, "chr1")
        assert str(caught.value) == (
            "device chr1 is read-only; vendor_write is not enabled"
        )


# ---- the flow ----------------------------------------------------------------------


def test_the_flow_uses_the_chr_operations(chr_lab: ChrLab) -> None:
    """The plan of a CHR speaks RouterOS, not VyOS."""
    planned = _plan(chr_lab)

    assert "/export" in chr_lab.runner.calls
    assert not any("vyatta" in call for call in chr_lab.runner.calls)
    record = _record(chr_lab, planned["session_id"])
    assert record["platform"] == "routeros"
    assert record["uci_batch"] == "/system identity set name=lab-chr-shape-01"
    assert record["reasons"] == ["vendor change on routeros"]
    assert record["probes"] == [["ping", PING_HOST]]


def test_the_plan_reply_names_the_undo_and_the_window(
    chr_lab: ChrLab,
) -> None:
    """A CHR plan says what the undo is and how long the window is."""
    planned = _plan(chr_lab, timeout_s=60)

    assert planned["undo"] == "reboot into the backup"
    assert planned["revert_window_s"] == 120


def test_the_window_is_the_timeout_or_two_minutes(
    chr_lab: ChrLab,
) -> None:
    """The revert window is max(timeout_s, 120); the timeout is kept."""
    short = _plan(chr_lab, timeout_s=60)
    long = _plan(chr_lab, timeout_s=600)

    assert short["revert_window_s"] == 120
    assert long["revert_window_s"] == 600
    assert _record(chr_lab, short["session_id"])["timeout_s"] == 60
    assert _record(chr_lab, long["session_id"])["timeout_s"] == 600


def test_a_vyos_plan_reply_has_no_undo_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The undo key is new for RouterOS only."""
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
        "chr1",
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


def test_the_operations_come_from_the_platform(
    chr_lab: ChrLab,
) -> None:
    """The flow picks the operations of the device's platform."""
    from newton_mcp import vendor_flow

    assert set(vendor_flow.OPS_BY_PLATFORM) == {"vyos", "routeros", "junos"}
    assert vendor_flow.OPS_BY_PLATFORM["vyos"] is VyosOps
    assert vendor_flow.OPS_BY_PLATFORM["routeros"] is RouterosOps
    assert isinstance(vendor_flow.OPS_BY_PLATFORM["routeros"](), RouterosOps)


def test_the_apply_of_a_chr_confirms_through_the_own_operations(
    chr_lab: ChrLab,
) -> None:
    """The whole CHR path arms the revert, applies and confirms."""
    planned = _plan(chr_lab)
    record = _record(chr_lab, planned["session_id"])
    _write_approval(chr_lab, planned["session_id"], record)
    chr_lab.runner.calls.clear()

    applied = chr_lab.service.apply("chr1", planned["session_id"])

    assert applied["result"] == "confirmed"
    assert chr_lab.runner.scheduler == 0
    assert chr_lab.runner.backups == 0
    assert any("/system backup save" in call for call in chr_lab.runner.calls)


# ---- the claims --------------------------------------------------------------------


def test_a_ping_claim_is_the_only_claim_a_chr_carries(
    chr_lab: ChrLab,
) -> None:
    """A CHR plan carries a ping claim."""
    planned = _plan(chr_lab)

    assert planned["session_id"]
    record = _record(chr_lab, planned["session_id"])
    assert record["explanation"]["expect"] == [{"kind": "ping", "host": PING_HOST}]


def test_a_config_has_claim_is_refused_on_a_chr(
    chr_lab: ChrLab,
) -> None:
    """Config_has is not supported on RouterOS; use ping."""
    with pytest.raises(server.NewtonError) as caught:
        _plan(
            chr_lab,
            expect=[{"kind": "config_has", "line": "/system/identity set name=x"}],
        )

    message = str(caught.value)
    assert "config_has is not supported on RouterOS; use ping" in message
    assert chr_lab.runner.calls == []


# ---- newton-approve ----------------------------------------------------------------


def _approve_record(**over: Any) -> dict[str, Any]:
    record: dict[str, Any] = {
        "device": "chr1",
        "host": "10.109.0.21",
        "session_id": SID,
        "uci_batch": CHANGE_TEXT,
        "diff": CHANGE_TEXT,
        "probes": [["ping", PING_HOST]],
        "timeout_s": 120,
        "base_hash": "a" * 64,
        "requires_approval": True,
        "router_digest": DIGEST,
        "router_profile": "lab",
        "router_leash": [],
        "router_sections": [],
        "staged_check": {"fw4": "pass", "reason": "", "not_checked": []},
        "router_requires_approval": True,
        "reasons": ["vendor change on routeros"],
        "created_at": "2026-10-18T12:00:00+00:00",
        "staged_at": datetime.now(timezone.utc).isoformat(),
        "explanation": _explanation(),
        "owner_confirmed_in_chat": True,
        "platform": "routeros",
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


def test_the_approval_shows_the_routeros_undo(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    """The owner is told what the undo of a CHR is."""
    code, out, err = _run_approve(
        tmp_path, monkeypatch, capsys, _approve_record()
    )

    # the record was displayed (the answer below is a refusal on purpose)
    assert "Type 'approve" in out
    assert (
        "undo is a reboot into the backup (RouterOS has no soft revert)" in out
    )


def test_the_approval_says_the_host_checks_the_approval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    """Every vendor platform says the device does not re-check it."""
    code, out, err = _run_approve(
        tmp_path, monkeypatch, capsys, _approve_record()
    )

    assert "Type 'approve" in out
    assert (
        "approval is checked by the Newton host only; the device does not "
        "re-check it" in out
    )


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


def test_the_backup_of_a_chr_hides_the_secrets(
    chr_lab: ChrLab,
) -> None:
    """The backup of a CHR keeps no secret of the export."""
    chr_lab.runner.config = (
        CHR_CONFIG
        + '/user add name=newton group=full password="synthetic-secret"\n'
        + "/interface wireless security-profiles add name=lab "
        "wpa2-pre-shared-key=synthetic-psk\n"
    )

    result = chr_lab.service.backup("chr1")

    path = Path(result["backup_path"]["text"])
    text = path.read_text(encoding="utf-8")
    assert "synthetic-secret" not in text
    assert "synthetic-psk" not in text
    assert "<redacted>" in text
    assert "password=" in text
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
