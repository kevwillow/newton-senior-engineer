"""The lab driver for vendor VMs (VyOS first).

Every device interaction is a fake.  The ssh transport is a scripted VyOS,
the Proxmox rollback is a monkeypatched stub and the approval record is
written by the real ``newton-approve`` code into a temporary state
directory.  Nothing here touches the network.

The tunnel to the lab VM: the driver opens one ssh tunnel per
run and points the inventory it writes at the tunnel's local endpoint, so
the MCP transport reaches the VM through apollo.  The tunnel is a fake
here too: no ssh process is started.

Review fixes: the allowlist of the devices a post
may run on, the baseline check of --no-reset, the proof that the listener
on the tunnel's port is our own ssh, and the per-shape failure of a
passphrase that is not UTF-8.
"""

from __future__ import annotations

from conftest import lab_toml_path

import hashlib
import importlib.util
import json
import os
import socket
import sys
import tomllib
from pathlib import Path
from typing import Any

import pytest

LAB_DIR = Path(__file__).resolve().parent.parent
DRIVER_PATH = LAB_DIR / "newton-vendor-lab.py"

# The driver file is named `newton-vendor-lab.py`, which
# Python cannot import directly because of the hyphens.  Load it as
# `newton_vendor_lab` for the tests.
_spec = importlib.util.spec_from_file_location("newton_vendor_lab", DRIVER_PATH)
vl = importlib.util.module_from_spec(_spec)
sys.modules["newton_vendor_lab"] = vl
_spec.loader.exec_module(vl)

# The lab runner itself; lab/tests/conftest.py has already loaded it as
# `newton_lab_test`.
import newton_lab_test as nl  # noqa: E402


RELOAD_LINE = "set system config-management commit-confirm action 'reload'"
BASE_CONFIG = "\n".join(
    [
        RELOAD_LINE,
        "set system host-name 'vyos-lab'",
        "set system description 'baseline'",
    ]
)
BASE_HASH = hashlib.sha256(BASE_CONFIG.encode("utf-8")).hexdigest()

SHAPE_IDS = (
    "01-harmless",
    "02-mgmt-ip",
    "03-input-drop",
    "04-injection",
    "05-bad-syntax",
    "06-service-reachable",
    "07-uplink-down",
    "08-no-approval",
)


# ---------- the fake device ----------

def _kind(spec: Any) -> str:
    """What kind of session this is, from the remote and the script."""
    remote = spec.remote
    if remote == "systemctl is-active commit-confirm.timer":
        return "timer"
    if remote == "/opt/vyatta/bin/vyatta-op-cmd-wrapper show configuration commands":
        return "config"
    if remote.startswith("ping "):
        return "ping"
    if remote in ("true", ""):
        return "other"
    lines = spec.stdin.splitlines()
    if any(line.startswith("commit-confirm ") for line in lines):
        return "apply"
    if "compare saved" in lines:
        return "saved"
    if "discard" in lines:
        return "stage"
    if "revert_soft" in spec.stdin:
        return "abort"
    if "confirm" in lines:
        return "confirm"
    if "save" in lines:
        return "save"
    return "other"


def _applied_statements(stdin: str) -> list[str]:
    """The statements of an applied script, in order.

    The script runs each statement on a line of its own and guards it
    with an ``if [ "$NEWTON_RC" -ne 0 ]`` line right after, so the
    statement is the line before the guard.  The stderr redirect and the
    capture of the exit status are stripped: the configuration the fake
    device holds carries the statement, not the guard.
    """
    statements: list[str] = []
    lines = stdin.splitlines()
    for index, line in enumerate(lines):
        if not line.startswith('if [ "$NEWTON_RC" -ne 0 ]'):
            continue
        if index == 0:
            continue
        statement = lines[index - 1].removesuffix("; NEWTON_RC=$?")
        statements.append(statement.removesuffix(' 2>"$NEWTON_ERR"'))
    return statements


class FakeRunner:
    """A scripted VyOS: it remembers the sessions and its own state."""

    def __init__(self, *, config: str = BASE_CONFIG, ping_ok: bool = True,
                 stage_ok: bool = True, session_error: bool = False) -> None:
        self.config = config
        self.initial_config = config
        self.pending = "idle"
        self.ping_ok = ping_ok
        self.stage_ok = stage_ok
        # The session could not be prepared: the error file was not there.
        self.session_error = session_error
        # How many sessions answer "unreachable" once the change is
        # committed: that is the device that lost its management path.
        self.down_reads = 0
        self.down_left = 0
        self.calls: list[str] = []

    def __call__(self, spec: Any) -> Any:
        from newton_mcp.vendor_change import RunOut

        kind = _kind(spec)
        self.calls.append(kind)
        if self.down_left > 0:
            self.down_left -= 1
            if self.down_left == 0:
                # the device-side timer fired: the change is gone and the
                # device answers again
                self.config = self.initial_config
                self.pending = "idle"
            return RunOut(status="unreachable", stdout="", stderr="no route",
                          exit_code=None)
        if kind == "config":
            return RunOut(status="ok", stdout=self.config, stderr="",
                          exit_code=0)
        if kind == "saved":
            return RunOut(
                status="ok",
                stdout=("NEWTON-BEGIN-SAVED\n"
                        "No changes between working and saved configurations.\n"
                        "NEWTON-END-SAVED\n"),
                stderr="",
                exit_code=0,
            )
        if kind == "timer":
            return RunOut(
                status="ok",
                stdout="active\n" if self.pending == "pending" else "inactive\n",
                stderr="",
                exit_code=0,
            )
        if kind == "stage":
            if self.session_error:
                return RunOut(status="ok", stdout="NEWTON-LINE-ERROR 0\n",
                              stderr="", exit_code=1)
            if not self.stage_ok:
                return RunOut(status="ok",
                              stdout="NEWTON-LINE-ERROR 1\n", stderr="",
                              exit_code=1)
            return RunOut(
                status="ok",
                stdout=("NEWTON-BEGIN-DIFF\n[edit system description]\n"
                        "+description 'newton-lab-shape-01'\nNEWTON-END-DIFF\n"),
                stderr="",
                exit_code=0,
            )
        if kind == "apply":
            statements = _applied_statements(spec.stdin)
            self.config = self.initial_config + "\n" + "\n".join(statements)
            self.pending = "pending"
            self.down_left = self.down_reads
            return RunOut(status="ok", stdout="NEWTON-COMMITTED rc=0\n",
                          stderr="", exit_code=0)
        if kind == "ping":
            return RunOut(status="ok", stdout="", stderr="",
                          exit_code=0 if self.ping_ok else 1)
        if kind == "confirm":
            self.pending = "idle"
            return RunOut(status="ok", stdout="NEWTON-CONFIRMED rc=0\n",
                          stderr="", exit_code=0)
        if kind == "save":
            return RunOut(status="ok", stdout="NEWTON-SAVED rc=0\n", stderr="",
                          exit_code=0)
        if kind == "abort":
            self.config = self.initial_config
            self.pending = "idle"
            return RunOut(status="ok", stdout="NEWTON-ABORT revert_rc=0\n",
                          stderr="", exit_code=0)
        return RunOut(status="ok", stdout="", stderr="", exit_code=0)


# ---------- the lab and the shapes the tests write ----------

def _lab_toml(tmp_path: Path, *, admin_key: str | None = None,
              known_hosts: str | None = None,
              device_paths: bool = True,
              passphrase: bytes | None = None,
              lab_known_hosts: str = "10.109.0.11 ssh-ed25519 LABBR1\n"
              ) -> Path:
    """The lab file the driver reads.

    The lab's own known_hosts pins the OpenWrt router and the device's
    pins the VM, so a test can tell which one the driver used.  The
    device's admin_key defaults to a fake key file; a test that wants the
    run to stop points it at a file that is not there.  The passphrase is
    written as bytes, so a test can make it something that is not UTF-8.
    """
    key = tmp_path / "router-key"
    key.write_text("FAKE-LAB-KEY\n", encoding="utf-8")
    key.chmod(0o600)
    lab_known_hosts_file = tmp_path / "known-hosts"
    lab_known_hosts_file.write_text(lab_known_hosts, encoding="utf-8")
    device_key = tmp_path / "lab-vyos-key"
    device_key.write_text("FAKE-VYOS-KEY\n", encoding="utf-8")
    device_key.chmod(0o600)
    device_known_hosts = tmp_path / "lab-vyos-known-hosts"
    device_known_hosts.write_text(
        "10.109.0.31 ssh-ed25519 AAAA\n", encoding="utf-8"
    )
    if admin_key is None:
        admin_key = str(device_key)
    if known_hosts is None:
        known_hosts = str(device_known_hosts)
    passphrase_file = tmp_path / "approve.pw"
    if passphrase is None:
        passphrase = b"lab-passphrase\n"
    passphrase_file.write_bytes(passphrase)
    device_lines = ""
    if device_paths:
        device_lines = (
            f'known_hosts = "{known_hosts}"\n'
            f'admin_key = "{admin_key}"\n'
        )
    path = tmp_path / "lab.toml"
    path.write_text(
        "[pve]\n"
        'host = "192.0.2.1"\n'
        'node = "test"\n'
        'token_file = "~/.config/pve/apollo.token"\n'
        'pin_file = "~/.config/pve/apollo.pin"\n'
        "\n"
        "[ssh]\n"
        'proxy = "ssh -i /tmp/fake -W %h:%p root@192.0.2.1"\n'
        'password_file = "~/.config/newton/lab-root.pw"\n'
        f'key = "{tmp_path / "lab-key"}"\n'
        f'router_key = "{key}"\n'
        f'approve_passphrase_file = "{passphrase_file}"\n'
        f'known_hosts = "{lab_known_hosts_file}"\n'
        "\n"
        "[devices.lab-vyos]\n"
        "vmid = 9104\n"
        'host = "10.109.0.31"\n'
        'user = "newton"\n'
        'platform = "vyos"\n'
        "vendor_write = true\n"
        'snapshot = "baseline-newton-write"\n'
        'settle_cmd = ""\n'
        + device_lines,
        encoding="utf-8",
    )
    return path


def _shapes_toml(tmp_path: Path, extra: str = "") -> Path:
    path = tmp_path / "vendor-shapes.toml"
    path.write_text(
        "[vars]\n"
        'uplink_peer = "192.168.150.1"\n'
        "\n"
        "[baseline.vyos]\n"
        f'config_hash = "{BASE_HASH}"\n'
        "\n"
        "[shapes.01-harmless]\n"
        'id = "01-harmless"\n'
        'description = "A harmless description change."\n'
        'expect = "confirmed"\n'
        "explanation = { intent = \"Set the lab description.\", "
        "steps = [\"Set the description.\"], "
        "risk = \"The description changes.\" }\n"
        "\n"
        "[vyos.01-harmless]\n"
        "lines = [\"set system description 'newton-lab-shape-01'\"]\n"
        "claims = [{ kind = \"config_has\", "
        "line = \"set system description 'newton-lab-shape-01'\" }]\n"
        "\n"
        "[shapes.02-mgmt-ip]\n"
        'id = "02-mgmt-ip"\n'
        'description = "The management address moves to another subnet."\n'
        'expect = "rolled_back"\n'
        "explanation = { intent = \"Move the management address.\", "
        "steps = [\"Delete the address.\", \"Set the new one.\"], "
        "risk = \"The management path moves.\" }\n"
        "\n"
        "[vyos.02-mgmt-ip]\n"
        "lines = [\"delete interfaces ethernet eth1 address '10.109.0.31/24'\", "
        "\"set interfaces ethernet eth1 address '10.109.9.99/24'\"]\n"
        "claims = [{ kind = \"ping\", host = \"10.109.9.1\" }]\n"
        "\n"
        "[shapes.04-injection]\n"
        'id = "04-injection"\n'
        'description = "An injection attempt in the change text."\n'
        'expect = "refused_at_plan"\n'
        "sessions = 0\n"
        "explanation = { intent = \"Try to smuggle shell text.\", "
        "steps = [\"One.\", \"Two.\", \"Three.\", \"Four.\"], "
        "risk = \"Nothing is applied.\" }\n"
        "\n"
        "[vyos.04-injection]\n"
        "lines = [\"set system description 'newton-lab; rm -rf /'\", "
        "\"set system description 'newton-lab'\", \"commit\", "
        "\"set system description 'NEWTON-fake'\"]\n"
        "claims = [{ kind = \"config_has\", "
        "line = \"set system description 'newton-lab'\" }]\n"
        "\n"
        "[shapes.08-no-approval]\n"
        'id = "08-no-approval"\n'
        'description = "A change with no approval record."\n'
        'expect = "refused_at_apply"\n'
        "approval = false\n"
        "explanation = { intent = \"Change the description without approval.\", "
        "steps = [\"Set the description.\"], "
        "risk = \"Nothing is applied.\" }\n"
        "\n"
        "[vyos.08-no-approval]\n"
        "lines = [\"set system description 'newton-lab-shape-08'\"]\n"
        "claims = [{ kind = \"config_has\", "
        "line = \"set system description 'newton-lab-shape-08'\" }]\n"
        + extra,
        encoding="utf-8",
    )
    return path


@pytest.fixture(autouse=True)
def _restore_env() -> Any:
    """The driver points NEWTON_INVENTORY and NEWTON_STATE_DIR at its own
    state; the environment goes back to what it was after every test."""
    saved = os.environ.copy()
    yield
    os.environ.clear()
    os.environ.update(saved)


@pytest.fixture(autouse=True)
def _no_recovery_wait(monkeypatch: pytest.MonkeyPatch) -> None:
    """Neutralise the recovery wait of the vendor driver.

    The wait is a default argument of ``apply_plan``, so patching
    ``time.sleep`` does not reach it: the tests would sit through the
    whole recovery window.  The wait itself is not what these tests
    check, so it is replaced by a no-op.
    """
    import newton_mcp.vendor_change as vc

    keyword_defaults = dict(getattr(vc.apply_plan, "__kwdefaults__", None) or {})
    keyword_defaults["wait"] = lambda _seconds: None
    monkeypatch.setattr(vc.apply_plan, "__kwdefaults__", keyword_defaults)


@pytest.fixture
def lab(tmp_path: Path) -> Any:
    return nl.load_lab(_lab_toml(tmp_path))


class FakeTunnel:
    """A tunnel that opens nothing: a port and a flag."""

    def __init__(self, port: int = 22022) -> None:
        self.port = port
        self.stopped = False

    def stop(self) -> None:
        self.stopped = True


def _tunnel_opener(opened: list[FakeTunnel], port: int = 22022):
    """An opener the driver uses instead of the real ssh tunnel."""

    def opener(_lab: Any, _device: Any) -> FakeTunnel:
        tunnel = FakeTunnel(port)
        opened.append(tunnel)
        return tunnel

    return opener


@pytest.fixture
def tunnels() -> list[FakeTunnel]:
    """The tunnels the run opened."""
    return []


@pytest.fixture
def vendor_lab(tmp_path: Path, lab: Any, monkeypatch: pytest.MonkeyPatch,
               tunnels: list[FakeTunnel]):
    """A driver context with a fake device and a stubbed Proxmox rollback."""
    monkeypatch.setattr(nl, "pve_rollback", lambda _lab, _dev: "UPID:fake")
    monkeypatch.setattr(
        nl,
        "pve_wait_task",
        lambda _lab, _upid, timeout_s=120: {"status": "stopped",
                                             "exitstatus": "OK"},
    )
    monkeypatch.setattr(vl, "open_tunnel", _tunnel_opener(tunnels))
    runner = FakeRunner()
    shapes_path = _shapes_toml(tmp_path)
    context = vl.build_context(
        lab,
        shapes_path,
        "vyos",
        factory=lambda _target: runner,
        state_dir=tmp_path / "state",
    )
    return context, runner


# ---------- the loader ----------

def test_the_shipped_shapes_file_expands_for_vyos() -> None:
    """The shipped shapes file carries the eight shapes."""
    shapes = vl.load_shapes(LAB_DIR / "vendor-shapes.toml", "vyos")

    assert tuple(sorted(shapes)) == SHAPE_IDS
    assert shapes["01-harmless"].expect == "confirmed"
    assert shapes["02-mgmt-ip"].expect == "rolled_back"
    assert shapes["03-input-drop"].expect == "rolled_back"
    assert shapes["04-injection"].expect == "refused_at_plan"
    assert shapes["04-injection"].sessions == 0
    assert shapes["05-bad-syntax"].expect == "refused_at_plan"
    assert shapes["06-service-reachable"].expect == "refused_at_plan"
    assert shapes["07-uplink-down"].expect == "rolled_back"
    assert shapes["08-no-approval"].expect == "refused_at_apply"
    assert shapes["08-no-approval"].approval is False
    for shape in shapes.values():
        assert shape.lines
        assert shape.claims
        assert shape.explanation["intent"]
        assert len(shape.explanation["steps"]) == len(shape.lines)


def test_an_unknown_vendor_is_refused(tmp_path: Path) -> None:
    """A vendor with no tables in the shapes file is refused."""
    path = _shapes_toml(tmp_path)

    with pytest.raises(vl.ShapeError, match="no tables for vendor"):
        vl.load_shapes(path, "chr")


def test_a_shape_without_lines_is_refused(tmp_path: Path) -> None:
    """A shape with no lines for the vendor is refused."""
    path = _shapes_toml(
        tmp_path,
        extra=(
            "[shapes.09-empty]\n"
            'id = "09-empty"\n'
            'description = "A shape with no lines."\n'
            'expect = "confirmed"\n'
            "explanation = { intent = \"Nothing.\", steps = [], "
            "risk = \"Nothing.\" }\n"
            "\n"
            "[vyos.09-empty]\n"
            "claims = [{ kind = \"ping\", host = \"10.109.9.1\" }]\n"
        ),
    )

    with pytest.raises(vl.ShapeError, match="lines"):
        vl.load_shapes(path, "vyos")


def test_a_shape_whose_steps_do_not_match_its_lines_is_refused(
    tmp_path: Path,
) -> None:
    """One explanation step per change line, or the shape is refused."""
    path = _shapes_toml(
        tmp_path,
        extra=(
            "[shapes.10-mismatch]\n"
            'id = "10-mismatch"\n'
            'description = "Two lines and one step."\n'
            'expect = "confirmed"\n'
            "explanation = { intent = \"Two lines.\", steps = [\"One step.\"], "
            "risk = \"Nothing.\" }\n"
            "\n"
            "[vyos.10-mismatch]\n"
            "lines = [\"set system description 'a'\", "
            "\"set system description 'b'\"]\n"
            "claims = [{ kind = \"config_has\", "
            "line = \"set system description 'a'\" }]\n"
        ),
    )

    with pytest.raises(vl.ShapeError, match="steps"):
        vl.load_shapes(path, "vyos")


# ---------- the run ----------

def test_the_harmless_shape_confirms_and_spends_the_approval(
    vendor_lab,
) -> None:
    """The whole path confirms and the approval record is used."""
    context, runner = vendor_lab

    result = vl.run_shape(context, context.shapes["01-harmless"])

    assert result.passed is True
    assert result.got == "confirmed"
    assert result.expected == "confirmed"
    assert result.seconds >= 0
    approvals = context.state / "approvals"
    assert approvals.is_dir()
    used = list(approvals.glob("*.used"))
    assert len(used) == 1
    record = json.loads(used[0].read_text(encoding="utf-8"))
    assert record["device"] == "lab-vyos"
    assert record["not_after"] > record["not_before"]
    assert len(record["token"]) == 64
    # the device was asked, and the change is in the running configuration
    assert "apply" in runner.calls
    assert "confirm" in runner.calls
    assert "newton-lab-shape-01" in runner.config


def test_a_tampered_approval_record_is_refused(
    vendor_lab,
) -> None:
    """An edited approval record stops the apply before the device."""
    context, runner = vendor_lab
    shape = context.shapes["01-harmless"]

    with vl.use_runner(context):
        planned = context.service.plan(
            "lab-vyos",
            "\n".join(shape.lines),
            shape.timeout_s,
            explanation=shape.explanation,
            owner_confirmed_in_chat=True,
        )
    ok, detail = vl.write_approval(context, planned["session_id"])
    assert ok is True, detail
    approval = context.state / "approvals" / f"{planned['session_id']}.json"
    value = json.loads(approval.read_text(encoding="utf-8"))
    value["base_hash"] = "0" * 64
    approval.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
    runner.calls.clear()

    from newton_mcp import server

    with vl.use_runner(context), pytest.raises(server.NewtonError):
        context.service.apply("lab-vyos", planned["session_id"])

    assert "apply" not in runner.calls


def test_the_injection_shape_opens_zero_sessions(vendor_lab) -> None:
    """The injection shape is refused before any session."""
    context, runner = vendor_lab

    result = vl.run_shape(context, context.shapes["04-injection"])

    assert result.got == "refused_at_plan"
    assert result.passed is True
    assert context.counter[0] == 0
    assert "stage" not in runner.calls
    assert "apply" not in runner.calls


def test_the_no_approval_shape_is_refused_at_the_apply(
    vendor_lab,
) -> None:
    """No approval record means no apply and no session."""
    context, runner = vendor_lab

    result = vl.run_shape(context, context.shapes["08-no-approval"])

    assert result.got == "refused_at_apply"
    assert result.passed is True
    assert "approval required" in result.detail
    assert "apply" not in runner.calls
    approvals = context.state / "approvals"
    assert list(approvals.glob("*.json")) == []


def test_a_device_that_comes_back_is_rolled_back(vendor_lab) -> None:
    """A change that takes the management path away ends rolled_back.

    The sessions that could not reach the device are the verify and the
    abort, so the driver cannot abort; the device-side timer brings it
    back and the driver sees the baseline configuration again.
    """
    context, runner = vendor_lab
    runner.down_reads = 4

    result = vl.run_shape(context, context.shapes["02-mgmt-ip"])

    assert result.got == "rolled_back"
    assert result.passed is True
    assert "baseline" in result.detail


def test_a_device_that_stays_away_is_not_called_rolled_back(
    vendor_lab,
) -> None:
    """A device that never comes back is unknown, not rolled_back."""
    context, runner = vendor_lab
    runner.down_reads = 10_000
    context.wait_budget_s = 0

    result = vl.run_shape(context, context.shapes["02-mgmt-ip"])

    assert result.got == "unknown"
    assert result.passed is False


def test_a_device_that_is_not_at_the_baseline_stops_the_run(
    vendor_lab,
) -> None:
    """The baseline hash check stops the run before the shapes."""
    context, runner = vendor_lab
    runner.initial_config = BASE_CONFIG + "\nset system description 'dirty'"
    runner.config = runner.initial_config

    result = vl.run_shape(context, context.shapes["01-harmless"])

    assert result.passed is False
    assert result.fatal is True
    assert result.got == "reset_failed"
    assert "baseline" in result.detail


def test_the_cli_prints_one_line_per_shape(tmp_path: Path,
                                                   monkeypatch: pytest.MonkeyPatch,
                                                   capsys) -> None:
    """The CLI prints name, expected, got, PASS and the seconds."""
    monkeypatch.setattr(nl, "pve_rollback", lambda _lab, _dev: "UPID:fake")
    monkeypatch.setattr(
        nl,
        "pve_wait_task",
        lambda _lab, _upid, timeout_s=120: {"status": "stopped",
                                             "exitstatus": "OK"},
    )
    monkeypatch.setattr(vl, "open_tunnel", lambda _lab, _device: FakeTunnel())
    runner = FakeRunner()
    lab_path = _lab_toml(tmp_path)
    lab = nl.load_lab(lab_path)
    shapes = _shapes_toml(tmp_path)

    rc = vl.main(
        [
            "--vendor",
            "vyos",
            "--shape",
            "01-harmless",
            "--lab",
            str(lab_path),
            "--shapes",
            str(shapes),
            "--state",
            str(tmp_path / "state"),
        ],
        factory=lambda _target: runner,
    )

    out = capsys.readouterr().out
    assert rc == 0, out
    assert "01-harmless" in out
    assert "confirmed" in out
    assert "PASS" in out


def test_the_list_option_contacts_nothing(capsys) -> None:
    """--list names the shapes and stops."""
    rc = vl.main(["--list", "--lab", str(lab_toml_path()),
                 "--shapes", str(LAB_DIR / "vendor-shapes.toml")])

    out = capsys.readouterr().out
    assert rc == 0, out
    for shape_id in SHAPE_IDS:
        assert shape_id in out


def test_the_driver_never_builds_a_shell_string() -> None:
    """No shell string, no os.system, no subprocess shell."""
    source = DRIVER_PATH.read_text(encoding="utf-8")
    assert "shell=True" not in source
    assert "os.system" not in source
    assert "sh -c" not in source


# ---------- the tunnel to the lab VM ----------
#
# The MCP ssh transport is a direct ssh to the device's host and port, but
# the lab VMs are reachable only through apollo.  The driver opens one ssh
# tunnel per run and points the inventory it writes at the tunnel's local
# endpoint, so the MCP transport reaches the VM without a change in mcp/.

def test_the_tunnel_argv_is_exactly_the_expected_list(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The tunnel is one ssh argv list, never a shell string."""
    lab = nl.load_lab(_lab_toml(tmp_path))
    device = lab.devices["lab-vyos"]
    seen: list[list[str]] = []

    class FakeProcess:
        pid = 424242

        def poll(self) -> int | None:
            return None

        def wait(self, timeout: float | None = None) -> int:
            return 0

    def fake_popen(argv: list[str], **_kwargs: Any) -> Any:
        seen.append(list(argv))
        return FakeProcess()

    monkeypatch.setattr(vl, "_free_port", lambda: 22022)
    monkeypatch.setattr(vl, "_port_accepts", lambda _port: True)

    tunnel = vl.open_tunnel(lab, device, popen=fake_popen)

    assert seen == [[
        "ssh",
        "-i", lab.ssh_key,
        "-o", "IdentitiesOnly=yes",
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=8",
        "-o", "ExitOnForwardFailure=yes",
        "-N",
        "-L", "127.0.0.1:22022:10.109.0.31:22",
        "root@192.0.2.1",
    ]]
    assert tunnel.port == 22022
    # the argv is a list of single arguments: no element carries the whole
    # command as one string
    assert not any(item.startswith("ssh -i") for item in seen[0])


def test_the_host_key_is_pinned_at_the_tunnel_endpoint(
    tmp_path: Path, tunnels: list[FakeTunnel]
) -> None:
    """The inventory points at the tunnel and the host key follows."""
    lab = nl.load_lab(_lab_toml(tmp_path))
    context = vl.build_context(
        lab,
        _shapes_toml(tmp_path),
        "vyos",
        factory=lambda _target: FakeRunner(),
        state_dir=tmp_path / "state",
        tunnel_opener=_tunnel_opener(tunnels),
    )
    try:
        inventory = (context.state / "devices.toml").read_text(encoding="utf-8")
        assert 'host = "127.0.0.1"' in inventory
        assert "port = 22022" in inventory
        assert 'user = "newton"' in inventory
        pinned = context.state / "known_hosts"
        assert pinned.read_text(encoding="utf-8") == (
            "[127.0.0.1]:22022 ssh-ed25519 AAAA\n"
        )
        assert pinned.stat().st_mode & 0o777 == 0o600
        # the MCP transport reads the tunnel's endpoint, not the VM's address
        assert context.target.host == "127.0.0.1"
        assert context.target.port == 22022
    finally:
        context.close()


def test_a_hashed_known_hosts_line_is_refused() -> None:
    """A hashed host cannot be rewritten, so the run stops."""
    with pytest.raises(vl.DriverError, match="hashed"):
        vl.rewrite_known_hosts(
            "|1|hashedhost|salt ssh-ed25519 AAAA\n", "10.109.0.31", 22022
        )


def test_an_unreadable_known_hosts_line_is_refused() -> None:
    """A line that is not a known_hosts line stops the run."""
    with pytest.raises(vl.DriverError, match="not a known_hosts line"):
        vl.rewrite_known_hosts("10.109.0.31\n", "10.109.0.31", 22022)
    with pytest.raises(vl.DriverError, match="not a known_hosts line"):
        vl.rewrite_known_hosts(
            "10.109.0.31 notakeytype AAAA\n", "10.109.0.31", 22022
        )
    with pytest.raises(vl.DriverError, match="marker line"):
        vl.rewrite_known_hosts(
            "@cert-authority 10.109.0.31 ssh-ed25519 AAAA\n",
            "10.109.0.31",
            22022,
        )


def test_another_host_s_line_is_skipped_with_a_message() -> None:
    """A line for another host is skipped, and the run says so."""
    text, notes = vl.rewrite_known_hosts(
        "10.109.0.11 ssh-ed25519 LABBR1\n"
        "10.109.0.31 ssh-ed25519 AAAA\n",
        "10.109.0.31",
        22022,
    )

    assert text == "[127.0.0.1]:22022 ssh-ed25519 AAAA\n"
    assert len(notes) == 1
    assert "another host" in notes[0]


def test_a_known_hosts_without_the_device_stops_the_run() -> None:
    """A file that pins nothing for the device stops the run."""
    with pytest.raises(vl.DriverError, match="no entry for"):
        vl.rewrite_known_hosts(
            "10.109.0.11 ssh-ed25519 LABBR1\n", "10.109.0.31", 22022
        )


def test_the_tunnel_is_stopped_when_a_shape_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The tunnel dies with the run, even when a shape raises."""
    opened: list[FakeTunnel] = []

    def fake_open(_lab: Any, _device: Any) -> FakeTunnel:
        tunnel = FakeTunnel()
        opened.append(tunnel)
        return tunnel

    def boom(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("the shape exploded")

    monkeypatch.setattr(vl, "open_tunnel", fake_open)
    monkeypatch.setattr(vl, "run_shape", boom)

    with pytest.raises(RuntimeError, match="the shape exploded"):
        vl.main([
            "--vendor",
            "vyos",
            "--lab",
            str(_lab_toml(tmp_path)),
            "--shapes",
            str(_shapes_toml(tmp_path)),
            "--state",
            str(tmp_path / "state"),
        ])

    assert len(opened) == 1
    assert opened[0].stopped is True


def test_a_missing_device_key_stops_the_run_with_a_message(
    tmp_path: Path, capsys
) -> None:
    """A missing key file is a clear exit 2, not a traceback."""
    lab_path = _lab_toml(tmp_path, admin_key=str(tmp_path / "no-such-key"))

    rc = vl.main([
        "--vendor",
        "vyos",
        "--lab",
        str(lab_path),
        "--shapes",
        str(_shapes_toml(tmp_path)),
        "--state",
        str(tmp_path / "state"),
    ])

    err = capsys.readouterr().err
    assert rc == 2
    assert "no-such-key" in err
    assert "Traceback" not in err


def test_the_device_owns_its_key_and_known_hosts(
    tmp_path: Path, tunnels: list[FakeTunnel]
) -> None:
    """The device's key and known_hosts, not the lab's."""
    lab = nl.load_lab(_lab_toml(tmp_path))
    context = vl.build_context(
        lab,
        _shapes_toml(tmp_path),
        "vyos",
        factory=lambda _target: FakeRunner(),
        state_dir=tmp_path / "state",
        tunnel_opener=_tunnel_opener(tunnels),
    )
    try:
        inventory = (context.state / "devices.toml").read_text(encoding="utf-8")
        assert str(tmp_path / "lab-vyos-key") in inventory
        assert str(tmp_path / "router-key") not in inventory
        pinned = (context.state / "known_hosts").read_text(encoding="utf-8")
        assert "AAAA" in pinned
        assert "LABBR1" not in pinned
    finally:
        context.close()


def test_a_device_without_its_own_key_uses_the_lab_one(
    tmp_path: Path, tunnels: list[FakeTunnel]
) -> None:
    """The lab's key and known_hosts are the fallback."""
    lab = nl.load_lab(_lab_toml(
        tmp_path,
        device_paths=False,
        lab_known_hosts="10.109.0.31 ssh-ed25519 AAAA\n",
    ))
    context = vl.build_context(
        lab,
        _shapes_toml(tmp_path),
        "vyos",
        factory=lambda _target: FakeRunner(),
        state_dir=tmp_path / "state",
        tunnel_opener=_tunnel_opener(tunnels),
    )
    try:
        inventory = (context.state / "devices.toml").read_text(encoding="utf-8")
        assert str(tmp_path / "router-key") in inventory
        pinned = (context.state / "known_hosts").read_text(encoding="utf-8")
        assert pinned == "[127.0.0.1]:22022 ssh-ed25519 AAAA\n"
    finally:
        context.close()


def test_a_lab_known_hosts_without_the_device_stops_the_run(
    tmp_path: Path, tunnels: list[FakeTunnel]
) -> None:
    """A fallback that pins nothing for the device stops the run."""
    lab = nl.load_lab(_lab_toml(tmp_path, device_paths=False))

    with pytest.raises(vl.DriverError, match="no entry for"):
        vl.build_context(
            lab,
            _shapes_toml(tmp_path),
            "vyos",
            factory=lambda _target: FakeRunner(),
            state_dir=tmp_path / "state",
            tunnel_opener=_tunnel_opener(tunnels),
        )


# ---------- the fixes of the review ----------
#
# A review found four holes in
# the driver: a post could name any device of the lab, --no-reset skipped
# the baseline check, the tunnel trusted whatever answered on its port,
# and a passphrase that was not UTF-8 ended the run with a traceback.


def test_a_post_may_not_name_another_device(tmp_path: Path) -> None:
    """A post may only name the VM under test or a helper.

    A post is a command the driver runs over ssh after the apply, and the
    shapes file is data.  Without an allowlist a shapes file could point
    a post at any device of the lab (lab-r1, lab-isp) and the driver
    would run a command on it.  The allowed names are the VM under test
    and the helpers the shapes file declares; anything else is refused
    when the file is read.
    """
    path = _shapes_toml(
        tmp_path,
        extra=(
            "[shapes.09-post]\n"
            'id = "09-post"\n'
            'description = "A post on a device the driver may not use."\n'
            'expect = "confirmed"\n'
            "explanation = { intent = \"Nothing.\", steps = [\"One.\"], "
            "risk = \"Nothing.\" }\n"
            "\n"
            "[vyos.09-post]\n"
            "lines = [\"set system description 'x'\"]\n"
            "claims = [{ kind = \"config_has\", "
            "line = \"set system description 'x'\" }]\n"
            "posts = [{ device = \"lab-r1\", cmd = \"true\" }]\n"
        ),
    )

    with pytest.raises(vl.ShapeError, match="lab-r1"):
        vl.load_shapes(path, "vyos")


def test_a_helper_may_be_used_by_a_post(tmp_path: Path) -> None:
    """A device of the [helpers] table may be used by a post.

    The helpers table is the operator's allowlist: a shape may run a post
    on a helper device, and on nothing else.
    """
    path = _shapes_toml(
        tmp_path,
        extra=(
            "[helpers]\n"
            'devices = ["lab-client"]\n'
            "\n"
            "[shapes.09-post]\n"
            'id = "09-post"\n'
            'description = "A post on a helper device."\n'
            'expect = "confirmed"\n'
            "explanation = { intent = \"Nothing.\", steps = [\"One.\"], "
            "risk = \"Nothing.\" }\n"
            "\n"
            "[vyos.09-post]\n"
            "lines = [\"set system description 'x'\"]\n"
            "claims = [{ kind = \"config_has\", "
            "line = \"set system description 'x'\" }]\n"
            "posts = [{ device = \"lab-client\", cmd = \"true\" }]\n"
        ),
    )

    shapes = vl.load_shapes(path, "vyos")

    assert shapes["09-post"].posts[0].device == "lab-client"
    assert shapes["09-post"].helpers == ("lab-client",)


def test_the_helpers_table_is_empty_by_default(tmp_path: Path) -> None:
    """A shapes file without a [helpers] table allows no helper."""
    shapes = vl.load_shapes(_shapes_toml(tmp_path), "vyos")

    assert shapes["01-harmless"].helpers == ()
    assert shapes["01-harmless"].posts == ()


def test_the_vm_under_test_may_be_named_by_a_post(
    tmp_path: Path,
) -> None:
    """The VM under test is not a helper and is still allowed.

    The driver knows the name of the VM it runs against, so a post may
    name it; the name is not a helper and needs no entry in [helpers].
    """
    path = _shapes_toml(
        tmp_path,
        extra=(
            "[shapes.09-post]\n"
            'id = "09-post"\n'
            'description = "A post on the VM under test."\n'
            'expect = "confirmed"\n'
            "explanation = { intent = \"Nothing.\", steps = [\"One.\"], "
            "risk = \"Nothing.\" }\n"
            "\n"
            "[vyos.09-post]\n"
            "lines = [\"set system description 'x'\"]\n"
            "claims = [{ kind = \"config_has\", "
            "line = \"set system description 'x'\" }]\n"
            "posts = [{ device = \"lab-vyos\", cmd = \"true\" }]\n"
        ),
    )

    shapes = vl.load_shapes(path, "vyos", device="lab-vyos")

    assert shapes["09-post"].posts[0].device == "lab-vyos"


def test_no_reset_still_checks_the_baseline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    """--no-reset reads the configuration hash and stops at 2.

    Without the reset the driver cannot put the VM back at the snapshot,
    so a device that is not at the recorded baseline would run the shape
    against a configuration nobody planned for.  The driver reads the
    hash first and stops with exit 2 when it differs from the baseline.
    """
    monkeypatch.setattr(nl, "pve_rollback", lambda _lab, _dev: "UPID:fake")
    monkeypatch.setattr(vl, "open_tunnel", lambda _lab, _device: FakeTunnel())
    runner = FakeRunner()
    runner.config = BASE_CONFIG + "\nset system description 'dirty'"

    rc = vl.main(
        [
            "--vendor",
            "vyos",
            "--shape",
            "01-harmless",
            "--lab",
            str(_lab_toml(tmp_path)),
            "--shapes",
            str(_shapes_toml(tmp_path)),
            "--state",
            str(tmp_path / "state"),
            "--no-reset",
        ],
        factory=lambda _target: runner,
    )

    err = capsys.readouterr().err
    assert rc == 2
    assert "baseline" in err
    assert "Traceback" not in err
    # the shape never ran
    assert "apply" not in runner.calls


def test_no_reset_runs_a_device_at_the_baseline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    """--no-reset on a device at the baseline runs the shape."""
    monkeypatch.setattr(nl, "pve_rollback", lambda _lab, _dev: "UPID:fake")
    monkeypatch.setattr(vl, "open_tunnel", lambda _lab, _device: FakeTunnel())
    runner = FakeRunner()

    rc = vl.main(
        [
            "--vendor",
            "vyos",
            "--shape",
            "01-harmless",
            "--lab",
            str(_lab_toml(tmp_path)),
            "--shapes",
            str(_shapes_toml(tmp_path)),
            "--state",
            str(tmp_path / "state"),
            "--no-reset",
        ],
        factory=lambda _target: runner,
    )

    out = capsys.readouterr().out
    assert rc == 0, out
    assert "01-harmless" in out
    assert "apply" in runner.calls


def test_a_foreign_listener_is_not_our_tunnel(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The listener on the port must be the ssh we started.

    The port is free when it is chosen, but something else may take it
    before the ssh binds it.  The tunnel then looks open while our ssh
    has died, and the driver would talk to whatever else is listening.
    The proof is that the ssh child is still running and that the port
    answers again after a short settle.
    """
    lab = nl.load_lab(_lab_toml(tmp_path))
    device = lab.devices["lab-vyos"]

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind((vl.TUNNEL_HOST, 0))
    listener.listen(1)
    port = int(listener.getsockname()[1])

    class DyingProcess:
        pid = 424242

        def __init__(self) -> None:
            self._polls = 0

        def poll(self) -> int | None:
            self._polls += 1
            # alive for the first check, gone for the proof
            return None if self._polls == 1 else 0

        def wait(self, timeout: float | None = None) -> int:
            return 0

    monkeypatch.setattr(vl, "_free_port", lambda: port)
    monkeypatch.setattr(vl, "_kill_tunnel", lambda _process: None)

    try:
        with pytest.raises(vl.DriverError, match="exited"):
            vl.open_tunnel(
                lab,
                device,
                popen=lambda _argv, **_kwargs: DyingProcess(),
            )
    finally:
        listener.close()


def test_a_passphrase_that_is_not_utf8_fails_the_shape(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A passphrase that is not UTF-8 fails the shape, not the run.

    The passphrase file is read as bytes and decoded for the approval
    prompt.  A file that is not UTF-8 must not end the whole run with a
    traceback: the shape fails and the driver goes on to the next one.
    """
    monkeypatch.setattr(nl, "pve_rollback", lambda _lab, _dev: "UPID:fake")
    monkeypatch.setattr(
        nl,
        "pve_wait_task",
        lambda _lab, _upid, timeout_s=120: {"status": "stopped",
                                             "exitstatus": "OK"},
    )
    monkeypatch.setattr(vl, "open_tunnel", lambda _lab, _device: FakeTunnel())
    lab = nl.load_lab(_lab_toml(tmp_path, passphrase=b"\xff\xfe not utf-8\n"))
    runner = FakeRunner()
    context = vl.build_context(
        lab,
        _shapes_toml(tmp_path),
        "vyos",
        factory=lambda _target: runner,
        state_dir=tmp_path / "state",
    )
    try:
        result = vl.run_shape(context, context.shapes["01-harmless"])
    finally:
        context.close()

    assert result.got == "approval_failed"
    assert result.passed is False
    assert "passphrase" in result.detail


def test_the_state_directory_is_kept_and_the_driver_says_so(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    """--state keeps the records, and the driver says so.

    The state directory holds the plan records and the approval records,
    which are not removed when the run ends.  The driver says so, so the
    operator knows the records are still there.
    """
    monkeypatch.setattr(nl, "pve_rollback", lambda _lab, _dev: "UPID:fake")
    monkeypatch.setattr(
        nl,
        "pve_wait_task",
        lambda _lab, _upid, timeout_s=120: {"status": "stopped",
                                             "exitstatus": "OK"},
    )
    monkeypatch.setattr(vl, "open_tunnel", lambda _lab, _device: FakeTunnel())
    runner = FakeRunner()
    state = tmp_path / "state"

    vl.main(
        [
            "--vendor",
            "vyos",
            "--shape",
            "01-harmless",
            "--lab",
            str(_lab_toml(tmp_path)),
            "--shapes",
            str(_shapes_toml(tmp_path)),
            "--state",
            str(state),
        ],
        factory=lambda _target: runner,
    )

    err = capsys.readouterr().err
    assert str(state) in err
    assert "records" in err
    assert state.is_dir()


def test_a_session_that_cannot_be_prepared_is_refused_at_plan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A session that cannot be prepared refuses the plan.

    The error file is made before the first statement, so a session that
    could not prepare it stops the plan with a refusal that says what
    happened.  Nothing is applied and no session is opened after it.
    """
    monkeypatch.setattr(nl, "pve_rollback", lambda _lab, _dev: "UPID:fake")
    monkeypatch.setattr(
        nl,
        "pve_wait_task",
        lambda _lab, _upid, timeout_s=120: {"status": "stopped",
                                             "exitstatus": "OK"},
    )
    monkeypatch.setattr(vl, "open_tunnel", lambda _lab, _device: FakeTunnel())
    lab = nl.load_lab(_lab_toml(tmp_path))
    runner = FakeRunner(session_error=True)
    context = vl.build_context(
        lab,
        _shapes_toml(tmp_path),
        "vyos",
        factory=lambda _target: runner,
        state_dir=tmp_path / "state",
    )
    try:
        result = vl.run_shape(context, context.shapes["01-harmless"])
    finally:
        context.close()

    assert result.got == "refused_at_plan"
    assert "could not prepare the session" in result.detail
    assert "apply" not in runner.calls


# ---------- planted mutations ----------
# Each line names a mutation an engineer may try, and the test that must
# fail when it is made.
#
# M1  the driver stops comparing the outcome with the shape's expect
#     -> test_vpa4_05 and test_vpa4_08 fail
# M2  the driver writes the approval record by hand instead of calling the
#     real newton-approve code
#     -> test_vpa4_05 fails (the file newton-approve writes is missing)
# M3  the driver opens a session before the plan (a "hello" probe)
#     -> test_vpa4_07 fails (the counter is not 0)
# M4  the driver skips the baseline hash check after the reset
#     -> test_vpa4_11 fails (the run is not fatal)
# M5  the driver reports a device that never came back as rolled_back
#     -> test_vpa4_10 fails
# M6  the driver treats a missing approval record as a normal apply
#     -> test_vpa4_08 fails
# M7  the loader accepts a shape whose steps do not match its lines
#     -> test_vpa4_04 fails
# M8  the loader accepts an unknown vendor
#     -> test_vpa4_02 fails
# M9  the loader accepts a shape with no lines
#     -> test_vpa4_03 fails
# M10 the tunnel is built as one shell string (or with shell=True)
#     -> test_vpa4b_01 fails (the argv is not the expected list)
# M11 the tunnel is not killed when a shape raises
#     -> test_vpa4b_07 fails (the tunnel is still open)
# M12 the known_hosts is not rewritten for the tunnel's endpoint
#     -> test_vpa4b_02 fails (the pinned host is the VM's address)
# M13 a missing key file is ignored (the run starts anyway)
#     -> test_vpa4b_08 fails (the exit code is not 2)
# M14 the lab's key is used where the device has its own
#     -> test_vpa4b_09 fails (the inventory carries the lab's key)
# M15 the loader accepts a post that names any device of the lab
#     -> test_vpa5c_01 fails (the post is not refused)
# M16 the driver skips the baseline check when the reset is skipped
#     -> test_vpa5c_05 fails (the run does not stop at 2)
# M17 the tunnel trusts whatever answers on its port
#     -> test_vpa5c_07 fails (the run continues with a foreign listener)
# M18 a passphrase that is not UTF-8 ends the run with a traceback
#     -> test_vpa5c_08 fails (the shape does not fail on its own)


# ---------- the RouterOS CHR in the lab driver ----------
#
# The driver is vendor-neutral: the shapes file carries one table per
# vendor, the lab file names the device of that vendor, and the hash of the
# running configuration is the one the vendor's own operations define.
#


CHR_EXPORT = "\n".join(
    [
        "# jan/01/2026 12:00:00 by RouterOS 7.24.5",
        "/ip address add address=10.109.0.21/24 interface=ether1 network=10.109.0.0",
        "/system identity set name=lab-chr",
        "",
    ]
)


def _chr_hash() -> str:
    """The hash the CHR operations define for the export above."""
    from newton_mcp.adapters import routeros_write

    return routeros_write.config_hash(CHR_EXPORT)


class FakeChr:
    """A scripted CHR: the export, the two counts, the arm and the ping."""

    def __init__(self, config: str = CHR_EXPORT) -> None:
        self.config = config
        self.scheduler = 0
        self.backups = 0
        self.calls: list[str] = []
        self.ping_ok = True

    def __call__(self, spec: Any) -> Any:
        from newton_mcp.vendor_change import RunOut

        remote = spec.remote
        self.calls.append(remote)
        if remote == "/export":
            return RunOut(status="ok", stdout=self.config, stderr="",
                          exit_code=0)
        if remote.startswith("/system scheduler print count-only"):
            return RunOut(status="ok", stdout=f"{self.scheduler}\n", stderr="",
                          exit_code=0)
        if remote.startswith("/file print count-only"):
            return RunOut(status="ok", stdout=f"{self.backups}\n", stderr="",
                          exit_code=0)
        if remote.startswith("/system scheduler print detail"):
            return RunOut(
                status="ok",
                stdout=(
                    "  name=newton-revert\n"
                    "  next-run=jan/01/2026 12:02:00\n"
                    '  on-event="/system backup load name=newton-revert '
                    'password=\\"\\""\n'
                ),
                stderr="",
                exit_code=0,
            )
        if "/system backup save" in remote:
            self.scheduler = 1
            self.backups = 1
            return RunOut(status="ok", stdout="armed for 00:02:00\n", stderr="",
                          exit_code=0)
        if "/system scheduler set" in remote:
            return RunOut(status="ok", stdout="", stderr="", exit_code=0)
        if remote.startswith("/system scheduler remove"):
            self.scheduler = 0
            return RunOut(status="ok", stdout="", stderr="", exit_code=0)
        if remote.startswith("/file remove"):
            self.backups = 0
            return RunOut(status="ok", stdout="", stderr="", exit_code=0)
        if remote.startswith("/system backup load"):
            self.config = CHR_EXPORT
            self.scheduler = 0
            self.backups = 0
            return RunOut(
                status="ok",
                stdout="System configuration restored, rebooting now\n",
                stderr="",
                exit_code=0,
            )
        if remote.startswith(":put [/system resource get uptime"):
            return RunOut(status="ok", stdout="1d02:03:04\n", stderr="",
                          exit_code=0)
        if remote.startswith("/ping "):
            return RunOut(
                status="ok",
                stdout="received=3 packets\n" if self.ping_ok else "received=0\n",
                stderr="",
                exit_code=0,
            )
        if remote.startswith(':put "NEWTON-LINE-ERROR'):
            return RunOut(status="ok", stdout="", stderr="", exit_code=0)
        return RunOut(status="ok", stdout="", stderr="", exit_code=0)


def _chr_lab_toml(tmp_path: Path) -> Path:
    """The lab file with a RouterOS CHR device."""
    key = tmp_path / "router-key"
    key.write_text("FAKE-LAB-KEY\n", encoding="utf-8")
    key.chmod(0o600)
    lab_known_hosts = tmp_path / "known-hosts"
    lab_known_hosts.write_text("10.109.0.11 ssh-ed25519 LABBR1\n", encoding="utf-8")
    device_key = tmp_path / "lab-chr-key"
    device_key.write_text("FAKE-CHR-KEY\n", encoding="utf-8")
    device_key.chmod(0o600)
    device_known_hosts = tmp_path / "lab-chr-known-hosts"
    device_known_hosts.write_text("10.109.0.21 ssh-ed25519 CHRKEY\n",
                                   encoding="utf-8")
    passphrase = tmp_path / "approve.pw"
    passphrase.write_bytes(b"lab-passphrase\n")
    path = tmp_path / "lab.toml"
    path.write_text(
        "[pve]\n"
        'host = "192.0.2.1"\n'
        'node = "test"\n'
        'token_file = "~/.config/pve/apollo.token"\n'
        'pin_file = "~/.config/pve/apollo.pin"\n'
        "\n"
        "[ssh]\n"
        'proxy = "ssh -i /tmp/fake -W %h:%p root@192.0.2.1"\n'
        'password_file = "~/.config/newton/lab-root.pw"\n'
        f'key = "{tmp_path / "lab-key"}"\n'
        f'router_key = "{key}"\n'
        f'approve_passphrase_file = "{passphrase}"\n'
        f'known_hosts = "{lab_known_hosts}"\n'
        "\n"
        "[devices.lab-chr]\n"
        "vmid = 9103\n"
        'host = "10.109.0.21"\n'
        'user = "newton"\n'
        'platform = "routeros"\n'
        "vendor_write = true\n"
        'snapshot = "baseline-newton-write"\n'
        'settle_cmd = ""\n'
        f'known_hosts = "{device_known_hosts}"\n'
        f'admin_key = "{device_key}"\n',
        encoding="utf-8",
    )
    return path


def _routeros_shapes_toml(tmp_path: Path) -> Path:
    """The shapes file with the routeros tables of two shapes."""
    path = tmp_path / "routeros-shapes.toml"
    path.write_text(
        "[vars]\n"
        'mgmt_peer = "10.109.0.10"\n'
        "\n"
        "[baseline.routeros]\n"
        f'config_hash = "{_chr_hash()}"\n'
        "\n"
        "[shapes.01-harmless]\n"
        'id = "01-harmless"\n'
        'description = "The identity of the CHR changes."\n'
        'expect = "confirmed"\n'
        "timeout_s = 90\n"
        'explanation = { intent = "Set the identity of the lab CHR.", '
        'steps = ["Set the identity name."], '
        'risk = "The identity of the lab device changes." }\n'
        "\n"
        "[routeros.01-harmless]\n"
        'lines = ["/system/identity set name=lab-chr-shape-01"]\n'
        'claims = [{ kind = "ping", host = "{mgmt_peer}" }]\n'
        "\n"
        "[shapes.08-no-approval]\n"
        'id = "08-no-approval"\n'
        'description = "A change nobody approved."\n'
        'expect = "refused_at_apply"\n'
        "approval = false\n"
        'explanation = { intent = "Apply a change nobody approved.", '
        'steps = ["Set the identity name."], '
        'risk = "Nothing is applied." }\n'
        "\n"
        "[routeros.08-no-approval]\n"
        'lines = ["/system/identity set name=lab-chr-shape-08"]\n'
        'claims = [{ kind = "ping", host = "{mgmt_peer}" }]\n',
        encoding="utf-8",
    )
    return path


def test_the_shipped_shapes_file_expands_for_routeros() -> None:
    """The shipped shapes file carries the eight CHR shapes."""
    shapes = vl.load_shapes(LAB_DIR / "vendor-shapes.toml", "routeros")

    assert tuple(sorted(shapes)) == SHAPE_IDS
    assert shapes["01-harmless"].expect == "confirmed"
    assert shapes["02-mgmt-ip"].expect == "rolled_back"
    assert shapes["03-input-drop"].expect == "rolled_back"
    assert shapes["04-injection"].expect == "refused_at_plan"
    assert shapes["04-injection"].sessions == 0
    assert shapes["05-bad-syntax"].expect == "rolled_back"
    assert shapes["06-service-reachable"].expect == "refused_at_plan"
    assert shapes["06-service-reachable"].sessions == 0
    assert shapes["07-uplink-down"].expect == "rolled_back"
    assert shapes["08-no-approval"].expect == "refused_at_apply"
    assert shapes["08-no-approval"].approval is False
    for shape in shapes.values():
        assert shape.lines
        assert shape.claims
        assert shape.explanation["intent"]
        assert len(shape.explanation["steps"]) == len(shape.lines)
        # a CHR carries the ping claim only: the export normalises its lines
        for claim in shape.claims:
            assert claim["kind"] == "ping"


def test_the_shipped_shapes_file_carries_the_chr_baseline() -> None:
    """The baseline table of the CHR is a hash of its own."""
    digest = vl.load_baseline_hash(LAB_DIR / "vendor-shapes.toml", "routeros")

    assert len(digest) == 64
    assert all(char in "0123456789abcdef" for char in digest)


def test_a_shape_without_chr_lines_is_refused(tmp_path: Path) -> None:
    """A shape with no lines for the vendor is refused."""
    path = _routeros_shapes_toml(tmp_path)
    text = path.read_text(encoding="utf-8")
    start = text.index("[routeros.01-harmless]")
    end = text.index("[shapes.08-no-approval]")
    path.write_text(text[:start] + text[end:], encoding="utf-8")

    with pytest.raises(vl.ShapeError, match="lines"):
        vl.load_shapes(path, "routeros")


def test_a_vendor_without_tables_is_refused(tmp_path: Path) -> None:
    """A vendor with no tables in the file is refused."""
    with pytest.raises(vl.ShapeError, match="no tables for vendor"):
        vl.load_shapes(_routeros_shapes_toml(tmp_path), "junos")


def test_the_gate_uses_the_hash_the_operations_define(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    """The driver compares the CHR's own hash of the export.

    The export of a CHR hashes as the CHR operations hash it, not as the
    sha256 of the text: the export normalises its lines.  The baseline
    gate must use the same definition, or a device that is at the baseline
    looks changed.
    """
    monkeypatch.setattr(nl, "pve_rollback", lambda _lab, _dev: "UPID:fake")
    monkeypatch.setattr(vl, "open_tunnel", lambda _lab, _device: FakeTunnel())
    runner = FakeChr()
    lab_path = _chr_lab_toml(tmp_path)
    shapes = _routeros_shapes_toml(tmp_path)

    rc = vl.main(
        [
            "--vendor",
            "routeros",
            "--shape",
            "01-harmless",
            "--lab",
            str(lab_path),
            "--shapes",
            str(shapes),
            "--state",
            str(tmp_path / "state"),
            "--no-reset",
        ],
        factory=lambda _target: runner,
    )

    out = capsys.readouterr().out
    err = capsys.readouterr().err
    assert rc == 0, (out, err)
    assert "01-harmless" in out
    assert "confirmed" in out
    # the CHR was asked for its export, not for a VyOS configuration
    assert "/export" in runner.calls


def test_the_vyos_hash_is_not_the_chr_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    """The sha256 of the export is not the CHR's hash."""
    monkeypatch.setattr(nl, "pve_rollback", lambda _lab, _dev: "UPID:fake")
    monkeypatch.setattr(vl, "open_tunnel", lambda _lab, _device: FakeTunnel())
    runner = FakeChr()
    lab_path = _chr_lab_toml(tmp_path)
    shapes = _routeros_shapes_toml(tmp_path)
    shapes.write_text(
        shapes.read_text(encoding="utf-8").replace(
            _chr_hash(),
            hashlib.sha256(CHR_EXPORT.encode("utf-8")).hexdigest(),
        ),
        encoding="utf-8",
    )

    rc = vl.main(
        [
            "--vendor",
            "routeros",
            "--shape",
            "01-harmless",
            "--lab",
            str(lab_path),
            "--shapes",
            str(shapes),
            "--state",
            str(tmp_path / "state"),
            "--no-reset",
        ],
        factory=lambda _target: runner,
    )

    err = capsys.readouterr().err
    assert rc == 2
    assert "baseline" in err


def test_the_list_uses_the_same_post_allowlist(
    tmp_path: Path, capsys
) -> None:
    """--list loads the shapes the way a run loads them.

    A post may name the device under test.  The loader refuses any other
    name, so a file that names the device under test must load under
    --list as well, or the listing of the file is not the listing of the
    run.
    """
    path = _shapes_toml(
        tmp_path,
        extra=(
            "[shapes.09-post]\n"
            'id = "09-post"\n'
            'description = "A post on the device under test."\n'
            'expect = "confirmed"\n'
            "explanation = { intent = \"Nothing.\", steps = [\"One.\"], "
            "risk = \"Nothing.\" }\n"
            "\n"
            "[vyos.09-post]\n"
            "lines = [\"set system description 'x'\"]\n"
            "claims = [{ kind = \"config_has\", "
            "line = \"set system description 'x'\" }]\n"
            "posts = [{ device = \"lab-vyos\", cmd = \"true\" }]\n"
        ),
    )

    rc = vl.main(
        [
            "--list",
            "--vendor",
            "vyos",
            "--lab",
            str(_lab_toml(tmp_path)),
            "--shapes",
            str(path),
        ]
    )

    out = capsys.readouterr().out
    assert rc == 0, out
    assert "09-post" in out


def test_a_post_may_not_name_a_foreign_device_at_run_time(
    tmp_path: Path, tunnels: list[FakeTunnel]
) -> None:
    """The run refuses a post the loader never allowed.

    The loader refuses a foreign name when the file is read.  The run
    checks again, because the loader is not the only way a post reaches
    the driver: a shape built by hand, or a file changed between the load
    and the run, must not make the driver run a command on a device it
    was not told about.
    """
    lab = nl.load_lab(_lab_toml(tmp_path))
    context = vl.build_context(
        lab,
        _shapes_toml(tmp_path),
        "vyos",
        factory=lambda _target: FakeRunner(),
        state_dir=tmp_path / "state",
        tunnel_opener=_tunnel_opener(tunnels),
    )
    try:
        post = vl.Post(device="lab-r1", cmd="true")
        ok, detail = vl._run_post(context, post)

        assert ok is False
        assert "lab-r1" in detail
        assert "not the device under test" in detail
    finally:
        context.close()


def test_a_shape_level_device_key_does_not_widen_the_allowlist(
    tmp_path: Path,
) -> None:
    """The device key of a shape is not a device a post may name.

    The allowed names are the device under test and the helpers of the
    [helpers] table.  A shape that names another device does not widen
    that list: the shape is data, and the data may not point the driver
    at a device of the lab.
    """
    path = _shapes_toml(
        tmp_path,
        extra=(
            "[shapes.09-post]\n"
            'id = "09-post"\n'
            'description = "A post on a device the driver may not use."\n'
            'expect = "confirmed"\n'
            'device = "lab-r1"\n'
            "explanation = { intent = \"Nothing.\", steps = [\"One.\"], "
            "risk = \"Nothing.\" }\n"
            "\n"
            "[vyos.09-post]\n"
            "lines = [\"set system description 'x'\"]\n"
            "claims = [{ kind = \"config_has\", "
            "line = \"set system description 'x'\" }]\n"
            "posts = [{ device = \"lab-r1\", cmd = \"true\" }]\n"
        ),
    )

    with pytest.raises(vl.ShapeError, match="lab-r1"):
        vl.load_shapes(path, "vyos", device="lab-vyos")


def test_no_reset_needs_exactly_one_shape(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    """--no-reset is only allowed with a single --shape.

    The baseline gate protects one shape: the gate runs before the first
    shape and cannot tell the second shape from a device that was changed
    by the first one.  So the run stops with exit 2 and a message.
    """
    monkeypatch.setattr(nl, "pve_rollback", lambda _lab, _dev: "UPID:fake")
    monkeypatch.setattr(vl, "open_tunnel", lambda _lab, _device: FakeTunnel())

    rc = vl.main(
        [
            "--vendor",
            "vyos",
            "--no-reset",
            "--lab",
            str(_lab_toml(tmp_path)),
            "--shapes",
            str(_shapes_toml(tmp_path)),
            "--state",
            str(tmp_path / "state"),
        ],
        factory=lambda _target: FakeRunner(),
    )

    err = capsys.readouterr().err
    assert rc == 2
    assert "--no-reset" in err
    assert "--shape" in err


def test_a_tunnel_that_loses_its_port_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The tunnel that stays alive but loses its port is refused.

    The proof of the tunnel has two legs: the ssh child must still be
    running, and the port must answer again after a short settle.  A child
    that is alive but whose port stopped answering is the second leg, and
    it is a refusal like the first one.
    """
    lab = nl.load_lab(_lab_toml(tmp_path))
    device = lab.devices["lab-vyos"]

    class AliveProcess:
        pid = 424242

        def poll(self) -> int | None:
            return None

        def wait(self, timeout: float | None = None) -> int:
            return 0

    answers = iter([True, False])
    monkeypatch.setattr(vl, "_free_port", lambda: 22022)
    monkeypatch.setattr(vl, "_port_accepts", lambda _port: next(answers))
    monkeypatch.setattr(vl, "_kill_tunnel", lambda _process: None)

    with pytest.raises(vl.DriverError, match="lost its port"):
        vl.open_tunnel(
            lab,
            device,
            popen=lambda _argv, **_kwargs: AliveProcess(),
        )


def test_the_tunnel_refuses_a_silent_forward_failure(
    tmp_path: Path,
) -> None:
    """The tunnel's argv pins ExitOnForwardFailure=yes.

    Without it the ssh may fail to open the forward and carry on, and the
    driver would talk to whatever else answers on the port.
    """
    lab = nl.load_lab(_lab_toml(tmp_path))
    device = lab.devices["lab-vyos"]

    argv = vl.tunnel_argv(lab, device, 22022)

    assert "ExitOnForwardFailure=yes" in argv
    assert "-N" in argv


def test_the_chr_lines_of_the_shipped_file_are_statements() -> None:
    """Every CHR line of the shipped file is a RouterOS statement.

    The lines of the two shapes that must be refused are refused by the
    lint of the vendor, one line at a time: a character RouterOS refuses,
    the menu it refuses, and the name it reserves for itself.
    """
    from newton_mcp.adapters import routeros_write

    shapes = vl.load_shapes(LAB_DIR / "vendor-shapes.toml", "routeros")
    refused = ("04-injection", "06-service-reachable")

    for shape in shapes.values():
        if shape.id in refused:
            continue
        statements = routeros_write.parse_lines("\n".join(shape.lines))
        assert len(statements) == len(shape.lines), shape.id

    for shape_id in refused:
        shape = shapes[shape_id]
        with pytest.raises(routeros_write.LintError):
            routeros_write.parse_lines("\n".join(shape.lines))
        assert shape.sessions == 0
        assert shape.expect == "refused_at_plan"


# ---- the reset that lost the lock -------------------------------------
#
# The rollback task of the Proxmox API can lose the lock of the config of
# the VM: the previous rollback of the same VM is still finishing and it
# holds that lock, so the task says "can't lock file ... - got timeout"
# and does nothing at all.  The rollback is then sent again, a few
# seconds later.  Every other failure of the task is a failure of the
# rollback itself and is not retried.

# The message of the Proxmox task that lost the lock (the CHR is vmid
# 9103, the VyOS device is vmid 9104).
LOCK_TIMEOUT = (
    "can't lock file '/var/lock/qemu-server/lock-704.conf' - got timeout"
)


def _reset_context(tmp_path: Path, lab: Any) -> Any:
    """A driver context with a fake device behind it."""
    return vl.build_context(
        lab,
        _shapes_toml(tmp_path),
        "vyos",
        factory=lambda _target: FakeRunner(),
        state_dir=tmp_path / "state",
    )


def _stub_rollback(
    monkeypatch: pytest.MonkeyPatch,
    statuses: list[dict[str, Any]],
    rollbacks: list[int],
) -> None:
    """The Proxmox stub: a list of task statuses and a counter."""
    monkeypatch.setattr(
        nl,
        "pve_rollback",
        lambda _lab, _dev: rollbacks.append(1) or "UPID:fake",
    )
    monkeypatch.setattr(
        nl,
        "pve_wait_task",
        lambda _lab, _upid, timeout_s=120: statuses.pop(0),
    )


def test_the_rollback_that_lost_the_lock_is_sent_again(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A task that lost the lock is rolled back again.

    The previous rollback of the same VM is still finishing and it holds
    the lock of the config of the VM.  The new task cannot take that
    lock and says so, and the rollback is sent again twenty seconds
    later.
    """
    lab = nl.load_lab(_lab_toml(tmp_path))
    monkeypatch.setattr(vl, "open_tunnel", _tunnel_opener([]))
    context = _reset_context(tmp_path, lab)
    rollbacks: list[int] = []
    _stub_rollback(
        monkeypatch,
        [
            {"status": "stopped", "exitstatus": LOCK_TIMEOUT},
            {"status": "stopped", "exitstatus": "OK"},
        ],
        rollbacks,
    )
    sleeps: list[float] = []

    ok, detail = vl._reset(context, sleep=sleeps.append)

    assert ok is True, detail
    assert len(rollbacks) == 2
    assert sleeps == [20]


def test_a_failure_that_is_not_the_lock_is_not_retried(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Any other failure of the task stops the run at once.

    A task that failed for another reason is a failure of the rollback
    itself: sending it again would only hide it.
    """
    lab = nl.load_lab(_lab_toml(tmp_path))
    monkeypatch.setattr(vl, "open_tunnel", _tunnel_opener([]))
    context = _reset_context(tmp_path, lab)
    rollbacks: list[int] = []
    _stub_rollback(
        monkeypatch,
        [
            {
                "status": "stopped",
                "exitstatus": "command 'qm rollback' failed: exit code 1",
            },
        ],
        rollbacks,
    )
    sleeps: list[float] = []

    ok, detail = vl._reset(context, sleep=sleeps.append)

    assert ok is False
    assert len(rollbacks) == 1
    assert sleeps == []
    assert "exit code 1" in detail


def test_the_lock_is_retried_four_times_at_most(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Four attempts, twenty seconds apart, and then the run stops.

    The lock of the config of the VM is held by the rollback that is
    still finishing.  Four attempts and three waits of twenty seconds
    are the bound; after that the run stops and says what the task said.
    """
    lab = nl.load_lab(_lab_toml(tmp_path))
    monkeypatch.setattr(vl, "open_tunnel", _tunnel_opener([]))
    context = _reset_context(tmp_path, lab)
    rollbacks: list[int] = []
    _stub_rollback(
        monkeypatch,
        [{"status": "stopped", "exitstatus": LOCK_TIMEOUT}] * 4,
        rollbacks,
    )
    sleeps: list[float] = []

    ok, detail = vl._reset(context, sleep=sleeps.append)

    assert ok is False
    assert len(rollbacks) == 4
    assert sleeps == [20, 20, 20]
    assert "got timeout" in detail


# ---------- the Junos in the lab driver ----------
#
# The third vendor is a Junos.  Its revert is native (commit confirmed),
# so the driver never has to undo anything itself, and the shapes file
# carries the Junos lines of the eight shapes.
#
# A Junos takes six to eight minutes to boot from a cold rollback, so a
# device that asks for the fast reset is left alone when it is already at
# the baseline: the driver reads the hash of the running configuration and
# the pending state, and a device that is at the baseline with nothing
# pending skips the Proxmox rollback.
#


JUNOS_CONFIG = "\n".join(
    [
        "set version 26.2R1.7",
        "set system host-name lab-junos",
        "set interfaces lo0 unit 0 family inet address 198.51.100.1/32",
    ]
)

JUNOS_CONFIG_COMMAND = "show configuration | display set | no-more"
JUNOS_CANDIDATE_COMMAND = "show | display set | no-more"
JUNOS_PENDING_COMMAND = "show system commit | no-more"
JUNOS_PROMPT = "newton@lab-junos"


def _junos_hash(config: str = JUNOS_CONFIG) -> str:
    """The hash the Junos operations define for a display-set text."""
    from newton_mcp.adapters import junos_write

    return junos_write.config_hash(config)


class FakeJunos:
    """A scripted Junos: the configuration, the commit list, the CLI and the ping.

    Every read is answered the way the device shows it: the block of the
    CLI that carries the answer.  A read may be an exec session or a
    session of the CLI, and the fake answers both the same way.
    """

    def __init__(self, *, config: str = JUNOS_CONFIG, ping_ok: bool = True,
                 refused: tuple[str, ...] = (),
                 pending_failures: int = 0) -> None:
        self.committed = config.splitlines()
        self.initial = list(self.committed)
        self.previous = list(self.committed)
        self.pending = False
        self.ping_ok = ping_ok
        self.refused = set(refused)
        self.pending_failures = pending_failures
        self.calls: list[str] = []
        self.scripts: list[str] = []

    def __call__(self, spec: Any) -> Any:
        from newton_mcp.vendor_change import RunOut

        remote = spec.remote
        script = spec.stdin
        first = script.splitlines()[0].strip() if script else ""
        self.calls.append(remote or first)
        if remote == JUNOS_CONFIG_COMMAND:
            return RunOut(status="ok", stdout="\n".join(self.committed),
                          stderr="", exit_code=0)
        if remote == JUNOS_PENDING_COMMAND:
            return RunOut(status="ok", stdout="\n".join(self._commit_list()),
                          stderr="", exit_code=0)
        if remote == "":
            if first == JUNOS_CONFIG_COMMAND:
                return RunOut(status="ok", stdout=self._read(
                    JUNOS_CONFIG_COMMAND, self.committed), stderr="",
                    exit_code=0)
            if first == JUNOS_PENDING_COMMAND:
                if self.pending_failures > 0:
                    # the commit list could not be read: the device did
                    # not answer the read.
                    self.pending_failures -= 1
                    return RunOut(status="unreachable", stdout="",
                                  stderr="unreachable", exit_code=None)
                return RunOut(status="ok", stdout=self._read(
                    JUNOS_PENDING_COMMAND, self._commit_list()), stderr="",
                    exit_code=0)
            if first.startswith("ping "):
                return RunOut(status="ok", stdout="3 packets received\n",
                              stderr="", exit_code=0)
            self.scripts.append(script)
            return RunOut(status="ok", stdout=self._cli(script), stderr="",
                          exit_code=0)
        if remote.startswith("ping "):
            return RunOut(status="ok", stdout="3 packets received\n", stderr="",
                          exit_code=0)
        raise AssertionError(f"unknown session: {remote!r}")

    def _read(self, command: str, lines: list[str]) -> str:
        """The transcript of a read: the echo of the command and its block."""
        out = [f"{JUNOS_PROMPT}> {command} "]
        out.extend(lines)
        out.append(f"{JUNOS_PROMPT}> exit ")
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
        added = [line for line in candidate if line not in self.committed]
        if not added:
            return []
        out = ["[edit interfaces lo0]"]
        for line in added:
            out.append(f"+    {line.split(' ', 2)[-1]}")
        return out

    def _cli(self, script: str) -> str:
        out: list[str] = []
        mode = "op"
        candidate: list[str] = []
        notice = ""
        for raw in script.splitlines():
            command = raw.strip()
            out.append(f"{JUNOS_PROMPT}{'>' if mode == 'op' else '#'} {command} ")
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
            elif command == JUNOS_CANDIDATE_COMMAND:
                out.extend(candidate)
            elif command == JUNOS_CONFIG_COMMAND:
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


def _junos_lab_toml(tmp_path: Path, *, fast_reset: bool = True) -> Path:
    """The lab file with a Junos device."""
    key = tmp_path / "router-key"
    key.write_text("FAKE-LAB-KEY\n", encoding="utf-8")
    key.chmod(0o600)
    lab_known_hosts = tmp_path / "known-hosts"
    lab_known_hosts.write_text("10.109.0.11 ssh-ed25519 LABBR1\n", encoding="utf-8")
    device_key = tmp_path / "lab-junos-key"
    device_key.write_text("FAKE-JUNOS-KEY\n", encoding="utf-8")
    device_key.chmod(0o600)
    device_known_hosts = tmp_path / "lab-junos-known-hosts"
    device_known_hosts.write_text("10.109.0.41 ssh-ed25519 JUNOSKEY\n",
                                   encoding="utf-8")
    passphrase = tmp_path / "approve.pw"
    passphrase.write_bytes(b"lab-passphrase\n")
    path = tmp_path / "lab.toml"
    path.write_text(
        "[pve]\n"
        'host = "192.0.2.1"\n'
        'node = "test"\n'
        'token_file = "~/.config/pve/apollo.token"\n'
        'pin_file = "~/.config/pve/apollo.pin"\n'
        "\n"
        "[ssh]\n"
        'proxy = "ssh -i /tmp/fake -W %h:%p root@192.0.2.1"\n'
        'password_file = "~/.config/newton/lab-root.pw"\n'
        f'key = "{tmp_path / "lab-key"}"\n'
        f'router_key = "{key}"\n'
        f'approve_passphrase_file = "{passphrase}"\n'
        f'known_hosts = "{lab_known_hosts}"\n'
        "\n"
        "[devices.lab-junos]\n"
        "vmid = 9106\n"
        'host = "10.109.0.41"\n'
        'user = "newton"\n'
        'platform = "junos"\n'
        "vendor_write = true\n"
        'snapshot = "baseline-newton-write"\n'
        'settle_cmd = ""\n'
        f'known_hosts = "{device_known_hosts}"\n'
        f'admin_key = "{device_key}"\n'
        + ("fast_reset = true\n" if fast_reset else ""),
        encoding="utf-8",
    )
    return path


def _junos_shapes_toml(tmp_path: Path, *, baseline: str) -> Path:
    """The shapes file with the junos tables of two shapes."""
    path = tmp_path / "junos-shapes.toml"
    path.write_text(
        "[vars]\n"
        'mgmt_peer = "10.109.0.10"\n'
        "\n"
        "[baseline.junos]\n"
        f'config_hash = "{baseline}"\n'
        "\n"
        "[shapes.01-harmless]\n"
        'id = "01-harmless"\n'
        'description = "The description of the loopback changes."\n'
        'expect = "confirmed"\n'
        "timeout_s = 90\n"
        'explanation = { intent = "Set the description of the loopback.", '
        'steps = ["Set the loopback description."], '
        'risk = "The description of the loopback changes." }\n'
        "\n"
        "[junos.01-harmless]\n"
        'lines = ["set interfaces lo0 description lab-shape-01"]\n'
        'claims = [{ kind = "config_has", '
        'line = "set interfaces lo0 description lab-shape-01" }]\n'
        "\n"
        "[shapes.08-no-approval]\n"
        'id = "08-no-approval"\n'
        'description = "A change nobody approved."\n'
        'expect = "refused_at_apply"\n'
        "approval = false\n"
        'explanation = { intent = "Apply a change nobody approved.", '
        'steps = ["Set the loopback description."], '
        'risk = "Nothing is applied." }\n'
        "\n"
        "[junos.08-no-approval]\n"
        'lines = ["set interfaces lo0 description lab-shape-08"]\n'
        'claims = [{ kind = "config_has", '
        'line = "set interfaces lo0 description lab-shape-08" }]\n',
        encoding="utf-8",
    )
    return path


def _junos_context(tmp_path: Path, lab: Any, *, runner: FakeJunos,
                   fast_reset: bool = False) -> Any:
    """A driver context with a fake Junos behind it."""
    return vl.build_context(
        lab,
        _junos_shapes_toml(tmp_path, baseline=_junos_hash()),
        "junos",
        factory=lambda _target: runner,
        state_dir=tmp_path / "state",
        tunnel_opener=_tunnel_opener([]),
        fast_reset=fast_reset,
    )


def _stub_junos_rollback(monkeypatch: pytest.MonkeyPatch, runner: FakeJunos,
                          rollbacks: list[int]) -> None:
    """The Proxmox stub: the rollback restores the snapshot of the device.

    The rollback of a VM puts it back at the snapshot it was taken from,
    so the fake is at its baseline again and nothing is pending on it.
    """
    def rollback(_lab: Any, _dev: Any) -> str:
        rollbacks.append(1)
        runner.committed = list(runner.initial)
        runner.pending = False
        return "UPID:fake"

    monkeypatch.setattr(nl, "pve_rollback", rollback)
    monkeypatch.setattr(
        nl,
        "pve_wait_task",
        lambda _lab, _upid, timeout_s=120: {"status": "stopped",
                                             "exitstatus": "OK"},
    )


def test_the_shipped_shapes_file_expands_for_junos() -> None:
    """The shipped shapes file carries the eight Junos shapes."""
    shapes = vl.load_shapes(LAB_DIR / "vendor-shapes.toml", "junos")

    assert tuple(sorted(shapes)) == SHAPE_IDS
    assert shapes["01-harmless"].expect == "confirmed"
    assert shapes["02-mgmt-ip"].expect == "rolled_back"
    assert shapes["03-input-drop"].expect == "rolled_back"
    assert shapes["04-injection"].expect == "refused_at_plan"
    assert shapes["04-injection"].sessions == 0
    assert shapes["05-bad-syntax"].expect == "refused_at_plan"
    assert shapes["06-service-reachable"].expect == "refused_at_plan"
    assert shapes["06-service-reachable"].sessions == 0
    assert shapes["07-uplink-down"].expect == "rolled_back"
    assert shapes["08-no-approval"].expect == "refused_at_apply"
    assert shapes["08-no-approval"].approval is False
    for shape in shapes.values():
        assert shape.lines
        assert shape.claims
        assert shape.explanation["intent"]
        assert len(shape.explanation["steps"]) == len(shape.lines)
        # a Junos carries the two vendor claims
        for claim in shape.claims:
            assert claim["kind"] in ("config_has", "ping")


def test_the_shipped_shapes_file_carries_the_junos_baseline() -> None:
    """The baseline table of the Junos is a hash of its own."""
    digest = vl.load_baseline_hash(LAB_DIR / "vendor-shapes.toml", "junos")

    assert len(digest) == 64
    assert all(char in "0123456789abcdef" for char in digest)


def test_the_junos_lines_of_the_shipped_file_are_statements() -> None:
    """Every Junos line of the shipped file is a Junos statement.

    The lines of the two shapes that must be refused are refused by the
    lint of the vendor: a character Junos refuses, a verb it refuses, a
    hierarchy it refuses and the name it reserves for itself.
    """
    from newton_mcp.adapters import junos_write

    shapes = vl.load_shapes(LAB_DIR / "vendor-shapes.toml", "junos")
    refused = ("04-injection", "06-service-reachable")

    for shape in shapes.values():
        if shape.id in refused:
            continue
        statements = junos_write.parse_lines("\n".join(shape.lines))
        assert len(statements) == len(shape.lines), shape.id

    for shape_id in refused:
        shape = shapes[shape_id]
        with pytest.raises(junos_write.LintError):
            junos_write.parse_lines("\n".join(shape.lines))
        assert shape.sessions == 0
        assert shape.expect == "refused_at_plan"


def test_a_shape_without_junos_lines_is_refused(tmp_path: Path) -> None:
    """A shape with no lines for the vendor is refused."""
    path = _junos_shapes_toml(tmp_path, baseline=_junos_hash())
    text = path.read_text(encoding="utf-8")
    start = text.index("[junos.01-harmless]")
    end = text.index("[shapes.08-no-approval]")
    path.write_text(text[:start] + text[end:], encoding="utf-8")

    with pytest.raises(vl.ShapeError, match="lines"):
        vl.load_shapes(path, "junos")


def test_the_driver_reads_the_junos_configuration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    """The driver asks the Junos for its own configuration."""
    monkeypatch.setattr(nl, "pve_rollback", lambda _lab, _dev: "UPID:fake")
    monkeypatch.setattr(
        nl,
        "pve_wait_task",
        lambda _lab, _upid, timeout_s=120: {"status": "stopped",
                                             "exitstatus": "OK"},
    )
    monkeypatch.setattr(vl, "open_tunnel", lambda _lab, _device: FakeTunnel())
    runner = FakeJunos()
    lab_path = _junos_lab_toml(tmp_path)
    shapes = _junos_shapes_toml(tmp_path, baseline=_junos_hash())

    rc = vl.main(
        [
            "--vendor",
            "junos",
            "--shape",
            "01-harmless",
            "--lab",
            str(lab_path),
            "--shapes",
            str(shapes),
            "--state",
            str(tmp_path / "state"),
        ],
        factory=lambda _target: runner,
    )

    out = capsys.readouterr().out
    assert rc == 0, out
    assert "01-harmless" in out
    assert "confirmed" in out
    # the Junos was asked for its own configuration, not for a VyOS one
    assert JUNOS_CONFIG_COMMAND in runner.calls
    assert not any("vyatta" in call for call in runner.calls)


def test_the_fast_reset_is_a_field_of_the_device(
    tmp_path: Path,
) -> None:
    """The fast reset is read from the device table of the lab file.

    The flag is optional: a device that does not name it keeps the
    behaviour it had (the rollback always happens).
    """
    lab_path = _junos_lab_toml(tmp_path)

    assert vl._fast_reset_flag(lab_path, "lab-junos") is True

    plain = _junos_lab_toml(tmp_path, fast_reset=False)
    assert vl._fast_reset_flag(plain, "lab-junos") is False

    # a device that is not in the file has no fast reset
    assert vl._fast_reset_flag(lab_path, "lab-vyos") is False


def test_a_device_at_the_baseline_skips_the_rollback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The fast reset skips the Proxmox rollback.

    The device is at the baseline and nothing is pending on it, so the
    rollback would put it back where it already is: it is skipped.
    """
    lab = nl.load_lab(_junos_lab_toml(tmp_path))
    runner = FakeJunos()
    context = _junos_context(tmp_path, lab, runner=runner, fast_reset=True)
    rollbacks: list[int] = []
    _stub_junos_rollback(monkeypatch, runner, rollbacks)

    try:
        result = vl.run_shape(context, context.shapes["01-harmless"])
    finally:
        context.close()

    assert result.passed is True, result.detail
    assert rollbacks == []


def test_a_device_that_is_not_at_the_baseline_is_rolled_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A device that is not at the baseline is rolled back."""
    lab = nl.load_lab(_junos_lab_toml(tmp_path))
    runner = FakeJunos()
    runner.committed = list(runner.committed) + ["set system host-name other"]
    context = _junos_context(tmp_path, lab, runner=runner, fast_reset=True)
    rollbacks: list[int] = []
    _stub_junos_rollback(monkeypatch, runner, rollbacks)

    try:
        result = vl.run_shape(context, context.shapes["01-harmless"])
    finally:
        context.close()

    assert result.passed is True, result.detail
    assert len(rollbacks) == 1


def test_a_pending_revert_is_rolled_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A device with a revert pending is rolled back.

    The configuration may be the baseline, but a revert that is pending
    would fire later, so the device is rolled back like any other.
    """
    lab = nl.load_lab(_junos_lab_toml(tmp_path))
    runner = FakeJunos()
    runner.pending = True
    context = _junos_context(tmp_path, lab, runner=runner, fast_reset=True)
    rollbacks: list[int] = []
    _stub_junos_rollback(monkeypatch, runner, rollbacks)

    try:
        result = vl.run_shape(context, context.shapes["01-harmless"])
    finally:
        context.close()

    assert len(rollbacks) == 1


def test_a_device_without_the_fast_reset_is_always_rolled_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The VyOS and the CHR keep the rollback they had."""
    lab = nl.load_lab(_junos_lab_toml(tmp_path))
    runner = FakeJunos()
    context = _junos_context(tmp_path, lab, runner=runner, fast_reset=False)
    rollbacks: list[int] = []
    _stub_junos_rollback(monkeypatch, runner, rollbacks)

    try:
        result = vl.run_shape(context, context.shapes["01-harmless"])
    finally:
        context.close()

    assert result.passed is True, result.detail
    assert len(rollbacks) == 1


def test_the_lab_file_carries_the_junos_device() -> None:
    """The Junos is a device of the lab with its own key."""
    lab = nl.load_lab(lab_toml_path())

    device = lab.devices["lab-junos"]
    # the VM id is the lab file's own (the live file holds the real one)
    raw = tomllib.loads(lab_toml_path().read_text(encoding="utf-8"))
    assert device.vmid == int(raw["devices"]["lab-junos"]["vmid"])
    assert device.host == "10.109.0.41"
    assert device.user == "newton"
    assert device.platform == "junos"
    assert device.vendor_write is True
    assert device.snapshot == "baseline-newton-write"
    assert device.known_hosts.endswith("lab-junos/known_hosts")
    assert device.admin_key.endswith("lab-junos/newton")
    # the other vendors keep their own devices
    assert lab.devices["lab-vyos"].platform == "vyos"
    assert lab.devices["lab-chr"].platform == "routeros"


# ---- review fixes ---
#
# MAJOR 2: the fast reset skipped the Proxmox rollback when the device
#     was at the baseline and nothing was pending.  The pending state
#     comes from the commit list of the device, and a commit list that
#     could not be read leaves the driver without that state: only an
#     idle timer may skip the rollback, a state the driver does not know
#     may not skip it.


def test_a_device_whose_pending_read_failed_is_rolled_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A pending read that failed forces the Proxmox rollback.

    The commit list could not be read, so the driver does not know that
    nothing is pending on the device: a revert may be armed.  Only an
    idle timer may skip the rollback.
    """
    lab = nl.load_lab(_junos_lab_toml(tmp_path))
    runner = FakeJunos(pending_failures=1)
    context = _junos_context(tmp_path, lab, runner=runner, fast_reset=True)
    rollbacks: list[int] = []
    _stub_junos_rollback(monkeypatch, runner, rollbacks)

    try:
        result = vl.run_shape(context, context.shapes["01-harmless"])
    finally:
        context.close()

    assert len(rollbacks) == 1
    assert result.passed is True, result.detail
