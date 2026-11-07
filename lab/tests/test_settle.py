"""Settle-gate and run-start reset tests for newton-lab-test.py."""
from __future__ import annotations

from conftest import lab_toml_path

import json
import os
import subprocess
from pathlib import Path
from unittest import mock

import pytest

import newton_lab_test as nl


LAB_TOML = lab_toml_path()


def _cp(stdout: str = "", stderr: str = "", returncode: int = 0):
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr=stderr)


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


def _clock(monkeypatch) -> FakeClock:
    clock = FakeClock()
    monkeypatch.setattr(nl.time, "monotonic", clock.monotonic)
    monkeypatch.setattr(nl.time, "sleep", clock.sleep)
    return clock


def _lab(*, settle_cmd: str = "fingerprint", quiet_s: float = 5,
         timeout_s: float = 30, poll_s: float = 1,
         steps: dict[str, nl.Step] | None = None) -> nl.Lab:
    device = nl.Device(
        name="router", vmid=101, host="192.0.2.1", user="root",
        snapshot="baseline", settle_cmd=settle_cmd)
    return nl.Lab(
        pve_host="pve.test",
        pve_node="node",
        pve_token_file="token",
        pve_pin_file="pin",
        ssh_proxy="none",
        ssh_password_file="password",
        ssh_key="key",
        devices={"router": device},
        var_defs={},
        settle_quiet_s=quiet_s,
        settle_timeout_s=timeout_s,
        settle_poll_s=poll_s,
        steps=steps,
    )


def _scenario(tmp_path: Path, *, setup: list[str] | None = None) -> nl.Scenario:
    return nl.Scenario(
        name="settle-test",
        description="",
        target="router",
        reset=["router"],
        expect="none",
        timeout=60,
        batch="",
        post=[],
        path=tmp_path / "settle-test.toml",
        setup=setup,
    )


def _successful_reset(_lab_obj, dname: str, records: list[dict]) -> dict:
    record = {
        "device": dname,
        "upid": f"UPID:{dname}",
        "task_ok": True,
        "exitstatus": "OK",
        "attempt": 1,
    }
    records.append(record)
    return record


def test_wait_settled_counts_changes_then_waits_full_quiet_period(monkeypatch):
    clock = _clock(monkeypatch)
    lab = _lab(quiet_s=5)
    outputs = ["a\n", "b\n", "c\n", "d\n", "e\n"]
    calls = 0

    def fake_run(args, **_kwargs):
        nonlocal calls
        stdout = outputs[min(calls, len(outputs) - 1)]
        calls += 1
        return _cp(stdout=stdout)

    monkeypatch.setattr(nl, "_run", fake_run)
    record = nl.wait_settled(lab, "router")

    assert record == {
        "device": "router",
        "settled": True,
        "waited_s": 9.0,
        "polls": 10,
        "changes": 4,
        "last_rc": 0,
    }
    assert clock.sleeps == [1] * 9


def test_scenario_waits_through_one_late_change_before_setup(
        monkeypatch, tmp_path):
    """A dnsmasq-like change after three quiet seconds restarts the gate."""
    clock = _clock(monkeypatch)
    setup_times: list[float] = []
    step = nl.Step(name="capture", device="router", cmd="capture-before")
    lab = _lab(quiet_s=5, steps={"capture": step})

    def fake_run(args, **_kwargs):
        cmd = args[-1]
        if cmd == "fingerprint":
            return _cp(stdout="first\n" if clock.now <= 3 else "second\n")
        if cmd == "capture-before":
            setup_times.append(clock.now)
            return _cp()
        raise AssertionError(f"unexpected command: {cmd}")

    monkeypatch.setattr(nl, "_run", fake_run)
    monkeypatch.setattr(nl, "pve_reset", _successful_reset)
    monkeypatch.setattr(nl, "ssh_ready", lambda *_args, **_kwargs: True)

    record = nl.run_scenario(lab, _scenario(tmp_path, setup=["capture"]))

    assert record["passed"] is True
    assert record["settle"][0]["changes"] == 1
    assert record["settle"][0]["waited_s"] == 9.0
    assert setup_times == [9.0]


def test_wait_settled_times_out_when_command_keeps_failing(monkeypatch):
    _clock(monkeypatch)
    lab = _lab(timeout_s=5)
    monkeypatch.setattr(
        nl, "_run", lambda *_args, **_kwargs: _cp(
            stdout="not ready\n", returncode=1))

    record = nl.wait_settled(lab, "router")

    assert record["settled"] is False
    assert record["waited_s"] == 5.0
    assert record["polls"] == 6
    assert record["changes"] == 0
    assert record["last_rc"] == 1


def test_wait_settled_without_command_returns_without_ssh(monkeypatch):
    clock = _clock(monkeypatch)
    lab = _lab(settle_cmd="")

    def no_run(*_args, **_kwargs):
        raise AssertionError("no SSH call expected")

    monkeypatch.setattr(nl, "_run", no_run)
    record = nl.wait_settled(lab, "router")

    assert record == {
        "device": "router",
        "settled": None,
        "waited_s": 0.0,
        "polls": 0,
        "changes": 0,
        "last_rc": None,
    }
    assert clock.now == 0


def test_scenario_never_settles_and_runs_no_setup(monkeypatch, tmp_path):
    _clock(monkeypatch)
    setup_calls: list[str] = []
    step = nl.Step(name="capture", device="router", cmd="capture-before")
    lab = _lab(timeout_s=3, steps={"capture": step})

    def fake_run(args, **_kwargs):
        if args[-1] == "fingerprint":
            return _cp(returncode=1)
        setup_calls.append(args[-1])
        return _cp()

    monkeypatch.setattr(nl, "_run", fake_run)
    monkeypatch.setattr(nl, "pve_reset", _successful_reset)
    monkeypatch.setattr(nl, "ssh_ready", lambda *_args, **_kwargs: True)

    record = nl.run_scenario(lab, _scenario(tmp_path, setup=["capture"]))

    assert record["error"] == (
        "router did not settle within 3s (changes=0, last_rc=1)")
    assert record["settle"][0]["settled"] is False
    assert record["setup"] == []
    assert setup_calls == []


def test_scenario_records_settle_before_running_setup(monkeypatch, tmp_path):
    clock = _clock(monkeypatch)
    events: list[tuple[str, float]] = []
    step = nl.Step(name="capture", device="router", cmd="capture-before")
    lab = _lab(quiet_s=2, steps={"capture": step})

    def fake_run(args, **_kwargs):
        if args[-1] == "fingerprint":
            events.append(("settle", clock.now))
            return _cp(stdout="stable\n")
        events.append(("setup", clock.now))
        return _cp()

    monkeypatch.setattr(nl, "_run", fake_run)
    monkeypatch.setattr(nl, "pve_reset", _successful_reset)
    monkeypatch.setattr(nl, "ssh_ready", lambda *_args, **_kwargs: True)

    record = nl.run_scenario(lab, _scenario(tmp_path, setup=["capture"]))

    assert record["settle"] == [{
        "device": "router",
        "settled": True,
        "waited_s": 2.0,
        "polls": 3,
        "changes": 0,
        "last_rc": 0,
    }]
    assert events[-1] == ("setup", 2.0)
    assert record["setup"][0]["passed"] is True


def _write_cli_fixture(tmp_path: Path, *,
                      scenarios: dict[str, str | None] | None = None
                      ) -> tuple[Path, Path]:
    lab_toml = tmp_path / "lab.toml"
    lab_toml.write_text("""
[pve]
host = "pve.test"
node = "node"
token_file = "token"
pin_file = "pin"

[ssh]
proxy = "none"
password_file = "password"
key = "key"

[settle]
quiet_s = 10
timeout_s = 120
poll_s = 1

[devices.lab-isp]
vmid = 9101
host = "10.0.0.1"
user = "root"
snapshot = "baseline"
settle_cmd = "isp-fingerprint"

[devices.lab-r1]
vmid = 9102
host = "10.0.0.2"
user = "root"
snapshot = "baseline"
settle_cmd = "r1-fingerprint"

[devices.lab-client]
vmid = 9105
host = "10.0.0.3"
user = "user"
snapshot = "baseline"
settle_cmd = "client-fingerprint"

[vars]
""")
    scenario_dir = tmp_path / "scenarios"
    scenario_dir.mkdir()
    # `scenarios` maps a scenario name to the access mode it declares
    # (None: the key is absent, so the mode is the default, installed).
    for name, access in (scenarios or {"01-a": None}).items():
        body = (f'name = "{name}"\n'
                'description = "audit"\n'
                'target = "lab-r1"\n'
                'reset = []\n'
                'expect = "none"\n'
                'timeout = 60\n'
                'batch = ""\n')
        if access is not None:
            body += f'access = "{access}"\n'
        (scenario_dir / f"{name}.toml").write_text(body)
    return lab_toml, scenario_dir


def _scenario_result(scenario: nl.Scenario) -> dict:
    return {
        "name": scenario.name,
        "expected": scenario.expect,
        "access": scenario.access,
        "outcome": "none",
        "passed": True,
        "error": None,
        "duration_s": 0.0,
        "after": [],
        "post": [],
        "reject": None,
    }


def test_main_resets_and_settles_all_devices_before_first_scenario(
        monkeypatch, tmp_path, capsys):
    lab_toml, scenario_dir = _write_cli_fixture(tmp_path)
    results_path = tmp_path / "run.json"
    events: list[tuple[str, str]] = []

    def fake_reset(_lab_obj, dname: str, records: list[dict]) -> dict:
        events.append(("reset", dname))
        return _successful_reset(_lab_obj, dname, records)

    def fake_ssh(_lab_obj, device, timeout_s=120):
        events.append(("ssh", device.name))
        return True

    def fake_settle(_lab_obj, dname: str):
        events.append(("settle", dname))
        return {
            "device": dname, "settled": True, "waited_s": 12.0,
            "polls": 13, "changes": 1, "last_rc": 0,
        }

    def fake_scenario(_lab_obj, scenario, *args, **kwargs):
        events.append(("scenario", scenario.name))
        return _scenario_result(scenario)

    monkeypatch.setattr(nl, "RESULTS_DIR", tmp_path / "internal-results")
    monkeypatch.setattr(nl, "pve_reset", fake_reset)
    monkeypatch.setattr(nl, "ssh_ready", fake_ssh)
    monkeypatch.setattr(nl, "wait_settled", fake_settle)
    monkeypatch.setattr(nl, "run_scenario", fake_scenario)

    rc = nl.main([
        "--lane", "password",
        "--lab", str(lab_toml),
        "--scenarios", str(scenario_dir),
        "--results", str(results_path),
    ])

    assert rc == 0
    assert events == [
        ("reset", "lab-isp"), ("ssh", "lab-isp"),
        ("settle", "lab-isp"),
        ("reset", "lab-r1"), ("ssh", "lab-r1"),
        ("settle", "lab-r1"),
        ("reset", "lab-client"), ("ssh", "lab-client"),
        ("settle", "lab-client"),
        ("scenario", "01-a"),
    ]
    stdout = capsys.readouterr().out
    for name in ("lab-isp", "lab-r1", "lab-client"):
        assert f"lab-reset {name} ok settled_in=12.0s changes=1" in stdout

    assert set(json.loads(results_path.read_text())) == {
        "timestamp", "summary", "devices", "access", "scenarios"}
    reset_path = tmp_path / "run-lab-reset.json"
    payload = json.loads(reset_path.read_text())
    assert [item["device"] for item in payload["devices"]] == [
        "lab-isp", "lab-r1", "lab-client"]
    assert all(item["settle"]["settled"] for item in payload["devices"])
    assert all(item["reset"][0]["task_ok"] for item in payload["devices"])


def test_main_no_lab_reset_skips_run_start_reset(monkeypatch, tmp_path):
    lab_toml, scenario_dir = _write_cli_fixture(tmp_path)
    scenario_calls: list[str] = []

    def no_reset(*_args, **_kwargs):
        raise AssertionError("run-start reset must be skipped")

    def fake_scenario(_lab_obj, scenario, *args, **kwargs):
        scenario_calls.append(scenario.name)
        return _scenario_result(scenario)

    monkeypatch.setattr(nl, "RESULTS_DIR", tmp_path / "internal-results")
    monkeypatch.setattr(nl, "pve_reset", no_reset)
    monkeypatch.setattr(nl, "run_scenario", fake_scenario)
    results_path = tmp_path / "quick.json"

    rc = nl.main([
        "--lane", "password",
        "--lab", str(lab_toml),
        "--scenarios", str(scenario_dir),
        "--results", str(results_path),
        "--no-lab-reset",
    ])

    assert rc == 0
    assert scenario_calls == ["01-a"]
    assert not (tmp_path / "quick-lab-reset.json").exists()


def test_main_list_never_resets(monkeypatch, tmp_path, capsys):
    lab_toml, scenario_dir = _write_cli_fixture(tmp_path)

    def no_reset(*_args, **_kwargs):
        raise AssertionError("--list must not reset")

    monkeypatch.setattr(nl, "pve_reset", no_reset)
    rc = nl.main([
        "--lane", "password",
        "--lab", str(lab_toml),
        "--scenarios", str(scenario_dir),
        "--list",
    ])

    assert rc == 0
    assert "01-a [none]: audit" in capsys.readouterr().out


def test_main_failed_run_start_reset_exits_2_without_scenario(
        monkeypatch, tmp_path, capsys):
    lab_toml, scenario_dir = _write_cli_fixture(tmp_path)
    results_path = tmp_path / "failed.json"
    scenario_calls: list[str] = []

    def failed_reset(_lab_obj, dname: str, records: list[dict]) -> dict:
        record = {
            "device": dname, "upid": "UPID:bad", "task_ok": False,
            "exitstatus": "TASK ERROR", "attempt": 1,
        }
        records.append(record)
        return record

    monkeypatch.setattr(nl, "RESULTS_DIR", tmp_path / "internal-results")
    monkeypatch.setattr(nl, "pve_reset", failed_reset)
    monkeypatch.setattr(
        nl, "run_scenario",
        lambda _lab_obj, scenario, *args, **kwargs:
            scenario_calls.append(scenario.name))

    rc = nl.main([
        "--lane", "password",
        "--lab", str(lab_toml),
        "--scenarios", str(scenario_dir),
        "--results", str(results_path),
    ])

    assert rc == 2
    assert scenario_calls == []
    assert "lab-reset lab-isp reset failed" in capsys.readouterr().err
    assert not results_path.exists()
    payload = json.loads((tmp_path / "failed-lab-reset.json").read_text())
    assert payload["devices"][0]["reset"][0]["task_ok"] is False


@pytest.mark.parametrize(
    ("results_name", "expected_name"),
    [("out.json", "out-lab-reset.json"),
     ("out.data", "out.data-lab-reset.json")],
)
def test_lab_reset_path_name(results_name, expected_name, tmp_path):
    assert nl._lab_reset_path(tmp_path / results_name) == tmp_path / expected_name


def test_real_lab_loads_settle_configuration():
    lab = nl.load_lab(LAB_TOML)
    router_cmd = (
        "{ ubus call service list; ubus call network.interface dump | "
        "jsonfilter -e '@.interface[*].interface' "
        "-e '@.interface[*].up'; } | md5sum")

    assert (lab.settle_quiet_s, lab.settle_timeout_s, lab.settle_poll_s) == (
        10, 120, 1)
    assert lab.devices["lab-isp"].settle_cmd == router_cmd
    assert lab.devices["lab-r1"].settle_cmd == router_cmd
    assert lab.devices["lab-client"].settle_cmd == (
        'systemctl is-system-running && '
        '[ "$(systemctl list-jobs --no-legend | wc -l)" = 0 ] && echo idle')


def test_missing_settle_configuration_uses_defaults(tmp_path):
    path = tmp_path / "lab.toml"
    path.write_text("""
[pve]
host = "pve"
node = "node"
token_file = "token"
pin_file = "pin"
[ssh]
proxy = "none"
password_file = "password"
key = "key"
[devices.router]
vmid = 1
host = "192.0.2.1"
user = "root"
snapshot = "baseline"
""")

    lab = nl.load_lab(path)

    assert (lab.settle_quiet_s, lab.settle_timeout_s, lab.settle_poll_s) == (
        10, 120, 1)
    assert lab.devices["router"].settle_cmd == ""


def _access_run(monkeypatch, tmp_path, inventory_body, *,
                scenarios: dict[str, str | None] | None = None,
                body=None):
    """A runner run against the inventory the operator's Newton reads.

    The scenarios run `body` instead of their own: the runner's own
    run_scenario is real, only the body of the scenario is replaced.
    The default body touches no transport at all, so the run measures
    nothing.

    Returns (rc, results path): the run may be refused, and a refused
    run writes no results file at all."""
    lab_toml, scenario_dir = _write_cli_fixture(tmp_path, scenarios=scenarios)
    inventory = tmp_path / "devices.toml"
    inventory.write_text(inventory_body)
    monkeypatch.setenv("NEWTON_INVENTORY", str(inventory))
    results_path = tmp_path / "run.json"
    monkeypatch.setattr(nl, "RESULTS_DIR", tmp_path / "internal-results")
    monkeypatch.setattr(nl, "pve_reset", lambda *_a, **_k: {"task_ok": True})
    monkeypatch.setattr(nl, "ssh_ready", lambda *_a, **_k: True)
    monkeypatch.setattr(nl, "wait_settled", lambda *_a, **_k: {
        "device": "lab-r1", "settled": True, "waited_s": 1.0, "polls": 1,
        "changes": 0, "last_rc": 0})
    monkeypatch.setattr(nl, "_run_scenario_inner",
                        lambda lab, scen, rec, t0, state, **kw:
                        (body or _body_nothing)(lab, scen, rec))
    rc = nl.main([
        "--lane", "password",
        "--lab", str(lab_toml),
        "--scenarios", str(scenario_dir),
        "--results", str(results_path),
    ])
    return rc, results_path


def _body_nothing(lab, scen, rec):
    """A body that touches no transport at all."""
    rec["outcome"] = "none"
    rec["passed"] = True


def _body_installed(lab, scen, rec):
    """A body that runs the installed SSH change path (plan_batch)."""
    with mock.patch.object(nl, "_run",
                           side_effect=lambda *a, **k: _cp(stdout="")):
        nl.plan_batch(lab, lab.devices[scen.target], "set foo=bar")
    rec["outcome"] = "none"
    rec["passed"] = True


def _body_rpcd(lab, scen, rec):
    """A body that runs the no-install transport: the MCP writes its
    receipt line into the file the runner handed it (the same line the
    one HTTPS choke point writes)."""
    path = os.environ[nl.RECEIPT_ENV]
    with open(path, "a", encoding="utf-8") as handle:
        handle.write("rpcd uci.set\n")
    rec["outcome"] = "none"
    rec["passed"] = True


def _body_both(lab, scen, rec):
    """A body that runs both transports."""
    _body_installed(lab, scen, rec)
    _body_rpcd(lab, scen, rec)


def test_an_installed_scenario_against_a_no_install_inventory_is_refused(
        monkeypatch, tmp_path, capsys):
    """The mode of a run is what its scenarios exercised (review's new
    defect 1): an installed scenario against a device the inventory
    says is a no-install one is refused, not labelled no-install."""
    rc, results_path = _access_run(
        monkeypatch, tmp_path,
        '[devices.lab-r1]\nplatform = "openwrt"\nhost = "10.0.0.2"\n'
        'user = "root"\naccess = "no-install"\n')
    assert rc == 2
    assert not results_path.exists()
    err = capsys.readouterr().err
    assert "installed" in err, err
    assert "no-install" in err, err


def test_a_mixed_run_is_refused(monkeypatch, tmp_path, capsys):
    """A run whose scenarios declare different modes has no mode at
    all: it is refused, not labelled with one of them."""
    rc, results_path = _access_run(
        monkeypatch, tmp_path,
        '[devices.lab-r1]\nplatform = "openwrt"\nhost = "10.0.0.2"\n'
        'user = "root"\naccess = "installed"\n',
        scenarios={"01-a": None, "02-b": "no-install"})
    assert rc == 2
    assert not results_path.exists()
    err = capsys.readouterr().err
    assert "mixes the access modes" in err, err


def test_a_no_install_scenario_against_a_no_install_inventory_runs(
        monkeypatch, tmp_path):
    """The declaration and the inventory agree: the run is not refused
    and the record keeps what the scenario said."""
    rc, results_path = _access_run(
        monkeypatch, tmp_path,
        '[devices.lab-r1]\nplatform = "openwrt"\nhost = "10.0.0.2"\n'
        'user = "root"\naccess = "no-install"\n',
        scenarios={"01-a": "no-install"})
    assert rc == 0
    payload = json.loads(results_path.read_text())
    assert [s["declared_access"] for s in payload["scenarios"]] == ["no-install"]


def test_an_installed_scenario_against_an_installed_inventory_runs(
        monkeypatch, tmp_path):
    """The installed mode is the default of a scenario: the run says
    so, and the scenario records carry the declaration."""
    rc, results_path = _access_run(
        monkeypatch, tmp_path,
        '[devices.lab-r1]\nplatform = "openwrt"\nhost = "10.0.0.2"\n'
        'user = "root"\naccess = "installed"\n')
    assert rc == 0
    payload = json.loads(results_path.read_text())
    assert [s["declared_access"] for s in payload["scenarios"]] == ["installed"]


def test_a_device_the_inventory_says_nothing_about_is_not_refused(
        monkeypatch, tmp_path):
    """The inventory has no opinion about a device that is not in it:
    the scenario's own declaration stands."""
    rc, results_path = _access_run(
        monkeypatch, tmp_path,
        '[devices.other]\nplatform = "openwrt"\nhost = "10.0.0.9"\n'
        'user = "root"\naccess = "no-install"\n',
        scenarios={"01-a": "no-install"})
    assert rc == 0
    payload = json.loads(results_path.read_text())
    assert [s["declared_access"] for s in payload["scenarios"]] == ["no-install"]


def test_the_installed_receipt_labels_the_run_installed(
        monkeypatch, tmp_path):
    """The runner drove the installed SSH change path: the run carries
    the installed mode, and the fact is in the results."""
    rc, results_path = _access_run(
        monkeypatch, tmp_path,
        '[devices.lab-r1]\nplatform = "openwrt"\nhost = "10.0.0.2"\n'
        'user = "root"\naccess = "installed"\n',
        body=_body_installed)
    assert rc == 0
    payload = json.loads(results_path.read_text())
    assert payload["access"] == "installed"
    assert payload["devices"] == [{"name": "lab-r1", "access": "installed"}]
    assert [s["access"] for s in payload["scenarios"]] == ["installed"]


def test_the_rpcd_receipt_labels_the_run_no_install(monkeypatch, tmp_path):
    """The no-install transport wrote its receipt: the run carries the
    no-install mode, and the fact is in the results."""
    rc, results_path = _access_run(
        monkeypatch, tmp_path,
        '[devices.lab-r1]\nplatform = "openwrt"\nhost = "10.0.0.2"\n'
        'user = "root"\naccess = "no-install"\n',
        scenarios={"01-a": "no-install"},
        body=_body_rpcd)
    assert rc == 0
    payload = json.loads(results_path.read_text())
    assert payload["access"] == "no-install"
    assert payload["devices"] == [{"name": "lab-r1", "access": "no-install"}]
    assert [s["access"] for s in payload["scenarios"]] == ["no-install"]


def test_a_no_install_declaration_without_a_receipt_carries_no_access_fact(
        monkeypatch, tmp_path):
    """The declaration alone labels nothing: a scenario that says
    no-install but exercised no transport carries no fact, so a run is
    never labelled with a mode it never used.  The label comes from the
    receipt, not from what the scenario said."""
    rc, results_path = _access_run(
        monkeypatch, tmp_path,
        '[devices.lab-r1]\nplatform = "openwrt"\nhost = "10.0.0.2"\n'
        'user = "root"\naccess = "no-install"\n',
        scenarios={"01-a": "no-install"})
    assert rc == 0
    payload = json.loads(results_path.read_text())
    assert payload["access"] is None
    assert [s["access"] for s in payload["scenarios"]] == [None]


def test_a_scenario_that_used_no_transport_carries_no_access_fact(
        monkeypatch, tmp_path):
    """Neither transport ran: the scenario carries no access fact, and
    so has the run.  A run that measured nothing cannot back a label."""
    rc, results_path = _access_run(
        monkeypatch, tmp_path,
        '[devices.lab-r1]\nplatform = "openwrt"\nhost = "10.0.0.2"\n'
        'user = "root"\naccess = "installed"\n')
    assert rc == 0
    payload = json.loads(results_path.read_text())
    assert payload["access"] is None
    assert [s["access"] for s in payload["scenarios"]] == [None]


def test_a_no_install_declaration_against_the_installed_path_is_refused(
        monkeypatch, tmp_path, capsys):
    """A scenario that declares no-install and runs the installed SSH
    path is refused: the declaration is not the fact."""
    rc, results_path = _access_run(
        monkeypatch, tmp_path,
        '[devices.lab-r1]\nplatform = "openwrt"\nhost = "10.0.0.2"\n'
        'user = "root"\naccess = "no-install"\n',
        scenarios={"01-a": "no-install"},
        body=_body_installed)
    assert rc == 2
    assert not results_path.exists()
    err = capsys.readouterr().err
    assert "no-install" in err, err
    assert "installed" in err, err


def test_an_installed_declaration_against_the_rpcd_transport_is_refused(
        monkeypatch, tmp_path, capsys):
    """A scenario that declares the installed mode and runs the rpcd
    transport is refused too."""
    rc, results_path = _access_run(
        monkeypatch, tmp_path,
        '[devices.lab-r1]\nplatform = "openwrt"\nhost = "10.0.0.2"\n'
        'user = "root"\naccess = "installed"\n',
        body=_body_rpcd)
    assert rc == 2
    assert not results_path.exists()
    err = capsys.readouterr().err
    assert "installed" in err, err
    assert "no-install" in err, err


def test_a_scenario_that_used_both_transports_is_refused(
        monkeypatch, tmp_path, capsys):
    """Both receipts in one scenario: the run has no mode to label it
    with, so it is refused."""
    rc, results_path = _access_run(
        monkeypatch, tmp_path,
        '[devices.lab-r1]\nplatform = "openwrt"\nhost = "10.0.0.2"\n'
        'user = "root"\naccess = "installed"\n',
        body=_body_both)
    assert rc == 2
    assert not results_path.exists()
    err = capsys.readouterr().err
    assert "both transports" in err, err


def test_the_runner_hands_every_scenario_the_receipt_file(
        monkeypatch, tmp_path):
    """The receipt file is exported to the scenario's commands, so the
    transport a scenario runs finds it."""
    seen = {}

    def body(lab, scen, rec):
        seen["path"] = os.environ.get(nl.RECEIPT_ENV)
        rec["outcome"] = "none"
        rec["passed"] = True

    rc, _results_path = _access_run(
        monkeypatch, tmp_path,
        '[devices.lab-r1]\nplatform = "openwrt"\nhost = "10.0.0.2"\n'
        'user = "root"\naccess = "installed"\n',
        body=body)
    assert rc == 0
    assert seen["path"], "the runner must export the receipt file"
    assert Path(seen["path"]).parent != tmp_path


def test_the_receipt_file_is_gone_when_the_run_is_over(
        monkeypatch, tmp_path):
    """The receipt file lives in the run's own temp directory, and the
    directory goes away with the run."""
    seen = {}

    def body(lab, scen, rec):
        seen["path"] = os.environ[nl.RECEIPT_ENV]
        rec["outcome"] = "none"
        rec["passed"] = True

    rc, _results_path = _access_run(
        monkeypatch, tmp_path,
        '[devices.lab-r1]\nplatform = "openwrt"\nhost = "10.0.0.2"\n'
        'user = "root"\naccess = "installed"\n',
        body=body)
    assert rc == 0
    assert not Path(seen["path"]).exists()
    assert not Path(seen["path"]).parent.exists()


def test_the_receipt_variable_is_not_left_behind(monkeypatch, tmp_path):
    """The runner exports the variable for the run and takes it back
    when the run is over."""
    monkeypatch.delenv(nl.RECEIPT_ENV, raising=False)

    def body(lab, scen, rec):
        assert os.environ.get(nl.RECEIPT_ENV)
        rec["outcome"] = "none"
        rec["passed"] = True

    rc, _results_path = _access_run(
        monkeypatch, tmp_path,
        '[devices.lab-r1]\nplatform = "openwrt"\nhost = "10.0.0.2"\n'
        'user = "root"\naccess = "installed"\n',
        body=body)
    assert rc == 0
    assert nl.RECEIPT_ENV not in os.environ


def test_a_scenario_may_declare_its_access_mode(tmp_path):
    """The access key of a scenario is read, and it defaults to the
    installed mode."""
    path = tmp_path / "01-x.toml"
    path.write_text('name = "01-x"\ntarget = "lab-r1"\nexpect = "none"\n'
                    'access = "no-install"\n')
    assert nl.load_scenarios(tmp_path)[0].access == "no-install"
    path.write_text('name = "01-x"\ntarget = "lab-r1"\nexpect = "none"\n')
    assert nl.load_scenarios(tmp_path)[0].access == "installed"


def test_an_unknown_access_mode_is_refused(monkeypatch, tmp_path, capsys):
    """A scenario that declares a mode Newton does not have is
    refused before anything is touched."""
    lab_toml, scenario_dir = _write_cli_fixture(
        tmp_path, scenarios={"01-a": "telepathy"})
    rc = nl.main([
        "--lane", "password",
        "--lab", str(lab_toml),
        "--scenarios", str(scenario_dir),
        "--results", str(tmp_path / "run.json"),
    ])
    assert rc == 2
    err = capsys.readouterr().err
    assert "access" in err, err
