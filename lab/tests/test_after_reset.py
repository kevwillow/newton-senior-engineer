"""Feature B: the scenario field `after_reset = ["check", ...]`.

A scenario's `regression` checks run as its BEFORE probes and its AFTER probes,
both before `reset_after`, so nothing proved the radios were off once
`reset_after` had restored the device. `after_reset` names `[checks]` the
runner runs, in the declared order, straight after the `reset_after` resets
finish OK. A check that fails fails the scenario, without hiding an earlier
error. Everything here runs against fakes: no Proxmox, no router ssh.
"""
from __future__ import annotations

import subprocess
from unittest import mock

import pytest

import newton_lab_test as nl


def _cp(stdout: str = "", stderr: str = "", returncode: int = 0):
    return subprocess.CompletedProcess(args=[], returncode=returncode,
                                       stdout=stdout, stderr=stderr)


_LAB_TOML = """
[pve]
host = "pve.test"
node = "lab"
token_file = "~/.config/pve/token"
pin_file = "~/.config/pve/pin"

[ssh]
proxy = "ssh -W %h:%p root@pve.test"
password_file = "~/.config/newton/lab-root.pw"
key = "~/.ssh/key"

[devices.lab-r1]
vmid = 9102
host = "10.109.0.11"
user = "root"
snapshot = "baseline"

[devices.lab-client]
vmid = 9105
host = "10.109.0.12"
user = "root"
snapshot = "baseline"

[vars.bssid]
device = "local"
cmd = "cat /sys/class/ieee80211/phy1/macaddress"

[vars.psk]
device = "local"
cmd = "printf a-real-looking-key"
secret = true

[checks.radios_off_ok]
device = "lab-r1"
cmd = "radio-off"
description = "the radios are off"

[checks.radios_off_ok2]
device = "lab-r1"
cmd = "radio-off-twice"
description = "the radios are still off"

[checks.radios_off_bssid]
device = "lab-r1"
cmd = "radio-off {bssid}"
description = "the radios are off, pinned to a BSSID"

[checks.radios_off_bad]
device = "lab-r1"
cmd = "radio-still-on"
description = "the radios are still on"

[checks.psk_echo]
device = "lab-r1"
cmd = "grep -c -F {psk}"
description = "a check that names the secret var"

[checks.never_ok]
device = "lab-r1"
cmd = "never-ok"
description = "always fails"

[steps.mark]
device = "lab-r1"
cmd = "true"
description = "no-op marker step"

[steps.psk_step]
device = "lab-r1"
cmd = "printf %s {psk}"
description = "a step that names the secret var"
"""


@pytest.fixture
def lab_path(tmp_path):
    path = tmp_path / "lab.toml"
    path.write_text(_LAB_TOML)
    return path


@pytest.fixture
def lab(lab_path):
    return nl.load_lab(lab_path)


def _scenario(tmp_path, body: str, name: str = "01-x"):
    d = tmp_path / "scenarios"
    d.mkdir(exist_ok=True)
    (d / f"{name}.toml").write_text(body)
    return nl.load_scenarios(d)[0]


def _fake_reset(order: list[str], *, ok: bool = True,
                fails: set[str] | None = None):
    """A reset_device() stand-in that records the call order and appends a
    record shaped like pve_reset's. `fails` names the devices whose reset does
    not finish OK."""
    fails = fails or set()

    def reset_device(lab, dname, records):
        order.append(f"reset:{dname}")
        good = ok and dname not in fails
        rec = {"device": dname, "upid": "UPID:fake",
               "task_ok": good, "exitstatus": "OK" if good else "boom",
               "attempt": 1}
        records.append(rec)
        return rec
    return reset_device


def _fake_post(order: list[str], *, failing: set[str] | None = None):
    """A run_post stand-in for both the scenario's [[post]] and its check
    probes. `failing` names the cmds that fail; every other one passes."""
    failing = failing or set()

    def run_post(lab, p):
        order.append(f"run_post:{p.cmd}")
        ok = p.cmd not in failing
        return {"device": p.device, "cmd": p.cmd, "expect_rc": p.expect_rc,
                "expect_stdout": p.expect_stdout,
                "rc": 0 if ok else 1, "stdout": "", "stderr": "",
                "passed": ok, "reason": "" if ok else "rc 1 != 0"}
    return run_post


def _fake_step(order: list[str], *, rc: int = 0):
    def run_step(lab, step, values):
        order.append(f"step:{step.name}")
        return rc, "true", ""
    return run_step


def _settled(lab, dname):
    return {"device": dname, "settled": True, "waited_s": 1.0, "polls": 1,
            "changes": 0, "last_rc": 0}


def _var_run(value: str = "aa:bb:cc:dd:ee:ff"):
    """A _run stand-in that answers a local [vars] cmd with `value` and any
    other command with an empty success."""
    def run(args, **kwargs):
        if len(args) > 2 and args[0] == "bash" and args[1] == "-c":
            return _cp(stdout=value)
        return _cp()
    return run


def _with_extra(body: str, extra: str) -> str:
    """Insert top-level `extra` lines before the first table of `body`: a key
    appended after [[post]] would belong to that table, not the scenario."""
    return body.replace("[[post]]", extra + "\n[[post]]")


AUDIT_BODY = """
name = "01-x"
description = "audit scenario with an after_reset check"
target = "lab-r1"
reset = ["lab-r1"]
reset_after = ["lab-client"]
after_reset = ["radios_off_ok"]
expect = "none"
timeout = 60
batch = ""

[[post]]
device = "lab-r1"
cmd = "uptime"
"""


@pytest.fixture
def wired(monkeypatch):
    """No device contact: reset_device, run_post and run_step are recorders and
    ssh_ready / wait_settled say the device came back."""
    order: list[str] = []
    monkeypatch.setattr(nl, "ssh_ready", lambda *a, **k: True)
    monkeypatch.setattr(nl, "wait_settled", _settled)
    monkeypatch.setattr(nl, "run_post", _fake_post(order))
    monkeypatch.setattr(nl, "run_step", _fake_step(order))
    return order


def _fake_reset_after(order: list[str], *, ok: bool = True):
    """The same recorder, naming the phase: lab-r1 is the start-of-scenario
    reset and lab-client the reset_after one, so the call order says which
    side of the reset_after a check ran on."""
    def reset_device(lab, dname, records):
        phase = "reset_after" if dname == "lab-client" else "reset"
        order.append(f"{phase}:{dname}")
        rec = {"device": dname, "upid": "UPID:fake",
               "task_ok": ok, "exitstatus": "OK" if ok else "boom",
               "attempt": 1}
        records.append(rec)
        return rec
    return reset_device


# ---------- loading and validation ----------

def test_after_reset_field_parses(lab, tmp_path):
    scen = _scenario(tmp_path, AUDIT_BODY)
    assert scen.after_reset == ["radios_off_ok"]


def test_after_reset_absent_parses_as_empty(lab, tmp_path):
    scen = _scenario(tmp_path, AUDIT_BODY.replace(
        'after_reset = ["radios_off_ok"]\n', ""))
    assert scen.after_reset == []


def test_after_reset_keeps_the_declared_order(lab, tmp_path):
    scen = _scenario(tmp_path, AUDIT_BODY.replace(
        'after_reset = ["radios_off_ok"]',
        'after_reset = ["radios_off_ok2", "radios_off_ok", "radios_off_ok2"]'))
    assert scen.after_reset == ["radios_off_ok2", "radios_off_ok",
                                "radios_off_ok2"]


def test_validate_unknown_after_reset_check_is_error(lab, tmp_path):
    scen = _scenario(tmp_path, AUDIT_BODY.replace(
        'after_reset = ["radios_off_ok"]', 'after_reset = ["no_such_check"]'))
    errs = nl.validate_scenarios(lab, [scen])
    assert any("no_such_check" in e and "after_reset" in e for e in errs)


def test_after_reset_without_reset_after_is_an_error(lab, tmp_path):
    """A check that runs after the reset is meaningless without one: loading
    the scenario is where that is caught."""
    scen = _scenario(tmp_path, AUDIT_BODY.replace(
        'reset_after = ["lab-client"]\n', ""))
    errs = nl.validate_scenarios(lab, [scen])
    assert any("after_reset" in e and "reset_after" in e for e in errs)


def test_main_refuses_after_reset_without_reset_after_before_any_device_contact(
        lab_path, tmp_path, capsys):
    d = tmp_path / "scenarios"
    d.mkdir()
    (d / "01-x.toml").write_text(AUDIT_BODY.replace(
        'reset_after = ["lab-client"]\n', ""))
    with mock.patch.object(nl, "_run",
                           side_effect=AssertionError("device contact")):
        rc = nl.main(["--lab", str(lab_path), "--scenarios", str(d),
                      "--lane", "password"])
    assert rc == 2
    assert "after_reset" in capsys.readouterr().err


def test_validate_valid_after_reset_is_silent(lab, tmp_path):
    scen = _scenario(tmp_path, AUDIT_BODY)
    assert nl.validate_scenarios(lab, [scen]) == []


def test_an_after_reset_check_naming_a_secret_var_is_refused(lab, tmp_path):
    """A secret var may only travel in the batch; an after_reset check cmd is
    an ssh argv like any other."""
    scen = _scenario(tmp_path, AUDIT_BODY.replace(
        'after_reset = ["radios_off_ok"]', 'after_reset = ["psk_echo"]'))
    errs = nl.validate_scenarios(lab, [scen])
    assert any("psk" in e and "after_reset" in e for e in errs)


# ---------- running them ----------

def test_after_reset_checks_run_after_the_reset(lab, tmp_path, wired,
                                               monkeypatch):
    scen = _scenario(tmp_path, AUDIT_BODY.replace(
        'after_reset = ["radios_off_ok"]',
        'after_reset = ["radios_off_ok2", "radios_off_ok"]'))
    monkeypatch.setattr(nl, "reset_device", _fake_reset_after(wired))
    with mock.patch.object(nl, "_run", return_value=_cp()):
        rec = nl.run_scenario(lab, scen)
    assert wired == ["reset:lab-r1", "run_post:uptime",
                     "reset_after:lab-client",
                     "run_post:radio-off-twice", "run_post:radio-off"]
    assert [e["name"] for e in rec["after_reset"]] == [
        "radios_off_ok2", "radios_off_ok"]
    assert all(e["role"] == "after_reset" and e["ok"] for e in
               rec["after_reset"])
    assert rec["passed"] is True
    assert rec["error"] is None


def test_after_reset_record_is_empty_without_the_field(lab, tmp_path, wired,
                                                       monkeypatch):
    """Absent field: the record is there and empty, and nothing new runs."""
    scen = _scenario(tmp_path, AUDIT_BODY.replace(
        'after_reset = ["radios_off_ok"]\n', ""))
    monkeypatch.setattr(nl, "reset_device", _fake_reset_after(wired))
    with mock.patch.object(nl, "_run", return_value=_cp()):
        rec = nl.run_scenario(lab, scen)
    assert wired == ["reset:lab-r1", "run_post:uptime",
                     "reset_after:lab-client"]
    assert rec["after_reset"] == []
    assert rec["passed"] is True


def test_a_passing_after_reset_check_keeps_the_scenario_passing(
        lab, tmp_path, wired, monkeypatch):
    scen = _scenario(tmp_path, AUDIT_BODY)
    monkeypatch.setattr(nl, "reset_device", _fake_reset_after(wired))
    with mock.patch.object(nl, "_run", return_value=_cp()):
        rec = nl.run_scenario(lab, scen)
    assert rec["error"] is None
    assert rec["passed"] is True
    assert nl.status_letter(rec) == "PASS"


def test_after_reset_checks_run_when_the_scenario_failed(lab, tmp_path, wired,
                                                         monkeypatch):
    """A failing BEFORE probe stops the scenario before plan/apply; the
    reset_after still runs and so do its checks."""
    scen = _scenario(tmp_path, _with_extra(
        AUDIT_BODY, 'regression = ["never_ok"]'))
    monkeypatch.setattr(nl, "reset_device", _fake_reset_after(wired))
    monkeypatch.setattr(nl, "run_post", _fake_post(wired, failing={"never-ok"}))
    with mock.patch.object(nl, "_run", return_value=_cp()):
        rec = nl.run_scenario(lab, scen)
    assert "run_post:radio-off" in wired
    assert rec["error"].startswith("before: regression never_ok")
    assert rec["after_reset"][0]["name"] == "radios_off_ok"
    assert rec["passed"] is False


def test_after_reset_checks_run_the_substituted_cmd(lab, tmp_path, wired,
                                                    monkeypatch):
    """A check cmd may carry a {var} placeholder like any other probe."""
    scen = _scenario(tmp_path, AUDIT_BODY.replace(
        'after_reset = ["radios_off_ok"]',
        'after_reset = ["radios_off_bssid"]'))
    monkeypatch.setattr(nl, "reset_device", _fake_reset_after(wired))
    with mock.patch.object(nl, "_run", side_effect=_var_run()):
        rec = nl.run_scenario(lab, scen)
    assert rec["after_reset"][0]["cmd"] == "radio-off aa:bb:cc:dd:ee:ff"
    assert rec["passed"] is True


# ---------- a failing check fails the scenario ----------

def test_a_failing_after_reset_check_fails_a_passing_scenario(lab, tmp_path,
                                                              wired, monkeypatch):
    scen = _scenario(tmp_path, AUDIT_BODY.replace(
        'after_reset = ["radios_off_ok"]',
        'after_reset = ["radios_off_ok", "radios_off_bad"]'))
    monkeypatch.setattr(nl, "reset_device", _fake_reset_after(wired))
    monkeypatch.setattr(nl, "run_post",
                        _fake_post(wired, failing={"radio-still-on"}))
    with mock.patch.object(nl, "_run", return_value=_cp()):
        rec = nl.run_scenario(lab, scen)
    bad = [e for e in rec["after_reset"] if not e["ok"]]
    assert [e["name"] for e in bad] == ["radios_off_bad"]
    assert bad[0]["passed"] is False and bad[0]["want"] == "pass"
    assert rec["error"] and "after_reset" in rec["error"]
    assert "radios_off_bad" in rec["error"]
    assert rec["passed"] is False
    assert nl.status_letter(rec) == "ERROR"


def test_a_failing_after_reset_check_does_not_hide_an_earlier_error(
        lab, tmp_path, wired, monkeypatch):
    scen = _scenario(tmp_path, _with_extra(
        AUDIT_BODY.replace('after_reset = ["radios_off_ok"]',
                           'after_reset = ["radios_off_bad"]'),
        'regression = ["never_ok"]'))
    monkeypatch.setattr(nl, "reset_device", _fake_reset_after(wired))
    monkeypatch.setattr(nl, "run_post",
                        _fake_post(wired, failing={"never-ok",
                                                   "radio-still-on"}))
    with mock.patch.object(nl, "_run", return_value=_cp()):
        rec = nl.run_scenario(lab, scen)
    assert rec["error"].startswith("before: regression never_ok")
    assert rec["after_reset"][0]["ok"] is False
    assert rec["passed"] is False


def test_after_reset_check_exception_is_recorded_and_fails_the_scenario(
        lab, tmp_path, wired, monkeypatch):
    """The checks run in run_scenario's finally: an exception escaping there
    would lose the whole record, so it is recorded as a failed check."""
    scen = _scenario(tmp_path, AUDIT_BODY)

    def run_post(lab, p):
        wired.append(f"run_post:{p.cmd}")
        if p.cmd == "radio-off":
            raise RuntimeError("ssh blew up")
        return {"device": p.device, "cmd": p.cmd, "expect_rc": p.expect_rc,
                "expect_stdout": p.expect_stdout,
                "rc": 0, "stdout": "", "stderr": "",
                "passed": True, "reason": ""}

    monkeypatch.setattr(nl, "reset_device", _fake_reset_after(wired))
    monkeypatch.setattr(nl, "run_post", run_post)
    with mock.patch.object(nl, "_run", return_value=_cp()):
        rec = nl.run_scenario(lab, scen)
    assert rec["error"] and "after_reset" in rec["error"]
    assert "RuntimeError" in rec["error"]
    assert rec["after_reset"][0]["ok"] is False
    assert rec["after_reset"][0]["rc"] is None
    assert rec["passed"] is False


def test_after_reset_checks_are_skipped_when_the_reset_failed(lab, tmp_path,
                                                             wired, monkeypatch):
    """A reset that did not finish OK already fails the scenario; the checks
    would read a device that is not the baseline."""
    scen = _scenario(tmp_path, AUDIT_BODY)
    monkeypatch.setattr(nl, "reset_device",
                        _fake_reset(wired, fails={"lab-client"}))
    with mock.patch.object(nl, "_run", return_value=_cp()):
        rec = nl.run_scenario(lab, scen)
    assert "run_post:radio-off" not in wired
    assert rec["after_reset"] == []
    assert rec["reset_after"][0]["task_ok"] is False
    assert rec["error"] and "reset_after" in rec["error"]
    assert rec["passed"] is False


def test_after_reset_checks_are_skipped_when_the_scenario_was_refused(
        lab, tmp_path, wired, monkeypatch):
    """A scenario refused before it contacted anything resets nothing, so
    there is no reset to run a check after."""
    scen = _scenario(tmp_path, _with_extra(AUDIT_BODY, 'setup = ["psk_step"]'))
    monkeypatch.setattr(nl, "reset_device", _fake_reset_after(wired))
    with mock.patch.object(nl, "_run", return_value=_cp()):
        rec = nl.run_scenario(lab, scen)
    assert rec["error"] and "secret var" in rec["error"]
    assert rec["reset_after"] == []
    assert rec["after_reset"] == []
    assert "run_post:radio-off" not in wired
    assert rec["passed"] is False