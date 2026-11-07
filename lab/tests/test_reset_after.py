"""Feature A: the scenario field `reset_after = ["device", ...]`.

The runner performs the same reset_device() a scenario gets at the start, for
each named device and in order, AFTER the scenario's posts and cleanup have run
and whatever the scenario's outcome was. A failing reset_after fails the
scenario without hiding an earlier error. Everything here runs against fakes: no
Proxmox, no router ssh.

The physical post-restore fingerprint mismatch case lives in test_physical.py,
where the FakeRouter that answers the archive restore already is.
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

[checks.always_ok]
device = "lab-r1"
cmd = "true"
description = "always passes"

[checks.never_ok]
device = "lab-r1"
cmd = "false"
description = "always fails"

[steps.mark]
device = "lab-r1"
cmd = "true"
description = "no-op marker step"
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


def _fake_reset(order: list[str], *, ok: bool = True, abort_run: bool = False,
                raises: Exception | None = None, labels: dict | None = None):
    """A reset_device() stand-in that records the call order and appends a
    record shaped like pve_reset's. `labels` names the phase per device, so a
    scenario that resets the same device at the start and after stays readable.
    """
    labels = labels or {}

    def reset_device(lab, dname, records):
        order.append(f"{labels.get(dname, 'reset')}:{dname}")
        if raises is not None:
            raise raises
        rec = {"device": dname, "upid": "UPID:fake",
               "task_ok": ok, "exitstatus": "OK" if ok else "boom",
               "attempt": 1}
        if abort_run:
            rec["abort_run"] = True
        records.append(rec)
        return rec
    return reset_device


def _fake_post(order: list[str], *, passed: bool = True):
    """A run_post stand-in. The `false` check in the lab file always fails, so
    a scenario that names it in `regression` stops at its BEFORE probe."""
    def run_post(lab, p):
        order.append(f"post:{p.device}")
        ok = passed and p.cmd != "false"
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


def _with_extra(body: str, extra: str) -> str:
    """Insert top-level `extra` lines before the first table of `body`: a key
    appended after [[post]] would belong to that table, not the scenario."""
    return body.replace("[[post]]", extra + "\n[[post]]")


AUDIT_BODY = """
name = "01-x"
description = "audit scenario with a reset_after"
target = "lab-r1"
reset = ["lab-r1"]
reset_after = ["lab-client"]
expect = "none"
timeout = 60
batch = ""

[[post]]
device = "lab-r1"
cmd = "true"
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


# ---------- loading and validation ----------

def test_reset_after_field_parses(lab, tmp_path):
    scen = _scenario(tmp_path, AUDIT_BODY)
    assert scen.reset == ["lab-r1"]
    assert scen.reset_after == ["lab-client"]


def test_reset_after_absent_parses_as_empty(lab, tmp_path):
    scen = _scenario(tmp_path, """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "none"
timeout = 60
batch = ""

[[post]]
device = "lab-r1"
cmd = "true"
""")
    assert scen.reset_after == []


def test_reset_after_keeps_the_declared_order(lab, tmp_path):
    scen = _scenario(tmp_path, AUDIT_BODY.replace(
        'reset_after = ["lab-client"]',
        'reset_after = ["lab-client", "lab-r1", "lab-client"]'))
    assert scen.reset_after == ["lab-client", "lab-r1", "lab-client"]


def test_validate_unknown_reset_after_device_is_error(lab, tmp_path):
    scen = _scenario(tmp_path, AUDIT_BODY.replace(
        'reset_after = ["lab-client"]', 'reset_after = ["lab-nope"]'))
    errs = nl.validate_scenarios(lab, [scen])
    assert any("lab-nope" in e and "reset_after" in e for e in errs)


def test_validate_reset_after_local_is_error(lab, tmp_path):
    """'local' is not a reset target for reset either; reset_after is the same."""
    scen = _scenario(tmp_path, AUDIT_BODY.replace(
        'reset_after = ["lab-client"]', 'reset_after = ["local"]'))
    errs = nl.validate_scenarios(lab, [scen])
    assert any("reset_after" in e and "'local'" in e for e in errs)


def test_validate_valid_reset_after_is_silent(lab, tmp_path):
    scen = _scenario(tmp_path, AUDIT_BODY)
    assert nl.validate_scenarios(lab, [scen]) == []


def test_main_refuses_a_bad_reset_after_before_any_device_contact(
        lab_path, tmp_path, capsys):
    d = tmp_path / "scenarios"
    d.mkdir()
    (d / "01-x.toml").write_text(AUDIT_BODY.replace(
        'reset_after = ["lab-client"]', 'reset_after = ["lab-nope"]'))
    with mock.patch.object(nl, "_run",
                           side_effect=AssertionError("device contact")):
        rc = nl.main(["--lab", str(lab_path), "--scenarios", str(d),
                      "--lane", "password"])
    assert rc == 2
    assert "reset_after" in capsys.readouterr().err


# ---------- running it ----------

def test_reset_after_runs_after_posts_and_cleanup(lab, tmp_path, wired,
                                                  monkeypatch):
    body = _with_extra(AUDIT_BODY, 'cleanup = ["mark"]')
    scen = _scenario(tmp_path, body)
    monkeypatch.setattr(nl, "reset_device", _fake_reset(wired, labels={"lab-client": "reset_after"}))
    with mock.patch.object(nl, "_run", return_value=_cp(returncode=0)):
        rec = nl.run_scenario(lab, scen)
    assert wired == ["reset:lab-r1", "post:lab-r1", "step:mark",
                     "reset_after:lab-client"]
    assert rec["reset_after"] == [
        {"device": "lab-client", "upid": "UPID:fake", "task_ok": True,
         "exitstatus": "OK", "attempt": 1}]
    assert rec["passed"] is True
    assert rec["error"] is None


def test_reset_after_record_is_empty_without_the_field(lab, tmp_path, wired,
                                                       monkeypatch):
    scen = _scenario(tmp_path, """
name = "01-x"
description = "x"
target = "lab-r1"
reset = ["lab-r1"]
expect = "none"
timeout = 60
batch = ""

[[post]]
device = "lab-r1"
cmd = "true"
""")
    monkeypatch.setattr(nl, "reset_device", _fake_reset(wired, labels={"lab-client": "reset_after"}))
    with mock.patch.object(nl, "_run", return_value=_cp(returncode=0)):
        rec = nl.run_scenario(lab, scen)
    assert wired == ["reset:lab-r1", "post:lab-r1"]
    assert rec["reset_after"] == []
    assert rec["passed"] is True


def test_reset_after_runs_when_the_scenario_failed(lab, tmp_path, wired,
                                                   monkeypatch):
    """A failing BEFORE probe stops the scenario before plan/apply; the
    reset_after still runs and the earlier error is kept."""
    scen = _scenario(tmp_path, _with_extra(
        AUDIT_BODY, 'regression = ["never_ok"]'))
    monkeypatch.setattr(nl, "reset_device", _fake_reset(wired, labels={"lab-client": "reset_after"}))
    with mock.patch.object(nl, "_run", return_value=_cp(returncode=1)):
        rec = nl.run_scenario(lab, scen)
    assert "reset_after:lab-client" in wired
    assert rec["reset_after"] == [
        {"device": "lab-client", "upid": "UPID:fake", "task_ok": True,
         "exitstatus": "OK", "attempt": 1}]
    assert rec["error"] and "before: regression never_ok" in rec["error"]
    assert rec["passed"] is False


def test_reset_after_runs_when_a_post_failed(lab, tmp_path, wired,
                                             monkeypatch):
    scen = _scenario(tmp_path, AUDIT_BODY)
    monkeypatch.setattr(nl, "reset_device", _fake_reset(wired, labels={"lab-client": "reset_after"}))
    monkeypatch.setattr(nl, "run_post", _fake_post(wired, passed=False))
    with mock.patch.object(nl, "_run", return_value=_cp(returncode=0)):
        rec = nl.run_scenario(lab, scen)
    assert "reset_after:lab-client" in wired
    assert rec["passed"] is False


APPLY_BODY = """
name = "01-x"
description = "confirmed apply, then the apply-time base does not match"
target = "lab-r1"
reset = ["lab-r1"]
reset_after = ["lab-client"]
expect = "confirmed"
timeout = 60
batch = "set foo=bar"

[[post]]
device = "lab-r1"
cmd = "true"
"""


def test_reset_after_runs_when_the_apply_errored_after_changes(lab, tmp_path,
                                                              wired, monkeypatch):
    """Changes were staged and applied, then the G3 base check errored: the
    reset_after must still run."""
    scen = _scenario(tmp_path, APPLY_BODY)
    monkeypatch.setattr(nl, "reset_device", _fake_reset(wired, labels={"lab-client": "reset_after"}))
    sid = "a" * 32
    plan_h = "b" * 64
    apply_h = "c" * 64
    with mock.patch.object(nl, "_run", side_effect=[
            _cp(stdout=f"STAGED session={sid}\nBASEHASH {plan_h}\n"
                       f"----- diff -----\nset foo=bar\n----------------\n"),
            _cp(stdout=f"APPLYBASE {apply_h}\nCONFIRMED session={sid}"),
    ]):
        rec = nl.run_scenario(lab, scen)
    assert "reset_after:lab-client" in wired
    assert rec["error"] and "apply-time base" in rec["error"]
    assert rec["reset_after"][0]["task_ok"] is True
    assert rec["passed"] is False


# ---------- a failing reset_after fails the scenario ----------

def test_failing_reset_after_fails_a_passing_scenario(lab, tmp_path, wired,
                                                      monkeypatch):
    scen = _scenario(tmp_path, AUDIT_BODY)

    def reset_device(lab, dname, records):
        wired.append(f"reset:{dname}")
        ok = dname == "lab-r1"
        rec = {"device": dname, "upid": "UPID:fake", "task_ok": ok,
               "exitstatus": "OK" if ok else "rollback failed",
               "attempt": 1}
        records.append(rec)
        return rec

    monkeypatch.setattr(nl, "reset_device", reset_device)
    with mock.patch.object(nl, "_run", return_value=_cp(returncode=0)):
        rec = nl.run_scenario(lab, scen)
    assert rec["outcome"] == "none"
    assert rec["reset_after"][0] == {
        "device": "lab-client", "upid": "UPID:fake", "task_ok": False,
        "exitstatus": "rollback failed", "attempt": 1}
    assert rec["error"] and "reset_after" in rec["error"]
    assert "lab-client" in rec["error"]
    assert rec["passed"] is False
    assert nl.status_letter(rec) == "ERROR"


def test_failing_reset_after_does_not_hide_an_earlier_error(lab, tmp_path,
                                                            wired, monkeypatch):
    scen = _scenario(tmp_path, _with_extra(
        AUDIT_BODY, 'regression = ["never_ok"]'))

    def reset_device(lab, dname, records):
        wired.append(f"reset:{dname}")
        ok = dname == "lab-r1"
        rec = {"device": dname, "upid": "UPID:fake", "task_ok": ok,
               "exitstatus": "OK" if ok else "rollback failed",
               "attempt": 1}
        records.append(rec)
        return rec

    monkeypatch.setattr(nl, "reset_device", reset_device)
    with mock.patch.object(nl, "_run", return_value=_cp(returncode=1)):
        rec = nl.run_scenario(lab, scen)
    assert rec["error"].startswith("before: regression never_ok")
    assert rec["reset_after"][0]["task_ok"] is False
    assert rec["passed"] is False


def test_reset_after_exception_is_recorded_and_fails_the_scenario(
        lab, tmp_path, wired, monkeypatch):
    scen = _scenario(tmp_path, AUDIT_BODY)

    def reset_device(lab, dname, records):
        wired.append(f"reset:{dname}")
        if dname == "lab-r1":
            return {"device": dname, "upid": "UPID:fake", "task_ok": True,
                    "exitstatus": "OK", "attempt": 1}
        raise RuntimeError("curl exploded")

    monkeypatch.setattr(nl, "reset_device", reset_device)
    with mock.patch.object(nl, "_run", return_value=_cp(returncode=0)):
        rec = nl.run_scenario(lab, scen)
    assert rec["error"] and "reset_after" in rec["error"]
    assert "RuntimeError" in rec["error"]
    assert rec["passed"] is False
    assert any(r.get("error") for r in rec["reset_after"])


def test_reset_after_abort_run_stops_the_run(lab, tmp_path, wired,
                                             monkeypatch):
    """A physical verify mismatch is already an abort_run; the reset_after
    record carries it so main() stops after this scenario."""
    scen = _scenario(tmp_path, AUDIT_BODY)

    def reset_device(lab, dname, records):
        wired.append(f"reset:{dname}")
        if dname == "lab-r1":
            return {"device": dname, "upid": "UPID:fake", "task_ok": True,
                    "exitstatus": "OK", "attempt": 1}
        rec = {"device": dname, "upid": "physical", "task_ok": False,
               "exitstatus": "post-restore fingerprint mismatch",
               "attempt": 1, "verify": "mismatch", "abort_run": True}
        records.append(rec)
        return rec

    monkeypatch.setattr(nl, "reset_device", reset_device)
    with mock.patch.object(nl, "_run", return_value=_cp(returncode=0)):
        rec = nl.run_scenario(lab, scen)
    assert rec["abort_run"] is True
    assert rec["reset_after"][0]["verify"] == "mismatch"
    assert rec["passed"] is False


def test_reset_after_runs_when_the_scenario_raised(lab, tmp_path, wired,
                                                   monkeypatch):
    """An exception mid-scenario still reaches the reset_after."""
    scen = _scenario(tmp_path, AUDIT_BODY)
    monkeypatch.setattr(nl, "reset_device", _fake_reset(wired, labels={"lab-client": "reset_after"}))
    with mock.patch.object(nl, "run_post",
                           side_effect=RuntimeError("ssh blew up")):
        rec = nl.run_scenario(lab, scen)
    assert "reset_after:lab-client" in wired
    assert rec["error"] and "RuntimeError" in rec["error"]
    assert rec["passed"] is False