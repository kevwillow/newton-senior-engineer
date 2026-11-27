"""The lab runner runs a held apply and its confirm.

A scenario may hold its apply: the apply runs the same rounds as always but
does not confirm, the router's rollback stays armed, and the runner confirms
the change itself after the steps the scenario names.  A confirm that is
refused leaves the change armed: the runner waits past the guard's deadline
and reads the router's status the way a controller-loss run reads it.

Nothing here touches a router: the plan, the apply, the confirm and the
status are answered by a fake subprocess wrapper, and the vantage inventory
is a synthetic file in a temp dir.
"""
from __future__ import annotations

from conftest import lab_toml_path

import copy
import json
import subprocess
from pathlib import Path
from unittest import mock

import pytest

import newton_lab_test as nl

LAB_DIR = Path(__file__).resolve().parent.parent
LAB_TOML = lab_toml_path()
EVERYDAY_DIR = LAB_DIR / "scenarios" / "everyday"
RULES_03 = "ev-rules-03-hold-confirm"
RULES_04 = "ev-rules-04-hold-break-before-confirm"
SID = "a" * 32
BASEHASH = "b" * 64

PLAN_OUT = (
    f"STAGED session={SID}\n"
    f"BASEHASH {BASEHASH}\n"
    "----- diff -----\n"
    "set foo=bar\n"
    "----------------\n"
)
# The apply of a held change: the rounds passed and nothing was confirmed.
HELD_OUT = (
    f"APPLYBASE {BASEHASH}\n"
    f"HELD session={SID} until=1893456000 (3 consecutive passes; NOT "
    "confirmed: the router rolls the change back when its window ends) "
    "confirm: /x/owrt-change.sh confirm root@10.109.0.11 " + SID + " "
    "abort: /x/owrt-change.sh abort root@10.109.0.11 " + SID
)
# The confirm of a held change that took.
CONFIRMED_OUT = (
    f"CONFIRMED session={SID} (held apply: 3 consecutive passes, then one "
    "more fresh ssh + router-side round before the confirm + local check)"
)
# The confirm of a held change the router refused.
REFUSED_OUT = (
    "ERROR: the local check failed before the confirm (exit 1); not "
    "confirmed: the router rolls the change back when its window ends, or "
    "abort now: /x/owrt-change.sh abort root@10.109.0.11 " + SID
)
# The router's own status line, as `owrt-change.sh status` prints it.
STATUS_ROLLED_BACK = (
    f"rolled-back sid={SID} guard=restored:deadline rpcd=- config=base "
    "boot=same running=match\n"
    f"RUNNING session={SID} match\n"
)
STATUS_ROLLED_BACK_DIFFERS = (
    f"rolled-back sid={SID} guard=restored:deadline rpcd=- config=base "
    "boot=same running=differs\n"
    f"RUNNING session={SID} differs\n"
)
STATUS_PENDING = (
    f"rolled-back sid={SID} guard=pending rpcd=- config=post boot=same\n"
)


def _cp(stdout: str = "", stderr: str = "", returncode: int = 0):
    return subprocess.CompletedProcess(args=[], returncode=returncode,
                                       stdout=stdout, stderr=stderr)


@pytest.fixture
def lab():
    """A fresh lab per test: some of these add a step to it."""
    return nl.load_lab(LAB_TOML)


@pytest.fixture(scope="module")
def everyday():
    return {scen.name: scen for scen in nl.load_scenarios(EVERYDAY_DIR)}


def _inventory(tmp_path: Path) -> Path:
    root = tmp_path / "vantage"
    root.mkdir()
    key = root / "scan-key"
    key.write_text("synthetic\n", encoding="utf-8")
    key.chmod(0o600)
    known_hosts = root / "known-hosts"
    known_hosts.write_text("synthetic\n", encoding="utf-8")
    inventory = root / "inventory.toml"
    inventory.write_text(
        f"""
[devices.lab-r1]
host = "10.109.0.11"

[vantages.lab-client]
host = "192.0.2.50"
user = "labuser"
key_file = "{key.as_posix()}"
known_hosts = "{known_hosts.as_posix()}"
proxy_command = "ssh -W %h:%p root@lab-proxy"
role = "inside"
devices = ["lab-r1"]

[[vantages.lab-client.zones]]
name = "guest"
src = "192.0.2.50"
canary = "192.0.2.1:53"
""",
        encoding="utf-8",
    )
    inventory.chmod(0o600)
    return inventory


class _Runner:
    """The fake subprocess wrapper: the plan, the apply, the confirm and the
    status are answered from here, and every call is recorded."""

    def __init__(self, *, apply_out: str = HELD_OUT,
                 apply_rc: int = 0,
                 confirm_out: str = CONFIRMED_OUT,
                 confirm_rc: int = 0,
                 status_out: str = STATUS_ROLLED_BACK,
                 abort_out: str = f"aborted {SID} gone",
                 abort_rc: int = 0):
        self.calls: list[list[str]] = []
        self.envs: list[dict] = []
        self.spec_exists: list[bool] = []
        self.apply_out = apply_out
        self.apply_rc = apply_rc
        self.confirm_out = confirm_out
        self.confirm_rc = confirm_rc
        self.status_out = status_out
        self.abort_out = abort_out
        self.abort_rc = abort_rc

    def __call__(self, args, **kw):
        args = list(args)
        self.calls.append(args)
        env = kw.get("env") or {}
        self.envs.append(dict(env))
        if args and args[0] == str(nl.OWRT_CHANGE):
            verb = args[1] if len(args) > 1 else ""
            if verb == "plan":
                return _cp(stdout=PLAN_OUT)
            if verb == "apply":
                return _cp(stdout=self.apply_out, returncode=self.apply_rc)
            if verb == "confirm":
                spec_dir = env.get("NEWTON_VANTAGE_SPEC_DIR")
                if spec_dir:
                    spec = Path(spec_dir) / f"{SID}.json"
                    self.spec_exists.append(spec.is_file())
                return _cp(stdout=self.confirm_out, stderr="",
                           returncode=self.confirm_rc)
            if verb == "status":
                return _cp(stdout=self.status_out)
            if verb == "abort":
                return _cp(stdout=self.abort_out, returncode=self.abort_rc)
            return _cp()
        return _cp()


def _scenario(tmp_path: Path, body: str, name: str = "hold-test"):
    directory = tmp_path / "scenarios"
    directory.mkdir(exist_ok=True)
    (directory / f"{name}.toml").write_text(body, encoding="utf-8")
    return nl.load_scenarios(directory)[0]


HOLD_BODY = """
name = "hold-test"
description = "a held apply and its confirm"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 300
batch = "set foo=bar"
hold = true

[[client_checks]]
kind = "client_dns"
zone = "guest"
"""

# The same scenario with a step that runs between the held apply and the
# confirm.  The step is a top-level key, so it comes before the table of
# the client checks.
HOLD_BODY_WITH_STEP = """
name = "hold-test"
description = "a held apply, a step and its confirm"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 300
batch = "set foo=bar"
hold = true
before_confirm = ["break_it"]

[[client_checks]]
kind = "client_dns"
zone = "guest"
"""


# The same held scenario, with the refusal of the confirm pinned: the run
# only passes when the confirm was refused AND the router rolled the change
# back.
HOLD_BODY_REFUSED = """
name = "hold-test"
description = "a held apply whose confirm is refused"
target = "lab-r1"
reset = []
expect = "rolled_back"
timeout = 300
batch = "set foo=bar"
hold = true
expect_confirm_refused = "the local check failed before the confirm"

[[client_checks]]
kind = "client_dns"
zone = "guest"
"""


def _run(lab, scen, tmp_path, monkeypatch, fake: _Runner, slept=None):
    """Run one scenario against the fake wrapper."""
    monkeypatch.setenv("NEWTON_LAB_VANTAGE_INVENTORY",
                       str(_inventory(tmp_path)))
    monkeypatch.setattr(nl, "RESULTS_DIR", tmp_path / "results")
    if slept is not None:
        monkeypatch.setattr(nl, "_cl_sleep", slept.append)
    with mock.patch.object(nl, "_run", side_effect=fake):
        return nl.run_scenario(lab, scen)


def _verb(fake: _Runner, verb: str) -> list[list[str]]:
    return [c for c in fake.calls
            if c and c[0] == str(nl.OWRT_CHANGE) and c[1:2] == [verb]]


# ---------- the apply and the confirm ----------

def test_the_held_apply_passes_the_hold_flag_in_its_argv(tmp_path, monkeypatch):
    """The apply of a held scenario is the apply of any other scenario plus
    the --hold flag, as the last argument of an argv list."""
    lab = nl.load_lab(LAB_TOML)
    scen = _scenario(tmp_path, HOLD_BODY)
    fake = _Runner()
    rec = _run(lab, scen, tmp_path, monkeypatch, fake)
    applies = _verb(fake, "apply")
    assert len(applies) == 1
    assert applies[0][-1] == "--hold"
    assert applies[0][1:4] == ["apply", "root@10.109.0.11", SID]
    assert rec["passed"] is True


def test_a_plain_apply_has_no_hold_flag(tmp_path, monkeypatch):
    """A scenario without a hold is applied as it was before."""
    lab = nl.load_lab(LAB_TOML)
    scen = _scenario(tmp_path, HOLD_BODY.replace("hold = true\n", ""))
    fake = _Runner(apply_out=f"APPLYBASE {BASEHASH}\nCONFIRMED session={SID}")
    rec = _run(lab, scen, tmp_path, monkeypatch, fake)
    applies = _verb(fake, "apply")
    assert "--hold" not in applies[0]
    assert rec["passed"] is True


def test_the_confirm_runs_with_the_client_check_env(tmp_path, monkeypatch):
    """The confirm of a held apply runs with the same client-check env as
    the apply: the vantage runner is called again, so the env must carry
    OWRT_LOCAL_CHECK and the spec dir."""
    lab = nl.load_lab(LAB_TOML)
    scen = _scenario(tmp_path, HOLD_BODY)
    fake = _Runner()
    rec = _run(lab, scen, tmp_path, monkeypatch, fake)
    confirms = _verb(fake, "confirm")
    assert len(confirms) == 1
    assert confirms[0][1:] == ["confirm", "root@10.109.0.11", SID]
    confirm_env = fake.envs[fake.calls.index(confirms[0])]
    assert "OWRT_LOCAL_CHECK" in confirm_env
    assert "NEWTON_VANTAGE_SPEC_DIR" in confirm_env
    assert rec["passed"] is True


def test_the_vantage_spec_is_there_for_the_confirm_and_gone_after_it(tmp_path,
                                                                      monkeypatch):
    """The vantage spec file must still exist while the confirm runs (the
    confirm checks the claims again), and the run removes it afterwards."""
    lab = nl.load_lab(LAB_TOML)
    scen = _scenario(tmp_path, HOLD_BODY)
    fake = _Runner()
    rec = _run(lab, scen, tmp_path, monkeypatch, fake)
    assert fake.spec_exists == [True]
    spec_dir = Path(fake.envs[fake.calls.index(_verb(fake, "confirm")[0])]
                    ["NEWTON_VANTAGE_SPEC_DIR"])
    assert not (spec_dir / f"{SID}.json").exists()


def test_the_vantage_spec_goes_away_after_a_failed_apply(tmp_path, monkeypatch):
    """A held apply whose rounds failed never confirms: the spec file is
    removed anyway."""
    lab = nl.load_lab(LAB_TOML)
    scen = _scenario(tmp_path, HOLD_BODY.replace('expect = "confirmed"',
                                                  'expect = "rolled_back"'))
    fake = _Runner(apply_out=f"APPLYBASE {BASEHASH}\n"
                              f"ROLLBACK WINDOW PASSED session={SID}",
                   apply_rc=1)
    rec = _run(lab, scen, tmp_path, monkeypatch, fake)
    assert _verb(fake, "confirm") == []
    spec_dir = Path(fake.envs[fake.calls.index(_verb(fake, "apply")[0])]
                    ["NEWTON_VANTAGE_SPEC_DIR"])
    assert not (spec_dir / f"{SID}.json").exists()
    assert rec["outcome"] == "rolled_back"


def test_a_confirmed_confirm_ends_the_scenario_confirmed(tmp_path, monkeypatch):
    lab = nl.load_lab(LAB_TOML)
    scen = _scenario(tmp_path, HOLD_BODY)
    fake = _Runner()
    rec = _run(lab, scen, tmp_path, monkeypatch, fake)
    assert rec["outcome"] == "confirmed"
    assert rec["passed"] is True
    assert rec["hold_confirm_rc"] == 0


def test_the_confirm_rc_and_its_last_output_are_recorded(tmp_path, monkeypatch):
    lab = nl.load_lab(LAB_TOML)
    scen = _scenario(tmp_path, HOLD_BODY)
    fake = _Runner(confirm_out=REFUSED_OUT, confirm_rc=1)
    rec = _run(lab, scen, tmp_path, monkeypatch, fake)
    assert rec["hold_confirm_rc"] == 1
    assert "the local check failed before the confirm" in rec["hold_confirm_log"]


# ---------- a refused confirm ----------

def test_a_refused_confirm_waits_past_the_deadline_and_reads_the_status(
        tmp_path, monkeypatch):
    """A refused confirm leaves the change armed: the runner waits past the
    guard's deadline (the timeout plus 30 s, the wait a controller-loss run
    uses) and then reads the router's status."""
    lab = nl.load_lab(LAB_TOML)
    scen = _scenario(tmp_path, HOLD_BODY.replace('expect = "confirmed"',
                                                  'expect = "rolled_back"'))
    fake = _Runner(confirm_out=REFUSED_OUT, confirm_rc=1)
    slept: list[float] = []
    rec = _run(lab, scen, tmp_path, monkeypatch, fake, slept=slept)
    assert len(slept) == 1
    assert abs(slept[0] - (300 + 30)) < 1
    assert _verb(fake, "status")
    assert rec["outcome"] == "rolled_back"
    assert rec["passed"] is True


def test_a_rolled_back_status_that_does_not_run_the_old_settings_is_not_a_rollback(
        tmp_path, monkeypatch):
    """The device ends in the pre-change state or in the confirmed state,
    never in between: a status that says rolled back but whose running
    network differs from the restored files is not a rollback."""
    lab = nl.load_lab(LAB_TOML)
    scen = _scenario(tmp_path, HOLD_BODY.replace('expect = "confirmed"',
                                                  'expect = "rolled_back"'))
    fake = _Runner(confirm_out=REFUSED_OUT, confirm_rc=1,
                   status_out=STATUS_ROLLED_BACK_DIFFERS)
    rec = _run(lab, scen, tmp_path, monkeypatch, fake)
    assert rec["passed"] is False
    assert rec["outcome"] != "rolled_back"
    assert "controller-loss-running-differs" in rec["error"]


def test_a_guard_that_did_not_restore_the_old_settings_is_not_a_rollback(
        tmp_path, monkeypatch):
    """The guard's own label decides: a rolled-back device must have put the
    old settings back."""
    lab = nl.load_lab(LAB_TOML)
    scen = _scenario(tmp_path, HOLD_BODY.replace('expect = "confirmed"',
                                                  'expect = "rolled_back"'))
    fake = _Runner(confirm_out=REFUSED_OUT, confirm_rc=1,
                   status_out=STATUS_PENDING)
    rec = _run(lab, scen, tmp_path, monkeypatch, fake)
    assert rec["passed"] is False
    assert rec["outcome"] != "rolled_back"
    assert "controller-loss-in-between" in rec["error"]


# ---------- the validation of the fields ----------

def test_hold_is_refused_with_a_controller_loss(everyday):
    lab = nl.load_lab(LAB_TOML)
    scen = copy.copy(everyday[RULES_03])
    scen.controller_loss = "verify-1"
    scen.expect = "rolled_back"
    errors = nl.validate_scenarios(lab, [scen])
    assert any("hold" in error and "controller_loss" in error
               for error in errors), errors


def test_hold_is_refused_with_a_tier(everyday):
    lab = nl.load_lab(LAB_TOML)
    scen = copy.copy(everyday[RULES_03])
    scen.tier = "standard"
    errors = nl.validate_scenarios(lab, [scen])
    assert any("hold" in error and "tier" in error for error in errors), errors


def test_before_confirm_without_hold_is_refused(everyday):
    lab = nl.load_lab(LAB_TOML)
    scen = copy.copy(everyday[RULES_04])
    scen.hold = False
    errors = nl.validate_scenarios(lab, [scen])
    assert any("before_confirm" in error for error in errors), errors


def test_the_before_confirm_steps_must_exist(everyday):
    lab = nl.load_lab(LAB_TOML)
    scen = copy.copy(everyday[RULES_04])
    scen.before_confirm = ["no_such_step"]
    errors = nl.validate_scenarios(lab, [scen])
    assert any("before_confirm" in error for error in errors), errors


# ---------- the steps of the scenario ----------

def test_the_before_confirm_steps_run_between_the_apply_and_the_confirm(
        tmp_path, monkeypatch):
    """The steps of the scenario run after the held apply and before the
    confirm: they are the last thing that can break the change."""
    lab = nl.load_lab(LAB_TOML)
    body = HOLD_BODY_WITH_STEP
    scen = _scenario(tmp_path, body)
    fake = _Runner()
    order: list[str] = []

    def fake_run(args, **kw):
        args = list(args)
        if args and args[0] == str(nl.OWRT_CHANGE):
            verb = args[1] if len(args) > 1 else ""
            if verb == "apply":
                order.append("apply")
            elif verb == "confirm":
                order.append("confirm")
            return _Runner()(args, **kw)
        order.append("step")
        return _cp(stdout="ok\n")

    monkeypatch.setenv("NEWTON_LAB_VANTAGE_INVENTORY",
                       str(_inventory(tmp_path)))
    monkeypatch.setattr(nl, "RESULTS_DIR", tmp_path / "results")
    lab.steps["break_it"] = nl.Step(name="break_it", device="lab-r1",
                                     cmd="true", timeout=30)
    with mock.patch.object(nl, "_run", side_effect=fake_run):
        rec = nl.run_scenario(lab, scen)
    assert order == ["apply", "step", "confirm"]
    assert rec["passed"] is True


def test_a_before_confirm_step_that_fails_stops_the_run(tmp_path, monkeypatch):
    """A step that fails before the confirm stops the scenario: the change
    is not confirmed."""
    lab = nl.load_lab(LAB_TOML)
    body = HOLD_BODY_WITH_STEP
    scen = _scenario(tmp_path, body)
    fake = _Runner()

    def fake_run(args, **kw):
        args = list(args)
        if args and args[0] == str(nl.OWRT_CHANGE):
            return fake(args, **kw)
        return _cp(stdout="", stderr="the step failed\n", returncode=1)

    monkeypatch.setenv("NEWTON_LAB_VANTAGE_INVENTORY",
                       str(_inventory(tmp_path)))
    monkeypatch.setattr(nl, "RESULTS_DIR", tmp_path / "results")
    lab.steps["break_it"] = nl.Step(name="break_it", device="lab-r1",
                                     cmd="true", timeout=30)
    with mock.patch.object(nl, "_run", side_effect=fake_run):
        rec = nl.run_scenario(lab, scen)
    assert rec["passed"] is False
    assert "break_it" in rec["error"]
    # the calls went through the fake, so the assertion below is not vacuous
    assert _verb(fake, "apply")
    assert _verb(fake, "confirm") == []


# ---------- the refused confirm the scenario pins ----------

def test_the_refused_confirm_the_scenario_pins_passes_the_run(tmp_path,
                                                              monkeypatch):
    """A scenario may pin the refusal of its confirm: the run passes when
    the confirm was refused and the router rolled the change back."""
    lab = nl.load_lab(LAB_TOML)
    scen = _scenario(tmp_path, HOLD_BODY_REFUSED)
    fake = _Runner(confirm_out=REFUSED_OUT, confirm_rc=1)
    rec = _run(lab, scen, tmp_path, monkeypatch, fake)
    assert rec["outcome"] == "rolled_back"
    assert rec["passed"] is True
    assert rec["confirm_refused"]["matched"] is True


def test_a_confirm_whose_output_does_not_match_the_pin_fails_the_run(tmp_path,
                                                                     monkeypatch):
    """The pin is a regex over the confirm's output: a confirm that was
    refused for another reason does not pass it."""
    lab = nl.load_lab(LAB_TOML)
    scen = _scenario(tmp_path, HOLD_BODY_REFUSED)
    fake = _Runner(confirm_out="ERROR: the router refused this confirm: busy",
                   confirm_rc=1)
    rec = _run(lab, scen, tmp_path, monkeypatch, fake)
    assert rec["passed"] is False
    assert "expect_confirm_refused" in rec["error"]
    assert rec["confirm_refused"]["matched"] is False


def test_a_confirm_that_was_not_refused_fails_the_run(tmp_path, monkeypatch):
    """The pin wants a refused confirm AND a rolled-back change: a confirm
    that took is not a refusal, whatever the output says."""
    lab = nl.load_lab(LAB_TOML)
    scen = _scenario(tmp_path, HOLD_BODY_REFUSED.replace(
        'expect = "rolled_back"', 'expect = "confirmed"').replace(
        'expect_confirm_refused = "the local check failed before the confirm"',
        'expect_confirm_refused = "CONFIRMED"'))
    fake = _Runner()
    rec = _run(lab, scen, tmp_path, monkeypatch, fake)
    assert rec["outcome"] == "confirmed"
    assert rec["passed"] is False
    assert "expect_confirm_refused" in rec["error"]


def test_expect_confirm_refused_needs_a_hold(everyday):
    """The pin is about the confirm of a held apply: a scenario that does
    not hold has no confirm to refuse."""
    lab = nl.load_lab(LAB_TOML)
    scen = copy.copy(everyday[RULES_04])
    scen.hold = False
    errors = nl.validate_scenarios(lab, [scen])
    assert any("expect_confirm_refused" in error for error in errors), errors


def test_a_pin_that_is_not_a_regex_is_refused(everyday):
    lab = nl.load_lab(LAB_TOML)
    scen = copy.copy(everyday[RULES_04])
    scen.expect_confirm_refused = "["
    errors = nl.validate_scenarios(lab, [scen])
    assert any("expect_confirm_refused" in error for error in errors), errors


# ---------- an early error leaves the change armed ----------

def test_a_held_apply_without_a_held_line_aborts_the_armed_change(tmp_path,
                                                                  monkeypatch):
    """An early error of a held apply leaves the change armed: the runner
    aborts it, so the device is not left with a change nobody confirmed."""
    lab = nl.load_lab(LAB_TOML)
    scen = _scenario(tmp_path, HOLD_BODY)
    fake = _Runner(apply_out=f"APPLYBASE {BASEHASH}\n")
    rec = _run(lab, scen, tmp_path, monkeypatch, fake)
    aborts = _verb(fake, "abort")
    assert len(aborts) == 1
    assert aborts[0][1:] == ["abort", "root@10.109.0.11", SID]
    assert rec["hold_abort_rc"] == 0
    assert rec["hold_abort_line"] == f"aborted {SID} gone"
    # the error of the run is the early one, not the abort's
    assert "no held session" in rec["error"]
    # the apply's own output is in the record, as on every other path
    assert "APPLYBASE" in rec["apply_log"]


def test_an_empty_expect_confirm_refused_pattern_is_refused(everyday):
    """The pin is a regex over the confirm's output: an empty pattern would
    match every output, so it is refused before the run."""
    lab = nl.load_lab(LAB_TOML)
    scen = copy.copy(everyday[RULES_04])
    scen.expect_confirm_refused = ""
    errors = nl.validate_scenarios(lab, [scen])
    assert any("expect_confirm_refused" in error for error in errors), errors


def test_a_confirm_that_took_is_not_a_refusal_even_when_its_output_matches(
        tmp_path, monkeypatch):
    """The pin wants a refused confirm: a confirm that took (its rc is zero)
    is not a refusal, whatever its output says."""
    lab = nl.load_lab(LAB_TOML)
    scen = _scenario(
        tmp_path,
        HOLD_BODY_REFUSED.replace(
            'expect_confirm_refused = "the local check failed before the confirm"',
            'expect_confirm_refused = "the confirm was not refused"'),
    )
    fake = _Runner(confirm_out="ERROR: the confirm was not refused\n",
                   confirm_rc=0)
    rec = _run(lab, scen, tmp_path, monkeypatch, fake, slept=[])
    assert rec["passed"] is False
    assert "expect_confirm_refused" in rec["error"]
    # the output matched the pin, but the confirm was not refused
    assert rec["confirm_refused"]["matched"] is True
    assert rec["hold_confirm_rc"] == 0


def test_a_before_confirm_step_that_fails_aborts_the_armed_change(tmp_path,
                                                                  monkeypatch):
    """A step that fails before the confirm leaves the change armed: the
    runner aborts it."""
    lab = nl.load_lab(LAB_TOML)
    scen = _scenario(tmp_path, HOLD_BODY_WITH_STEP)
    fake = _Runner()

    def fake_run(args, **kw):
        args = list(args)
        if args and args[0] == str(nl.OWRT_CHANGE):
            return fake(args, **kw)
        return _cp(stdout="", stderr="the step failed\n", returncode=1)

    monkeypatch.setenv("NEWTON_LAB_VANTAGE_INVENTORY",
                       str(_inventory(tmp_path)))
    monkeypatch.setattr(nl, "RESULTS_DIR", tmp_path / "results")
    lab.steps["break_it"] = nl.Step(name="break_it", device="lab-r1",
                                     cmd="true", timeout=30)
    with mock.patch.object(nl, "_run", side_effect=fake_run):
        rec = nl.run_scenario(lab, scen)
    assert rec["passed"] is False
    assert "break_it" in rec["error"]
    assert len(_verb(fake, "abort")) == 1
    assert rec["hold_abort_rc"] == 0
    assert "APPLYBASE" in rec["apply_log"]


def test_a_before_confirm_step_that_raises_aborts_the_armed_change(tmp_path,
                                                                    monkeypatch):
    """A step that raises before the confirm leaves the change armed: the
    runner aborts it before it returns the error."""
    lab = nl.load_lab(LAB_TOML)
    scen = _scenario(tmp_path, HOLD_BODY_WITH_STEP)
    fake = _Runner()
    steps = {"n": 0}

    def fake_run(args, **kw):
        args = list(args)
        if args and args[0] == str(nl.OWRT_CHANGE):
            return fake(args, **kw)
        steps["n"] += 1
        if steps["n"] == 1:
            raise subprocess.TimeoutExpired(cmd="the step", timeout=30)
        return _cp(stdout="ok\n")

    monkeypatch.setenv("NEWTON_LAB_VANTAGE_INVENTORY",
                       str(_inventory(tmp_path)))
    monkeypatch.setattr(nl, "RESULTS_DIR", tmp_path / "results")
    lab.steps["break_it"] = nl.Step(name="break_it", device="lab-r1",
                                     cmd="true", timeout=30)
    with mock.patch.object(nl, "_run", side_effect=fake_run):
        rec = nl.run_scenario(lab, scen)
    assert rec["passed"] is False
    assert "TimeoutExpired" in rec["error"]
    assert len(_verb(fake, "abort")) == 1
    assert rec["hold_abort_rc"] == 0


def test_a_confirm_that_raises_aborts_the_armed_change(tmp_path, monkeypatch):
    """A confirm that raises leaves the change armed: the runner aborts it
    before it returns the error."""
    lab = nl.load_lab(LAB_TOML)
    scen = _scenario(tmp_path, HOLD_BODY)
    fake = _Runner()

    def fake_run(args, **kw):
        args = list(args)
        if args and args[0] == str(nl.OWRT_CHANGE):
            if len(args) > 1 and args[1] == "confirm":
                raise subprocess.TimeoutExpired(cmd="the confirm", timeout=300)
            return fake(args, **kw)
        return _cp(stdout="ok\n")

    monkeypatch.setenv("NEWTON_LAB_VANTAGE_INVENTORY",
                       str(_inventory(tmp_path)))
    monkeypatch.setattr(nl, "RESULTS_DIR", tmp_path / "results")
    with mock.patch.object(nl, "_run", side_effect=fake_run):
        rec = nl.run_scenario(lab, scen)
    assert rec["passed"] is False
    assert "TimeoutExpired" in rec["error"]
    assert len(_verb(fake, "abort")) == 1
    assert rec["hold_abort_rc"] == 0


def test_a_status_read_that_raises_aborts_the_armed_change(tmp_path, monkeypatch):
    """The status of a refused confirm cannot be read: the change is still
    armed, so the runner aborts it before it returns the error."""
    lab = nl.load_lab(LAB_TOML)
    scen = _scenario(tmp_path, HOLD_BODY.replace('expect = "confirmed"',
                                                  'expect = "rolled_back"'))
    fake = _Runner(confirm_out=REFUSED_OUT, confirm_rc=1)

    def fake_run(args, **kw):
        args = list(args)
        if args and args[0] == str(nl.OWRT_CHANGE):
            if len(args) > 1 and args[1] == "status":
                raise subprocess.TimeoutExpired(cmd="the status", timeout=90)
            return fake(args, **kw)
        return _cp(stdout="ok\n")

    monkeypatch.setenv("NEWTON_LAB_VANTAGE_INVENTORY",
                       str(_inventory(tmp_path)))
    monkeypatch.setattr(nl, "RESULTS_DIR", tmp_path / "results")
    monkeypatch.setattr(nl, "_cl_sleep", lambda seconds: None)
    with mock.patch.object(nl, "_run", side_effect=fake_run):
        rec = nl.run_scenario(lab, scen)
    assert rec["passed"] is False
    assert "TimeoutExpired" in rec["error"]
    assert len(_verb(fake, "abort")) == 1
    assert rec["hold_abort_rc"] == 0


def test_an_unreadable_status_aborts_the_armed_change(tmp_path, monkeypatch):
    """A status the runner cannot read leaves the change armed too: the
    runner aborts it."""
    lab = nl.load_lab(LAB_TOML)
    scen = _scenario(tmp_path, HOLD_BODY.replace('expect = "confirmed"',
                                                  'expect = "rolled_back"'))
    fake = _Runner(confirm_out=REFUSED_OUT, confirm_rc=1,
                   status_out=STATUS_PENDING)
    rec = _run(lab, scen, tmp_path, monkeypatch, fake)
    assert rec["passed"] is False
    assert len(_verb(fake, "abort")) == 1
    assert rec["hold_abort_rc"] == 0
    assert rec["hold_abort_line"] == f"aborted {SID} gone"


def test_the_abort_of_a_held_apply_runs_with_the_env_of_the_confirm(tmp_path,
                                                                    monkeypatch):
    """The abort is the change wrapper's own, with the same env the confirm
    had: the client-check env travels with it."""
    lab = nl.load_lab(LAB_TOML)
    scen = _scenario(tmp_path, HOLD_BODY)
    fake = _Runner(apply_out=f"APPLYBASE {BASEHASH}\n")
    _run(lab, scen, tmp_path, monkeypatch, fake)
    aborts = _verb(fake, "abort")
    assert len(aborts) == 1
    abort_env = fake.envs[fake.calls.index(aborts[0])]
    assert "OWRT_LOCAL_CHECK" in abort_env
    assert "NEWTON_VANTAGE_SPEC_DIR" in abort_env


def test_a_confirm_that_was_refused_and_rolled_back_aborts_nothing(tmp_path,
                                                                   monkeypatch):
    """The refused confirm is not an early error: the router rolled the
    change back on its own, so there is nothing left to abort."""
    lab = nl.load_lab(LAB_TOML)
    scen = _scenario(tmp_path, HOLD_BODY.replace('expect = "confirmed"',
                                                  'expect = "rolled_back"'))
    fake = _Runner(confirm_out=REFUSED_OUT, confirm_rc=1)
    rec = _run(lab, scen, tmp_path, monkeypatch, fake)
    assert rec["outcome"] == "rolled_back"
    assert _verb(fake, "abort") == []


# ---------- the loader's type checks ----------

def test_hold_must_be_a_boolean(tmp_path):
    """`hold` is a boolean: a scenario that says anything else is refused by
    the load, and the refusal names the file and the field."""
    with pytest.raises(ValueError) as excinfo:
        _scenario(tmp_path, HOLD_BODY.replace("hold = true", 'hold = "yes"'))
    message = str(excinfo.value)
    assert "hold-test.toml" in message
    assert "hold" in message


def test_before_confirm_must_be_a_list(tmp_path):
    """`before_confirm` is a list of step names: a bare string is refused by
    the load, and the refusal names the file and the field."""
    with pytest.raises(ValueError) as excinfo:
        _scenario(tmp_path, HOLD_BODY_WITH_STEP.replace(
            'before_confirm = ["break_it"]', 'before_confirm = "break_it"'))
    message = str(excinfo.value)
    assert "hold-test.toml" in message
    assert "before_confirm" in message


def test_before_confirm_must_hold_strings(tmp_path):
    """A list of names: an entry that is not a string is refused by the
    load."""
    with pytest.raises(ValueError) as excinfo:
        _scenario(tmp_path, HOLD_BODY_WITH_STEP.replace(
            'before_confirm = ["break_it"]', 'before_confirm = [1]'))
    message = str(excinfo.value)
    assert "hold-test.toml" in message
    assert "before_confirm" in message


# ---------- the before_confirm steps join the checks ----------

def test_a_before_confirm_step_with_an_unknown_device_is_refused(everyday):
    """The steps of a scenario are checked the same way, whichever phase
    they run in: a before_confirm step of a device that does not exist is
    refused before anything is touched."""
    lab = nl.load_lab(LAB_TOML)
    scen = copy.copy(everyday[RULES_04])
    lab.steps["ghost_step"] = nl.Step(name="ghost_step",
                                      device="no-such-device", cmd="true",
                                      timeout=30)
    scen.before_confirm = ["ghost_step"]
    errors = nl.validate_scenarios(lab, [scen])
    assert any("ghost_step" in error and "no-such-device" in error
               for error in errors), errors


def test_a_before_confirm_step_may_not_name_a_secret_var(everyday):
    """A secret var may only reach the batch: a before_confirm step runs its
    cmd in ssh argv, so it is refused like a setup or a cleanup step."""
    lab = nl.load_lab(LAB_TOML)
    lab.var_defs["wifi_psk"] = {"device": "local", "cmd": "true"}
    lab.var_defs["wifi_psk"]["secret"] = True
    lab.steps["show_secret"] = nl.Step(
        name="show_secret", device="lab-r1",
        cmd="uci get wireless.@wifi[0].key='{wifi_psk}'", timeout=30)
    scen = copy.copy(everyday[RULES_04])
    scen.before_confirm = ["show_secret"]
    errors = nl.validate_scenarios(lab, [scen])
    assert any("wifi_psk" in error and "before_confirm" in error
               for error in errors), errors


def test_a_run_refuses_a_before_confirm_step_that_names_a_secret_var(everyday,
                                                                     tmp_path,
                                                                     monkeypatch):
    """The refusal happens before any device is contacted."""
    lab = nl.load_lab(LAB_TOML)
    lab.var_defs["wifi_psk"] = {"device": "local", "cmd": "true"}
    lab.var_defs["wifi_psk"]["secret"] = True
    lab.steps["show_secret"] = nl.Step(
        name="show_secret", device="lab-r1",
        cmd="uci get wireless.@wifi[0].key='{wifi_psk}'", timeout=30)
    scen = copy.copy(everyday[RULES_04])
    scen.before_confirm = ["show_secret"]

    def boom(*args, **kw):
        raise AssertionError("the runner contacted a device")

    monkeypatch.setattr(nl, "_run", boom)
    rec = nl.run_scenario(lab, scen)
    assert rec["passed"] is False
    assert "wifi_psk" in rec["error"]


def test_the_vars_of_a_before_confirm_step_are_resolved(tmp_path, monkeypatch):
    """The placeholders of a before_confirm step are resolved like the ones
    of a setup or a cleanup step: the step runs with the value, not with the
    placeholder."""
    lab = nl.load_lab(LAB_TOML)
    # a plain (not secret) var: the loader's default when the key is absent
    lab.var_defs["lan_ip"] = {"device": "local", "cmd": "echo lan"}
    scen = _scenario(tmp_path, HOLD_BODY_WITH_STEP)
    lab.steps["break_it"] = nl.Step(name="break_it", device="lab-r1",
                                     cmd="echo {lan_ip}", timeout=30)

    def fake_run(args, **kw):
        args = list(args)
        if args and args[0] == str(nl.OWRT_CHANGE):
            return _Runner()(args, **kw)
        if args[:2] == ["bash", "-c"]:
            return _cp(stdout="192.168.1.1\n")
        return _cp(stdout="ok\n")

    monkeypatch.setenv("NEWTON_LAB_VANTAGE_INVENTORY",
                       str(_inventory(tmp_path)))
    monkeypatch.setattr(nl, "RESULTS_DIR", tmp_path / "results")
    with mock.patch.object(nl, "_run", side_effect=fake_run):
        rec = nl.run_scenario(lab, scen)
    assert rec["vars"] == {"lan_ip": "192.168.1.1"}
    assert rec["before_confirm"][0]["cmd"] == "echo 192.168.1.1"
