"""Feature B: `[vars.NAME] secret = true`.

A secret var is read like any other var and substituted into the scenario
`batch` only. The value must not reach rec["vars"], the results JSON, the
runner's stdout/stderr, any rec text (plan_log, apply_log, the stdout/stderr of
steps, posts and probes) or the argv of any child process. Everything here runs
against fakes: no network, no Proxmox, no router ssh.
"""
from __future__ import annotations

from conftest import lab_toml_path

import json
import os
import stat
import subprocess
from pathlib import Path
from unittest import mock

import pytest

import newton_lab_test as nl


def _cp(stdout: str = "", stderr: str = "", returncode: int = 0):
    return subprocess.CompletedProcess(args=[], returncode=returncode,
                                       stdout=stdout, stderr=stderr)


CANARY = "CANARY-7f3a91c2-KEY-xyz"
PLAIN = "plain-value-1234"
SID = "a" * 32
BASEHASH = "b" * 64
APPLYBASE = "b" * 64


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

[vars.wifi_psk]
device = "local"
cmd = "read -r wlan_psk"
secret = true

[vars.lan_ip]
device = "local"
cmd = "echo lan-ip"
secret = false

[steps.mark]
device = "lab-r1"
cmd = "true"
description = "no-op marker step"

[steps.show_secret]
device = "lab-r1"
cmd = "uci get wireless.@wifi[0].key='{wifi_psk}'"
description = "a step that would put the secret in ssh argv"

[checks.ok]
device = "lab-r1"
cmd = "true"
description = "always passes"

[checks.shows_secret]
device = "lab-r1"
cmd = "uci get wireless.@wifi[0].key='{wifi_psk}'"
description = "a regression check that would put the secret in ssh argv"
"""


@pytest.fixture
def lab_path(tmp_path):
    path = tmp_path / "lab.toml"
    path.write_text(_LAB_TOML)
    return path


@pytest.fixture
def lab(lab_path):
    return nl.load_lab(lab_path)


class FakeRun:
    """Answers every child process the runner starts and records what it got.

    Every argv is kept (the /proc/<pid>/cmdline shape), and the batch temp file
    the plan wrapper was pointed at is read and stat'd while it still exists.
    """

    def __init__(self):
        self.argvs: list[list[str]] = []
        self.batch_paths: list[str] = []
        self.batch_texts: list[str] = []
        self.batch_modes: list[int] = []
        self.last_batch = ""

    def run(self, args, *, env=None, timeout=None, input=None):
        self.argvs.append(list(args))
        if args[:2] == ["bash", "-c"]:
            if "wlan_psk" in args[2]:
                return _cp(stdout=CANARY + "\n")
            return _cp(stdout=PLAIN + "\n")
        if len(args) > 1 and args[1] == "plan":
            path = args[3]
            self.batch_paths.append(path)
            self.batch_texts.append(Path(path).read_text())
            self.batch_modes.append(stat.S_IMODE(os.stat(path).st_mode))
            self.last_batch = Path(path).read_text().strip()
            return _cp(stdout=self.plan_out())
        if len(args) > 1 and args[1] == "apply":
            return _cp(stdout=self.apply_out())
        return _cp(returncode=0)

    def plan_out(self) -> str:
        return (f"STAGED session={SID}\n"
                f"BASEHASH {BASEHASH}\n"
                f"APPROVAL not-required\n"
                f"PLANDIGEST {'d' * 64}\n"
                "----- diff -----\n"
                f"{self.last_batch}\n"
                "----------------\n")

    def apply_out(self) -> str:
        return f"APPLYBASE {APPLYBASE}\nCONFIRMED session={SID}"

    def every_argv_text(self) -> str:
        return "\n".join(" ".join(a) for a in self.argvs)


def _no_contact():
    def boom(*a, **k):
        raise AssertionError("the runner contacted a device")
    return boom


SECRET_BODY = """
name = "01-secret"
description = "puts a secret var in the batch"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 60
batch = "set wireless.@wifi[0].key='{wifi_psk}'"

[[post]]
device = "lab-r1"
cmd = "true"
"""


def _scenario(tmp_path, body: str, name: str = "01-secret"):
    d = tmp_path / "scenarios"
    d.mkdir(exist_ok=True)
    (d / f"{name}.toml").write_text(body)
    return nl.load_scenarios(d)[0]


@pytest.fixture(autouse=True)
def _clear_secret_registry():
    """The runner keeps the resolved values it must mask for the write-time
    pass; each test starts from an empty set."""
    nl.SECRET_VALUES.clear()
    yield
    nl.SECRET_VALUES.clear()


# ---------- loading ----------

def test_secret_flag_parses(lab):
    assert lab.var_defs["wifi_psk"]["secret"] is True


def test_secret_false_and_absent_parse_as_false(lab):
    assert lab.var_defs["lan_ip"]["secret"] is False
    lab2 = nl.load_lab(lab_toml_path())
    assert all(v["secret"] is False for v in lab2.var_defs.values())


def test_secret_must_be_a_boolean(tmp_path):
    path = tmp_path / "lab.toml"
    path.write_text(_LAB_TOML.replace("secret = true", 'secret = "yes"'))
    with pytest.raises(nl.LabConfigError) as e:
        nl.load_lab(path)
    assert "vars.wifi_psk.secret" in str(e.value)


# ---------- the batch carries it, nothing else does ----------

def test_batch_the_plan_wrapper_got_contains_the_secret(lab, tmp_path, monkeypatch):
    """The proof the masking tests need: the secret really is substituted into
    the batch that travels to the change wrapper."""
    scen = _scenario(tmp_path, SECRET_BODY)
    fake = FakeRun()
    monkeypatch.setattr(nl, "_run", fake.run)
    rec = nl.run_scenario(lab, scen)
    assert rec["passed"] is True
    assert fake.batch_texts
    assert CANARY in fake.batch_texts[0]
    assert "wifi_psk" not in fake.batch_texts[0]


def test_batch_travels_in_a_0600_file_that_is_removed(lab, tmp_path,
                                                      monkeypatch):
    """Requirement: the batch must not be in argv, and the file it does travel
    in must be private and gone afterwards."""
    scen = _scenario(tmp_path, SECRET_BODY)
    fake = FakeRun()
    monkeypatch.setattr(nl, "_run", fake.run)
    nl.run_scenario(lab, scen)
    assert fake.batch_paths
    path = fake.batch_paths[0]
    assert path in fake.every_argv_text()          # argv carries the path only
    assert CANARY not in fake.every_argv_text()    # never the value
    assert fake.batch_modes == [0o600] * len(fake.batch_modes)
    assert not Path(path).exists()


def test_secret_is_absent_from_the_record(lab, tmp_path, monkeypatch):
    scen = _scenario(tmp_path, SECRET_BODY)
    fake = FakeRun()
    monkeypatch.setattr(nl, "_run", fake.run)
    rec = nl.run_scenario(lab, scen)
    assert CANARY not in repr(rec)
    assert rec["vars"] == {"wifi_psk": "<secret>"}


def test_secret_is_masked_in_plan_and_apply_logs(lab, tmp_path, monkeypatch):
    """The router's diff echoes the staged batch, so plan_log and apply_log
    carry the value until it is masked."""
    scen = _scenario(tmp_path, SECRET_BODY)
    fake = FakeRun()
    monkeypatch.setattr(nl, "_run", fake.run)
    rec = nl.run_scenario(lab, scen)
    assert CANARY in fake.plan_out()          # the value really was in the log
    assert CANARY not in rec["plan_log"]
    assert "***" in rec["plan_log"]
    assert CANARY not in rec["apply_log"]


def test_secret_is_absent_from_every_child_argv(lab, tmp_path, monkeypatch):
    scen = _scenario(tmp_path, SECRET_BODY)
    fake = FakeRun()
    monkeypatch.setattr(nl, "_run", fake.run)
    nl.run_scenario(lab, scen)
    assert fake.argvs
    assert CANARY not in fake.every_argv_text()


def test_plain_var_still_travels_and_is_recorded(lab, tmp_path, monkeypatch):
    body = SECRET_BODY.replace(
        'batch = "set wireless.@wifi[0].key=\'{wifi_psk}\'"',
        'batch = "set dhcp.lan.ipaddr=\'{lan_ip}\'"')
    scen = _scenario(tmp_path, body)
    fake = FakeRun()
    monkeypatch.setattr(nl, "_run", fake.run)
    rec = nl.run_scenario(lab, scen)
    assert rec["passed"] is True
    assert rec["vars"]["lan_ip"] == PLAIN
    assert PLAIN in fake.batch_texts[0]
    assert PLAIN in rec["plan_log"]


# ---------- end to end through main(): stdout, stderr, results JSON ----------

def test_canary_absent_from_stdout_results_and_argv(lab_path, tmp_path,
                                                    monkeypatch, capsys):
    d = tmp_path / "scenarios"
    d.mkdir()
    (d / "01-secret.toml").write_text(SECRET_BODY)
    fake = FakeRun()
    monkeypatch.setattr(nl, "_run", fake.run)
    monkeypatch.setattr(nl, "RESULTS_DIR", tmp_path / "results")
    results = tmp_path / "results.json"
    rc = nl.main(["--lab", str(lab_path), "--scenarios", str(d),
                  "--lane", "password", "--no-lab-reset",
                  "--results", str(results)])
    assert rc == 0
    out = capsys.readouterr()
    assert CANARY not in out.out
    assert CANARY not in out.err
    assert CANARY not in results.read_text()
    assert CANARY in fake.batch_texts[0]           # the test proves something
    assert CANARY not in fake.every_argv_text()
    payload = results.read_text()
    assert "<secret>" in payload
    assert "***" in payload


# ---------- a secret may only be used in the batch ----------

def _with_extra(body: str, extra: str) -> str:
    """Insert top-level `extra` lines before the first table of `body`: a key
    appended after [[post]] would belong to that table, not the scenario."""
    return body.replace("[[post]]", extra + "\n[[post]]")


REFUSAL_BODIES = {
    "setup": _with_extra(SECRET_BODY, 'setup = ["show_secret"]'),
    "cleanup": _with_extra(SECRET_BODY, 'cleanup = ["show_secret"]'),
    "post": SECRET_BODY.replace(
        '[[post]]\ndevice = "lab-r1"\ncmd = "true"',
        '[[post]]\ndevice = "lab-r1"\ncmd = "uci get wireless.@wifi[0].key=\'{wifi_psk}\'"'),
    "effect": SECRET_BODY + """
[[effect]]
device = "lab-r1"
cmd = "uci get wireless.@wifi[0].key='{wifi_psk}'"
""",
    "regression": _with_extra(SECRET_BODY, 'regression = ["shows_secret"]'),
}


@pytest.mark.parametrize("kind", sorted(REFUSAL_BODIES))
def test_a_cmd_referencing_a_secret_var_is_refused(kind, lab, tmp_path,
                                                  monkeypatch):
    scen = _scenario(tmp_path, REFUSAL_BODIES[kind])
    monkeypatch.setattr(nl, "_run", _no_contact())
    rec = nl.run_scenario(lab, scen)
    assert rec["error"] and "wifi_psk" in rec["error"]
    assert "batch" in rec["error"]
    assert rec["passed"] is False


@pytest.mark.parametrize("kind", sorted(REFUSAL_BODIES))
def test_validate_refuses_a_cmd_referencing_a_secret_var(kind, lab, tmp_path):
    scen = _scenario(tmp_path, REFUSAL_BODIES[kind])
    errs = nl.validate_scenarios(lab, [scen])
    assert any("wifi_psk" in e and "batch" in e for e in errs)


def test_refusal_happens_before_any_device_contact(lab, tmp_path, monkeypatch):
    """A scenario that resets devices and declares reset_after still contacts
    nothing: the refusal is the first thing the scenario runner does."""
    body = SECRET_BODY.replace("reset = []", 'reset = ["lab-r1"]')
    body = _with_extra(body, 'reset_after = ["lab-r1"]\nsetup = ["show_secret"]')
    scen = _scenario(tmp_path, body)
    monkeypatch.setattr(nl, "_run", _no_contact())
    monkeypatch.setattr(nl, "pve_rollback", _no_contact())
    rec = nl.run_scenario(lab, scen)
    assert rec["error"] and "wifi_psk" in rec["error"]
    assert rec["reset"] == []
    assert rec["reset_after"] == []


def test_a_lane_filtered_post_refuses_only_the_lane_that_runs_it(
        lab, tmp_path, monkeypatch):
    body = SECRET_BODY + """
[[post]]
device = "lab-r1"
cmd = "uci get wireless.@wifi[0].key='{wifi_psk}'"
lanes = ["password"]
"""
    scen = _scenario(tmp_path, body)
    fake = FakeRun()
    monkeypatch.setattr(nl, "_run", fake.run)
    rec = nl.run_scenario(lab, scen, lane="key")
    assert rec["passed"] is True
    # only the scenario's own (unrestricted) post ran
    assert [p["cmd"] for p in rec["post"]] == ["true"]
    # the static check has no lane and sees every post, so the scenario is
    # refused outright before a run
    errs = nl.validate_scenarios(lab, [scen])
    assert any("wifi_psk" in e for e in errs)


# ---------- the write-time pass (belt and braces) ----------

def test_write_time_mask_replaces_any_residue():
    nl.register_secret(CANARY)
    payload = '{"plan_log": "set wireless.key=\'' + CANARY + '\'"}\n'
    masked = nl.mask_payload_text(payload)
    assert CANARY not in masked
    assert masked.count("***") == 1
    json.loads(masked)          # still a valid results file


def test_an_empty_secret_value_masks_nothing():
    nl.register_secret("")
    assert nl.mask_payload_text("nothing to hide") == "nothing to hide"


def test_short_reason_and_summary_never_print_the_secret(lab, tmp_path,
                                                        monkeypatch, capsys):
    scen = _scenario(tmp_path, SECRET_BODY)
    fake = FakeRun()
    monkeypatch.setattr(nl, "_run", fake.run)
    rec = nl.run_scenario(lab, scen)
    rec["error"] = f"apply said {CANARY}"
    nl.print_summary([rec])
    out = capsys.readouterr().out
    assert CANARY not in out
    assert "***" in out