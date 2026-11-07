"""Unit tests for lab/newton-lab-test.py.

Mock subprocess throughout: no network, no Proxmox, no router SSH.
"""
from __future__ import annotations

from conftest import lab_toml_path

import json
import subprocess
import tomllib
import urllib.parse
from pathlib import Path
from unittest import mock

import pytest

import newton_lab_test as nl

LAB_DIR = Path(__file__).resolve().parent.parent
SCEN_DIR = LAB_DIR / "scenarios"
LAB_TOML = lab_toml_path()


def _cp(stdout: str = "", stderr: str = "", returncode: int = 0):
    return subprocess.CompletedProcess(args=[], returncode=returncode,
                                       stdout=stdout, stderr=stderr)


# A constant BASEHASH/APPLYBASE the existing fakes print so the design 9.4
# G3 equality check (BASEHASH == APPLYBASE) passes; the value itself is not
# tested anywhere else.
APPLYBASE_BB_HASH = "b" * 64


# ---------- Realistic plan refusal outputs ----------
# The router reason for "staging rejected" lives on STDERR; the marker line on
# stdout. These are the real shapes the helper scripts emit.

STAGING_REJECTED_STDOUT = "ERROR: staging rejected\n"

REJECT_04_STDERR = (
    "ERROR: only set/add/add_list/del_list/delete/rename/reorder are "
    "allowed, got: commit system\n"
)
REJECT_05_STDERR = (
    "ERROR: uci batch rejected the changes (exit 0), nothing staged: "
    "uci: Invalid argument\n"
)
REJECT_08_STDERR = (
    "ERROR: uci batch rejected the changes (exit 0), nothing staged: "
    "uci: Entry not found\n"
)
REJECT_05_EXIT1_STDERR = (
    "ERROR: uci batch rejected the changes (exit 1), nothing staged: "
    "uci: Invalid argument\n"
)
REJECT_08_EXIT1_STDERR = (
    "ERROR: uci batch rejected the changes (exit 1), nothing staged: "
    "uci: Entry not found\n"
)

# Other refusals of the same stage (still marker + stderr), the wrong reason
# for 04/05/08.
REJECT_STATE_OPEN_STDERR = (
    "ERROR: another transaction is open (session <sid>) — confirm or abort "
    "it first\n"
)
REJECT_STATE_CHANGES_STDERR = (
    "ERROR: uncommitted CLI changes exist (uci changes) — resolve them "
    "first\n"
)
REJECT_STATE_LOCK_STDERR = "ERROR: could not take transaction lock\n"

# The seven infra failures (rc 1, no marker): plan never reached the router.
INFRA_FAILURES = [
    ("stderr", "ERROR: password file not readable\n"),
    ("stderr", "ERROR: password file must be mode 600\n"),
    ("stdout", "ERROR: cannot push helper\n"),
    ("stdout", "ERROR: router unreachable\n"),
    ("stdout", "ERROR: backup failed or corrupt: /x\n"),
    ("stdout", "ERROR: changes file not readable: /x\n"),
    ("stdout", "ERROR: malformed or missing session id\n"),
]


def _refused_pair(stderr: str) -> dict:
    """The pair of stdout (marker) + stderr (router reason) that a plan prints
    when the router's stage step refused the batch (owrt-change.sh line 75)."""
    return {"stdout": STAGING_REJECTED_STDOUT, "stderr": stderr}


def _refused(where: str, text: str, returncode: int = 1):
    """Build a CompletedProcess for a single-stream text. where is 'stdout' or
    'stderr'; the other stream is empty."""
    if where == "stdout":
        return _cp(stdout=text, stderr="", returncode=returncode)
    return _cp(stdout="", stderr=text, returncode=returncode)


# ---------- Fixtures ----------

@pytest.fixture
def lab():
    return nl.load_lab(LAB_TOML)


@pytest.fixture
def scenarios():
    return nl.load_scenarios(SCEN_DIR)


@pytest.fixture
def fake_lab(tmp_path):
    """A self-contained lab.toml + scenarios/ for tests that must not touch the real config."""
    lab_toml = tmp_path / "lab.toml"
    lab_toml.write_text("""
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

[vars]
""")
    scen_dir = tmp_path / "scenarios"
    scen_dir.mkdir()
    return lab_toml, scen_dir


# ---------- TOML loading ----------

def test_load_lab_devices(lab):
    assert "lab-r1" in lab.devices
    r1 = lab.devices["lab-r1"]
    raw = tomllib.loads(LAB_TOML.read_text())["devices"]
    # the VM id is the lab file's own (the live file holds the real one)
    assert r1.vmid == int(raw["lab-r1"]["vmid"])
    assert r1.host == "10.109.0.11"
    assert r1.user == "root"
    # snapshot names are per device (lab-r1 differs from the others): follow lab.toml, never assume one name
    assert {n: d.snapshot for n, d in lab.devices.items()} == {n: d["snapshot"] for n, d in raw.items()}


def test_load_lab_expands_paths(lab):
    assert "~" not in lab.ssh_password_file
    assert "~" not in lab.ssh_key
    assert "~" not in lab.pve_token_file
    assert lab.ssh_password_file.endswith(".pw")


def test_load_lab_vars(lab):
    assert "r1_wan_ip" in lab.var_defs
    assert "client_lab_ip" in lab.var_defs
    assert lab.var_defs["r1_wan_ip"]["device"] == "lab-r1"
    assert lab.var_defs["client_lab_ip"]["device"] == "lab-client"


def test_load_scenarios_count_and_order(scenarios):
    names = [s.name for s in scenarios]
    assert len(scenarios) == 9
    expected = [
        "01-static-lease", "02-mgmt-ip-lockout", "03-mgmt-firewall-drop",
        "04-commit-smuggling", "05-bad-syntax", "06-port-forward-from-isp",
        "07-wan-down-isolation", "08-partial-batch", "09-add-section",
    ]
    assert names == expected


def test_scenarios_have_required_fields(scenarios):
    for s in scenarios:
        assert s.target in s.name or s.target in {"lab-r1", "lab-isp", "lab-client"}
        assert s.expect in nl.VALID_EXPECT
        assert s.batch.strip()
        assert 60 <= s.timeout <= 600
        # `check` is gone: the loader refuses it and Scenario has no slot for it
        assert not hasattr(s, "check")


def test_scenarios_consistent_expect_and_reset(scenarios):
    rejected = [s for s in scenarios if s.expect == "rejected"]
    for s in rejected:
        assert s.reset == [], f"{s.name} is rejected but resets {s.reset}"


# ---------- Var resolution ----------

def test_used_placeholders_basic():
    assert nl.used_placeholders("set foo='{a}'", "echo {b}") == {"a", "b"}


def test_used_placeholders_dedup():
    assert nl.used_placeholders("{a} {a} {b}", "{b}") == {"a", "b"}


def test_used_placeholders_ignores_braces_without_name():
    assert nl.used_placeholders("set foo='{0}'", "echo {bad name}") == set()


def test_substitute_full():
    assert nl.substitute("a={a} b={b}", {"a": "1", "b": "2"}) == "a=1 b=2"


def test_substitute_keeps_unknown():
    assert nl.substitute("a={a} c={c}", {"a": "1"}) == "a=1 c={c}"


def test_resolve_vars_only_used(lab):
    with mock.patch.object(nl, "_run", return_value=_cp(stdout="10.109.0.42\n")) as m:
        values, err = nl.resolve_vars(lab, {"r1_wan_ip"})
    assert err is None
    assert values == {"r1_wan_ip": "10.109.0.42"}
    assert m.call_count == 1


def test_resolve_vars_strips_stdout(lab):
    with mock.patch.object(nl, "_run", return_value=_cp(stdout="  1.2.3.4 \n\n")):
        values, err = nl.resolve_vars(lab, {"r1_wan_ip"})
    assert values == {"r1_wan_ip": "1.2.3.4"}


def test_resolve_vars_unknown_returns_error(lab):
    values, err = nl.resolve_vars(lab, {"does_not_exist"})
    assert values == {}
    assert err and "unknown var" in err


def test_resolve_vars_unused_not_called(lab):
    with mock.patch.object(nl, "_run") as m:
        values, err = nl.resolve_vars(lab, set())
    assert err is None
    assert values == {}
    m.assert_not_called()


def test_resolve_vars_cmd_failure(lab):
    with mock.patch.object(nl, "_run", return_value=_cp(returncode=1, stderr="boom")):
        values, err = nl.resolve_vars(lab, {"r1_wan_ip"})
    assert values == {}
    assert err and "failed" in err


def test_resolve_vars_local_runs_bash(lab):
    lab.var_defs["my_var"] = {"device": "local", "cmd": "echo hi"}
    with mock.patch.object(nl, "_run", return_value=_cp(stdout="hi\n")) as m:
        values, err = nl.resolve_vars(lab, {"my_var"})
    assert err is None
    assert values == {"my_var": "hi"}
    args = m.call_args[0][0]
    assert args[0:2] == ["bash", "-c"]


# ---------- Outcome classification ----------

APPLY_SID = "0123456789abcdef0123456789abcdef"

def test_classify_apply_confirmed():
    assert nl.classify_apply(0, f"CONFIRMED session={APPLY_SID} (3 passes)\n", "", APPLY_SID) == "confirmed"


def test_classify_apply_confirmed_in_stderr():
    assert nl.classify_apply(0, "", f"CONFIRMED session={APPLY_SID}", APPLY_SID) == "unknown"


def test_classify_apply_rolled_back():
    assert nl.classify_apply(1, f"ROLLBACK WINDOW PASSED session={APPLY_SID}\n", "", APPLY_SID) == "rolled_back"


def test_classify_apply_alert_is_unknown():
    assert nl.classify_apply(1, f"ALERT session={APPLY_SID}", "", APPLY_SID) == "unknown"


def test_classify_apply_outcome_unknown_text():
    assert nl.classify_apply(1, f"OUTCOME UNKNOWN session={APPLY_SID}", "", APPLY_SID) == "unknown"


def test_classify_apply_unexpected_text_is_unknown():
    assert nl.classify_apply(1, "some other failure", "", APPLY_SID) == "unknown"


def test_classify_apply_confirmed_text_but_exit_nonzero_is_unknown():
    # Confirmed requires both: text AND rc == 0
    assert nl.classify_apply(1, f"CONFIRMED session={APPLY_SID}", "", APPLY_SID) == "unknown"


def test_classify_apply_zero_rc_without_confirmed_is_unknown():
    assert nl.classify_apply(0, "all good but missing token", "", APPLY_SID) == "unknown"


@pytest.mark.parametrize("line", [
    "CONFIRMED session=ffffffffffffffffffffffffffffffff",
    "ROLLBACK WINDOW PASSED session=ffffffffffffffffffffffffffffffff",
    f"x CONFIRMED session={APPLY_SID}",
])
def test_classify_apply_rejects_wrong_session_or_unanchored_outcome(line):
    rc = 1 if line.startswith("ROLLBACK") else 0
    assert nl.classify_apply(rc, line, "", APPLY_SID) == "unknown"


def test_classify_apply_old_spoof_shape_is_unknown():
    stdout = (
        f"APPLIED session={APPLY_SID} rollback=60s\n"
        f"ROLLBACK WINDOW PASSED session={APPLY_SID}\n"
        f"VERIFY FAILED session={APPLY_SID} — not confirming\n"
        f"ALERT session={APPLY_SID} rolled back, but DNS/DHCP check failed\n"
    )
    assert nl.classify_apply(1, stdout, "", APPLY_SID) == "unknown"


@pytest.mark.parametrize(
    ("rc", "stdout", "expected"),
    [
        (0, f"CONFIRMED session={APPLY_SID}x", "unknown"),
        (1, f"ROLLBACK WINDOW PASSED session={APPLY_SID}x", "unknown"),
        (1, f"CONFIRMED session={APPLY_SID}", "unknown"),
        (0, f"ROLLBACK WINDOW PASSED session={APPLY_SID}", "unknown"),
        (0, f"CONFIRMED session={APPLY_SID}\nALERT session={APPLY_SID}", "unknown"),
        (0, f"ALERT session={APPLY_SID}\nCONFIRMED session={APPLY_SID}\n", "confirmed"),
        (1, f"ALERT session={APPLY_SID}\nROLLBACK WINDOW PASSED session={APPLY_SID}\n", "rolled_back"),
    ],
)
def test_classify_apply_strict_terminal_contract(rc, stdout, expected):
    """Kills M14-M20/M22: exact SID, required rc, and last non-empty line decide."""
    assert nl.classify_apply(rc, stdout, "ignored", APPLY_SID) == expected


REBOOT_REASON = (
    "service or firewall health was not compared after the rollback: "
    "health: not compared: the router rebooted during the window; "
    "the guard restored the config at boot")
# scripts/owrt-change.sh logs this shape when the rollback reason is only the reboot
REBOOT_TAIL = " \u2014 check the router now; latest backup in /x/backups (abort: gone)"


def _reboot_alert(sid=APPLY_SID, reason=REBOOT_REASON, tail=REBOOT_TAIL):
    return f"ALERT session={sid} rolled back, but {reason}{tail}"


def test_classify_apply_reboot_restored_alert():
    """P-R01: the in-window reboot ALERT is its own class, not unknown."""
    stdout = f"APPLIED session={APPLY_SID} rollback=60s\n{_reboot_alert()}\n"
    assert nl.classify_apply(1, stdout, "", APPLY_SID) == "rebooted_restored"


def test_classify_apply_reboot_restored_needs_exit_1_and_stdout_and_final_line():
    assert nl.classify_apply(0, _reboot_alert(), "", APPLY_SID) == "unknown"
    assert nl.classify_apply(1, "", _reboot_alert(), APPLY_SID) == "unknown"
    assert nl.classify_apply(
        1, _reboot_alert() + "\nsomething after\n", "", APPLY_SID) == "unknown"


def test_classify_apply_reboot_restored_is_session_bound():
    other = "f" * 32
    assert nl.classify_apply(1, _reboot_alert(sid=other), "", APPLY_SID) == "unknown"
    assert nl.classify_apply(1, _reboot_alert(sid=APPLY_SID + "0"), "", APPLY_SID) == "unknown"


@pytest.mark.parametrize("line", [
    # the other not-compared reason (a plain health read failure)
    f"ALERT session={APPLY_SID} rolled back, but service or firewall health was not compared after the rollback: health: not compared: router unreachable{REBOOT_TAIL}",
    # health differs
    f"ALERT session={APPLY_SID} rolled back, but service or firewall health differs from before the apply after the rollback: health: dnsmasq stopped{REBOOT_TAIL}",
    # reboot reason plus a second reason: not a clean restore
    _reboot_alert(reason=REBOOT_REASON + "; logd is not running after the rollback (was pid 5)"),
    # the config-differs ALERT quotes the reason after 'also:'
    f"ALERT session={APPLY_SID} status=rolled-back after the rollback window, but the committed config differs from its state before the apply in: dhcp; also: {REBOOT_REASON}{REBOOT_TAIL}",
    f"ALERT session={APPLY_SID} abort did not report success: x{REBOOT_TAIL}",
    f"ALERT session={APPLY_SID} status=confirmed after the rollback window{REBOOT_TAIL}",
    f"ALERT session={APPLY_SID}",
    # the reboot text embedded in an unrelated line
    f"x {_reboot_alert()}",
])
def test_classify_apply_reboot_class_does_not_swallow_other_alerts(line):
    assert nl.classify_apply(1, line, "", APPLY_SID) == "unknown"


def test_classify_apply_unknown_alert_still_unknown_and_fails_scenario():
    stdout = f"ALERT session={APPLY_SID} status=unexpected (zzz) after rollback window"
    assert nl.classify_apply(1, stdout, "", APPLY_SID) == "unknown"
    # an unknown outcome can never equal any expect a scenario may name
    assert "unknown" not in nl.VALID_EXPECT


def test_rebooted_restored_is_a_valid_expect():
    assert "rebooted_restored" in nl.VALID_EXPECT


def test_p_r01_expects_rebooted_restored():
    scens = nl.load_scenarios(Path(nl.__file__).resolve().parent / "scenarios-pulsar")
    (s,) = [x for x in scens if x.name == "p-r01-reboot-in-window"]
    assert s.expect == "rebooted_restored"


def test_rebooted_restored_post_checks_run_like_rolled_back():
    scen = nl.Scenario(
        name="x", description="", target="t", reset=[], expect="rebooted_restored",
        timeout=60, batch="b", post=[], path=Path("x.toml"),
        regression=["reg"], breaks=["brk"],
        effects=[nl.Post("local", "true")])
    checks = {"reg": nl.Post("local", "r"), "brk": nl.Post("local", "b")}
    def roles(outcome):
        items = nl._build_after_probes(scen, mock.Mock(regression_default=[]), outcome,
                                       scen.effects, checks, scen.breaks)
        return [(i[1], i[2], i[3]) for i in items]
    assert roles("rebooted_restored") == roles("rolled_back")
    assert roles("rebooted_restored") != roles("confirmed")


def test_classify_apply_refused_with_health_gate_marker():
    """The apply-time health gate (scripts/owrt-change.sh line ~466) dies
    with 'cannot record service and firewall health before the apply;
    nothing applied, session <SID> is still staged; helper said: ...'
    when fw4 check fails on the running config. classify_apply must
    return 'refused' for any rc != 0 and the narrow marker present, so
    the runner calls abort_batch and the refuse_match pattern can be
    checked against the helper's reason."""
    sid = "7" * 32
    aout = (
        f"ERROR: cannot record service and firewall health before the apply; "
        f"nothing applied, session {sid} is still staged; helper said: "
        f"the firewall config already fails fw4 check before the change: "
        f"Could not resolve protocol name; fix it first\n"
    )
    assert nl.classify_apply(1, "", aout, sid) == "refused"


def test_classify_apply_other_die_text_keeps_unknown():
    """A different owrt-change.sh die text that also contains 'nothing
    applied' (here: 'router unreachable before apply; nothing applied,
    session X is still staged') must NOT be classified refused. The
    health-gate marker is the only one that maps to 'refused'; a
    router-unreachable mid-apply stays 'unknown' and the runner
    treats it as a normal failure (no abort, no refuse_match check)."""
    sid = "8" * 32
    aout = (
        f"ERROR: router unreachable before apply; nothing applied, "
        f"session {sid} is still staged\n"
    )
    assert nl.classify_apply(1, "", aout, sid) == "unknown"


def test_classify_apply_health_gate_marker_requires_nonzero_rc():
    """The health-gate marker alone, without rc != 0, must NOT be
    classified refused (a ref check with rc 0 is still a failed
    outcome from the runner's view, but a different code path)."""
    aout = (
        f"ERROR: cannot record service and firewall health before the apply; "
        f"nothing applied, session {APPLY_SID} is still staged; helper said: "
        f"the firewall config already fails fw4 check before the change\n"
    )
    assert nl.classify_apply(0, "", aout, APPLY_SID) == "unknown"


# ---------- Post-conditions ----------

def test_post_rc_pass():
    p = nl.Post(device="local", cmd="true")
    with mock.patch.object(nl, "_run", return_value=_cp(returncode=0)):
        r = nl.run_post(nl.load_lab(LAB_TOML), p)
    assert r["passed"] is True


def test_post_rc_fail():
    p = nl.Post(device="local", cmd="false", expect_rc=0)
    with mock.patch.object(nl, "_run", return_value=_cp(returncode=1)):
        r = nl.run_post(nl.load_lab(LAB_TOML), p)
    assert r["passed"] is False
    assert "rc" in r["reason"]


def test_post_regex_pass():
    p = nl.Post(device="local", cmd="x", expect_stdout="^10\\.109\\.0\\.11$")
    with mock.patch.object(nl, "_run", return_value=_cp(stdout="10.109.0.11\n")):
        r = nl.run_post(nl.load_lab(LAB_TOML), p)
    assert r["passed"] is True


def test_post_regex_no_match():
    p = nl.Post(device="local", cmd="x", expect_stdout="^NOPE$")
    with mock.patch.object(nl, "_run", return_value=_cp(stdout="10.109.0.11\n")):
        r = nl.run_post(nl.load_lab(LAB_TOML), p)
    assert r["passed"] is False
    assert "stdout" in r["reason"]


def test_post_truncates_output():
    p = nl.Post(device="local", cmd="x")
    big = "x" * 5000
    with mock.patch.object(nl, "_run", return_value=_cp(stdout=big, stderr=big)):
        r = nl.run_post(nl.load_lab(LAB_TOML), p)
    assert len(r["stdout"]) == nl.MAX_POST
    assert len(r["stderr"]) == nl.MAX_POST


def test_post_unknown_device():
    p = nl.Post(device="no-such-device", cmd="true")
    r = nl.run_post(nl.load_lab(LAB_TOML), p)
    assert r["passed"] is False
    assert "unknown device" in r["reason"]


def test_post_uses_ssh_for_device():
    p = nl.Post(device="lab-r1", cmd="true")
    with mock.patch.object(nl, "_run", return_value=_cp()) as m:
        nl.run_post(nl.load_lab(LAB_TOML), p)
    args = m.call_args[0][0]
    assert args[0] == "ssh"
    assert "-i" in args
    assert "BatchMode=yes" in args
    assert "StrictHostKeyChecking=accept-new" in args
    assert "ConnectTimeout=8" in args
    assert any(a.startswith("ProxyCommand=") for a in args)
    assert "root@10.109.0.11" in args


# ---------- Reset / Proxmox ----------

def test_pve_rollback_uses_start1_and_rollback_path(lab):
    r1 = lab.devices["lab-r1"]
    with mock.patch.object(nl, "_run",
                           return_value=_cp(stdout=json.dumps({"data": "UPID:abc"}))) as m:
        upid = nl.pve_rollback(lab, r1)
    assert upid == "UPID:abc"
    args = m.call_args[0][0]
    assert args[0] == "curl"
    di = args.index("-d")
    assert args[di + 1] == "start=1"
    mi = args.index("-X")
    assert args[mi + 1] == "POST"
    assert args[-1].endswith(f"/qemu/{r1.vmid}/snapshot/{r1.snapshot}/rollback")


def test_pve_rollback_per_device(lab):
    isp = lab.devices["lab-isp"]
    with mock.patch.object(nl, "_run",
                           return_value=_cp(stdout=json.dumps({"data": "UPID"}))) as m:
        nl.pve_rollback(lab, isp)
    assert f"/qemu/{isp.vmid}/snapshot/{isp.snapshot}/rollback" in m.call_args[0][0][-1]


def test_pve_wait_task_ok_true(lab):
    with mock.patch.object(nl, "pve_task_status",
                           return_value={"status": "stopped", "exitstatus": "OK"}):
        assert nl.pve_wait_task_ok(lab, "UPID", timeout_s=5) is True


def test_pve_wait_task_ok_false_on_error_exit(lab):
    with mock.patch.object(nl, "pve_task_status",
                           return_value={"status": "stopped", "exitstatus": "ERROR"}):
        assert nl.pve_wait_task_ok(lab, "UPID", timeout_s=5) is False


def test_pve_wait_task_ok_false_on_timeout(lab):
    with mock.patch.object(nl, "pve_task_status",
                           return_value={"status": "running"}), \
         mock.patch("newton_lab_test.time.sleep"):
        assert nl.pve_wait_task_ok(lab, "UPID", timeout_s=0) is False


def test_pve_task_status_url_encodes_upid(lab):
    with mock.patch.object(nl, "_run",
                           return_value=_cp(stdout=json.dumps({"data": {"status": "stopped"}}))) as m:
        nl.pve_task_status(lab, "UPID:abc/123")
    url = m.call_args[0][0][-1]
    assert "UPID%3Aabc%2F123" in url


# ---------- Proxmox curl retry on rc=7 (could not connect) ----------
#
# A 0.1 s PVE API outage made curl exit 7 once (request never sent) and took
# 15 scenarios down with it. _curl_pve must retry ONLY when rc==7, up to
# PVE_CURL_MAX_ATTEMPTS (4) attempts with PVE_CURL_RETRY_SLEEPS_S = [2, 5, 10]
# seconds between them, logging each retry to stderr in the existing style
# ("pve: curl rc=7 (could not connect), retry 1/3 in 2 s"). Any other non-zero
# exit raises immediately. The retry sleep is patchable via the module's
# `time.sleep` (the conftest already monkeypatches it).

PVE_CURL_URL = "https://pve.test:8006/api2/json/nodes/lab/status"


def _pve_curl_side_effect(rcs, success_stdout):
    """Build a side_effect list of CompletedProcess for _curl_pve: rc=7 for
    the given count, then success with `success_stdout`. The successes all
    parse as JSON with a "data" key."""
    out = [_cp(returncode=7, stderr="curl: (7) Could not connect") for _ in rcs]
    out.append(_cp(returncode=0, stdout=success_stdout))
    return out


def test_pve_retry_rc7_twice_then_succeeds(lab, capsys, monkeypatch):
    """Two rc=7 failures then success: returns the parsed data, 2 retry log
    lines, sleeps [2, 5]; no third sleep (succeeded on the 3rd attempt)."""
    sleeps: list[float] = []
    monkeypatch.setattr(nl.time, "sleep",
                        lambda s, *a, **k: sleeps.append(s))
    side = _pve_curl_side_effect(rcs=[7, 7], success_stdout=json.dumps(
        {"data": {"status": "running"}}))
    with mock.patch.object(nl, "_run", side_effect=side) as m:
        data = nl._curl_pve(lab, PVE_CURL_URL)
    assert data == {"status": "running"}
    assert m.call_count == 3
    assert sleeps == [2, 5]
    err = capsys.readouterr().err
    assert "pve: curl rc=7 (could not connect), retry 1/3 in 2 s" in err
    assert "pve: curl rc=7 (could not connect), retry 2/3 in 5 s" in err
    # No third retry line — the third attempt succeeded.
    assert "retry 3/3" not in err


def test_pve_retry_rc7_four_times_raises(lab, capsys, monkeypatch):
    """Four rc=7 in a row: RuntimeError after all 4 attempts, sleeps
    [2, 5, 10], 3 retry log lines (1/3, 2/3, 3/3); no 4th retry."""
    sleeps: list[float] = []
    monkeypatch.setattr(nl.time, "sleep",
                        lambda s, *a, **k: sleeps.append(s))
    side = [_cp(returncode=7, stderr="curl: (7) Could not connect")
            for _ in range(4)]
    with mock.patch.object(nl, "_run", side_effect=side) as m:
        with pytest.raises(RuntimeError) as exc:
            nl._curl_pve(lab, PVE_CURL_URL)
    assert "curl failed rc=7" in str(exc.value)
    assert m.call_count == 4
    assert sleeps == [2, 5, 10]
    err = capsys.readouterr().err
    assert "retry 1/3 in 2 s" in err
    assert "retry 2/3 in 5 s" in err
    assert "retry 3/3 in 10 s" in err


def test_pve_retry_rc28_raises_immediately(lab, capsys, monkeypatch):
    """rc=28 (timeout) is not a transient connection failure: raise at once,
    no sleep, exactly one _run call, no retry log lines."""
    sleeps: list[float] = []
    monkeypatch.setattr(nl.time, "sleep",
                        lambda s, *a, **k: sleeps.append(s))
    side = [_cp(returncode=28, stderr="curl: (28) Operation timed out")]
    with mock.patch.object(nl, "_run", side_effect=side) as m:
        with pytest.raises(RuntimeError) as exc:
            nl._curl_pve(lab, PVE_CURL_URL)
    assert "rc=28" in str(exc.value)
    assert m.call_count == 1
    assert sleeps == []
    err = capsys.readouterr().err
    assert "retry" not in err


def test_pve_retry_rc0_first_no_sleep(lab, capsys, monkeypatch):
    """rc=0 on the first call: return the data, no sleep, no retry log."""
    sleeps: list[float] = []
    monkeypatch.setattr(nl.time, "sleep",
                        lambda s, *a, **k: sleeps.append(s))
    side = [_cp(returncode=0, stdout=json.dumps({"data": {"status": "ok"}}))]
    with mock.patch.object(nl, "_run", side_effect=side) as m:
        data = nl._curl_pve(lab, PVE_CURL_URL)
    assert data == {"status": "ok"}
    assert m.call_count == 1
    assert sleeps == []
    assert "retry" not in capsys.readouterr().err


# ---------- Password secrecy ----------

def test_password_path_in_env_not_contents(capsys):
    lab = nl.load_lab(LAB_TOML)
    env = nl.build_env(lab)
    blob = json.dumps(env)
    # The path is fine to serialise; assert it ends with .pw so we know which env var it is.
    assert env["OWRT_SSH_PASSWORD_FILE"].endswith(".pw")
    # The contents of any hypothetical file must not be in the env.
    assert "secret" not in blob.lower()


def test_password_contents_never_in_output(capsys, tmp_path, monkeypatch):
    fake_pw = "HUNTER2_THIS_MUST_NEVER_APPEAR"
    pwf = tmp_path / "lab-root.pw"
    pwf.write_text(fake_pw)
    lab_toml = tmp_path / "lab.toml"
    lab_toml.write_text(f"""
[pve]
host = "pve.test"
node = "lab"
token_file = "~/.config/pve/token"
pin_file = "~/.config/pve/pin"
[ssh]
proxy = "ssh -W %h:%p root@pve.test"
password_file = "{pwf}"
key = "~/.ssh/key"
[devices.lab-r1]
vmid = 9102
host = "10.109.0.11"
user = "root"
snapshot = "baseline"
[vars]
""")
    scen_dir = tmp_path / "scenarios"
    scen_dir.mkdir()
    (scen_dir / "01-x.toml").write_text("""
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "rejected"
timeout = 60
batch = "set system.@system[0].description='x'"
[[post]]
device = "lab-r1"
cmd = "true"
""")
    lab = nl.load_lab(lab_toml)
    scens = nl.load_scenarios(scen_dir)
    with mock.patch.object(nl, "_run", side_effect=[
        _cp(returncode=1, stderr="ERROR: staging rejected"),
        _cp(returncode=0),
    ]):
        nl.run_scenario(lab, scens[0])
    out = capsys.readouterr()
    assert fake_pw not in out.out
    assert fake_pw not in out.err


def test_password_file_contents_never_read_by_runner(tmp_path, monkeypatch):
    pwf = tmp_path / "lab-root.pw"
    pwf.write_text("CONTENTS_MUST_NEVER_BE_READ")
    lab_toml = tmp_path / "lab.toml"
    lab_toml.write_text(f"""
[pve]
host = "pve"
node = "n"
token_file = "~/.config/pve/token"
pin_file = "~/.config/pve/pin"
[ssh]
proxy = "ssh -W %h:%p root@pve"
password_file = "{pwf}"
key = "~/.ssh/k"
[devices.lab-r1]
vmid = 9102
host = "10.109.0.11"
user = "root"
snapshot = "baseline"
[vars]
""")
    real_read_text = Path.read_text

    def spy(self, *a, **kw):
        if str(self) == str(pwf):
            raise AssertionError("runner must not read the password file's contents")
        return real_read_text(self, *a, **kw)

    monkeypatch.setattr(Path, "read_text", spy)
    lab = nl.load_lab(lab_toml)
    # build_env and any reset/var resolution must not touch the password file.
    nl.build_env(lab)
    nl.run_scenario(lab, nl.Scenario(
        name="x", description="", target="lab-r1", reset=[],
        expect="rejected", timeout=60,
        batch="set foo", post=[], path=tmp_path / "scenarios" / "x.toml",
    ))


# ---------- --only filtering & list ----------

def test_only_filter_preserves_file_order(scenarios):
    wanted = {"05-bad-syntax", "01-static-lease"}
    filtered = [s for s in scenarios if s.name in wanted]
    assert [s.name for s in filtered] == ["01-static-lease", "05-bad-syntax"]


def test_main_only_unknown_returns_2(capsys):
    rc = nl.main(["--lab", str(LAB_TOML), "--only", "no-such-scenario"])
    assert rc == 2
    assert "no-such-scenario" in capsys.readouterr().err


def test_main_list_prints_all_seven(capsys):
    rc = nl.main(["--lab", str(LAB_TOML), "--list"])
    assert rc == 0
    out = capsys.readouterr().out
    for name in ["01-static-lease", "02-mgmt-ip-lockout", "03-mgmt-firewall-drop",
                 "04-commit-smuggling", "05-bad-syntax", "06-port-forward-from-isp",
                 "07-wan-down-isolation"]:
        assert name in out


def test_main_list_does_no_subprocess(capsys):
    with mock.patch.object(nl, "_run") as m:
        rc = nl.main(["--lab", str(LAB_TOML), "--list"])
    assert rc == 0
    m.assert_not_called()


def test_main_only_known_filters(monkeypatch, capsys, fake_lab):
    lab_toml, scen_dir = fake_lab
    (scen_dir / "01-a.toml").write_text("""
name = "01-a"
description = "a"
target = "lab-r1"
reset = []
expect = "rejected"
timeout = 60
batch = "set foo"
reject_match = "unit-test reason"
[[post]]
device = "lab-r1"
cmd = "true"
""")
    (scen_dir / "02-b.toml").write_text("""
name = "02-b"
description = "b"
target = "lab-r1"
reset = []
expect = "rejected"
timeout = 60
batch = "set bar"
reject_match = "unit-test reason"
[[post]]
device = "lab-r1"
cmd = "true"
""")
    monkeypatch.setattr(nl, "SCEN_DIR", scen_dir)
    monkeypatch.setattr(nl, "RESULTS_DIR", scen_dir / "results")
    with mock.patch.object(nl, "_run", side_effect=[
        _cp(returncode=1, stdout="ERROR: staging rejected\n",
            stderr="ERROR: unit-test reason\n"),
        _cp(returncode=0),
    ]) as m_run:
        rc = nl.main(["--lab", str(lab_toml), "--lane", "password", "--only", "02-b", "--results",
                      str(scen_dir / "r.json"), "--no-lab-reset"])
    # _run called once for plan (rejected) and once for post — only scenario 02-b
    assert m_run.call_count == 2
    assert rc in (0, 1)


# ---------- Exit code contract ----------

def test_exit_zero_when_all_pass(fake_lab, monkeypatch):
    lab_toml, scen_dir = fake_lab
    (scen_dir / "01-a.toml").write_text("""
name = "01-a"
description = "a"
target = "lab-r1"
reset = []
expect = "rejected"
timeout = 60
batch = "set foo"
reject_match = "unit-test reason"
[[post]]
device = "lab-r1"
cmd = "true"
""")
    monkeypatch.setattr(nl, "SCEN_DIR", scen_dir)
    monkeypatch.setattr(nl, "RESULTS_DIR", scen_dir / "results")
    with mock.patch.object(nl, "_run", side_effect=[
        _cp(returncode=1, stdout="ERROR: staging rejected\n",
            stderr="ERROR: unit-test reason\n"),
        _cp(returncode=0),
    ]):
        rc = nl.main(["--lab", str(lab_toml), "--lane", "password", "--results",
                      str(scen_dir / "r.json"), "--no-lab-reset"])
    assert rc == 0


def test_staged_fw4_failure_counts_as_rejected(fake_lab, monkeypatch):
    # owrt-change.sh plan dies with "staged firewall config fails fw4 check ... discarded"
    lab_toml, scen_dir = fake_lab
    (scen_dir / "01-a.toml").write_text("""
name = "01-a"
description = "a"
target = "lab-r1"
reset = []
expect = "rejected"
timeout = 60
batch = "set foo"
reject_match = "fails fw4 check"
[[post]]
device = "lab-r1"
cmd = "true"
""")
    monkeypatch.setattr(nl, "SCEN_DIR", scen_dir)
    monkeypatch.setattr(nl, "RESULTS_DIR", scen_dir / "results")
    with mock.patch.object(nl, "_run", side_effect=[
        _cp(returncode=1, stderr="ERROR: staged firewall config fails fw4 check: Could not resolve protocol name; "
                                 "the staged change was discarded\n"),
        _cp(returncode=0),
    ]):
        rc = nl.main(["--lab", str(lab_toml), "--lane", "password", "--results",
                      str(scen_dir / "r.json"), "--no-lab-reset"])
    assert rc == 0


_PM_SCEN = """
name = "01-a"
description = "a"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 60
batch = "set foo=bar"
plan_match = "%s"
[[post]]
device = "lab-r1"
cmd = "uci get foo"
expect_stdout = "^bar$"
"""


def _run_plan_match(fake_lab, pattern, plan_extra):
    lab_toml, scen_dir = fake_lab
    (scen_dir / "01-a.toml").write_text(_PM_SCEN % pattern)
    lab = nl.load_lab(lab_toml)
    scens = nl.load_scenarios(scen_dir)
    sid = "a" * 32
    plan_out = (
        f"STAGED session={sid}\n{plan_extra}"
        f"BASEHASH {APPLYBASE_BB_HASH}\n"
        "----- diff -----\nset foo=bar\n----------------\n"
    )
    apply_out = f"APPLYBASE {APPLYBASE_BB_HASH}\nCONFIRMED session={sid}"
    with mock.patch.object(nl, "_run", side_effect=[
        _cp(stdout=plan_out), _cp(stdout=apply_out),
        _cp(returncode=0, stdout="bar\n"),
    ]):
        return nl.run_scenario(lab, scens[0])


def test_plan_match_present_passes(fake_lab):
    rec = _run_plan_match(fake_lab, "STAGEDCHECK fw4 pass", "STAGEDCHECK fw4 pass\n")
    assert rec["passed"] is True
    assert rec["plan_match"]["matched"] is True


def test_plan_match_absent_fails_with_reason(fake_lab):
    rec = _run_plan_match(fake_lab, "STAGEDCHECK fw4 pass",
                          "STAGEDCHECK fw4 skipped-untouched\n")
    assert rec["passed"] is False
    assert rec["plan_match"]["matched"] is False
    assert "plan_match" in nl.short_reason(rec)


def test_plan_match_invalid_regex_is_refused(fake_lab):
    lab_toml, scen_dir = fake_lab
    (scen_dir / "01-a.toml").write_text(_PM_SCEN % "(unclosed")
    errs = nl.validate_scenarios(nl.load_lab(lab_toml), nl.load_scenarios(scen_dir))
    assert any("plan_match" in e and "regex" in e for e in errs)


def test_plan_match_refused_with_rejected(fake_lab):
    lab_toml, scen_dir = fake_lab
    (scen_dir / "01-a.toml").write_text(
        (_PM_SCEN % "x").replace('expect = "confirmed"',
                                 'expect = "rejected"\nreject_match = "y"'))
    errs = nl.validate_scenarios(nl.load_lab(lab_toml), nl.load_scenarios(scen_dir))
    assert any("plan_match" in e for e in errs)


def test_exit_nonzero_when_scenario_fails(fake_lab, monkeypatch):
    lab_toml, scen_dir = fake_lab
    (scen_dir / "01-a.toml").write_text("""
name = "01-a"
description = "a"
target = "lab-r1"
reset = []
expect = "rejected"
timeout = 60
batch = "set foo"
reject_match = "unit-test reason"
[[post]]
device = "lab-r1"
cmd = "true"
""")
    monkeypatch.setattr(nl, "SCEN_DIR", scen_dir)
    monkeypatch.setattr(nl, "RESULTS_DIR", scen_dir / "results")
    # Plan succeeds but apply fails unexpectedly: outcome=unknown != rejected => fail
    sid = "a" * 32
    with mock.patch.object(nl, "_run", side_effect=[
        _cp(stdout=f"STAGED session={sid}\n----- diff -----\n...\n----------------\n"),
        _cp(returncode=2, stderr="apply broke"),
        _cp(returncode=0),  # post (we still run posts)
    ]):
        rc = nl.main(["--lab", str(lab_toml), "--lane", "password", "--results",
                      str(scen_dir / "r.json"), "--no-lab-reset"])
    assert rc != 0


def test_exit_nonzero_when_error(fake_lab, monkeypatch):
    lab_toml, scen_dir = fake_lab
    (scen_dir / "01-a.toml").write_text("""
name = "01-a"
description = "a"
target = "lab-r1"
reset = []
expect = "rejected"
timeout = 60
batch = "set foo"
reject_match = "unit-test reason"
[[post]]
device = "lab-r1"
cmd = "true"
""")
    monkeypatch.setattr(nl, "SCEN_DIR", scen_dir)
    monkeypatch.setattr(nl, "RESULTS_DIR", scen_dir / "results")
    with mock.patch.object(nl, "_run", side_effect=RuntimeError("boom")):
        rc = nl.main(["--lab", str(lab_toml), "--lane", "password", "--results",
                      str(scen_dir / "r.json"), "--no-lab-reset"])
    assert rc != 0


# ---------- Run scenario happy-path integration (mocked) ----------

def test_run_scenario_confirmed_happy_path(fake_lab, monkeypatch):
    lab_toml, scen_dir = fake_lab
    (scen_dir / "01-a.toml").write_text("""
name = "01-a"
description = "a"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 60
batch = "set foo=bar"
[[post]]
device = "lab-r1"
cmd = "uci get foo"
expect_stdout = "^bar$"
""")
    lab = nl.load_lab(lab_toml)
    scens = nl.load_scenarios(scen_dir)
    sid = "a" * 32
    plan_out = (
        f"STAGED session={sid}\n"
        f"BASEHASH {APPLYBASE_BB_HASH}\n"
        "----- diff -----\nset foo=bar\n----------------\n"
    )
    apply_out = (
        f"APPLYBASE {APPLYBASE_BB_HASH}\n"
        f"CONFIRMED session={sid}"
    )
    with mock.patch.object(nl, "_run", side_effect=[
        _cp(stdout=plan_out),
        _cp(stdout=apply_out),
        _cp(returncode=0, stdout="bar\n"),
    ]):
        rec = nl.run_scenario(lab, scens[0])
    assert rec["passed"] is True
    assert rec["error"] is None
    assert rec["outcome"] == "confirmed"
    assert rec["expected"] == "confirmed"
    assert rec["post"][0]["passed"] is True


def test_run_scenario_rejected_no_apply(fake_lab, monkeypatch):
    lab_toml, scen_dir = fake_lab
    (scen_dir / "01-a.toml").write_text("""
name = "01-a"
description = "a"
target = "lab-r1"
reset = []
expect = "rejected"
timeout = 60
batch = "commit system"
[[post]]
device = "lab-r1"
cmd = "true"
""")
    lab = nl.load_lab(lab_toml)
    scens = nl.load_scenarios(scen_dir)
    with mock.patch.object(nl, "_run", side_effect=[
        _cp(returncode=1, stdout="ERROR: staging rejected\n",
            stderr="ERROR: only set/add/add_list/del_list/delete/rename/reorder are allowed, got: commit system\n"),
        _cp(returncode=0),
    ]):
        rec = nl.run_scenario(lab, scens[0])
    assert rec["outcome"] == "rejected"
    assert rec["passed"] is True
    assert rec["apply_log"] == ""


# ---------- Design 9.4 G3: APPLYBASE == BASEHASH ----------

def test_applybase_match_recorded_and_scenario_passes(fake_lab, monkeypatch):
    """Happy path: the plan's BASEHASH equals the apply's APPLYBASE.
    rec["base"] records both shas + match=True; scenario passes."""
    lab_toml, scen_dir = fake_lab
    (scen_dir / "01-a.toml").write_text("""
name = "01-a"
description = "a"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 60
batch = "set foo=bar"
[[post]]
device = "lab-r1"
cmd = "true"
""")
    lab = nl.load_lab(lab_toml)
    scens = nl.load_scenarios(scen_dir)
    sid = "a" * 32
    base_sha = "b" * 64
    plan_out = (
        f"STAGED session={sid}\n"
        f"BASEHASH {base_sha}\n"
        "----- diff -----\nset foo=bar\n----------------\n"
    )
    apply_out = (
        f"APPLYBASE {base_sha}\n"
        f"APPLIED session={sid} rollback=60s\n"
        f"CONFIRMED session={sid}\n"
    )
    with mock.patch.object(nl, "_run", side_effect=[
        _cp(stdout=plan_out),
        _cp(stdout=apply_out),
        _cp(returncode=0),
    ]):
        rec = nl.run_scenario(lab, scens[0])
    assert rec["outcome"] == "confirmed"
    assert rec["passed"] is True
    assert rec["error"] is None
    assert rec["base"] == {"plan": base_sha, "apply": base_sha, "match": True}


def test_applybase_mismatch_fails_scenario(fake_lab, monkeypatch):
    """apply prints an APPLYBASE that does not match the plan's BASEHASH:
    rec["base"] records both shas + match=False and the scenario fails
    with a clear error naming the two shas."""
    lab_toml, scen_dir = fake_lab
    (scen_dir / "01-a.toml").write_text("""
name = "01-a"
description = "a"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 60
batch = "set foo=bar"
[[post]]
device = "lab-r1"
cmd = "true"
""")
    lab = nl.load_lab(lab_toml)
    scens = nl.load_scenarios(scen_dir)
    sid = "a" * 32
    plan_base = "b" * 64
    apply_base = "c" * 64
    plan_out = (
        f"STAGED session={sid}\n"
        f"BASEHASH {plan_base}\n"
        "----- diff -----\nset foo=bar\n----------------\n"
    )
    apply_out = (
        f"APPLYBASE {apply_base}\n"
        f"APPLIED session={sid} rollback=60s\n"
        f"CONFIRMED session={sid}\n"
    )
    with mock.patch.object(nl, "_run", side_effect=[
        _cp(stdout=plan_out),
        _cp(stdout=apply_out),
        _cp(returncode=0),
    ]):
        rec = nl.run_scenario(lab, scens[0])
    assert rec["outcome"] == "confirmed"
    assert rec["base"] == {"plan": plan_base, "apply": apply_base, "match": False}
    assert rec["error"] is not None
    assert "apply-time base" in rec["error"]
    assert apply_base in rec["error"]
    assert plan_base in rec["error"]
    assert rec["passed"] is False


def test_applybase_missing_in_confirmed_fails_scenario(fake_lab, monkeypatch):
    """A confirmed apply with NO APPLYBASE line: scenario fails with an
    error mentioning the missing line; no rec['base']."""
    lab_toml, scen_dir = fake_lab
    (scen_dir / "01-a.toml").write_text("""
name = "01-a"
description = "a"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 60
batch = "set foo=bar"
[[post]]
device = "lab-r1"
cmd = "true"
""")
    lab = nl.load_lab(lab_toml)
    scens = nl.load_scenarios(scen_dir)
    sid = "a" * 32
    plan_out = (
        f"STAGED session={sid}\n"
        f"BASEHASH {'b' * 64}\n"
        "----- diff -----\nset foo=bar\n----------------\n"
    )
    apply_out = (
        f"APPLIED session={sid} rollback=60s\n"
        f"CONFIRMED session={sid}\n"
    )
    with mock.patch.object(nl, "_run", side_effect=[
        _cp(stdout=plan_out),
        _cp(stdout=apply_out),
        _cp(returncode=0),
    ]):
        rec = nl.run_scenario(lab, scens[0])
    assert rec["outcome"] == "confirmed"
    assert rec["error"] is not None
    assert "APPLYBASE" in rec["error"]
    assert rec["passed"] is False
    assert "base" not in rec


def test_applybase_absent_when_rejected(fake_lab, monkeypatch):
    """A rejected scenario never reaches apply: no rec['base'], no error
    about APPLYBASE. The scenario still passes (rejected was the expect)."""
    lab_toml, scen_dir = fake_lab
    (scen_dir / "01-a.toml").write_text("""
name = "01-a"
description = "a"
target = "lab-r1"
reset = []
expect = "rejected"
timeout = 60
batch = "commit system"
reject_match = "only set/add/add_list/del_list/delete/rename/reorder are allowed"
[[post]]
device = "lab-r1"
cmd = "true"
""")
    lab = nl.load_lab(lab_toml)
    scens = nl.load_scenarios(scen_dir)
    with mock.patch.object(nl, "_run", side_effect=[
        _cp(returncode=1, stdout="ERROR: staging rejected\n",
            stderr="ERROR: only set/add/add_list/del_list/delete/rename/reorder are allowed, got: commit system\n"),
        _cp(returncode=0),
    ]):
        rec = nl.run_scenario(lab, scens[0])
    assert rec["outcome"] == "rejected"
    assert rec["passed"] is True
    assert rec["error"] is None
    assert "base" not in rec


def test_run_scenario_unknown_var_is_error(fake_lab):
    lab_toml, scen_dir = fake_lab
    (scen_dir / "01-a.toml").write_text("""
name = "01-a"
description = "a"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 60
batch = "set foo='{bogus_var}'"
[[post]]
device = "lab-r1"
cmd = "true"
""")
    lab = nl.load_lab(lab_toml)
    scens = nl.load_scenarios(scen_dir)
    rec = nl.run_scenario(lab, scens[0])
    assert rec["error"] and "unknown var" in rec["error"]
    assert rec["passed"] is False
    assert rec["outcome"] is None


def test_run_scenario_reset_failure(fake_lab, monkeypatch):
    lab_toml, scen_dir = fake_lab
    (scen_dir / "01-a.toml").write_text("""
name = "01-a"
description = "a"
target = "lab-r1"
reset = ["lab-r1"]
expect = "rejected"
timeout = 60
batch = "set foo"
[[post]]
device = "lab-r1"
cmd = "true"
""")
    lab = nl.load_lab(lab_toml)
    scens = nl.load_scenarios(scen_dir)
    with mock.patch.object(nl, "pve_rollback", return_value="UPID:abc"), \
         mock.patch.object(nl, "pve_wait_task", return_value={"status": "stopped", "exitstatus": "ERROR"}):
        rec = nl.run_scenario(lab, scens[0])
    assert rec["error"] and "did not finish OK" in rec["error"]
    assert rec["passed"] is False


# ---------- Plan / Apply plumbing ----------

def test_plan_batch_uses_owrt_change_and_writes_0600(tmp_path, lab):
    captured = {}

    def fake_run(args, **_kw):
        captured["args"] = args
        # While _run is being invoked, the temp file still exists on disk.
        captured["mode"] = Path(args[3]).stat().st_mode & 0o777
        captured["body"] = Path(args[3]).read_text()
        return _cp(stdout="STAGED session=" + "a"*32)

    with mock.patch.object(nl, "_run", side_effect=fake_run):
        rc, out, err = nl.plan_batch(lab, lab.devices["lab-r1"], "set foo=bar")
    assert rc == 0
    args = captured["args"]
    assert args[0] == str(nl.OWRT_CHANGE)
    assert args[1] == "plan"
    assert args[2] == "root@10.109.0.11"
    assert args[4] == "90"   # the default plan timeout (seal binds T)
    assert len(args) == 5    # no probes: no 5th argument to owrt-change
    assert captured["mode"] == 0o600
    assert captured["body"] == "set foo=bar"
    # After plan_batch returns, the temp file is cleaned up.
    assert not Path(args[3]).exists()


def test_apply_batch_uses_owrt_change(lab):
    sid = "a" * 32
    with mock.patch.object(nl, "_run", return_value=_cp(stdout="CONFIRMED session=" + sid)) as m:
        nl.apply_batch(lab, lab.devices["lab-r1"], sid, 60)
    args = m.call_args[0][0]
    assert args[0] == str(nl.OWRT_CHANGE)
    assert args[1] == "apply"
    assert args[2] == "root@10.109.0.11"
    assert args[3] == sid
    assert args[4] == "60"
    # the shell `check` argument is gone
    assert len(args) == 5
    assert m.call_args.kwargs["timeout"] == 60 + 300


def test_build_env_uses_lab_paths(lab):
    env = nl.build_env(lab)
    assert env["OWRT_SSH_PROXY"] == lab.ssh_proxy
    assert env["OWRT_SSH_PASSWORD_FILE"] == lab.ssh_password_file
    assert env["OWRT_AUDIT_LOG"].endswith("audit.log")
    assert env["OWRT_BACKUP_DIR"].endswith("backups")
    # ~ must not survive into the env
    assert "~" not in env["OWRT_SSH_PROXY"]
    assert "~" not in env["OWRT_SSH_PASSWORD_FILE"]


def test_runner_identifies_operator_and_exposes_audit_to_local_posts(lab):
    """Guards: protocol and local audit posts share lab-runner identity/path."""
    protocol_env = nl.build_env(lab)
    local_env = nl._local_env(lab)
    assert protocol_env["OWRT_OPERATOR"] == "lab-runner"
    assert local_env["OWRT_AUDIT_LOG"] == protocol_env["OWRT_AUDIT_LOG"]


# ============================================================================
# Runner v2: [checks]/[steps] in lab.toml, setup/before/after/cleanup phases,
# validation, new CLI flags, probe timeout, local env, vars across checks.
# ============================================================================

_FULL_LAB_TOML = """
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

[vars]
my_var = { device = "local", cmd = "echo hi" }
unused_var = { device = "local", cmd = "echo unused" }

[checks.reg_ok]
device = "lab-r1"
cmd = "true"
description = "always passes"

[checks.breaks_marker]
device = "lab-r1"
cmd = "cat /tmp/marker"
expect_stdout = "^BEFORE$"
description = "BEFORE marker flips to AFTER after a confirmed apply"

[checks.foo_is_bar]
device = "lab-r1"
cmd = "uci get foo"
expect_stdout = "^bar$"
description = "foo unset before, =bar after"

[checks.uses_my_var]
device = "lab-r1"
cmd = "echo {my_var}"
description = "echoes a {var} defined in [vars]"

[steps.dummy_step]
device = "lab-r1"
cmd = "true"
description = "no-op"

[steps.bad_setup]
device = "lab-r1"
cmd = "false"
description = "always fails (setup)"

[steps.bad_cleanup]
device = "lab-r1"
cmd = "false"
description = "always fails (cleanup)"

[regression]
default = ["reg_ok"]
"""


@pytest.fixture
def full_lab(tmp_path):
    """A lab.toml with [checks], [steps], [vars] and [regression].default."""
    lab_toml = tmp_path / "lab.toml"
    lab_toml.write_text(_FULL_LAB_TOML)
    return lab_toml


def _write_scenario(tmp_path, name, body):
    d = tmp_path / "scenarios"
    d.mkdir(exist_ok=True)
    (d / f"{name}.toml").write_text(body)
    return d


def _load_one(tmp_path, name):
    return nl.load_scenarios(tmp_path / "scenarios")[0]


# ---------- Loading: real scenarios still load 9; new keys parse ----------

def test_load_real_scenarios_still_nine(scenarios):
    """The real lab/scenarios dir still loads exactly 9 scenarios."""
    assert len(scenarios) == 9


def test_load_scenarios_parses_new_keys(tmp_path):
    """New scenario fields (setup/cleanup/regression/breaks/effects/empty-batch) parse."""
    _write_scenario(tmp_path, "01-fancy", """
name = "01-fancy"
description = "fancy scenario"
target = "lab-r1"
reset = []
expect = "noop"
timeout = 60
batch = ""

setup = ["prep_a", "prep_b"]
cleanup = ["teardown"]
regression = ["reg_ok", "breaks_marker"]
breaks = ["foo_is_bar"]

[[effect]]
device = "lab-r1"
cmd = "uci get foo"
expect_stdout = "^bar$"
timeout = 30

[[post]]
device = "lab-r1"
cmd = "true"
""")
    s = _load_one(tmp_path, "01-fancy")
    assert s.setup == ["prep_a", "prep_b"]
    assert s.cleanup == ["teardown"]
    assert s.regression == ["reg_ok", "breaks_marker"]
    assert s.breaks == ["foo_is_bar"]
    assert s.batch == ""
    assert s.expect == "noop"
    assert len(s.effects) == 1
    assert s.effects[0].device == "lab-r1"
    assert s.effects[0].cmd == "uci get foo"
    assert s.effects[0].expect_stdout == "^bar$"
    assert s.effects[0].timeout == 30


def test_load_lab_parses_checks_and_regression_default(full_lab):
    lab = nl.load_lab(full_lab)
    assert "reg_ok" in lab.checks
    assert lab.checks["reg_ok"].cmd == "true"
    assert lab.checks["reg_ok"].timeout == 60
    assert "breaks_marker" in lab.checks
    assert "dummy_step" in lab.steps
    assert lab.steps["bad_setup"].cmd == "false"
    assert lab.steps["bad_setup"].timeout == 120
    assert lab.regression_default == ["reg_ok"]


# ---------- Validation ----------

def test_validate_unknown_setup_step_is_error(full_lab, tmp_path):
    _write_scenario(tmp_path, "01-x", """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 60
batch = "set foo=bar"
setup = ["unknown_step"]
""")
    lab = nl.load_lab(full_lab)
    scens = nl.load_scenarios(tmp_path / "scenarios")
    errs = nl.validate_scenarios(lab, scens)
    assert any("unknown_step" in e and "setup" in e for e in errs)


def test_validate_unknown_check_in_regression_is_error(full_lab, tmp_path):
    _write_scenario(tmp_path, "01-x", """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 60
batch = "set foo=bar"
regression = ["nope"]
""")
    lab = nl.load_lab(full_lab)
    scens = nl.load_scenarios(tmp_path / "scenarios")
    errs = nl.validate_scenarios(lab, scens)
    assert any("nope" in e and "regression" in e for e in errs)


def test_validate_regression_default_without_table_is_error(tmp_path):
    lab_toml = tmp_path / "lab.toml"
    lab_toml.write_text("""
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
[vars]
""")
    _write_scenario(tmp_path, "01-x", """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 60
batch = "set foo=bar"
regression = "default"
""")
    lab = nl.load_lab(lab_toml)
    scens = nl.load_scenarios(tmp_path / "scenarios")
    errs = nl.validate_scenarios(lab, scens)
    assert any("default" in e and "regression" in e for e in errs)


def test_validate_bad_expect_is_error(full_lab, tmp_path):
    _write_scenario(tmp_path, "01-x", """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "bogus_outcome"
timeout = 60
batch = "set foo=bar"
""")
    lab = nl.load_lab(full_lab)
    scens = nl.load_scenarios(tmp_path / "scenarios")
    errs = nl.validate_scenarios(lab, scens)
    assert any("bogus_outcome" in e for e in errs)


def test_validate_batchless_without_none_expect_is_error(full_lab, tmp_path):
    _write_scenario(tmp_path, "01-x", """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 60
batch = ""
""")
    lab = nl.load_lab(full_lab)
    scens = nl.load_scenarios(tmp_path / "scenarios")
    errs = nl.validate_scenarios(lab, scens)
    assert any("empty" in e or "missing" in e for e in errs)


def test_validate_none_expect_with_batch_is_error(full_lab, tmp_path):
    _write_scenario(tmp_path, "01-x", """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "none"
timeout = 60
batch = "set foo=bar"
""")
    lab = nl.load_lab(full_lab)
    scens = nl.load_scenarios(tmp_path / "scenarios")
    errs = nl.validate_scenarios(lab, scens)
    assert any("'none'" in e for e in errs)


def test_main_returns_2_on_validation_error(full_lab, tmp_path, capsys):
    _write_scenario(tmp_path, "01-x", """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "bogus"
timeout = 60
batch = "set foo=bar"
""")
    with mock.patch.object(nl, "RESULTS_DIR", tmp_path / "results"):
        rc = nl.main(["--lab", str(full_lab), "--lane", "password",
                      "--scenarios", str(tmp_path / "scenarios")])
    assert rc == 2
    assert "bogus" in capsys.readouterr().err


# ---------- BEFORE / AFTER / cleanup phases ----------

def test_before_regression_failure_blocks_apply_and_runs_cleanup(full_lab, tmp_path):
    _write_scenario(tmp_path, "01-x", """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 60
batch = "set foo=bar"
regression = ["reg_ok"]
cleanup = ["dummy_step"]
""")
    lab = nl.load_lab(full_lab)
    scen = _load_one(tmp_path, "01-x")
    with mock.patch.object(nl, "_run", side_effect=[
        _cp(returncode=1, stderr="ssh denied"),  # before reg_ok fails
        _cp(returncode=0),                        # cleanup dummy_step
    ]) as m:
        rec = nl.run_scenario(lab, scen)
    assert rec["error"] and "before: regression reg_ok" in rec["error"]
    assert rec["passed"] is False
    # plan_batch, apply_batch and any further _run calls must NOT have happened
    assert m.call_count == 2
    # cleanup still ran
    assert len(rec["cleanup"]) == 1
    assert rec["cleanup"][0]["name"] == "dummy_step"
    assert rec["cleanup"][0]["passed"] is True


def test_before_effect_already_passing_blocks_apply(full_lab, tmp_path):
    _write_scenario(tmp_path, "01-x", """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 60
batch = "set foo=bar"

[[effect]]
device = "lab-r1"
cmd = "uci get foo"
expect_stdout = "^bar$"
""")
    lab = nl.load_lab(full_lab)
    scen = _load_one(tmp_path, "01-x")
    # effect already passes -> want=fail, ok=False
    with mock.patch.object(nl, "_run", return_value=_cp(
            returncode=0, stdout="bar\n")):
        rec = nl.run_scenario(lab, scen)
    assert rec["error"] and "cannot detect" in rec["error"]
    assert "effect" in rec["error"] and "effect[0]" in rec["error"]
    assert rec["passed"] is False
    assert rec["before"][0]["role"] == "effect"
    assert rec["before"][0]["want"] == "fail"
    assert rec["before"][0]["passed"] is True
    assert rec["before"][0]["ok"] is False


def test_confirmed_full_pass(full_lab, tmp_path):
    _write_scenario(tmp_path, "01-x", """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 60
batch = "set foo=bar"
regression = ["reg_ok"]
breaks = ["breaks_marker"]

[[effect]]
device = "lab-r1"
cmd = "uci get foo"
expect_stdout = "^bar$"

[[post]]
device = "lab-r1"
cmd = "true"
""")
    lab = nl.load_lab(full_lab)
    scen = _load_one(tmp_path, "01-x")
    sid = "a" * 32
    plan_out = (
        f"STAGED session={sid}\n"
        f"BASEHASH {APPLYBASE_BB_HASH}\n"
        "----- diff -----\nset foo=bar\n----------------\n"
    )
    apply_out = (
        f"APPLYBASE {APPLYBASE_BB_HASH}\n"
        f"CONFIRMED session={sid}"
    )
    with mock.patch.object(nl, "_run", side_effect=[
        _cp(returncode=0),                       # before reg_ok (pass)
        _cp(returncode=0, stdout="BEFORE\n"),   # before breaks_marker (regex matches)
        _cp(returncode=0, stdout="not_bar\n"),  # before effect[0] (regex does NOT match -> passed=False, want=fail -> ok=True)
        _cp(stdout=plan_out),                    # plan_batch
        _cp(stdout=apply_out),                   # apply_batch
        _cp(returncode=0),                       # after reg_ok (want=pass)
        _cp(returncode=0, stdout="AFTER\n"),     # after breaks_marker (want=fail; regex no match -> ok=True)
        _cp(returncode=0, stdout="bar\n"),       # after effect[0] (want=pass)
        _cp(returncode=0),                       # post
    ]):
        rec = nl.run_scenario(lab, scen)
    assert rec["outcome"] == "confirmed"
    assert rec["passed"] is True
    assert all(a["ok"] for a in rec["after"])
    assert all(b["ok"] for b in rec["before"])


def test_confirmed_breaks_check_still_passes_after_is_fail(full_lab, tmp_path):
    _write_scenario(tmp_path, "01-x", """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 60
batch = "set foo=bar"
regression = ["reg_ok"]
breaks = ["breaks_marker"]

[[post]]
device = "lab-r1"
cmd = "true"
""")
    lab = nl.load_lab(full_lab)
    scen = _load_one(tmp_path, "01-x")
    sid = "a" * 32
    plan_out = (
        f"STAGED session={sid}\n"
        f"BASEHASH {APPLYBASE_BB_HASH}\n"
        "----- diff -----\nset foo=bar\n----------------\n"
    )
    apply_out = (
        f"APPLYBASE {APPLYBASE_BB_HASH}\n"
        f"CONFIRMED session={sid}"
    )
    with mock.patch.object(nl, "_run", side_effect=[
        _cp(returncode=0),                       # before reg_ok
        _cp(returncode=0, stdout="BEFORE\n"),   # before breaks_marker (pass)
        _cp(stdout=plan_out),                    # plan
        _cp(stdout=apply_out),                   # apply
        _cp(returncode=0),                       # after reg_ok (pass)
        _cp(returncode=0, stdout="BEFORE\n"),   # after breaks_marker (regex still matches -> passed=True, want=fail -> ok=False)
        _cp(returncode=0),                       # post
    ]):
        rec = nl.run_scenario(lab, scen)
    assert rec["outcome"] == "confirmed"
    assert rec["passed"] is False
    assert rec["after"][1]["role"] == "breaks"
    assert rec["after"][1]["name"] == "breaks_marker"
    assert rec["after"][1]["ok"] is False
    assert "after: breaks breaks_marker wanted fail" in nl.short_reason(rec)


def test_confirmed_effect_fails_after_is_fail(full_lab, tmp_path):
    _write_scenario(tmp_path, "01-x", """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 60
batch = "set foo=bar"
regression = ["reg_ok"]
breaks = ["breaks_marker"]

[[effect]]
device = "lab-r1"
cmd = "uci get foo"
expect_stdout = "^bar$"

[[post]]
device = "lab-r1"
cmd = "true"
""")
    lab = nl.load_lab(full_lab)
    scen = _load_one(tmp_path, "01-x")
    sid = "a" * 32
    plan_out = (
        f"STAGED session={sid}\n"
        f"BASEHASH {APPLYBASE_BB_HASH}\n"
        "----- diff -----\nset foo=bar\n----------------\n"
    )
    apply_out = (
        f"APPLYBASE {APPLYBASE_BB_HASH}\n"
        f"CONFIRMED session={sid}"
    )
    with mock.patch.object(nl, "_run", side_effect=[
        _cp(returncode=0),                       # before reg_ok
        _cp(returncode=0, stdout="BEFORE\n"),   # before breaks_marker
        _cp(returncode=0, stdout="not_bar\n"),  # before effect[0] (want=fail -> ok=True)
        _cp(stdout=plan_out),                    # plan
        _cp(stdout=apply_out),                   # apply
        _cp(returncode=0),                       # after reg_ok
        _cp(returncode=0, stdout="AFTER\n"),     # after breaks_marker (want=fail -> ok=True)
        _cp(returncode=0, stdout="not_bar\n"),  # after effect[0] (want=pass, passed=False -> ok=False)
        _cp(returncode=0),                       # post
    ]):
        rec = nl.run_scenario(lab, scen)
    assert rec["passed"] is False
    bad = [a for a in rec["after"] if not a["ok"]]
    assert len(bad) == 1
    assert bad[0]["role"] == "effect"
    assert bad[0]["name"] == "effect[0]"
    assert bad[0]["want"] == "pass"
    assert "after: effect effect[0] wanted pass" in nl.short_reason(rec)


def test_rolled_back_regression_pass_effects_fail_is_pass(full_lab, tmp_path):
    _write_scenario(tmp_path, "01-x", """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "rolled_back"
timeout = 60
batch = "set foo=bar"
regression = ["reg_ok"]
breaks = ["breaks_marker"]

[[effect]]
device = "lab-r1"
cmd = "uci get foo"
expect_stdout = "^bar$"

[[post]]
device = "lab-r1"
cmd = "true"
""")
    lab = nl.load_lab(full_lab)
    scen = _load_one(tmp_path, "01-x")
    sid = "a" * 32
    plan_out = (
        f"STAGED session={sid}\n"
        f"BASEHASH {APPLYBASE_BB_HASH}\n"
        "----- diff -----\nset foo=bar\n----------------\n"
    )
    apply_out = (
        f"APPLYBASE {APPLYBASE_BB_HASH}\n"
        f"ROLLBACK WINDOW PASSED session={sid}"
    )
    with mock.patch.object(nl, "_run", side_effect=[
        _cp(returncode=0),                       # before reg_ok
        _cp(returncode=0, stdout="BEFORE\n"),   # before breaks_marker
        _cp(returncode=0, stdout="not_bar\n"),  # before effect[0] (want=fail -> ok=True)
        _cp(stdout=plan_out),                    # plan
        _cp(returncode=1, stdout=apply_out),     # apply
        _cp(returncode=0),                       # after reg_ok (want=pass)
        _cp(returncode=0, stdout="BEFORE\n"),   # after breaks_marker (want=pass -> ok=True)
        _cp(returncode=0, stdout="not_bar\n"),  # after effect[0] (want=fail -> ok=True)
        _cp(returncode=0),                       # post
    ]):
        rec = nl.run_scenario(lab, scen)
    assert rec["outcome"] == "rolled_back"
    assert rec["passed"] is True


def test_rolled_back_effect_passes_after_is_fail(full_lab, tmp_path):
    _write_scenario(tmp_path, "01-x", """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "rolled_back"
timeout = 60
batch = "set foo=bar"

[[effect]]
device = "lab-r1"
cmd = "uci get foo"
expect_stdout = "^bar$"

[[post]]
device = "lab-r1"
cmd = "true"
""")
    lab = nl.load_lab(full_lab)
    scen = _load_one(tmp_path, "01-x")
    sid = "a" * 32
    plan_out = (
        f"STAGED session={sid}\n"
        f"BASEHASH {APPLYBASE_BB_HASH}\n"
        "----- diff -----\nset foo=bar\n----------------\n"
    )
    apply_out = (
        f"APPLYBASE {APPLYBASE_BB_HASH}\n"
        f"ROLLBACK WINDOW PASSED session={sid}"
    )
    with mock.patch.object(nl, "_run", side_effect=[
        _cp(returncode=0, stdout="not_bar\n"),  # before effect[0] (want=fail -> ok=True)
        _cp(stdout=plan_out),                    # plan
        _cp(returncode=1, stdout=apply_out),     # apply
        _cp(returncode=0, stdout="bar\n"),       # after effect[0] (want=fail, passed=True -> ok=False)
        _cp(returncode=0),                       # post
    ]):
        rec = nl.run_scenario(lab, scen)
    assert rec["outcome"] == "rolled_back"
    assert rec["passed"] is False
    assert rec["after"][0]["ok"] is False


# ---------- Noop / audit scenarios ----------

def test_no_changes_staged_is_noop_pass(full_lab, tmp_path):
    _write_scenario(tmp_path, "01-x", """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "noop"
timeout = 60
batch = "set foo=bar"

[[post]]
device = "lab-r1"
cmd = "true"
""")
    lab = nl.load_lab(full_lab)
    scen = _load_one(tmp_path, "01-x")
    with mock.patch.object(nl, "_run", side_effect=[
        _cp(returncode=1, stdout="no changes staged\n"),  # plan
        _cp(returncode=0),                                # post
    ]):
        rec = nl.run_scenario(lab, scen)
    assert rec["outcome"] == "noop"
    assert rec["passed"] is True
    assert rec["apply_log"] == ""


def test_no_changes_staged_with_expect_confirmed_is_fail(full_lab, tmp_path):
    _write_scenario(tmp_path, "01-x", """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 60
batch = "set foo=bar"

[[post]]
device = "lab-r1"
cmd = "true"
""")
    lab = nl.load_lab(full_lab)
    scen = _load_one(tmp_path, "01-x")
    with mock.patch.object(nl, "_run", side_effect=[
        _cp(returncode=1, stdout="no changes staged\n"),  # plan -> noop
        _cp(returncode=0),                                # post
    ]):
        rec = nl.run_scenario(lab, scen)
    assert rec["outcome"] == "noop"
    assert rec["passed"] is False
    assert "outcome=noop" in nl.short_reason(rec)


def test_audit_scenario_no_batch_runs_posts(full_lab, tmp_path):
    """No batch + expect none -> no plan, no apply; posts still run; PASS."""
    _write_scenario(tmp_path, "01-x", """
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
[[post]]
device = "lab-r1"
cmd = "true"
""")
    lab = nl.load_lab(full_lab)
    scen = _load_one(tmp_path, "01-x")
    with mock.patch.object(nl, "_run", side_effect=[
        _cp(returncode=0),  # post 1
        _cp(returncode=0),  # post 2
    ]) as m:
        rec = nl.run_scenario(lab, scen)
    assert rec["outcome"] == "none"
    assert rec["passed"] is True
    assert rec["plan_log"] == ""
    assert rec["apply_log"] == ""
    assert len(rec["post"]) == 2
    # Only the posts ran: no plan/apply side-effects
    assert m.call_count == 2


# ---------- Setup / Cleanup error handling ----------

def test_failing_setup_step_blocks_apply_and_runs_cleanup(full_lab, tmp_path):
    _write_scenario(tmp_path, "01-x", """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 60
batch = "set foo=bar"
setup = ["dummy_step", "bad_setup"]
cleanup = ["dummy_step"]
""")
    lab = nl.load_lab(full_lab)
    scen = _load_one(tmp_path, "01-x")
    with mock.patch.object(nl, "_run", side_effect=[
        _cp(returncode=0),                  # setup dummy_step
        _cp(returncode=1, stderr="boom"),  # setup bad_setup -> ERROR
        _cp(returncode=0),                  # cleanup dummy_step
    ]) as m:
        rec = nl.run_scenario(lab, scen)
    assert rec["error"] and "setup bad_setup failed" in rec["error"]
    assert rec["passed"] is False
    # plan/apply never called -> total calls = setup(2) + cleanup(1)
    assert m.call_count == 3
    assert len(rec["setup"]) == 2
    assert len(rec["cleanup"]) == 1


def test_cleanup_failure_alone_is_error(full_lab, tmp_path):
    _write_scenario(tmp_path, "01-x", """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 60
batch = "set foo=bar"
cleanup = ["bad_cleanup"]

[[post]]
device = "lab-r1"
cmd = "true"
""")
    lab = nl.load_lab(full_lab)
    scen = _load_one(tmp_path, "01-x")
    sid = "a" * 32
    plan_out = (
        f"STAGED session={sid}\n"
        f"BASEHASH {APPLYBASE_BB_HASH}\n"
        "----- diff -----\nset foo=bar\n----------------\n"
    )
    apply_out = (
        f"APPLYBASE {APPLYBASE_BB_HASH}\n"
        f"CONFIRMED session={sid}"
    )
    with mock.patch.object(nl, "_run", side_effect=[
        _cp(stdout=plan_out),                    # plan
        _cp(stdout=apply_out),                   # apply
        _cp(returncode=0),                       # post
        _cp(returncode=1, stderr="cleanup-bad"), # cleanup bad_cleanup
    ]):
        rec = nl.run_scenario(lab, scen)
    assert rec["error"] and "cleanup bad_cleanup failed" in rec["error"]
    assert nl.status_letter(rec) == "ERROR"
    assert rec["passed"] is False


def test_cleanup_failure_after_setup_error_keeps_first_error(full_lab, tmp_path):
    _write_scenario(tmp_path, "01-x", """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 60
batch = "set foo=bar"
setup = ["bad_setup"]
cleanup = ["bad_cleanup"]
""")
    lab = nl.load_lab(full_lab)
    scen = _load_one(tmp_path, "01-x")
    with mock.patch.object(nl, "_run", side_effect=[
        _cp(returncode=1, stderr="setup-bad"),  # setup bad_setup -> ERROR
        _cp(returncode=1, stderr="cleanup-bad"),# cleanup bad_cleanup -> would be error, but first wins
    ]):
        rec = nl.run_scenario(lab, scen)
    assert rec["error"] and "setup bad_setup failed" in rec["error"]
    assert "cleanup bad_cleanup failed" not in rec["error"]


# ---------- Local env / SSH routing ----------

def test_local_probe_gets_lab_ssh_env():
    lab = nl.load_lab(LAB_TOML)
    p = nl.Post(device="local", cmd="true")
    with mock.patch.object(nl, "_run", return_value=_cp()) as m:
        nl.run_post(lab, p)
    env = m.call_args.kwargs["env"]
    assert env["LAB_SSH_KEY"] == lab.ssh_key
    assert env["LAB_SSH_PROXY"] == lab.ssh_proxy


def test_local_step_gets_lab_ssh_env(full_lab):
    lab = nl.load_lab(full_lab)
    step = nl.Step(name="x", device="local", cmd="true")
    with mock.patch.object(nl, "_run", return_value=_cp()) as m:
        rc, _cmd, _stderr = nl.run_step(lab, step, values={})
    assert rc == 0
    env = m.call_args.kwargs["env"]
    assert env["LAB_SSH_KEY"] == lab.ssh_key
    assert env["LAB_SSH_PROXY"] == lab.ssh_proxy


def test_remote_probe_uses_ssh_not_local_env():
    lab = nl.load_lab(LAB_TOML)
    p = nl.Post(device="lab-r1", cmd="true")
    with mock.patch.object(nl, "_run", return_value=_cp()) as m:
        nl.run_post(lab, p)
    args = m.call_args[0][0]
    assert args[0] == "ssh"
    assert "root@10.109.0.11" in args
    # Remote probes do not get the local LAB_SSH_* env injected
    env = m.call_args.kwargs.get("env")
    assert env is None


# ---------- Vars across referenced checks ----------

def test_var_used_in_referenced_check_is_resolved(full_lab, tmp_path):
    """A placeholder used only inside a referenced check's cmd is resolved;
    unused vars are not resolved; the substituted cmd is what ssh receives
    in BEFORE and AFTER."""
    _write_scenario(tmp_path, "01-x", """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 60
batch = "set foo=bar"
regression = ["uses_my_var"]

[[post]]
device = "lab-r1"
cmd = "true"
""")
    lab = nl.load_lab(full_lab)
    scen = _load_one(tmp_path, "01-x")
    sid = "a" * 32
    plan_out = (
        f"STAGED session={sid}\n"
        f"BASEHASH {APPLYBASE_BB_HASH}\n"
        "----- diff -----\nset foo=bar\n----------------\n"
    )
    apply_out = (
        f"APPLYBASE {APPLYBASE_BB_HASH}\n"
        f"CONFIRMED session={sid}"
    )
    with mock.patch.object(nl, "_run", side_effect=[
        _cp(stdout="hi\n"),                          # resolve_vars: only my_var
        _cp(returncode=0, stdout="hi\n"),             # before uses_my_var (cmd "echo {my_var}" -> "echo hi")
        _cp(stdout=plan_out),                        # plan
        _cp(stdout=apply_out),                       # apply
        _cp(returncode=0, stdout="hi\n"),             # after uses_my_var
        _cp(returncode=0),                           # post
    ]) as m:
        rec = nl.run_scenario(lab, scen)
    assert "unused_var" not in rec["vars"]
    assert rec["vars"]["my_var"] == "hi"
    assert rec["passed"] is True
    # If unused_var had been resolved we'd see one more _run call: assert exact.
    assert m.call_count == 6
    # The check's cmd was substituted: ssh received the resolved form, not the
    # raw placeholder, in both BEFORE (call_args_list[1]) and AFTER
    # (call_args_list[4]).
    assert m.call_args_list[1][0][0][-1] == "echo hi"
    assert m.call_args_list[4][0][0][-1] == "echo hi"
    assert rec["before"][0]["cmd"] == "echo hi"
    assert rec["after"][0]["cmd"] == "echo hi"


# ---------- CLI ----------

def test_cli_scenarios_dir(full_lab, tmp_path):
    # An alternative scenarios dir with a UNIQUE name that does not appear in
    # the tmp_path scenarios dir. If --scenarios were ignored, the unique name
    # would be missing from the results JSON.
    other = tmp_path / "alt_scenarios"
    other.mkdir()
    (other / "77-alt-only.toml").write_text("""
name = "77-alt-only"
description = "alt"
target = "lab-r1"
reset = []
expect = "rejected"
timeout = 60
batch = "set foo"
reject_match = "unit-test reason"
[[post]]
device = "lab-r1"
cmd = "true"
""")
    with mock.patch.object(nl, "RESULTS_DIR", other / "results"), \
         mock.patch.object(nl, "_run", side_effect=[
             _cp(returncode=1, stdout="ERROR: staging rejected\n",
                 stderr="ERROR: unit-test reason\n"),
             _cp(returncode=0),
         ]):
        rc = nl.main(["--lab", str(full_lab), "--lane", "password", "--scenarios", str(other),
                      "--results", str(other / "r.json"), "--no-lab-reset"])
    assert rc == 0
    payload = json.loads((other / "r.json").read_text())
    names = [s["name"] for s in payload["scenarios"]]
    assert names == ["77-alt-only"]


def test_cli_only_glob_matches(full_lab, tmp_path):
    for n in ("01-foo", "02-foo-baz", "03-bar"):
        _write_scenario(tmp_path, n, f"""
name = "{n}"
description = "x"
target = "lab-r1"
reset = []
expect = "rejected"
timeout = 60
batch = "set foo"
reject_match = "unit-test reason"
[[post]]
device = "lab-r1"
cmd = "true"
""")
    with mock.patch.object(nl, "RESULTS_DIR", tmp_path / "results"), \
         mock.patch.object(nl, "_run", side_effect=[
             _cp(returncode=1, stdout="ERROR: staging rejected\n",
                 stderr="ERROR: unit-test reason\n"),  # 02-foo-baz plan
             _cp(returncode=0),                       # 02-foo-baz post
        ]):
            rc = nl.main(["--lab", str(full_lab), "--lane", "password",
                          "--scenarios", str(tmp_path / "scenarios"),
                          "--only", "*-baz",
                          "--results", str(tmp_path / "r.json"),
                          "--no-lab-reset"])
    assert rc in (0, 1)
    payload = json.loads((tmp_path / "r.json").read_text())
    names = [s["name"] for s in payload["scenarios"]]
    assert names == ["02-foo-baz"]


def test_cli_only_glob_nothing_matches_exits_2(full_lab, tmp_path, capsys):
    _write_scenario(tmp_path, "01-a", """
name = "01-a"
description = "x"
target = "lab-r1"
reset = []
expect = "rejected"
timeout = 60
batch = "set foo"
reject_match = "unit-test reason"
[[post]]
device = "lab-r1"
cmd = "true"
""")
    rc = nl.main(["--lab", str(full_lab), "--lane", "password",
                  "--scenarios", str(tmp_path / "scenarios"),
                  "--only", "no-match-*"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "no-match-*" in err


def test_cli_list_format_includes_expect(capsys):
    """--list prints 'name [expect]: description' per scenario and runs no subprocess."""
    with mock.patch.object(nl, "_run") as m:
        rc = nl.main(["--lab", str(LAB_TOML), "--list"])
    assert rc == 0
    out = capsys.readouterr().out
    # The new format wraps expect in square brackets after the name.
    assert "01-static-lease [confirmed]:" in out
    assert "02-mgmt-ip-lockout [rolled_back]:" in out
    assert "05-bad-syntax [rejected]:" in out
    m.assert_not_called()


# ---------- Probe timeout ----------

def test_probe_timeout_is_passed_to_subprocess():
    lab = nl.load_lab(LAB_TOML)
    p = nl.Post(device="local", cmd="true", timeout=123)
    with mock.patch.object(nl, "_run", return_value=_cp()) as m:
        nl.run_post(lab, p)
    assert m.call_args.kwargs["timeout"] == 123


def test_check_default_timeout_is_60():
    """A probe's default timeout is 60 seconds."""
    p = nl.Post(device="local", cmd="true")
    assert p.timeout == 60
    c = nl.Check(name="x", device="local", cmd="true")
    assert c.timeout == 60


def test_step_default_timeout_is_120():
    s = nl.Step(name="x", device="local", cmd="true")
    assert s.timeout == 120


# ============================================================================
# six defects from a review.
# Each test below was added in this commit; before the fix it must FAIL.
# ============================================================================


# ---------- cleanup still runs after an exception during the scenario ----

def test_plan_exception_after_setup_runs_cleanup(full_lab, tmp_path):
    """subprocess.TimeoutExpired in plan (after setup began) -> cleanup runs,
    error names the exception, passed=False."""
    _write_scenario(tmp_path, "01-x", """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 60
batch = "set foo=bar"
setup = ["dummy_step"]
cleanup = ["dummy_step"]
regression = ["reg_ok"]
""")
    lab = nl.load_lab(full_lab)
    scen = _load_one(tmp_path, "01-x")
    with mock.patch.object(nl, "_run", side_effect=[
        _cp(returncode=0),                                    # setup dummy_step
        _cp(returncode=0),                                    # before reg_ok
        subprocess.TimeoutExpired("owrt-change plan", 120),   # plan raises
        _cp(returncode=0),                                    # cleanup dummy_step
    ]):
        rec = nl.run_scenario(lab, scen)
    assert rec["error"] and "TimeoutExpired" in rec["error"]
    assert len(rec["cleanup"]) == 1
    assert rec["cleanup"][0]["name"] == "dummy_step"
    assert rec["passed"] is False


def test_before_probe_timeout_is_error_and_runs_cleanup(full_lab, tmp_path):
    """A BEFORE regression probe that times out -> ERROR, cleanup still runs."""
    _write_scenario(tmp_path, "01-x", """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 60
batch = "set foo=bar"
setup = ["dummy_step"]
cleanup = ["dummy_step"]
regression = ["reg_ok"]
""")
    lab = nl.load_lab(full_lab)
    scen = _load_one(tmp_path, "01-x")
    with mock.patch.object(nl, "_run", side_effect=[
        _cp(returncode=0),                                    # setup dummy_step
        subprocess.TimeoutExpired("ssh reg_ok", 60),           # before reg_ok times out
        _cp(returncode=0),                                    # cleanup dummy_step
    ]):
        rec = nl.run_scenario(lab, scen)
    assert rec["error"] == "before: regression reg_ok: timed out after 60s"
    assert len(rec["cleanup"]) == 1
    assert rec["cleanup"][0]["name"] == "dummy_step"
    assert rec["passed"] is False
    assert rec["before"][0]["rc"] is None
    assert nl.status_letter(rec) == "ERROR"


def test_setup_step_exception_runs_cleanup_and_skips_plan(full_lab, tmp_path):
    """An exception in a setup step -> cleanup runs, plan/apply never called."""
    _write_scenario(tmp_path, "01-x", """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 60
batch = "set foo=bar"
setup = ["dummy_step", "bad_setup"]
cleanup = ["dummy_step"]
""")
    lab = nl.load_lab(full_lab)
    scen = _load_one(tmp_path, "01-x")
    with mock.patch.object(nl, "_run", side_effect=[
        _cp(returncode=0),                                     # setup dummy_step (ok)
        subprocess.TimeoutExpired("bad_setup ssh", 120),        # setup bad_setup raises
        _cp(returncode=0),                                     # cleanup dummy_step
    ]) as m:
        rec = nl.run_scenario(lab, scen)
    assert rec["error"] and "TimeoutExpired" in rec["error"]
    assert len(rec["cleanup"]) == 1
    assert rec["cleanup"][0]["name"] == "dummy_step"
    assert rec["passed"] is False
    # plan/apply never called -> no owrt-change args in the recorded calls.
    assert not any(c.args[0][0] == str(nl.OWRT_CHANGE) for c in m.call_args_list)


def test_cleanup_not_run_when_var_resolution_fails(tmp_path):
    """Exception in step 2 (var resolution) -> step 3 was never reached,
    so cleanup must not run even when the scenario declares cleanup steps.
    Pins 'iff step 3 reached'."""
    lab_toml = tmp_path / "lab.toml"
    lab_toml.write_text("""
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
[vars]
[checks.uses_nope]
device = "lab-r1"
cmd = "echo {nope}"
description = "uses an undefined var"
[steps.dummy_step]
device = "lab-r1"
cmd = "true"
[regression]
default = []
""")
    _write_scenario(tmp_path, "01-x", """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 60
batch = "set foo=bar"
regression = ["uses_nope"]
cleanup = ["dummy_step"]
""")
    lab = nl.load_lab(lab_toml)
    scen = _load_one(tmp_path, "01-x")
    with mock.patch.object(nl, "_run") as m:
        rec = nl.run_scenario(lab, scen)
    assert rec["error"] and ("nope" in rec["error"] or "unknown" in rec["error"])
    assert rec["cleanup"] == []
    # No _run call at all: var resolution failed before reaching any device.
    assert m.call_count == 0
    assert rec["passed"] is False


# ---------- cleanup step exception is recorded, remaining steps still run

def test_cleanup_step_exception_records_entry_and_runs_next_step(full_lab, tmp_path):
    """A cleanup step that raises TimeoutExpired records rc=None/passed=False
    on that entry, the second cleanup step still runs, and rec["error"] names
    the failed step."""
    _write_scenario(tmp_path, "01-x", """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 60
batch = "set foo=bar"
setup = ["dummy_step"]
cleanup = ["bad_cleanup", "dummy_step"]

[[post]]
device = "lab-r1"
cmd = "true"
""")
    lab = nl.load_lab(full_lab)
    scen = _load_one(tmp_path, "01-x")
    sid = "a" * 32
    plan_out = (
        f"STAGED session={sid}\n"
        f"BASEHASH {APPLYBASE_BB_HASH}\n"
        "----- diff -----\nset foo=bar\n----------------\n"
    )
    apply_out = (
        f"APPLYBASE {APPLYBASE_BB_HASH}\n"
        f"CONFIRMED session={sid}"
    )
    with mock.patch.object(nl, "_run", side_effect=[
        _cp(returncode=0),                                  # setup dummy_step
        _cp(stdout=plan_out),                              # plan
        _cp(stdout=apply_out),                             # apply
        _cp(returncode=0),                                 # post
        subprocess.TimeoutExpired("bad_cleanup", 120),     # cleanup bad_cleanup raises
        _cp(returncode=0),                                 # cleanup dummy_step still runs
    ]):
        rec = nl.run_scenario(lab, scen)
    assert len(rec["cleanup"]) == 2
    assert rec["cleanup"][0]["name"] == "bad_cleanup"
    assert rec["cleanup"][0]["rc"] is None
    assert rec["cleanup"][0]["passed"] is False
    assert rec["cleanup"][0]["stderr"].startswith("TimeoutExpired")
    assert rec["cleanup"][1]["name"] == "dummy_step"
    assert rec["cleanup"][1]["rc"] == 0
    assert rec["cleanup"][1]["passed"] is True
    assert rec["error"] and rec["error"].startswith("cleanup bad_cleanup failed")
    assert rec["passed"] is False


def test_cleanup_step_exception_after_setup_error_keeps_first_error(full_lab, tmp_path):
    """A cleanup step that raises must NOT overwrite an error already set
    earlier in the run (e.g. a setup failure)."""
    _write_scenario(tmp_path, "01-x", """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 60
batch = "set foo=bar"
setup = ["bad_setup"]
cleanup = ["bad_cleanup"]
""")
    lab = nl.load_lab(full_lab)
    scen = _load_one(tmp_path, "01-x")
    with mock.patch.object(nl, "_run", side_effect=[
        _cp(returncode=1, stderr="setup-bad"),              # setup bad_setup -> ERROR
        subprocess.TimeoutExpired("bad_cleanup", 120),     # cleanup bad_cleanup raises
    ]):
        rec = nl.run_scenario(lab, scen)
    assert rec["error"] and "setup bad_setup failed" in rec["error"]
    assert "cleanup" not in rec["error"]
    assert rec["passed"] is False


# ---------- a check in both regression and breaks runs once in AFTER ----

def test_regression_in_breaks_runs_once_in_after_confirmed(full_lab, tmp_path):
    """regression=[reg_ok, breaks_marker], breaks=[breaks_marker], confirmed:
    AFTER must contain exactly the reg_ok and the breaks_marker (in that order),
    and the breaks_marker probe runs exactly once in AFTER."""
    _write_scenario(tmp_path, "01-x", """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 60
batch = "set foo=bar"
regression = ["reg_ok", "breaks_marker"]
breaks = ["breaks_marker"]

[[post]]
device = "lab-r1"
cmd = "true"
""")
    lab = nl.load_lab(full_lab)
    scen = _load_one(tmp_path, "01-x")
    sid = "a" * 32
    plan_out = (
        f"STAGED session={sid}\n"
        f"BASEHASH {APPLYBASE_BB_HASH}\n"
        "----- diff -----\nset foo=bar\n----------------\n"
    )
    apply_out = (
        f"APPLYBASE {APPLYBASE_BB_HASH}\n"
        f"CONFIRMED session={sid}"
    )
    state = {"after_apply": False}

    def fake_run(args, **kw):
        args_list = list(args)
        if args_list[0] == str(nl.OWRT_CHANGE):
            if args_list[1] == "plan":
                return _cp(stdout=plan_out)
            if args_list[1] == "apply":
                state["after_apply"] = True
                return _cp(stdout=apply_out)
            return _cp()
        cmd = args_list[-1]
        if cmd == "cat /tmp/marker":
            # BEFORE wants "BEFORE\n" so the regex ^BEFORE$ matches (passed=True, ok=True for want=pass).
            # AFTER wants "AFTER\n" so the regex does NOT match (passed=False, ok=True for want=fail).
            stdout = "AFTER\n" if state["after_apply"] else "BEFORE\n"
            return _cp(returncode=0, stdout=stdout)
        return _cp(returncode=0)

    with mock.patch.object(nl, "_run", side_effect=fake_run) as m:
        rec = nl.run_scenario(lab, scen)

    assert rec["outcome"] == "confirmed"
    assert rec["passed"] is True

    # AFTER must have exactly 2 items: reg_ok (pass), breaks_marker (fail).
    assert len(rec["after"]) == 2
    assert rec["after"][0]["role"] == "regression"
    assert rec["after"][0]["name"] == "reg_ok"
    assert rec["after"][0]["want"] == "pass"
    assert rec["after"][1]["role"] == "breaks"
    assert rec["after"][1]["name"] == "breaks_marker"
    assert rec["after"][1]["want"] == "fail"

    # Count ssh invocations whose command is the breaks_marker check, AFTER
    # the apply call.
    apply_idx = next(
        i for i, c in enumerate(m.call_args_list)
        if c.args[0][0] == str(nl.OWRT_CHANGE) and c.args[0][1] == "apply"
    )
    ssh_marker_after = [
        c for c in m.call_args_list[apply_idx + 1:]
        if c.args[0][0] == "ssh" and c.args[0][-1] == "cat /tmp/marker"
    ]
    assert len(ssh_marker_after) == 1


# ---------- --only preserves sorted order, no duplicates ----------------

def test_cli_only_preserves_sorted_order_and_dedups(full_lab, tmp_path):
    """--only must keep the original (sorted) order regardless of pattern order,
    and a glob+exact that both match the same scenario must dedup."""
    for n in ("01-a", "02-b", "03-c"):
        _write_scenario(tmp_path, n, f"""
name = "{n}"
description = "{n}"
target = "lab-r1"
reset = []
expect = "rejected"
timeout = 60
batch = "set foo"
reject_match = "unit-test reason"
[[post]]
device = "lab-r1"
cmd = "true"
""")
    # Case 1: pattern order differs from sorted order -> sorted wins.
    with mock.patch.object(nl, "RESULTS_DIR", tmp_path / "results"), \
         mock.patch.object(nl, "_run", side_effect=[
             _cp(returncode=1, stdout="ERROR: staging rejected\n",
                 stderr="ERROR: unit-test reason\n"),  # 01-a plan
             _cp(returncode=0),                       # 01-a post
             _cp(returncode=1, stdout="ERROR: staging rejected\n",
                 stderr="ERROR: unit-test reason\n"),  # 03-c plan
             _cp(returncode=0),                       # 03-c post
        ]):
            rc = nl.main(["--lab", str(full_lab), "--lane", "password",
                          "--scenarios", str(tmp_path / "scenarios"),
                          "--only", "03-c", "01-a",
                          "--results", str(tmp_path / "r1.json"),
                          "--no-lab-reset"])
    assert rc == 0
    payload = json.loads((tmp_path / "r1.json").read_text())
    names = [s["name"] for s in payload["scenarios"]]
    assert names == ["01-a", "03-c"]

    # Case 2: glob+exact both match -> single run.
    with mock.patch.object(nl, "RESULTS_DIR", tmp_path / "results"), \
         mock.patch.object(nl, "_run", side_effect=[
             _cp(returncode=1, stdout="ERROR: staging rejected\n",
                 stderr="ERROR: unit-test reason\n"),  # 02-b plan
             _cp(returncode=0),                       # 02-b post
        ]):
            rc = nl.main(["--lab", str(full_lab), "--lane", "password",
                          "--scenarios", str(tmp_path / "scenarios"),
                          "--only", "0*-b", "02-b",
                          "--results", str(tmp_path / "r2.json"),
                          "--no-lab-reset"])
    assert rc == 0
    payload = json.loads((tmp_path / "r2.json").read_text())
    names = [s["name"] for s in payload["scenarios"]]
    assert names == ["02-b"]


# ---------- Local env for var commands ---------------------------------------

def test_resolve_vars_local_passes_lab_ssh_env():
    """resolve_vars for a local var command sets LAB_SSH_KEY and LAB_SSH_PROXY
    in the subprocess env (packet: 'For device == local (probes, steps, posts,
    vars), the subprocess environment must contain ...')."""
    lab = nl.load_lab(LAB_TOML)
    lab.var_defs["my_local_var"] = {"device": "local", "cmd": "echo hi"}
    with mock.patch.object(nl, "_run", return_value=_cp(stdout="hi\n")) as m:
        values, err = nl.resolve_vars(lab, {"my_local_var"})
    assert err is None
    assert values == {"my_local_var": "hi"}
    env = m.call_args.kwargs["env"]
    assert env["LAB_SSH_KEY"] == lab.ssh_key
    assert env["LAB_SSH_PROXY"] == lab.ssh_proxy


# ============================================================================
# contract statements with no existing test guard.
# A mutation review found runner behaviour that nothing guards.
# Each test below asserts the contract directly; a mutation that removes the
# rule causes the test to fail.
# ============================================================================


# ---------- Second lab fixture for the round-2 validation tests ------------

_EXT_LAB_TOML = """
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

[vars]

[checks.reg_ok]
device = "lab-r1"
cmd = "true"
description = "always passes"

[steps.dummy_step]
device = "lab-r1"
cmd = "true"
description = "no-op"

[regression]
default = ["reg_ok"]
"""


@pytest.fixture
def ext_lab(tmp_path):
    """A second, smaller lab TOML for the round-2 validation tests.
    Kept separate from full_lab so we don't collide with the names that
    full_lab defines (reg_ok, dummy_step, breaks_marker, ...)."""
    lab_toml = tmp_path / "lab.toml"
    lab_toml.write_text(_EXT_LAB_TOML)
    return lab_toml


# ---------- noop must be detected when 'no changes staged' is on stderr

def test_noop_detected_from_stderr_only(ext_lab, tmp_path):
    """owrt-safe-apply writes 'ERROR: no changes staged' to STDERR (its
    die() at scripts/owrt-safe-apply.sh goes to >&2). The runner combines
    stdout+stderr before matching, so a noop with that text on stderr only
    must still be classified as 'noop'."""
    _write_scenario(tmp_path, "01-x", """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "noop"
timeout = 60
batch = "set foo=bar"

[[post]]
device = "lab-r1"
cmd = "true"
""")
    lab = nl.load_lab(ext_lab)
    scen = _load_one(tmp_path, "01-x")
    with mock.patch.object(nl, "_run", side_effect=[
        _cp(returncode=1, stdout="", stderr="ERROR: no changes staged\n"),  # plan
        _cp(returncode=0),                                                  # post
    ]) as m:
        rec = nl.run_scenario(lab, scen)
    assert rec["outcome"] == "noop"
    assert rec["passed"] is True
    assert rec["apply_log"] == ""
    apply_calls = [c for c in m.call_args_list
                   if c.args[0][0] == str(nl.OWRT_CHANGE) and c.args[0][1] == "apply"]
    assert len(apply_calls) == 0


def test_plan_failure_without_marker_is_error(ext_lab, tmp_path):
    """A plan failure whose stderr does NOT contain 'no changes staged' or
    'staging rejected' is an ERROR (plan failed), not 'rejected'."""
    _write_scenario(tmp_path, "01-x", """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "rejected"
timeout = 60
batch = "set foo=bar"

[[post]]
device = "lab-r1"
cmd = "true"
""")
    lab = nl.load_lab(ext_lab)
    scen = _load_one(tmp_path, "01-x")
    with mock.patch.object(nl, "_run", side_effect=[
        _cp(returncode=1, stdout="", stderr="ERROR: some other failure\n"),  # plan
    ]) as m:
        rec = nl.run_scenario(lab, scen)
    assert rec["error"] == "plan failed (rc=1): ERROR: some other failure"
    assert rec["outcome"] is None
    assert nl.status_letter(rec) == "ERROR"
    apply_calls = [c for c in m.call_args_list
                   if c.args[0][0] == str(nl.OWRT_CHANGE) and c.args[0][1] == "apply"]
    assert len(apply_calls) == 0


# ---------- validate_scenarios rules with no existing guard ------------

def test_validate_unknown_target_is_error(ext_lab, tmp_path):
    """A scenario whose target is not in [devices] is invalid when a batch is
    present; the error message must name the scenario file."""
    _write_scenario(tmp_path, "01-x", """
name = "01-x"
description = "x"
target = "lab-garbage"
reset = []
expect = "confirmed"
timeout = 60
batch = "set foo=bar"
""")
    lab = nl.load_lab(ext_lab)
    scens = nl.load_scenarios(tmp_path / "scenarios")
    errs = nl.validate_scenarios(lab, scens)
    target_errs = [e for e in errs
                   if "target" in e and "lab-garbage" in e and "01-x.toml" in e]
    assert target_errs, f"expected target error for lab-garbage; got {errs}"


def test_validate_unknown_cleanup_step_is_error(ext_lab, tmp_path):
    """A scenario whose cleanup lists an unknown step name is invalid; the
    error message must name the scenario file."""
    _write_scenario(tmp_path, "01-x", """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 60
batch = "set foo=bar"
cleanup = ["missing_step"]
""")
    lab = nl.load_lab(ext_lab)
    scens = nl.load_scenarios(tmp_path / "scenarios")
    errs = nl.validate_scenarios(lab, scens)
    cleanup_errs = [e for e in errs
                    if "missing_step" in e and "cleanup" in e and "01-x.toml" in e]
    assert cleanup_errs, f"expected cleanup error for missing_step; got {errs}"


def test_validate_unknown_breaks_check_is_error(ext_lab, tmp_path):
    """A scenario whose breaks lists an unknown check name is invalid; the
    error message must name the scenario file."""
    _write_scenario(tmp_path, "01-x", """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 60
batch = "set foo=bar"
breaks = ["missing_check"]
""")
    lab = nl.load_lab(ext_lab)
    scens = []
    scens += nl.load_scenarios(tmp_path / "scenarios")
    errs = nl.validate_scenarios(lab, scens)
    breaks_errs = [e for e in errs
                   if "missing_check" in e and "breaks" in e and "01-x.toml" in e]
    assert breaks_errs, f"expected breaks error for missing_check; got {errs}"


def test_validate_regression_bogus_string_is_error(ext_lab, tmp_path):
    """A regression value that is a string other than 'default' is invalid;
    the error message must name the scenario file."""
    _write_scenario(tmp_path, "01-x", """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 60
batch = "set foo=bar"
regression = "bogus"
""")
    lab = nl.load_lab(ext_lab)
    scens = nl.load_scenarios(tmp_path / "scenarios")
    errs = nl.validate_scenarios(lab, scens)
    regression_errs = [e for e in errs
                       if "bogus" in e and "regression" in e and "01-x.toml" in e]
    assert regression_errs, f"expected regression error for bogus; got {errs}"


def test_validate_clean_scenario_has_no_errors(ext_lab, tmp_path):
    """A fully valid scenario using every feature (setup, cleanup,
    regression='default', breaks and an inline [[effect]]) returns [].
    Guards against over-eager validation that rejects legal scenarios."""
    _write_scenario(tmp_path, "01-x", """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "rejected"
timeout = 60
batch = "set foo=bar"
reject_match = "unit-test reason"

setup = ["dummy_step"]
cleanup = ["dummy_step"]
regression = "default"
breaks = ["reg_ok"]

[[effect]]
device = "lab-r1"
cmd = "true"
""")
    lab = nl.load_lab(ext_lab)
    scens = nl.load_scenarios(tmp_path / "scenarios")
    errs = nl.validate_scenarios(lab, scens)
    assert errs == []


def test_validate_unknown_target_ignored_without_batch(ext_lab, tmp_path):
    """An audit scenario (no batch, expect='none') with an unknown target
    produces no target error: the target rule is gated by has_batch."""
    _write_scenario(tmp_path, "01-x", """
name = "01-x"
description = "x"
target = "lab-garbage"
reset = []
expect = "none"
timeout = 60
batch = ""
""")
    lab = nl.load_lab(ext_lab)
    scens = nl.load_scenarios(tmp_path / "scenarios")
    errs = nl.validate_scenarios(lab, scens)
    target_errs = [e for e in errs if "target" in e and "lab-garbage" in e]
    assert target_errs == [], f"unexpected target errors: {target_errs}"


# ---------- var resolution covers every referenced command ------------

def test_vars_resolved_for_every_referenced_cmd(ext_lab, tmp_path):
    """Vars used in setup-step cmds, cleanup-step cmds, breaks-check cmds,
    inline [[effect]] cmds, and checks reached via regression='default' are
    all resolved. Unused vars are not. Substitution reaches ssh and is recorded
    on the rec entries."""
    lab_toml = tmp_path / "lab.toml"
    lab_toml.write_text("""
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
[vars]
a = { device = "local", cmd = "echo val_a" }
b = { device = "local", cmd = "echo val_b" }
c = { device = "local", cmd = "echo val_c" }
d = { device = "local", cmd = "echo val_d" }
e = { device = "local", cmd = "echo val_e" }
unused = { device = "local", cmd = "echo unused" }

[checks.uses_e]
device = "lab-r1"
cmd = "echo {e}"

[checks.uses_c]
device = "lab-r1"
cmd = "echo {c}"

[steps.uses_a]
device = "lab-r1"
cmd = "echo {a}"

[steps.uses_b]
device = "lab-r1"
cmd = "echo {b}"

[regression]
default = ["uses_e"]
""")
    _write_scenario(tmp_path, "01-x", """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "rejected"
timeout = 60
batch = "set foo=bar"

setup = ["uses_a"]
cleanup = ["uses_b"]
regression = "default"
breaks = ["uses_c"]

[[effect]]
device = "lab-r1"
cmd = "echo {d}"

[[post]]
device = "lab-r1"
cmd = "true"
""")
    lab = nl.load_lab(lab_toml)
    scen = _load_one(tmp_path, "01-x")

    ssh_cmds: list[str] = []

    def fake_run(args, **kw):
        if args[0] == "bash" and args[1] == "-c":
            # local var resolution: cmd is "echo val_X"
            return _cp(stdout=args[2].replace("echo ", "") + "\n")
        if args[0] == "ssh":
            ssh_cmds.append(args[-1])
            # effects return rc=1 so want=fail is satisfied; everything else rc=0
            if args[-1] == "echo val_d":
                return _cp(returncode=1)
            return _cp(returncode=0)
        if args[0] == str(nl.OWRT_CHANGE):
            return _cp(returncode=1, stdout="ERROR: staging rejected\n",
                       stderr="ERROR: unit-test reason\n")
        raise AssertionError(f"unexpected _run call: {args}")

    with mock.patch.object(nl, "_run", side_effect=fake_run):
        rec = nl.run_scenario(lab, scen)

    assert rec["passed"] is True, f"rec={rec}"
    # 'unused' must not be resolved; every referenced var must be.
    assert set(rec["vars"]) == {"a", "b", "c", "d", "e"}, \
        f"unexpected vars: {set(rec['vars'])}"
    # each substituted ssh cmd shows up at least once
    for needle in ("val_a", "val_b", "val_c", "val_d", "val_e"):
        assert any(needle in c for c in ssh_cmds), \
            f"ssh did not receive {needle}; ssh_cmds={ssh_cmds}"
    # no ssh cmd still carries an unsubstituted placeholder
    for c in ssh_cmds:
        assert "{" not in c, f"unsubstituted placeholder in ssh cmd: {c}"
    # setup/cleanup records show the substituted cmd, not the raw {text}
    assert rec["setup"][0]["cmd"] == "echo val_a"
    assert rec["cleanup"][0]["cmd"] == "echo val_b"


# ---------- every timeout reaches the subprocess call -----------------

def test_timeouts_reach_subprocess_calls(ext_lab, tmp_path):
    """Every probe/step/post/effect timeout reaches the subprocess call's
    timeout kwarg. Checks/posts/effects default to 60, steps to 120.
    A mutation that drops any of these timeouts (hard-coded, missing from
    TOML parsing, dropped when the check is turned into a probe, or dropped
    when the effect is substituted) makes this test fail."""
    lab_toml = tmp_path / "lab.toml"
    lab_toml.write_text("""
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
[vars]
[steps.s_local]
device = "local"
cmd = "echo step_local"
timeout = 17
[steps.s_remote]
device = "lab-r1"
cmd = "echo step_remote"
timeout = 19
[steps.s_default]
device = "lab-r1"
cmd = "echo step_default"
[checks.c_slow]
device = "lab-r1"
cmd = "echo check_slow"
timeout = 23
[checks.c_default]
device = "lab-r1"
cmd = "echo check_default"
[regression]
default = []
""")
    _write_scenario(tmp_path, "01-x", """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "rejected"
timeout = 60
batch = "set foo=bar"

setup = ["s_local", "s_remote", "s_default"]
cleanup = ["s_default"]
regression = ["c_slow", "c_default"]

[[effect]]
device = "lab-r1"
cmd = "echo effect_with_timeout"
timeout = 31
[[effect]]
device = "lab-r1"
cmd = "echo effect_default"

[[post]]
device = "lab-r1"
cmd = "echo post_with_timeout"
timeout = 29
[[post]]
device = "lab-r1"
cmd = "echo post_default"
""")
    lab = nl.load_lab(lab_toml)
    scen = _load_one(tmp_path, "01-x")

    calls: list[tuple[str, int | None]] = []

    def fake_run(args, **kw):
        if args and args[0] == "ssh":
            cmd = args[-1]
        elif args and args[0] == "bash":
            cmd = args[-1]
        elif args and args[0] == str(nl.OWRT_CHANGE):
            cmd = "PLAN/APPLY"
        else:
            raise AssertionError(f"unexpected _run call: {args}")
        calls.append((cmd, kw.get("timeout")))
        if args[0] == str(nl.OWRT_CHANGE):
            return _cp(returncode=1, stdout="ERROR: staging rejected\n",
                       stderr="ERROR: unit-test reason\n")
        # effects return rc=1 so want=fail is satisfied
        if "effect_" in cmd:
            return _cp(returncode=1)
        return _cp(returncode=0)

    with mock.patch.object(nl, "_run", side_effect=fake_run):
        rec = nl.run_scenario(lab, scen)

    assert rec["passed"] is True, f"rec={rec}"
    by_cmd: dict[str, list[int | None]] = {}
    for cmd, to in calls:
        by_cmd.setdefault(cmd, []).append(to)

    # steps (s_default also runs in cleanup, so it appears twice at 120)
    assert by_cmd["echo step_local"] == [17]
    assert by_cmd["echo step_remote"] == [19]
    assert by_cmd["echo step_default"] == [120, 120]
    # checks (BEFORE + AFTER)
    assert by_cmd["echo check_slow"] == [23, 23]
    assert by_cmd["echo check_default"] == [60, 60]
    # effects (BEFORE + AFTER)
    assert by_cmd["echo effect_with_timeout"] == [31, 31]
    assert by_cmd["echo effect_default"] == [60, 60]
    # posts (once each)
    assert by_cmd["echo post_with_timeout"] == [29]
    assert by_cmd["echo post_default"] == [60]


# ============================================================================
# probe timeouts, ssh_ready, validation honesty,
# three review findings (D4a-c).
# ============================================================================


# ---------- probe/post timeouts are a normal failed result --------------

def test_before_effect_timeout_counts_as_failing_and_plan_runs(full_lab, tmp_path):
    """BEFORE [[effect]] that hangs is a failing proxy (want=fail is satisfied).
    Plan still runs (rejected)."""
    _write_scenario(tmp_path, "01-x", """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "rejected"
timeout = 60
batch = "set foo=bar"

[[effect]]
device = "lab-r1"
cmd = "echo effect_cmd"
""")
    lab = nl.load_lab(full_lab)
    scen = _load_one(tmp_path, "01-x")
    with mock.patch.object(nl, "_run", side_effect=[
        subprocess.TimeoutExpired("ssh effect_cmd", 60),   # BEFORE effect hangs
        _cp(returncode=1, stdout="ERROR: staging rejected\n",
            stderr="ERROR: unit-test reason\n"),          # plan -> rejected
        _cp(returncode=1),                                # AFTER effect (want=fail)
    ]) as m:
        rec = nl.run_scenario(lab, scen)
    assert rec["error"] is None
    assert rec["outcome"] == "rejected"
    assert rec["passed"] is True
    assert rec["before"][0]["rc"] is None
    assert rec["before"][0]["passed"] is False
    assert rec["before"][0]["ok"] is True
    assert rec["before"][0]["want"] == "fail"
    assert rec["before"][0]["reason"] == "timed out after 60s"
    plan_calls = [c for c in m.call_args_list
                  if c.args[0][0] == str(nl.OWRT_CHANGE) and c.args[0][1] == "plan"]
    assert len(plan_calls) == 1


def test_after_regression_timeout_is_fail_not_error(full_lab, tmp_path):
    """AFTER regression probe that times out -> FAIL (not ERROR)."""
    _write_scenario(tmp_path, "01-x", """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 60
batch = "set foo=bar"
regression = ["reg_ok"]
""")
    lab = nl.load_lab(full_lab)
    scen = _load_one(tmp_path, "01-x")
    sid = "a" * 32
    plan_out = (
        f"STAGED session={sid}\n"
        f"BASEHASH {APPLYBASE_BB_HASH}\n"
        "----- diff -----\nset foo=bar\n----------------\n"
    )
    apply_out = (
        f"APPLYBASE {APPLYBASE_BB_HASH}\n"
        f"CONFIRMED session={sid}"
    )
    with mock.patch.object(nl, "_run", side_effect=[
        _cp(returncode=0),                       # before reg_ok (pass)
        _cp(stdout=plan_out),                    # plan
        _cp(stdout=apply_out),                   # apply
        subprocess.TimeoutExpired("ssh reg_ok", 60),  # after reg_ok times out
    ]):
        rec = nl.run_scenario(lab, scen)
    assert rec["error"] is None
    assert nl.status_letter(rec) == "FAIL"
    assert rec["passed"] is False
    assert rec["after"][0]["rc"] is None
    assert rec["after"][0]["ok"] is False
    assert nl.short_reason(rec) == (
        "after: regression reg_ok wanted pass, got fail: timed out after 60s")


def test_after_breaks_timeout_after_confirmed_is_ok(full_lab, tmp_path):
    """Confirmed flow: a breaks check that times out AFTER is still ok=True."""
    _write_scenario(tmp_path, "01-x", """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 60
batch = "set foo=bar"
regression = ["reg_ok"]
breaks = ["breaks_marker"]
""")
    lab = nl.load_lab(full_lab)
    scen = _load_one(tmp_path, "01-x")
    sid = "a" * 32
    plan_out = (
        f"STAGED session={sid}\n"
        f"BASEHASH {APPLYBASE_BB_HASH}\n"
        "----- diff -----\nset foo=bar\n----------------\n"
    )
    apply_out = (
        f"APPLYBASE {APPLYBASE_BB_HASH}\n"
        f"CONFIRMED session={sid}"
    )
    with mock.patch.object(nl, "_run", side_effect=[
        _cp(returncode=0),                                # before reg_ok
        _cp(returncode=0, stdout="BEFORE\n"),            # before breaks_marker (regex matches -> passed)
        _cp(stdout=plan_out),                             # plan
        _cp(stdout=apply_out),                            # apply
        _cp(returncode=0),                                # after reg_ok
        subprocess.TimeoutExpired("ssh breaks_marker", 60),  # after breaks_marker times out
    ]):
        rec = nl.run_scenario(lab, scen)
    assert rec["error"] is None
    assert rec["passed"] is True
    after_breaks = [a for a in rec["after"] if a["role"] == "breaks"]
    assert len(after_breaks) == 1
    assert after_breaks[0]["ok"] is True
    assert after_breaks[0]["rc"] is None


def test_post_timeout_is_failed_post_not_error(full_lab, tmp_path):
    """A hanging remote post (default timeout 60) and a hanging local post with
    timeout=7 each become a failed post (rc=None, passed=False) -> FAIL."""
    _write_scenario(tmp_path, "01-x", """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "rejected"
timeout = 60
batch = "set foo=bar"

[[post]]
device = "lab-r1"
cmd = "true"

[[post]]
device = "local"
cmd = "true"
timeout = 7
""")
    lab = nl.load_lab(full_lab)
    scen = _load_one(tmp_path, "01-x")
    with mock.patch.object(nl, "_run", side_effect=[
        _cp(returncode=1, stdout="ERROR: staging rejected\n",
            stderr="ERROR: unit-test reason\n"),               # plan -> rejected
        subprocess.TimeoutExpired("ssh true", 60),             # remote post hangs
        subprocess.TimeoutExpired("bash -c true", 7),          # local post hangs
    ]):
        rec = nl.run_scenario(lab, scen)
    assert rec["error"] is None
    assert nl.status_letter(rec) == "FAIL"
    assert len(rec["post"]) == 2
    assert rec["post"][0]["rc"] is None
    assert rec["post"][0]["passed"] is False
    assert rec["post"][0]["reason"] == "timed out after 60s"
    assert rec["post"][1]["rc"] is None
    assert rec["post"][1]["passed"] is False
    assert rec["post"][1]["reason"] == "timed out after 7s"
    assert nl.short_reason(rec) == (
        "2 post condition(s) failed: timed out after 60s; timed out after 7s")


def test_timeout_result_decodes_partial_output():
    """nl.run_post converts a TimeoutExpired into a normal failed result and
    decodes bytes output/stderr to str (errors='replace')."""
    lab = nl.load_lab(LAB_TOML)

    def run_with_side_effect(post, side_effect):
        with mock.patch.object(nl, "_run", side_effect=side_effect):
            return nl.run_post(lab, post)

    # Remote Post, bytes output/stderr.
    p_remote = nl.Post(device="lab-r1", cmd="true")
    r = run_with_side_effect(p_remote, subprocess.TimeoutExpired(
        "c", 60, output=b"partial out", stderr=b"partial err"))
    assert r["stdout"] == "partial out"
    assert r["stderr"] == "partial err"
    assert r["rc"] is None
    assert r["passed"] is False
    assert r["reason"] == "timed out after 60s"

    # Remote Post, None output/stderr.
    r = run_with_side_effect(p_remote, subprocess.TimeoutExpired("c", 60))
    assert r["stdout"] == ""
    assert r["stderr"] == ""
    assert r["reason"] == "timed out after 60s"

    # Remote Post, non-UTF-8 bytes.
    r = run_with_side_effect(p_remote, subprocess.TimeoutExpired(
        "c", 60, output=b"\xff\xfeok"))
    assert isinstance(r["stdout"], str)
    assert "ok" in r["stdout"]

    # Remote Post, plain str output.
    r = run_with_side_effect(p_remote, subprocess.TimeoutExpired(
        "c", 60, output="plain str output"))
    assert r["stdout"] == "plain str output"

    # Local Post, bytes output/stderr.
    p_local = nl.Post(device="local", cmd="true")
    r = run_with_side_effect(p_local, subprocess.TimeoutExpired(
        "c", 60, output=b"partial out", stderr=b"partial err"))
    assert r["stdout"] == "partial out"
    assert r["stderr"] == "partial err"


def test_timeout_result_keeps_only_the_tail_of_long_output():
    """Like a normal result, a timed-out probe keeps the last MAX_POST characters."""
    lab = nl.load_lab(LAB_TOML)
    big = b"a" * 50 + b"b" * nl.MAX_POST
    for device in ("lab-r1", "local"):
        with mock.patch.object(nl, "_run", side_effect=subprocess.TimeoutExpired(
                "c", 60, output=big, stderr=big)):
            r = nl.run_post(lab, nl.Post(device=device, cmd="true"))
        assert r["stdout"] == "b" * nl.MAX_POST
        assert r["stderr"] == "b" * nl.MAX_POST


def test_before_probe_exception_runs_cleanup(full_lab, tmp_path):
    """An OSError (not a timeout) in a BEFORE probe -> ERROR, cleanup still runs.
    Pins the generic exception path."""
    _write_scenario(tmp_path, "01-x", """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 60
batch = "set foo=bar"
setup = ["dummy_step"]
cleanup = ["dummy_step"]
regression = ["reg_ok"]
""")
    lab = nl.load_lab(full_lab)
    scen = _load_one(tmp_path, "01-x")
    with mock.patch.object(nl, "_run", side_effect=[
        _cp(returncode=0),                  # setup dummy_step
        OSError("ssh missing"),             # before reg_ok raises (not a timeout)
        _cp(returncode=0),                  # cleanup dummy_step
    ]):
        rec = nl.run_scenario(lab, scen)
    assert rec["error"] and "OSError" in rec["error"] and "ssh missing" in rec["error"]
    assert len(rec["cleanup"]) == 1
    assert rec["cleanup"][0]["name"] == "dummy_step"
    assert rec["passed"] is False


def test_apply_timeout_is_error_and_runs_cleanup(full_lab, tmp_path):
    """apply_batch raises TimeoutExpired after setup began -> ERROR,
    cleanup still runs (apply keeps raising on timeout)."""
    _write_scenario(tmp_path, "01-x", """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 60
batch = "set foo=bar"
setup = ["dummy_step"]
cleanup = ["dummy_step"]
regression = ["reg_ok"]
""")
    lab = nl.load_lab(full_lab)
    scen = _load_one(tmp_path, "01-x")
    sid = "a" * 32
    plan_out = f"STAGED session={sid}\n"
    with mock.patch.object(nl, "_run", side_effect=[
        _cp(returncode=0),                                     # setup dummy_step
        _cp(returncode=0),                                     # before reg_ok
        _cp(stdout=plan_out),                                  # plan
        subprocess.TimeoutExpired("apply", 60),                # apply raises
        _cp(returncode=0),                                     # cleanup dummy_step
    ]):
        rec = nl.run_scenario(lab, scen)
    assert rec["error"] and "TimeoutExpired" in rec["error"]
    assert len(rec["cleanup"]) == 1
    assert rec["cleanup"][0]["name"] == "dummy_step"
    assert rec["passed"] is False


# ---------- ssh_ready treats timeout as "not ready yet" -----------------

def test_ssh_ready_retries_after_timeout(lab):
    """Two TimeoutExpired then rc=0 -> ssh_ready returns True, _run called 3 times."""
    r1 = lab.devices["lab-r1"]
    with mock.patch.object(nl, "_run", side_effect=[
        subprocess.TimeoutExpired("ssh", 15),
        subprocess.TimeoutExpired("ssh", 15),
        _cp(returncode=0),
    ]) as m:
        ok = nl.ssh_ready(lab, r1)
    assert ok is True
    assert m.call_count == 3


def test_ssh_ready_gives_up_at_deadline_when_every_attempt_times_out(
        lab, monkeypatch):
    """Every attempt times out; with a fake clock advancing 20s, ssh_ready
    returns False and _run was called more than once."""
    import itertools
    r1 = lab.devices["lab-r1"]
    counter = itertools.count(0, 20)
    monkeypatch.setattr(nl.time, "monotonic", lambda: next(counter))
    with mock.patch.object(nl, "_run",
                           side_effect=subprocess.TimeoutExpired("ssh", 15)) as m:
        ok = nl.ssh_ready(lab, r1)
    assert ok is False
    assert m.call_count > 1


# ---------- validate_scenarios uses plain membership -------------------

def test_main_validates_scenarios_against_the_loaded_lab(tmp_path, capsys):
    """A lab.toml that has no lab-r1 device, run with --list against the real
    scenarios dir, returns 2 and stderr names lab-r1 and a scenario file."""
    bad_lab = tmp_path / "no_lab_r1.toml"
    bad_lab.write_text("""
[pve]
host = "pve.test"
node = "lab"
token_file = "~/.config/pve/token"
pin_file = "~/.config/pve/pin"
[ssh]
proxy = "ssh -W %h:%p root@pve.test"
password_file = "~/.config/newton/lab-root.pw"
key = "~/.ssh/key"
[devices.other-r1]
vmid = 800
host = "10.109.0.99"
user = "root"
snapshot = "baseline"
[vars]
""")
    rc = nl.main(["--lab", str(bad_lab), "--lane", "password", "--list"])
    err = capsys.readouterr().err
    assert rc == 2
    assert "lab-r1" in err
    assert any(s in err for s in (
        "01-static-lease.toml", "02-mgmt-ip-lockout.toml",
        "03-mgmt-firewall-drop.toml", "04-commit-smuggling.toml",
        "05-bad-syntax.toml", "06-port-forward-from-isp.toml",
        "07-wan-down-isolation.toml", "08-partial-batch.toml",
        "09-add-section.toml",
    )), f"no scenario file named in stderr: {err!r}"


# ---------- missing/empty scenarios dir is an error -------------------

def test_main_missing_scenarios_dir_exits_2(tmp_path, capsys, monkeypatch):
    """--scenarios pointing at a non-existent path -> rc 2, stderr names the
    path, stdout empty, _run never called, no results file written."""
    monkeypatch.setattr(nl, "RESULTS_DIR", tmp_path / "results")
    bad = tmp_path / "nope"
    with mock.patch.object(nl, "_run") as m:
        rc = nl.main(["--lab", str(LAB_TOML), "--scenarios", str(bad),
                      "--results", str(tmp_path / "r.json")])
    captured = capsys.readouterr()
    assert rc == 2
    assert str(bad) in captured.err
    assert captured.out == ""
    m.assert_not_called()
    assert not (tmp_path / "r.json").exists()


def test_main_empty_scenarios_dir_exits_2(tmp_path, capsys, monkeypatch):
    """An existing empty scenarios dir -> rc 2, stderr contains 'no scenarios found'."""
    empty = tmp_path / "empty"
    empty.mkdir()
    monkeypatch.setattr(nl, "RESULTS_DIR", tmp_path / "results")
    rc = nl.main(["--lab", str(LAB_TOML), "--scenarios", str(empty),
                  "--results", str(tmp_path / "r.json")])
    err = capsys.readouterr().err
    assert rc == 2
    assert "no scenarios found" in err


def test_main_list_with_empty_scenarios_dir_exits_2(tmp_path, capsys, monkeypatch):
    """--list with an empty scenarios dir -> rc 2, stdout empty."""
    empty = tmp_path / "empty"
    empty.mkdir()
    monkeypatch.setattr(nl, "RESULTS_DIR", tmp_path / "results")
    rc = nl.main(["--lab", str(LAB_TOML), "--scenarios", str(empty), "--list",
                  "--results", str(tmp_path / "r.json")])
    captured = capsys.readouterr()
    assert rc == 2
    assert captured.out == ""


# ---------- exception in middle of phase keeps completed records -----

def test_exception_in_second_before_probe_keeps_first_record(full_lab, tmp_path):
    """regression=[reg_ok, breaks_marker], second BEFORE probe raises OSError
    -> rec['error'] contains OSError, len(rec['before']) == 1,
    rec['before'][0]['name'] == 'reg_ok'."""
    _write_scenario(tmp_path, "01-x", """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "none"
timeout = 60
batch = ""
regression = ["reg_ok", "breaks_marker"]
""")
    lab = nl.load_lab(full_lab)
    scen = _load_one(tmp_path, "01-x")
    with mock.patch.object(nl, "_run", side_effect=[
        _cp(returncode=0, stdout="BEFORE\n"),    # before reg_ok (want pass)
        OSError("boom"),                          # before breaks_marker raises
    ]):
        rec = nl.run_scenario(lab, scen)
    assert rec["error"] and "OSError" in rec["error"] and "boom" in rec["error"]
    assert len(rec["before"]) == 1
    assert rec["before"][0]["name"] == "reg_ok"


def test_exception_in_second_after_probe_keeps_first_record(full_lab, tmp_path):
    """Confirmed flow, two regression checks, second AFTER probe raises OSError
    -> len(rec['after']) == 1, rec['before'] complete (2 items)."""
    _write_scenario(tmp_path, "01-x", """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 60
batch = "set foo=bar"
regression = ["reg_ok", "breaks_marker"]
""")
    lab = nl.load_lab(full_lab)
    scen = _load_one(tmp_path, "01-x")
    sid = "a" * 32
    plan_out = (
        f"STAGED session={sid}\n"
        f"BASEHASH {APPLYBASE_BB_HASH}\n"
        "----- diff -----\nset foo=bar\n----------------\n"
    )
    apply_out = (
        f"APPLYBASE {APPLYBASE_BB_HASH}\n"
        f"CONFIRMED session={sid}"
    )
    with mock.patch.object(nl, "_run", side_effect=[
        _cp(returncode=0, stdout="BEFORE\n"),     # before reg_ok
        _cp(returncode=0, stdout="BEFORE\n"),     # before breaks_marker
        _cp(stdout=plan_out),                      # plan
        _cp(stdout=apply_out),                     # apply
        _cp(returncode=0, stdout="AFTER\n"),      # after reg_ok (pass)
        OSError("boom"),                           # after breaks_marker raises
    ]):
        rec = nl.run_scenario(lab, scen)
    assert rec["error"] and "OSError" in rec["error"] and "boom" in rec["error"]
    assert len(rec["before"]) == 2
    assert len(rec["after"]) == 1
    assert rec["after"][0]["name"] == "reg_ok"


def test_exception_in_second_post_keeps_first_record(full_lab, tmp_path):
    """Two [[post]], the second raises -> len(rec['post']) == 1."""
    _write_scenario(tmp_path, "01-x", """
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
[[post]]
device = "lab-r1"
cmd = "true"
""")
    lab = nl.load_lab(full_lab)
    scen = _load_one(tmp_path, "01-x")
    with mock.patch.object(nl, "_run", side_effect=[
        _cp(returncode=0),                       # post 1
        OSError("boom"),                        # post 2 raises
    ]):
        rec = nl.run_scenario(lab, scen)
    assert rec["error"] and "OSError" in rec["error"] and "boom" in rec["error"]
    assert len(rec["post"]) == 1
    assert rec["post"][0]["passed"] is True


# ---------- validate_scenarios rejects unknown device names ----------

def test_validate_unknown_effect_device_is_error(ext_lab, tmp_path):
    """effect device='lab-r9' -> error contains '01-x.toml', 'lab-r9', '[[effect]]'."""
    _write_scenario(tmp_path, "01-x", """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "rejected"
timeout = 60
batch = "set foo=bar"

[[effect]]
device = "lab-r9"
cmd = "true"
""")
    lab = nl.load_lab(ext_lab)
    scens = nl.load_scenarios(tmp_path / "scenarios")
    errs = nl.validate_scenarios(lab, scens)
    matching = [e for e in errs
                if "01-x.toml" in e and "lab-r9" in e and "[[effect]]" in e]
    assert matching, f"expected effect device error; got {errs}"


def test_validate_unknown_post_device_is_error(ext_lab, tmp_path):
    """post device='lab-r9' -> error contains '01-x.toml', 'lab-r9', '[[post]]'."""
    _write_scenario(tmp_path, "01-x", """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "rejected"
timeout = 60
batch = "set foo=bar"

[[post]]
device = "lab-r9"
cmd = "true"
""")
    lab = nl.load_lab(ext_lab)
    scens = nl.load_scenarios(tmp_path / "scenarios")
    errs = nl.validate_scenarios(lab, scens)
    matching = [e for e in errs
                if "01-x.toml" in e and "lab-r9" in e and "[[post]]" in e]
    assert matching, f"expected post device error; got {errs}"


def test_validate_unknown_reset_device_is_error(ext_lab, tmp_path):
    """reset=['lab-r9'] -> error contains '01-x.toml', 'lab-r9'."""
    _write_scenario(tmp_path, "01-x", """
name = "01-x"
description = "x"
target = "lab-r1"
reset = ["lab-r9"]
expect = "rejected"
timeout = 60
batch = "set foo=bar"
""")
    lab = nl.load_lab(ext_lab)
    scens = nl.load_scenarios(tmp_path / "scenarios")
    errs = nl.validate_scenarios(lab, scens)
    matching = [e for e in errs if "01-x.toml" in e and "lab-r9" in e]
    assert matching, f"expected reset device error; got {errs}"


def test_validate_referenced_check_with_unknown_device_is_error(tmp_path):
    """A lab.toml check with device='lab-r9' referenced via breaks AND via
    regression='default' produces two errors naming the check and lab-r9."""
    lab_toml = tmp_path / "lab.toml"
    lab_toml.write_text("""
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
[vars]

[checks.bad_check]
device = "lab-r9"
cmd = "true"

[checks.reg_ok]
device = "lab-r1"
cmd = "true"

[regression]
default = ["bad_check"]
""")
    _write_scenario(tmp_path, "01-x", """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "rejected"
timeout = 60
batch = "set foo=bar"
breaks = ["bad_check"]
regression = "default"
""")
    lab = nl.load_lab(lab_toml)
    scens = nl.load_scenarios(tmp_path / "scenarios")
    errs = nl.validate_scenarios(lab, scens)
    matching = [e for e in errs
                if "01-x.toml" in e and "lab-r9" in e and "bad_check" in e]
    assert len(matching) >= 2, (
        f"expected 2 errors for bad_check referenced twice; got {matching}")


def test_validate_referenced_step_with_unknown_device_is_error(tmp_path):
    """A lab.toml step with device='lab-r9' referenced via setup AND cleanup
    produces two errors naming the step and lab-r9."""
    lab_toml = tmp_path / "lab.toml"
    lab_toml.write_text("""
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
[vars]

[steps.bad_step]
device = "lab-r9"
cmd = "true"
""")
    _write_scenario(tmp_path, "01-x", """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "rejected"
timeout = 60
batch = "set foo=bar"
setup = ["bad_step"]
cleanup = ["bad_step"]
""")
    lab = nl.load_lab(lab_toml)
    scens = nl.load_scenarios(tmp_path / "scenarios")
    errs = nl.validate_scenarios(lab, scens)
    matching = [e for e in errs
                if "01-x.toml" in e and "lab-r9" in e and "bad_step" in e]
    assert len(matching) >= 2, (
        f"expected 2 errors for bad_step referenced twice; got {matching}")


def test_validate_local_device_is_accepted_and_unreferenced_bad_items_ignored(tmp_path):
    """probes/steps/checks on 'local' are accepted; lab.toml check/step with a
    bad device that NO scenario references produces no error. ('local' as a
    reset target is an error: test_validate_reset_local_is_error.)"""
    lab_toml = tmp_path / "lab.toml"
    lab_toml.write_text("""
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
[vars]

[checks.reg_ok]
device = "lab-r1"
cmd = "true"

[checks.unreferenced_bad_check]
device = "lab-r9"
cmd = "true"

[steps.local_step]
device = "local"
cmd = "true"

[steps.unreferenced_bad_step]
device = "lab-r9"
cmd = "true"
""")
    _write_scenario(tmp_path, "01-x", """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "rejected"
timeout = 60
batch = "set foo=bar"
reject_match = "unit-test reason"
setup = ["local_step"]
regression = ["reg_ok"]

[[effect]]
device = "local"
cmd = "true"

[[post]]
device = "local"
cmd = "true"
""")
    lab = nl.load_lab(lab_toml)
    scens = nl.load_scenarios(tmp_path / "scenarios")
    errs = nl.validate_scenarios(lab, scens)
    # Everything the scenario references is valid ('local' probes, steps and
    # checks included); the bad items are not referenced, so nothing is reported.
    assert errs == []


def test_validate_reset_local_is_error(ext_lab, tmp_path):
    """'local' is a valid probe/step device but not a reset target."""
    _write_scenario(tmp_path, "01-x", """
name = "01-x"
description = "x"
target = "lab-r1"
reset = ["local"]
expect = "rejected"
timeout = 60
batch = "set foo=bar"
""")
    lab = nl.load_lab(ext_lab)
    scens = nl.load_scenarios(tmp_path / "scenarios")
    errs = nl.validate_scenarios(lab, scens)
    assert any("01-x.toml" in e and "reset" in e and "local" in e for e in errs), errs


# ============================================================================
# a plan failure is not a rejection (A); a rejection must be
# for the right reason (C). reject_match pins WHY the plan was refused.
# ============================================================================


# ---------- A: plan failures -- infra or other non-zero rc is ERROR, not
# rejected; only "staging rejected" on stdout+stderr is a rejection -----------

def test_plan_infra_failures_are_error_not_rejected(ext_lab, tmp_path):
    """For every infra failure output, a scenario whose expect is 'rejected'
    is classified as ERROR (plan failed) and never as rejected. The cleanup
    step still runs; no apply ever runs."""
    _write_scenario(tmp_path, "01-x", """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "rejected"
timeout = 60
batch = "set foo=bar"
reject_match = "unit-test reason"

cleanup = ["dummy_step"]

[[post]]
device = "lab-r1"
cmd = "true"
""")
    lab = nl.load_lab(ext_lab)
    scen = _load_one(tmp_path, "01-x")
    for where, text in INFRA_FAILURES:
        with mock.patch.object(nl, "_run", side_effect=[
            _refused(where, text, returncode=1),
            _cp(returncode=0),  # cleanup dummy_step
        ]) as m:
            rec = nl.run_scenario(lab, scen)
        assert rec["error"] is not None, (
            f"{where}:{text!r}: rec.error is None; rec={rec}")
        assert rec["error"].startswith("plan failed (rc=1): "), (
            f"{where}:{text!r}: error text was {rec['error']!r}")
        assert text.strip() in rec["error"], (
            f"{where}:{text!r}: stripped message not in {rec['error']!r}")
        assert rec["outcome"] is None, (
            f"{where}:{text!r}: outcome should be None; got {rec['outcome']}")
        assert nl.status_letter(rec) == "ERROR", (
            f"{where}:{text!r}: status letter was {nl.status_letter(rec)}")
        assert rec["passed"] is False
        # No apply ever ran.
        apply_calls = [c for c in m.call_args_list
                       if c.args[0][0] == str(nl.OWRT_CHANGE)
                       and c.args[0][1] == "apply"]
        assert apply_calls == [], (
            f"{where}:{text!r}: apply was called: {apply_calls}")
        # Cleanup still ran.
        assert len(rec["cleanup"]) == 1, (
            f"{where}:{text!r}: cleanup len was {len(rec['cleanup'])}")
        assert rec["cleanup"][0]["name"] == "dummy_step"
        # No posts ran (we returned early).
        assert rec["post"] == [], (
            f"{where}:{text!r}: posts should be empty; got {rec['post']}")


def test_plan_infra_failures_for_confirmed_scenario_are_error(ext_lab, tmp_path):
    """Same infra failures, but the scenario's expect is 'confirmed': the
    ERROR path still triggers and there is no apply."""
    _write_scenario(tmp_path, "01-x", """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 60
batch = "set foo=bar"

cleanup = ["dummy_step"]
""")
    lab = nl.load_lab(ext_lab)
    scen = _load_one(tmp_path, "01-x")
    for where, text in INFRA_FAILURES:
        with mock.patch.object(nl, "_run", side_effect=[
            _refused(where, text, returncode=1),
            _cp(returncode=0),  # cleanup dummy_step
        ]) as m:
            rec = nl.run_scenario(lab, scen)
        assert rec["error"] is not None, (
            f"{where}:{text!r}: rec.error is None")
        assert rec["error"].startswith("plan failed (rc=1): ")
        assert rec["outcome"] is None
        assert nl.status_letter(rec) == "ERROR"
        apply_calls = [c for c in m.call_args_list
                       if c.args[0][0] == str(nl.OWRT_CHANGE)
                       and c.args[0][1] == "apply"]
        assert apply_calls == []
        assert len(rec["cleanup"]) == 1


def test_plan_marker_alone_is_rejected(ext_lab, tmp_path):
    """rc=1, stdout marker, stderr a reason, scenario with matching reject_match:
    outcome is rejected and the scenario passes."""
    _write_scenario(tmp_path, "01-x", """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "rejected"
timeout = 60
batch = "set foo=bar"
reject_match = "unit-test reason"

[[post]]
device = "lab-r1"
cmd = "true"
""")
    lab = nl.load_lab(ext_lab)
    scen = _load_one(tmp_path, "01-x")
    with mock.patch.object(nl, "_run", side_effect=[
        _cp(returncode=1, stdout=STAGING_REJECTED_STDOUT,
            stderr="ERROR: unit-test reason\n"),
        _cp(returncode=0),  # post
    ]):
        rec = nl.run_scenario(lab, scen)
    assert rec["outcome"] == "rejected"
    assert rec["passed"] is True
    assert rec["reject"] == {
        "pattern": "unit-test reason", "matched": True,
    }


def test_noop_wins_over_the_staging_rejected_marker(ext_lab, tmp_path):
    """A no-change plan prints BOTH 'staging rejected' on stdout AND
    'no changes staged' on stderr (see scripts/owrt-safe-apply.sh line 65
    vs line 50). 'no changes staged' wins and the outcome is noop."""
    _write_scenario(tmp_path, "01-x", """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "noop"
timeout = 60
batch = "set foo=bar"
reject_match = "unit-test reason"

[[post]]
device = "lab-r1"
cmd = "true"
""")
    lab = nl.load_lab(ext_lab)
    scen = _load_one(tmp_path, "01-x")
    with mock.patch.object(nl, "_run", side_effect=[
        _cp(returncode=1, stdout=STAGING_REJECTED_STDOUT,
            stderr="ERROR: no changes staged\n"),
        _cp(returncode=0),  # post
    ]):
        rec = nl.run_scenario(lab, scen)
    assert rec["outcome"] == "noop"
    assert rec["passed"] is True
    assert rec["reject"] is None

    # Same mocked output with expect='rejected' -> FAIL (noop != rejected);
    # rec["reject"] stays None because the rejected path did not run.
    _write_scenario(tmp_path, "01-x", """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "rejected"
timeout = 60
batch = "set foo=bar"
reject_match = "unit-test reason"

[[post]]
device = "lab-r1"
cmd = "true"
""")
    scen = _load_one(tmp_path, "01-x")
    with mock.patch.object(nl, "_run", side_effect=[
        _cp(returncode=1, stdout=STAGING_REJECTED_STDOUT,
            stderr="ERROR: no changes staged\n"),
        _cp(returncode=0),  # post
    ]):
        rec = nl.run_scenario(lab, scen)
    assert rec["outcome"] == "noop"
    assert rec["passed"] is False
    assert rec["reject"] is None


def test_confirmed_scenario_refused_with_marker_is_fail(full_lab, tmp_path):
    """expect='confirmed', plan refused with the marker -> outcome rejected,
    FAIL (error None, not ERROR). The scenario has no reject_match, so no
    reject check is recorded."""
    _write_scenario(tmp_path, "01-x", """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 60
batch = "set foo=bar"

[[post]]
device = "lab-r1"
cmd = "true"
""")
    lab = nl.load_lab(full_lab)
    scen = _load_one(tmp_path, "01-x")
    with mock.patch.object(nl, "_run", side_effect=[
        _cp(returncode=1, stdout=STAGING_REJECTED_STDOUT,
            stderr="ERROR: unit-test reason\n"),
        _cp(returncode=0),  # post
    ]):
        rec = nl.run_scenario(lab, scen)
    assert rec["outcome"] == "rejected"
    assert rec["error"] is None
    assert nl.status_letter(rec) == "FAIL"
    assert rec["passed"] is False
    assert rec["reject"] is None


def test_rejected_outcome_without_reject_match_records_no_reject_check(
        full_lab, tmp_path):
    """run_scenario called directly (validation bypassed) on an expect='rejected'
    scenario that has no reject_match: nothing is checked, rec['reject'] stays
    None, and the scenario passes on the outcome alone."""
    _write_scenario(tmp_path, "01-x", """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "rejected"
timeout = 60
batch = "set foo=bar"

[[post]]
device = "lab-r1"
cmd = "true"
""")
    lab = nl.load_lab(full_lab)
    scen = _load_one(tmp_path, "01-x")
    assert scen.reject_match is None
    with mock.patch.object(nl, "_run", side_effect=[
        _cp(returncode=1, stdout=STAGING_REJECTED_STDOUT,
            stderr="ERROR: unit-test reason\n"),
        _cp(returncode=0),  # post
    ]):
        rec = nl.run_scenario(lab, scen)
    assert rec["outcome"] == "rejected"
    assert rec["passed"] is True
    assert rec["reject"] is None
    assert json.dumps(rec["reject"]) == "null"


def test_plan_failed_tail_is_whitespace_collapsed_and_capped(ext_lab, tmp_path):
    """The 'plan failed' error is the last 200 chars of the whitespace-collapsed
    pout+stderr on one line."""
    _write_scenario(tmp_path, "01-x", """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "rejected"
timeout = 60
batch = "set foo=bar"
""")
    lab = nl.load_lab(ext_lab)
    scen = _load_one(tmp_path, "01-x")
    # Build a long, multi-line, multi-space stdout. The unique tail substring
    # must survive into the error message; anything older than the last 200
    # chars must NOT survive.
    tail_marker = "MARKER_TAIL_END_abcdef0123"
    big = "X" * 400 + "\n\n   " + tail_marker
    with mock.patch.object(nl, "_run", return_value=_cp(stdout=big, returncode=1)):
        rec = nl.run_scenario(lab, scen)
    assert rec["error"] is not None
    assert rec["error"].startswith("plan failed (rc=1): ")
    # Whitespace collapsed to single spaces: no '\n', no runs of spaces.
    payload = rec["error"]
    assert "\n" not in payload
    assert "  " not in payload[len("plan failed (rc=1): "):]
    # Tail marker present, capped at 200 chars from the end of the collapsed text.
    assert tail_marker in payload
    tail_part = payload[len("plan failed (rc=1): "):]
    assert len(tail_part) == 200
    # No part of the error is longer than MAX_LOG-style; it's the last 200 chars.
    expected_tail = " ".join(big.split())[-200:]
    assert payload == f"plan failed (rc=1): {expected_tail}"


# ---------- C: reject_match is the right-reason check ------------------------

def test_load_scenarios_parses_reject_match(tmp_path):
    """`reject_match` is read from TOML into Scenario.reject_match: the key
    is parsed to a string when present, None when absent."""
    _write_scenario(tmp_path, "01-with", """
name = "01-with"
description = "x"
target = "lab-r1"
reset = []
expect = "rejected"
timeout = 60
batch = "set foo=bar"
reject_match = "only set/add are allowed"
""")
    _write_scenario(tmp_path, "02-without", """
name = "02-without"
description = "x"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 60
batch = "set foo=bar"
""")
    scens = nl.load_scenarios(tmp_path / "scenarios")
    by_name = {s.name: s for s in scens}
    assert by_name["01-with"].reject_match == "only set/add are allowed"
    assert by_name["02-without"].reject_match is None


def test_validate_rejected_without_reject_match_is_error(ext_lab, tmp_path):
    """expect='rejected' + missing/empty/whitespace-only reject_match -> error."""
    for body in (
        # Missing reject_match entirely.
        """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "rejected"
timeout = 60
batch = "set foo=bar"
""",
        # Empty reject_match.
        """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "rejected"
timeout = 60
batch = "set foo=bar"
reject_match = ""
""",
        # Whitespace-only reject_match.
        """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "rejected"
timeout = 60
batch = "set foo=bar"
reject_match = "   \t  "
""",
    ):
        _write_scenario(tmp_path, "01-x", body)
        lab = nl.load_lab(ext_lab)
        scens = nl.load_scenarios(tmp_path / "scenarios")
        errs = nl.validate_scenarios(lab, scens)
        matching = [e for e in errs
                    if "01-x.toml" in e
                    and "reject_match" in e
                    and "requires reject_match" in e]
        assert matching, (
            f"missing reject_match body should error: body={body!r}; "
            f"errs={errs}")


def test_validate_reject_match_on_other_expect_is_error(ext_lab, tmp_path):
    """reject_match is only allowed when expect='rejected'. Forbidden for
    confirmed, rolled_back, noop, and none."""
    for expect_value in ("confirmed", "rolled_back", "noop", "none"):
        _write_scenario(tmp_path, "01-x", f"""
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "{expect_value}"
timeout = 60
batch = "set foo=bar"
reject_match = "unit-test reason"
""")
        lab = nl.load_lab(ext_lab)
        scens = nl.load_scenarios(tmp_path / "scenarios")
        errs = nl.validate_scenarios(lab, scens)
        matching = [e for e in errs
                    if "01-x.toml" in e
                    and "reject_match" in e
                    and "only allowed when expect = 'rejected'" in e]
        assert matching, (
            f"reject_match on expect={expect_value!r} should error; "
            f"errs={errs}")


def test_validate_invalid_reject_match_regex_is_error(ext_lab, tmp_path):
    """A reject_match that re.compile cannot parse is an error."""
    _write_scenario(tmp_path, "01-x", """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "rejected"
timeout = 60
batch = "set foo=bar"
reject_match = "("
""")
    lab = nl.load_lab(ext_lab)
    scens = nl.load_scenarios(tmp_path / "scenarios")
    errs = nl.validate_scenarios(lab, scens)
    matching = [e for e in errs
                if "01-x.toml" in e
                and "reject_match" in e
                and "not a valid regex" in e]
    assert matching, f"invalid regex should error; got {errs}"


def test_validate_valid_reject_match_is_clean(ext_lab, tmp_path):
    """expect='rejected' + valid regex reject_match -> no errors."""
    _write_scenario(tmp_path, "01-x", """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "rejected"
timeout = 60
batch = "set foo=bar"
reject_match = "only set/add are allowed"
""")
    lab = nl.load_lab(ext_lab)
    scens = nl.load_scenarios(tmp_path / "scenarios")
    errs = nl.validate_scenarios(lab, scens)
    assert errs == []


def test_reject_match_matches_stdout_stderr_or_both(ext_lab, tmp_path):
    """reject_match.search uses re.MULTILINE over plan stdout+stderr."""
    pattern = r"^fingerprint: ([0-9a-f]+)$"
    # The plan stdout contains the marker line ("staging rejected" is what
    # makes it a rejection at all; the reject_match needle is somewhere else).
    plan_base = STAGING_REJECTED_STDOUT  # needed so the runner classifies 'rejected'
    scen_body = f"""
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "rejected"
timeout = 60
batch = "set foo=bar"
reject_match = '{pattern}'

[[post]]
device = "lab-r1"
cmd = "true"
"""
    _write_scenario(tmp_path, "01-x", scen_body)
    lab = nl.load_lab(ext_lab)
    scen = _load_one(tmp_path, "01-x")

    # Pattern present in stdout only (needs MULTILINE '^...$' to anchor).
    out_only = plan_base + "fingerprint: deadbeefcafebabe1234567890abcdef\n"
    with mock.patch.object(nl, "_run", side_effect=[
        _cp(returncode=1, stdout=out_only, stderr=""),
        _cp(returncode=0),
    ]):
        rec = nl.run_scenario(lab, scen)
    assert rec["reject"]["matched"] is True, rec

    # Pattern present in stderr only.
    with mock.patch.object(nl, "_run", side_effect=[
        _cp(returncode=1, stdout=plan_base, stderr=out_only),
        _cp(returncode=0),
    ]):
        rec = nl.run_scenario(lab, scen)
    assert rec["reject"]["matched"] is True, rec

    # Pattern matches a middle line (MULTILINE '^...' must anchor only at start
    # of a line, not the whole string).
    multiline = (
        "preamble\n" + plan_base +
        "fingerprint: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n" +
        "trailer\n"
    )
    with mock.patch.object(nl, "_run", side_effect=[
        _cp(returncode=1, stdout=multiline, stderr=""),
        _cp(returncode=0),
    ]):
        rec = nl.run_scenario(lab, scen)
    assert rec["reject"]["matched"] is True, rec


def test_rejected_for_another_reason_is_fail_with_the_specific_reason(
        ext_lab, tmp_path):
    """Marker + reason that does NOT match reject_match -> outcome rejected,
    FAIL (error None), rec['passed'] is False, rec['reject']['matched'] is False,
    posts and AFTER probes still ran, short_reason names the pattern and the
    plan-output tail."""
    _write_scenario(tmp_path, "01-x", r"""
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "rejected"
timeout = 60
batch = "set foo=bar"
reject_match = 'this pattern does not appear in the plan output'

regression = ["reg_ok"]

[[post]]
device = "lab-r1"
cmd = "true"
""")
    lab = nl.load_lab(ext_lab)
    scen = _load_one(tmp_path, "01-x")
    plan_stdout = STAGING_REJECTED_STDOUT
    plan_stderr = "ERROR: only set/add/add_list/del_list/delete/rename/reorder are allowed, got: commit system\n"
    with mock.patch.object(nl, "_run", side_effect=[
        _cp(returncode=0),                    # before reg_ok (pass)
        _cp(returncode=1, stdout=plan_stdout, stderr=plan_stderr),  # plan
        _cp(returncode=0),                    # after reg_ok (want pass for non-confirmed)
        _cp(returncode=0),                    # post
    ]):
        rec = nl.run_scenario(lab, scen)
    assert rec["outcome"] == "rejected"
    assert rec["error"] is None
    assert rec["passed"] is False
    assert rec["reject"] is not None
    assert rec["reject"]["matched"] is False
    assert rec["reject"]["pattern"] == (
        "this pattern does not appear in the plan output")
    assert len(rec["after"]) == 1
    assert len(rec["post"]) == 1
    # short_reason exact match
    expected_tail = nl._tail(plan_stdout + "\n" + plan_stderr)
    expected = (
        "rejected, but plan output does not match reject_match "
        "/this pattern does not appear in the plan output/: " + expected_tail
    )
    assert nl.short_reason(rec) == expected


def test_reject_match_is_ignored_when_outcome_is_not_rejected(ext_lab, tmp_path):
    """A scenario with reject_match whose plan is noop -> rec['reject'] is None."""
    _write_scenario(tmp_path, "01-x", """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "noop"
timeout = 60
batch = "set foo=bar"
reject_match = "unit-test reason"

[[post]]
device = "lab-r1"
cmd = "true"
""")
    lab = nl.load_lab(ext_lab)
    scen = _load_one(tmp_path, "01-x")
    with mock.patch.object(nl, "_run", side_effect=[
        _cp(returncode=1, stdout="no changes staged\n"),
        _cp(returncode=0),
    ]):
        rec = nl.run_scenario(lab, scen)
    assert rec["outcome"] == "noop"
    assert rec["reject"] is None
    assert rec["passed"] is True


def test_reject_record_survives_json(fake_lab, monkeypatch, tmp_path):
    """A rejected scenario's rec['reject'] ends up in the JSON results under
    scenarios[0]['reject']."""
    lab_toml, scen_dir = fake_lab
    (scen_dir / "01-a.toml").write_text("""
name = "01-a"
description = "a"
target = "lab-r1"
reset = []
expect = "rejected"
timeout = 60
batch = "set foo=bar"
reject_match = "unit-test reason"
[[post]]
device = "lab-r1"
cmd = "true"
""")
    monkeypatch.setattr(nl, "SCEN_DIR", scen_dir)
    monkeypatch.setattr(nl, "RESULTS_DIR", scen_dir / "results")
    with mock.patch.object(nl, "_run", side_effect=[
        _cp(returncode=1, stdout=STAGING_REJECTED_STDOUT,
            stderr="ERROR: unit-test reason\n"),
        _cp(returncode=0),
    ]):
        rc = nl.main(["--lab", str(lab_toml), "--lane", "password",
                      "--scenarios", str(scen_dir),
                      "--results", str(scen_dir / "r.json"),
                      "--no-lab-reset"])
    assert rc == 0
    payload = json.loads((scen_dir / "r.json").read_text())
    assert len(payload["scenarios"]) == 1
    assert payload["scenarios"][0]["reject"] == {
        "pattern": "unit-test reason", "matched": True,
    }


# ---------- Real scenarios -----------------------------------------------

def test_real_rejected_scenarios_have_reject_match(scenarios):
    """Exactly 04-commit-smuggling, 05-bad-syntax, 08-partial-batch carry a
    non-empty reject_match (and they all expect 'rejected'); every other
    real scenario has None."""
    by_name = {s.name: s for s in scenarios}
    assert set(by_name) == {
        "01-static-lease", "02-mgmt-ip-lockout", "03-mgmt-firewall-drop",
        "04-commit-smuggling", "05-bad-syntax", "06-port-forward-from-isp",
        "07-wan-down-isolation", "08-partial-batch", "09-add-section",
    }
    expected_with = {"04-commit-smuggling", "05-bad-syntax", "08-partial-batch"}
    for name, scen in by_name.items():
        if name in expected_with:
            assert scen.reject_match, (
                f"{name} should have a non-empty reject_match; got "
                f"{scen.reject_match!r}")
            assert scen.expect == "rejected"
        else:
            assert scen.reject_match is None, (
                f"{name} should not have a reject_match; got "
                f"{scen.reject_match!r}")

    # All real scenarios validate cleanly against the real lab.
    real_lab = nl.load_lab(LAB_TOML)
    errs = nl.validate_scenarios(real_lab, scenarios)
    assert errs == [], f"real scenarios should validate; got {errs}"


def test_real_reject_matches_pin_the_reason():
    """With the realistic plan refusal shapes, each of 04 / 05 / 08 matches its
    own reason and FAILs with the other scenarios' shapes plus the infra
    failures (which are ERROR, not FAIL)."""
    real_lab = nl.load_lab(LAB_TOML)
    real_scenarios = {s.name: s for s in nl.load_scenarios(SCEN_DIR)}

    def posts_for(scen):
        """Return the expected posts to satisfy each scenario's [[post]]
        expectations. The post's regex is anchored (^...$); strip the anchors
        and append a newline so the regex matches."""
        results = []
        for p in scen.post:
            pat = p.expect_stdout or ""
            if pat.startswith("^"):
                pat = pat[1:]
            if pat.endswith("$"):
                pat = pat[:-1]
            results.append(_cp(returncode=0, stdout=pat + "\n"))
        return results

    def run_with_plan(scen, plan_pair):
        """Dispatch _run: refused plan, then posts. (We never reach apply.)"""
        side_effects = [
            _cp(returncode=1, stdout=plan_pair["stdout"],
                stderr=plan_pair["stderr"]),
        ]
        side_effects.extend(posts_for(scen))
        return side_effects

    # Scenarios to test, with the post stdout mapping.
    cases = [
        ("04-commit-smuggling", REJECT_04_STDERR, lambda r: r == 1),
        ("05-bad-syntax", REJECT_05_STDERR, lambda r: r == 0),
        ("08-partial-batch", REJECT_08_STDERR, lambda r: r == 1),
    ]

    # Each scenario must PASS with its own refusal text and FAIL with the
    # other scenarios' refusal text (and with the state refusals).
    for name, own_stderr, post_rc_fn in cases:
        scen = real_scenarios[name]
        # PASS with own text.
        with mock.patch.object(nl, "_run",
                               side_effect=run_with_plan(scen, _refused_pair(own_stderr))):
            rec = nl.run_scenario(real_lab, scen)
        assert rec["outcome"] == "rejected", f"{name}: own reason: rec={rec}"
        assert rec["passed"] is True, (
            f"{name}: own reason: passed was {rec['passed']}; rec={rec}")
        assert rec["reject"]["matched"] is True

    # FAIL with cross-text: 04's text on 05 or 08; 05's text on 04; 08's text on
    # 04 or 05; state-refusal texts on any of them. 05-on-08 is NOT asserted:
    # 08's regex includes 'Invalid argument', so 05's text matches; the spec
    # says don't assert exclusivity between 05 and 08.
    cross_texts = [
        ("04 on 05", "05-bad-syntax", REJECT_04_STDERR),
        ("04 on 08", "08-partial-batch", REJECT_04_STDERR),
        ("05 on 04", "04-commit-smuggling", REJECT_05_STDERR),
        ("08 on 04", "04-commit-smuggling", REJECT_08_STDERR),
        ("08 on 05", "05-bad-syntax", REJECT_08_STDERR),
        ("state open on 04", "04-commit-smuggling", REJECT_STATE_OPEN_STDERR),
        ("state open on 05", "05-bad-syntax", REJECT_STATE_OPEN_STDERR),
        ("state open on 08", "08-partial-batch", REJECT_STATE_OPEN_STDERR),
        ("state changes on 04", "04-commit-smuggling", REJECT_STATE_CHANGES_STDERR),
        ("state changes on 05", "05-bad-syntax", REJECT_STATE_CHANGES_STDERR),
        ("state changes on 08", "08-partial-batch", REJECT_STATE_CHANGES_STDERR),
        ("state lock on 04", "04-commit-smuggling", REJECT_STATE_LOCK_STDERR),
        ("state lock on 05", "05-bad-syntax", REJECT_STATE_LOCK_STDERR),
        ("state lock on 08", "08-partial-batch", REJECT_STATE_LOCK_STDERR),
    ]
    for label, name, stderr in cross_texts:
        scen = real_scenarios[name]
        with mock.patch.object(nl, "_run",
                               side_effect=run_with_plan(scen, _refused_pair(stderr))):
            rec = nl.run_scenario(real_lab, scen)
        assert rec["outcome"] == "rejected", (
            f"{label}: outcome should be rejected; got {rec['outcome']}")
        assert rec["passed"] is False, f"{label}: passed was True"
        assert rec["reject"]["matched"] is False

    # Infra failures on each of the three: ERROR, not FAIL.
    for where, text in INFRA_FAILURES:
        for name in ("04-commit-smuggling", "05-bad-syntax", "08-partial-batch"):
            with mock.patch.object(nl, "_run",
                                   side_effect=[_refused(where, text, returncode=1)]):
                rec = nl.run_scenario(real_lab, real_scenarios[name])
            assert nl.status_letter(rec) == "ERROR", (
                f"{name} on {where}:{text!r}: status letter "
                f"was {nl.status_letter(rec)}; rec.error={rec.get('error')!r}")

    # 08 FAILs with an (exit 1) variant while 05 accepts (exit 1).
    scen = real_scenarios["08-partial-batch"]
    with mock.patch.object(nl, "_run",
                           side_effect=run_with_plan(scen,
                                                     _refused_pair(REJECT_08_EXIT1_STDERR))):
        rec = nl.run_scenario(real_lab, scen)
    assert rec["outcome"] == "rejected"
    assert rec["passed"] is False
    assert rec["reject"]["matched"] is False

    scen = real_scenarios["05-bad-syntax"]
    with mock.patch.object(nl, "_run",
                           side_effect=run_with_plan(scen,
                                                     _refused_pair(REJECT_05_EXIT1_STDERR))):
        rec = nl.run_scenario(real_lab, scen)
    assert rec["outcome"] == "rejected"
    assert rec["passed"] is True
    assert rec["reject"]["matched"] is True


def test_reject_match_fragments_exist_in_the_helper_scripts():
    """Drift guard: the regexes the real scenarios rely on must still match
    the helper scripts. If somebody rewords the helpers, the scenarios'
    reject_match lines must be updated too."""
    safe = (LAB_DIR.parent / "scripts" / "owrt-safe-apply.sh").read_text()
    change = (LAB_DIR.parent / "scripts" / "owrt-change.sh").read_text()
    assert "only set/add/add_list/del_list/delete/rename/reorder are allowed, got:" in safe
    assert "uci batch rejected the changes (exit $rc), nothing staged:" in safe
    assert "die \"staging rejected\"" in change


# ============================================================================
# Reset retry on VM config-lock timeout.
#
# After every `qm rollback` the old QEMU process exit runs `qm cleanup <vmid>
# 1 0`, which holds the VM config lock for about 35 s. A rollback that starts
# inside that window waits at most 10 s for the lock; the PVE task then ends
# with an exitstatus such as `can't lock file '/var/lock/qemu-server/lock-702
# .conf' - got timeout`. The runner must retry ONLY when the task's exitstatus
# contains "can't lock file" (up to RESET_MAX_ATTEMPTS attempts,
# RESET_RETRY_SLEEP_S seconds apart), and report the last exitstatus when it
# gives up.
# ============================================================================

LOCK = "can't lock file '/var/lock/qemu-server/lock-702.conf' - got timeout"


def _audit_scenario_1device(tmp_path):
    """Write an audit scenario: reset lab-r1, no batch, one passing post."""
    _write_scenario(tmp_path, "01-a", """
name = "01-a"
description = "a"
target = "lab-r1"
reset = ["lab-r1"]
expect = "none"
timeout = 60
batch = ""

[[post]]
device = "lab-r1"
cmd = "true"
""")
    return nl.load_scenarios(tmp_path / "scenarios")


def _make_rollback_counter():
    """Counter shared between the fake pve_rollback and the test.

    Returning a list lets the fake mutate it (`counter[0] += 1`) and the test
    read it without `nonlocal`."""
    return [0]


def _fake_rollback_factory(counter):
    def fake_rollback(lab, dev):
        counter[0] += 1
        return f"UPID:{counter[0]}"
    return fake_rollback


# 1. [must fail first]
def test_reset_retries_after_vm_lock_timeout_and_passes_on_attempt_2(
        fake_lab, monkeypatch):
    """First task stopped with LOCK, second task OK -> PASS, two attempts,
    one 12 s pause, ssh_ready called once (after the second attempt)."""
    lab_toml, scen_dir = fake_lab
    scens = _audit_scenario_1device(scen_dir.parent)
    lab = nl.load_lab(lab_toml)
    status_by_upid = {
        "UPID:1": {"status": "stopped", "exitstatus": LOCK},
        "UPID:2": {"status": "stopped", "exitstatus": "OK"},
    }
    counter = _make_rollback_counter()
    ssh_calls: list[str] = []
    sleeps: list[float] = []
    monkeypatch.setattr(nl, "pve_rollback", _fake_rollback_factory(counter))
    monkeypatch.setattr(
        nl, "pve_task_status",
        lambda lab, upid: status_by_upid[upid])
    monkeypatch.setattr(
        nl, "ssh_ready",
        lambda lab, dev, timeout_s=120: ssh_calls.append(dev.name) or True)
    monkeypatch.setattr(nl.time, "sleep",
                        lambda s, *a, **k: sleeps.append(s))
    with mock.patch.object(nl, "_run", return_value=_cp(returncode=0)):
        rec = nl.run_scenario(lab, scens[0])
    assert rec["error"] is None
    assert rec["passed"] is True
    assert rec["reset"] == [
        {"device": "lab-r1", "upid": "UPID:1",
         "task_ok": False, "exitstatus": LOCK, "attempt": 1},
        {"device": "lab-r1", "upid": "UPID:2",
         "task_ok": True, "exitstatus": "OK", "attempt": 2},
    ]
    assert counter[0] == 2
    assert sleeps.count(12) == 1
    assert ssh_calls == ["lab-r1"]


# 2. [must fail first]
def test_reset_gives_up_after_four_lock_timeouts(fake_lab, monkeypatch):
    """Four tasks all stopped with LOCK -> ERROR after 4 attempts, three 12 s
    pauses (none after the last attempt), no ssh_ready, post mock not called."""
    lab_toml, scen_dir = fake_lab
    scens = _audit_scenario_1device(scen_dir.parent)
    lab = nl.load_lab(lab_toml)
    status_by_upid = {f"UPID:{i}": {"status": "stopped", "exitstatus": LOCK}
                      for i in range(1, 5)}
    counter = _make_rollback_counter()
    sleeps: list[float] = []
    monkeypatch.setattr(nl, "pve_rollback", _fake_rollback_factory(counter))
    monkeypatch.setattr(
        nl, "pve_task_status",
        lambda lab, upid: status_by_upid[upid])
    monkeypatch.setattr(nl, "ssh_ready",
                        lambda lab, dev, timeout_s=120: True)
    monkeypatch.setattr(nl.time, "sleep",
                        lambda s, *a, **k: sleeps.append(s))
    run_calls: list[list[str]] = []
    def tracking_run(args, **kwargs):
        run_calls.append(args)
        return _cp(returncode=0)
    monkeypatch.setattr(nl, "_run", tracking_run)
    rec = nl.run_scenario(lab, scens[0])
    assert nl.status_letter(rec) == "ERROR"
    assert rec["passed"] is False
    err = rec["error"]
    assert err.startswith("reset of lab-r1 did not finish OK")
    assert "can't lock file" in err
    assert "attempt 4 of 4" in err
    assert len(rec["reset"]) == 4
    for i, r in enumerate(rec["reset"], start=1):
        assert r == {"device": "lab-r1", "upid": f"UPID:{i}",
                      "task_ok": False, "exitstatus": LOCK, "attempt": i}
    assert counter[0] == 4
    assert sleeps.count(12) == 3
    # Nothing after the reset ran: no _run calls for posts, var resolution,
    # plan, apply.
    assert run_calls == []


# 3. [must fail first]
def test_reset_does_not_retry_a_non_lock_failure(fake_lab, monkeypatch):
    """One task stopped with a non-lock error -> 1 attempt, no 12 s pause,
    error contains that exitstatus and 'attempt 1 of 4'."""
    lab_toml, scen_dir = fake_lab
    scens = _audit_scenario_1device(scen_dir.parent)
    lab = nl.load_lab(lab_toml)
    other = ("unable to rollback 'baseline-pw': snapshot does not exist")
    status_by_upid = {"UPID:1": {"status": "stopped", "exitstatus": other}}
    counter = _make_rollback_counter()
    sleeps: list[float] = []
    monkeypatch.setattr(nl, "pve_rollback", _fake_rollback_factory(counter))
    monkeypatch.setattr(
        nl, "pve_task_status",
        lambda lab, upid: status_by_upid[upid])
    monkeypatch.setattr(nl, "ssh_ready",
                        lambda lab, dev, timeout_s=120: True)
    monkeypatch.setattr(nl.time, "sleep",
                        lambda s, *a, **k: sleeps.append(s))
    with mock.patch.object(nl, "_run", return_value=_cp(returncode=0)):
        rec = nl.run_scenario(lab, scens[0])
    assert len(rec["reset"]) == 1
    assert counter[0] == 1
    assert sleeps.count(12) == 0
    err = rec["error"]
    assert err.startswith("reset of lab-r1 did not finish OK")
    assert other in err
    assert "attempt 1 of 4" in err


# 4. [must fail first]
def test_reset_lock_then_other_failure_stops_and_reports_the_last_exitstatus(
        fake_lab, monkeypatch):
    """Attempt 1 LOCK, attempt 2 a different error: 2 records, 1 pause,
    no third attempt, error contains the SECOND exitstatus and 'attempt 2
    of 4'."""
    lab_toml, scen_dir = fake_lab
    scens = _audit_scenario_1device(scen_dir.parent)
    lab = nl.load_lab(lab_toml)
    other = "TASK ERROR: some unrelated rollback failure"
    status_by_upid = {
        "UPID:1": {"status": "stopped", "exitstatus": LOCK},
        "UPID:2": {"status": "stopped", "exitstatus": other},
    }
    counter = _make_rollback_counter()
    sleeps: list[float] = []
    monkeypatch.setattr(nl, "pve_rollback", _fake_rollback_factory(counter))
    monkeypatch.setattr(
        nl, "pve_task_status",
        lambda lab, upid: status_by_upid[upid])
    monkeypatch.setattr(nl, "ssh_ready",
                        lambda lab, dev, timeout_s=120: True)
    monkeypatch.setattr(nl.time, "sleep",
                        lambda s, *a, **k: sleeps.append(s))
    with mock.patch.object(nl, "_run", return_value=_cp(returncode=0)):
        rec = nl.run_scenario(lab, scens[0])
    assert len(rec["reset"]) == 2
    assert counter[0] == 2
    assert sleeps.count(12) == 1
    err = rec["error"]
    assert other in err
    assert "attempt 2 of 4" in err


# 5. [must fail first]
def test_reset_task_that_never_stops_is_not_retried(fake_lab, monkeypatch):
    """Patch pve_wait_task to return {"status": "running"} -> 1 record with
    task_ok=False and exitstatus=None; pve_rollback called once; no 12 s
    pause; ERROR."""
    lab_toml, scen_dir = fake_lab
    scens = _audit_scenario_1device(scen_dir.parent)
    lab = nl.load_lab(lab_toml)
    counter = _make_rollback_counter()
    sleeps: list[float] = []
    monkeypatch.setattr(nl, "pve_rollback", _fake_rollback_factory(counter))
    monkeypatch.setattr(nl, "pve_wait_task",
                        lambda lab, upid: {"status": "running"})
    monkeypatch.setattr(nl.time, "sleep",
                        lambda s, *a, **k: sleeps.append(s))
    with mock.patch.object(nl, "_run", return_value=_cp(returncode=0)):
        rec = nl.run_scenario(lab, scens[0])
    assert len(rec["reset"]) == 1
    assert rec["reset"][0]["task_ok"] is False
    assert rec["reset"][0]["exitstatus"] is None
    assert counter[0] == 1
    assert sleeps.count(12) == 0
    assert nl.status_letter(rec) == "ERROR"
    assert rec["passed"] is False


# 6. [must fail first]
def test_reset_first_attempt_ok_records_attempt_1(fake_lab, monkeypatch):
    """First task OK -> 1 record with exitstatus='OK' and attempt=1; no 12 s
    pause; ssh_ready called once; PASS."""
    lab_toml, scen_dir = fake_lab
    scens = _audit_scenario_1device(scen_dir.parent)
    lab = nl.load_lab(lab_toml)
    counter = _make_rollback_counter()
    ssh_calls: list[str] = []
    sleeps: list[float] = []
    monkeypatch.setattr(nl, "pve_rollback", _fake_rollback_factory(counter))
    monkeypatch.setattr(
        nl, "pve_task_status",
        lambda lab, upid: {"status": "stopped", "exitstatus": "OK"})
    monkeypatch.setattr(
        nl, "ssh_ready",
        lambda lab, dev, timeout_s=120: ssh_calls.append(dev.name) or True)
    monkeypatch.setattr(nl.time, "sleep",
                        lambda s, *a, **k: sleeps.append(s))
    with mock.patch.object(nl, "_run", return_value=_cp(returncode=0)):
        rec = nl.run_scenario(lab, scens[0])
    assert len(rec["reset"]) == 1
    assert rec["reset"][0]["exitstatus"] == "OK"
    assert rec["reset"][0]["attempt"] == 1
    assert counter[0] == 1
    assert sleeps.count(12) == 0
    assert ssh_calls == ["lab-r1"]
    assert rec["passed"] is True


# 7. [must fail first]
def test_reset_exception_on_second_attempt_keeps_the_first_record(
        fake_lab, monkeypatch):
    """First task LOCK, then pve_rollback raises RuntimeError on the second
    call: rec['error'] contains 'RuntimeError', len(rec['reset']) == 1 and
    that record is the attempt-1 LOCK record."""
    lab_toml, scen_dir = fake_lab
    scens = _audit_scenario_1device(scen_dir.parent)
    lab = nl.load_lab(lab_toml)
    status_by_upid = {"UPID:1": {"status": "stopped", "exitstatus": LOCK}}

    rollback_calls = [0]

    def fake_rollback(lab, dev):
        rollback_calls[0] += 1
        if rollback_calls[0] == 2:
            raise RuntimeError("curl failed")
        return f"UPID:{rollback_calls[0]}"

    sleeps: list[float] = []
    monkeypatch.setattr(nl, "pve_rollback", fake_rollback)
    monkeypatch.setattr(
        nl, "pve_task_status",
        lambda lab, upid: status_by_upid[upid])
    monkeypatch.setattr(nl.time, "sleep",
                        lambda s, *a, **k: sleeps.append(s))
    with mock.patch.object(nl, "_run", return_value=_cp(returncode=0)):
        rec = nl.run_scenario(lab, scens[0])
    assert "RuntimeError" in rec["error"]
    assert len(rec["reset"]) == 1
    assert rec["reset"][0] == {
        "device": "lab-r1", "upid": "UPID:1",
        "task_ok": False, "exitstatus": LOCK, "attempt": 1,
    }


# 8. [must fail first]
def test_reset_two_devices_retry_independently(monkeypatch, tmp_path):
    """Use the real lab (lab-isp 701, lab-r1 702). Scenario resets both.
    lab-isp loses the lock once then succeeds; lab-r1 succeeds at once.
    Assert attempt numbering restarts per device and ssh_ready call order."""
    real_lab = nl.load_lab(LAB_TOML)
    _write_scenario(tmp_path, "01-x", """
name = "01-x"
description = "x"
target = "lab-r1"
reset = ["lab-isp", "lab-r1"]
expect = "none"
timeout = 60
batch = ""

[[post]]
device = "lab-r1"
cmd = "true"
""")
    scens = nl.load_scenarios(tmp_path / "scenarios")
    status_by_upid = {
        "UPID:1": {"status": "stopped", "exitstatus": LOCK},
        "UPID:2": {"status": "stopped", "exitstatus": "OK"},
        "UPID:3": {"status": "stopped", "exitstatus": "OK"},
    }
    counter = _make_rollback_counter()
    ssh_calls: list[str] = []
    sleeps: list[float] = []
    monkeypatch.setattr(nl, "pve_rollback", _fake_rollback_factory(counter))
    monkeypatch.setattr(
        nl, "pve_task_status",
        lambda lab, upid: status_by_upid[upid])
    monkeypatch.setattr(
        nl, "ssh_ready",
        lambda lab, dev, timeout_s=120: ssh_calls.append(dev.name) or True)
    monkeypatch.setattr(
        nl, "wait_settled",
        lambda lab, dname: {
            "device": dname, "settled": True, "waited_s": 10.0,
            "polls": 11, "changes": 0, "last_rc": 0,
        })
    monkeypatch.setattr(nl.time, "sleep",
                        lambda s, *a, **k: sleeps.append(s))
    with mock.patch.object(nl, "_run", return_value=_cp(returncode=0)):
        rec = nl.run_scenario(real_lab, scens[0])
    assert rec["passed"] is True
    assert rec["reset"] == [
        {"device": "lab-isp", "upid": "UPID:1",
         "task_ok": False, "exitstatus": LOCK, "attempt": 1},
        {"device": "lab-isp", "upid": "UPID:2",
         "task_ok": True, "exitstatus": "OK", "attempt": 2},
        {"device": "lab-r1", "upid": "UPID:3",
         "task_ok": True, "exitstatus": "OK", "attempt": 1},
    ]
    assert ssh_calls == ["lab-isp", "lab-r1"]
    # Only the isp lock triggered one 12 s pause.
    assert sleeps.count(12) == 1


def test_reset_lock_then_ok_through_the_curl_layer(fake_lab, monkeypatch):
    """The whole chain with only `_run` faked (curl and ssh): the real
    pve_rollback / pve_task_status / pve_wait_task / ssh_ready run. A lock
    failure then OK gives exactly four curl calls in order (POST, GET, POST,
    GET), two records, one 12 s pause, PASS."""
    lab_toml, scen_dir = fake_lab
    scens = _audit_scenario_1device(scen_dir.parent)
    lab = nl.load_lab(lab_toml)
    posted = iter(["UPID:1", "UPID:2"])
    exitstatus_by_upid = {"UPID:1": LOCK, "UPID:2": "OK"}
    curl_calls: list[tuple[str, str]] = []
    sleeps: list[float] = []

    def fake_run(args, **kw):
        if args[0] == "curl":
            method = args[args.index("-X") + 1]
            url = args[-1]
            curl_calls.append((method, url))
            if method == "POST":
                return _cp(stdout=json.dumps({"data": next(posted)}))
            upid = urllib.parse.unquote(
                url.rsplit("/tasks/", 1)[1].rsplit("/status", 1)[0])
            return _cp(stdout=json.dumps({"data": {
                "status": "stopped",
                "exitstatus": exitstatus_by_upid[upid]}}))
        return _cp(returncode=0)   # ssh_ready probe and the post

    monkeypatch.setattr(nl, "_run", fake_run)
    monkeypatch.setattr(nl.time, "sleep", lambda s, *a, **k: sleeps.append(s))
    rec = nl.run_scenario(lab, scens[0])
    assert rec["error"] is None
    assert rec["passed"] is True
    assert [m for m, _u in curl_calls] == ["POST", "GET", "POST", "GET"]
    assert all("/qemu/9102/snapshot/" in u and u.endswith("/rollback")
               for m, u in curl_calls if m == "POST")
    assert [r["exitstatus"] for r in rec["reset"]] == [LOCK, "OK"]
    assert [r["attempt"] for r in rec["reset"]] == [1, 2]
    assert sleeps.count(12) == 1


# 9. [passes on the old runner; pins unchanged behaviour]
def test_reset_ssh_not_ready_after_rollback_is_still_an_error(
        fake_lab, monkeypatch):
    """Task OK, ssh_ready False -> rec['error'] == 'ssh to lab-r1 not ready
    after reset'."""
    lab_toml, scen_dir = fake_lab
    scens = _audit_scenario_1device(scen_dir.parent)
    lab = nl.load_lab(lab_toml)
    counter = _make_rollback_counter()
    monkeypatch.setattr(nl, "pve_rollback", _fake_rollback_factory(counter))
    monkeypatch.setattr(
        nl, "pve_task_status",
        lambda lab, upid: {"status": "stopped", "exitstatus": "OK"})
    monkeypatch.setattr(nl, "ssh_ready",
                        lambda lab, dev, timeout_s=120: False)
    rec = nl.run_scenario(lab, scens[0])
    assert rec["error"] == "ssh to lab-r1 not ready after reset"


# 10. [must fail first]
def test_pve_wait_task_returns_the_final_status_dict(lab):
    """pve_wait_task returns the LAST status dict; on timeout the running
    dict; pve_wait_task_ok is False for LOCK, True for OK."""
    with mock.patch.object(
            nl, "pve_task_status",
            side_effect=[
                {"status": "running"},
                {"status": "running"},
                {"status": "stopped", "exitstatus": LOCK, "upid": "UPID:1"},
            ]), mock.patch("newton_lab_test.time.sleep"):
        result = nl.pve_wait_task(lab, "UPID:1")
    assert result == {"status": "stopped",
                      "exitstatus": LOCK, "upid": "UPID:1"}

    with mock.patch.object(
            nl, "pve_task_status",
            return_value={"status": "running"}), \
            mock.patch("newton_lab_test.time.sleep"):
        result = nl.pve_wait_task(lab, "UPID:1", timeout_s=0)
    assert result == {"status": "running"}

    # pve_wait_task_ok is a thin wrapper around pve_wait_task.
    with mock.patch.object(
            nl, "pve_task_status",
            return_value={"status": "stopped", "exitstatus": LOCK}):
        assert nl.pve_wait_task_ok(lab, "UPID:1") is False
    with mock.patch.object(
            nl, "pve_task_status",
            return_value={"status": "stopped", "exitstatus": "OK"}):
        assert nl.pve_wait_task_ok(lab, "UPID:1") is True


# 11. [must fail first]
def test_pve_reset_helper_returns_the_last_record_and_checks_the_device_first(
        lab, monkeypatch):
    """Call nl.pve_reset directly: lock then OK -> returns the second
    record; records has both. With an unknown device name -> KeyError and
    pve_rollback not called."""
    status_by_upid = {
        "UPID:1": {"status": "stopped", "exitstatus": LOCK},
        "UPID:2": {"status": "stopped", "exitstatus": "OK"},
    }
    counter = _make_rollback_counter()
    monkeypatch.setattr(nl, "pve_rollback", _fake_rollback_factory(counter))
    monkeypatch.setattr(
        nl, "pve_task_status",
        lambda lab, upid: status_by_upid[upid])
    monkeypatch.setattr(nl.time, "sleep", lambda s, *a, **k: None)

    records: list[dict] = []
    last = nl.pve_reset(lab, "lab-r1", records)
    assert last["task_ok"] is True
    assert last["attempt"] == 2
    assert len(records) == 2
    assert records[1] is last
    assert counter[0] == 2

    # Unknown device -> KeyError; rollback not called.
    counter2 = _make_rollback_counter()
    rollback_calls: list[str] = []
    wait_calls: list[str] = []

    def tracking_rollback(lab, dev):
        rollback_calls.append(dev.name)
        return _fake_rollback_factory(counter2)(lab, dev)

    def tracking_wait(lab, upid):
        wait_calls.append(upid)
        return {"status": "stopped", "exitstatus": "OK"}

    monkeypatch.setattr(nl, "pve_rollback", tracking_rollback)
    monkeypatch.setattr(nl, "pve_wait_task", tracking_wait)
    records2: list[dict] = []
    with pytest.raises(KeyError):
        nl.pve_reset(lab, "lab-does-not-exist", records2)
    assert rollback_calls == []
    assert wait_calls == []
    assert records2 == []


# 12. [must fail first]
def test_reset_constants():
    """The three retry constants exist with the exact expected values."""
    assert nl.PVE_LOCK_TEXT == "can't lock file"
    assert nl.RESET_MAX_ATTEMPTS == 4
    assert nl.RESET_RETRY_SLEEP_S == 12


# ---------- rebooted_restored keeps the APPLYBASE requirement ----------

def test_resolve_applies_base_requires_applybase_for_rebooted_restored():
    rec = {"outcome": "rebooted_restored"}
    assert nl._resolve_applies_base(rec, f"BASEHASH {'b' * 64}\n", "") is False
    assert "APPLYBASE" in rec["error"]
    rec = {"outcome": "rebooted_restored"}
    assert nl._resolve_applies_base(
        rec, f"BASEHASH {'b' * 64}\n", f"APPLYBASE {'b' * 64}\n") is True
    assert rec["base"]["match"] is True


def test_rebooted_restored_without_applybase_fails_scenario(fake_lab):
    lab_toml, scen_dir = fake_lab
    (scen_dir / "01-a.toml").write_text("""
name = "01-a"
description = "a"
target = "lab-r1"
reset = []
expect = "rebooted_restored"
timeout = 60
batch = "set foo=bar"
[[post]]
device = "lab-r1"
cmd = "true"
""")
    lab = nl.load_lab(lab_toml)
    scens = nl.load_scenarios(scen_dir)
    sid = "a" * 32
    plan_out = (f"STAGED session={sid}\nBASEHASH {'b' * 64}\n"
                "----- diff -----\nset foo=bar\n----------------\n")
    apply_out = f"APPLIED session={sid} rollback=60s\n{_reboot_alert(sid)}\n"
    with mock.patch.object(nl, "_run", side_effect=[
        _cp(stdout=plan_out),
        _cp(returncode=1, stdout=apply_out),
        _cp(returncode=0),
    ]):
        rec = nl.run_scenario(lab, scens[0])
    assert rec["outcome"] == "rebooted_restored"
    assert rec["passed"] is False
    assert "APPLYBASE" in (rec["error"] or "")
