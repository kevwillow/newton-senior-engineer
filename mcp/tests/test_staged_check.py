"""MCP side: the staged-config check is part of the plan and of what an approval binds (SC-01..SC-05, SC-11..SC-14).

The router program does the check (`check-staged`, router program 1.3.0); `owrt-change.sh plan` prints a
`STAGEDCHECK fw4 <status>` line before the diff. The server reads it into the plan record's `staged_check`,
which is a plan-hash field: editing it, or planning without it, changes the hash the approval is bound to.
"""

from __future__ import annotations

import io
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest

from exhelp import explained, make_explanation, record_fields, record_fields_display

import newton_mcp.approve as approve
import newton_mcp.server as server
from newton_mcp import plan
from newton_mcp.plan import compute_plan_hash


SID = "fd595e20f2cd6c2b928fe3156f82d5db"
FIXTURE = Path(__file__).parent / "fixtures" / "plan_output.txt"


def _output(line: str | None, *, in_diff: str = "") -> str:
    """The fixture plan output with a STAGEDCHECK line after PLANDIGEST (or none)."""
    text = FIXTURE.read_text()
    marker = "----- diff -----"
    head, tail = text.split(marker, 1)
    if line is not None:
        head = head.rstrip("\n") + "\n" + line + "\n"
    if in_diff:
        tail = tail.replace("\n", "\n" + in_diff + "\n", 1)
    return head + marker + tail


# SC-01: the status words reach the parsed plan.
@pytest.mark.parametrize(("line", "fw4", "reason"), [
    ("STAGEDCHECK fw4 pass", "pass", ""),
    ("STAGEDCHECK fw4 skipped-untouched", "skipped-untouched", ""),
    ("STAGEDCHECK fw4 not-checked network-live-state", "not-checked", "network-live-state"),
    ("STAGEDCHECK fw4 not-checked router-program-has-no-check", "not-checked", "router-program-has-no-check"),
])
def test_sc01_parse_plan_reads_the_stagedcheck_line(line, fw4, reason):
    parsed = server.parse_plan(_output(line))
    assert parsed is not None
    assert parsed["staged_check"]["fw4"] == fw4
    assert parsed["staged_check"]["reason"] == reason


# SC-04: no line, or a line we do not understand, is not-checked: never a pass.
@pytest.mark.parametrize("line", [
    None,
    "STAGEDCHECK fw4 maybe",
    "STAGEDCHECK fw4 pass; reboot",
    "STAGEDCHECK fw4 not-checked Bad Reason",
    "STAGEDCHECK dnsmasq pass",
    "stagedcheck fw4 pass",
])
def test_sc04_missing_or_odd_line_is_not_checked(line):
    parsed = server.parse_plan(_output(line))
    assert parsed is not None
    assert parsed["staged_check"]["fw4"] == "not-checked"
    assert parsed["staged_check"]["reason"] == "no-report"


# SC-12: diff text cannot forge the check result.
def test_sc12_a_line_inside_the_diff_block_is_ignored():
    parsed = server.parse_plan(_output(None, in_diff="STAGEDCHECK fw4 pass"))
    assert parsed["staged_check"]["fw4"] == "not-checked"


# SC-13: the packages with no check before apply are listed; fw4 covers only the firewall.
def test_sc13_not_checked_packages():
    parsed = server.parse_plan(_output("STAGEDCHECK fw4 pass"))
    touched = parsed["touched_configs"]
    assert set(parsed["staged_check"]["not_checked"]) == set(touched) - {"firewall"}
    parsed = server.parse_plan(_output("STAGEDCHECK fw4 not-checked network-live-state"))
    assert set(parsed["staged_check"]["not_checked"]) == set(parsed["touched_configs"])


# SC-02: the field is hash-bound.
def test_sc02_staged_check_is_a_plan_hash_field():
    assert "staged_check" in plan.PLAN_HASH_FIELDS
    record = _record(staged_check={"fw4": "pass", "reason": "", "not_checked": []})
    assert '"staged_check":{"fw4":"pass"' in plan.canonical_plan_json(record)


def _record(**updates):
    record = {
        "device": "quasar",
        "host": "192.0.2.1",
        "session_id": SID,
        "uci_batch": "set dhcp.skilltest=host",
        "diff": "dhcp.skilltest='host'",
        "probes": [["fail"]],
        "timeout_s": 90,
        "base_hash": "8" * 64,
        "requires_approval": True,
        "router_digest": "3" * 64,
        **record_fields("set dhcp.skilltest=host"),
        **record_fields_display(),
        "created_at": "2026-10-24T12:00:00+00:00",
        "staged_at": "2026-10-24T12:00:00+00:00",
    }
    record.update(updates)
    record["plan_hash"] = compute_plan_hash(record)
    return record


def test_sc02b_changing_the_result_changes_the_hash():
    base = _record(staged_check={"fw4": "pass", "reason": "", "not_checked": []})
    for other in (
        {"fw4": "not-checked", "reason": "no-report", "not_checked": []},
        {"fw4": "pass", "reason": "", "not_checked": ["dhcp"]},
        {"fw4": "skipped-untouched", "reason": "", "not_checked": []},
    ):
        assert _record(staged_check=other)["plan_hash"] != base["plan_hash"]


def test_sc02c_a_record_without_the_field_does_not_hash():
    record = _record()
    del record["staged_check"]
    with pytest.raises(ValueError, match="staged_check"):
        compute_plan_hash(record)


# SC-03: plan() stores what the script reported and returns it.
@pytest.fixture
def configured_lab(tmp_path, monkeypatch):
    inventory = tmp_path / "devices-lab.toml"
    inventory.write_text(
        '[devices.quasar]\nplatform = "openwrt"\nhost = "192.0.2.1"\nuser = "root"\nprofile = "lab"\nlab = true\n'
    )
    monkeypatch.setenv("NEWTON_INVENTORY", str(inventory))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))
    return tmp_path


def test_sc03_plan_stores_and_returns_the_result(configured_lab, monkeypatch):
    monkeypatch.setattr(
        server.NewtonService, "run_script",
        lambda *a, **k: subprocess.CompletedProcess([], 0, _output("STAGEDCHECK fw4 skipped-untouched"), ""),
    )
    monkeypatch.setattr(server.NewtonService, "read", lambda self, d, c: {"exit_code": 0})
    batch = "set dhcp.skilltest=host"
    planned = server.newton_plan_change("quasar", batch, **explained(batch))
    assert planned["staged_check"]["fw4"] == "skipped-untouched"
    saved = json.loads((configured_lab / "state" / "plans" / f"{planned['session_id']}.json").read_text())
    assert saved["staged_check"]["fw4"] == "skipped-untouched"
    assert saved["plan_hash"] == compute_plan_hash(saved)
    tampered = dict(saved, staged_check={"fw4": "pass", "reason": "", "not_checked": []})
    assert compute_plan_hash(tampered) != saved["plan_hash"]


def test_sc03b_apply_refuses_an_edited_staged_check(configured_lab, monkeypatch):
    record = _record(host="192.0.2.1", requires_approval=False, staged_check={"fw4": "not-checked", "reason": "no-report", "not_checked": ["dhcp"]})
    plans = configured_lab / "state" / "plans"
    plans.mkdir(parents=True)
    record["staged_check"] = {"fw4": "pass", "reason": "", "not_checked": []}
    (plans / f"{SID}.json").write_text(json.dumps(record))
    monkeypatch.setattr(server.NewtonService, "run_script", lambda *a, **k: pytest.fail("must not run"))
    assert "plan record was modified" in server.newton_apply_change("quasar", SID)["error"]


# SC-05: newton-approve prints the result in Newton's own facts, in words an owner reads.
class TTY(io.StringIO):
    def isatty(self):
        return True


def _approve_text(tmp_path, monkeypatch, capsys, record):
    state = tmp_path / "astate"
    (state / "plans").mkdir(parents=True, exist_ok=True)
    (state / "plans" / f"{SID}.json").write_text(json.dumps(record))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(state))
    monkeypatch.setattr(approve.sys, "stdin", TTY("no\n"))
    monkeypatch.setattr(approve, "_getpass", lambda p: pytest.fail("not reached"))
    approve.main([SID])
    return capsys.readouterr().out


def _approvable(**updates):
    record = _record(**updates)
    record["staged_at"] = datetime.now(timezone.utc).isoformat()
    record["plan_hash"] = compute_plan_hash(record)
    return record


def test_sc05_approve_prints_pass_and_the_unchecked_packages(tmp_path, monkeypatch, capsys):
    out = _approve_text(tmp_path, monkeypatch, capsys, _approvable(
        staged_check={"fw4": "pass", "reason": "", "not_checked": ["dhcp", "system"]}))
    assert "Staged check: fw4 passed on the staged config" in out
    assert "NOT CHECKED before apply: dhcp, system" in out


def test_sc05b_approve_says_not_checked_loudly(tmp_path, monkeypatch, capsys):
    out = _approve_text(tmp_path, monkeypatch, capsys, _approvable(
        staged_check={"fw4": "not-checked", "reason": "router-program-has-no-check", "not_checked": ["firewall"]}))
    assert "Staged check: fw4 NOT CHECKED (router-program-has-no-check)" in out
    assert "NOT CHECKED before apply: firewall" in out
    assert "passed" not in out.split("Staged check:")[1].splitlines()[0]


def test_sc05c_approve_untouched_firewall(tmp_path, monkeypatch, capsys):
    out = _approve_text(tmp_path, monkeypatch, capsys, _approvable(
        staged_check={"fw4": "skipped-untouched", "reason": "", "not_checked": ["dhcp"]}))
    assert "Staged check: fw4 not needed, the firewall config is untouched" in out


def test_sc05d_approve_masks_odd_values(tmp_path, monkeypatch, capsys):
    out = _approve_text(tmp_path, monkeypatch, capsys, _approvable(
        staged_check={"fw4": "pass\x1b[31m", "reason": "x", "not_checked": ["a\x1b[2Jb"]}))
    assert "\x1b" not in out
    assert "Staged check: unknown" in out


# SC-14: the existing fw4 precheck on the running config still refuses up front (item 1's follow-up on the MCP path).
@pytest.mark.real_fw4_precheck
def test_sc14_running_fw4_failure_still_refuses_plan(configured_lab, monkeypatch):
    monkeypatch.setattr(
        server.NewtonService, "read",
        lambda self, d, c: {"exit_code": 1, "stdout": "Error: Could not resolve protocol name", "stderr": ""},
    )
    monkeypatch.setattr(server.NewtonService, "run_script", lambda *a, **k: pytest.fail("must not stage"))
    batch = "set dhcp.skilltest=host"
    result = server.newton_plan_change("quasar", batch, **explained(batch))
    assert "fw4 check already fails" in json.dumps(result)
