"""What scripts/owrt-change.sh says when a step fails part way.

Each test pins one message the owner (or the server) acts on: whether a
staged change was really discarded, what the next command is, whether a
change the router says is confirmed gets recorded on this host, and that an
ssh failure is never reported as a router verdict.
"""

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_owrt_change import (  # noqa: E402,F401
    PROG, SCRIPT, SID, _prepare_state_dirs, _wrap_args_with_unshare, fail_verify_rounds,
    plan_record, protocol, remote_calls, run_script, set_router_state, write_changes)

ROUTER = "root@192.0.2.1"
SSH_DOWN = "ssh: connect to host 192.0.2.1 port 22: Connection timed out"
CONFIRMED_STATUS = f"confirmed sid={SID} guard=idle rpcd=- config=other boot=-"
NOT_DISCARDED = (f"the staged change could NOT be discarded (session {SID} is still staged "
                 f"on the router); run: {SCRIPT} abort {ROUTER} {SID}")
RECONCILED = f"CONFIRMED session={SID} (reconciled: "


def _final(result):
    return [l for l in result.stdout.splitlines() if l.strip()][-1]


def _server():
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "mcp"))
    from newton_mcp import server
    return server


def _plan_record(protocol):
    record = plan_record(protocol, ".sha256")
    record.parent.mkdir(parents=True, exist_ok=True)
    record.write_text("0" * 64 + "\n")
    _prepare_state_dirs(protocol)
    return record


# --- the cleanup abort of a failed plan is checked ---


def test_a_seal_refusal_whose_cleanup_abort_fails_says_the_session_is_still_staged(protocol, tmp_path):
    set_router_state(protocol, seal_fail={"rc": 2, "stderr": "error bad-probe 1 unknown-probe"},
                     abort_fail=SSH_DOWN + "\n")
    result = protocol["run_plan"](write_changes(tmp_path))
    assert result.returncode == 1
    assert f"{PROG} abort {SID}" in remote_calls(protocol)
    assert "the staged change was discarded" not in result.stdout
    assert _final(result) == f"ERROR: probes refused: error bad-probe 1 unknown-probe; {NOT_DISCARDED}"


def test_a_seal_that_loses_the_connection_is_not_called_a_probe_refusal(protocol, tmp_path):
    set_router_state(protocol, seal_fail={"rc": 255, "stderr": SSH_DOWN})
    result = protocol["run_plan"](write_changes(tmp_path))
    assert result.returncode == 1
    assert "probes refused" not in result.stdout
    assert _final(result) == (f"ERROR: the connection to the router failed while sealing the plan: "
                              f"{SSH_DOWN}; the staged change was discarded")


def test_a_lost_seal_whose_cleanup_abort_also_fails_names_the_abort_to_run(protocol, tmp_path):
    set_router_state(protocol, seal_fail={"rc": 255, "stderr": SSH_DOWN}, abort_fail=SSH_DOWN + "\n")
    result = protocol["run_plan"](write_changes(tmp_path))
    assert result.returncode == 1
    assert _final(result) == (f"ERROR: the connection to the router failed while sealing the plan: "
                              f"{SSH_DOWN}; {NOT_DISCARDED}")


@pytest.mark.parametrize("abort_ok", [True, False], ids=["abort-ok", "abort-fails"])
def test_a_staged_config_that_fails_fw4_says_whether_it_was_discarded(protocol, tmp_path, abort_ok):
    set_router_state(protocol, hello_overrides={"version": "1.3.0"},
                     check_staged="fw4 fail Error: bad rule",
                     abort_fail=None if abort_ok else SSH_DOWN + "\n")
    result = protocol["run_plan"](write_changes(tmp_path))
    assert result.returncode == 1
    assert f"{PROG} abort {SID}" in remote_calls(protocol)
    tail = "the staged change was discarded" if abort_ok else NOT_DISCARDED
    final = _final(result)
    assert final.startswith("ERROR: staged firewall config fails fw4 check: Error: bad rule")
    assert final.endswith(f"; {tail}")


@pytest.mark.parametrize("abort_ok", [True, False], ids=["abort-ok", "abort-fails"])
def test_a_malformed_seal_reply_discards_the_staged_change(protocol, tmp_path, abort_ok):
    set_router_state(protocol, seal_raw=["base " + "a" * 64],
                     abort_fail=None if abort_ok else SSH_DOWN + "\n")
    result = protocol["run_plan"](write_changes(tmp_path))
    assert result.returncode == 1
    assert f"{PROG} abort {SID}" in remote_calls(protocol)
    tail = "the staged change was discarded" if abort_ok else NOT_DISCARDED
    assert _final(result) == f"ERROR: malformed seal reply; {tail}"
    assert not plan_record(protocol, ".sha256").exists()


def test_a_stage_that_loses_the_connection_says_the_outcome_is_not_known(protocol, tmp_path):
    set_router_state(protocol, stage_fail={"rc": 255, "stderr": SSH_DOWN + "\n"})
    result = protocol["run_plan"](write_changes(tmp_path))
    assert result.returncode == 1
    final = _final(result)
    assert "staging rejected" not in final
    assert final.startswith("ERROR: the connection to the router failed while staging: " + SSH_DOWN)
    assert "whether the change was staged is not known" in final
    assert "plan again" in final


# --- a plan refused because a session is still open says which one ---


def test_a_plan_refused_busy_with_this_logins_session_names_it_and_the_next_step(protocol, tmp_path):
    other = "f" * 32
    set_router_state(protocol, stage_fail={"rc": 3, "stderr": f"error busy root {other}\n"})
    result = protocol["run_plan"](write_changes(tmp_path))
    assert result.returncode == 1
    final = _final(result)
    assert final.startswith(f"ERROR: staging rejected: error busy root {other}; ")
    assert f"session {other} of this login is still open on the router" in final
    assert f"{SCRIPT} apply {ROUTER} {other}" in final
    assert f"{SCRIPT} abort {ROUTER} {other}" in final
    assert "then plan again" in final


def test_a_plan_refused_busy_with_this_logins_held_session_says_to_confirm_or_abort_it(protocol, tmp_path):
    """A held apply of this host is applied, not staged: applying it again is
    refused as already applied, and the router rolls it back when its window
    ends, not after about 45 minutes."""
    other = "f" * 32
    held = protocol["root"] / "state" / "network-agent" / "plans" / f"{other}.held"
    held.parent.mkdir(parents=True, exist_ok=True)
    held.write_text("0 0 1794000000\n")
    _prepare_state_dirs(protocol)
    set_router_state(protocol, stage_fail={"rc": 3, "stderr": f"error busy root {other}\n"})
    result = protocol["run_plan"](write_changes(tmp_path))
    assert result.returncode == 1
    final = _final(result)
    assert f"session {other} of this login is applied and held on the router, not confirmed" in final
    assert f"{SCRIPT} confirm {ROUTER} {other}" in final
    assert f"{SCRIPT} abort {ROUTER} {other}" in final
    assert "rolls it back when its window ends" in final
    assert f"{SCRIPT} apply {ROUTER} {other}" not in final
    assert "45 minutes" not in final


def test_a_plan_refused_busy_with_this_logins_applied_session_says_it_rolls_back_at_window_end(
    protocol, tmp_path
):
    """An apply this host started is in its window: it is not applied again,
    and unless it is confirmed the router rolls it back when that window ends."""
    other = "f" * 32
    protocol["audit"].write_text(f"2026-11-19T10:00:00+00:00 {ROUTER} APPLYING session={other}\n")
    set_router_state(protocol, stage_fail={"rc": 3, "stderr": f"error busy root {other}\n"})
    result = protocol["run_plan"](write_changes(tmp_path))
    assert result.returncode == 1
    final = _final(result)
    assert f"session {other} of this login was applied and its window is still open" in final
    assert f"{SCRIPT} abort {ROUTER} {other}" in final
    assert "rolls it back when its window ends" in final
    assert f"{SCRIPT} apply {ROUTER} {other}" not in final
    assert "45 minutes" not in final


@pytest.mark.parametrize("shown", ["ffffffff", "f" * 32], ids=["short-id", "full-id-shown-to-root"])
def test_a_plan_refused_busy_with_another_logins_session_says_to_wait(protocol, tmp_path, shown):
    """The router shows root the full id of anyone's session: the owner, not
    the id's length, decides whether it is this login's session."""
    set_router_state(protocol, stage_fail={"rc": 3, "stderr": f"error busy alice {shown}\n"})
    result = protocol["run_plan"](write_changes(tmp_path))
    assert result.returncode == 1
    final = _final(result)
    assert final.startswith(f"ERROR: staging rejected: error busy alice {shown}; ")
    assert "another login (alice) has a change open on the router" in final
    assert "of this login" not in final


# --- the next line of a plan carries its timeout ---


def test_the_plans_next_line_carries_the_planned_timeout(protocol, tmp_path):
    result = protocol["run_plan"](write_changes(tmp_path), timeout=120)
    assert result.returncode == 0, result.stdout
    assert f"next: {SCRIPT} apply {ROUTER} {SID} 120" in result.stdout.splitlines()
    assert f"{SCRIPT} apply {ROUTER} {SID} 120 --hold" in result.stdout
    assert "[timeout]" not in result.stdout


def test_a_timeout_refusal_says_the_session_is_still_staged_and_to_use_the_planned_timeout(protocol):
    set_router_state(protocol, apply_rc=3, apply_stderr="error plan-changed t")
    result = protocol["run"]()
    assert result.returncode == 1
    final = _final(result)
    assert final.startswith("ERROR: apply refused, nothing applied: error plan-changed t; ")
    assert f"session {SID} is still staged" in final
    assert "the timeout it was planned with" in final
    assert "plan the change again" not in final


# --- the reads before an apply name the router's refusal ---


@pytest.mark.parametrize("knob,what", [("diff_fail", "cannot read staged diff"),
                                       ("named_fail", "cannot inspect the staged change for named nft objects")])
def test_a_pre_apply_read_refused_for_a_gone_session_says_plan_again(protocol, knob, what):
    set_router_state(protocol, **{knob: {"rc": 3, "stderr": "error no-such-txn"}})
    result = protocol["run"]()
    assert result.returncode == 1
    final = _final(result)
    assert final.startswith(f"ERROR: {what}: error no-such-txn; ")
    assert "plan the change again" in final
    assert "still staged" not in final
    assert not any(c.startswith(f"{PROG} apply ") for c in remote_calls(protocol))


def test_a_health_snapshot_refused_for_a_gone_session_says_plan_again(protocol):
    set_router_state(protocol, health_snapshot="error session-gone", health_snapshot_rc=3)
    result = protocol["run"]()
    assert result.returncode == 1
    final = _final(result)
    assert final.startswith("ERROR: cannot record service and firewall health before the apply: "
                            "error session-gone; ")
    assert "plan the change again" in final
    assert "still staged" not in final


def test_a_pre_apply_read_that_loses_the_connection_keeps_the_staged_text(protocol):
    set_router_state(protocol, diff_fail={"rc": 255, "stderr": SSH_DOWN})
    result = protocol["run"]()
    assert result.returncode == 1
    assert _final(result) == f"ERROR: cannot read staged diff; nothing applied, session {SID} is still staged"


# --- an ssh failure after the rollback is not a health verdict ---


def test_an_unreachable_router_after_the_rollback_is_not_called_a_health_difference(protocol):
    set_router_state(protocol, health_checks=["unreachable"])
    fail_verify_rounds(protocol)
    result = protocol["run"]()
    assert result.returncode == 1
    final = _final(result)
    assert "health differs" not in final
    assert ("the router was unreachable, so service or firewall health was not compared "
            "after the rollback: " + SSH_DOWN) in final


def test_an_unreachable_router_at_the_dns_check_is_not_called_a_dns_failure(protocol):
    set_router_state(protocol, logd=["1314", "2020"])
    fail_verify_rounds(protocol)
    (protocol["root"] / "dns-dhcp-unreachable").touch()
    result = protocol["run"]()
    assert result.returncode == 1
    final = _final(result)
    assert "DNS/DHCP check failed" not in final
    assert ("the router was unreachable, so DNS and DHCP were not checked after the dnsmasq "
            "restart: " + SSH_DOWN) in final


# --- backups ---


def test_a_truncated_backup_is_removed(protocol):
    data = (protocol["root"] / "backup.tar.gz").read_bytes()
    (protocol["root"] / "backup.tar.gz").write_bytes(data[: len(data) // 2])
    result = run_script(protocol, ["backup", ROUTER])
    assert result.returncode == 1
    assert "backup failed or corrupt" in result.stdout
    assert list((protocol["root"] / "backups").iterdir()) == []


def test_a_backup_never_overwrites_one_with_the_same_name(protocol):
    fakebin = protocol["root"] / "fakedate"
    fakebin.mkdir()
    date = fakebin / "date"
    date.write_text('#!/bin/sh\n[ "$1" = +%Y%m%d-%H%M%S ] && { echo 20261118-090000; exit 0; }\n'
                    'exec /bin/date "$@"\n')
    date.chmod(0o755)
    backups = protocol["root"] / "backups"
    backups.mkdir(mode=0o700)
    other = backups / "lab-r1-20261118-090000.tar.gz"
    other.write_bytes(b"the other router's backup")
    env = {"PATH": str(fakebin) + os.pathsep + protocol["env"]["PATH"]}
    result = run_script(protocol, ["backup", ROUTER], extra_env=env)
    assert result.returncode == 0, result.stdout
    assert other.read_bytes() == b"the other router's backup"
    made = sorted(p.name for p in backups.iterdir())
    assert len(made) == 2, made
    new = next(n for n in made if n != other.name)
    assert new.startswith("lab-r1-20261118-090000") and new.endswith(".tar.gz")
    assert f"BACKUP {backups / new} (1 config files)" in result.stdout


# --- an interrupt and a second apply ---


def test_an_interrupted_apply_says_it_rolls_back_by_itself(protocol):
    (protocol["root"] / "slow-apply").touch()
    record = plan_record(protocol, ".sha256")
    record.parent.mkdir(parents=True, exist_ok=True)
    import hashlib
    diff = json.loads(protocol["router"].read_text())["diff"]
    record.write_text(hashlib.sha256((diff.rstrip("\n") + "\n").encode()).hexdigest() + "\n")
    _prepare_state_dirs(protocol)
    proc = subprocess.Popen(
        _wrap_args_with_unshare([str(SCRIPT), "apply", ROUTER, SID, "60"], protocol),
        env=protocol["env"], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL)
    deadline = time.time() + 30
    while time.time() < deadline:
        if any(c.startswith(f"{PROG} apply ") for c in remote_calls(protocol)):
            break
        time.sleep(0.05)
    proc.send_signal(signal.SIGINT)
    out, _ = proc.communicate(timeout=60)
    assert proc.returncode == 130, out
    final = [l for l in out.splitlines() if l.strip()][-1]
    assert final.startswith(f"INTERRUPTED session={SID}: ")
    assert "rolls it back by itself when its window ends" in final
    assert f"run: {SCRIPT} status {ROUTER} {SID}" in final
    assert "CONFIRMED" not in out and "OUTCOME UNKNOWN" not in out
    assert f"INTERRUPTED session={SID}" in protocol["audit"].read_text()


def _interrupt_at_the_confirm(protocol, args):
    """Run the script, wait until it has sent the confirm, then send SIGINT."""
    (protocol["root"] / "slow-confirm").touch()
    proc = subprocess.Popen(
        _wrap_args_with_unshare([str(SCRIPT), *args], protocol),
        env=protocol["env"], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL)
    deadline = time.time() + 120
    while time.time() < deadline and proc.poll() is None:
        if f"{PROG} confirm {SID}" in remote_calls(protocol):
            break
        time.sleep(0.05)
    proc.send_signal(signal.SIGINT)
    out, _ = proc.communicate(timeout=60)
    assert proc.returncode == 130, out
    return [l for l in out.splitlines() if l.strip()][-1]


def _assert_confirm_sent_message(final):
    assert final.startswith(f"INTERRUPTED session={SID}: ")
    assert "the confirm was sent; whether it took is not known from here" in final
    assert "rolls it back" not in final and "confirmed nothing" not in final
    assert final.endswith(f"run: {SCRIPT} status {ROUTER} {SID}")


def test_an_interrupt_after_the_confirm_was_sent_does_not_promise_a_rollback(protocol):
    _plan_record_for_apply(protocol)
    _assert_confirm_sent_message(_interrupt_at_the_confirm(protocol, ["apply", ROUTER, SID, "60"]))
    assert f"INTERRUPTED session={SID}" in protocol["audit"].read_text()


def test_an_interrupt_after_a_held_confirm_was_sent_says_the_outcome_is_unknown(protocol):
    _plan_record_for_apply(protocol)
    held = run_script(protocol, ["apply", ROUTER, SID, "120", "--hold"])
    assert held.returncode == 0, held.stdout
    _assert_confirm_sent_message(_interrupt_at_the_confirm(protocol, ["confirm", ROUTER, SID]))


def _plan_record_for_apply(protocol):
    import hashlib
    record = plan_record(protocol, ".sha256")
    record.parent.mkdir(parents=True, exist_ok=True)
    diff = json.loads(protocol["router"].read_text())["diff"]
    record.write_text(hashlib.sha256((diff.rstrip("\n") + "\n").encode()).hexdigest() + "\n")
    _prepare_state_dirs(protocol)


def test_a_second_apply_of_an_applied_session_is_not_an_unknown_outcome(protocol):
    set_router_state(protocol, apply_rc=1, apply_stderr="error already-applied")
    result = protocol["run"]()
    assert result.returncode == 1
    final = _final(result)
    assert "OUTCOME UNKNOWN" not in result.stdout
    assert final.startswith("ERROR: apply refused: the router says session "
                            f"{SID} was already applied (by an earlier run); nothing applied by this run")
    assert f"run: {SCRIPT} status {ROUTER} {SID}" in final


# --- a second abort ---


def _audit(protocol, *lines):
    with protocol["audit"].open("a") as f:
        for line in lines:
            f.write(f"2026-11-18T09:00:00+00:00 {ROUTER} {line}\n")


def test_a_second_abort_of_a_session_aborted_here_says_nothing_to_do(protocol):
    _audit(protocol, f"ABORTED session={SID} (discarded)")
    set_router_state(protocol, abort_how="gone", status=f"gone sid={SID} guard=idle rpcd=- config=other boot=-")
    result = run_script(protocol, ["abort", ROUTER, SID])
    assert result.returncode == 0, result.stdout
    assert _final(result) == f"session {SID} was already aborted on this host; nothing to do"
    assert "may still be live" not in result.stdout
    assert protocol["audit"].read_text().count("ABORTED") == 1


def test_an_abort_after_a_gone_abort_line_is_not_taken_as_aborted(protocol):
    """The failure branch logs `ABORTED session=<sid> (gone)` when the router no
    longer had the session: that rolled nothing back."""
    _audit(protocol, f"ABORTED session={SID} (gone)")
    set_router_state(protocol, abort_how="gone", status=f"gone sid={SID} guard=idle rpcd=- config=other boot=-")
    result = run_script(protocol, ["abort", ROUTER, SID])
    assert result.returncode == 1
    assert "already aborted" not in result.stdout
    assert "may still be live" in _final(result)


# --- a changes file with CR line endings ---


def test_a_changes_file_with_crlf_is_refused_before_any_ssh_call(protocol, tmp_path):
    changes = tmp_path / "change.uci"
    changes.write_bytes(b"set system.@system[0].description='lab'\r\n")
    _prepare_state_dirs(protocol)
    result = protocol["run_plan"](changes)
    assert result.returncode == 1
    assert f"changes file contains CR (convert CRLF line endings to LF): {changes}" in result.stdout
    assert remote_calls(protocol) == []


# --- a confirm the router has but this host never logged ---


@pytest.mark.parametrize("record", ["sha256", "held"])
def test_status_records_a_confirm_the_router_reports_for_an_apply_of_this_host(protocol, record):
    _plan_record(protocol)
    if record == "held":
        plan_record(protocol, ".held").write_text(f"0 0 {int(time.time()) + 300}\n")
        plan_record(protocol, ".sha256").unlink()
    _audit(protocol, f"CONFIRM DID NOT REPORT SUCCESS session={SID} — OUTCOME UNKNOWN; run: x")
    set_router_state(protocol, status=CONFIRMED_STATUS)
    result = run_script(protocol, ["status", ROUTER, SID])
    assert result.returncode == 0, result.stdout
    lines = result.stdout.splitlines()
    rec = [l for l in lines if l.startswith(RECONCILED)]
    assert rec == [f"{RECONCILED}the router's status says confirmed)"], result.stdout
    hashes = [l for l in lines if l.startswith("CONFIGHASH ")]
    assert len(hashes) == 3 and lines.index(hashes[-1]) < lines.index(rec[0])
    assert rec[0] in protocol["audit"].read_text()
    assert not plan_record(protocol, ".sha256").exists()
    assert not plan_record(protocol, ".held").exists()


def test_status_records_nothing_for_a_session_this_host_already_confirmed(protocol):
    _plan_record(protocol)
    _audit(protocol, f"CONFIRMED session={SID} (3 consecutive passes)")
    set_router_state(protocol, status=CONFIRMED_STATUS)
    result = run_script(protocol, ["status", ROUTER, SID])
    assert RECONCILED not in result.stdout
    assert protocol["audit"].read_text().count("CONFIRMED session=") == 1


def test_status_records_nothing_without_an_apply_of_this_host(protocol):
    _prepare_state_dirs(protocol)
    set_router_state(protocol, status=CONFIRMED_STATUS)
    result = run_script(protocol, ["status", ROUTER, SID])
    assert result.returncode == 0, result.stdout
    assert RECONCILED not in result.stdout


def test_status_records_nothing_when_the_router_does_not_say_confirmed(protocol):
    _plan_record(protocol)
    set_router_state(protocol, status=f"applied-pending-confirm sid={SID} guard=armed rpcd=- config=other boot=same")
    result = run_script(protocol, ["status", ROUTER, SID])
    assert RECONCILED not in result.stdout
    assert plan_record(protocol, ".sha256").exists()


def test_an_abort_the_router_refuses_as_confirmed_records_the_confirm(protocol):
    _plan_record(protocol)
    set_router_state(protocol, abort_confirmed=True)
    result = run_script(protocol, ["abort", ROUTER, SID])
    assert result.returncode == 1
    assert f"{RECONCILED}the router refused the abort: it says confirmed)" in result.stdout.splitlines()
    assert _final(result) == (f"ERROR: abort refused: session {SID} was already confirmed; the change "
                              "stays live. To undo it, plan the reverse change (newton_plan_undo)")
    assert not plan_record(protocol, ".sha256").exists()


def test_an_abort_answered_gone_with_a_confirmed_status_records_the_confirm(protocol):
    _plan_record(protocol)
    _audit(protocol, f"STAGED session={SID}")
    set_router_state(protocol, abort_how="gone", status=CONFIRMED_STATUS)
    result = run_script(protocol, ["abort", ROUTER, SID])
    assert result.returncode == 1
    assert f"{RECONCILED}the router's status says confirmed)" in result.stdout.splitlines()
    assert "abort refused" in _final(result)


def test_an_abort_refused_as_confirmed_without_an_apply_here_records_nothing(protocol):
    _prepare_state_dirs(protocol)
    set_router_state(protocol, abort_confirmed=True)
    result = run_script(protocol, ["abort", ROUTER, SID])
    assert result.returncode == 1
    assert RECONCILED not in result.stdout


# --- a second confirm after the first reached the router ---


def _held(protocol):
    _plan_record(protocol)
    plan_record(protocol, ".held").write_text(f"0 0 {int(time.time()) + 300}\n")
    _audit(protocol, f"CONFIRM DID NOT REPORT SUCCESS session={SID} — OUTCOME UNKNOWN; run: x")


@pytest.mark.parametrize("failing", ["verify", "local-check", "logd"])
def test_a_confirm_whose_check_fails_on_a_confirmed_session_says_it_is_confirmed(protocol, failing):
    _held(protocol)
    set_router_state(protocol, status=CONFIRMED_STATUS)
    env = None
    if failing == "verify":
        set_router_state(protocol, status=CONFIRMED_STATUS)
        (protocol["root"] / "fail-ping").touch()
    elif failing == "local-check":
        env = {"OWRT_LOCAL_CHECK": "false"}
    else:
        set_router_state(protocol, logd=[])
    result = run_script(protocol, ["confirm", ROUTER, SID], extra_env=env)
    assert result.returncode == 1
    final = _final(result)
    assert final.startswith(f"ERROR: session {SID} is already confirmed on the router; "
                            "nothing confirmed by this run; ")
    assert "the router rolls the change back" not in final
    assert f"{PROG} confirm {SID}" not in remote_calls(protocol)
    assert not plan_record(protocol, ".held").exists()
    assert f"{RECONCILED}the router's status says confirmed)" in result.stdout.splitlines()
    assert _server()._host_confirm_refusal_re(SID).match(final), final


def test_a_confirm_whose_verify_fails_on_an_armed_session_still_says_it_rolls_back(protocol):
    _held(protocol)
    set_router_state(protocol, status=f"applied-pending-confirm sid={SID} guard=armed rpcd=- config=other boot=same")
    (protocol["root"] / "fail-ping").touch()
    result = run_script(protocol, ["confirm", ROUTER, SID])
    assert result.returncode == 1
    final = _final(result)
    assert final.startswith("ERROR: verify failed before the confirm: ")
    assert "the router rolls the change back when its window ends" in final
    assert plan_record(protocol, ".held").exists()
    assert RECONCILED not in result.stdout
