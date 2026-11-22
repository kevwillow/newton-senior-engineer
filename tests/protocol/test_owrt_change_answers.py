"""What scripts/owrt-change.sh answers in the cases its first answer was wrong.

Each test pins one answer the owner (or the server) acts on:

* a change to named nft objects whose rollback this run could not follow
  (link lost, run interrupted) leaves a firewall restart owed, and the
  messages and the next abort say so and make it;
* a confirm the router refuses because an earlier confirm already took is
  reported as confirmed, never as rolling back;
* a plan whose staged-diff read fails discards the session it staged;
* an abort of a session id this host never planned is not a clean abort;
* status of a session confirmed here that the router has forgotten says
  the change stays live;
* the setup hints of an installed Newton name the installed launcher.
"""

import json
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
NAMED = "firewall.blocklist (ipset blocklist: set blocklist)"
CONFIRMED_STATUS = f"confirmed sid={SID} guard=idle rpcd=- config=other boot=-"
GONE_STATUS = f"gone sid={SID} guard=idle rpcd=- config=- boot=-"
OWED = "the firewall must be restarted after the rollback"


def _final(result):
    return [l for l in result.stdout.splitlines() if l.strip()][-1]


def _audit(protocol, *lines):
    with protocol["audit"].open("a") as f:
        for line in lines:
            f.write(f"2026-11-18T09:00:00+00:00 {ROUTER} {line}\n")


def _fwrestarts(protocol):
    return [c for c in remote_calls(protocol) if c.startswith(f"{PROG} fwrestart ")]


def _plan_record(protocol):
    record = plan_record(protocol, ".sha256")
    record.parent.mkdir(parents=True, exist_ok=True)
    record.write_text("0" * 64 + "\n")
    _prepare_state_dirs(protocol)
    return record


# --- a firewall restart owed after a rollback this run did not follow ---


def _apply_link_lost(protocol):
    """A change to named nft objects: the firewall restart after the apply
    works, then the link is lost for the verify rounds and the whole status
    wait, so the run ends with the unreachable ALERT."""
    set_router_state(protocol, named=NAMED, status_ssh=["fail"] * 40)
    fail_verify_rounds(protocol)
    result = protocol["run"]()
    # the link is back for the next command
    set_router_state(protocol, status_ssh=[])
    return result


def test_a_lost_link_after_a_named_change_says_a_firewall_restart_is_owed(protocol):
    result = _apply_link_lost(protocol)
    assert result.returncode == 1, result.stdout
    assert f"FIREWALL RESTARTED session={SID} (after apply)" in result.stdout
    final = _final(result)
    assert final.startswith(f"ALERT session={SID} status=unreachable after rollback window"), final
    assert OWED in final, final
    assert f"run: {SCRIPT} abort {ROUTER} {SID}" in final, final
    assert len(_fwrestarts(protocol)) == 1
    assert plan_record(protocol, ".named").read_text() == "1\n"


@pytest.mark.parametrize("how", ["rolled-back", "already-rolled-back", "rolled-back-by-guard"])
def test_the_abort_after_a_lost_link_restarts_the_firewall(protocol, how):
    _apply_link_lost(protocol)
    set_router_state(protocol, abort_how=how)
    result = run_script(protocol, ["abort", ROUTER, SID])
    assert result.returncode == 0, result.stdout
    assert f"ABORTED session={SID} ({how})" in result.stdout
    assert f"FIREWALL RESTARTED session={SID} (after abort)" in result.stdout
    assert _fwrestarts(protocol) == [f"{PROG} fwrestart 1", f"{PROG} fwrestart 1"]
    assert not plan_record(protocol, ".named").exists()
    again = run_script(protocol, ["abort", ROUTER, SID])
    assert len(_fwrestarts(protocol)) == 2, again.stdout


def test_an_abort_whose_firewall_restart_fails_says_so_and_keeps_it_owed(protocol):
    _apply_link_lost(protocol)
    set_router_state(protocol, abort_how="rolled-back", fw_restart=["refuse"])
    result = run_script(protocol, ["abort", ROUTER, SID])
    assert result.returncode == 1, result.stdout
    final = _final(result)
    assert final.startswith(f"ERROR: session {SID} was rolled back, but the firewall restart after it failed"), final
    assert f"run: {SCRIPT} abort {ROUTER} {SID}" in final
    assert plan_record(protocol, ".named").exists()


def test_an_abort_answered_gone_and_rolled_back_restarts_an_owed_firewall(protocol):
    _apply_link_lost(protocol)
    set_router_state(protocol, abort_how="gone",
                     status=f"rolled-back sid={SID} guard=idle rpcd=rolled-back config=same boot=-")
    result = run_script(protocol, ["abort", ROUTER, SID])
    assert result.returncode == 0, result.stdout
    assert f"FIREWALL RESTARTED session={SID} (after abort)" in result.stdout
    assert len(_fwrestarts(protocol)) == 2
    assert not plan_record(protocol, ".named").exists()


def test_a_second_abort_of_an_aborted_session_restarts_an_owed_firewall(protocol):
    _apply_link_lost(protocol)
    _audit(protocol, f"ABORTED session={SID} (rolled-back)")
    set_router_state(protocol, abort_how="gone", status=GONE_STATUS)
    result = run_script(protocol, ["abort", ROUTER, SID])
    assert result.returncode == 0, result.stdout
    assert f"FIREWALL RESTARTED session={SID} (after abort)" in result.stdout
    assert not plan_record(protocol, ".named").exists()


def test_status_names_an_owed_firewall_restart(protocol):
    _apply_link_lost(protocol)
    set_router_state(protocol, status=f"rolled-back sid={SID} guard=idle rpcd=rolled-back config=same boot=-")
    before = len(_fwrestarts(protocol))
    result = run_script(protocol, ["status", ROUTER, SID])
    assert result.returncode == 0, result.stdout
    note = [l for l in result.stdout.splitlines() if l.startswith(f"NOTE session={SID}: ")]
    assert len(note) == 1, result.stdout
    assert OWED in note[0] and f"run: {SCRIPT} abort {ROUTER} {SID}" in note[0]
    # status only reads: the restart needs the change role
    assert len(_fwrestarts(protocol)) == before


def test_a_rollback_this_run_followed_owes_no_firewall_restart(protocol):
    set_router_state(protocol, named=NAMED,
                     status=f"rolled-back sid={SID} guard=idle rpcd=rolled-back config=same boot=-")
    fail_verify_rounds(protocol)
    result = protocol["run"]()
    assert f"FIREWALL RESTARTED session={SID} (after rollback)" in result.stdout
    assert OWED not in result.stdout
    assert not plan_record(protocol, ".named").exists()


def test_a_confirmed_named_change_owes_no_firewall_restart(protocol):
    set_router_state(protocol, named=NAMED)
    result = protocol["run"]()
    assert result.returncode == 0, result.stdout
    assert not plan_record(protocol, ".named").exists()


def test_a_refused_apply_owes_no_firewall_restart(protocol):
    set_router_state(protocol, named=NAMED, apply_rc=3, apply_stderr="error needs-approval")
    result = protocol["run"]()
    assert result.returncode == 1
    assert not plan_record(protocol, ".named").exists()


def test_an_interrupted_named_apply_says_a_firewall_restart_is_owed(protocol):
    set_router_state(protocol, named=NAMED)
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
    proc.send_signal(signal.SIGTERM)
    out, _ = proc.communicate(timeout=60)
    assert proc.returncode == 130, out
    final = [l for l in out.splitlines() if l.strip()][-1]
    assert final.startswith(f"INTERRUPTED session={SID}: "), final
    assert OWED in final, final
    assert f"run: {SCRIPT} abort {ROUTER} {SID}" in final, final


# --- a confirm refused because an earlier confirm already took ---


def _held(protocol):
    _plan_record(protocol)
    plan_record(protocol, ".held").write_text(f"0 0 {int(time.time()) + 300}\n")


def test_a_confirm_refused_no_such_txn_on_a_confirmed_session_says_it_is_confirmed(protocol):
    _held(protocol)
    set_router_state(protocol, confirm_rc=3, confirm_stderr="error no-such-txn", status=CONFIRMED_STATUS)
    result = run_script(protocol, ["confirm", ROUTER, SID])
    assert result.returncode == 1
    final = _final(result)
    assert final.startswith(f"ERROR: session {SID} is already confirmed on the router; "
                            "nothing confirmed by this run; "), final
    assert "rolls the change back" not in final
    assert not plan_record(protocol, ".held").exists()


def test_a_confirm_refused_on_an_armed_session_still_says_it_rolls_back(protocol):
    _held(protocol)
    set_router_state(protocol, confirm_rc=3, confirm_stderr="error too-late",
                     status=f"applied-pending-confirm sid={SID} guard=armed rpcd=- config=other boot=same")
    result = run_script(protocol, ["confirm", ROUTER, SID])
    assert result.returncode == 1
    assert _final(result).startswith("ERROR: confirm refused: error too-late; not confirmed: "
                                     "the router rolls the change back on its own")


# --- a plan whose staged-diff read fails ---


@pytest.mark.parametrize("rc", [1, 255])
def test_a_plan_whose_diff_read_fails_discards_the_staged_session(protocol, tmp_path, rc):
    set_router_state(protocol, diff_fail={"rc": rc, "stderr": "client_loop: send disconnect: Broken pipe"})
    result = protocol["run_plan"](write_changes(tmp_path))
    assert result.returncode == 1
    assert f"{PROG} abort {SID}" in remote_calls(protocol)
    final = _final(result)
    assert final.startswith(f"ERROR: cannot read the staged diff of session {SID}"), final
    assert final.endswith("; the staged change was discarded"), final
    plans = plan_record(protocol, ".sha256").parent
    assert not list(plans.glob(f"{SID}.*")), sorted(p.name for p in plans.iterdir())
    assert "next: " not in result.stdout


def test_a_plan_whose_diff_read_fails_and_whose_abort_fails_names_the_abort(protocol, tmp_path):
    set_router_state(protocol, diff_fail={"rc": 255, "stderr": "Broken pipe"},
                     abort_fail="ssh: connect to host 192.0.2.1 port 22: Connection timed out\n")
    result = protocol["run_plan"](write_changes(tmp_path))
    assert result.returncode == 1
    final = _final(result)
    assert final.endswith(f"session {SID} is still staged on the router); run: {SCRIPT} abort {ROUTER} {SID}"), final


# --- an abort of a session id this host never planned ---


def test_an_abort_of_a_session_never_planned_here_is_not_a_clean_abort(protocol):
    _prepare_state_dirs(protocol)
    _audit(protocol, f"STAGED session={'f' * 32} from x")
    set_router_state(protocol, abort_how="gone", status=GONE_STATUS)
    result = run_script(protocol, ["abort", ROUTER, SID])
    assert result.returncode == 1, result.stdout
    final = _final(result)
    assert "only staged" not in result.stdout
    assert final.startswith(f"ERROR: the router has no session {SID}, and this host has no plan of it"), final
    again = run_script(protocol, ["abort", ROUTER, SID])
    assert again.returncode == 1, again.stdout


def test_an_abort_of_a_staged_session_whose_plan_record_is_gone_is_still_only_staged(protocol):
    _prepare_state_dirs(protocol)
    _audit(protocol, f"STAGED session={SID} from x")
    set_router_state(protocol, abort_how="gone", status=GONE_STATUS)
    result = run_script(protocol, ["abort", ROUTER, SID])
    assert result.returncode == 0, result.stdout
    assert "it was only staged" in _final(result)


# --- status of a confirmed session the router no longer remembers ---


def test_status_of_a_session_confirmed_here_that_the_router_forgot_says_it_stays_live(protocol):
    _prepare_state_dirs(protocol)
    _audit(protocol, f"CONFIRMED session={SID} (3 consecutive passes)")
    set_router_state(protocol, status=GONE_STATUS)
    result = run_script(protocol, ["status", ROUTER, SID])
    assert result.returncode == 0, result.stdout
    final = _final(result)
    assert final.startswith(f"NOTE session={SID}: this host's audit log records it confirmed"), final
    assert "the change stays live" in final and "newton_plan_undo" in final


def test_status_of_a_gone_session_not_confirmed_here_adds_no_confirmed_note(protocol):
    _prepare_state_dirs(protocol)
    set_router_state(protocol, status=GONE_STATUS)
    result = run_script(protocol, ["status", ROUTER, SID])
    assert result.returncode == 0, result.stdout
    assert "records it confirmed" not in result.stdout


# --- the setup hints of an installed Newton ---

INSTALLED = "sudo -u newton /usr/local/bin/newton-router-setup"


def test_an_installed_newton_hints_the_installed_launcher_for_a_profile_mismatch(protocol, tmp_path):
    _prepare_state_dirs(protocol)
    set_router_state(protocol, hello_overrides={"profile": "lab"})
    result = run_script(protocol, ["status", ROUTER, SID], extra_env={
        "OWRT_EXPECT_PROFILE": "prod", "OWRT_EXPECT_DEVICE": "lab-r1", "NEWTON_HOME": str(tmp_path)})
    assert result.returncode == 1
    assert _final(result).endswith(f"or run: {INSTALLED} lab-r1 profile prod"), _final(result)


def test_an_installed_newton_hints_the_installed_launcher_for_an_upgrade(protocol, tmp_path):
    _prepare_state_dirs(protocol)
    set_router_state(protocol, hello_overrides={"prog": "0" * 64})
    result = run_script(protocol, ["status", ROUTER, SID], extra_env={
        "OWRT_EXPECT_DEVICE": "lab-r1", "NEWTON_HOME": str(tmp_path)})
    assert result.returncode == 1
    assert _final(result).endswith(f"run: {INSTALLED} lab-r1 upgrade"), _final(result)


def test_an_installed_newton_hints_the_installed_launcher_for_a_missing_approval_key(protocol, tmp_path):
    set_router_state(protocol, apply_rc=3, apply_stderr="error approval-key-missing")
    result = protocol["run"](extra_env={"OWRT_EXPECT_DEVICE": "lab-r1", "NEWTON_HOME": str(tmp_path)})
    assert result.returncode == 1
    assert f"(run: {INSTALLED} lab-r1 approval-key)" in _final(result), _final(result)
