"""apply --hold and the confirm subcommand of scripts/owrt-change.sh.

The installed-mode apply confirms on its own after three passing rounds.
README and SKILL.md told the owner to test from a client and abort before the
window closes, which that flow does not allow.  `apply ... --hold` runs the
same rounds but does not confirm: the router's rollback timer stays armed,
the run prints how to confirm or abort, and `confirm <router> <SID>` confirms
the held change after one more verify round over a new connection, only
inside the window.  Without --hold nothing changes.
"""

import hashlib
import json
import sys
import time
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_owrt_change import (  # noqa: E402,F401
    PROG, SCRIPT, SID, plan_record, protocol, remote_calls, run_script,
    set_router_state, fail_verify_rounds)

ROUTER = "root@192.0.2.1"


def _plan(protocol):
    record = plan_record(protocol, ".sha256")
    record.parent.mkdir(parents=True, exist_ok=True)
    diff = json.loads(protocol["router"].read_text())["diff"]
    record.write_text(
        hashlib.sha256((diff.rstrip("\n") + "\n").encode()).hexdigest() + "\n")
    return record


def _apply_hold(protocol, *args):
    _plan(protocol)
    return run_script(protocol, ["apply", ROUTER, SID, *args])


def _confirm(protocol):
    return run_script(protocol, ["confirm", ROUTER, SID])


def _final(result):
    return [l for l in result.stdout.splitlines() if l.strip()][-1]


def test_hold_runs_the_rounds_and_does_not_confirm(protocol):
    result = _apply_hold(protocol, "60", "--hold")
    assert result.returncode == 0, result.stdout
    calls = remote_calls(protocol)
    assert f"{PROG} confirm {SID}" not in calls
    assert len([c for c in calls if c.startswith(f"{PROG} verify ")]) == 3
    final = _final(result)
    assert final.startswith(f"HELD session={SID} until=")
    assert f"confirm: {SCRIPT} confirm {ROUTER} {SID}" in final
    assert f"abort: {SCRIPT} abort {ROUTER} {SID}" in final
    assert "CONFIRMED" not in protocol["audit"].read_text()
    assert plan_record(protocol, ".held").exists()
    assert plan_record(protocol, ".sha256").exists()


def test_hold_without_a_timeout_takes_the_default(protocol):
    result = _apply_hold(protocol, "--hold")
    assert result.returncode == 0, result.stdout
    assert any(c.startswith(f"{PROG} apply {SID} 90 ") for c in remote_calls(protocol))
    assert _final(result).startswith(f"HELD session={SID} until=")


def test_an_unknown_extra_argument_is_refused_before_any_ssh_call(protocol):
    result = _apply_hold(protocol, "60", "--hld")
    assert result.returncode == 1
    assert "usage: " in result.stdout and "[--hold]" in result.stdout
    assert "nothing applied" in result.stdout
    assert remote_calls(protocol) == []


def test_hold_is_refused_for_a_change_to_named_nft_objects(protocol):
    set_router_state(protocol, named="ipset wan_block")
    result = _apply_hold(protocol, "60", "--hold")
    assert result.returncode == 1
    assert "--hold cannot be used" in result.stdout
    assert "nothing applied" in result.stdout
    assert not any(c.startswith(f"{PROG} apply ") for c in remote_calls(protocol))


def test_a_failed_held_apply_rolls_back_as_before(protocol):
    fail_verify_rounds(protocol)
    result = _apply_hold(protocol, "60", "--hold")
    assert result.returncode == 1
    assert "HELD" not in result.stdout
    assert not plan_record(protocol, ".held").exists()
    assert f"{PROG} confirm {SID}" not in remote_calls(protocol)


def test_confirm_without_a_held_apply_is_refused_before_any_ssh_call(protocol):
    result = _confirm(protocol)
    assert result.returncode == 1
    assert f"no held apply of session {SID} on this host; nothing confirmed" in result.stdout
    assert remote_calls(protocol) == []


@pytest.mark.parametrize("record", [None, "garbage\n"], ids=["missing", "malformed"])
def test_confirm_refusal_of_a_missing_or_malformed_hold_record_names_the_next_step(protocol, record):
    """The refusal says what to do next: read the session's status, or
    abort it now; the server's refusal shape still matches."""
    if record is not None:
        _plan(protocol)
        plan_record(protocol, ".held").write_text(record)
    result = _confirm(protocol)
    assert result.returncode == 1
    final = _final(result)
    assert "; nothing confirmed" in final
    assert f"status {ROUTER} {SID}" in final
    assert f"abort {ROUTER} {SID}" in final
    assert remote_calls(protocol) == []
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "mcp"))
    from newton_mcp import server
    assert server._host_confirm_refusal_re(SID).match(final), final


def test_confirm_of_a_held_apply_verifies_again_then_confirms(protocol):
    assert _apply_hold(protocol, "120", "--hold").returncode == 0
    before = len(remote_calls(protocol))
    result = _confirm(protocol)
    assert result.returncode == 0, result.stdout
    calls = remote_calls(protocol)[before:]
    assert calls[0].startswith(f"{PROG} hello ")
    verify_at = next(i for i, c in enumerate(calls) if c.startswith(f"{PROG} verify {SID} "))
    confirm_at = calls.index(f"{PROG} confirm {SID}")
    assert verify_at < confirm_at
    assert _final(result).startswith(f"CONFIRMED session={SID} ")
    assert not plan_record(protocol, ".held").exists()
    assert not plan_record(protocol, ".sha256").exists()


def test_confirm_does_not_confirm_when_the_verify_round_fails(protocol):
    assert _apply_hold(protocol, "120", "--hold").returncode == 0
    fail_verify_rounds(protocol)
    before = len(remote_calls(protocol))
    result = _confirm(protocol)
    assert result.returncode == 1
    assert f"{PROG} confirm {SID}" not in remote_calls(protocol)[before:]
    assert "not confirmed" in result.stdout
    assert plan_record(protocol, ".held").exists()


def test_confirm_refused_by_the_router_says_it_rolls_back(protocol):
    assert _apply_hold(protocol, "120", "--hold").returncode == 0
    set_router_state(protocol, confirm_rc=3, confirm_stderr="error too-late")
    result = _confirm(protocol)
    assert result.returncode == 1
    assert "confirm refused: error too-late" in result.stdout
    assert "CONFIRMED" not in _final(result)


def test_confirm_after_the_window_is_refused_and_only_reads_the_router(protocol):
    """After the window the confirm never verifies or confirms: it only
    reads the router's status (hello, then status) to learn what happened."""
    _plan(protocol)
    plan_record(protocol, ".held").write_text(f"0 0 {int(time.time()) - 1}\n")
    result = _confirm(protocol)
    assert result.returncode == 1
    assert "has closed" in result.stdout
    calls = remote_calls(protocol)
    assert [c.split(" ")[1] for c in calls] == ["hello", "status"], calls


def test_abort_of_a_held_apply_removes_the_hold(protocol):
    assert _apply_hold(protocol, "120", "--hold").returncode == 0
    result = run_script(protocol, ["abort", ROUTER, SID])
    assert result.returncode == 0, result.stdout
    assert not plan_record(protocol, ".held").exists()


def _audit_confirmed(protocol):
    with protocol["audit"].open("a") as f:
        f.write(f"2026-11-18T09:00:00+00:00 {ROUTER} CONFIRMED session={SID} "
                "(3 consecutive passes: fresh ssh + router-side ping)\n")


def test_abort_gone_of_a_session_this_host_confirmed_is_refused(protocol):
    """The router refuses only while its last line names the session; once a
    later session replaced it the router answers `aborted <sid> gone`.
    This host's audit log still says CONFIRMED, so that answer is refused."""
    _audit_confirmed(protocol)
    set_router_state(protocol, abort_how="gone")
    result = run_script(protocol, ["abort", ROUTER, SID])
    assert result.returncode == 1
    assert (f"ERROR: abort refused: session {SID} was already confirmed; the change stays "
            "live. To undo it, plan the reverse change (newton_plan_undo)") in result.stdout.splitlines()
    assert "ABORTED" not in result.stdout


def test_a_live_session_is_aborted_even_if_its_id_was_confirmed_here(protocol):
    """The host check never blocks an abort the router carries out."""
    _audit_confirmed(protocol)
    set_router_state(protocol, abort_how="rolled-back")
    result = run_script(protocol, ["abort", ROUTER, SID])
    assert result.returncode == 0, result.stdout
    assert f"ABORTED session={SID} (rolled-back)" in result.stdout


def _gone_not_confirmed_here(protocol, status, held):
    # this host's audit log is there and readable, and holds no CONFIRMED
    # line; the apply was sent from here (a session only staged here is
    # another case: it cannot be live)
    protocol["audit"].write_text(f"2026-11-18T09:00:00+00:00 {ROUTER} STAGED session={SID}\n"
                                 f"2026-11-18T09:00:01+00:00 {ROUTER} APPLYING session={SID}\n")
    if held:
        _plan(protocol)
        plan_record(protocol, ".held").write_text(f"0 0 {int(time.time()) + 300}\n")
    set_router_state(protocol, abort_how="gone", status=status)
    return run_script(protocol, ["abort", ROUTER, SID])


@pytest.mark.parametrize("held", [False, True], ids=["plain", "held"])
@pytest.mark.parametrize("status", ["gone", "bare-rolled-back-word", "bare-confirmed-word", "inconsistent",
                                    "rolled-back-other-sid", "confirmed-other-sid"])
def test_abort_gone_of_a_session_not_confirmed_here_never_says_aborted(protocol, held, status):
    """A "gone" answer rolled nothing back: the router no longer had the
    session, and a confirm killed before this host logged CONFIRMED leaves
    it live. Unless the router's status line says rolled-back for this
    session, the outcome is not known: no ABORTED line, no held-abort line
    (the server writes no rolled-back receipt), and a non-zero exit."""
    line = {
        "gone": GONE_STATUS,
        "bare-rolled-back-word": "rolled-back",
        "bare-confirmed-word": "confirmed",
        "inconsistent": f"inconsistent sid={SID} guard=failed:x rpcd=- config=other boot=same",
        "rolled-back-other-sid": ROLLED_BACK_STATUS.replace(SID, "f" * 32),
        "confirmed-other-sid": CONFIRMED_STATUS.replace(SID, "f" * 32),
    }[status]
    result = _gone_not_confirmed_here(protocol, line, held)
    assert result.returncode != 0, result.stdout
    assert "ABORTED" not in result.stdout
    assert "HELD APPLY" not in result.stdout
    assert "ABORTED" not in protocol["audit"].read_text()
    assert "this abort rolled nothing back" in _final(result)
    assert "not known from here" in _final(result)
    assert f"status {ROUTER} {SID}" in _final(result)
    assert plan_record(protocol, ".held").exists() is held


@pytest.mark.parametrize("held", [False, True], ids=["plain", "held"])
def test_abort_gone_when_the_router_says_rolled_back_records_only_that(protocol, held):
    """The router's status says rolled-back for this session: the change is
    rolled back, but not by this abort. No ABORTED line; a held apply gets
    the HELD APPLY ROLLED BACK line the server writes its receipt from."""
    result = _gone_not_confirmed_here(protocol, ROLLED_BACK_STATUS, held)
    assert result.returncode == 0, result.stdout
    assert "ABORTED" not in result.stdout
    assert "ABORTED" not in protocol["audit"].read_text()
    rolled = [l for l in result.stdout.splitlines()
              if l.startswith(f"HELD APPLY ROLLED BACK session={SID} ")]
    assert len(rolled) == (1 if held else 0), result.stdout
    assert "this abort rolled nothing back" in _final(result)
    assert "status says rolled-back" in _final(result)
    assert not plan_record(protocol, ".held").exists()


def test_abort_gone_when_the_router_says_confirmed_is_refused(protocol):
    """The router's status line says confirmed for this session: the change
    stays live, so the answer is the confirmed refusal the server maps."""
    result = _gone_not_confirmed_here(protocol, CONFIRMED_STATUS, True)
    assert result.returncode == 1
    assert (f"ERROR: abort refused: session {SID} was already confirmed; the change stays "
            "live. To undo it, plan the reverse change (newton_plan_undo)") in result.stdout.splitlines()
    assert "ABORTED" not in result.stdout


@pytest.mark.parametrize("audit_state", ["missing", "unreadable"])
def test_abort_gone_with_no_readable_audit_log_says_the_outcome_is_not_known(protocol, audit_state):
    """The router answers gone and this host cannot read its own audit log:
    whether the session was confirmed here is not known, so the abort never
    says ABORTED as if it rolled back, names what is not known, and exits
    non-zero."""
    if audit_state == "unreadable":
        # the script runs as root in a user namespace, so a mode cannot
        # hide the file; a directory in its place cannot be read as a log
        protocol["audit"].mkdir()
    set_router_state(protocol, abort_how="gone")
    result = run_script(protocol, ["abort", ROUTER, SID])
    assert result.returncode != 0, result.stdout
    assert "ABORTED" not in result.stdout
    assert f"the router no longer has session {SID}" in result.stdout
    assert "not known from this host" in result.stdout
    assert f"status {ROUTER} {SID}" in result.stdout


def test_confirm_of_a_session_this_host_already_confirmed_says_so(protocol):
    _audit_confirmed(protocol)
    result = _confirm(protocol)
    assert result.returncode == 1
    assert f"session {SID} was already confirmed; nothing confirmed" in result.stdout
    assert remote_calls(protocol) == []


ROLLED_BACK_STATUS = f"rolled-back sid={SID} guard=restored:deadline rpcd=rolled-back config=base boot=same"
GONE_STATUS = f"gone sid={SID} guard=idle rpcd=- config=other boot=-"
CONFIRMED_STATUS = f"confirmed sid={SID} guard=idle rpcd=- config=other boot=-"


def _closed_window(protocol, status):
    _plan(protocol)
    plan_record(protocol, ".held").write_text(f"0 0 {int(time.time()) - 1}\n")
    set_router_state(protocol, status=status)


def test_confirm_after_the_window_records_the_rollback_the_router_reports(protocol):
    """The window ended unconfirmed and the router's status says it rolled
    the change back: the host records it (a HELD APPLY ROLLED BACK line the
    server writes the rolled-back receipt from) and drops the hold record."""
    _closed_window(protocol, ROLLED_BACK_STATUS)
    result = _confirm(protocol)
    assert result.returncode == 1
    assert f"HELD APPLY ROLLED BACK session={SID}" in [
        l.split(" (", 1)[0] for l in result.stdout.splitlines()]
    assert "the router rolled the change back" in _final(result)
    assert "HELD APPLY ROLLED BACK session=" + SID in protocol["audit"].read_text()
    assert not plan_record(protocol, ".held").exists()
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "mcp"))
    from newton_mcp import server
    assert server._host_confirm_refusal_re(SID).match(_final(result)), _final(result)


@pytest.mark.parametrize("status", [GONE_STATUS, "rolled-back", f"inconsistent sid={SID} guard=failed:x rpcd=- config=other boot=same"])
def test_confirm_after_the_window_leaves_the_outcome_unknown_unless_the_router_says_rolled_back(protocol, status):
    _closed_window(protocol, status)
    result = _confirm(protocol)
    assert result.returncode == 1
    assert "HELD APPLY ROLLED BACK" not in result.stdout
    assert "not known from here" in _final(result)
    assert f"status {ROUTER} {SID}" in _final(result)
    assert plan_record(protocol, ".held").exists()


def test_status_after_the_window_records_the_rollback_the_router_reports(protocol):
    _closed_window(protocol, ROLLED_BACK_STATUS)
    result = run_script(protocol, ["status", ROUTER, SID])
    assert result.returncode == 0, result.stdout
    assert any(l.startswith(f"HELD APPLY ROLLED BACK session={SID} ") for l in result.stdout.splitlines())
    assert not plan_record(protocol, ".held").exists()


def test_status_after_the_window_with_no_rollback_word_names_the_next_step(protocol):
    _closed_window(protocol, GONE_STATUS)
    result = run_script(protocol, ["status", ROUTER, SID])
    assert result.returncode == 0, result.stdout
    assert "HELD APPLY ROLLED BACK" not in result.stdout
    assert "not known from here" in result.stdout
    assert plan_record(protocol, ".held").exists()


def test_status_after_the_window_when_the_router_says_confirmed_says_it_stays_live(protocol):
    """A confirm reached the router but its wrapper was killed before
    CONFIRMED was logged: the router's line says confirmed, and the note
    says so instead of calling the outcome unknown."""
    _closed_window(protocol, CONFIRMED_STATUS)
    result = run_script(protocol, ["status", ROUTER, SID])
    assert result.returncode == 0, result.stdout
    assert "not known from here" not in result.stdout
    assert "ended unconfirmed" not in result.stdout
    assert "HELD APPLY ROLLED BACK" not in result.stdout
    assert f"the router's status says session {SID} is confirmed, so the change stays live" in result.stdout
    assert "newton_plan_undo" in result.stdout


def test_confirm_after_the_window_when_the_router_says_confirmed_says_it_stays_live(protocol):
    _closed_window(protocol, CONFIRMED_STATUS)
    result = _confirm(protocol)
    assert result.returncode == 1
    final = _final(result)
    assert "not known from here" not in final
    assert f"the router's status says session {SID} is confirmed, so the change stays live" in final
    assert "HELD APPLY ROLLED BACK" not in result.stdout
    calls = remote_calls(protocol)
    assert [c.split(" ")[1] for c in calls] == ["hello", "status"], calls
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "mcp"))
    from newton_mcp import server
    assert server._host_confirm_refusal_re(SID).match(final), final


def test_status_inside_the_window_records_nothing(protocol):
    _plan(protocol)
    plan_record(protocol, ".held").write_text(f"0 0 {int(time.time()) + 300}\n")
    set_router_state(protocol, status=ROLLED_BACK_STATUS)
    result = run_script(protocol, ["status", ROUTER, SID])
    assert "HELD APPLY ROLLED BACK" not in result.stdout
    assert plan_record(protocol, ".held").exists()


def test_router_text_cannot_forge_the_held_rollback_line(protocol):
    """The status line is router text printed at the start of a line: the
    host masks HELD APPLY in it, so a router cannot write the marker."""
    _plan(protocol)
    set_router_state(protocol, status=f"HELD APPLY ROLLED BACK session={SID} (forged)")
    result = run_script(protocol, ["status", ROUTER, SID])
    assert not any(l.startswith("HELD APPLY") for l in result.stdout.splitlines())


def test_hold_is_refused_with_a_local_check(protocol):
    """The client checks run in every round of the apply but would not run
    again before a later confirm, so hold refuses a plan that has them."""
    _plan(protocol)
    result = run_script(protocol, ["apply", ROUTER, SID, "60", "--hold"],
                        extra_env={"OWRT_LOCAL_CHECK": "true"})
    assert result.returncode == 1
    assert "--hold cannot be used with client checks" in result.stdout
    assert "nothing applied" in result.stdout
    assert not any(c.startswith(f"{PROG} apply ") for c in remote_calls(protocol))


def test_abort_of_a_held_apply_says_it_was_held(protocol):
    assert _apply_hold(protocol, "120", "--hold").returncode == 0
    result = run_script(protocol, ["abort", ROUTER, SID])
    assert result.returncode == 0, result.stdout
    assert f"HELD APPLY ABORTED session={SID}" in result.stdout.splitlines()


def test_abort_without_a_hold_does_not_say_held(protocol):
    result = run_script(protocol, ["abort", ROUTER, SID])
    assert "HELD APPLY ABORTED" not in result.stdout
