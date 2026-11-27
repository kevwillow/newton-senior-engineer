"""apply --hold with a client check, and the confirm of a held apply.

The client checks (OWRT_LOCAL_CHECK) run on the agent host in every round
of the apply.  A held apply runs the same rounds and leaves the change
armed, so the confirm runs the client checks once more, right before it
asks the router to confirm: a local check that fails there refuses the
confirm, and the router puts the change back at its deadline.

The hold record says which check the held apply ran: its fourth field is
the sha256 of the check itself (or 0 when the apply ran none).  A confirm
that runs another check would confirm a change nobody checked the way the
apply checked it, so it is refused before the router is asked.
"""

import hashlib
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_owrt_change import (  # noqa: E402,F401
    PROG, SCRIPT, SID, plan_record, protocol, remote_calls, run_script,
    set_router_state,
)

ROUTER = "root@192.0.2.1"


def _plan(protocol):
    record = plan_record(protocol, ".sha256")
    record.parent.mkdir(parents=True, exist_ok=True)
    diff = json.loads(protocol["router"].read_text())["diff"]
    record.write_text(
        hashlib.sha256((diff.rstrip("\n") + "\n").encode()).hexdigest() + "\n")
    return record


def _final(result):
    return [line for line in result.stdout.splitlines() if line.strip()][-1]


def _counter_check(protocol):
    """A local check that counts its own runs."""
    counter = protocol["root"] / "local-check-count"
    local = (
        f"n=$(cat {counter} 2>/dev/null || echo 0); n=$((n + 1)); "
        f"printf '%s' \"$n\" > {counter}"
    )
    return counter, local


def test_apply_hold_with_a_client_check_is_accepted_and_runs_it_in_every_round(protocol):
    """The held apply is not refused for the client check: it runs them in
    each of its rounds and leaves the change armed."""
    counter, local = _counter_check(protocol)
    _plan(protocol)
    result = run_script(protocol, ["apply", ROUTER, SID, "60", "--hold"],
                        extra_env={"OWRT_LOCAL_CHECK": local})
    assert result.returncode == 0, result.stdout
    assert _final(result).startswith(f"HELD session={SID} until=")
    assert "--hold cannot be used" not in result.stdout
    # one run in each of the three rounds of the held apply
    assert counter.read_text() == "3"
    assert len([c for c in remote_calls(protocol) if c.startswith(f"{PROG} verify ")]) == 3
    assert plan_record(protocol, ".held").exists()


def test_confirm_with_a_failing_client_check_refuses_and_does_not_confirm(protocol):
    """The client check runs again before the confirm: when it fails, the
    router is never asked to confirm and the change stays armed (the
    router puts it back at its deadline).  The check of the confirm is
    the check of the apply (the hold record says which one it was), so
    the check is the one that fails now and passed in the rounds."""
    marker = protocol["root"] / "the-check-fails-now"
    check = f"[[ -e {marker} ]] && exit 1; exit 0"
    _plan(protocol)
    assert run_script(protocol, ["apply", ROUTER, SID, "120", "--hold"],
                      extra_env={"OWRT_LOCAL_CHECK": check}).returncode == 0
    marker.write_text("")
    before = len(remote_calls(protocol))
    result = run_script(protocol, ["confirm", ROUTER, SID],
                        extra_env={"OWRT_LOCAL_CHECK": check})
    assert result.returncode == 1, result.stdout
    assert f"{PROG} confirm {SID}" not in remote_calls(protocol)[before:]
    assert "the local check failed before the confirm" in result.stdout
    assert "not confirmed" in result.stdout
    assert "the router rolls the change back when its window ends" in result.stdout
    assert "CONFIRMED" not in _final(result)
    assert plan_record(protocol, ".held").exists()


def test_confirm_with_a_passing_client_check_confirms(protocol):
    """The client check runs again before the confirm and passes, so the
    router is asked to confirm as usual."""
    counter, local = _counter_check(protocol)
    _plan(protocol)
    assert run_script(protocol, ["apply", ROUTER, SID, "120", "--hold"],
                      extra_env={"OWRT_LOCAL_CHECK": local}).returncode == 0
    assert counter.read_text() == "3"
    before = len(remote_calls(protocol))
    result = run_script(protocol, ["confirm", ROUTER, SID],
                        extra_env={"OWRT_LOCAL_CHECK": local})
    assert result.returncode == 0, result.stdout
    assert f"{PROG} confirm {SID}" in remote_calls(protocol)[before:]
    assert _final(result).startswith(f"CONFIRMED session={SID} ")
    # the check ran once more, right before the confirm
    assert counter.read_text() == "4"
    assert not plan_record(protocol, ".held").exists()


def _held_record(protocol) -> str:
    """The hold record the apply left, as one line."""
    return plan_record(protocol, ".held").read_text(encoding="utf-8").strip()


def test_the_hold_record_carries_the_digest_of_the_client_check(protocol):
    """The hold record says which client check the apply ran: the fourth
    field is the sha256 of the check itself, so a confirm that runs
    another check can be told apart from one that runs the same."""
    check = "echo 'vantage-check: claim 1 OK' >&2"
    _plan(protocol)
    assert run_script(protocol, ["apply", ROUTER, SID, "120", "--hold"],
                      extra_env={"OWRT_LOCAL_CHECK": check}).returncode == 0
    fields = _held_record(protocol).split()
    assert len(fields) == 4
    assert fields[3] == hashlib.sha256(check.encode()).hexdigest()


def test_the_hold_record_says_the_apply_ran_no_client_check(protocol):
    """The same apply without a client check leaves the fourth field at 0."""
    _plan(protocol)
    assert run_script(protocol, ["apply", ROUTER, SID, "120", "--hold"]).returncode == 0
    fields = _held_record(protocol).split()
    assert len(fields) == 4
    assert fields[3] == "0"


def test_a_confirm_without_the_client_check_of_the_hold_is_refused(protocol):
    """The held apply ran a client check and the confirm does not have it:
    the confirm is refused before the router is asked, so the change stays
    armed and the router puts it back at its deadline."""
    _plan(protocol)
    assert run_script(protocol, ["apply", ROUTER, SID, "120", "--hold"],
                      extra_env={"OWRT_LOCAL_CHECK": "true"}).returncode == 0
    before = len(remote_calls(protocol))
    result = run_script(protocol, ["confirm", ROUTER, SID])
    assert result.returncode == 1, result.stdout
    final = _final(result)
    assert f"the held apply of session {SID} ran a client check" in final
    assert "run the confirm with the same OWRT_LOCAL_CHECK as the apply" in final
    assert "nothing confirmed" in final
    # the refusal happens before any router call
    assert remote_calls(protocol)[before:] == []
    # the change stays armed: the hold record is still there
    assert plan_record(protocol, ".held").exists()


def test_a_three_field_hold_record_still_confirms(protocol):
    """A hold record written by an older host has three fields: it means the
    apply ran no client check, and the confirm goes on as it did."""
    _plan(protocol)
    assert run_script(protocol, ["apply", ROUTER, SID, "120", "--hold"]).returncode == 0
    fields = _held_record(protocol).split()
    assert len(fields) == 4
    # the record of an older host: three fields, no client check
    plan_record(protocol, ".held").write_text(
        " ".join(fields[:3]) + "\n", encoding="utf-8")
    result = run_script(protocol, ["confirm", ROUTER, SID])
    assert result.returncode == 0, result.stdout
    assert _final(result).startswith(f"CONFIRMED session={SID} ")


def test_a_confirm_with_another_client_check_is_refused(protocol):
    """The held apply ran one client check and the confirm runs another:
    the confirm is refused before the router is asked, so the change stays
    armed and the router puts it back at its deadline."""
    _plan(protocol)
    assert run_script(protocol, ["apply", ROUTER, SID, "120", "--hold"],
                      extra_env={"OWRT_LOCAL_CHECK": "true"}).returncode == 0
    before = len(remote_calls(protocol))
    result = run_script(protocol, ["confirm", ROUTER, SID],
                        extra_env={"OWRT_LOCAL_CHECK": "echo 'another check' >&2"})
    assert result.returncode == 1, result.stdout
    final = _final(result)
    assert f"the held apply of session {SID} ran a client check" in final
    assert "run the confirm with the same OWRT_LOCAL_CHECK as the apply" in final
    assert "nothing confirmed" in final
    # the refusal happens before any router call
    assert remote_calls(protocol)[before:] == []
    # the change stays armed: the hold record is still there
    assert plan_record(protocol, ".held").exists()


def test_a_hold_record_with_a_fourth_field_of_one_is_refused(protocol):
    """A hold record whose fourth field is 1 is malformed: no such record
    ever shipped, so the confirm refuses it instead of reading it as a
    check it does not know."""
    _plan(protocol)
    assert run_script(protocol, ["apply", ROUTER, SID, "120", "--hold"]).returncode == 0
    fields = _held_record(protocol).split()
    plan_record(protocol, ".held").write_text(
        " ".join(fields[:3]) + " 1\n", encoding="utf-8")
    before = len(remote_calls(protocol))
    result = run_script(protocol, ["confirm", ROUTER, SID])
    assert result.returncode == 1, result.stdout
    final = _final(result)
    assert f"the hold record of session {SID} is malformed" in final
    assert "nothing confirmed" in final
    assert remote_calls(protocol)[before:] == []
    assert plan_record(protocol, ".held").exists()


def test_the_status_reads_a_hold_record_that_carries_a_digest(protocol):
    """The status reads the same record as the confirm: a record whose
    fourth field is the digest of a client check still names the window
    that ended unconfirmed."""
    _plan(protocol)
    plan_record(protocol, ".held").write_text(
        f"0 0 {int(time.time()) - 1} {hashlib.sha256(b'true').hexdigest()}\n",
        encoding="utf-8")
    set_router_state(
        protocol, status=f"gone sid={SID} guard=idle rpcd=- config=other boot=-")
    result = run_script(protocol, ["status", ROUTER, SID])
    assert result.returncode == 0, result.stdout
    assert "the window of its held apply ended unconfirmed" in result.stdout

