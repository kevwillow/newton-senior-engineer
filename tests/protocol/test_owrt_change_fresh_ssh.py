"""Rule 6, OpenWrt installed: every verify round of scripts/owrt-change.sh
runs over a fresh SSH connection.

The change-protocol contract (docs/design/13-CHANGE-PROTOCOL.md) promises
that the installed mode verifies over fresh connections, and the host
script keeps that promise by asking ssh for no shared connection on every
call (-o ControlMaster=no -o ControlPath=none) and by running each verify
round as its own ssh process.  Nothing proved it: these tests do.

The fake ssh of tests/protocol/test_owrt_change.py logs every argv it is
called with.  The rule needs the identity of the process behind each argv
as well (a reused connection would be one process answering several
calls), so the fake ssh logs its own pid and start time next to the argv.
"""

import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_owrt_change import (  # noqa: E402,F401
    PROG, SID, plan_record, protocol, run_script)

ROUTER = "root@192.0.2.1"


def ssh_processes(protocol):
    """Every ssh the fake ssh saw: the argv it was called with, the remote
    command it ran and the process that ran it (pid and start time, so a
    pid the kernel reuses cannot pass for the same process)."""
    return [
        json.loads(line)
        for line in protocol["ssh_proc"].read_text().splitlines()
        if line.strip()
    ]


def ssh_calls(protocol, prefix):
    """The ssh calls whose remote command starts with *prefix*."""
    return [rec for rec in ssh_processes(protocol) if rec["cmd"].startswith(prefix)]


def verify_calls(protocol):
    """The ssh calls that ran a verify round of this session."""
    return ssh_calls(protocol, f"{PROG} verify {SID} ")


def assert_no_shared_connection(record):
    """The ssh call of *record* asks for no shared connection, so ssh cannot
    serve it over a multiplexed connection it opened earlier."""
    pairs = list(zip(record["argv"], record["argv"][1:]))
    assert ("-o", "ControlMaster=no") in pairs, record["argv"]
    assert ("-o", "ControlPath=none") in pairs, record["argv"]


def _plan(protocol):
    """The plan record the apply of the script reads (the diff hash)."""
    record = plan_record(protocol, ".sha256")
    record.parent.mkdir(parents=True, exist_ok=True)
    diff = json.loads(protocol["router"].read_text())["diff"]
    record.write_text(
        hashlib.sha256((diff.rstrip("\n") + "\n").encode()).hexdigest() + "\n")
    return record


def test_every_verify_round_of_an_apply_runs_as_its_own_ssh_process(protocol):
    """The three verify rounds of an apply are three ssh processes, each
    with the connection sharing off, and none of them is the ssh that ran
    the apply."""
    result = protocol["run"]()

    assert result.returncode == 0, result.stdout
    assert f"CONFIRMED session={SID}" in result.stdout
    verifies = verify_calls(protocol)
    assert len(verifies) == 3, [rec["cmd"] for rec in ssh_processes(protocol)]
    assert [rec["cmd"] for rec in verifies] == [f"{PROG} verify {SID} 0"] * 3
    # three processes of their own: one connection answering three rounds
    # would be a single process
    assert len({(rec["pid"], rec["start"]) for rec in verifies}) == 3
    applies = ssh_calls(protocol, f"{PROG} apply {SID} ")
    assert len(applies) == 1
    assert applies[0]["pid"] not in {rec["pid"] for rec in verifies}
    for record in verifies:
        assert_no_shared_connection(record)


def test_every_verify_round_of_an_apply_runs_as_its_own_ssh_process_in_the_password_lane(
    protocol, tmp_path
):
    """The same for the password lane: that lane builds its own ssh
    options, and they carry the same two options."""
    password_file = tmp_path / "password"
    password_file.write_text("made-up-password\n")
    password_file.chmod(0o600)

    result = protocol["run"](
        extra_env={"OWRT_SSH_PASSWORD_FILE": str(password_file)}
    )

    assert result.returncode == 0, result.stdout
    assert f"CONFIRMED session={SID}" in result.stdout
    verifies = verify_calls(protocol)
    assert len(verifies) == 3, [rec["cmd"] for rec in ssh_processes(protocol)]
    assert [rec["cmd"] for rec in verifies] == [f"{PROG} verify {SID} 0"] * 3
    assert len({(rec["pid"], rec["start"]) for rec in verifies}) == 3
    applies = ssh_calls(protocol, f"{PROG} apply {SID} ")
    assert len(applies) == 1
    assert applies[0]["pid"] not in {rec["pid"] for rec in verifies}
    for record in verifies:
        # the password lane really ran (its own options), and it asked for
        # no shared connection just like the key lane
        assert "-o" in record["argv"]
        assert any(
            arg.startswith("PreferredAuthentications=password")
            for arg in record["argv"]
        ), record["argv"]
        assert_no_shared_connection(record)


def test_the_extra_verify_round_of_a_held_apply_is_a_fresh_ssh(protocol):
    """`apply --hold` runs its three rounds and confirms nothing; `confirm`
    runs one more round before it confirms, and that round is an ssh
    process of its own, with the connection sharing off."""
    _plan(protocol)
    held = run_script(protocol, ["apply", ROUTER, SID, "120", "--hold"])
    assert held.returncode == 0, held.stdout
    assert len(verify_calls(protocol)) == 3
    before = len(ssh_processes(protocol))

    result = run_script(protocol, ["confirm", ROUTER, SID])

    assert result.returncode == 0, result.stdout
    assert f"CONFIRMED session={SID}" in result.stdout
    fresh = ssh_processes(protocol)[before:]
    verifies = [rec for rec in fresh if rec["cmd"].startswith(f"{PROG} verify {SID} ")]
    confirms = [rec for rec in fresh if rec["cmd"] == f"{PROG} confirm {SID}"]
    assert len(verifies) == 1, [rec["cmd"] for rec in fresh]
    assert len(confirms) == 1
    # the round ran in a process of its own, not in the ssh that confirmed
    assert verifies[0]["pid"] != confirms[0]["pid"]
    assert_no_shared_connection(verifies[0])
    # and it is a fourth process, not one of the three of the held apply
    every_verify = verify_calls(protocol)
    assert len(every_verify) == 4
    assert len({(rec["pid"], rec["start"]) for rec in every_verify}) == 4
