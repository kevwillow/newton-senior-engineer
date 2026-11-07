"""The Junos lint, the pinned command texts and the Junos operations.

The module under test is ``newton_mcp.adapters.junos_write``: the lint and
the tokenizer for the platform "junos", the command texts the driver sends
to Junos 26.2R1.7 and ``JunosOps``, the operations that implement the
generic ``vendor_change.VendorOps`` protocol for a Junos device.

No device is contacted.  Every session in this file is answered by a fake
that emulates the CLI transcript of the measured device (the confirm,
abort and backup transcripts of a vJunos lab run), and every command text is pinned exactly.


"""

from __future__ import annotations

import hashlib
import inspect
from dataclasses import dataclass, field
from typing import Any

import pytest

from newton_mcp import vendor_change as vc
from newton_mcp.adapters import junos_write as jw
from newton_mcp.adapters import vendor_write as vw


# ---- the texts the driver sends, pinned exactly ------------------------------
#
# The session of a Junos device is one ssh with no remote command and the
# CLI script on stdin (measured, measure/tr/junos-confirm.txt).  The two
# exec sessions read the configuration and the commit list; the pipe in
# them is Junos CLI syntax, not a shell pipe: the login shell of the
# device is the CLI (measured on 26.2R1.7).

CONFIG_COMMAND = "show configuration | display set | no-more"
CANDIDATE_COMMAND = "show | display set | no-more"
PENDING_COMMAND = "show system commit | no-more"
PING_COMMAND = "ping 192.0.2.1 count 3 rapid"

# The reads are sessions of the CLI as well: the login shell of a Junos
# is the CLI, and the output of a command is the block between the echo
# of the command and the next prompt.  The candidate of a stage and the
# running configuration of a snapshot are read the same way, so one
# normaliser hashes both.
CONFIG_READ_SCRIPT = f"{CONFIG_COMMAND}\nexit\n"
PENDING_READ_SCRIPT = f"{PENDING_COMMAND}\nexit\n"

STAGE_SCRIPT = (
    "configure exclusive\n"
    "set system host-name p11-confirm\n"
    "show | compare | no-more\n"
    "show | display set | no-more\n"
    "rollback 0\n"
    "exit\n"
    "exit\n"
)
APPLY_SCRIPT = (
    "configure exclusive\n"
    "set system host-name p11-confirm\n"
    "commit confirmed 3 comment newton-pending\n"
    "exit\n"
    "exit\n"
)
CONFIRM_SCRIPT = "configure\ncommit\nexit\nexit\n"
ABORT_SCRIPT = "configure exclusive\nrollback 1\ncommit\nexit\nexit\n"

# The change of the tests: one plain statement and one with a value that
# holds a space (the driver renders it in double quotes).
CHANGE_TEXT = "set system host-name p11-confirm"
SECOND_TEXT = "set interfaces ge-0/0/0 unit 0 description 'lab uplink'"
SECOND_COMMAND = 'set interfaces ge-0/0/0 unit 0 description "lab uplink"'

# The configuration of the device, as the device shows it (display set).
CONFIG_TEXT = "\n".join(
    [
        "set version 26.2R1.7",
        "set system host-name lab-junos",
        'set system root-authentication encrypted-password "$6$redacted"',
        "set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24",
    ]
)

REAL_CHANGE_LINE = "set interfaces lo0 description lab-shape-01"

JUNOS_STAGE_REAL = "\n".join(
    [
        "newton@lab-junos> configure exclusive ",
        "warning: uncommitted changes will be discarded on exit",
        "Entering configuration mode",
        "",
        "[edit]",
        "newton@lab-junos# set interfaces lo0 description lab-shape-01 ",
        "",
        "[edit]",
        "newton@lab-junos# show | compare | no-more ",
        "[edit interfaces]",
        "+   lo0 {",
        "+       description lab-shape-01;",
        "+   }",
        "",
        "[edit]",
        "newton@lab-junos# show configuration",
        "                       ^",
        "syntax error.",
        "",
        "newton@lab-junos# show configuration   \b\b|",
        "                       ^",
        "syntax error.",
        "",
        "newton@lab-junos# show configuration|   \b\bdisplay",
        "                       ^",
        "syntax error.",
        "",
        "newton@lab-junos# show configuration|display   \b\bset",
        "                       ^",
        "syntax error.",
        "",
        "newton@lab-junos# show configuration|displayset   \b\b|",
        "                       ^",
        "syntax error.",
        "",
        "newton@lab-junos# show configuration|displayset|   \b\bno-more",
        "                       ^",
        "syntax error.",
        "",
        "[edit]",
        "newton@lab-junos# rollback 0 ",
        "load complete",
        "",
        "[edit]",
        "newton@lab-junos# exit ",
        "Exiting configuration mode",
        "",
        "newton@lab-junos> exit ",
        "",
    ]
)

JUNOS_STAGE_CORRECT = "\n".join(
    [
        "newton@lab-junos> configure exclusive ",
        "warning: uncommitted changes will be discarded on exit",
        "Entering configuration mode",
        "",
        "[edit]",
        f"newton@lab-junos# {REAL_CHANGE_LINE} ",
        "",
        "[edit]",
        "newton@lab-junos# show | compare | no-more ",
        "[edit interfaces]",
        "+   lo0 {",
        "+       description lab-shape-01;",
        "+   }",
        "",
        "[edit]",
        f"newton@lab-junos# {CANDIDATE_COMMAND} ",
        CONFIG_TEXT,
        REAL_CHANGE_LINE,
        "",
        "[edit]",
        "newton@lab-junos# rollback 0 ",
        "load complete",
        "",
        "[edit]",
        "newton@lab-junos# exit ",
        "Exiting configuration mode",
        "",
        "newton@lab-junos> exit ",
        "",
    ]
)

# A stage whose compare fails: the error is not in a statement, it
# happens before the candidate is read.
JUNOS_STAGE_PRE_CANDIDATE_ERROR = "\n".join(
    [
        "newton@lab-junos> configure exclusive ",
        "warning: uncommitted changes will be discarded on exit",
        "Entering configuration mode",
        "",
        "[edit]",
        f"newton@lab-junos# {CHANGE_TEXT} ",
        "",
        "[edit]",
        f"newton@lab-junos# {SECOND_COMMAND} ",
        "",
        "[edit]",
        "newton@lab-junos# show | compare | no-more ",
        "error: could not read the candidate configuration",
        "",
        "[edit]",
        f"newton@lab-junos# {CANDIDATE_COMMAND} ",
        CONFIG_TEXT,
        "",
        "[edit]",
        "newton@lab-junos# rollback 0 ",
        "load complete",
        "",
        "[edit]",
        "newton@lab-junos# exit ",
        "Exiting configuration mode",
        "",
        "newton@lab-junos> exit ",
        "",
    ]
)

# The measured ping summary of Junos.
PING_OK = "\n".join(
    [
        "PING 192.0.2.1 (192.0.2.1): 56 data bytes",
        "--- 192.0.2.1 ping statistics ---",
        "3 packets transmitted, 3 packets received, 0% packet loss",
        "round-trip min/avg/max/stddev = 1.2/1.3/1.4/0.1 ms",
    ]
)
PING_LOST = "\n".join(
    [
        "PING 192.0.2.1 (192.0.2.1): 56 data bytes",
        "--- 192.0.2.1 ping statistics ---",
        "3 packets transmitted, 0 packets received, 100% packet loss",
    ]
)

# CS-04: the corpus.  Every hostile line must be refused and every benign
# line must be accepted.
HOSTILE_LINES = (
    # the hierarchies that are not on the allow list
    "set snmp community public",
    "set system login user newton class super-user",
    "delete system login user newton",
    "set system services ssh",
    "delete system services ssh",
    "set event-options user-login message 'hello'",
    "set system scripts start lab.py",
    "set chassis auto-image-upgrade",
    "set system root-authentication encrypted-password 'x'",
    "set system syslog file messages any notice",
    "set system processes dhcp-service traceoptions level all",
    "set switching-options vlans vlan10 vlan-id 10",
    "set groups lab system host-name p11",
    # the verbs that are not allowed
    "request system reboot",
    "request configuration rollback 1",
    "load set terminal",
    "commit",
    "rollback 1",
    "run show version",
    "show configuration",
    "edit system host-name",
    # the abbreviations
    "set sys host-name p11",
    "set int ge-0/0/0 description x",
    "set proto bgp group lab peer-as 1",
    "set rout-options static route 0.0.0.0/0 next-hop 192.0.2.1",
    "set sec zones security-zone trust",
    "set fire family inet filter lab term accept",
    "set pol policy-statement lab then accept",
    "set vl vlan10 vlan-id 10",
    # the case variants
    "set System host-name p11",
    "set SYSTEM HOST-NAME p11",
    "Set system host-name p11",
    "set Interfaces ge-0/0/0 description x",
    "set system HOST-NAME p11",
    "set security ZONES security-zone trust",
    # the raw text rules
    "set system host-name p11; request system reboot",
    "set system host-name p11 | match x",
    "set system host-name $(id)",
    "set system host-name `id`",
    "set system host-name [x]",
    "set system host-name {x}",
    "set system host-name <x>",
    "set system host-name (x)",
    "set system host-name !x",
    "set system host-name x?",
    'set system host-name "x"',
    "set system host-name x\\y",
    "set system host-name x*y",
    "set system host-name x\ty",
    "set system host-name x\ry",
    "set system host-name x\x1by",
    "set system host-name x\x00y",
    "set system host-name café",
    "# a comment with a semicolon; inside",
    # the reserved marker text
    "set system host-name NEWTON-COMMITTED",
    "set system host-name NEWTON-LINE-ERROR",
    # the reserved tag of the commit of Newton
    "set system host-name newton-pending",
    # the grammar
    "set",
    "set system",
    "set system host-name",
    "set system host-name ''",
    "set system host-name 'unterminated",
)

BENIGN_LINES = (
    "set system host-name p11-confirm",
    "set system name-server 192.0.2.53",
    "set system ntp server 192.0.2.53",
    "set system time-zone America/New_York",
    "set interfaces ge-0/0/0 unit 0 description 'lab uplink'",
    "set vlans vlan10 vlan-id 10",
    "set routing-options static route 0.0.0.0/0 next-hop 192.0.2.1",
    "set protocols bgp group lab peer-as 64512",
    "set policy-options policy-statement lab then accept",
    "set firewall family inet filter lab term accept then accept",
    "set security zones security-zone trust host-inbound-services ssh",
    "set security policies policy lab match source-address 192.0.2.0/24",
    "set security nat source-rule lab then translation static",
    "delete system name-server 192.0.2.53",
    "activate protocols bgp",
    "deactivate protocols bgp",
    "set interfaces fxp0 unit 0 family inet address 10.109.9.41/24",
)


def _out(
    stdout: str = "",
    *,
    stderr: str = "",
    exit_code: int | None = 0,
    status: str = "ok",
) -> vc.RunOut:
    return vc.RunOut(
        status=status,  # type: ignore[arg-type]
        stdout=stdout,
        stderr=stderr,
        exit_code=exit_code,
    )


@dataclass
class FakeCommit:
    """One entry of the commit list of the fake device."""

    who: str = "root"
    comment: str = ""
    pending: bool = False
    armed: bool = False
    minutes: int = 0


class FakeJunos:
    """A scripted Junos that emulates the CLI transcript of the device.

    Every session is answered with the text the real CLI prints: the
    banner, the prompt with the echoed command, the output of the command
    and the next prompt.  The read sessions (the configuration and the
    commit list) are sessions of the CLI as well, so the noise of the
    CLI is in every transcript and the normaliser has to survive it.

    The state of the device is the committed configuration, the
    configuration of the commit before it and the commit list, so a test
    can take the device into the state it wants.
    """

    # The banner the CLI prints before the first prompt.
    BANNER = "\n".join(
        [
            "JUNOS 26.2R1.7",
            "Last login: Thu Oct 23 23:27:36 UTC 2026",
        ]
    )

    def __init__(
        self,
        *,
        config: str = CONFIG_TEXT,
        ping_output: str = PING_OK,
        errors: tuple[str, ...] = (),
        statement_error: str = "syntax error.",
        statement_output: str | None = None,
        drop_at_commit: str | None = None,
        fail_commit: bool = False,
        notice_minutes: int | None = None,
        keep_pending_on_confirm: bool = False,
        timer_fires_before_confirm: bool = False,
        timer_fires_before_ping: bool = False,
        refuse_occurrences: dict[str, tuple[int, ...]] | None = None,
        fail_first_exit: bool = False,
    ) -> None:
        self.committed = config.splitlines()
        self.previous = list(self.committed)
        self.commits: list[FakeCommit] = [
            FakeCommit(who="newton"),
            FakeCommit(who="root"),
        ]
        self.ping_output = ping_output
        self.errors = set(errors)
        self.statement_error = statement_error
        self.statement_output = statement_output
        self.drop_at_commit = drop_at_commit
        self.fail_commit = fail_commit
        self.notice_minutes = notice_minutes
        self.keep_pending_on_confirm = keep_pending_on_confirm
        self.timer_fires_before_confirm = timer_fires_before_confirm
        self.timer_fires_before_ping = timer_fires_before_ping
        self.refuse_occurrences = dict(refuse_occurrences or {})
        self.fail_first_exit = fail_first_exit
        self.calls: list[vw.SessionSpec] = []
        self.outputs: list[vc.RunOut] = []
        self.stage_sessions = 0
        self.apply_sessions = 0
        self.confirm_sessions = 0
        self.abort_sessions = 0
        self.armed = False
        self._failed_exit = False

    # -- the sessions ---------------------------------------------------------

    def __call__(self, spec: vw.SessionSpec) -> vc.RunOut:
        self.calls.append(spec)
        output = self._answer(spec)
        self.outputs.append(output)
        return output

    @property
    def remotes(self) -> list[str]:
        return [spec.remote for spec in self.calls]

    @property
    def scripts(self) -> list[str]:
        return [spec.stdin for spec in self.calls]

    @property
    def cli_scripts(self) -> list[str]:
        """The scripts of the sessions that ran in the CLI of the device."""
        return [spec.stdin for spec in self.calls if spec.remote == ""]

    def _answer(self, spec: vw.SessionSpec) -> vc.RunOut:
        remote = spec.remote
        if remote == "":
            return _out(self._cli(spec.stdin))
        if remote.startswith("ping "):
            return _out(self._exec(remote))
        raise AssertionError(f"unknown session: {remote!r}")

    def _exec(self, remote: str) -> str:
        """The transcript of a session that runs one command."""
        if self.timer_fires_before_ping and remote.startswith("ping "):
            # the armed revert fires while the driver is verifying the
            # change: the device rolls back by itself.
            self._fire_timer()
        out = [self.BANNER, f"{self._prompt('op')} {remote} "]
        out.extend(self.ping_output.splitlines())
        out.append(self._prompt("op"))
        return "\n".join(out) + "\n"

    # -- the state of the device ---------------------------------------------

    def display_set(self) -> str:
        """The committed configuration, as the device shows it."""
        return "\n".join(self.committed)

    def commit_list(self) -> str:
        """The commit list of the device, as the device shows it."""
        out: list[str] = []
        for index, commit in enumerate(self.commits):
            header = f"{index}   2026-10-23 23:2{index}:07 UTC by {commit.who} via cli"
            if commit.armed:
                header += f" commit confirmed, rollback in {commit.minutes}mins"
            out.append(header)
            if commit.comment:
                out.append(f"    comment: {commit.comment}")
            if commit.pending:
                out.append("    rollback pending")
        return "\n".join(out)

    def set_commits(self, commits: list[FakeCommit]) -> None:
        """Put the commit list of the device into the state a test wants."""
        self.commits = list(commits)

    @property
    def pending(self) -> bool:
        """True when the device shows a revert that is pending."""
        return any(commit.pending for commit in self.commits)

    @pending.setter
    def pending(self, value: bool) -> None:
        """Set the pending flag of the top entry of the commit list."""
        if not self.commits:
            self.commits.append(FakeCommit(who="root"))
        self.commits[0].pending = value

    # -- the CLI --------------------------------------------------------------

    def _prompt(self, mode: str) -> str:
        return "newton@lab-junos" + (">" if mode == "op" else "#")

    def _cli(self, script: str) -> str:
        """Answer one CLI session the way the device does."""
        out: list[str] = [self.BANNER]
        mode = "op"
        candidate: list[str] = []
        notice = ""
        seen: dict[str, int] = {}
        if self.timer_fires_before_confirm and script.startswith("configure\ncommit"):
            self._fire_timer()
        for raw in script.splitlines():
            command = raw.strip()
            out.append(f"{self._prompt(mode)} {command} ")
            marker = True
            if command == "configure exclusive":
                mode = "config"
                candidate = list(self.committed)
                out.append("warning: uncommitted changes will be discarded on exit")
                out.append("Entering configuration mode")
            elif command == "configure":
                mode = "config"
                candidate = list(self.committed)
                out.append("Entering configuration mode")
            elif command.startswith(("set ", "delete ", "activate ", "deactivate ")):
                count = seen.get(command, 0) + 1
                seen[command] = count
                refused = command in self.errors or count in self.refuse_occurrences.get(
                    command, ()
                )
                if refused:
                    out.append(self.statement_error)
                    marker = False
                else:
                    candidate = self._apply(candidate, command)
                    if self.statement_output is not None:
                        out.append(self.statement_output)
                        marker = False
            elif command == "show | compare | no-more":
                out.extend(self._compare(candidate))
            elif command == CANDIDATE_COMMAND:
                out.extend(candidate if mode == "config" else self.committed)
            elif command == CONFIG_COMMAND:
                if mode == "config":
                    out.append("                       ^")
                    out.append("syntax error.")
                    marker = False
                else:
                    out.extend(self.committed)
            elif command == PENDING_COMMAND:
                out.extend(self.commit_list().splitlines())
            elif command == "rollback 0":
                candidate = list(self.committed)
                out.append("load complete")
            elif command == "rollback 1":
                candidate = list(self.previous)
                out.append("load complete")
            elif command.startswith("commit confirmed "):
                minutes = int(command.split()[2])
                shown = self.notice_minutes if self.notice_minutes is not None else minutes
                out.append(
                    "commit confirmed will be automatically rolled back in "
                    f"{shown} minutes unless confirmed"
                )
                out.append("commit complete")
                notice = f"# commit confirmed will be rolled back in {shown} minutes"
                self._commit(candidate, confirmed=False, tag=jw.COMMIT_TAG, minutes=minutes)
            elif command == "commit":
                if self.fail_commit:
                    out.append("error: the commit failed")
                else:
                    out.append("commit complete")
                    self._commit(candidate, confirmed=True)
            elif command == "exit":
                if mode == "config":
                    if self.fail_first_exit and not self._failed_exit:
                        self._failed_exit = True
                        out.append("error: could not leave the configuration mode")
                        marker = False
                    else:
                        mode = "op"
                        out.append("Exiting configuration mode")
            else:
                raise AssertionError(f"unknown command: {command!r}")
            if mode == "config" and marker:
                out.append("")
                if notice:
                    out.append(notice)
                out.append("[edit]")
            elif notice and mode == "op":
                out.append("")
                out.append(notice)
        if "commit confirmed" in script:
            self.apply_sessions += 1
        elif "show | compare | no-more" in script:
            self.stage_sessions += 1
        elif script.startswith("configure\ncommit"):
            self.confirm_sessions += 1
        elif "rollback 1" in script:
            self.abort_sessions += 1
        return "\n".join(out) + "\n"

    def _apply(self, candidate: list[str], command: str) -> list[str]:
        """Put one statement into the candidate configuration."""
        key = " ".join(command.split(" ")[:-1])
        for index, line in enumerate(candidate):
            if " ".join(line.split(" ")[:-1]) == key:
                out = list(candidate)
                out[index] = command
                return out
        return list(candidate) + [command]

    def _compare(self, candidate: list[str]) -> list[str]:
        """The diff between the candidate and the committed configuration.

        The device shows the diff in the "show configuration" form, with
        the semicolon at the end of the line and the hierarchy under an
        "[edit ...]" header (measured, junos-abort.txt).
        """
        out: list[str] = []
        header = ""
        for line in self.committed:
            if line in candidate:
                continue
            if not header:
                header = self._hierarchy(line)
                out.append(f"[edit {header}]")
            out.append(f"-  {self._compare_line(line, header)}")
        for line in candidate:
            if line in self.committed:
                continue
            if not header:
                header = self._hierarchy(line)
                out.append(f"[edit {header}]")
            out.append(f"+  {self._compare_line(line, header)}")
        return out

    def _hierarchy(self, line: str) -> str:
        words = self._path(line)
        return words[0] if words else ""

    def _compare_line(self, line: str, header: str) -> str:
        words = self._path(line)
        if header and words and words[0] == header:
            words = words[1:]
        return " ".join(words) + ";"

    def _path(self, line: str) -> list[str]:
        words = line.split(" ")
        if words and words[0] in ("set", "delete", "activate", "deactivate"):
            words = words[1:]
        return words

    def _commit(
        self,
        candidate: list[str],
        *,
        confirmed: bool,
        tag: str = "",
        minutes: int = 0,
    ) -> None:
        """Commit the candidate configuration."""
        lines = list(candidate)
        if self.drop_at_commit is not None and self.drop_at_commit in lines:
            lines.remove(self.drop_at_commit)
        self.previous = list(self.committed)
        self.committed = lines
        self.commits.insert(
            0,
            FakeCommit(
                who="newton",
                comment=tag,
                pending=not confirmed,
                armed=not confirmed,
                minutes=minutes,
            ),
        )
        if confirmed and not self.keep_pending_on_confirm:
            # a plain commit takes every armed revert away
            for commit in self.commits:
                commit.pending = False
        self.armed = not confirmed

    def _fire_timer(self) -> None:
        """The armed revert fires: the device rolls back by itself.

        The rollback is a commit of its own, so the commit before it is
        the change of Newton: a "rollback 1" from there would put the
        change back with no revert armed.
        """
        self.committed = list(self.previous)
        for commit in self.commits:
            commit.pending = False
        self.commits.insert(0, FakeCommit(who="root", comment="auto-rollback"))
        self.armed = False


def _plan(
    *,
    text: str = CHANGE_TEXT,
    base_hash: str | None = None,
    timeout_s: int = 150,
    probes: list[list[str]] | None = None,
) -> dict[str, Any]:
    return {
        "uci_batch": text,
        "base_hash": jw.config_hash(CONFIG_TEXT) if base_hash is None else base_hash,
        "timeout_s": timeout_s,
        "probes": [] if probes is None else probes,
    }


# ---- the lint ---------------------------------------------------------------


def test_the_corpus_refuses_every_hostile_line() -> None:
    """CS-04, the hostile half: every hostile line is refused."""
    assert len(HOSTILE_LINES) >= 40
    for line in HOSTILE_LINES:
        with pytest.raises(jw.LintError):
            jw.parse_lines(line)


def test_the_corpus_accepts_every_benign_line() -> None:
    """CS-04, the benign half: every benign line is accepted."""
    assert len(BENIGN_LINES) >= 10
    for line in BENIGN_LINES:
        parsed = jw.parse_lines(line)
        assert len(parsed) == 1, line


def test_the_statements_parse_into_words() -> None:
    """A statement is a verb, a hierarchy and its values."""
    parsed = jw.parse_lines("\n".join((CHANGE_TEXT, SECOND_TEXT)))
    assert parsed == [
        ["set", "system", "host-name", "p11-confirm"],
        [
            "set",
            "interfaces",
            "ge-0/0/0",
            "unit",
            "0",
            "description",
            "lab uplink",
        ],
    ]


def test_only_the_four_verbs_are_allowed() -> None:
    """A verb outside the four is refused and the verb is named."""
    for verb in ("request", "load", "commit", "rollback", "run", "show", "edit"):
        with pytest.raises(jw.LintError) as excinfo:
            jw.parse_lines(f"{verb} system host-name p11")
        assert verb in str(excinfo.value)


def test_every_allowed_hierarchy_is_accepted() -> None:
    """The allow list holds the hierarchies the agent may touch."""
    samples = {
        "interfaces": "set interfaces ge-0/0/0 unit 0 description x",
        "vlans": "set vlans vlan10 vlan-id 10",
        "routing-options": (
            "set routing-options static route 0.0.0.0/0 next-hop 192.0.2.1"
        ),
        "protocols": "set protocols bgp group lab peer-as 64512",
        "policy-options": "set policy-options policy-statement lab then accept",
        "firewall": "set firewall family inet filter lab term accept then accept",
        "security zones": (
            "set security zones security-zone trust host-inbound-services ssh"
        ),
        "security policies": (
            "set security policies policy lab match source-address 192.0.2.0/24"
        ),
        "security nat": "set security nat source-rule lab then translation static",
        "system host-name": "set system host-name p11-confirm",
        "system name-server": "set system name-server 192.0.2.53",
        "system ntp": "set system ntp server 192.0.2.53",
        "system time-zone": "set system time-zone America/New_York",
    }
    allowed = {" ".join(hierarchy) for hierarchy in jw.ALLOWED_HIERARCHIES}
    assert set(samples) == allowed
    for hierarchy, line in samples.items():
        parsed = jw.parse_lines(line)
        assert len(parsed) == 1, line
        words = hierarchy.split(" ")
        assert parsed[0][1 : 1 + len(words)] == words, line


def test_every_other_hierarchy_is_refused() -> None:
    """A hierarchy that is not on the list is not allowed."""
    for line in (
        "set snmp community public",
        "set system login user newton class super-user",
        "set system services ssh",
        "set event-options user-login message hello",
        "set system scripts start lab.py",
        "set system root-authentication encrypted-password x",
        "set switching-options vlans vlan10 vlan-id 10",
        "set groups lab system host-name p11",
        "set chassis auto-image-upgrade",
    ):
        with pytest.raises(jw.LintError) as excinfo:
            jw.parse_lines(line)
        assert str(excinfo.value) == "hierarchy not allowed", line


def test_no_abbreviation_and_no_case_variant_gets_through() -> None:
    """Junos takes an abbreviation, so neither may pass the lint."""
    for line in (
        "set sys host-name p11",
        "set int ge-0/0/0 description x",
        "set proto bgp group lab peer-as 1",
        "set rout-options static route 0.0.0.0/0 next-hop 192.0.2.1",
        "set sec zones security-zone trust",
        "set System host-name p11",
        "set SYSTEM HOST-NAME p11",
        "Set system host-name p11",
        "set Interfaces ge-0/0/0 description x",
        "set system HOST-NAME p11",
        "set security ZONES security-zone trust",
    ):
        with pytest.raises(jw.LintError):
            jw.parse_lines(line)


@pytest.mark.parametrize(
    "char",
    (
        ";",
        "|",
        "&",
        "$",
        "`",
        "[",
        "]",
        "{",
        "}",
        "<",
        ">",
        "(",
        ")",
        "!",
        "?",
        '"',
        "\\",
    ),
)
def test_every_forbidden_character_is_refused(char: str) -> None:
    """The raw text of a line carries no metacharacter."""
    with pytest.raises(jw.LintError):
        jw.parse_lines(f"set system host-name p11{char}tail")


@pytest.mark.parametrize("char", ("\t", "\r", "\x00", "\x1b", "\x7f"))
def test_every_control_character_is_refused(char: str) -> None:
    """Tab, CR, NUL, ESC and DEL are refused."""
    with pytest.raises(jw.LintError):
        jw.parse_lines(f"set system host-name p11{char}tail")


def test_a_non_ascii_character_is_refused() -> None:
    """The change text is ascii only."""
    with pytest.raises(jw.LintError):
        jw.parse_lines("set system host-name café")


def test_a_long_line_and_too_many_statements_are_refused() -> None:
    """401 characters and 201 statements are refused."""
    long_line = "set system host-name " + "a" * 380
    assert len(long_line) > 400
    with pytest.raises(jw.LintError):
        jw.parse_lines(long_line)
    body = "\n".join(f"set system host-name p11-{index}" for index in range(200))
    assert len(jw.parse_lines(body)) == 200
    with pytest.raises(jw.LintError):
        jw.parse_lines(body + "\nset system host-name p11-200")


def test_the_reserved_marker_text_is_refused() -> None:
    """A token that carries NEWTON- is refused."""
    with pytest.raises(jw.LintError) as excinfo:
        jw.parse_lines("set system host-name NEWTON-COMMITTED")
    assert str(excinfo.value) == "reserved marker text"


def test_an_empty_value_is_refused() -> None:
    """A value may not be empty, not bare and not quoted."""
    with pytest.raises(jw.LintError):
        jw.parse_lines("set system host-name ''")
    with pytest.raises(jw.LintError):
        jw.parse_lines("set system host-name 'unterminated")


def test_a_statement_needs_a_hierarchy_and_a_value() -> None:
    """A statement is a verb, a hierarchy and at least one value."""
    with pytest.raises(jw.LintError):
        jw.parse_lines("set")
    with pytest.raises(jw.LintError):
        jw.parse_lines("set system")
    with pytest.raises(jw.LintError):
        jw.parse_lines("set system host-name")


def test_the_owner_text_keeps_the_single_quotes() -> None:
    """The owner text is what the agent wrote, and it parses again."""
    parsed = jw.parse_lines(SECOND_TEXT)
    assert jw.render_line(parsed[0]) == SECOND_TEXT
    assert jw.parse_lines(jw.render_line(parsed[0])) == parsed


def test_the_device_text_quotes_a_value_with_spaces() -> None:
    """The driver renders a value with spaces in double quotes."""
    parsed = jw.parse_lines(SECOND_TEXT)
    assert jw.command_text(parsed[0]) == SECOND_COMMAND


def test_the_lint_message_never_echoes_the_agent_text() -> None:
    """A lint message is a short reason, never the whole line."""
    long_word = "p" * 300
    cases = (
        f"{long_word} system host-name p11",
        f"set system host-name p11{';' * 300}",
        "set system login user newton",
    )
    for line in cases:
        with pytest.raises(jw.LintError) as excinfo:
            jw.parse_lines(line)
        message = str(excinfo.value)
        assert len(message) <= 120, line[:40]
        assert long_word not in message


# ---- the pinned command texts ------------------------------------------------


def test_the_exec_commands_are_pinned() -> None:
    """The two reads and the ping are the pinned texts.

    The reads are sessions of the CLI as well: the login shell of a Junos
    is the CLI, and the output of a command is the block between the
    echo of the command and the next prompt.
    """
    assert jw.config_command().remote == ""
    assert jw.config_command().stdin == CONFIG_READ_SCRIPT
    assert jw.pending_command().remote == ""
    assert jw.pending_command().stdin == PENDING_READ_SCRIPT
    assert jw.ping_command("192.0.2.1").remote == PING_COMMAND
    assert jw.ping_command("192.0.2.1").stdin == ""


def test_the_ping_host_is_bounded() -> None:
    """The ping target is bounded before it reaches a remote string."""
    for host in ("-oProxyCommand=id", "host name", "", "a" * 254, "host; reboot"):
        with pytest.raises(jw.LintError):
            jw.ping_command(host)


def test_the_stage_script_is_the_measured_shape() -> None:
    """The stage is one session and it never changes the device."""
    statements = jw.parse_lines(CHANGE_TEXT)
    spec = jw.stage_script(statements)
    assert spec.remote == ""
    assert spec.stdin == STAGE_SCRIPT
    # the candidate is thrown away before the session ends
    assert spec.stdin.index("rollback 0") < spec.stdin.index("exit")
    assert spec.stdin.count("exit") == 2
    assert "commit" not in spec.stdin


def test_the_apply_script_commits_confirmed() -> None:
    """The apply arms the revert in the same session as the change."""
    statements = jw.parse_lines(CHANGE_TEXT)
    spec = jw.apply_script(statements, 3)
    assert spec.remote == ""
    assert spec.stdin == APPLY_SCRIPT
    assert "commit confirmed 3" in spec.stdin
    assert "configure exclusive" in spec.stdin


def test_the_confirm_and_the_abort_scripts_are_pinned() -> None:
    """The confirm commits, the abort rolls back one commit."""
    assert jw.confirm_script().remote == ""
    assert jw.confirm_script().stdin == CONFIRM_SCRIPT
    assert jw.abort_script().remote == ""
    assert jw.abort_script().stdin == ABORT_SCRIPT


def test_the_config_hash_ignores_the_comments_and_the_blanks() -> None:
    """The hash is over the configuration, not over the CLI noise."""
    one = "# header\nset system host-name p11\n\n"
    two = "set system host-name p11\n"
    assert jw.config_hash(one) == jw.config_hash(two)
    assert jw.config_hash(two) == hashlib.sha256(
        "set system host-name p11".encode()
    ).hexdigest()


# ---- the ops ----------------------------------------------------------------


def test_the_snapshot_hashes_the_display_set() -> None:
    """The snapshot is the configuration and the commit list."""
    device = FakeJunos()
    snapshot = jw.JunosOps().snapshot(device)

    assert snapshot.text == CONFIG_TEXT
    assert snapshot.base_hash == jw.config_hash(CONFIG_TEXT)
    assert snapshot.reload_ok is True
    assert snapshot.saved_clean is True
    assert snapshot.pending == "idle"
    assert device.cli_scripts == [CONFIG_READ_SCRIPT, PENDING_READ_SCRIPT]


def test_a_pending_revert_makes_the_snapshot_pending() -> None:
    """A revert that is pending is read from the commit list."""
    device = FakeJunos()
    device.pending = True
    assert jw.JunosOps().snapshot(device).pending == "pending"
    assert jw.JunosOps().pending(device) == "pending"


def test_the_stage_returns_the_diff_and_the_candidate_hash() -> None:
    """The stage is the diff and the hash of the candidate."""
    device = FakeJunos()
    statements = jw.parse_lines(CHANGE_TEXT)
    staged = jw.JunosOps().stage(device, statements)

    assert staged.ok is True
    assert staged.bad_line is None
    assert "[edit system]" in staged.diff
    assert "-  host-name lab-junos;" in staged.diff
    assert "+  host-name p11-confirm;" in staged.diff
    assert staged.candidate_hash == jw.config_hash(
        CONFIG_TEXT.replace(
            "set system host-name lab-junos",
            "set system host-name p11-confirm",
        )
    )
    # the stage never changes the device
    assert device.committed == CONFIG_TEXT.splitlines()
    assert device.pending is False


def test_the_stage_finds_the_line_the_device_refused() -> None:
    """A refused statement is a line error and it names the line."""
    device = FakeJunos(errors=(CHANGE_TEXT,))
    statements = jw.parse_lines("\n".join((CHANGE_TEXT, SECOND_TEXT)))
    staged = jw.JunosOps().stage(device, statements)

    assert staged.ok is False
    assert staged.bad_line == 1


def test_the_stage_fails_closed_on_every_error_text() -> None:
    """Any line that is not blank and not an [edit] marker is one.

    Junos prints "syntax error." and carries on, so the exit status says
    nothing about a bad line.  The only acceptable output of a statement
    is nothing at all or an [edit ...] marker.
    """
    for text in (
        "syntax error.",
        "error: syntax error",
        "warning: statement not applied",
        "unknown command",
        "missing argument",
        "\x1b[1m",
        "\u200b",
    ):
        device = FakeJunos(statement_output=text)
        statements = jw.parse_lines(CHANGE_TEXT)
        staged = jw.JunosOps().stage(device, statements)
        assert staged.ok is False, text
        assert staged.bad_line == 1, text


def test_the_apply_stages_again_before_it_commits() -> None:
    """The apply re-stages in a fresh session and then commits."""
    device = FakeJunos()
    statements = jw.parse_lines(CHANGE_TEXT)
    ops = jw.JunosOps()
    result = ops.apply(device, statements, 150)

    assert result == "committed"
    # the re-stage comes first, the apply session second
    assert device.cli_scripts[0] == STAGE_SCRIPT
    assert device.cli_scripts[1] == APPLY_SCRIPT
    assert ops.expected_hash is not None
    assert ops.expected_hash == jw.config_hash(
        CONFIG_TEXT.replace(
            "set system host-name lab-junos",
            "set system host-name p11-confirm",
        )
    )


def test_a_refused_line_sends_no_apply_session() -> None:
    """The re-stage refuses, so nothing is committed and nothing armed."""
    device = FakeJunos(errors=(CHANGE_TEXT,))
    statements = jw.parse_lines(CHANGE_TEXT)
    result = jw.JunosOps().apply(device, statements, 150)

    assert result == "line_error"
    assert APPLY_SCRIPT not in device.cli_scripts
    assert device.cli_scripts[0] == STAGE_SCRIPT
    assert device.pending is False
    assert device.committed == CONFIG_TEXT.splitlines()


def test_the_commit_is_only_committed_with_the_notice() -> None:
    """"commit complete" alone is not a commit: the notice counts."""
    statements = jw.parse_lines(CHANGE_TEXT)

    class _NoNotice(FakeJunos):
        def _cli(self, script: str) -> str:
            out = super()._cli(script)
            return out.replace(
                "commit confirmed will be automatically rolled back in 3 minutes "
                "unless confirmed",
                "",
            ).replace(
                "# commit confirmed will be rolled back in 3 minutes",
                "",
            )

    device = _NoNotice()
    assert jw.JunosOps().apply(device, statements, 150) == "failed"

    class _NoComplete(FakeJunos):
        def _cli(self, script: str) -> str:
            return super()._cli(script).replace("commit complete", "commit failed")

    device = _NoComplete()
    assert jw.JunosOps().apply(device, statements, 150) == "failed"


def test_the_confirm_needs_the_commit_and_no_pending() -> None:
    """The confirm is true only when the commit went through."""
    device = FakeJunos()
    device.pending = True
    assert jw.JunosOps().confirm(device) is True
    assert device.pending is False

    device = FakeJunos(fail_commit=True)
    device.pending = True
    assert jw.JunosOps().confirm(device) is False
    assert device.pending is True


def test_the_abort_rolls_back_one_commit() -> None:
    """The abort is the rollback of the commit before the change."""
    device = FakeJunos()
    statements = jw.parse_lines(CHANGE_TEXT)
    jw.JunosOps().apply(device, statements, 150)
    assert device.committed != CONFIG_TEXT.splitlines()

    assert jw.JunosOps().abort(device) is True
    assert device.committed == CONFIG_TEXT.splitlines()
    assert device.pending is False
    assert ABORT_SCRIPT in device.cli_scripts


def test_the_save_is_a_no_op() -> None:
    """A Junos commits into the saved configuration: no save."""
    device = FakeJunos()
    assert jw.JunosOps().save(device) is True
    assert device.calls == []


def test_the_ping_needs_the_packets_back() -> None:
    """The ping is a probe, so the packets have to come back."""
    device = FakeJunos()
    assert jw.JunosOps().probe_ping(device, "192.0.2.1") is True
    assert device.remotes[-1] == PING_COMMAND

    lost = FakeJunos(ping_output=PING_LOST)
    assert jw.JunosOps().probe_ping(lost, "192.0.2.1") is False


def test_has_line_compares_the_tokens_of_both_sides() -> None:
    """The device quotes with double quotes, the agent with single."""
    ops = jw.JunosOps()
    assert ops.has_line(CONFIG_TEXT, "set system host-name lab-junos") is True
    assert ops.has_line(CONFIG_TEXT, "set system host-name other") is False
    assert ops.has_line(CONFIG_TEXT, "set system host-name 'lab-junos'") is True
    # the device text of a value with a space carries double quotes
    device_text = 'set system description "lab uplink"'
    assert ops.has_line(device_text, "set system description 'lab uplink'") is True
    assert ops.has_line(device_text, "set system description 'other'") is False
    assert ops.has_line("", "") is False


def test_the_module_is_pure() -> None:
    """The module never runs a command and never touches a file."""
    source = inspect.getsource(jw)
    for needle in (
        "import subprocess",
        "shell=True",
        "os.system",
        "eval(",
        "exec(",
        "open(",
    ):
        assert needle not in source, needle


def test_the_platform_is_junos() -> None:
    """The ops carry the platform the driver dispatches on."""
    assert jw.JunosOps().platform == "junos"
    assert jw.PLATFORM_JUNOS == "junos"


def test_the_dispatcher_reaches_the_junos_lint() -> None:
    """Vendor_write dispatches to the junos lint and renderer."""
    parsed = vw.parse_lines("junos", "set system host-name p11-confirm")
    assert parsed == [["set", "system", "host-name", "p11-confirm"]]
    assert vw.render_line("junos", parsed[0]) == "set system host-name p11-confirm"
    with pytest.raises(vw.LintError):
        vw.parse_lines("junos", "set system login user newton")


def test_the_other_platforms_have_no_expected_hash() -> None:
    """The expected hash is a Junos thing: the others have none."""
    assert not hasattr(vw.VyosOps(), "expected_hash")
    from newton_mcp.adapters.routeros_write import RouterosOps

    assert not hasattr(RouterosOps(), "expected_hash")
    assert jw.JunosOps().expected_hash is None


# ---- the driver --------------------------------------------------------------


def test_the_end_to_end_happy_path_confirms() -> None:
    """Plan, apply, verify, probe and confirm in that order."""
    device = FakeJunos()
    ops = jw.JunosOps()
    outcome = vc.apply_plan(ops, device, _plan(), [["ping", "192.0.2.1"]])

    assert outcome.result == "confirmed"
    assert outcome.failed_probe is None
    assert outcome.saved is True
    assert device.cli_scripts[0] == CONFIG_READ_SCRIPT
    stage_index = device.cli_scripts.index(STAGE_SCRIPT)
    apply_index = device.cli_scripts.index(APPLY_SCRIPT)
    assert stage_index < apply_index
    assert CONFIRM_SCRIPT in device.cli_scripts
    # the verify reads the configuration in a session of its own
    assert device.cli_scripts.count(CONFIG_READ_SCRIPT) >= 2


def test_a_failing_probe_takes_the_recover_path() -> None:
    """A probe that fails rolls the change back."""
    device = FakeJunos(ping_output=PING_LOST)
    outcome = vc.apply_plan(jw.JunosOps(), device, _plan(), [["ping", "192.0.2.1"]])

    assert outcome.result == "rolled_back"
    assert outcome.failed_probe == ["ping", "192.0.2.1"]
    assert device.committed == CONFIG_TEXT.splitlines()
    assert ABORT_SCRIPT in device.cli_scripts


def test_a_partial_commit_is_rolled_back() -> None:
    """A commit that is not the candidate is a partial change."""
    device = FakeJunos(drop_at_commit=SECOND_COMMAND)
    text = "\n".join((CHANGE_TEXT, SECOND_TEXT))
    outcome = vc.apply_plan(jw.JunosOps(), device, _plan(text=text), [])

    assert outcome.result == "rolled_back"
    assert device.committed == CONFIG_TEXT.splitlines()
    assert ABORT_SCRIPT in device.cli_scripts


def test_the_commit_that_matches_the_candidate_goes_on() -> None:
    """The candidate hash that comes back is the one that goes."""
    device = FakeJunos()
    outcome = vc.apply_plan(jw.JunosOps(), device, _plan(), [])

    assert outcome.result == "confirmed"


def test_a_withheld_confirm_leaves_the_revert_armed() -> None:
    """A stop after the apply leaves the revert armed on the device."""
    device = FakeJunos()
    calls = {"n": 0}

    def runner(spec: vw.SessionSpec) -> vc.RunOut:
        calls["n"] += 1
        if calls["n"] == 5:
            raise RuntimeError("the verify stopped")
        return device(spec)

    with pytest.raises(RuntimeError, match="the verify stopped"):
        vc.apply_plan(jw.JunosOps(), runner, _plan(), [])

    assert device.pending is True
    assert device.armed is True
    assert CONFIRM_SCRIPT not in device.cli_scripts
    assert ABORT_SCRIPT not in device.cli_scripts

    status = vc.change_status(jw.JunosOps(), device)
    assert status["pending"] == "pending"


def test_a_change_without_a_difference_is_refused() -> None:
    """A candidate that is the running one is not a change."""
    device = FakeJunos()
    with pytest.raises(vc.VendorRefusal) as excinfo:
        vc.stage_plan(
            jw.JunosOps(),
            device,
            "set system host-name lab-junos",
            150,
        )
    assert "nothing to change" in str(excinfo.value)


def test_a_stale_base_hash_is_refused() -> None:
    """A device that changed after the plan is stale."""
    device = FakeJunos()
    outcome = vc.apply_plan(
        jw.JunosOps(),
        device,
        _plan(base_hash="0" * 64),
        [],
    )
    assert outcome.result == "stale"


def test_a_pending_revert_refuses_the_plan() -> None:
    """A revert that is already pending refuses the change."""
    device = FakeJunos()
    device.pending = True
    with pytest.raises(vc.VendorRefusal) as excinfo:
        vc.stage_plan(jw.JunosOps(), device, CHANGE_TEXT, 150)
    assert "pending" in str(excinfo.value)


# ---- review fixes ------------------------
#
# The review found two blockers and three majors against fc35a79:
#
# the abort rolled the change back with "rollback 1" whatever the
#     commit list said.  Once the armed revert has fired, the rollback is
#     a commit of its own, so "rollback 1" is the change of Newton and the
#     abort put it back with no revert armed.  The commit of Newton now
#     carries a tag ("commit confirmed N comment newton-pending") and the
#     abort reads the commit list before it rolls anything back.
# the confirm did not prove that the change was still on the device.
#     The timer can fire between the verify and the confirm, and the
#     driver then confirmed a device that held the base configuration.
#     The driver reads a fresh snapshot after the confirm and compares it
#     with the candidate that was staged.
# a concurrent commit on top of the change of Newton shifts
#     "rollback 1" to the change itself.
# a session that died while it held the exclusive lock leaves the
#     database of the device locked, and every abort after it failed with
#     "database locked".
# the proof that the revert was armed was a substring of the whole
#     transcript, so a value of the change could carry it.
# the candidate hash came from a CLI session and the running hash
#     from an exec session, so the noise of the CLI could make every
#     apply revert.
#
# The minors are regression tests: a duplicate statement, a notice of
# another window, a pending that survives a commit and the address of the
# management interface.


def _tagged_commit(**kwargs: Any) -> FakeCommit:
    """The commit of Newton: tagged, armed and with a pending revert."""
    defaults: dict[str, Any] = {
        "who": "newton",
        "comment": "newton-pending",
        "pending": True,
        "armed": True,
        "minutes": 3,
    }
    defaults.update(kwargs)
    return FakeCommit(**defaults)


def test_the_apply_script_tags_the_commit() -> None:
    """The commit of Newton carries the tag the abort looks for."""
    statements = jw.parse_lines(CHANGE_TEXT)
    spec = jw.apply_script(statements, 3)

    assert "commit confirmed 3 comment newton-pending" in spec.stdin
    assert jw.COMMIT_TAG == "newton-pending"
    # the tag is reserved: an agent cannot put it into the device
    with pytest.raises(jw.LintError):
        jw.parse_lines("set system host-name newton-pending")


def test_the_abort_rolls_back_the_tagged_commit() -> None:
    """The tagged commit with a pending revert is rolled back.

    This is the ordinary case: the change of Newton is the top entry of
    the commit list and its revert is pending, so the rollback of the
    commit before it is the change.
    """
    device = FakeJunos()
    device.set_commits([_tagged_commit(), FakeCommit(who="root")])

    assert jw.JunosOps().abort(device) is True
    assert ABORT_SCRIPT in device.cli_scripts
    # the commit list is read before anything is rolled back
    assert device.cli_scripts[0] == PENDING_READ_SCRIPT
    assert device.cli_scripts.index(PENDING_READ_SCRIPT) < device.cli_scripts.index(
        ABORT_SCRIPT
    )


def test_the_abort_does_nothing_when_the_device_already_reverted() -> None:
    """The armed revert fired: there is nothing to roll back.

    The rollback of the device is a commit of its own, so the commit
    before it is the change of Newton.  A "rollback 1" from there would
    put the change back with no revert armed, so the abort does nothing.

    The commit of Newton is still in the visible list of the device, so
    the abort cannot say that the device reverted the change (the text
    of an entry the device rolled back is not recorded): it says that it
    does not know.  The test of the missing Newton commit pins the one case in which the abort may
    say that the change is gone.
    """
    device = FakeJunos()
    device.set_commits(
        [
            FakeCommit(who="root", comment="auto-rollback"),
            _tagged_commit(pending=False),
        ]
    )

    assert jw.JunosOps().abort(device) is False
    assert ABORT_SCRIPT not in device.cli_scripts


def test_the_abort_is_unknown_when_our_commit_is_confirmed() -> None:
    """The tagged commit on top with no pending revert is unknown.

    The change was confirmed by somebody else, or the state of the device
    is ambiguous: the abort cannot say that the change is gone.
    """
    device = FakeJunos()
    device.set_commits([_tagged_commit(pending=False), FakeCommit(who="root")])

    assert jw.JunosOps().abort(device) is False
    assert ABORT_SCRIPT not in device.cli_scripts


def test_the_abort_is_unknown_when_a_foreign_commit_is_on_top() -> None:
    """A commit of somebody else is on top of the change.

    The revert of Newton is still armed, so the change is still on the
    device, and "rollback 1" would roll back the commit of somebody else.
    The abort says that it does not know.
    """
    device = FakeJunos()
    device.set_commits(
        [
            FakeCommit(who="root"),
            _tagged_commit(),
        ]
    )

    assert jw.JunosOps().abort(device) is False
    assert ABORT_SCRIPT not in device.cli_scripts


def test_a_timer_that_fires_before_the_confirm_is_unknown() -> None:
    """The confirm does not prove that the change is still there.

    The armed revert fires between the verify and the confirm: the device
    rolls back by itself and the confirm commits the base configuration.
    The result is unknown, never confirmed.
    """
    device = FakeJunos(timer_fires_before_confirm=True)
    outcome = vc.apply_plan(jw.JunosOps(), device, _plan(), [])

    assert outcome.result == "unknown"
    assert outcome.log == (
        "the device differs from the verified change after the confirm"
    )
    assert outcome.saved is None


def test_the_reads_are_sessions_of_the_cli() -> None:
    """The reads are the CLI form, so one normaliser reads both.

    The candidate of a stage and the running configuration of a snapshot
    are read the same way: the block between the echo of the command and
    the next prompt.
    """
    device = FakeJunos()
    ops = jw.JunosOps()
    snapshot = ops.snapshot(device)

    assert device.cli_scripts == [CONFIG_READ_SCRIPT, PENDING_READ_SCRIPT]
    assert snapshot.text == CONFIG_TEXT
    assert snapshot.base_hash == jw.config_hash(CONFIG_TEXT)


def test_the_banner_and_the_prompts_do_not_change_the_hash() -> None:
    """The noise of the CLI is not part of the hash.

    The banner and the prompts of the CLI are in every transcript, so a
    hash that counts them would make every apply revert.
    """
    device = FakeJunos()
    snapshot = jw.JunosOps().snapshot(device)

    assert device.BANNER.splitlines()[0] in device.outputs[0].stdout
    assert snapshot.base_hash == jw.config_hash(CONFIG_TEXT)
    assert snapshot.base_hash != jw.config_hash(device.outputs[0].stdout)


def test_the_stage_order_holds_when_the_first_exit_fails() -> None:
    """The candidate is thrown away before the session ends.

    The stage keeps the exclusive lock of the device, so the candidate is
    thrown away ("rollback 0") before the session leaves the
    configuration mode, and the second "exit" ends the session even when
    the first one failed.
    """
    device = FakeJunos(fail_first_exit=True)
    statements = jw.parse_lines(CHANGE_TEXT)
    staged = jw.JunosOps().stage(device, statements)

    script = jw.stage_script(statements).stdin
    assert script.index("rollback 0") < script.index("exit")
    assert script.count("exit") == 2
    assert staged.ok is True
    # the candidate was thrown away and the device did not move
    assert device.committed == CONFIG_TEXT.splitlines()


def test_the_arm_proof_is_a_line_and_not_a_substring() -> None:
    """A value of the change is not the proof that anything is armed.

    The words of the notice inside the echo of a statement are not the
    notice: the proof has to be a line of its own.
    """
    statements = jw.parse_lines("set system host-name 'x rolled back in 3 minutes'")
    out = "\n".join(
        [
            'newton@lab-junos# set system host-name "x rolled back in 3 minutes"',
            "[edit]",
            "newton@lab-junos# commit confirmed 3 comment newton-pending",
            "commit complete",
        ]
    )

    assert jw.parse_apply(out, 3, statements) == "failed"


def test_the_pending_is_line_anchored() -> None:
    """A commit comment that quotes the phrase is not a pending."""
    listed = "\n".join(
        [
            "0   2026-10-23 23:28:07 UTC by newton via cli",
            "    comment: rollback pending",
            "1   2026-10-23 23:27:36 UTC by root via cli",
        ]
    )
    assert jw.parse_pending(listed) is False

    pending = "\n".join(
        [
            "0   2026-10-23 23:28:07 UTC by newton via cli",
            "    rollback pending",
            "1   2026-10-23 23:27:36 UTC by root via cli",
        ]
    )
    assert jw.parse_pending(pending) is True


def test_a_duplicate_statement_is_read_twice() -> None:
    """The same statement twice is read twice.

    The search for the output of a statement starts after the output of
    the statement before it, so a refused copy of a statement is found
    even when the statement is in the change twice.
    """
    device = FakeJunos(refuse_occurrences={CHANGE_TEXT: (2,)})
    statements = jw.parse_lines("\n".join((CHANGE_TEXT, CHANGE_TEXT)))
    staged = jw.JunosOps().stage(device, statements)

    assert staged.ok is False
    assert staged.bad_line == 2


def test_a_notice_of_another_window_is_not_an_arm() -> None:
    """The notice has to be the window the driver asked for."""
    device = FakeJunos(notice_minutes=5)
    statements = jw.parse_lines(CHANGE_TEXT)

    assert jw.JunosOps().apply(device, statements, 150) == "failed"


def test_a_pending_that_survives_the_confirm_is_not_a_confirm() -> None:
    """The commit is not enough: the pending flag has to be gone."""
    device = FakeJunos(keep_pending_on_confirm=True)
    device.set_commits([_tagged_commit(), FakeCommit(who="root")])

    assert jw.JunosOps().confirm(device) is False
    assert device.pending is True


def test_the_management_interface_address_is_accepted() -> None:
    """The address of the management interface is a change.

    It is not refused by the lint: it is staged, it shows in the diff and
    it is owned by the probes and by the revert.
    """
    line = "set interfaces fxp0 unit 0 family inet address 10.109.9.41/24"
    parsed = jw.parse_lines(line)

    assert len(parsed) == 1
    assert parsed[0][:4] == ["set", "interfaces", "fxp0", "unit"]
    assert jw.render_line(parsed[0]) == line


def test_the_comment_of_the_cli_is_not_the_arm_proof() -> None:
    """The comment of the CLI is not the notice of the commit.

    The CLI prints the notice of the armed revert as a comment ("# commit
    confirmed will be rolled back in 3 minutes").  A comment is not the
    notice of the commit: the proof has to be the line of the notice
    itself.
    """
    statements = jw.parse_lines(CHANGE_TEXT)
    out = "\n".join(
        [
            "newton@lab-junos# set system host-name p11-confirm",
            "[edit]",
            "newton@lab-junos# commit confirmed 3 comment newton-pending",
            "# commit confirmed will be rolled back in 3 minutes",
            "commit complete",
        ]
    )

    assert jw.parse_apply(out, 3, statements) == "failed"


def test_the_stage_reads_the_candidate_in_configuration_mode() -> None:
    """The candidate read is valid in configure mode."""
    statements = jw.parse_lines(CHANGE_TEXT)
    spec = jw.stage_script(statements)

    assert spec.stdin == STAGE_SCRIPT
    assert CANDIDATE_COMMAND in spec.stdin
    assert CONFIG_COMMAND not in spec.stdin


def test_the_running_command_is_refused_in_configuration_mode() -> None:
    """The fake refuses the running read in configure mode."""
    device = FakeJunos()
    script = f"configure exclusive\n{CONFIG_COMMAND}\nexit\nexit\n"
    output = device(vw.SessionSpec(remote="", stdin=script)).stdout

    assert "syntax error." in output
    assert CONFIG_TEXT not in output


def test_the_real_stage_transcript_is_a_line_error() -> None:
    """The measured syntax error fails the stage closed."""
    statements = jw.parse_lines(REAL_CHANGE_LINE)
    staged = jw.parse_stage(JUNOS_STAGE_REAL, statements)

    assert staged.ok is False
    assert staged.bad_line == 1


def test_the_correct_stage_transcript_parses_clean() -> None:
    """The corrected transcript yields the candidate hash."""
    statements = jw.parse_lines(REAL_CHANGE_LINE)
    staged = jw.parse_stage(JUNOS_STAGE_CORRECT, statements)

    assert staged.ok is True
    assert staged.bad_line is None
    assert staged.candidate_hash == jw.config_hash(
        f"{CONFIG_TEXT}\n{REAL_CHANGE_LINE}"
    )


def test_the_candidate_and_running_hashes_use_one_normaliser() -> None:
    """An unchanged candidate has the running configuration hash."""
    device = FakeJunos()
    statements = jw.parse_lines("set system host-name lab-junos")
    staged = jw.parse_stage(
        device(jw.stage_script(statements)).stdout,
        statements,
    )
    running = jw.config_text(device(jw.config_command()).stdout)

    assert staged.ok is False
    assert staged.no_changes is True
    assert staged.bad_line is None
    assert staged.candidate_hash == jw.config_hash(running)


# ---- review fixes ---
#
# The review found three majors and two minors against the Junos path:
#
# MAJOR 1: the abort decided that the device had already reverted the
#     change whenever the top entry of the commit list was not the
#     commit of Newton and no revert was pending.  That state also
#     arises when the commit of Newton was confirmed (the change is
#     still on the device) and a commit of somebody else landed on top
#     of it: the abort said that the change was gone and it was not.
#     The visible list shows an entry the device rolled back with the
#     same text as any other entry, so the abort may only say that the
#     change is gone when the visible list carries no commit of Newton
#     at all.  Every other state is ambiguous.
# MINOR 4: the guard that skipped a commit comment in the pending of
#     an entry was dead code (a line that starts with "comment:" can
#     never start with "rollback pending").
# MINOR 8: the index a pre-candidate error reports was not tested.


def test_the_abort_is_unknown_when_a_foreign_commit_is_on_top_of_a_confirmed_change() -> None:
    """The commit of Newton is under a commit of somebody else.

    The commit of Newton carries no pending revert any more (it was
    confirmed) and a commit of somebody else is on top of it.  The
    change is still on the device, so the abort must not say that the
    device reverted it and it must not roll anything back.
    """
    device = FakeJunos()
    device.set_commits(
        [
            FakeCommit(who="root"),
            _tagged_commit(pending=False),
        ]
    )

    assert jw.JunosOps().abort(device) is False
    assert ABORT_SCRIPT not in device.cli_scripts


def test_the_abort_says_the_change_is_gone_when_it_is_not_visible() -> None:
    """No commit of Newton in the list: the change is gone.

    The visible list of the device carries no commit of Newton at all,
    so the device rolled the change back by itself and there is nothing
    to roll back.  This is the one case in which the abort may say that
    the change is gone.
    """
    device = FakeJunos()
    device.set_commits([FakeCommit(who="root", comment="auto-rollback")])

    assert jw.JunosOps().abort(device) is True
    assert ABORT_SCRIPT not in device.cli_scripts


def test_the_apply_of_a_device_that_reverted_by_itself_is_unknown() -> None:
    """A device that rolled back by itself is unknown.

    The armed revert fired while the driver was verifying the change:
    the device is back at the base configuration and its commit list
    shows the commit of the device on top of the commit of Newton.  The
    abort cannot tell that the commit of Newton was rolled back, so it
    says that it does not know: the result is unknown and never
    rolled_back.
    """
    device = FakeJunos(ping_output=PING_LOST, timer_fires_before_ping=True)
    outcome = vc.apply_plan(
        jw.JunosOps(),
        device,
        _plan(),
        [["ping", "192.0.2.1"]],
    )

    assert outcome.result == "unknown"
    assert outcome.log == "the rollback state is unknown"
    assert outcome.failed_probe == ["ping", "192.0.2.1"]
    assert outcome.saved is None


def test_the_index_of_a_pre_candidate_error_is_pinned() -> None:
    """The index of a pre-candidate error is the last statement.

    An error that happens before the candidate is read is not in a
    statement, so the report names the number of the statements of the
    change.  The number is pinned here: a report that named another
    index would tell the owner something else about the change.
    """
    statements = jw.parse_lines(f"{CHANGE_TEXT}\n{SECOND_TEXT}")
    staged = jw.parse_stage(JUNOS_STAGE_PRE_CANDIDATE_ERROR, statements)

    assert staged.ok is False
    assert staged.bad_line == 2


def test_the_commit_list_of_a_device_is_read_before_the_abort() -> None:
    """The abort reads the commit list of the device first.

    The commit list is what the abort decides on, so it is read in a
    session of its own before anything is rolled back.
    """
    device = FakeJunos()
    device.set_commits([_tagged_commit(), FakeCommit(who="root")])

    jw.JunosOps().abort(device)

    assert device.cli_scripts[0] == PENDING_READ_SCRIPT


#
# 1. A lint with a deny list: Junos takes a hierarchy in an abbreviated
#    form ("sys host-name") and in any case ("System host-name"), so the
#    allow list and the corpus refuse both.
# 2. A lint that lets ";" through: the corpus refuses the injection line
#    and the raw-text rule refuses the character.
# 3. A stage that does not throw the candidate away: the pinned script
#    carries "rollback 0" before the "exit", and the fake is
#    read back after the stage: the running configuration did
#    not move.
# 4. An error detection that only looks at the exit status: the exit
#    status of a Junos session says nothing, so the corpus of the
#    output refuses a statement that printed "syntax error.",
#    an "error:", a "warning:", an "unknown command" or a "missing
#    argument".
# 5. An apply that commits without staging again: the re-stage comes
#    first and a refused line sends no apply session at all
#   , so nothing is committed and nothing is armed.
# 6. A commit that is read from "commit complete" alone: the notice of
#    the armed revert counts too, so a session that did not
#    arm the revert is not a commit.
# 7. A driver that confirms a commit that is not the candidate: the
#    candidate hash is compared with the configuration that comes back
#   , and a partial commit is rolled back.
# 8. A transport that runs the script in the login shell of a device
#    whose shell is not the CLI: the empty remote is refused for every
#    platform but the ones whose login shell is the CLI
#    (see test_vendor_ssh.py).
