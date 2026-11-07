"""The RouterOS CHR lint, the pinned command texts and the CHR ops.

The module under test is ``newton_mcp.adapters.routeros_write``: the lint and
tokenizer for the platform "routeros", the command texts the driver sends to
RouterOS 7.24.5 and ``RouterosOps``, the operations that implement the
generic ``vendor_change.VendorOps`` protocol for a RouterOS CHR.

No device is contacted.  Every session in this file is answered by a fake
that records what the ops asked the device to do, and every command text is
pinned exactly, the way the VyOS texts are pinned in ``test_vendor_write``.

The revert of a CHR is not native: the driver arms a backup plus a scheduler
entry that loads the backup when it fires, so the ops here build those two
objects and never confirm anything before the receipt was read back.


"""

from __future__ import annotations

import hashlib
import inspect
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any, NamedTuple

import pytest

from newton_mcp import vendor_change as vc
from newton_mcp.adapters import routeros_write as rw
from newton_mcp.adapters import vendor_write as vw


# ---- the texts the driver sends, pinned exactly ------------------------------
#
# The arm text is the one that worked on RouterOS 7.24.5 (measure/tr/
# chr-confirm.txt), with the fixed name newton-revert in place of the
# measured name.  The backup save needs password="" and the on-event needs
# the escaped quotes, or the load inside the scheduler errors and nothing
# ever reverts (measured).

ARM_120 = (
    r':local t ([/system clock get time] + 00:02:00); '
    r'/system backup save name=newton-revert password=""; '
    r'/system scheduler add name=newton-revert start-time=$t interval=0 '
    r'on-event="/system backup load name=newton-revert password=\"\""; '
    r':put "armed for $t"'
)

REFRESH_120 = (
    r':local t ([/system clock get time] + 00:02:00); '
    r'/system scheduler set newton-revert start-time=$t'
)

RECEIPT_FILE = '/file print count-only where name="newton-revert.backup"'
RECEIPT_SCHEDULER = "/system scheduler print detail where name=newton-revert"
CLOCK = "/system clock print"

CONFIRM_SCHEDULER = "/system scheduler remove newton-revert"
CONFIRM_FILE = "/file remove newton-revert.backup"

LOAD = r'/system backup load name=newton-revert password=""'

EXPORT = "/export"
SCHEDULER_COUNT = "/system scheduler print count-only where name=newton-revert"
BACKUP_COUNT = '/file print count-only where name="newton-revert.backup"'
# The uptime is asked with a ":put": a bare "get" prints nothing over an
# ssh exec (measured on the live CHR, chr-05.log, sessions 19 and 21).
UPTIME = ":put [/system resource get uptime]"

# The device output of the measured receipt (measure/tr/chr-confirm.txt).
SCHEDULER_DETAIL = "\n".join(
    [
        '0  name="newton-revert" start-date=2026-10-23 start-time=23:31:23 '
        "interval=0s",
        '   on-event=/system backup load name=newton-revert password="" '
        'owner="newton"',
        "   policy=ftp,reboot,read,write,policy,test,password,sensitive "
        "run-count=0",
        "   next-run=2026-10-23 23:31:23",
    ]
)

# The clock of the device, as "/system clock print" prints it.  The entry
# above fires two minutes later, so the receipt is a current one.
CLOCK_OUTPUT = "time: 23:29:23\ndate: oct/23/2026\n"

# The measured ping summary of RouterOS.
PING_OK = (
    "  SEQ HOST                                     SIZE TTL TIME  STATUS\n"
    "    0 192.0.2.1                                  56  64 0ms\n"
    "    1 192.0.2.1                                  56  64 0ms\n"
    "    2 192.0.2.1                                  56  64 0ms\n"
    "    sent=3 received=3 packet-loss=0% min-rtt=0ms avg-rtt=0ms max-rtt=0ms"
)
PING_LOST = (
    "  SEQ HOST                                     SIZE TTL TIME  STATUS\n"
    "    sent=3 received=0 packet-loss=100% min-rtt=0ms avg-rtt=0ms max-rtt=0ms"
)

# The export of a CHR: the header carries a timestamp, so the hash of the
# configuration ignores every line that starts with a hash.
EXPORT_TEXT = "\n".join(
    [
        "# 2026-10-24 10:00:00 by RouterOS 7.24.5",
        "# software id = ABCD-1234",
        "",
        "/interface bridge",
        "add name=bridge",
        "/ip address",
        "add address=192.0.2.1/24 interface=bridge network=192.0.2.0",
        "/system identity",
        "set name=chr-baseline",
    ]
)

# The statements of the change: a menu path, a verb and key=value params.
STATEMENTS = [
    "/system identity set name=p11-chr",
    "/ip/address add address=198.51.100.7/24 interface=bridge",
]

# The text the device prints when it accepted the load of the backup.
LOAD_ACCEPTED = "System configuration restored, rebooting now"

# The uptime of the device, in the form RouterOS prints it (measured,
# measure/tr/chr-abort.txt: "00:00:23" right after the reboot).
UPTIME_FRESH = "00:00:23"
# The uptime of a device that has been up for hours (measured, same file).
UPTIME_OLD = "05:50:42"

# CS-04: the corpus.  Every hostile line must be refused and every benign
# line must be accepted.
HOSTILE_LINES = (
    # the refused menus
    "/system/reset-configuration set mode=reset",
    "/system/reboot add name=x",
    "/system/shutdown add name=x",
    "/system/script add name=x",
    "/system/scheduler add name=x",
    "/system/backup save name=x",
    "/system/package update installed=yes",
    "/system/logging/action set disabled=no",
    "/import file=x",
    "/file remove name=x",
    "/tool/fetch url=x",
    "/tool/ping address=192.0.2.1",
    "/user/add name=x",
    "/user/group/add name=x",
    "/ip/service set port=2222",
    "/ip/ssh set strong-crypto=no",
    "/certificate/add name=x",
    "/interface/wireless/enable numbers=1",
    "/export file=x",
    # the clock and the NTP client: the start time of the revert is a
    # time of the device clock, so a clock change moves the revert
    "/system/clock set time-zone-name=UTC",
    "/system/clock set date=jan/01/2026",
    "/system/ntp/client set enabled=yes",
    "/system/ntp/client set servers=192.0.2.1",
    # the menus that are not on the allow list
    "/ppp/secret add name=x password=y",
    "/ppp/secret set password=y",
    "/snmp/community add name=x",
    "/snmp/community set name=x",
    "/system/watchdog set watch-timeout=yes",
    "/queue/simple add name=x target=192.0.2.0/24",
    "/routing/filter add chain=lab rule=accept",
    "/ip/service set port=2222",
    # the case variants: RouterOS menus are case-insensitive
    "/SYSTEM/SCHEDULER add name=x",
    "/System/Scheduler add name=x",
    "/SYSTEM REBOOT add name=x",
    "/IP/ADDRESS add address=192.0.2.1/24",
    "/System/Identity set name=p11-chr",
    # the shortest unique abbreviations: RouterOS accepts them
    "/system sch add name=x",
    "/sys sch add name=x",
    "/tool f url=x",
    "/user g add name=x",
    "/int br add name=x",
    "/ip dh add address=192.0.2.1/24",
    "/sys id set name=p11-chr",
    # the refused verbs
    "/ip/address print count-only",
    "/ip/address get address=192.0.2.1",
    "/ip/address run script=x",
    "/ip/address monitor",
    "/system/identity",
    # the raw text rules
    "/ip/address add address=192.0.2.1; /system reboot",
    "/ip/address add address=192.0.2.1 | tee",
    "/ip/address add address=$(id)",
    "/ip/address add address=`id`",
    "/ip/address add address=[192.0.2.1]",
    "/ip/address add address={192.0.2.1}",
    "/ip/address add address=<192.0.2.1>",
    "/ip/address add address=(192.0.2.1)",
    "/ip/address add address=!192.0.2.1",
    "/ip/address add address=192.0.2.1?",
    '/ip/address add address="192.0.2.1"',
    "/ip/address add address=192.0.2.1\\24",
    "/ip/address add address=192.0.2.1\ty",
    "/ip/address add address=192.0.2.1\ry",
    "/ip/address add address=192.0.2.1\x1by",
    "/ip/address add address=192.0.2.1\x00y",
    "/ip/address add address=192.0.2.1é",
    "# a comment with a semicolon; inside",
    "/ip/address add address=192.0.2.1/24 name=a*b",
    # the reserved names and the marker text
    "/ip/address add address=192.0.2.1/24 name=newton-lab",
    "/ip/address add address=192.0.2.1/24 comment=NEWTON-COMMITTED rc=0",
    "/ip/address add address=192.0.2.1/24 comment=NEWTON-LINE-ERROR",
    # the grammar
    "/ip/address add address=",
    "/ip/address add address=''",
    "/ip/address add address='unterminated",
    "/ip/address add address=192.0.2.1/24 extra",
    "/ip/address remove",
    "/ip/address remove numbers=1,2",
    "/ip/address remove numbers=abc",
    "ip/address add address=192.0.2.1/24",
    "/ip/address add address=192.0.2.1/24 name=",
)

BENIGN_LINES = (
    "/system/identity set name=p11-chr",
    "/ip/address add address=192.0.2.1/24 interface=ether1",
    "/ip/address remove numbers=1",
    "/interface/ethernet disable numbers=2",
    "/interface/ethernet enable numbers=*2",
    "/ip/dns set servers=192.0.2.53",
    "/ip/firewall/filter add chain=forward action=accept",
    "/ip/firewall/address-list add list=lab address=192.0.2.7",
    "/ip/pool add name=lab-pool ranges=192.0.2.0/24",
    "/ip/address set comment='lab uplink' numbers=1",
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


class LoadOutcome(NamedTuple):
    """What one load of the backup did on the device.

    ``reboots`` says whether the device rebooted into the backup: a load
    whose session dropped still reboots the device, and the proof of the
    load is the reboot, not the session.
    """

    status: str = "ok"
    exit_code: int | None = 0
    stdout: str = LOAD_ACCEPTED
    reboots: bool = True


class FakeChr:
    """A scripted RouterOS CHR that records every fresh session.

    The fake answers the commands the ops sends: the export, the two
    counts, the arm, the receipt, the refresh, the statements, the confirm
    removes, the load and the ping.  Every state the ops can see (the
    scheduler entry, the backup file, the configuration) is a field, so a
    test can take the device into the state it wants.
    """

    def __init__(
        self,
        *,
        config: str = EXPORT_TEXT,
        arm_ok: bool = True,
        arm_output: str = "Configuration backup saved\narmed for 23:31:23",
        arm_status: str = "ok",
        arm_exit_code: int | None = 0,
        backup_count: str | None = None,
        receipt_detail: str = SCHEDULER_DETAIL,
        scheduler_present: bool = False,
        backup_present: bool = False,
        statement_outputs: Mapping[str, vc.RunOut] | None = None,
        load_output: str = LOAD_ACCEPTED,
        load_status: str = "ok",
        load_exit_code: int | None = 0,
        load_reboots: bool | None = None,
        load_outcomes: Sequence[LoadOutcome] = (),
        ping_output: str = PING_OK,
        uptime_output: str = UPTIME_FRESH,
        clock_output: str = CLOCK_OUTPUT,
        unreachable: Sequence[str] = (),
    ) -> None:
        self.config = config
        self.initial_config = config
        self.arm_ok = arm_ok
        self.arm_output = arm_output
        self.arm_status = arm_status
        self.arm_exit_code = arm_exit_code
        self.backup_count = backup_count
        self.receipt_detail = receipt_detail
        self.scheduler_present = scheduler_present
        self.backup_present = backup_present
        self.statement_outputs = dict(statement_outputs or {})
        self.load_output = load_output
        self.load_status = load_status
        self.load_exit_code = load_exit_code
        self.load_reboots = load_reboots
        self.load_outcomes = tuple(load_outcomes)
        self.ping_output = ping_output
        self.uptime_output = uptime_output
        self.clock_output = clock_output
        self.unreachable = tuple(unreachable)
        self.calls: list[vw.SessionSpec] = []
        self.outputs: list[vc.RunOut] = []
        self.loaded = False
        self.loads = 0

    @property
    def remotes(self) -> list[str]:
        return [spec.remote for spec in self.calls]

    def __call__(self, spec: vw.SessionSpec) -> vc.RunOut:
        self.calls.append(spec)
        output = self._answer(spec)
        self.outputs.append(output)
        return output

    def _load_outcome(self) -> LoadOutcome:
        """The outcome of the load that is being sent now."""
        if self.load_outcomes:
            index = min(self.loads, len(self.load_outcomes) - 1)
            return self.load_outcomes[index]
        accepted = self.load_status == "ok" and self.load_exit_code in (0, None)
        return LoadOutcome(
            status=self.load_status,
            exit_code=self.load_exit_code,
            stdout=self.load_output,
            reboots=accepted if self.load_reboots is None else self.load_reboots,
        )

    def _answer(self, spec: vw.SessionSpec) -> vc.RunOut:
        remote = spec.remote
        if remote in self.unreachable:
            return _out("", exit_code=255, status="unreachable")
        if remote == rw.export_command().remote:
            return _out(self.config)
        if remote == rw.scheduler_count_command().remote:
            return _out("1" if self.scheduler_present else "0")
        if remote == rw.backup_count_command().remote:
            if self.backup_count is not None:
                return _out(self.backup_count)
            return _out("1" if self.backup_present else "0")
        if remote == rw.scheduler_detail_command().remote:
            return _out(self.receipt_detail)
        if remote == rw.scheduler_remove_command().remote:
            self.scheduler_present = False
            return _out("")
        if remote == rw.backup_remove_command().remote:
            self.backup_present = False
            return _out("")
        if remote == rw.load_command().remote:
            self.loaded = True
            outcome = self._load_outcome()
            self.loads += 1
            if outcome.reboots:
                self.scheduler_present = False
                self.backup_present = False
                self.config = self.initial_config
            return _out(
                outcome.stdout,
                exit_code=outcome.exit_code,
                status=outcome.status,
            )
        if remote == rw.uptime_command().remote:
            return _out(self.uptime_output)
        if remote == rw.clock_command().remote:
            return _out(self.clock_output)
        if remote.startswith(":put "):
            return _out(remote[6:-1])
        if remote.startswith(":local t ("):
            if "/system scheduler add" in remote:
                if not self.arm_ok:
                    return _out("bad command name add", exit_code=1)
                output = _out(
                    self.arm_output,
                    exit_code=self.arm_exit_code,
                    status=self.arm_status,
                )
                if (
                    output.status == "ok"
                    and output.exit_code in (0, None)
                    and "failure:" not in self.arm_output
                ):
                    self.scheduler_present = True
                    self.backup_present = True
                return output
            if "/system scheduler set" in remote:
                if not self.scheduler_present:
                    return _out("no such item (4)", exit_code=1)
                return _out("")
            raise AssertionError(f"unknown session: {remote!r}")
        if remote.startswith("/ping "):
            return _out(self.ping_output)
        scripted = self.statement_outputs.get(remote)
        if scripted is not None:
            return scripted
        return _out("")


# ---- the lint ---------------------------------------------------------------


def test_the_corpus_refuses_every_hostile_line() -> None:
    """CS-04, the hostile half: every hostile line is refused."""
    assert len(HOSTILE_LINES) >= 40
    for line in HOSTILE_LINES:
        with pytest.raises(rw.LintError):
            rw.parse_lines(line)


def test_the_corpus_accepts_every_benign_line() -> None:
    """CS-04, the benign half: every benign line is accepted."""
    assert len(BENIGN_LINES) >= 10
    for line in BENIGN_LINES:
        parsed = rw.parse_lines(line)
        assert len(parsed) == 1, line


def test_the_statements_parse_into_tokens() -> None:
    """A statement is a menu path, a verb and key=value params."""
    parsed = rw.parse_lines("\n".join(STATEMENTS))
    assert parsed == [
        ["/system", "identity", "set", "name=p11-chr"],
        ["/ip", "address", "add", "address=198.51.100.7/24", "interface=bridge"],
    ]


def test_the_slash_form_and_the_space_form_are_the_same_menu() -> None:
    """"/ip/address" and "/ip address" are the same menu path."""
    slash = rw.parse_lines("/ip/address remove numbers=1")
    space = rw.parse_lines("/ip address remove numbers=1")
    assert slash == space
    assert rw.command_text(slash[0]) == rw.command_text(space[0])
    assert rw.command_text(slash[0]) == "/ip address remove numbers=1"


def test_only_the_five_verbs_are_allowed() -> None:
    """A verb outside the five is refused and the verb is named."""
    for verb in ("print", "export", "import", "run", "get", "monitor", "unset"):
        with pytest.raises(rw.LintError) as excinfo:
            rw.parse_lines(f"/ip/address {verb} numbers=1")
        assert verb in str(excinfo.value)


def test_the_refused_menus_are_refused_after_normalising() -> None:
    """The refused menu is refused in the space form too."""
    refused = (
        ("/system/reset-configuration", "set mode=reset"),
        ("/system/reboot", "add name=x"),
        ("/system/shutdown", "add name=x"),
        ("/system/script", "add name=x"),
        ("/system/scheduler", "add name=x"),
        ("/system/backup", "save name=x"),
        ("/system/package", "update"),
        ("/system/logging/action", "set disabled=no"),
        ("/import", "file=x"),
        ("/file", "remove name=x"),
        ("/tool/fetch", "url=x"),
        ("/tool", "ping address=192.0.2.1"),
        ("/user", "add name=x"),
        ("/ip/service", "set port=2222"),
        ("/ip/ssh", "set strong-crypto=no"),
        ("/certificate", "add name=x"),
        ("/interface/wireless", "enable numbers=1"),
    )
    for path, tail in refused:
        for text in (f"{path} {tail}", f"{path.replace('/', ' ', 1)} {tail}"):
            with pytest.raises(rw.LintError):
                rw.parse_lines(text)


def test_the_system_identity_menu_is_allowed() -> None:
    """/system/identity is not a refused menu."""
    parsed = rw.parse_lines("/system identity set name=p11-chr")
    assert parsed == [["/system", "identity", "set", "name=p11-chr"]]
    assert rw.command_text(parsed[0]) == "/system identity set name=p11-chr"


@pytest.mark.parametrize(
    "char",
    (
        ";",
        "|",
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
    with pytest.raises(rw.LintError):
        rw.parse_lines(f"/ip/address add address=192.0.2.1{char}tail")


@pytest.mark.parametrize("char", ("\t", "\r", "\x00", "\x1b", "\x7f"))
def test_every_control_character_is_refused(char: str) -> None:
    """Tab, CR, NUL, ESC and DEL are refused."""
    with pytest.raises(rw.LintError):
        rw.parse_lines(f"/ip/address add address=192.0.2.1{char}tail")


def test_a_non_ascii_character_is_refused() -> None:
    """The change text is ascii only."""
    with pytest.raises(rw.LintError):
        rw.parse_lines("/ip/address add address=192.0.2.1/24 comment=café")


def test_a_long_line_and_too_many_statements_are_refused() -> None:
    """401 characters and 201 statements are refused."""
    long_line = "/ip/address add address=192.0.2.1/24 comment=" + "a" * 380
    assert len(long_line) > 400
    with pytest.raises(rw.LintError):
        rw.parse_lines(long_line)
    body = "\n".join(
        f"/ip/address add address=192.0.2.{index}/24" for index in range(200)
    )
    assert len(rw.parse_lines(body)) == 200
    with pytest.raises(rw.LintError):
        rw.parse_lines(body + "\n/ip/address add address=192.0.2.200/24")


def test_the_reserved_names_are_refused() -> None:
    """NEWTON- and a name that starts with newton- are refused."""
    with pytest.raises(rw.LintError):
        rw.parse_lines("/ip/address add address=192.0.2.1/24 name=newton-lab")
    with pytest.raises(rw.LintError) as excinfo:
        rw.parse_lines("/ip/address add address=192.0.2.1/24 comment=NEWTON-X")
    assert str(excinfo.value) == "reserved marker text"
    with pytest.raises(rw.LintError) as excinfo:
        rw.parse_lines("/ip/address add address=192.0.2.1/24 name=newton-lab")
    assert str(excinfo.value) == "reserved name"


def test_the_numbers_value_selects_one_item() -> None:
    """Numbers is digits or a star and hex, and the star is only there."""
    assert rw.parse_lines("/ip/address remove numbers=12")
    assert rw.parse_lines("/ip/address remove numbers=*1F")
    with pytest.raises(rw.LintError):
        rw.parse_lines("/ip/address remove numbers=abc")
    with pytest.raises(rw.LintError):
        rw.parse_lines("/ip/address remove numbers=1,2")
    with pytest.raises(rw.LintError):
        rw.parse_lines("/ip/address add address=192.0.2.1/24 name=a*b")


def test_an_empty_value_is_refused() -> None:
    """A value may not be empty, not bare and not quoted."""
    with pytest.raises(rw.LintError):
        rw.parse_lines("/ip/address add address=")
    with pytest.raises(rw.LintError):
        rw.parse_lines("/ip/address add address=''")


def test_a_statement_needs_a_path_a_verb_and_params() -> None:
    """The grammar is a path, a verb and at least one param."""
    with pytest.raises(rw.LintError):
        rw.parse_lines("ip/address add address=192.0.2.1/24")
    with pytest.raises(rw.LintError):
        rw.parse_lines("/ip/address address=192.0.2.1/24")
    with pytest.raises(rw.LintError):
        rw.parse_lines("/ip/address remove")


def test_the_owner_text_keeps_the_single_quotes() -> None:
    """The owner text is what the agent wrote, and it parses again."""
    parsed = rw.parse_lines("/ip/address set comment='lab uplink' numbers=1")
    assert rw.render_line(parsed[0]) == (
        "/ip address set comment='lab uplink' numbers=1"
    )
    assert rw.parse_lines(rw.render_line(parsed[0])) == parsed


def test_the_device_text_quotes_a_value_with_spaces() -> None:
    """The driver renders a value with spaces in double quotes."""
    parsed = rw.parse_lines("/ip/address set comment='lab uplink' numbers=1")
    assert rw.command_text(parsed[0]) == (
        '/ip address set comment="lab uplink" numbers=1'
    )


def test_the_lint_message_never_echoes_the_agent_text() -> None:
    """A lint message is a short reason, never the whole line."""
    long_word = "p" * 300
    cases = (
        f"/ip/address {long_word} numbers=1",
        f"/ip/address add address=192.0.2.1{';' * 300}",
        "/system/scheduler add name=x",
    )
    for line in cases:
        with pytest.raises(rw.LintError) as excinfo:
            rw.parse_lines(line)
        message = str(excinfo.value)
        assert len(message) <= 120, line[:40]
        assert long_word not in message


# ---- the pinned command texts ----------------------------------------------


def test_the_arm_text_is_the_measured_text() -> None:
    """The arm is the measured text with the fixed name."""
    spec = rw.arm_command(120)
    assert spec.remote == ARM_120
    assert spec.stdin == ""
    assert rw.arm_command(150).remote == ARM_120.replace(
        "00:02:00", "00:02:30"
    )
    assert rw.arm_command(60).remote == ARM_120


def test_the_receipt_texts_are_pinned() -> None:
    """The receipt reads the backup file and the scheduler detail."""
    assert rw.backup_count_command().remote == RECEIPT_FILE
    assert rw.scheduler_detail_command().remote == RECEIPT_SCHEDULER
    assert rw.backup_count_command().stdin == ""
    assert rw.scheduler_detail_command().stdin == ""


def test_the_refresh_text_sets_the_start_time_in_place() -> None:
    """The refresh is a set, never a remove and an add."""
    spec = rw.refresh_command(120)
    assert spec.remote == REFRESH_120
    assert "/system scheduler set" in spec.remote
    assert "/system scheduler add" not in spec.remote
    assert "/system scheduler remove" not in spec.remote


def test_the_confirm_removes_the_scheduler_and_the_file() -> None:
    """The confirm is two sessions, the scheduler first."""
    assert rw.scheduler_remove_command().remote == CONFIRM_SCHEDULER
    assert rw.backup_remove_command().remote == CONFIRM_FILE


def test_the_load_text_carries_the_password() -> None:
    """The load needs password="" or it errors and nothing reverts."""
    assert rw.load_command().remote == LOAD
    assert 'password=""' in rw.load_command().remote


def test_the_ping_text_is_pinned() -> None:
    """The ping asks for three packets from the named address."""
    assert rw.ping_command("192.0.2.1").remote == (
        "/ping count=3 address=192.0.2.1"
    )
    assert rw.ping_command("192.0.2.1").stdin == ""


def test_the_ping_host_is_bounded() -> None:
    """The ping target is bounded before it reaches a remote string."""
    for host in ("-oProxyCommand=id", "host name", "", "a" * 254, "host; reboot"):
        with pytest.raises(rw.LintError):
            rw.ping_command(host)


# ---- the ops ----------------------------------------------------------------


def test_the_snapshot_hashes_the_export_without_the_header() -> None:
    """The hash ignores the '#' lines, so a timestamp is no change."""
    device = FakeChr(config=EXPORT_TEXT)
    snapshot = rw.RouterosOps().snapshot(device)

    assert snapshot.text == EXPORT_TEXT
    assert snapshot.base_hash == rw.config_hash(EXPORT_TEXT)
    assert snapshot.reload_ok is True
    assert snapshot.saved_clean is True
    assert snapshot.pending == "idle"

    later = FakeChr(
        config=EXPORT_TEXT.replace("2026-10-24 10:00:00", "2026-10-25 11:00:00")
    )
    assert rw.RouterosOps().snapshot(later).base_hash == snapshot.base_hash


def test_a_pending_revert_makes_the_snapshot_pending() -> None:
    """A scheduler or a backup file that is there is a pending revert."""
    scheduled = FakeChr(scheduler_present=True, backup_present=True)
    assert rw.RouterosOps().snapshot(scheduled).pending == "pending"
    leftover = FakeChr(scheduler_present=False, backup_present=True)
    assert rw.RouterosOps().snapshot(leftover).pending == "pending"


def test_the_stage_is_the_rendered_lines_and_no_session() -> None:
    """A CHR has no candidate, so the diff is the lines themselves."""
    device = FakeChr()
    statements = rw.parse_lines("\n".join(STATEMENTS))
    staged = rw.RouterosOps().stage(device, statements)

    assert staged.ok is True
    assert staged.bad_line is None
    assert staged.diff == "\n".join(rw.render_line(s) for s in statements)
    assert device.calls == []


def test_the_apply_arms_and_reads_the_receipt_before_the_lines() -> None:
    """The arm, the receipt, then every statement in its own session."""
    device = FakeChr()
    statements = rw.parse_lines("\n".join(STATEMENTS))
    result = rw.RouterosOps().apply(device, statements, 120)

    assert result == "committed"
    remotes = device.remotes
    assert remotes[0] == ARM_120
    assert RECEIPT_FILE in remotes
    assert RECEIPT_SCHEDULER in remotes
    assert "/system identity set name=p11-chr" in remotes
    assert "/ip address add address=198.51.100.7/24 interface=bridge" in remotes
    # the receipt is read before the first statement is sent
    assert remotes.index(RECEIPT_SCHEDULER) < remotes.index(
        "/system identity set name=p11-chr"
    )
    # the scheduler is re-checked and refreshed before every statement
    for statement in (
        "/system identity set name=p11-chr",
        "/ip address add address=198.51.100.7/24 interface=bridge",
    ):
        index = remotes.index(statement)
        assert remotes[index - 1] == REFRESH_120
        assert remotes[index - 2] == SCHEDULER_COUNT


def test_a_missing_receipt_sends_no_change_line() -> None:
    """No receipt, no change line: the arm is cleaned up instead."""
    device = FakeChr(backup_count="0")
    statements = rw.parse_lines("\n".join(STATEMENTS))
    result = rw.RouterosOps().apply(device, statements, 120)

    assert result == "armed_failed"
    assert "/system identity set name=p11-chr" not in device.remotes
    assert CONFIRM_SCHEDULER in device.remotes
    assert CONFIRM_FILE in device.remotes
    assert device.scheduler_present is False
    assert device.backup_present is False


def test_a_malformed_receipt_sends_no_change_line() -> None:
    """A receipt without the on-event or the next-run is no receipt."""
    for detail in (
        '0  name="newton-revert" start-date=2026-10-23 start-time=23:31:23',
        '   on-event=/system backup load name=newton-revert password=""',
        "   next-run=2026-10-23 23:31:23",
    ):
        device = FakeChr(receipt_detail=detail)
        statements = rw.parse_lines("\n".join(STATEMENTS))
        result = rw.RouterosOps().apply(device, statements, 120)

        assert result == "armed_failed", detail
        assert "/system identity set name=p11-chr" not in device.remotes


def test_a_scheduler_that_vanished_stops_the_next_statement() -> None:
    """A scheduler that fired is a dead revert, so nothing is sent."""
    device = FakeChr()
    statements = rw.parse_lines("\n".join(STATEMENTS))
    checks = 0

    def fake(spec: vw.SessionSpec) -> vc.RunOut:
        nonlocal checks
        if spec.remote == rw.scheduler_count_command().remote:
            checks += 1
            # the scheduler is there for the arm, gone before the second line
            if checks >= 2:
                device.scheduler_present = False
                return _out("0")
        return device(spec)

    result = rw.RouterosOps().apply(fake, statements, 120)

    # the first statement ran, so this is not an "armed_failed": the driver
    # has to take the recover path for it.
    assert result == "revert_lost"
    assert "/system identity set name=p11-chr" in device.remotes
    assert "/ip address add address=198.51.100.7/24 interface=bridge" not in (
        device.remotes
    )


def test_a_line_error_prints_the_marker_and_aborts() -> None:
    """A bad line is a line error, and the revert is loaded first."""
    bad = "/ip address add address=198.51.100.7/24 interface=bridge"
    device = FakeChr(
        statement_outputs={
            bad: _out(
                "invalid value for argument address (/ip/address/add; line 1)",
                exit_code=1,
            )
        }
    )
    statements = rw.parse_lines("\n".join(STATEMENTS))
    result = rw.RouterosOps().apply(device, statements, 120)

    assert result == "line_error"
    remotes = device.remotes
    assert bad in remotes
    assert ':put "NEWTON-LINE-ERROR 2"' in remotes
    # the load comes before the scheduler is removed
    assert remotes.index(LOAD) < remotes.index(CONFIRM_SCHEDULER)
    assert remotes.index(CONFIRM_SCHEDULER) < remotes.index(CONFIRM_FILE)


def test_the_line_error_marker_is_read_by_the_driver() -> None:
    """The marker is the one the driver reads, so it names the line."""
    bad = "/ip address add address=198.51.100.7/24 interface=bridge"
    device = FakeChr(
        statement_outputs={bad: _out("bad command name bridge", exit_code=1)}
    )
    statements = rw.parse_lines("\n".join(STATEMENTS))
    rw.RouterosOps().apply(device, statements, 120)

    marker = ':put "NEWTON-LINE-ERROR 2"'
    index = device.remotes.index(marker)
    assert vc._line_error([device.outputs[index]]) == 2


def test_the_abort_loads_the_backup_before_it_removes_anything() -> None:
    """The load is first, so a failed load keeps the backstop."""
    device = FakeChr(scheduler_present=True, backup_present=True)
    assert rw.RouterosOps().abort(device) is True

    remotes = device.remotes
    assert remotes.index(LOAD) < remotes.index(CONFIRM_SCHEDULER)
    assert remotes.index(CONFIRM_SCHEDULER) < remotes.index(CONFIRM_FILE)
    # the device reboots into the backup: the leftovers are removed only
    # after the device answered that it is back.
    assert remotes.index(LOAD) < remotes.index(UPTIME)
    assert remotes.index(UPTIME) < remotes.index(CONFIRM_SCHEDULER)
    assert device.scheduler_present is False
    assert device.backup_present is False


def test_the_abort_accepts_a_session_that_dropped_after_the_load() -> None:
    """The device reboots and the session drops: that is the load."""
    device = FakeChr(
        scheduler_present=True,
        backup_present=True,
        load_output="",
        load_status="unreachable",
        load_exit_code=255,
        load_reboots=True,
    )
    assert rw.RouterosOps().abort(device) is True
    assert device.loaded is True
    # the drop is not a proof on its own: the device is asked again, and
    # the reboot is what proves the load.
    assert rw.uptime_command().remote in device.remotes
    assert device.scheduler_present is False
    assert device.backup_present is False


def test_a_failed_load_keeps_the_scheduler_as_the_backstop() -> None:
    """A load that was refused leaves the scheduler in place."""
    device = FakeChr(
        scheduler_present=True,
        backup_present=True,
        load_output="missing value(s) of argument(s) password",
        load_exit_code=1,
    )
    assert rw.RouterosOps().abort(device) is False
    assert CONFIRM_SCHEDULER not in device.remotes
    assert device.scheduler_present is True


def test_the_confirm_needs_the_read_back() -> None:
    """The confirm is true only when neither object is there."""
    device = FakeChr(scheduler_present=True, backup_present=True)
    assert rw.RouterosOps().confirm(device) is True

    class _StuckScheduler(FakeChr):
        def __call__(self, spec: vw.SessionSpec) -> vc.RunOut:
            if spec.remote == rw.scheduler_count_command().remote:
                self.calls.append(spec)
                return _out("1")
            return super().__call__(spec)

    stuck = _StuckScheduler(scheduler_present=True, backup_present=True)
    assert rw.RouterosOps().confirm(stuck) is False


def test_the_save_is_a_no_op_and_the_pending_is_read() -> None:
    """A CHR keeps its configuration, and the pending is a count."""
    device = FakeChr()
    assert rw.RouterosOps().save(device) is True
    assert device.calls == []

    assert rw.RouterosOps().pending(device) == "idle"
    scheduled = FakeChr(scheduler_present=True)
    assert rw.RouterosOps().pending(scheduled) == "pending"
    # a read that cannot reach the device is not "idle": it is unknown.
    unreachable = FakeChr(
        unreachable=(rw.scheduler_count_command().remote,)
    )
    assert rw.RouterosOps().pending(unreachable) == "unknown"


def test_the_ping_needs_one_received_packet() -> None:
    """The ping is a probe, so one received packet is enough."""
    device = FakeChr()
    assert rw.RouterosOps().probe_ping(device, "192.0.2.1") is True
    assert device.remotes[-1] == "/ping count=3 address=192.0.2.1"

    lost = FakeChr(ping_output=PING_LOST)
    assert rw.RouterosOps().probe_ping(lost, "192.0.2.1") is False


def test_has_line_never_claims_a_hit() -> None:
    """The export normalises the lines, so a config claim is refused."""
    ops = rw.RouterosOps()
    assert ops.has_line(EXPORT_TEXT, "/system identity set name=p11-chr") is False
    assert ops.has_line(EXPORT_TEXT, "set name=p11-chr") is False
    assert ops.has_line("", "") is False


def test_the_module_is_pure() -> None:
    """The module never runs a command and never touches a file."""
    source = inspect.getsource(rw)
    for needle in (
        "import subprocess",
        "shell=True",
        "os.system",
        "eval(",
        "exec(",
        "open(",
    ):
        assert needle not in source, needle


def test_the_platform_is_routeros() -> None:
    """The ops carry the platform the driver dispatches on."""
    assert rw.RouterosOps().platform == "routeros"
    assert rw.PLATFORM_ROUTEROS == "routeros"


def test_the_dispatcher_reaches_the_routeros_lint() -> None:
    """Vendor_write dispatches to the routeros lint and renderer."""
    parsed = vw.parse_lines("routeros", "/system identity set name=p11-chr")
    assert parsed == [["/system", "identity", "set", "name=p11-chr"]]
    assert vw.render_line("routeros", parsed[0]) == (
        "/system identity set name=p11-chr"
    )
    with pytest.raises(vw.LintError):
        vw.parse_lines("routeros", "/system/reboot add name=x")


def test_the_config_hash_is_stable_over_the_whitespace() -> None:
    """The hash is over the export without the trailing spaces."""
    one = "# header\n/ip address\nadd address=192.0.2.1/24   \n"
    two = "# another header\n/ip address\nadd address=192.0.2.1/24\n"
    assert rw.config_hash(one) == rw.config_hash(two)
    assert rw.config_hash(one) == hashlib.sha256(
        "/ip address\nadd address=192.0.2.1/24".encode()
    ).hexdigest()


# ---- the meta tests: the pinned texts really bite --------------------------


def _assert_same(actual: str, expected: str) -> None:
    """The pinned text is exactly the expected text."""
    assert actual == expected


PINNED_TEXTS: tuple[tuple[str, str, str], ...] = (
    ("arm", ARM_120, ARM_120),
    ("refresh", REFRESH_120, REFRESH_120),
    ("receipt file", RECEIPT_FILE, RECEIPT_FILE),
    ("receipt scheduler", RECEIPT_SCHEDULER, RECEIPT_SCHEDULER),
    ("clock", CLOCK, CLOCK),
    ("confirm scheduler", CONFIRM_SCHEDULER, CONFIRM_SCHEDULER),
    ("confirm file", CONFIRM_FILE, CONFIRM_FILE),
    ("load", LOAD, LOAD),
    ("ping", "/ping count=3 address=192.0.2.1", "/ping count=3 address=192.0.2.1"),
)

PINNED_MUTATIONS: tuple[tuple[str, str, str], ...] = (
    ("arm", ARM_120, ARM_120.replace('password=""', "password=x")),
    ("arm", ARM_120, ARM_120.replace("00:02:00", "00:01:00")),
    ("refresh", REFRESH_120, REFRESH_120.replace("set ", "add ")),
    ("receipt file", RECEIPT_FILE, RECEIPT_FILE.replace("count-only", "print")),
    (
        "receipt scheduler",
        RECEIPT_SCHEDULER,
        RECEIPT_SCHEDULER.replace("detail", "print"),
    ),
    ("clock", CLOCK, CLOCK.replace("print", "get time")),
    ("confirm scheduler", CONFIRM_SCHEDULER, CONFIRM_SCHEDULER.replace("newton-", "")),
    ("confirm file", CONFIRM_FILE, CONFIRM_FILE.replace(".backup", "")),
    ("load", LOAD, LOAD.replace('password=""', "")),
    ("ping", "/ping count=3 address=192.0.2.1", "/ping count=1 address=192.0.2.1"),
)


@pytest.mark.parametrize(("name", "actual", "expected"), PINNED_TEXTS)
def test_the_pinned_texts_are_pinned(
    name: str, actual: str, expected: str
) -> None:
    """Every text the driver sends is the pinned text."""
    _assert_same(actual, expected)


@pytest.mark.parametrize(("name", "actual", "mutated"), PINNED_MUTATIONS)
def test_the_pinned_text_check_catches_a_mutated_text(
    name: str, actual: str, mutated: str
) -> None:
    """A mutated text fails the pinned-text check.

    The check is written as a function so it can be run twice: once on the
    real text and once on a text that was changed in the way a planted
    defect would change it.  The second run must raise, or the test proves
    nothing.
    """
    _assert_same(actual, actual)
    assert mutated != actual
    with pytest.raises(AssertionError):
        _assert_same(mutated, actual)


def test_the_armed_window_is_at_least_two_minutes() -> None:
    """The window is max(timeout, 120) seconds, in HH:MM:SS."""
    assert rw.arm_command(60).remote == ARM_120
    assert rw.arm_command(120).remote == ARM_120
    assert rw.arm_command(150).remote == ARM_120.replace("00:02:00", "00:02:30")
    assert rw.arm_command(600).remote == ARM_120.replace("00:02:00", "00:10:00")


def test_the_statement_text_is_the_rendered_menu_and_params() -> None:
    """The statement the device gets is the menu, verb and params."""
    parsed = rw.parse_lines("/ip/address add address=192.0.2.1/24")
    assert rw.statement_command(parsed[0]).remote == (
        "/ip address add address=192.0.2.1/24"
    )
    assert rw.statement_command(parsed[0]).stdin == ""


def test_the_parse_of_a_rendered_line_is_the_same_statement() -> None:
    """The tokens the device gets are the tokens the lint checked."""
    for line in BENIGN_LINES:
        parsed = rw.parse_lines(line)
        assert rw.parse_lines(rw.render_line(parsed[0])) == parsed, line


# ---- the planted defects these tests catch --------------------------
#
# 1. A lint that lets ";" through: the corpus refuses the
#    injection line, and the raw-text rule refuses the character.
# 2. An arm without password="": the pinned arm text and the
#    pinned load text both carry it, and the mutation test for the load text
#    fails the check.
# 3. An abort that removes the scheduler before the load: the order check
#    puts the load first, and the backstop test keeps the backstop when the
#    load fails.
# 4. A confirm that does not read back: the read-back is what the confirm
#    checks, so a scheduler that is still there is not a confirm.
#
# The defects fixed in review:
# 5. A lint with a deny list: "/SYSTEM/SCHEDULER" and "/system sch" reach
#    the scheduler, and the allow list and
#    the corpus refuse them.
# 6. A confirm that removes the backup first: the order check
#    puts the scheduler first, and a later test shows that a swapped confirm
#    fails it.
# 7. An abort that reads a dropped session as the load: the proof
#    asks the device again and keeps the
#    backstop when the load cannot be proven.
# 8. An arm guard that looks at the status only: the arm failures
#    are refused, and no change line is sent.
# 9. A driver that aborts an armed_failed: the branch reads the
#    hash back instead of loading a backup the ops deleted.
# 10. A receipt that only looks at the words: the times are parsed
#     and a stale entry is not a receipt.
#
# The defects fixed in review:
# 11. A clock the agent may move: the clock menus are off the allow
#     list and the revert is read again after the last change
#     line (the review-fix tests).
# 12. A menu that takes any key of the grammar: the table of the
#     parameter keys refuses the key that opens a resolver (the review-fix tests).
# 13. An uptime proof with an unpinned slack: the boundary of the slack
#     is pinned and a dead revert before the first change
#     line is a lost revert and not an armed failure.
# 14. An approval note for a platform that cannot write: the note
#     belongs to the platforms that write (the review-fix tests).


# ---- review fixes ----------------------
#
# The review found a lint that a deny list cannot be safe against (RouterOS
# menus are case-insensitive and accept the shortest unique abbreviation),
# two safety orderings with no test, an abort that read a dropped session as
# a load, an arm guard with no test and a receipt that only looked at the
# words of the device output.  The tests below are the fixes.

# The menus the allow list holds: the full lowercase paths and nothing else.
ALLOWED_SAMPLES: dict[str, str] = {
    "/ip/address": "/ip/address add address=192.0.2.1/24",
    "/ip/route": "/ip/route add dst-address=192.0.2.0/24 gateway=192.0.2.254",
    "/ip/dns": "/ip/dns set servers=192.0.2.53",
    "/ip/firewall/filter": "/ip/firewall/filter add chain=forward action=accept",
    "/ip/firewall/nat": "/ip/firewall/nat add chain=srcnat action=masquerade",
    "/ip/firewall/address-list": (
        "/ip/firewall/address-list add list=lab address=192.0.2.7"
    ),
    "/ip/dhcp-server": (
        "/ip/dhcp-server add name=lab interface=bridge address-pool=lab-pool"
    ),
    "/ip/dhcp-server/network": (
        "/ip/dhcp-server/network add address=192.0.2.0/24 gateway=192.0.2.1"
    ),
    "/ip/dhcp-client": "/ip/dhcp-client add interface=ether1 disabled=no",
    "/ip/pool": "/ip/pool add name=lab-pool ranges=192.0.2.0/24",
    "/interface/ethernet": "/interface/ethernet disable numbers=1",
    "/interface/bridge": "/interface/bridge add name=bridge",
    "/interface/bridge/port": (
        "/interface/bridge/port add bridge=bridge interface=ether1"
    ),
    "/interface/vlan": "/interface/vlan add name=vlan10 interface=bridge vlan-id=10",
    "/interface/list": "/interface/list add name=lab",
    "/interface/list/member": "/interface/list/member add list=lab interface=ether1",
    "/system/identity": "/system/identity set name=p11-chr",
}


def test_every_allowed_menu_is_accepted() -> None:
    """The allow list holds the menus the agent may touch."""
    assert set(ALLOWED_SAMPLES) == set(rw.ALLOWED_MENUS)
    for menu, line in ALLOWED_SAMPLES.items():
        parsed = rw.parse_lines(line)
        assert len(parsed) == 1, line
        assert rw.render_line(parsed[0]).startswith(
            "/" + menu[1:].replace("/", " ")
        ), line


def test_every_other_menu_is_refused() -> None:
    """A menu that is not on the allow list is not allowed."""
    for line in (
        "/ppp/secret add name=x password=y",
        "/snmp/community add name=x",
        "/system/watchdog set watch-timeout=yes",
        "/queue/simple add name=x target=192.0.2.0/24",
        "/routing/filter add chain=lab rule=accept",
        "/ip/address/print add name=x",
        "/ip add address=192.0.2.1/24",
        "/interface/wireguard add name=x",
    ):
        with pytest.raises(rw.LintError) as excinfo:
            rw.parse_lines(line)
        assert str(excinfo.value) == "menu not allowed", line


def test_no_abbreviation_and_no_case_variant_gets_through() -> None:
    """RouterOS takes both, so neither may pass the lint."""
    for line in (
        "/SYSTEM/SCHEDULER add name=x",
        "/System/Identity set name=p11-chr",
        "/IP/ADDRESS add address=192.0.2.1/24",
        "/system sch add name=x",
        "/sys sch add name=x",
        "/tool f url=x",
        "/user g add name=x",
        "/int br add name=x",
        "/ip dh add address=192.0.2.1/24",
        "/sys id set name=p11-chr",
    ):
        with pytest.raises(rw.LintError):
            rw.parse_lines(line)


def test_the_menus_the_design_names_keep_their_own_reason() -> None:
    """The owner sees why a menu of the design is refused."""
    for path, tail in (
        ("/system/scheduler", "add name=x"),
        ("/system/reboot", "add name=x"),
        ("/system/backup", "remove numbers=1"),
        ("/system/reset-configuration", "set mode=reset"),
        ("/user", "add name=x"),
        ("/tool", "set name=x"),
        ("/import", "add file=x"),
        ("/file", "remove name=x"),
        ("/ip/service", "set port=2222"),
        ("/export", "add file=x"),
    ):
        with pytest.raises(rw.LintError) as excinfo:
            rw.parse_lines(f"{path} {tail}")
        assert "refused menu" in str(excinfo.value), path


def _assert_scheduler_removed_first(remotes: list[str]) -> None:
    """The confirm takes the scheduler away before the backup file."""
    assert remotes.index(CONFIRM_SCHEDULER) < remotes.index(CONFIRM_FILE)


def test_the_confirm_takes_the_scheduler_away_first() -> None:
    """The confirm removes the scheduler, then the backup file.

    The other order is unsafe: a scheduler that fires in the gap runs its
    on-event against a backup file that is already gone, so the revert
    fails silently.
    """
    device = FakeChr(scheduler_present=True, backup_present=True)
    assert rw.RouterosOps().confirm(device) is True
    _assert_scheduler_removed_first(device.remotes)


def test_a_confirm_with_the_order_swapped_fails_the_check() -> None:
    """The order check catches a confirm that is put in reverse."""
    swapped = [CONFIRM_FILE, CONFIRM_SCHEDULER]
    assert swapped != [CONFIRM_SCHEDULER, CONFIRM_FILE]
    with pytest.raises(AssertionError):
        _assert_scheduler_removed_first(swapped)


def test_a_failed_arm_sends_no_change_line() -> None:
    """The arm has to work: a failed arm changes nothing.

    The device-side objects are there in every case, so the receipt would
    be a receipt: only the arm itself says that the revert is not armed.
    """
    cases = (
        FakeChr(
            scheduler_present=True,
            backup_present=True,
            arm_exit_code=1,
            arm_output="failure: cannot save the backup",
        ),
        FakeChr(
            scheduler_present=True,
            backup_present=True,
            arm_status="unreachable",
            arm_exit_code=255,
        ),
        FakeChr(
            scheduler_present=True,
            backup_present=True,
            arm_output="failure: cannot save the backup",
        ),
    )
    statements = rw.parse_lines("\n".join(STATEMENTS))
    for device in cases:
        result = rw.RouterosOps().apply(device, statements, 120)
        assert result == "armed_failed"
        sent = [
            remote
            for remote in device.remotes
            if remote.startswith("/system identity")
            or remote.startswith("/ip address")
        ]
        assert sent == []


def test_the_load_is_accepted_only_with_the_text_of_the_device() -> None:
    """A load without the text of the device is not accepted."""
    assert rw._load_accepted(_out(LOAD_ACCEPTED)) is True
    assert rw._load_accepted(_out("", exit_code=0)) is False
    assert rw._load_accepted(_out("", status="unreachable", exit_code=255)) is False
    assert rw._load_accepted(_out(LOAD_ACCEPTED, exit_code=1)) is False


def test_a_refusal_with_an_empty_output_is_a_failure() -> None:
    """A session that ends with rc 1 and says nothing failed."""
    assert rw._is_failure(_out("", exit_code=1)) is True
    assert rw._is_failure(_out("", exit_code=0)) is False
    assert rw._is_failure(_out("failure: no such item", exit_code=0)) is True


def test_the_reserved_name_is_refused_in_any_case() -> None:
    """"Newton-lab" is the reserved name in another case."""
    for name in ("Newton-lab", "NewToN-lab", "Newton-x"):
        with pytest.raises(rw.LintError) as excinfo:
            rw.parse_lines(f"/ip/address add address=192.0.2.1/24 name={name}")
        assert str(excinfo.value) == "reserved name"
    # the marker text is refused as the marker text, in any case too.
    with pytest.raises(rw.LintError) as excinfo:
        rw.parse_lines("/ip/address add address=192.0.2.1/24 name=NEWTON-lab")
    assert str(excinfo.value) == "reserved marker text"


def test_the_receipt_needs_an_entry_that_has_not_fired() -> None:
    """The receipt is the entry of this arm, not an older one.

    An entry of an earlier run carries the same words, so the times are
    parsed: the next run of a stale entry is in the past.
    """
    stale = SCHEDULER_DETAIL.replace("23:31:23", "01:02:03")
    device = FakeChr(receipt_detail=stale)
    statements = rw.parse_lines("\n".join(STATEMENTS))

    result = rw.RouterosOps().apply(device, statements, 120)

    assert result == "armed_failed"
    assert "/system identity set name=p11-chr" not in device.remotes


def test_the_receipt_needs_a_parseable_next_run() -> None:
    """A detail without a start time and a next run is no receipt."""
    for detail in (
        '0  name="newton-revert" start-date=2026-10-23 start-time=23:31:23 '
        "interval=0s",
        '   on-event=/system backup load name=newton-revert password="" owner="x"',
        "   next-run=2026-10-23 23:31:23",
        SCHEDULER_DETAIL.replace("next-run", "next"),
        SCHEDULER_DETAIL.replace("backup load", "backup save"),
    ):
        device = FakeChr(receipt_detail=detail)
        statements = rw.parse_lines("\n".join(STATEMENTS))

        result = rw.RouterosOps().apply(device, statements, 120)

        assert result == "armed_failed", detail
        assert "/system identity set name=p11-chr" not in device.remotes


def test_the_start_time_has_to_be_the_next_run() -> None:
    """an entry that does not fire when it starts is not ours."""
    detail = SCHEDULER_DETAIL.replace("start-time=23:31:23", "start-time=01:02:03")
    device = FakeChr(receipt_detail=detail)
    statements = rw.parse_lines("\n".join(STATEMENTS))

    assert rw.RouterosOps().apply(device, statements, 120) == "armed_failed"


def test_a_device_without_a_clock_still_gives_a_receipt() -> None:
    """a device that does not say the time proves what it can.

    The file is there, the on-event is the load of that backup and the
    next run parses: that is the receipt of such a device.
    """
    device = FakeChr(clock_output="")
    statements = rw.parse_lines("\n".join(STATEMENTS))

    assert rw.RouterosOps().apply(device, statements, 120) == "committed"
    assert rw.clock_command().remote in device.remotes


def test_the_load_is_sent_again_when_it_did_not_happen() -> None:
    """A load the device denies is sent once more.

    The first load failed on the way and the device answered with the
    entry of the revert still there: the load did not happen, so it is
    sent again.
    """
    device = FakeChr(
        scheduler_present=True,
        backup_present=True,
        load_outcomes=(
            LoadOutcome(status="unreachable", exit_code=255, stdout="", reboots=False),
            LoadOutcome(),
        ),
    )

    assert rw.RouterosOps(wait=lambda seconds: None).abort(device) is True
    assert device.loads == 2
    assert device.remotes.count(LOAD) == 2


def test_the_leftovers_go_only_after_the_load_is_proven() -> None:
    """The reboot is the proof, and then the leftovers go."""
    device = FakeChr(scheduler_present=True, backup_present=True)

    assert rw.RouterosOps(wait=lambda seconds: None).abort(device) is True

    remotes = device.remotes
    assert remotes.index(LOAD) < remotes.index(CONFIRM_SCHEDULER)
    assert remotes.index(CONFIRM_SCHEDULER) < remotes.index(CONFIRM_FILE)
    assert device.scheduler_present is False
    assert device.backup_present is False


def test_a_device_that_did_not_reboot_does_not_prove_the_load() -> None:
    """the entry is gone, but the device never rebooted.

    The uptime of the device is the second half of the proof: a device
    that has been up for hours has not loaded the backup.
    """
    device = FakeChr(
        scheduler_present=True,
        backup_present=True,
        uptime_output=UPTIME_OLD,
    )

    assert rw.RouterosOps(wait=lambda seconds: None).abort(device) is False
    assert device.loads == 2


def test_a_load_that_cannot_be_proven_keeps_the_backstop() -> None:
    """The entry and the backup stay when the load did not work."""
    device = FakeChr(
        scheduler_present=True,
        backup_present=True,
        load_outcomes=(
            LoadOutcome(status="unreachable", exit_code=255, stdout="", reboots=False),
        ),
    )

    assert rw.RouterosOps(wait=lambda seconds: None).abort(device) is False

    assert device.scheduler_present is True
    assert device.backup_present is True
    assert CONFIRM_SCHEDULER not in device.remotes
    assert CONFIRM_FILE not in device.remotes


def test_a_device_that_never_answers_is_not_loaded_twice() -> None:
    """An unknown proof is not a proof: the load is not repeated."""
    device = FakeChr(
        scheduler_present=True,
        backup_present=True,
        load_outcomes=(LoadOutcome(reboots=False),),
        unreachable=(rw.uptime_command().remote,),
    )
    waits: list[float] = []

    assert rw.RouterosOps(wait=waits.append).abort(device) is False

    assert device.loads == 1
    assert waits == [5] * 30
    assert device.scheduler_present is True
    assert device.backup_present is True


def test_the_uptime_of_the_device_is_read_in_seconds() -> None:
    """The uptime is the proof that the device rebooted."""
    assert rw._parse_uptime("00:00:23") == 23
    assert rw._parse_uptime("uptime: 05:50:42") == 5 * 3600 + 50 * 60 + 42
    assert rw._parse_uptime("1d2h3m4s") == 86400 + 2 * 3600 + 3 * 60 + 4
    assert rw._parse_uptime("") is None
    assert rw._parse_uptime("no answer at all") is None


def test_a_secret_bearing_menu_line_is_refused() -> None:
    """The export hides the secrets, so the allow list matters.

    The test is a behaviour and not a reading of a docstring: a menu
    that carries a secret is refused by the lint, so a change of a secret
    never reaches the device and never has to be undone by the hash of
    the export (the export does not show a password, a passphrase, a
    pre-shared key or a community).
    """
    for line in (
        "/user add name=x password=y",
        "/user/group add name=x comment=y",
        "/ppp/secret add name=x password=y",
        "/ip/service set password=y",
        "/interface/wireless/security-profiles add name=lab wpa2-pre-shared-key=y",
        "/snmp/community set name=x community=public",
    ):
        with pytest.raises(rw.LintError):
            rw.parse_lines(line)


def test_a_dead_revert_before_the_first_line_is_a_revert_lost() -> None:
    """The entry was armed and it is gone: the revert fired.

    The entry of the revert is armed before the first change line, so an
    entry that is gone before that line is not a revert that could not be
    armed: it is a revert that fired.  The driver has to take the recover
    path and prove that the device is back at the base configuration.
    """
    device = FakeChr()
    statements = rw.parse_lines("\n".join(STATEMENTS))

    def gone_before_any(spec: vw.SessionSpec) -> vc.RunOut:
        if spec.remote == rw.scheduler_count_command().remote:
            device.scheduler_present = False
            return _out("0")
        return device(spec)

    assert rw.RouterosOps().apply(gone_before_any, statements, 120) == "revert_lost"
    assert "/system identity set name=p11-chr" not in device.remotes


def test_the_allow_list_is_not_a_prefix_match() -> None:
    """A menu under an allowed one is not allowed."""
    for line in (
        "/ip/address/print add name=x",
        "/ip/firewall add chain=input action=accept",
        "/interface/bridge/settings add name=x",
        "/system/identity/extra set name=x",
    ):
        with pytest.raises(rw.LintError) as excinfo:
            rw.parse_lines(line)
        assert str(excinfo.value) == "menu not allowed", line


# ---- the findings of the live CHR -------------------------------------
#
# The live CHR (RouterOS 7.24.5) showed three things the code did not
# know.  A bare "get" prints nothing over an ssh exec, so the uptime was
# never read, the rollback could not be proven and the file of the backup
# was left on the device.  The uptime comes in six forms and only two of
# them were read.  And a rollback that cannot be proven leaves the
# backup file of the revert on the device, which makes the state of the
# device "pending" and the driver reports the rollback as unknown.
#
# The recorded session is the lab's CHR live session; the sessions the tests
# below reproduce are 13 to 31.

# The uptime of the device, in every form RouterOS prints it.  The first
# two are the measured ones ("00:00:23" right after the reboot and
# "05:50:42" for a device that has been up for hours); the longer ones
# are the forms a device that has been up for more than a day prints.
UPTIME_FORMS = (
    ("00:00:23", 23),
    ("05:50:42", 5 * 3600 + 50 * 60 + 42),
    ("1d02:03:04", 86400 + 2 * 3600 + 3 * 60 + 4),
    ("2w1d02:03:04", 2 * 604800 + 86400 + 2 * 3600 + 3 * 60 + 4),
    ("1m23s", 60 + 23),
    ("45s", 45),
)

# The texts that are not an uptime: the device said nothing, or it said
# something else.  An uptime that is not read proves nothing.
UPTIME_NOT_UPTIME = (
    "",
    "   ",
    "no answer at all",
    "uptime:",
    "00:00:2a",
    "--",
)

# The clock of the live CHR, as "/system clock print" printed it (the
# recorded session 10).  The text is multi-line and padded, so the
# parser has to read it exactly as the device printed it.
CLOCK_LIVE = (
    "                  time: 18:33:57  \r\n"
    "                  date: 2026-10-24\r\n"
    "  time-zone-autodetect: yes       \r\n"
    "        time-zone-name: manual    \r\n"
    "            gmt-offset: +00:00    \r\n"
    "            dst-active: no        \r\n"
)

# The change the live CHR refused (the shape 05 of the vendor lab) and
# the command the device gets for it.
LIVE_CHANGE = "/ip/address add address=999.1.1.1/24 interface=ether2"
LIVE_COMMAND = "/ip address add address=999.1.1.1/24 interface=ether2"


class LiveAbortChr(FakeChr):
    """The live CHR abort, as the recorded session shows it.

    The recorded session (chr-05.log, sessions 13-31) shows this: the
    statement is refused (session 13), the marker is printed (14), the
    load is accepted (15) and the device reboots.  The three sessions of
    the proof are unreachable (16, 17 and 18), then the device answers
    again (19 to 21): the entry of the revert is gone (the load
    restored the configuration of the backup), the backup file is still
    on the device (sessions 24, 27 and 31 count one) and the uptime
    says that the device rebooted.
    """

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.after_load = 0
        self.unreachable_sessions = 0

    def _answer(self, spec: vw.SessionSpec) -> vc.RunOut:
        remote = spec.remote
        if remote == rw.load_command().remote:
            output = super()._answer(spec)
            # the load restores the configuration of the backup, not the
            # files of the device: the backup file is still there.
            self.backup_present = True
            return output
        if self.loaded and self.after_load < 3:
            # the device is rebooting: the sessions of the proof fail
            self.after_load += 1
            self.unreachable_sessions += 1
            return _out("", exit_code=255, status="unreachable")
        return super()._answer(spec)


def _live_chr() -> LiveAbortChr:
    """The live CHR with the statement the device refused."""
    return LiveAbortChr(
        statement_outputs={
            LIVE_COMMAND: _out(
                "invalid value for argument address (/ip/address/add; line 1)",
                exit_code=1,
            )
        },
    )


def test_the_uptime_is_asked_with_a_put() -> None:
    """A bare "get" prints nothing over an ssh exec.

    Measured on the live CHR (chr-05.log, sessions 19 and 21): the
    session answered with an empty stdout and the exit status 0, so the
    uptime was not there and the proof of the rollback failed.  RouterOS
    needs the ":put" to print the value of the get.
    """
    assert rw.uptime_command().remote == ":put [/system resource get uptime]"
    assert rw.uptime_command().stdin == ""


@pytest.mark.parametrize(("text", "expected"), UPTIME_FORMS)
def test_the_uptime_is_read_in_seconds(text: str, expected: int) -> None:
    """Every form the device prints is one number of seconds."""
    assert rw._parse_uptime(text) == expected


@pytest.mark.parametrize("text", UPTIME_NOT_UPTIME)
def test_an_uptime_that_is_not_there_is_not_proven(text: str) -> None:
    """A text that is not an uptime proves nothing."""
    assert rw._parse_uptime(text) is None


def test_the_clock_is_read_from_the_recorded_text() -> None:
    """The clock parser reads the text the live CHR printed.

    The recorded text is multi-line and padded, and it carries the time
    zone lines of the device: the time and the date have to be found in
    it and not in a text the test made up.
    """
    assert rw._parse_clock(CLOCK_LIVE) == datetime(2026, 10, 24, 18, 33, 57)


def test_the_abort_removes_the_backup_file_and_reads_it_back() -> None:
    """The leftover backup file goes, and the device says so.

    The live CHR kept the file of the backup after the reboot (the
    abort could not prove the load), and a file that is still there
    makes the snapshot say "pending", so the driver reports the
    rollback as unknown.  The file is removed after the proof and the
    device is read back: a removal that was not read back is not a
    removal.
    """
    device = _live_chr()

    assert rw.RouterosOps(wait=lambda _seconds: None).abort(device) is True

    assert device.backup_present is False
    remotes = device.remotes
    # the removal comes after the proof of the load
    assert remotes.index(UPTIME) < remotes.index(CONFIRM_FILE)
    # and the device is read back after the removal
    assert remotes[-2:] == [SCHEDULER_COUNT, BACKUP_COUNT]


def test_the_apply_plan_rolls_the_live_sequence_back() -> None:
    """The recorded session, through apply_plan, is a rollback.

    The whole sequence of the live CHR: the statement is refused, the
    load is accepted, the device reboots, three sessions are
    unreachable and the device answers again with the entry of the
    revert gone and the backup file still there.  The backup file goes,
    the hash of the configuration is the base hash and the driver
    reports a rollback.
    """
    device = _live_chr()
    plan = {
        "uci_batch": LIVE_CHANGE,
        "base_hash": rw.config_hash(EXPORT_TEXT),
        "timeout_s": 150,
        "probes": [],
    }

    outcome = vc.apply_plan(
        rw.RouterosOps(wait=lambda _seconds: None),
        device,
        plan,
        [],
        wait=lambda _seconds: None,
    )

    assert outcome.result == "rolled_back"
    assert outcome.failed_probe is None
    # the three sessions of the proof were unreachable, and then the
    # device answered with the uptime that proves the reboot
    assert device.unreachable_sessions == 3
    # the file of the backup is gone and the device was read back
    assert device.backup_present is False
    remotes = device.remotes
    assert remotes.index(UPTIME) < remotes.index(CONFIRM_FILE)
    assert remotes[-2:] == [SCHEDULER_COUNT, BACKUP_COUNT]


# ---- review fixes -------------
#
# The review found four things:
#
# 1. The clock of the device decides when the revert fires: the start
#    time of the scheduler entry is a time of the device clock, so a
#    clock change after the arm moves the revert by up to a day.  The
#    clock menus are off the allow list, and the revert is read again
#    after the last change line: it has to be there and its next run has
#    to be inside the window.
# 2. A menu on the allow list took any key of the grammar, so one key
#    opened a service the owner never asked for ("/ip/dns set
#    allow-remote-requests=yes" opens a resolver to the world).
# 3. The slack of the uptime proof was a number in the source and not a
#    number in a test, the test of the allow list read a docstring
#    instead of the behaviour, and an entry that vanished before the
#    first change line said "armed_failed" when the revert had fired.
# 4. approve.py told the owner that the device does not re-check the
#    approval for every platform that is not OpenWrt, including the ones
#    that cannot write at all.


def test_the_clock_and_the_ntp_client_are_refused() -> None:
    """The agent may not move the clock of the device.

    The start time of the revert is a time of the device clock, so a
    clock change after the arm moves the revert by up to a day: the
    change would be on the device with no revert behind it.  The two
    menus are off the allow list, so the corpus refuses them.
    """
    assert "/system/clock" not in rw.ALLOWED_MENUS
    assert "/system/ntp/client" not in rw.ALLOWED_MENUS
    for line in (
        "/system/clock set time-zone-name=UTC",
        "/system/clock set date=jan/01/2026",
        "/system/ntp/client set enabled=yes",
        "/system/ntp/client set servers=192.0.2.1",
    ):
        with pytest.raises(rw.LintError) as excinfo:
            rw.parse_lines(line)
        assert str(excinfo.value) == "menu not allowed", line


def test_the_revert_is_read_again_after_the_last_line() -> None:
    """The last change line is followed by a read of the revert.

    The revert is the scheduler entry, so the entry is read again once
    the change is on the device: the count says that the entry is there
    and the detail says when it fires.
    """
    device = FakeChr()
    statements = rw.parse_lines("\n".join(STATEMENTS))

    assert rw.RouterosOps().apply(device, statements, 120) == "committed"

    remotes = device.remotes
    last = remotes.index("/ip address add address=198.51.100.7/24 interface=bridge")
    assert remotes[last + 1] == SCHEDULER_COUNT
    assert remotes[last + 2] == RECEIPT_SCHEDULER
    assert remotes[last + 3] == CLOCK


def test_a_revert_that_vanished_after_the_last_line_is_lost() -> None:
    """An entry that is gone after the last line is a lost revert.

    The entry was there for the change and it is gone now, so the revert
    fired (or was removed): there is no revert left for this change and
    the driver has to take the recover path.
    """
    device = FakeChr()
    statements = rw.parse_lines("\n".join(STATEMENTS))
    reads = 0

    def fake(spec: vw.SessionSpec) -> vc.RunOut:
        nonlocal reads
        if spec.remote == rw.scheduler_count_command().remote:
            reads += 1
            # the entry is there for the two change lines and gone after
            if reads >= 3:
                device.scheduler_present = False
                return _out("0")
        return device(spec)

    assert rw.RouterosOps().apply(fake, statements, 120) == "revert_lost"
    # the change ran, so the driver has to undo it
    assert "/ip address add address=198.51.100.7/24 interface=bridge" in device.remotes


def _detail_with_next_run(hhmmss: str) -> str:
    """The receipt of the device with the next run of the entry at a time."""
    return SCHEDULER_DETAIL.replace("23:31:23", hhmmss)


def test_the_next_run_has_to_be_inside_the_window() -> None:
    """The revert fires inside the window of the change.

    The window of the revert is measured from the clock of the device,
    and the clock is read again with the entry: a next run that is
    further away than the window (and the slack) is not a revert that
    protects this change.
    """
    statements = rw.parse_lines("\n".join(STATEMENTS))
    # the clock of the device says 23:29:23 and the window is 120 s, so
    # the last next run that is inside the window is 23:31:53
    inside = FakeChr(receipt_detail=_detail_with_next_run("23:31:53"))
    assert rw.RouterosOps().apply(inside, statements, 120) == "committed"

    outside = FakeChr(receipt_detail=_detail_with_next_run("23:31:54"))
    assert rw.RouterosOps().apply(outside, statements, 120) == "revert_lost"


def test_a_clock_that_moves_after_the_arm_is_a_lost_revert() -> None:
    """the clock of the device decides when the revert fires.

    A clock that jumps forward after the arm leaves the entry behind:
    the next run is in the past now, so the entry fires at once (or has
    fired) and it is not a revert that protects the change.
    """
    device = FakeChr()
    statements = rw.parse_lines("\n".join(STATEMENTS))
    clock_reads = 0

    def fake(spec: vw.SessionSpec) -> vc.RunOut:
        nonlocal clock_reads
        if spec.remote == rw.clock_command().remote:
            clock_reads += 1
            if clock_reads >= 2:
                # the clock of the device jumped a day forward
                return _out("time: 23:29:23\ndate: oct/24/2026\n")
        return device(spec)

    assert rw.RouterosOps().apply(fake, statements, 120) == "revert_lost"


def test_an_entry_that_has_fired_is_no_receipt() -> None:
    """a next run in the past is not a receipt at all.

    The receipt of the arm is the entry that has not fired yet, so an
    entry whose next run has passed is refused before any change line
    runs: there is nothing to undo.
    """
    statements = rw.parse_lines("\n".join(STATEMENTS))
    fired = FakeChr(receipt_detail=_detail_with_next_run("23:29:23"))

    assert rw.RouterosOps().apply(fired, statements, 120) == "armed_failed"


def test_the_dns_menu_takes_only_its_own_keys() -> None:
    """"/ip/dns set allow-remote-requests=yes" opens a resolver.

    The menu is on the allow list because the names of the servers show
    in the export of the device, so the hash of the export moves when
    they change.  A key that opens a resolver to the world does not show
    in the export, so it may not be written at all.
    """
    for line in (
        "/ip/dns set servers=192.0.2.53",
        "/ip/dns set cache-size=2048",
        "/ip/dns set servers=192.0.2.53 cache-size=2048",
    ):
        assert len(rw.parse_lines(line)) == 1, line
    for line in (
        "/ip/dns set allow-remote-requests=yes",
        "/ip/dns set cache-max-ttl=1d",
        "/ip/dns remove numbers=1",
    ):
        with pytest.raises(rw.LintError) as excinfo:
            rw.parse_lines(line)
        assert str(excinfo.value) == "parameter not allowed", line


def test_the_address_list_takes_only_its_own_keys() -> None:
    """The address list takes the keys that name an entry.

    The other menus are unchanged: they take any key of the grammar.
    """
    for line in (
        "/ip/firewall/address-list add list=lab address=192.0.2.7",
        "/ip/firewall/address-list add list=lab address=192.0.2.7 comment='lab host'",
        "/ip/firewall/address-list add list=lab address=192.0.2.7 timeout=1d",
    ):
        assert len(rw.parse_lines(line)) == 1, line
    for line in (
        "/ip/firewall/address-list add list=lab address=192.0.2.7 src-address=192.0.2.0/24",
        "/ip/firewall/address-list set comment='x' numbers=1",
    ):
        with pytest.raises(rw.LintError) as excinfo:
            rw.parse_lines(line)
        assert str(excinfo.value) == "parameter not allowed", line
    # the menus that are not in the table are unchanged
    for line in (
        "/ip/address add address=192.0.2.1/24 interface=ether1 comment='lab uplink'",
        "/ip/firewall/filter add chain=forward action=accept src-address=192.0.2.0/24",
        "/ip/pool add name=lab-pool ranges=192.0.2.0/24",
    ):
        assert len(rw.parse_lines(line)) == 1, line


class _FakeClock:
    """A monotonic clock that is read twice and moves by a fixed amount.

    The proof of the load compares the uptime of the device with the
    time the load took, so a test that pins the boundary needs a clock
    it controls.
    """

    def __init__(self, elapsed: float) -> None:
        self._elapsed = elapsed
        self._reads = 0

    def __call__(self) -> float:
        self._reads += 1
        if self._reads == 1:
            return 1000.0
        return 1000.0 + self._elapsed


def test_the_uptime_slack_is_pinned() -> None:
    """The proof of the load needs an uptime under elapsed+60.

    The slack is 60 seconds: an uptime that is exactly the elapsed time
    plus the slack is not a proof (the device may have answered before
    the reboot), and an uptime under it is.
    """
    assert rw.UPTIME_SLACK_S == 60

    def _abort_with(uptime: str) -> bool:
        device = FakeChr(
            scheduler_present=True,
            backup_present=True,
            uptime_output=uptime,
        )
        ops = rw.RouterosOps(wait=lambda _seconds: None, now=_FakeClock(30.0))
        return ops.abort(device)

    # 89 s of uptime is under the 30 s that passed plus the 60 s of slack
    assert _abort_with("00:01:29") is True
    # 90 s of uptime is not under it
    assert _abort_with("00:01:30") is False


# ---- the export that is not the same before and after a reboot -------
#
# The live CHR 7.24.5 showed that the export of a device that has been up
# for a minute holds a block that the same device does not have right
# after a reboot.  The configuration is the same in both exports:
#
#   /system keymat-provider
#   add disabled=yes key-size=0 name=default qkd-cache-size=0 \
#       qkd-certificate=*0 type=qkd
#
# The hash over the text is not the same, so the plan base hash (taken
# while the device was up) and the hash after the reboot of the abort
# (taken while it was down again) were different, and every rollback of
# the live run ended "unknown" although the device was back (the live
# runs on a CHR: every shape that had to be rolled back ended "unknown").
#
# The hash is over the normalised export now: the volatile sections are
# not part of it.  The two exports below are the recorded ones
# of a live CHR run.  They carry the CR of the
# ssh session, and the export of the device that had just rebooted is
# the baseline the live lab recorded for the CHR
# (lab/vendor-shapes.toml).

CHR_EXPORT_RUNNING = "\r\n".join(
    [
        '# 2026-10-24 19:15:39 by RouterOS 7.24.5',
        '# system id = d8vL9iXFkBN',
        '#',
        '/interface ethernet',
        'set [ find default-name=ether1 ] disable-running-check=no',
        'set [ find default-name=ether2 ] disable-running-check=no',
        '/user group',
        'add name=newton-read policy="ssh,read,!local,!telnet,!ftp,!reboot,!write,!poli\\',
        '    cy,!test,!winbox,!password,!web,!sniff,!sensitive,!api,!romon,!rest-api"',
        'add name=newton-write policy="ssh,ftp,reboot,read,write,policy,test,password,s\\',
        '    ensitive,!local,!telnet,!winbox,!web,!sniff,!api,!romon,!rest-api"',
        '/ip address',
        'add address=10.109.0.21/24 comment=newton-mgmt interface=ether1 network=\\',
        '    10.109.0.0',
        'add address=192.168.150.251/24 comment=newton-lab-peer-side interface=ether2 \\',
        '    network=192.168.150.0',
        '/ip dhcp-client',
        'add interface=ether1 name=client1',
        'add comment=lab-lan disabled=yes interface=ether2 name=client2',
        '/system identity',
        'set name=lab-chr',
        '/system keymat-provider',
        'add disabled=yes key-size=0 name=default qkd-cache-size=0 qkd-certificate=*0 \\',
        '    type=qkd',
        '',
    ]
)

CHR_EXPORT_AFTER_REBOOT = "\r\n".join(
    [
        '# 2026-10-24 19:15:51 by RouterOS 7.24.5',
        '# system id = d8vL9iXFkBN',
        '#',
        '/interface ethernet',
        'set [ find default-name=ether1 ] disable-running-check=no',
        'set [ find default-name=ether2 ] disable-running-check=no',
        '/user group',
        'add name=newton-read policy="ssh,read,!local,!telnet,!ftp,!reboot,!write,!poli\\',
        '    cy,!test,!winbox,!password,!web,!sniff,!sensitive,!api,!romon,!rest-api"',
        'add name=newton-write policy="ssh,ftp,reboot,read,write,policy,test,password,s\\',
        '    ensitive,!local,!telnet,!winbox,!web,!sniff,!api,!romon,!rest-api"',
        '/ip address',
        'add address=10.109.0.21/24 comment=newton-mgmt interface=ether1 network=\\',
        '    10.109.0.0',
        'add address=192.168.150.251/24 comment=newton-lab-peer-side interface=ether2 \\',
        '    network=192.168.150.0',
        '/ip dhcp-client',
        'add interface=ether1 name=client1',
        'add comment=lab-lan disabled=yes interface=ether2 name=client2',
        '/system identity',
        'set name=lab-chr',
        '',
    ]
)

# The hash of the export of the CHR that had just rebooted, as the live
# lab recorded it for the baseline of the CHR (lab/vendor-shapes.toml).
CHR_BASELINE_HASH = (
    "6a41de5e577d65090ef3f87bf23df3852990fa6a088ac5dd79b96e353d80cb64"
)


def test_the_two_exports_of_the_device_hash_the_same() -> None:
    """The export before and after the reboot is one hash.

    The block that the export of the device holds while it is up is not
    part of the configuration, so it is not part of the hash: the plan
    base hash and the hash after the reboot of the abort are the same
    and the driver finds the base configuration back.
    """
    running = rw.config_hash(CHR_EXPORT_RUNNING)
    rebooted = rw.config_hash(CHR_EXPORT_AFTER_REBOOT)

    assert running == rebooted
    # the export of the device that had just rebooted is the baseline
    # the live lab recorded for the CHR
    assert rebooted == CHR_BASELINE_HASH
    # the two exports are the same configuration, so the raw texts are
    # not the same
    assert CHR_EXPORT_RUNNING != CHR_EXPORT_AFTER_REBOOT


def test_the_volatile_section_goes_as_a_whole() -> None:
    """The header and the lines under it go together.

    The section of the volatile block ends with a line that continues on
    the next one, so the continuation goes with the section it belongs
    to.
    """
    normalised = rw.normalise_export(CHR_EXPORT_RUNNING)

    assert "/system keymat-provider" not in normalised
    assert "keymat" not in normalised
    assert "type=qkd" not in normalised
    # the rest of the export is still there
    assert "/system identity" in normalised
    assert "set name=lab-chr" in normalised
    assert "/ip dhcp-client" in normalised
    # the volatile section is named in the set of the sections
    assert "/system keymat-provider" in rw.VOLATILE_SECTIONS


def test_a_real_change_still_moves_the_hash() -> None:
    """A change of the configuration still moves the hash.

    The normalisation drops the volatile block and nothing else: an
    address that is added is a change of the configuration and the hash
    has to say so.
    """
    changed = CHR_EXPORT_AFTER_REBOOT.replace(
        "/ip dhcp-client\r\n",
        "/ip address add address=10.109.0.22/24 interface=ether3\r\n"
        "/ip dhcp-client\r\n",
    )

    assert changed != CHR_EXPORT_AFTER_REBOOT
    assert rw.config_hash(changed) != rw.config_hash(CHR_EXPORT_AFTER_REBOOT)


def test_a_volatile_name_inside_a_value_is_not_removed() -> None:
    """Only a header is a section, a value is a value.

    The name of a volatile section that appears inside a value is a
    value: it is part of the configuration and it stays in the hash.
    """
    text = "\r\n".join(
        [
            "/system identity",
            'set name=lab-chr comment="/system keymat-provider"',
            "",
        ]
    )
    without = "\r\n".join(
        [
            "/system identity",
            "set name=lab-chr",
            "",
        ]
    )

    assert "/system keymat-provider" in rw.normalise_export(text)
    assert rw.config_hash(text) != rw.config_hash(without)


def test_the_snapshot_hashes_the_normalised_export() -> None:
    """The snapshot hashes the export and keeps the raw text.

    The hash of the snapshot is the hash of the normalised export, so
    the snapshot of the device that is up and the snapshot of the device
    that has just rebooted are the same hash.  The text of the snapshot
    is the text of the device: the export is what the device answered.
    """
    running = rw.RouterosOps().snapshot(FakeChr(config=CHR_EXPORT_RUNNING))
    rebooted = rw.RouterosOps().snapshot(FakeChr(config=CHR_EXPORT_AFTER_REBOOT))

    assert running.text == CHR_EXPORT_RUNNING
    assert rebooted.text == CHR_EXPORT_AFTER_REBOOT
    assert running.base_hash == rebooted.base_hash
    assert running.base_hash == CHR_BASELINE_HASH


class _RebootChr(FakeChr):
    """The CHR of the live export: the load brings the export of the reboot.

    A load restores the configuration of the backup and the device
    reboots into it, so the export of the device after the load is the
    export of a device that has just rebooted: the one without the
    volatile block.
    """

    def __init__(self, *, restored: str, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.restored = restored

    def _answer(self, spec: vw.SessionSpec) -> vc.RunOut:
        output = super()._answer(spec)
        if spec.remote == rw.load_command().remote:
            self.config = self.restored
        return output


def test_the_rollback_of_the_live_export_is_a_rollback() -> None:
    """The rollback ends "rolled_back" and not "unknown".

    The whole live sequence: the plan is taken from the export of the
    device that is up, the device refuses the statement, the load of the
    backup reboots the device and the export of the device is the export
    of a device that has just rebooted.  The two exports are one
    configuration, so the driver reads the base hash back and reports a
    rollback instead of an unknown state.
    """
    device = _RebootChr(
        config=CHR_EXPORT_RUNNING,
        restored=CHR_EXPORT_AFTER_REBOOT,
        statement_outputs={
            LIVE_COMMAND: _out(
                "invalid value for argument address (/ip/address/add; line 1)",
                exit_code=1,
            )
        },
    )
    plan = {
        "uci_batch": LIVE_CHANGE,
        "base_hash": rw.config_hash(CHR_EXPORT_RUNNING),
        "timeout_s": 150,
        "probes": [],
    }

    outcome = vc.apply_plan(
        rw.RouterosOps(wait=lambda _seconds: None),
        device,
        plan,
        [],
        wait=lambda _seconds: None,
    )

    assert outcome.result == "rolled_back"
    assert outcome.failed_probe is None
    assert "statement 1 was rejected" in outcome.log
    # the device rebooted into the backup and the export says so
    assert device.config == CHR_EXPORT_AFTER_REBOOT
    assert device.loads == 1
    # the leftovers of the revert are gone
    assert device.scheduler_present is False
    assert device.backup_present is False
