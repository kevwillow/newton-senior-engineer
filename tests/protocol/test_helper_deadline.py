import os
import shlex
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

HELPER = Path(__file__).resolve().parents[2] / "scripts" / "owrt-safe-apply.sh"
SID = "0123456789abcdef0123456789abcdef"


class HelperLab:
    """Runs the real helper under `busybox sh` with shell-function fakes:
    `ubus` (logs every call, always succeeds), `date +%s` (prints a fake
    epoch from the environment), NEWTON_LOCK and NEWTON_UPTIME_FILE in
    tmp_path (CH-10: wall-clock steps must not move the deadline)."""

    def __init__(self, tmp_path):
        self.lock = tmp_path / "lock"
        self.lock.mkdir()
        self.uptime = tmp_path / "uptime"
        self.calls = tmp_path / "ubus.log"
        self.calls.write_text("")
        self.set_uptime(500.37)
        self.epoch = 1_700_000_000

    def set_uptime(self, up):
        self.uptime.write_text(f"{up} 480.00\n")

    def applied_file(self):
        return self.lock / f"{SID}.applied"

    def ubus_calls(self):
        return self.calls.read_text().splitlines()

    def run(self, *cmd, uptime_file=None):
        shell = textwrap.dedent(
            f"""\
            ubus() {{
                printf '%s\\n' "$*" >> {shlex.quote(str(self.calls))}
                return 0
            }}
            uci() {{ return 1; }}
            date() {{
                if [ "${{1:-}}" = "+%s" ]; then
                    printf '%s\\n' "$FAKE_EPOCH"
                else
                    command date "$@"
                fi
            }}
            set -- {shlex.join(cmd)}
            . {shlex.quote(str(HELPER))}
            """
        )
        busybox = shutil.which("busybox")
        assert busybox is not None
        env = os.environ.copy()
        env["NEWTON_LOCK"] = str(self.lock)
        env["NEWTON_UPTIME_FILE"] = str(uptime_file or self.uptime)
        env["FAKE_EPOCH"] = str(self.epoch)
        return subprocess.run(
            [busybox, "sh", "-c", shell],
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
        )


@pytest.fixture
def lab(tmp_path):
    return HelperLab(tmp_path)


def test_apply_writes_uptime_deadline(lab):
    """(a) `apply SID 90` with uptime 500.37 writes exactly "up 590\\n"
    and calls `ubus call uci apply` once."""
    res = lab.run("apply", SID, "90")

    assert res.returncode == 0
    assert "APPLIED with rollback" in res.stdout
    assert lab.applied_file().read_text() == "up 590\n"
    assert [c for c in lab.ubus_calls() if "uci apply" in c] == [
        f"call uci apply {{\"rollback\":true,\"timeout\":90,\"ubus_rpc_session\":\"{SID}\"}}"
    ]


def apply_quietly(lab):
    res = lab.run("apply", SID, "90")
    assert res.returncode == 0


def test_forward_wall_clock_step_confirm_still_works(lab):
    """(b) NTP steps the wall clock +2000 s inside the window while uptime
    moves only +10 s: status stays applied-pending-confirm and confirm
    still CONFIRMs (rpcd is the authority, uptime is the ruler)."""
    apply_quietly(lab)
    lab.epoch += 2000
    lab.set_uptime(510.37)

    status = lab.run("status", SID)
    assert status.returncode == 0
    assert status.stdout == "applied-pending-confirm\n"

    confirm = lab.run("confirm", SID)
    assert confirm.returncode == 0
    assert "CONFIRMED" in confirm.stdout
    assert any("uci confirm" in c for c in lab.ubus_calls())


def test_forward_wall_clock_step_abort_rolls_back(lab):
    """(c) same step: abort calls `uci rollback` and prints ROLLED BACK,
    not "already happened"."""
    apply_quietly(lab)
    lab.epoch += 2000
    lab.set_uptime(510.37)

    abort = lab.run("abort", SID)
    assert abort.returncode == 0
    assert "ROLLED BACK" in abort.stdout
    assert "already happened" not in abort.stdout
    assert any("uci rollback" in c for c in lab.ubus_calls())


def test_uptime_past_deadline(lab):
    """(d) uptime past deadline + 5 with the wall clock unchanged:
    status rolled-back; confirm refuses with no uci confirm call; abort
    reports the automatic rollback with no uci rollback call."""
    apply_quietly(lab)
    lab.set_uptime(596.37)

    status = lab.run("status", SID)
    assert status.stdout == "rolled-back\n"

    confirm = lab.run("confirm", SID)
    assert confirm.returncode == 1
    assert "rollback deadline passed" in confirm.stdout + confirm.stderr
    assert not any("uci confirm" in c for c in lab.ubus_calls())

    # fresh session for the abort half (confirm above dropped the state)
    lab.set_uptime(500.37)
    apply_quietly(lab)
    lab.set_uptime(596.37)
    abort = lab.run("abort", SID)
    assert abort.returncode == 0
    assert "automatic rollback already happened" in abort.stdout
    assert not any("uci rollback" in c for c in lab.ubus_calls())


def test_backward_wall_clock_step_uptime_decides(lab):
    """(e) wall clock jumps back 2000 s but uptime is past deadline + 5:
    still rolled-back (uptime decides, CH-10)."""
    apply_quietly(lab)
    lab.epoch -= 2000
    lab.set_uptime(600.00)

    status = lab.run("status", SID)
    assert status.stdout == "rolled-back\n"


@pytest.mark.parametrize(
    ("epoch_offset", "expected"),
    [(100, "rolled-back\n"), (0, "applied-pending-confirm\n")],
)
def test_old_epoch_format_still_judged_by_wall_clock(lab, epoch_offset, expected):
    """(f) a bare epoch (older router program) keeps the wall-clock
    judgement: past the fake window -> rolled-back, inside it -> pending."""
    apply_quietly(lab)
    written = 1_700_000_000
    lab.applied_file().write_text(f"{written}\n")
    lab.epoch = written + epoch_offset

    status = lab.run("status", SID)
    assert status.stdout == expected


def test_garbage_deadline_file_defers_to_rpcd(lab):
    """(g) garbage in the deadline file: not expired, so status says
    applied-pending-confirm and confirm asks rpcd (`uci confirm` called)."""
    apply_quietly(lab)
    lab.applied_file().write_text("garbage\n")

    status = lab.run("status", SID)
    assert status.stdout == "applied-pending-confirm\n"

    confirm = lab.run("confirm", SID)
    assert confirm.returncode == 0
    assert "CONFIRMED" in confirm.stdout
    assert any("uci confirm" in c for c in lab.ubus_calls())


def test_unreadable_uptime_apply_refused(lab, tmp_path):
    """(h) uptime unreadable: apply dies with "cannot read uptime" and
    never calls `uci apply`."""
    res = lab.run("apply", SID, "90", uptime_file=tmp_path / "no-such-uptime")

    assert res.returncode == 1
    assert "cannot read uptime" in res.stdout + res.stderr
    assert not any("uci apply" in c for c in lab.ubus_calls())
