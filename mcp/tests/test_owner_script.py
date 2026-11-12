"""Tests of the owner script template (A3 Part 2; ADR-021 point 7).

The owner approves the EXACT bytes of the script, so the bytes have to
be pinned: a golden render for a fixed plan, the template's own sha256
pin, and a parse that re-derives the plan from the bytes.

What is checked here:

  * the golden renders (apply and restore), byte for byte;
  * the template pin: an edit of the template changes it;
  * the parse round trip, and that every one-byte edit of a rendered
    script either refuses to parse or parses into a different plan;
  * that the bytes carry no agent text, no explanation and no device
    name inside a value;
  * that the script never reads stdin without ``</dev/null``, never
    confirms, never destroys the session and never prints the session
    id;
  * that shellcheck is clean of warnings.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
from pathlib import Path

import pytest

from newton_mcp import owner_script
from newton_mcp.owner_script import ScriptError, ScriptPlan

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "owner"

APPLY_ID = "3f9a1c0be2d44b17a1c3d5e7f9012345"
RESTORE_ID = "9e8d7c6b5a4938271605f4e3d2c1b0a9"

APPLY_PLAN = ScriptPlan(
    sid=APPLY_ID,
    kind="apply",
    device="lab-r1",
    window=180,
    restore_sid=RESTORE_ID,
    preconditions=(("firewall.cfg0a1b2c.dest_port", "22"),),
    ops=(("set", "firewall.cfg0a1b2c.dest_port", "2222"),),
)

RESTORE_PLAN = ScriptPlan(
    sid=RESTORE_ID,
    kind="restore",
    device="lab-r1",
    window=180,
    restore_of=APPLY_ID,
    preconditions=(("firewall.cfg0a1b2c.dest_port", "2222"),),
    ops=(("set", "firewall.cfg0a1b2c.dest_port", "22"),),
)

APPLY_LISTS_PLAN = ScriptPlan(
    sid="00112233445566778899aabbccddeeff",
    kind="apply",
    device="lab-r1",
    window=300,
    restore_sid="ffeeddccbbaa99887766554433221100",
    preconditions=(
        ("firewall.cfg03dc81.network", "wan wan6 wan2"),
        ("firewall.labz.ntp", None),
    ),
    ops=(
        ("del_list", "firewall.cfg03dc81.network", "wan6"),
        ("add_list", "firewall.cfg03dc81.network", "wan3"),
        ("delete", "firewall.labz", None),
        ("set", "system.hostname", "newton-lab"),
    ),
)

RESTORE_LISTS_PLAN = ScriptPlan(
    sid="ffeeddccbbaa99887766554433221100",
    kind="restore",
    device="lab-r1",
    window=300,
    restore_of="00112233445566778899aabbccddeeff",
    preconditions=(
        ("firewall.cfg03dc81.network", "wan wan2 wan3"),
        ("firewall.labz", "zone"),
    ),
    ops=(
        ("delete", "firewall.cfg03dc81.network", None),
        ("add_list", "firewall.cfg03dc81.network", "wan"),
        ("add_list", "firewall.cfg03dc81.network", "wan6"),
        ("add_list", "firewall.cfg03dc81.network", "wan2"),
        ("set", "firewall.newton_r_00112233_13.name", "lab"),
        ("reorder", "firewall.newton_r_00112233_13", "13"),
        ("set", "system.hostname", "OpenWrt"),
    ),
)

ALL_PLANS = (APPLY_PLAN, RESTORE_PLAN, APPLY_LISTS_PLAN, RESTORE_LISTS_PLAN)

GOLDENS = {
    "apply.sh": APPLY_PLAN,
    "restore.sh": RESTORE_PLAN,
    "apply-lists.sh": APPLY_LISTS_PLAN,
    "restore-lists.sh": RESTORE_LISTS_PLAN,
}


# ---- the pin ---------------------------------------------------------------


def test_template_sha256_pin():
    """The template's own sha256 is pinned in the source."""
    assert owner_script.template_sha256() == owner_script.TEMPLATE_SHA256
    assert owner_script.TEMPLATE_SHA256 == hashlib.sha256(
        owner_script.TEMPLATE_SKELETON.encode("utf-8")
    ).hexdigest()


def test_template_skeleton_has_one_marker_per_variable_line():
    """Every variable line of the template is a marker, not a value."""
    markers = [
        line for line in owner_script.TEMPLATE_LINES if line.startswith("@@")
    ]
    assert markers == [
        "@@kind_line@@",
        "@@plan_line@@",
        "@@purpose_line@@",
        "@@reboot_line@@",
        "@@touches_line@@",
        "@@undo_line@@",
        "@@plan_var@@",
        "@@window_var@@",
        "@@preconditions@@",
        "@@stages@@",
    ]
    # no marker may hide a value: the skeleton holds no plan id
    assert APPLY_ID not in owner_script.TEMPLATE_SKELETON
    assert "2222" not in owner_script.TEMPLATE_SKELETON


# ---- the golden renders ----------------------------------------------------


@pytest.mark.parametrize("name", sorted(GOLDENS))
def test_golden_render_is_byte_exact(name):
    """The rendered script is the golden file, byte for byte."""
    plan = GOLDENS[name]
    rendered = owner_script.render_script(plan)
    assert rendered == (FIXTURES / name).read_bytes()


@pytest.mark.parametrize("name", sorted(GOLDENS))
def test_golden_parses_back_to_the_plan(name):
    """The golden file parses into the plan it was rendered from."""
    parsed = owner_script.parse_script((FIXTURES / name).read_bytes())
    assert parsed == GOLDENS[name]


@pytest.mark.parametrize("plan", ALL_PLANS)
def test_render_is_deterministic(plan):
    """The same plan renders the same bytes every time."""
    assert owner_script.render_script(plan) == owner_script.render_script(plan)


@pytest.mark.parametrize("plan", ALL_PLANS)
def test_render_is_lf_only_with_a_final_newline(plan):
    """The bytes are LF only and end with a newline."""
    data = owner_script.render_script(plan)
    assert b"\r" not in data
    assert data.endswith(b"\n")
    assert not data.endswith(b"\n\n")


@pytest.mark.parametrize("plan", ALL_PLANS)
def test_parse_round_trip(plan):
    """parse_script(render_script(p)) == p."""
    assert owner_script.parse_script(owner_script.render_script(plan)) == plan


def test_apply_header_is_nine_lines_and_restore_header_is_eight():
    """The two headers have the line counts the design asks for."""
    apply_lines = owner_script.render_script(APPLY_PLAN).decode().split("\n")
    restore_lines = owner_script.render_script(RESTORE_PLAN).decode().split("\n")
    assert apply_lines[8] == "set -u"
    assert restore_lines[7] == "set -u"
    # the apply script has the undo line, the restore script does not
    assert apply_lines[7].startswith("# To undo it later")
    assert not any(
        line.startswith("# To undo it later") for line in restore_lines[:8]
    )


# ---- the one-byte edits ----------------------------------------------------


def _mutated(data: bytes, position: int, replacement: bytes) -> bytes:
    return data[:position] + replacement + data[position + 1 :]


@pytest.mark.parametrize("name", ["apply.sh", "restore.sh"])
def test_every_one_byte_edit_is_caught(name):
    """No one-byte edit of a rendered script goes unnoticed."""
    data = (FIXTURES / name).read_bytes()
    plan = GOLDENS[name]
    for position in range(len(data)):
        original = data[position : position + 1]
        for replacement in (b"X", b" ", b"'"):
            if replacement == original:
                continue
            edited = _mutated(data, position, replacement)
            try:
                parsed = owner_script.parse_script(edited)
            except ScriptError:
                continue
            assert parsed != plan, (
                "a one-byte edit of {0} at {1} parsed into the same plan".format(
                    name, position
                )
            )


def test_an_added_line_is_caught():
    """A line the template does not have is refused."""
    data = (FIXTURES / "apply.sh").read_bytes()
    edited = data.replace(
        b'echo "NEWTON-CHECKED plan=$PLAN"\n',
        b'echo "NEWTON-CHECKED plan=$PLAN"\nrm -rf /etc/config\n',
    )
    assert edited != data
    with pytest.raises(ScriptError):
        owner_script.parse_script(edited)


def test_a_removed_line_is_caught():
    """A missing line is refused."""
    data = (FIXTURES / "apply.sh").read_bytes()
    edited = data.replace(b"umask 077\n", b"")
    with pytest.raises(ScriptError):
        owner_script.parse_script(edited)


def test_a_changed_value_is_caught():
    """Changing a value in the bytes changes the plan."""
    data = (FIXTURES / "apply.sh").read_bytes()
    edited = data.replace(b"dest_port=2222", b"dest_port=2223")
    assert edited != data
    parsed = owner_script.parse_script(edited)
    assert parsed != APPLY_PLAN


def test_a_changed_apply_line_is_caught():
    """Changing the apply line is refused."""
    data = (FIXTURES / "apply.sh").read_bytes()
    edited = data.replace(b'\\"rollback\\":true', b'\\"rollback\\":fals')
    with pytest.raises(ScriptError):
        owner_script.parse_script(edited)


def test_a_changed_key_is_caught():
    """Changing a key changes the plan."""
    data = (FIXTURES / "apply.sh").read_bytes()
    edited = data.replace(b"cfg0a1b2c.dest_port", b"cfg0a1b2c.dest_porf")
    parsed = owner_script.parse_script(edited)
    assert parsed != APPLY_PLAN


# ---- what the bytes may not carry -----------------------------------------


@pytest.mark.parametrize("plan", ALL_PLANS)
def test_no_agent_text_or_explanation_in_the_bytes(plan):
    """Only the plan's own facts are in the bytes."""
    text = owner_script.render_script(plan).decode()
    for banned in (
        "intent",
        "expect",
        "because",
        "the agent",
        "Newton thinks",
    ):
        assert banned not in text


@pytest.mark.parametrize("plan", ALL_PLANS)
def test_the_device_name_is_never_inside_a_value(plan):
    """The device name appears in the header and nowhere else."""
    text = owner_script.render_script(plan).decode()
    for line in text.split("\n"):
        if line.startswith("want ") or line.startswith("stage "):
            assert plan.device not in line


@pytest.mark.parametrize("plan", ALL_PLANS)
def test_every_command_that_could_read_stdin_closes_it(plan):
    """Every command that could read stdin carries ``</dev/null``."""
    text = owner_script.render_script(plan).decode()
    for line in text.split("\n"):
        if line.startswith("#") or not line.strip():
            continue
        if "=" in line.split()[0] and not line.startswith("["):
            # an assignment (PATH=..., PLAN=..., D=...) is not a command
            continue
        if line.startswith("stage "):
            # the stage() function adds </dev/null to whatever it runs
            assert line.startswith('stage uci -P "$D" '), line
            continue
        for reader in ("uci", "ubus", "jsonfilter", "mktemp", "id -u"):
            if reader in line:
                assert "</dev/null" in line, line


@pytest.mark.parametrize("plan", ALL_PLANS)
def test_the_script_never_confirms_and_never_destroys_the_session_after_the_apply(
    plan,
):
    """The script confirms nothing, and it destroys its session only when
    it cannot use it.

    A destroy after the apply would cancel the rollback, so there is
    none: every destroy is on the way to the apply, where nothing has
    been applied yet.
    """
    text = owner_script.render_script(plan).decode()
    lines = text.split("\n")
    assert "uci confirm" not in text
    assert "session delete" not in text
    assert "luci-uploads" not in text
    apply_line = next(
        i for i, l in enumerate(lines) if l.startswith("ubus call uci apply")
    )
    destroys = [i for i, l in enumerate(lines) if "session destroy" in l]
    assert destroys, "the script must be able to drop its own session"
    assert all(i < apply_line for i in destroys), lines
    # the destroy is called on the failure paths on the way to the apply
    calls = [i for i, l in enumerate(lines) if "drop_session" in l]
    assert calls
    assert all(i < apply_line for i in calls), lines


@pytest.mark.parametrize("plan", ALL_PLANS)
def test_the_script_prints_the_session_only_on_the_applied_line(plan):
    """The session id reaches the screen on the APPLIED line only.

    It is a confirm-only token: the host needs it to confirm the
    change, and the session it names can do nothing else (measured,
    a3m-03 section A).
    """
    text = owner_script.render_script(plan).decode()
    echoes = [line for line in text.split("\n") if line.startswith("echo ")]
    with_session = [line for line in echoes if "$SID" in line]
    assert len(with_session) == 1, echoes
    assert 'echo "NEWTON-APPLIED plan=$PLAN window=$WINDOW session=$SID"' in (
        with_session[0]
    )


@pytest.mark.parametrize("plan", ALL_PLANS)
def test_the_script_grants_its_own_session_the_right_to_confirm(plan):
    """The script's session may confirm, and nothing else.

    A fresh limited session cannot confirm a root script's apply
    (measured, a3m-01: the answer is [6]), so the session the script
    opens is given the one right it needs: ``uci confirm``.
    """
    text = owner_script.render_script(plan).decode()
    grants = [
        line
        for line in text.split("\n")
        if line.startswith("ubus call session grant")
    ]
    assert len(grants) == 2, grants
    confirm_grant = grants[1]
    assert r'\"scope\":\"ubus\"' in confirm_grant
    assert r'\"objects\":[[\"uci\",\"confirm\"]]' in confirm_grant
    assert "</dev/null" in confirm_grant
    assert '|| { drop_session; die "could not open a session"; }' in confirm_grant
    # the right is the confirm and nothing else
    assert confirm_grant.count(r'\"uci\"') == 1
    assert "read" not in confirm_grant
    assert "write" not in confirm_grant


@pytest.mark.parametrize("plan", ALL_PLANS)
def test_a_pending_window_is_an_empty_or_a_full_directory(plan):
    """The script stops when the snapshot directory holds something.

    An EMPTY directory is not a window: a refused apply leaves it
    behind, empty, and it stays that way (measured, a3m-04).
    """
    text = owner_script.render_script(plan).decode()
    assert (
        'if [ -n "$(ls -A /var/run/rpcd/snapshot-files 2>/dev/null </dev/null)" ]'
        in text
    )
    assert (
        'die "another change is waiting for confirmation (LuCI or Newton)"'
        in text
    )
    assert "[ ! -e /var/run/rpcd/snapshot-files ]" not in text


@pytest.mark.parametrize("plan", ALL_PLANS)
def test_a_leftover_undo_file_names_the_way_out(plan):
    """An undo file the router forgot about says how to get rid of it.

    A restart of the router's web service forgets the window but leaves
    the undo file behind for good (measured, a4m-02).  The script still
    refuses, and it tells the owner what to do about it.
    """
    text = owner_script.render_script(plan).decode()
    assert 'if [ "$undo_age" -ge 900 ]; then' in text
    assert (
        "the router has a leftover undo file from $undo_text ago (its web "
        "service restarted during a change). If nobody is changing the router "
        "right now, reboot it, or as root run: rm -rf /var/run/rpcd/snapshot-files"
    ) in text


@pytest.mark.parametrize("plan", ALL_PLANS)
def test_the_script_says_when_the_router_has_an_empty_leftover(plan):
    """The script tells the owner that the empty directory is harmless.

    The owner reads that as a NOTE line, and nothing removes the
    directory: the script writes nothing outside its own temporary
    directory and the staging directory.
    """
    text = owner_script.render_script(plan).decode()
    assert (
        "NEWTON-NOTE: the router has an empty leftover from a refused "
        "change (/var/run/rpcd/snapshot-files); it does not block Newton"
    ) in text
    assert "rmdir" not in text
    for line in text.splitlines():
        if "rm -rf /var/run/rpcd" in line:
            # the way out is TOLD to the owner; the script never runs it
            assert line.lstrip().startswith("die "), line


@pytest.mark.parametrize("plan", ALL_PLANS)
def test_the_script_makes_exactly_one_apply(plan):
    """There is one state-changing call, and it is the apply."""
    text = owner_script.render_script(plan).decode()
    applies = [
        line
        for line in text.split("\n")
        if "uci apply" in line and not line.startswith("#")
    ]
    assert len(applies) == 1
    assert '\\"rollback\\":true' in applies[0]
    assert '\\"timeout\\":$WINDOW' in applies[0]


@pytest.mark.parametrize("plan", ALL_PLANS)
def test_no_eval_no_sh_c_no_backtick_in_a_command(plan):
    """No command can run something the plan brought with it."""
    text = owner_script.render_script(plan).decode()
    for line in text.split("\n"):
        if line.startswith("#") or not line.strip():
            continue
        assert "eval" not in line
        assert "sh -c" not in line
        assert "`" not in line


# ---- the refusals ----------------------------------------------------------


def test_a_plan_without_ops_is_refused():
    with pytest.raises(ScriptError):
        owner_script.render_script(
            ScriptPlan(sid=APPLY_ID, kind="apply", device="lab-r1", window=180,
                       restore_sid=RESTORE_ID)
        )


def test_a_plan_with_a_bad_id_is_refused():
    with pytest.raises(ScriptError):
        owner_script.render_script(
            ScriptPlan(sid="nope", kind="apply", device="lab-r1", window=180,
                       restore_sid=RESTORE_ID)
        )


def test_a_plan_with_a_bad_device_is_refused():
    with pytest.raises(ScriptError):
        owner_script.render_script(
            ScriptPlan(sid=APPLY_ID, kind="apply", device="lab r1", window=180,
                       restore_sid=RESTORE_ID)
        )


@pytest.mark.parametrize("window", [0, 119, 601, 100000, True, "180"])
def test_a_plan_with_a_bad_window_is_refused(window):
    with pytest.raises(ScriptError):
        owner_script.render_script(
            ScriptPlan(sid=APPLY_ID, kind="apply", device="lab-r1", window=window,
                       restore_sid=RESTORE_ID)
        )


def test_an_apply_plan_without_a_restore_id_is_refused():
    with pytest.raises(ScriptError):
        owner_script.render_script(
            ScriptPlan(sid=APPLY_ID, kind="apply", device="lab-r1", window=180)
        )


def test_a_restore_plan_without_the_plan_it_restores_is_refused():
    with pytest.raises(ScriptError):
        owner_script.render_script(
            ScriptPlan(sid=RESTORE_ID, kind="restore", device="lab-r1", window=180)
        )


def test_a_plan_with_an_unsafe_value_is_refused():
    with pytest.raises(ScriptError):
        owner_script.render_script(
            ScriptPlan(
                sid=APPLY_ID,
                kind="apply",
                device="lab-r1",
                window=180,
                restore_sid=RESTORE_ID,
                ops=(("set", "system.hostname", "$(touch /tmp/x)"),),
            )
        )


def test_a_plan_with_a_bad_key_is_refused():
    with pytest.raises(ScriptError):
        owner_script.render_script(
            ScriptPlan(
                sid=APPLY_ID,
                kind="apply",
                device="lab-r1",
                window=180,
                restore_sid=RESTORE_ID,
                ops=(("set", "not a key", "x"),),
            )
        )


def test_a_plan_with_a_bad_verb_is_refused():
    with pytest.raises(ScriptError):
        owner_script.render_script(
            ScriptPlan(
                sid=APPLY_ID,
                kind="apply",
                device="lab-r1",
                window=180,
                restore_sid=RESTORE_ID,
                ops=(("rename", "system.hostname", "x"),),
            )
        )


def test_a_script_with_a_carriage_return_is_refused():
    data = (FIXTURES / "apply.sh").read_bytes().replace(b"\n", b"\r\n")
    with pytest.raises(ScriptError):
        owner_script.parse_script(data)


def test_a_script_without_a_final_newline_is_refused():
    data = (FIXTURES / "apply.sh").read_bytes().rstrip(b"\n")
    with pytest.raises(ScriptError):
        owner_script.parse_script(data)


def test_a_script_that_is_not_utf8_is_refused():
    with pytest.raises(ScriptError):
        owner_script.parse_script(b"#!/bin/sh\n\xff\xfe\n")


def test_script_sha256():
    """The sha256 of a rendered script is the sha256 of its bytes."""
    data = (FIXTURES / "apply.sh").read_bytes()
    assert owner_script.script_sha256(data) == hashlib.sha256(data).hexdigest()


# ---- the linters -----------------------------------------------------------


@pytest.mark.parametrize("name", sorted(GOLDENS))
def test_shellcheck_is_clean_of_warnings(name):
    """shellcheck says nothing about the golden scripts."""
    shellcheck = shutil.which("shellcheck")
    if shellcheck is None:
        pytest.skip("shellcheck is not installed")
    done = subprocess.run(
        [shellcheck, "-s", "sh", "-S", "warning", str(FIXTURES / name)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 0, done.stdout + done.stderr
