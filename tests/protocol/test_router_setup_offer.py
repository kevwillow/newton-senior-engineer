"""The offer of the installed mode (ADR-021 point 1).

The no-install setup ends with the offer: the owner is asked ONCE whether
the installed mode should be used on that router too.  A "no" is
remembered in the inventory (installed_offer = "declined") and is not
asked again; a "yes" stores nothing and prints the two steps that switch
the mode (uninstall, then install) without running them.  The
`offer-installed` action asks the same question again.

The tests: the question is asked once; a "no" writes the field and a
re-run does not ask; a "yes" writes no field, prints the steps and runs
nothing; a run with no terminal asks nothing; the action works on a
no-install device and is refused on an installed one; the uninstall
takes the field away; the loader refuses a bad value.
"""

import os
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from router_setup_env import setup_env  # noqa: E402,F401
from test_router_setup_disclosure import YES, seed_known_hosts  # noqa: E402
from test_router_setup_noinstall import (  # noqa: E402
    CLOSING_NOTES,
    GOOD_PW,
    inventory_entry,
    prepare_router,
    run_noinstall,
    run_uninstall,
    write_rpcd_stub,
)

REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "scripts" / "newton-router-setup"

# the question of the offer, word for word (the design)
QUESTION = ("Also use installed mode on this router? It puts Newton's "
            "program and guard on the router (y/N)")

SOURCE_RUN = (
    'source "$1"\n'
    'INVENTORY="$2"\n'
    'load_inventory r1\n'
)


def run_noinstall_with_offer(env, answer=None, extra=None):
    """A no-install run whose typed lines carry the offer's answer.

    The typed lines are the root password and the two answers of the
    approval passphrase; the answer of the offer is the last one.
    """
    typed = [GOOD_PW, GOOD_PW, GOOD_PW]
    if answer is not None:
        typed.append(answer)
    return run_noinstall(env, typed=typed, extra=extra)


def run_offer_installed(env, answer=None, extra=None):
    """An `offer-installed` run (host-only work: no router, no password)."""
    seam = {"NEWTON_SETUP_RPCD": str(write_rpcd_stub(env)),
            "NEWTON_TEST_RPCD_ROUTER": str(env.router.root)}
    if extra:
        seam.update(extra)
    typed = [] if answer is None else [answer]
    return env.run("r1", "offer-installed", typed=typed, env=seam)


def inventory_field(env, name):
    """One field of the device's inventory entry (None when it is absent)."""
    return inventory_entry(env).get(name)


def loader_run(tmp_path, body, extra=""):
    """The setup loader on an inventory body: (rc, stdout, stderr)."""
    inventory = tmp_path / "devices.toml"
    inventory.write_text(body, encoding="utf-8")
    inventory.chmod(0o644)
    proc = subprocess.run(
        ["bash", "-c", SOURCE_RUN + extra, "bash", str(TOOL), str(inventory)],
        capture_output=True, text=True, timeout=60,
        env={k: v for k, v in os.environ.items()
             if not k.startswith("NEWTON_")})
    return proc.returncode, proc.stdout, proc.stderr


# -- 1. the question at the end of the no-install setup ----------------------


def test_the_offer_is_asked_once_at_the_end_of_the_no_install(setup_env):
    """The setup asks the question once, at the end, and a "no" is
    remembered in the inventory."""
    env = setup_env
    prepare_router(env)
    r = run_noinstall_with_offer(env, answer="no")
    assert r.rc == 0, r.out + r.err
    assert r.err.count(QUESTION) == 1, r.err
    assert inventory_field(env, "installed_offer") == "declined"


def test_a_declined_offer_is_not_asked_again(setup_env):
    """A re-run of the no-install setup on a device whose inventory says
    the offer was declined does not ask again."""
    env = setup_env
    prepare_router(env)
    first = run_noinstall_with_offer(env, answer="no")
    assert first.rc == 0, first.out + first.err
    second = run_noinstall_with_offer(env, answer="no")
    assert second.rc == 0, second.out + second.err
    assert QUESTION not in second.err, second.err
    assert inventory_field(env, "installed_offer") == "declined"


def test_a_yes_stores_nothing_and_prints_the_switch_steps(setup_env):
    """A "yes" writes no field, prints the two steps that switch the mode
    and runs neither of them."""
    env = setup_env
    prepare_router(env)
    r = run_noinstall_with_offer(env, answer="yes")
    assert r.rc == 0, r.out + r.err
    assert inventory_field(env, "installed_offer") is None
    lines = r.out.splitlines()
    assert any("newton-router-setup r1 uninstall" in line
               and "removes the no-install login" in line
               for line in lines), lines
    assert any("newton-router-setup r1 install" in line
               for line in lines), lines
    # nothing was run: the no-install login is still on the router and the
    # device is still a no-install device
    assert "config login 'newton'" in env.router.read("etc/config/rpcd")
    assert inventory_field(env, "access") == "no-install"


def test_a_run_without_a_terminal_asks_nothing(setup_env):
    """No terminal to read: the question is not asked and nothing is
    stored."""
    env = setup_env
    prepare_router(env)
    # the first run writes the approval fingerprint, so the second run
    # needs no terminal for the passphrase either; the root password
    # comes from a file, the way a non-interactive run gets it
    first = run_noinstall_with_offer(env, answer="no")
    assert first.rc == 0, first.out + first.err
    password_file = env.tmp / "root-password"
    password_file.write_text(GOOD_PW + "\n", encoding="utf-8")
    password_file.chmod(0o600)
    seam = {"NEWTON_SETUP_RPCD": str(write_rpcd_stub(env)),
            "NEWTON_TEST_RPCD_ROUTER": str(env.router.root),
            "NEWTON_SETUP_TTY": ""}
    second = env.run("--password-file", str(password_file), "r1", "no-install",
                     typed=(), env=seam)
    assert second.rc == 0, second.out + second.err
    assert QUESTION not in second.err, second.err


def test_an_answer_that_is_neither_yes_nor_no_stores_nothing(setup_env):
    """Any other answer is not an answer: nothing is stored."""
    env = setup_env
    prepare_router(env)
    r = run_noinstall_with_offer(env, answer="maybe")
    assert r.rc == 0, r.out + r.err
    assert inventory_field(env, "installed_offer") is None


# -- 2. the offer-installed action -----------------------------------------


def test_offer_installed_asks_again_and_records_a_no(setup_env):
    """The action asks the same question and records a "no" the same way."""
    env = setup_env
    prepare_router(env)
    first = run_noinstall_with_offer(env, answer="no")
    assert first.rc == 0, first.out + first.err
    r = run_offer_installed(env, answer="no")
    assert r.rc == 0, r.out + r.err
    assert r.err.count(QUESTION) == 1, r.err
    assert inventory_field(env, "installed_offer") == "declined"


def test_offer_installed_with_a_yes_removes_the_declined_field(setup_env):
    """A "yes" takes the declined field away and prints the steps."""
    env = setup_env
    prepare_router(env)
    first = run_noinstall_with_offer(env, answer="no")
    assert first.rc == 0, first.out + first.err
    r = run_offer_installed(env, answer="yes")
    assert r.rc == 0, r.out + r.err
    assert inventory_field(env, "installed_offer") is None
    lines = r.out.splitlines()
    assert any("newton-router-setup r1 uninstall" in line
               for line in lines), lines
    assert any("newton-router-setup r1 install" in line
               for line in lines), lines


def test_offer_installed_without_a_terminal_asks_nothing(setup_env):
    """No terminal: the action asks nothing and stores nothing."""
    env = setup_env
    prepare_router(env)
    first = run_noinstall_with_offer(env, answer="no")
    assert first.rc == 0, first.out + first.err
    r = run_offer_installed(env, answer=None, extra={"NEWTON_SETUP_TTY": ""})
    assert r.rc == 0, r.out + r.err
    assert QUESTION not in r.err, r.err
    assert inventory_field(env, "installed_offer") == "declined"


def test_offer_installed_is_refused_on_an_installed_device(setup_env):
    """An installed device has nothing to offer: one plain line, no
    question, nothing stored."""
    env = setup_env
    r = run_offer_installed(env, answer="yes")
    assert r.rc == 1, r.out + r.err
    assert "STOPPED offer-installed r1" in r.out, r.out
    assert "installed access" in r.out, r.out
    assert QUESTION not in r.err, r.err
    assert inventory_field(env, "installed_offer") is None


# -- 3. the uninstall takes the field away ----------------------------------


def test_the_uninstall_removes_the_installed_offer_field(setup_env):
    """The uninstall of a no-install device removes the offer field with
    the other no-install fields."""
    env = setup_env
    prepare_router(env)
    first = run_noinstall_with_offer(env, answer="no")
    assert first.rc == 0, first.out + first.err
    assert inventory_field(env, "installed_offer") == "declined"
    r = run_uninstall(env, typed=(GOOD_PW,))
    assert r.rc == 0, r.out + r.err
    assert inventory_field(env, "installed_offer") is None
    assert inventory_field(env, "access") is None


# -- 4. the inventory loader ------------------------------------------------


def test_the_loader_refuses_a_bad_installed_offer_value(tmp_path):
    """A value that is not "declined" is refused, the way a bad access
    is refused."""
    body = ('[devices.r1]\nhost = "10.1.2.3"\nprofile = "lab"\n'
            'access = "no-install"\ninstalled_offer = "maybe"\n')
    rc, _out, err = loader_run(tmp_path, body)
    assert rc == 2, err
    assert "installed_offer" in err, err


def test_the_loader_refuses_the_field_on_an_installed_device(tmp_path):
    """The field belongs to a no-install device only."""
    body = ('[devices.r1]\nhost = "10.1.2.3"\nprofile = "lab"\n'
            'installed_offer = "declined"\n')
    rc, _out, err = loader_run(tmp_path, body)
    assert rc == 2, err
    assert "installed_offer" in err, err


def test_the_loader_refuses_the_field_on_a_device_that_is_not_openwrt(tmp_path):
    """The field belongs to a no-install OpenWrt device: the MCP loader
    refuses it anywhere else, and so does this one (review item 5)."""
    body = ('[devices.r1]\nhost = "10.1.2.3"\nprofile = "lab"\n'
            'platform = "junos"\naccess = "no-install"\n'
            'installed_offer = "declined"\n')
    rc, _out, err = loader_run(tmp_path, body)
    assert rc == 2, err
    assert "installed_offer" in err, err


def test_the_loader_refuses_the_field_on_a_no_install_openwrt_device_that_is_not_openwrt(
    tmp_path,
):
    """The same rule for every platform the tool does not know: the
    field is an OpenWrt field."""
    for platform in ("vyos", "routeros", "eos"):
        body = ('[devices.r1]\nhost = "10.1.2.3"\nprofile = "lab"\n'
                'platform = "%s"\naccess = "no-install"\n'
                'installed_offer = "declined"\n' % platform)
        rc, _out, err = loader_run(tmp_path, body)
        assert rc == 2, err
        assert "installed_offer" in err, err


def test_the_loader_accepts_the_field_on_a_no_install_device(tmp_path):
    """The field is read on a no-install device."""
    body = ('[devices.r1]\nhost = "10.1.2.3"\nprofile = "lab"\n'
            'access = "no-install"\ninstalled_offer = "declined"\n')
    rc, _out, err = loader_run(tmp_path, body)
    assert rc == 0, err


def test_the_field_is_kept_next_to_the_other_fields(tmp_path):
    """The loader keeps the value it read (the setup tool uses it to
    decide whether to ask again)."""
    body = ('[devices.r1]\nhost = "10.1.2.3"\nprofile = "lab"\n'
            'access = "no-install"\ninstalled_offer = "declined"\n')
    rc, out, err = loader_run(
        tmp_path, body,
        extra='printf "installed_offer=%s\\n" "$DEV_INSTALLED_OFFER"\n')
    assert rc == 0, err
    assert "installed_offer=declined" in out, out


def test_the_inventory_still_parses_after_the_offer(tmp_path):
    """The offer's field is a normal inventory field: the file stays a
    valid inventory."""
    path = tmp_path / "devices.toml"
    path.write_text('[devices.r1]\nhost = "10.1.2.3"\n'
                    'installed_offer = "declined"\n', encoding="utf-8")
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    assert data["devices"]["r1"]["installed_offer"] == "declined"


@pytest.mark.parametrize("value", ["declined", "maybe", "", "yes"])
def test_only_the_declined_value_is_accepted(value, tmp_path):
    """Only the value "declined" is a recorded answer."""
    body = ('[devices.r1]\nhost = "10.1.2.3"\nprofile = "lab"\n'
            'access = "no-install"\ninstalled_offer = "%s"\n' % value)
    rc, _out, err = loader_run(tmp_path, body)
    if value == "declined":
        assert rc == 0, err
    else:
        assert rc == 2, err
        assert "installed_offer" in err, err


def test_a_run_with_a_yes_flag_asks_nothing_and_stores_nothing(setup_env):
    """The tool has no `--yes` flag: an unknown option is refused before
    anything is asked, so no flag can ever answer the offer."""
    env = setup_env
    prepare_router(env)
    r = env.run("r1", "no-install", "--yes", typed=[GOOD_PW])
    assert r.rc != 0, r.out + r.err
    assert QUESTION not in r.err, r.err
    assert inventory_field(env, "installed_offer") is None


# -- 2. the side-by-side comes before the router is touched ---


def test_the_no_install_shows_the_side_by_side_before_the_router_is_touched(
    setup_env,
):
    """ADR-021 point 9: the two access modes are shown before the router
    is touched.  A run that stops at the very first router call still
    shows them, so the owner read them before anything was changed."""
    env = setup_env
    prepare_router(env)
    r = run_noinstall(env, typed=("wrong-password",))
    assert r.rc != 0, r.out + r.err
    for line in CLOSING_NOTES:
        assert line in r.out.splitlines(), line


def test_the_no_install_shows_the_side_by_side_once(setup_env):
    """One place per run: the side-by-side is shown at the start, not
    again at the end."""
    env = setup_env
    prepare_router(env)
    r = run_noinstall(env, typed=(GOOD_PW, GOOD_PW, GOOD_PW, "no"))
    assert r.rc == 0, r.out + r.err
    notes = [l for l in r.out.splitlines() if l.startswith("NOTE ")]
    assert notes[:10] == CLOSING_NOTES, notes[:12]
    for line in CLOSING_NOTES:
        assert r.out.count(line) == 1, line


def test_the_install_shows_the_side_by_side_before_the_router_is_touched(
    setup_env,
):
    """The installed action shows the same side-by-side before it asks
    the yes, so before the first router write: a refused answer leaves
    the router untouched and the notes are still there."""
    env = setup_env
    seed_known_hosts(env)
    r = env.run(env.device, "install", typed=(GOOD_PW, "no"))
    assert r.rc != 0, r.out + r.err
    assert r.calls == [], r.calls
    for line in CLOSING_NOTES:
        assert line in r.out.splitlines(), line


def test_the_install_shows_the_side_by_side_once(setup_env):
    """One place per run on the installed side too."""
    env = setup_env
    seed_known_hosts(env)
    r = env.run(env.device, "install", typed=(GOOD_PW, "yes"))
    assert r.rc == 0, r.out
    for line in CLOSING_NOTES:
        assert r.out.count(line) == 1, line


# -- 4. the commands the owner runs are the ones that work ---

# the installed layout: the launcher refuses to run as anyone but the
# newton user (scripts/newton-install writes the launcher), so a command
# the owner copies has to carry the prefix.
OWNER_PREFIX = "sudo -u newton /usr/local/bin/newton-router-setup"


def test_the_command_the_no_answer_prints_is_one_the_owner_can_run(setup_env):
    """The line that says how to ask again is a command that works."""
    env = setup_env
    prepare_router(env)
    r = run_noinstall_with_offer(env, answer="no")
    assert r.rc == 0, r.out + r.err
    lines = r.out.splitlines()
    assert any(OWNER_PREFIX + " r1 offer-installed" in line for line in lines), r.out
    # no bare command anywhere in the line
    for line in lines:
        assert not line.strip().startswith("newton-router-setup"), line


def test_the_yes_says_the_plain_key_must_be_made_first(setup_env):
    """A no-install setup makes no plain key, and swap-key needs one: the
    printed steps say to make it first."""
    env = setup_env
    prepare_router(env)
    r = run_noinstall_with_offer(env, answer="yes")
    assert r.rc == 0, r.out + r.err
    assert any("swap-key" in line and "plain key" in line
               and "first" in line for line in r.out.splitlines()), r.out


def test_the_switch_steps_the_yes_prints_are_one_the_owner_can_run(setup_env):
    """The two steps that switch the mode are printed with the prefix."""
    env = setup_env
    prepare_router(env)
    r = run_noinstall_with_offer(env, answer="yes")
    assert r.rc == 0, r.out + r.err
    lines = r.out.splitlines()
    for action in ("uninstall", "install"):
        assert any(OWNER_PREFIX + " r1 " + action in line
                   for line in lines), r.out


def test_the_offer_installed_hint_is_one_the_owner_can_run(setup_env):
    """The `offer-installed` action prints the same runnable command."""
    env = setup_env
    prepare_router(env)
    run_noinstall_with_offer(env, answer="no")
    r = run_offer_installed(env, answer="no")
    assert r.rc == 0, r.out + r.err
    assert any(OWNER_PREFIX + " r1 offer-installed" in line
               for line in r.out.splitlines()), r.out


def test_the_docs_print_the_owner_run_command_in_the_installed_layout():
    """SKILL.md and SETUP.md give the owner a command that works."""
    for name, placeholder in (("SKILL.md", "<device>"), ("SETUP.md", "<name>")):
        text = (REPO / name).read_text(encoding="utf-8")
        assert OWNER_PREFIX + " " + placeholder + " owner-run" in text, name


# -- 5. the offer prompt is bounded --------------------------


def test_the_offer_gives_up_when_the_terminal_never_answers(setup_env,
                                                            tmp_path):
    """A terminal that never answers: the read gives up, nothing is
    stored and the setup still ends DONE (review item 6)."""
    env = setup_env
    prepare_router(env)
    fifo = tmp_path / "silent-tty"
    os.mkfifo(fifo)
    # the test holds the fifo open, so the tool's open of it succeeds and
    # the read waits for the timeout; the three answers the setup needs
    # are in it and nothing follows
    fd = os.open(fifo, os.O_RDWR)
    try:
        os.write(fd, ("\n".join([GOOD_PW, GOOD_PW, GOOD_PW]) + "\n").encode())
        r = run_noinstall(env, typed=(),
                          extra={"NEWTON_SETUP_TTY": str(fifo),
                                 "NEWTON_SETUP_ANSWER_TIMEOUT": "2"},
                          timeout=60)
    finally:
        os.close(fd)
    assert r.rc == 0, r.out + r.err
    assert r.out.strip().splitlines()[-1] == "DONE no-install r1", r.out
    # nothing was stored: the offer was never answered
    assert inventory_field(env, "installed_offer") is None
    # and the owner is told how to ask again
    assert "offer-installed" in r.out, r.out
