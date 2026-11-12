"""One text about the two access modes.

The setup's closing lines, the installer's closing text, README.md,
SETUP.md and SKILL.md all say the same thing about the two modes, in the
same words: what each mode puts on the router, what protects the owner
and what it cannot do.  The test keeps the copies equal, so no place
promises more than another, and it checks the numbers (the file count
and the size of the installed program) against the tree.
"""

import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from router_setup_env import setup_env  # noqa: E402,F401
from test_router_setup_disclosure import GOOD_PW, YES, seed_known_hosts  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "scripts" / "newton-router-setup"
INSTALLER = REPO / "scripts" / "newton-install"

# the shared text: the two modes, five sentences each.  The order is the
# order of every copy.
NO_INSTALL_SENTENCES = [
    "Newton puts nothing on the router except one web-interface user.",
    "Every change uses OpenWrt's own undo timer.",
    "Limit: if the router reboots or its web service restarts while a "
    "change waits for confirmation, the change stays.",
    "Limit: whoever steals Newton's router password could take an "
    "interface down, restart Wi-Fi, kick a device off, or store files in "
    "/etc/luci-uploads, without your approval.",
    "Newton applies only DHCP static leases and DNS entries itself; every "
    "other change is a script you approve and run.",
]

INSTALLED_SENTENCES = [
    "Newton puts a program on the router: a small set of shell scripts "
    "(6 files, about 216 KB), no packages and no compiled code.",
    "Newton's key can run that program and nothing else, so the agent "
    "never gets a root shell.",
    "If a Newton change is still waiting for confirmation at boot, the "
    "guard puts the last good settings back, so a reboot cannot leave that "
    "change stuck.",
    "More checks can run, and fewer changes need a script.",
    "uninstall removes Newton's program and key; it keeps the guard's saved "
    "settings and the rest of /etc/newton (its lock and log), the program "
    "directory, the WAN-health settings in /etc/config/newton_wanhealth, the "
    "keys from before swap-key and the sysupgrade file: the saved settings "
    "and the copy of your keys are what you restore by hand.",
]

SENTENCES = NO_INSTALL_SENTENCES + INSTALLED_SENTENCES

# the docs that carry the text
DOCS = ("README.md", "SETUP.md", "SKILL.md")


def clean_env():
    """The environment of a script that is sourced for its functions."""
    return {k: v for k, v in __import__("os").environ.items()
            if not k.startswith("NEWTON_")}


def setup_closing_lines():
    """The closing lines of the no-install setup, as the tool prints them."""
    proc = subprocess.run(
        ["bash", "-c", 'source "$1"; access_modes_notes', "bash", str(TOOL)],
        capture_output=True, text=True, timeout=120, env=clean_env())
    assert proc.returncode == 0, proc.stderr
    return [line[len("NOTE "):] for line in proc.stdout.splitlines()
            if line.startswith("NOTE ")]


def installer_closing_text():
    """The closing text of the installer, as the installer prints it."""
    proc = subprocess.run(
        ["bash", "-c", 'source "$1"; access_modes_closing', "bash",
         str(INSTALLER)],
        capture_output=True, text=True, timeout=120, env=clean_env())
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


def installed_program():
    """The files the install uploads, measured from the sources: (count,
    total bytes)."""
    proc = subprocess.run(
        ["bash", "-c",
         'source "$1"; for row in "${CODE_FILES[@]}" "${EXTRA_FILES[@]}"; do '
         'IFS="|" read -r rel remote mode rotate <<<"$row"; '
         'printf "%s %s\\n" "$rel" "$(wc -c <"$DEFAULT_SRC/$rel")"; done',
         "bash", str(TOOL)],
        capture_output=True, text=True, timeout=120, env=clean_env())
    assert proc.returncode == 0, proc.stderr
    sizes = []
    for line in proc.stdout.splitlines():
        rel, size = line.rsplit(" ", 1)
        sizes.append(int(size))
    assert sizes, "no file was measured"
    return len(sizes), sum(sizes)


# -- 1. the two scripts say the same thing ----------------------------------


def test_the_setup_closing_lines_carry_the_shared_text():
    """The setup's closing lines are the ten sentences, in order."""
    lines = setup_closing_lines()
    assert len(lines) == len(SENTENCES), lines
    for line, sentence in zip(lines[:5], NO_INSTALL_SENTENCES):
        assert line == "no-install: " + sentence, line
    for line, sentence in zip(lines[5:], INSTALLED_SENTENCES):
        assert line == "installed: " + sentence, line


def test_the_installer_closing_text_carries_the_same_sentences():
    """The installer's closing text says the same thing, word for word."""
    text = installer_closing_text()
    for sentence in SENTENCES:
        assert sentence in text, sentence
    # the same order
    positions = [text.index(sentence) for sentence in SENTENCES]
    assert positions == sorted(positions), positions


def test_the_installer_prints_the_text_at_the_end_of_the_install():
    """The installer's closing text is part of the install's own ending,
    not a helper nobody calls."""
    source = INSTALLER.read_text(encoding="utf-8")
    assert "access_modes_closing" in source
    body = source[source.index("perform_install()"):]
    assert "access_modes_closing" in body


# -- 2. the docs say the same thing -----------------------------------------


def test_the_docs_carry_the_shared_text():
    """README.md, SETUP.md and SKILL.md carry the same sentences."""
    for name in DOCS:
        text = (REPO / name).read_text(encoding="utf-8")
        positions = []
        for sentence in SENTENCES:
            assert sentence in text, "%s misses: %s" % (name, sentence)
            positions.append(text.index(sentence))
        assert positions == sorted(positions), name


# -- 3. the numbers are the ones the tree holds -----------------------------


def test_the_numbers_in_the_shared_text_match_the_tree():
    """The file count and the size are measured from the sources the
    install uploads, never written by hand."""
    count, total = installed_program()
    kilobytes = (total + 512) // 1024
    sentence = INSTALLED_SENTENCES[0]
    found = re.search(r"\((\d+) files, about (\d+) KB\)", sentence)
    assert found, sentence
    assert int(found.group(1)) == count, (sentence, count)
    assert int(found.group(2)) == kilobytes, (sentence, kilobytes)


def test_the_shared_text_does_not_claim_more_than_the_code_does():
    """The text says "no packages and no compiled code": the files the
    install uploads are shell scripts, and nothing else is written to
    /usr/libexec."""
    proc = subprocess.run(
        ["bash", "-c",
         'source "$1"; for row in "${CODE_FILES[@]}" "${EXTRA_FILES[@]}"; do '
         'IFS="|" read -r rel remote mode rotate <<<"$row"; '
         'printf "%s\\n" "$rel"; done',
         "bash", str(TOOL)],
        capture_output=True, text=True, timeout=120, env=clean_env())
    assert proc.returncode == 0, proc.stderr
    for rel in proc.stdout.splitlines():
        path = REPO / rel
        data = path.read_bytes()
        assert not data.startswith(b"\x7fELF"), rel
        assert data.startswith(b"#!"), rel


def test_the_install_guide_offers_the_choice_of_mode():
    """docs/INSTALL.md step 7e gives the owner the choice: the no-install
    command and the installed command, and says which one is the default."""
    text = (REPO / "docs/INSTALL.md").read_text(encoding="utf-8")
    step = text.index("**7e.**")
    after = text[step:text.index("**7f.**")]
    assert "newton-router-setup router1 no-install" in after, after
    assert "newton-router-setup router1 install" in after, after
    assert "newton-router-setup router1 swap-key --new-key newton-agent" \
        in after, after
    # the no-install mode is the default for a new OpenWrt router
    assert "default" in after, after
    # and it is not as safe as the installed mode (ADR consequences)
    assert "not" in after and "as safe as the installed mode" in after, after


def test_the_install_guide_carries_the_shared_text():
    """docs/INSTALL.md carries the ten sentences too: the installer's
    closing text is the same text."""
    text = (REPO / "docs/INSTALL.md").read_text(encoding="utf-8")
    positions = []
    for sentence in SENTENCES:
        assert sentence in text, sentence
        positions.append(text.index(sentence))
    assert positions == sorted(positions)


# -- 4. the sentences are pinned to the code they describe ------------------


def test_the_uninstall_sentence_says_what_the_uninstall_really_does(setup_env):
    """The sentence about the uninstall is checked against the code: an
    install and then an uninstall on the fake router, and what is left
    is exactly what the sentence says is kept -- every kept thing, not
    a subset of them (review item 2: the sentence named two of the
    seven and was false by omission)."""
    env = setup_env
    seed_known_hosts(env)
    install = env.run(env.device, "install", typed=(GOOD_PW, YES))
    assert install.rc == 0, install.out
    fs = env.router.root / "fs"
    # the guard's saved copies of the router's settings, as a run of the
    # guard leaves them, the rest of the config dir (the guard's lock
    # and log), the copy of the keys from before swap-key and the
    # run-time files (they are in memory and go at the next reboot)
    (fs / "etc/newton/lkg/txn1").mkdir(parents=True)
    (fs / "etc/newton/lkg/txn1/network").write_text("saved\n")
    (fs / "etc/newton/quarantine").mkdir(parents=True)
    (fs / "etc/newton/guard.log").write_text("log\n")
    (fs / "etc/newton/lock").write_text("lock\n")
    prev = fs / "etc/dropbear/authorized_keys.newton-prev"
    prev.parent.mkdir(parents=True, exist_ok=True)
    prev.write_text("ssh-ed25519 AAAA one\n")
    (fs / "tmp/newton").mkdir(parents=True, exist_ok=True)
    (fs / "tmp/owrt-safe-apply.lock").write_text("lock\n")
    # the WAN-health run-time state, as the health check leaves it: the
    # state file of a tracked WAN and the all-down flag
    wan_state = _plant_wan_state(fs)
    keys = fs / "etc/dropbear/authorized_keys"
    keys.parent.mkdir(parents=True, exist_ok=True)
    keys.write_text(
        'command="/usr/libexec/newton/newton-router plan" ssh-ed25519 AAAA one\n'
        "ssh-ed25519 BBBB two\n")
    uninstall = env.run(env.device, "uninstall", typed=(GOOD_PW,))
    assert uninstall.rc == 0, uninstall.out + uninstall.err
    # the program is gone
    for path in ("usr/libexec/newton/newton-router",
                 "usr/libexec/newton/newton-safe-apply",
                 "usr/libexec/newton/newton-wan-health",
                 "usr/libexec/newton-guard",
                 "etc/init.d/newton-guard",
                 "etc/init.d/newton-wan-health"):
        assert not (fs / path).exists(), path
    # the key line is gone and the owner's own line is not
    left = keys.read_text()
    assert "newton-router" not in left, left
    assert "BBBB" in left, left
    # and everything an uninstall keeps on purpose is kept, all of it
    for path in ("etc/newton/lkg/txn1/network",
                 "etc/newton/quarantine",
                 "etc/newton/guard.log",
                 "etc/newton/lock",
                 "usr/libexec/newton",
                 "etc/config/newton_wanhealth",
                 "etc/dropbear/authorized_keys.newton-prev",
                 "etc/sysupgrade.conf",
                 "tmp/newton",
                 "tmp/owrt-safe-apply.lock"):
        assert (fs / path).exists(), path
    # the WAN-health run-time state does NOT survive: the uninstall
    # stops the health check first, and its restore removes the state
    # files.  The directory itself stays.
    assert not (wan_state / "wan.state").exists(), (
        "the stop path must remove the WAN-health state file")
    assert not (wan_state / "all_down.flag").exists(), (
        "the stop path must remove the all-down flag")
    assert wan_state.is_dir(), "the state directory itself stays"
    # the sysupgrade file stays, and the Newton lines are gone out of it
    sysupgrade = (fs / "etc/sysupgrade.conf").read_text()
    assert "/usr/libexec/newton/newton-router" not in sysupgrade, sysupgrade
    # and the sentence the tool really prints names every one of them
    sentence = setup_closing_lines()[-1]
    assert sentence.startswith("installed: "), sentence
    sentence = sentence[len("installed: "):]
    assert "/etc/newton" in sentence, sentence
    assert "/etc/config/newton_wanhealth" in sentence, sentence
    for kept in ("saved settings", "lock and log", "program directory",
                 "WAN-health settings", "keys from before swap-key",
                 "sysupgrade file"):
        assert kept in sentence, (kept, sentence)
    # the sentence must not claim the run-time files: the WAN-health
    # stop deletes them
    assert "run-time files" not in sentence, sentence


# The WAN-health run-time state, as the health check leaves it: the
# state file of a tracked WAN and the all-down flag.
WAN_STATE = ("s_dev=wan\ns_gw=192.0.2.1\ns_metric=10\ns_fail=0\n"
             "s_good=1\ns_mark=up\ns_active=1\n")


def _plant_wan_state(fs) -> Path:
    """The WAN-health run-time state in the fake router fs."""
    state = fs / "var/run/newton-wan-health"
    state.mkdir(parents=True, exist_ok=True)
    (state / "wan.state").write_text(WAN_STATE)
    (state / "all_down.flag").write_text("")
    return state


def test_the_real_stop_path_removes_the_wan_health_state_files(tmp_path):
    """The stop path the uninstall really runs: the init's stop runs
    the daemon's restore, and the restore removes the run-time state
    files (every *.state file and all_down.flag) and leaves the
    directory."""
    state = tmp_path / "newton-wan-health"
    state.mkdir()
    (state / "wan.state").write_text(WAN_STATE)
    (state / "all_down.flag").write_text("")
    proc = subprocess.run(
        ["sh", str(REPO / "scripts/newton-wan-health.sh"), "restore"],
        capture_output=True, text=True, timeout=60,
        env=dict(__import__("os").environ,
                 NEWTON_WAN_HEALTH_STATE=str(state)))
    assert proc.returncode == 0, proc.stderr
    assert list(state.iterdir()) == [], "the stop path must remove them"


def test_the_wan_health_init_stops_with_the_restore():
    """The init script the install puts on the router stops with the
    daemon's restore: that is the stop path the uninstall drives."""
    init = (REPO / "scripts/newton-wan-health.init").read_text()
    assert "newton-wan-health restore" in init, init


def test_the_uninstall_sentence_points_at_a_list_that_names_every_leftover():
    """The setup's own detailed block names every leftover, path and
    all: the things an uninstall keeps and the run-time files that do
    not survive it."""
    proc = subprocess.run(
        ["bash", "-c",
         'source "$1"; router_disclosure_block "$DEFAULT_SRC"',
         "bash", str(TOOL)],
        capture_output=True, text=True, timeout=120, env=clean_env())
    assert proc.returncode == 0, proc.stderr
    block = proc.stdout
    for path in ("/etc/newton/lkg",
                 "/etc/newton/quarantine",
                 "/usr/libexec/newton",
                 "/etc/config/newton_wanhealth",
                 "/etc/dropbear/authorized_keys.newton-prev",
                 "/etc/sysupgrade.conf",
                 "/tmp/newton",
                 "/tmp/owrt-safe-apply.lock",
                 "/var/run/newton-wan-health"):
        assert path in block, path
    # and it says what the WAN-health stop removes: the run-time state
    # in /var/run/newton-wan-health does not survive the uninstall
    assert "all_down.flag" in block, block
    assert "*.state" in block, block
    # the block must not claim that the run-time files all survive
    assert ("/var/run/newton-wan-health are in memory"
            not in block), block


def test_the_guard_sentence_says_what_the_guard_does_at_boot():
    """The sentence about the guard is checked against the guard's own
    boot command: it puts the last good settings back only when a change
    is still waiting for confirmation."""
    guard = (REPO / "device/openwrt/newton-guard/newton-guard").read_text()
    start = guard.index("boot_cmd() {")
    body = guard[start:guard.index("\n}\n", start)]
    # no pending transaction: the boot command returns without restoring
    assert '[ ! -f "$NG/pending" ]' in body
    # a pending transaction: the sealed pre-change copy is put back
    assert "restore_core boot" in body
    sentence = INSTALLED_SENTENCES[2]
    assert "still waiting for confirmation at boot" in sentence, sentence
