"""The Active Directory approval on an INSTALLED Newton.

Two launchers carry it, both run as the newton user through the owner's
own sudo, in a clean environment, like newton-router-setup:

* /usr/local/bin/newton-approve takes ``ad-change <32-hex plan id>`` as
  well as a lone plan id, checks both words and passes both on;
* /usr/local/bin/newton-ad-setup takes ``approval-key <device>`` and
  nothing else, and records the fingerprint in the newton user's state
  directory, the one newton-approve reads.

Every test runs the repo scripts with fakes for /usr/bin/id (and, where
the test only looks at the argv, /usr/bin/env); nothing touches the
real system.
"""

import os
import pty
import re
import select
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_newton_isolation import (  # noqa: E402
    INSTALL,
    install_test_env,
    launcher_text,
    make_executable,
    run,
)

ROOT = Path(__file__).resolve().parents[2]
PLAN_ID = "0123456789abcdef0123456789abcdef"
CLEAN_PATH = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


def make_fake_id(tmp_path):
    fake_id = tmp_path / "id"
    make_executable(
        fake_id,
        "#!/bin/sh\n"
        'if [ "${2:-}" = newton ]; then echo 4242; else echo "${FAKE_UID:-4242}"; fi\n',
    )
    return fake_id


def make_launcher(tmp_path, slot, name, fake_env=True, replace=()):
    """The launcher of ``slot`` with /usr/bin/id swapped for a fake and,
    when ``fake_env`` is set, /usr/bin/env swapped for one that prints its
    own argv."""
    text = launcher_text(slot).replace("/usr/bin/id", str(make_fake_id(tmp_path)))
    if fake_env:
        printer = tmp_path / "env"
        make_executable(printer, "#!/bin/sh\nprintf '%s\\n' \"$@\"\n")
        text = text.replace("/usr/bin/env", str(printer))
    for old, new in replace:
        assert old in text, old
        text = text.replace(old, new)
    launcher = tmp_path / name
    make_executable(launcher, text)
    return launcher


def owner_env(sudo_user="labuser"):
    env = os.environ.copy()
    if sudo_user is None:
        env.pop("SUDO_USER", None)
    else:
        env["SUDO_USER"] = sudo_user
    return env


# ---- newton-approve ad-change <plan_id> ----


def test_approve_launcher_passes_ad_change_and_the_plan_id(tmp_path):
    launcher = make_launcher(tmp_path, "approve_launcher_tmp", "newton-approve")

    result = run(launcher, "ad-change", PLAN_ID, env=owner_env())

    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [
        "-i",
        "NEWTON_HOME=/opt/newton",
        "NEWTON_STATE_DIR=/var/lib/newton/state",
        "NEWTON_INVENTORY=/var/lib/newton/devices.toml",
        "HOME=/var/lib/newton",
        CLEAN_PATH,
        "SUDO_USER=labuser",
        "/opt/newton/venv/bin/newton-approve",
        "ad-change",
        PLAN_ID,
    ]


def test_approve_launcher_still_passes_a_lone_plan_id(tmp_path):
    launcher = make_launcher(tmp_path, "approve_launcher_tmp", "newton-approve")

    result = run(launcher, PLAN_ID, env=owner_env())

    assert result.returncode == 0, result.stderr
    lines = result.stdout.splitlines()
    assert lines[-2:] == ["/opt/newton/venv/bin/newton-approve", PLAN_ID]


@pytest.mark.parametrize(
    "args",
    [
        pytest.param((), id="nothing"),
        pytest.param(("ad-change",), id="no-id"),
        pytest.param(("ad-change", "BAD"), id="short-id"),
        pytest.param(("ad-change", PLAN_ID.upper()), id="upper-hex"),
        pytest.param(("ad-change", PLAN_ID + "0"), id="long-id"),
        pytest.param(("ad-change", PLAN_ID[:-1] + "g"), id="not-hex"),
        pytest.param(("ad-change", PLAN_ID, "x"), id="extra-word"),
        pytest.param(("ad-chang", PLAN_ID), id="other-verb"),
        pytest.param((PLAN_ID, "ad-change"), id="swapped"),
        pytest.param((PLAN_ID, PLAN_ID), id="two-ids"),
        pytest.param(("ad-change", "--help"), id="flag"),
        pytest.param(("ad-change", "$(touch pwned)"), id="hostile"),
    ],
)
def test_approve_launcher_refuses_every_other_form(tmp_path, args):
    launcher = make_launcher(tmp_path, "approve_launcher_tmp", "newton-approve")

    result = run(launcher, *args, env=owner_env())

    assert result.returncode == 2, result.stdout + result.stderr
    assert "newton-approve:" in result.stderr
    # the fake env never ran: nothing reached newton-approve
    assert result.stdout == ""
    assert not (tmp_path / "pwned").exists()


def test_approve_launcher_ad_change_still_needs_newton_and_sudo_user(tmp_path):
    launcher = make_launcher(tmp_path, "approve_launcher_tmp", "newton-approve")

    wrong_uid = owner_env()
    wrong_uid["FAKE_UID"] = "9999"
    result = run(launcher, "ad-change", PLAN_ID, env=wrong_uid)
    assert result.returncode == 1
    assert "newton-approve: must run as user newton" in result.stderr

    result = run(launcher, "ad-change", PLAN_ID, env=owner_env("root"))
    assert result.returncode == 1
    assert "valid non-root SUDO_USER" in result.stderr


def test_approve_launcher_preview_names_the_ad_change_form(tmp_path):
    result = run(INSTALL, "--check", env=install_test_env(tmp_path))
    assert result.returncode == 0, result.stderr
    assert (
        "Would install launcher: /usr/local/bin/newton-approve "
        "(root:root 0755; clean environment; newton user only; "
        "one 32-hex argument, or ad-change and one 32-hex argument)"
    ) in result.stdout


# ---- newton-ad-setup approval-key <device> as the newton user ----


AD_SLOT = "ad_setup_launcher_tmp"


def test_ad_setup_launcher_runs_approval_key_in_the_newton_state_dir(tmp_path):
    launcher = make_launcher(tmp_path, AD_SLOT, "newton-ad-setup")
    env = owner_env()
    env["NEWTON_STATE_DIR"] = "/poisoned/from/caller"
    env["PYTHONPATH"] = "/poisoned/from/caller"

    result = run(launcher, "approval-key", "dc1", env=env)

    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [
        "-i",
        "NEWTON_HOME=/opt/newton",
        "NEWTON_STATE_DIR=/var/lib/newton/state",
        "HOME=/var/lib/newton",
        CLEAN_PATH,
        "SUDO_USER=labuser",
        "/opt/newton/venv/bin/python",
        "-I",
        "-m",
        "newton_mcp.ad.setupgen_write",
        "approval-key",
        "dc1",
    ]


def test_ad_setup_launcher_writes_where_newton_approve_reads():
    def state_dir_of(slot):
        found = re.findall(r"NEWTON_STATE_DIR=(\S+)", launcher_text(slot))
        assert len(found) == 1, (slot, found)
        return found[0].rstrip("\\").strip()

    assert state_dir_of(AD_SLOT) == state_dir_of("approve_launcher_tmp")


def test_ad_setup_launcher_runs_only_as_newton(tmp_path):
    launcher = make_launcher(tmp_path, AD_SLOT, "newton-ad-setup")
    env = owner_env()
    env["FAKE_UID"] = "9999"

    result = run(launcher, "approval-key", "dc1", env=env)

    assert result.returncode == 1
    assert "newton-ad-setup: must run as user newton" in result.stderr
    assert result.stdout == ""


@pytest.mark.parametrize("bad", [None, "root", "1evil", "evil name"])
def test_ad_setup_launcher_refuses_bad_sudo_user(tmp_path, bad):
    launcher = make_launcher(tmp_path, AD_SLOT, "newton-ad-setup")

    result = run(launcher, "approval-key", "dc1", env=owner_env(bad))

    assert result.returncode == 1, bad
    assert "valid non-root SUDO_USER" in result.stderr
    assert result.stdout == ""


@pytest.mark.parametrize(
    "args",
    [
        pytest.param((), id="nothing"),
        pytest.param(("approval-key",), id="no-device"),
        pytest.param(("approval-key", "Dc1"), id="upper"),
        pytest.param(("approval-key", "1dc"), id="digit-first"),
        pytest.param(("approval-key", "a" * 33), id="too-long"),
        pytest.param(("approval-key", "dc1", "dc2"), id="two-devices"),
        pytest.param(("approval-key", "-h"), id="flag"),
        pytest.param(("approval-key", "dc 1"), id="space"),
        pytest.param(("approval-key", "$(touch pwned)"), id="hostile"),
        pytest.param(
            ("write", "windows", "--domain", "x.test", "--pubkey",
             "/var/lib/newton/keys/k", "--device", "dc1", "--host", "h",
             "--ou", "OU=a,DC=x,DC=test"),
            id="write",
        ),
        pytest.param(("windows", "--pubkey", "/var/lib/newton/keys/k"), id="audit"),
    ],
)
def test_ad_setup_launcher_takes_approval_key_and_one_device_only(tmp_path, args):
    launcher = make_launcher(tmp_path, AD_SLOT, "newton-ad-setup")

    result = run(launcher, *args, env=owner_env())

    assert result.returncode == 2, result.stdout + result.stderr
    assert "newton-ad-setup:" in result.stderr
    assert result.stdout == ""
    assert not (tmp_path / "pwned").exists()


def test_ad_setup_launcher_device_may_be_32_characters(tmp_path):
    launcher = make_launcher(tmp_path, AD_SLOT, "newton-ad-setup")
    device = "a" + "b-9" * 10 + "c"
    assert len(device) == 32

    result = run(launcher, "approval-key", device, env=owner_env())

    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines()[-1] == device


def test_ad_setup_launcher_cds_to_root_before_exec(tmp_path):
    fake_id = make_fake_id(tmp_path)
    fake_env = tmp_path / "env"
    make_executable(fake_env, "#!/bin/sh\npwd -P\n")
    launcher = tmp_path / "newton-ad-setup"
    make_executable(
        launcher,
        launcher_text(AD_SLOT)
        .replace("/usr/bin/id", str(fake_id))
        .replace("/usr/bin/env", str(fake_env)),
    )

    result = subprocess.run(
        [str(launcher), "approval-key", "dc1"], text=True, capture_output=True,
        env=owner_env(), cwd=tmp_path, timeout=10,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "/"
    text = launcher_text(AD_SLOT)
    assert re.search(r"\ncd /\nexec /usr/bin/env -i \\\n", text)


def test_ad_setup_launcher_refuses_without_a_terminal(tmp_path):
    """The real exec line, with the venv python of this test run in place
    of /opt/newton/venv/bin/python: the module runs under -I and refuses a
    stdin that is not a terminal, before it writes anything."""
    state = tmp_path / "state"
    launcher = make_launcher(
        tmp_path, AD_SLOT, "newton-ad-setup", fake_env=False,
        replace=(
            ("/opt/newton/venv/bin/python", sys.executable),
            ("/var/lib/newton/state", str(state)),
        ),
    )

    result = subprocess.run(
        [str(launcher), "approval-key", "dc1"], text=True, capture_output=True,
        env=owner_env(), stdin=subprocess.DEVNULL, timeout=60,
    )

    assert result.returncode == 2, result.stdout + result.stderr
    assert "the approval passphrase must be read from a terminal" in result.stderr
    assert not (state / "approval-fp").exists()


def _drive_pty(argv, env, answers, timeout=120):
    """Run argv on a new pseudo-terminal, answer each prompt in turn and
    return (exit status, everything printed)."""
    pid, fd = pty.fork()
    if pid == 0:  # pragma: no cover - the child
        try:
            os.execve(argv[0], argv, env)
        finally:
            os._exit(127)
    output = b""
    pending = list(answers)
    deadline = time.monotonic() + timeout
    try:
        while time.monotonic() < deadline:
            ready, _w, _x = select.select([fd], [], [], 0.5)
            if not ready:
                continue
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                break
            if not chunk:
                break
            output += chunk
            while pending and output.count(b": ") > len(answers) - len(pending):
                os.write(fd, pending.pop(0))
    finally:
        os.close(fd)
    _pid, status = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(status), output.decode(errors="replace")


def test_ad_setup_launcher_fingerprint_is_the_one_newton_approve_checks(tmp_path):
    """End to end on a terminal: the fingerprint the AD launcher records
    is in the state directory the approve launcher hands newton-approve,
    and it is the fingerprint of the passphrase the owner typed."""
    from newton_mcp.approve import approval_fingerprint, derive_k

    state = tmp_path / "var-lib-newton-state"
    launcher = make_launcher(
        tmp_path, AD_SLOT, "newton-ad-setup", fake_env=False,
        replace=(
            ("/opt/newton/venv/bin/python", sys.executable),
            ("/var/lib/newton/state", str(state)),
        ),
    )
    env = owner_env()
    env.pop("NEWTON_STATE_DIR", None)

    code, output = _drive_pty(
        [str(launcher), "approval-key", "dc1"], env,
        [b"correct horse\n", b"correct horse\n"],
    )

    expected = approval_fingerprint(derive_k(b"correct horse", "dc1"))
    assert code == 0, output
    assert expected in output
    recorded = state / "approval-fp" / "dc1"
    assert recorded.read_text() == f"v1 {expected}\n"
    assert (recorded.stat().st_mode & 0o777) == 0o600


def test_ad_setup_launcher_is_installed_and_listed(tmp_path):
    source = INSTALL.read_text()
    assert 'ad_setup_launcher_tmp=$(mktemp "${AD_SETUP_LAUNCHER}.new.XXXXXX")' in source
    assert 'install -o root -g root -m 0755 "$ad_setup_launcher_tmp" "$AD_SETUP_LAUNCHER"' \
        in source
    assert "AD_SETUP_LAUNCHER=/usr/local/bin/newton-ad-setup" in source

    result = run(INSTALL, "--check", env=install_test_env(tmp_path))
    assert result.returncode == 0, result.stderr
    assert (
        "Would install launcher: /usr/local/bin/newton-ad-setup "
        "(root:root 0755; clean environment; newton user only; "
        "approval-key and one device name)"
    ) in result.stdout
    lines = result.stdout.splitlines()
    assert "agent ALL=(newton) /usr/local/bin/newton-ad-setup" in lines
    assert "Defaults!/usr/local/bin/newton-ad-setup timestamp_timeout=0" in lines
    assert not [
        line for line in lines
        if "newton-ad-setup" in line and "NOPASSWD" in line
    ]


# ---- scripts/newton-ad-setup on the installed code root ----


def test_ad_setup_script_uses_the_installed_venv(tmp_path):
    """/opt/newton/scripts/newton-ad-setup, run by the owner for the
    audit and write scripts, uses /opt/newton/venv/bin/python when the
    code root has no mcp/.venv."""
    code_root = tmp_path / "opt-newton"
    (code_root / "scripts").mkdir(parents=True)
    (code_root / "mcp").mkdir()
    shutil.copy2(ROOT / "scripts/newton-ad-setup", code_root / "scripts/newton-ad-setup")
    (code_root / "venv/bin").mkdir(parents=True)
    make_executable(
        code_root / "venv/bin/python",
        "#!/bin/sh\nprintf 'venv %s\\n' \"$*\"\n",
    )
    env = os.environ.copy()
    env.pop("NEWTON_PYTHON", None)

    result = run(code_root / "scripts/newton-ad-setup", "windows", "--domain", "x.test", env=env)

    assert result.returncode == 0, result.stderr
    assert result.stdout == "venv -m newton_mcp.ad.setupgen windows --domain x.test\n"


# ---- the docs name the installed forms ----


def test_skill_ad_section_names_the_installed_commands():
    text = (ROOT / "SKILL.md").read_text()
    start = text.index("\n## Active Directory\n")
    end = text.find("\n## ", start + 1)
    section = text[start:] if end == -1 else text[start:end]
    assert "sudo -u newton /usr/local/bin/newton-approve ad-change <plan_id>" in section
    assert "sudo -u newton /usr/local/bin/newton-ad-setup approval-key <device>" in section
    # every newton-approve ad-change the section names is the sudo form
    for match in re.finditer(r"newton-approve ad-change", section):
        before = section[max(0, match.start() - len("sudo -u newton /usr/local/bin/")):match.start()]
        assert before == "sudo -u newton /usr/local/bin/", section[match.start() - 40:match.end()]
