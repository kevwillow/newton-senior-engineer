"""The doctor's Claude Code debug-logging warning.

ADR-019: a typed approval passphrase lands in ~/.claude/debug when Claude
Code debug logging is on, and the agent can read it from there.  The
doctor warns about that; it never fails the install.

The check reads the invoking owner's files only: the home of $SUDO_USER,
found with getent, is the only place it looks, and nothing in that home
is executed.  Uses the NEWTON_DOCTOR_* seams of the shared doctor_env
fixture (fake root, fake sudo and ssh) plus a fake getent on PATH.
"""

import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_newton_isolation import DOCTOR, doctor_env, run  # noqa: E402


WARNING = (
    "Claude Code debug logging looks enabled: a typed approval passphrase "
    "lands in ~/.claude/debug where the agent can read it. Turn it off and "
    "rotate the passphrase (newton-enrol rotate <device>) if you approved "
    "while it was on."
)


@pytest.fixture
def owner_home(tmp_path):
    """The home of the owner who invoked the doctor."""
    home = tmp_path / "owner-home"
    home.mkdir()
    return home


@pytest.fixture
def owner_env(doctor_env, owner_home, tmp_path):
    """The doctor environment with SUDO_USER set and a fake getent.

    The fake getent answers the passwd lookup with the fake owner home,
    so the check reads the fixture's files and nothing of the real host.
    """
    bindir = tmp_path / "shim"
    bindir.mkdir()
    getent = bindir / "getent"
    getent.write_text(
        "#!/bin/sh\n"
        "if [ \"$1\" = passwd ]; then\n"
        "  printf 'owner:x:1000:1000::OWNER_HOME:/bin/bash\\n'\n"
        "  exit 0\n"
        "fi\n"
        "exit 2\n".replace("OWNER_HOME", str(owner_home))
    )
    getent.chmod(0o755)
    env = doctor_env["env"].copy()
    env["PATH"] = f"{bindir}:{env['PATH']}"
    env["SUDO_USER"] = "owner"
    return env


def _write_newer(path, content="typed approval passphrase: hunter2\n"):
    """Write *content* to *path* and make the file newer than the install."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    stamp = time.time() + 120
    os.utime(path, (stamp, stamp))
    return path


def test_doctor_warns_when_a_debug_log_is_newer_than_the_install(owner_env, owner_home):
    _write_newer(owner_home / ".claude/debug/session.log")

    result = run(DOCTOR, "--router", "root@192.0.2.1", env=owner_env)

    assert result.returncode == 3, result.stdout + result.stderr
    assert "INCONCLUSIVE claude-debug-logging" in result.stdout
    assert WARNING in result.stdout
    # a warning never fails the install
    assert "FAIL claude-debug-logging" not in result.stdout


def test_doctor_warns_when_the_settings_turn_the_debug_log_on(owner_env, owner_home):
    settings = owner_home / ".claude/settings.json"
    settings.parent.mkdir(parents=True)
    settings.write_text('{"debug": true}\n')

    result = run(DOCTOR, "--router", "root@192.0.2.1", env=owner_env)

    assert result.returncode == 3, result.stdout + result.stderr
    assert "INCONCLUSIVE claude-debug-logging" in result.stdout
    assert WARNING in result.stdout


def test_doctor_warns_when_the_local_settings_turn_the_debug_log_on(owner_env, owner_home):
    settings = owner_home / ".claude/settings.local.json"
    settings.parent.mkdir(parents=True)
    settings.write_text('{\n  "debug":true\n}\n')

    result = run(DOCTOR, "--router", "root@192.0.2.1", env=owner_env)

    assert result.returncode == 3, result.stdout + result.stderr
    assert "INCONCLUSIVE claude-debug-logging" in result.stdout


def test_doctor_warns_when_the_environment_turns_the_debug_log_on(owner_env):
    env = owner_env.copy()
    env["DEBUG"] = "1"

    result = run(DOCTOR, "--router", "root@192.0.2.1", env=env)

    assert result.returncode == 3, result.stdout + result.stderr
    assert "INCONCLUSIVE claude-debug-logging" in result.stdout
    assert WARNING in result.stdout


def test_doctor_warns_when_the_claude_debug_environment_variable_is_set(owner_env):
    env = owner_env.copy()
    env["CLAUDE_CODE_DEBUG"] = "1"

    result = run(DOCTOR, "--router", "root@192.0.2.1", env=env)

    assert result.returncode == 3, result.stdout + result.stderr
    assert "INCONCLUSIVE claude-debug-logging" in result.stdout


def test_doctor_passes_on_a_clean_owner_home(owner_env):
    result = run(DOCTOR, "--router", "root@192.0.2.1", env=owner_env)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS claude-debug-logging" in result.stdout
    assert "INCONCLUSIVE claude-debug-logging" not in result.stdout
    assert "FAIL claude-debug-logging" not in result.stdout


def test_doctor_ignores_a_debug_log_older_than_the_install(owner_env, owner_home):
    # a debug log from before Newton was installed cannot have caught an
    # approval typed after it
    debug = owner_home / ".claude/debug/session.log"
    debug.parent.mkdir(parents=True)
    debug.write_text("old log\n")
    stamp = time.time() - 3600
    os.utime(debug, (stamp, stamp))

    result = run(DOCTOR, "--router", "root@192.0.2.1", env=owner_env)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS claude-debug-logging" in result.stdout


def test_doctor_reads_home_when_run_as_the_owner_without_sudo(doctor_env, owner_home):
    env = doctor_env["env"].copy()
    env.pop("SUDO_USER", None)
    env["HOME"] = str(owner_home)
    _write_newer(owner_home / ".claude" / "debug" / "latest.txt")

    result = run(DOCTOR, "--router", "root@192.0.2.1", env=env)

    assert result.returncode == 3, result.stdout + result.stderr
    assert "INCONCLUSIVE claude-debug-logging" in result.stdout
    assert WARNING in result.stdout
    assert "PASS claude-debug-logging" not in result.stdout


def test_doctor_passes_from_a_clean_home_without_sudo(doctor_env, owner_home):
    env = doctor_env["env"].copy()
    env.pop("SUDO_USER", None)
    env["HOME"] = str(owner_home)

    result = run(DOCTOR, "--router", "root@192.0.2.1", env=env)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS claude-debug-logging" in result.stdout


def test_doctor_reads_only_the_owners_home(owner_env, owner_home, tmp_path):
    # a debug log of another user must not make the doctor warn
    other = tmp_path / "other-home/.claude/debug"
    other.mkdir(parents=True)
    _write_newer(other / "session.log")

    result = run(DOCTOR, "--router", "root@192.0.2.1", env=owner_env)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS claude-debug-logging" in result.stdout
