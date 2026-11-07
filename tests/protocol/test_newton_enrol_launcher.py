"""The newton-enrol launcher and its sudoers rule.

newton-enrol is the owner's own terminal tool: it enrols a TOTP
authenticator, rotates the approval passphrase and ends an easy grant.
The seed and the passphrase are secrets the agent must never see, so the
launcher runs as the newton user only, through the owner's own sudo, in a
clean environment.

Every test runs the repo scripts with the NEWTON_INSTALL_ROOT /
NEWTON_DOCTOR_* seams only; nothing touches the real system.
"""

import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_newton_isolation import (  # noqa: E402
    INSTALL,
    install_test_env,
    launcher_text,
    make_executable,
    run,
)


def enrol_launcher_text():
    return launcher_text("enrol_launcher_tmp")


def make_fake_id_env(tmp_path):
    """A fake /usr/bin/id (newton has uid 4242) and a fake /usr/bin/env
    that prints its own argv, so a test can see the clean environment the
    launcher hands to newton-enrol."""
    fake_id = tmp_path / "id"
    make_executable(
        fake_id,
        "#!/bin/sh\n"
        'if [ "${2:-}" = newton ]; then echo 4242; else echo "${FAKE_UID:-4242}"; fi\n',
    )
    fake_env = tmp_path / "env"
    make_executable(fake_env, "#!/bin/sh\nprintf '%s\\n' \"$@\"\n")
    return fake_id, fake_env


def make_enrol_launcher(tmp_path):
    fake_id, fake_env = make_fake_id_env(tmp_path)
    launcher = tmp_path / "newton-enrol"
    text = (
        enrol_launcher_text()
        .replace("/usr/bin/id", str(fake_id))
        .replace("/usr/bin/env", str(fake_env))
    )
    make_executable(launcher, text)
    return launcher, fake_env


# ---- the launcher itself ----


def test_enrol_launcher_runs_only_as_newton(tmp_path):
    launcher, _env = make_enrol_launcher(tmp_path)

    # a valid SUDO_USER so the uid refusal is the only refusal proven
    wrong_env = os.environ.copy()
    wrong_env["SUDO_USER"] = "labuser"
    wrong_env["FAKE_UID"] = "9999"
    wrong_user = run(launcher, "totp", "r1", env=wrong_env)
    assert wrong_user.returncode == 1
    assert "newton-enrol: must run as user newton" in wrong_user.stderr
    # the fake env never ran: nothing was printed on stdout
    assert wrong_user.stdout == ""


def test_enrol_launcher_refuses_bad_sudo_user(tmp_path):
    launcher, _env = make_enrol_launcher(tmp_path)

    for bad in (None, "root", "1evil", "evil name"):
        env = os.environ.copy()
        if bad is None:
            env.pop("SUDO_USER", None)
        else:
            env["SUDO_USER"] = bad
        result = run(launcher, "totp", "r1", env=env)
        assert result.returncode == 1, bad
        assert "valid non-root SUDO_USER" in result.stderr


def test_enrol_launcher_passes_sudo_user_through_and_cleans_env(tmp_path):
    launcher, _fake_env = make_enrol_launcher(tmp_path)
    env = os.environ.copy()
    env["SUDO_USER"] = "labuser"
    env["NEWTON_INVENTORY"] = "/poisoned/from/caller"

    good = run(launcher, "totp", "r1", env=env)

    assert good.returncode == 0, good.stderr
    assert good.stdout.splitlines() == [
        "-i",
        "NEWTON_HOME=/opt/newton",
        "NEWTON_STATE_DIR=/var/lib/newton/state",
        "NEWTON_INVENTORY=/var/lib/newton/devices.toml",
        "NEWTON_KEYS_DIR=/var/lib/newton/keys",
        "HOME=/var/lib/newton",
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "SUDO_USER=labuser",
        "/opt/newton/venv/bin/newton-enrol",
        "totp",
        "r1",
    ]


def test_enrol_launcher_passes_no_arguments_through(tmp_path):
    # newton-enrol always takes a subcommand, but the launcher must not
    # invent one and must not refuse an empty argument list.
    launcher, _fake_env = make_enrol_launcher(tmp_path)
    env = os.environ.copy()
    env["SUDO_USER"] = "labuser"

    good = run(launcher, env=env)

    assert good.returncode == 0, good.stderr
    assert good.stdout.splitlines()[-1] == "/opt/newton/venv/bin/newton-enrol"
    assert len(good.stdout.splitlines()) == 9


def test_enrol_launcher_keeps_hostile_argument_as_one_word(tmp_path):
    launcher, _fake_env = make_enrol_launcher(tmp_path)
    env = os.environ.copy()
    env["SUDO_USER"] = "labuser"

    hostile = "a b *.c 'quoted' $(touch pwned)"
    good = run(launcher, hostile, env=env)

    assert good.returncode == 0, good.stderr
    lines = good.stdout.splitlines()
    tool_index = lines.index("/opt/newton/venv/bin/newton-enrol")
    assert lines[tool_index + 1] == hostile
    assert len(lines) == tool_index + 2
    assert not (tmp_path / "pwned").exists()


def test_enrol_launcher_is_listed_with_mode_in_preview(tmp_path):
    env = install_test_env(tmp_path)
    result = run(INSTALL, "--check", env=env)
    assert result.returncode == 0, result.stderr
    assert (
        "Would install launcher: /usr/local/bin/newton-enrol "
        "(root:root 0755; clean environment; newton user only; "
        "arguments passed through to newton-enrol)" in result.stdout
    )
    assert 'install -o root -g root -m 0755 "$enrol_launcher_tmp" "$ENROL_LAUNCHER"' \
        in INSTALL.read_text()


def test_enrol_sudoers_line_has_no_nopasswd_and_drops_timestamp(tmp_path):
    env = install_test_env(tmp_path)
    result = run(INSTALL, "--check", env=env)
    assert result.returncode == 0, result.stderr
    assert "agent ALL=(newton) /usr/local/bin/newton-enrol" in result.stdout
    assert (
        "Defaults!/usr/local/bin/newton-enrol timestamp_timeout=0"
        in result.stdout
    )
    enrol_lines = [
        line
        for line in result.stdout.splitlines()
        if "newton-enrol" in line and line.startswith("agent ALL=")
    ]
    assert enrol_lines == ["agent ALL=(newton) /usr/local/bin/newton-enrol"]


def test_enrol_launcher_runs_from_a_clean_root(tmp_path):
    # The FastMCP server reads ./.env from the cwd; the launcher must
    # therefore change to / before it execs the tool.
    launcher = tmp_path / "newton-enrol"
    fake_id, fake_env = make_fake_id_env(tmp_path)
    make_executable(fake_env, "#!/bin/sh\npwd -P\n")
    make_executable(
        launcher,
        enrol_launcher_text()
        .replace("/usr/bin/id", str(fake_id))
        .replace("/usr/bin/env", str(fake_env)),
    )
    env = os.environ.copy()
    env["SUDO_USER"] = "labuser"

    result = subprocess.run(
        [str(launcher), "totp", "r1"], text=True, capture_output=True,
        env=env, cwd=tmp_path, timeout=10,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "/", result.stdout + result.stderr


def test_enrol_launcher_template_cd_to_root_precedes_exec():
    text = enrol_launcher_text()
    cd_offset = text.index("cd /")
    exec_offset = text.index("exec /usr/bin/env -i")
    assert cd_offset < exec_offset
    line_start = text.rfind("\n", 0, cd_offset) + 1
    line_end = text.find("\n", cd_offset)
    assert text[line_start:line_end].strip() == "cd /"
    assert text[line_end:exec_offset].strip() == ""


def test_enrol_console_script_exists_in_the_installed_package():
    # The launcher execs /opt/newton/venv/bin/newton-enrol; the console
    # script has to be part of the package the installer builds.
    pyproject = (Path(__file__).resolve().parents[2] / "mcp" / "pyproject.toml").read_text()
    assert 'newton-enrol = "newton_mcp.enrol:main"' in pyproject
