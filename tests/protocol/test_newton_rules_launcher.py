"""The installed newton-rules launcher and its sudoers rule.

scripts/newton-rules reads the inventory from NEWTON_INVENTORY (default
~/.config/newton/devices.toml) and keeps rules.toml next to it.  On an
installed Newton the inventory is /var/lib/newton/devices.toml, owned by
the newton user, so the owner runs the tool through a launcher, like
newton-enrol: newton user only, a clean environment that names the
installed inventory, and a sudoers rule without NOPASSWD that drops the
timestamp cache.

Every test runs the repo scripts with the NEWTON_INSTALL_ROOT seam only;
nothing touches the real system.
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_newton_enrol_launcher import make_fake_id_env  # noqa: E402
from test_newton_isolation import (  # noqa: E402
    INSTALL,
    install_test_env,
    launcher_text,
    make_executable,
    run,
)


def make_rules_launcher(tmp_path):
    fake_id, fake_env = make_fake_id_env(tmp_path)
    launcher = tmp_path / "newton-rules"
    text = (
        launcher_text("rules_launcher_tmp")
        .replace("/usr/bin/id", str(fake_id))
        .replace("/usr/bin/env", str(fake_env))
    )
    make_executable(launcher, text)
    return launcher


def test_rules_launcher_runs_only_as_newton(tmp_path):
    launcher = make_rules_launcher(tmp_path)
    env = os.environ.copy()
    env["SUDO_USER"] = "labuser"
    env["FAKE_UID"] = "9999"
    result = run(launcher, "list", env=env)
    assert result.returncode == 1
    assert "newton-rules: must run as user newton" in result.stderr
    assert result.stdout == ""


def test_rules_launcher_refuses_bad_sudo_user(tmp_path):
    launcher = make_rules_launcher(tmp_path)
    for bad in (None, "root", "1evil", "evil name"):
        env = os.environ.copy()
        if bad is None:
            env.pop("SUDO_USER", None)
        else:
            env["SUDO_USER"] = bad
        result = run(launcher, "list", env=env)
        assert result.returncode == 1, bad
        assert "valid non-root SUDO_USER" in result.stderr


def test_rules_launcher_names_the_installed_inventory_in_a_clean_env(tmp_path):
    launcher = make_rules_launcher(tmp_path)
    env = os.environ.copy()
    env["SUDO_USER"] = "labuser"
    env["NEWTON_INVENTORY"] = "/poisoned/from/caller"
    hostile = "a b $(touch pwned)"

    result = run(launcher, "add", "r1", hostile, env=env)

    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [
        "-i",
        "NEWTON_INVENTORY=/var/lib/newton/devices.toml",
        "HOME=/var/lib/newton",
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "SUDO_USER=labuser",
        "/opt/newton/venv/bin/python",
        "-I",
        "/opt/newton/scripts/newton-rules",
        "add",
        "r1",
        hostile,
    ]
    assert not (tmp_path / "pwned").exists()


def test_rules_launcher_changes_to_root_before_exec():
    text = launcher_text("rules_launcher_tmp")
    assert text.index("\ncd /\n") < text.index("exec /usr/bin/env -i")


def test_rules_launcher_and_sudoers_rule_are_in_the_preview(tmp_path):
    result = run(INSTALL, "--check", env=install_test_env(tmp_path))
    assert result.returncode == 0, result.stderr
    lines = result.stdout.splitlines()
    assert (
        "Would install launcher: /usr/local/bin/newton-rules (root:root 0755; "
        "clean environment; newton user only; arguments passed through to newton-rules)"
        in lines
    )
    assert "agent ALL=(newton) /usr/local/bin/newton-rules" in lines
    assert "Defaults!/usr/local/bin/newton-rules timestamp_timeout=0" in lines
    assert not any("NOPASSWD" in line and "newton-rules" in line for line in lines)
    assert 'install -o root -g root -m 0755 "$rules_launcher_tmp" "$RULES_LAUNCHER"' \
        in INSTALL.read_text()


# ---- the doctor checks the launcher like the others ----

from test_newton_isolation import DOCTOR, doctor_env  # noqa: E402,F401


def test_doctor_fails_when_the_rules_launcher_is_missing(doctor_env):
    doctor_env["rules"].parent.chmod(0o755)
    doctor_env["rules"].unlink()
    doctor_env["rules"].parent.chmod(0o555)
    result = run(DOCTOR, "--router", "root@192.0.2.1", env=doctor_env["env"])
    assert result.returncode == 1
    assert any(
        line.startswith("FAIL code-not-writable: installed code or launcher is missing: ")
        and line.endswith("/usr/local/bin/newton-rules")
        for line in result.stdout.splitlines()
    ), result.stdout


def test_doctor_fails_when_the_rules_launcher_is_writable(doctor_env):
    doctor_env["rules"].chmod(0o777)
    result = run(DOCTOR, "--router", "root@192.0.2.1", env=doctor_env["env"])
    assert result.returncode == 1
    assert any(
        line.startswith("FAIL code-not-writable") and "newton-rules" in line
        for line in result.stdout.splitlines()
    ), result.stdout
