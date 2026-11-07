"""R2 ap2: the newton-router-setup launcher, its sudoers line and the
installed router sources in scripts/newton-install (design 7.2 row INST).

Every test runs the repo scripts with the NEWTON_INSTALL_ROOT /
NEWTON_DOCTOR_* seams only; nothing touches the real system.
"""

import os
import re
import stat
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_newton_isolation import (  # noqa: E402
    INSTALL,
    install_test_env,
    launcher_text,
    make_executable,
    make_install_repo,
    rootless_root_command,
    run,
    run_make_snapshot,
)

ROOT = Path(__file__).resolve().parents[2]


def setup_launcher_text():
    return launcher_text("setup_launcher_tmp")


def make_fake_id_env(tmp_path):
    fake_id = tmp_path / "id"
    make_executable(
        fake_id,
        "#!/bin/sh\n"
        'if [ "${2:-}" = newton ]; then echo 4242; else echo "${FAKE_UID:-4242}"; fi\n',
    )
    fake_env = tmp_path / "env"
    make_executable(fake_env, "#!/bin/sh\nprintf '%s\\n' \"$@\"\n")
    return fake_id, fake_env


def make_setup_launcher(tmp_path):
    fake_id, fake_env = make_fake_id_env(tmp_path)
    launcher = tmp_path / "newton-router-setup"
    text = (
        setup_launcher_text()
        .replace("/usr/bin/id", str(fake_id))
        .replace("/usr/bin/env", str(fake_env))
    )
    make_executable(launcher, text)
    return launcher, fake_env


# ---- the launcher itself ----


def test_setup_launcher_runs_only_as_newton(tmp_path):
    launcher, _env = make_setup_launcher(tmp_path)

    # a valid SUDO_USER so the uid refusal is the only refusal proven
    wrong_env = os.environ.copy()
    wrong_env["SUDO_USER"] = "labuser"
    wrong_env["FAKE_UID"] = "9999"
    wrong_user = run(launcher, "r1", "check", env=wrong_env)
    assert wrong_user.returncode == 1
    assert "newton-router-setup: must run as user newton" in wrong_user.stderr
    # the fake env never ran: nothing was printed on stdout
    assert wrong_user.stdout == ""


def test_setup_launcher_refuses_bad_sudo_user(tmp_path):
    launcher, _env = make_setup_launcher(tmp_path)

    for bad in (None, "root", "1evil", "evil name"):
        env = os.environ.copy()
        if bad is None:
            env.pop("SUDO_USER", None)
        else:
            env["SUDO_USER"] = bad
        result = run(launcher, "r1", "check", env=env)
        assert result.returncode == 1, bad
        assert "valid non-root SUDO_USER" in result.stderr


def test_setup_launcher_passes_sudo_user_through_and_cleans_env(tmp_path):
    launcher, _fake_env = make_setup_launcher(tmp_path)
    env = os.environ.copy()
    env["SUDO_USER"] = "labuser"
    env["NEWTON_INVENTORY"] = "/poisoned/from/caller"

    good = run(launcher, "r1", "check", env=env)

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
        "/opt/newton/scripts/newton-router-setup",
        "r1",
        "check",
    ]


def test_setup_launcher_keeps_hostile_argument_as_one_word(tmp_path):
    launcher, _fake_env = make_setup_launcher(tmp_path)
    env = os.environ.copy()
    env["SUDO_USER"] = "labuser"

    hostile = "a b *.c 'quoted' $(touch pwned)"
    good = run(launcher, hostile, env=env)

    assert good.returncode == 0, good.stderr
    lines = good.stdout.splitlines()
    tool_index = lines.index("/opt/newton/scripts/newton-router-setup")
    assert lines[tool_index + 1] == hostile
    assert len(lines) == tool_index + 2
    assert not (tmp_path / "pwned").exists()


def test_setup_launcher_is_listed_with_mode_in_preview(tmp_path):
    env = install_test_env(tmp_path)
    result = run(INSTALL, "--check", env=env)
    assert result.returncode == 0, result.stderr
    assert (
        "Would install launcher: /usr/local/bin/newton-router-setup "
        "(root:root 0755; clean environment; newton user only; "
        "arguments passed through to newton-router-setup)" in result.stdout
    )
    assert 'install -o root -g root -m 0755 "$setup_launcher_tmp" "$SETUP_LAUNCHER"' \
        in INSTALL.read_text()


def test_setup_sudoers_line_has_no_nopasswd_and_drops_timestamp(tmp_path):
    env = install_test_env(tmp_path)
    result = run(INSTALL, "--check", env=env)
    assert result.returncode == 0, result.stderr
    assert "agent ALL=(newton) /usr/local/bin/newton-router-setup" in result.stdout
    assert (
        "Defaults!/usr/local/bin/newton-router-setup timestamp_timeout=0"
        in result.stdout
    )
    setup_lines = [
        line
        for line in result.stdout.splitlines()
        if "newton-router-setup" in line and line.startswith("agent ALL=")
    ]
    assert setup_lines == ["agent ALL=(newton) /usr/local/bin/newton-router-setup"]


# ---- installed router sources ----


DEVICE_SOURCE_ROWS = [
    ("device/openwrt/newton-router/newton-router", "0o755"),
    ("device/openwrt/newton-router/router-tools.txt", "0o644"),
    ("device/openwrt/newton-router/grammar.tsv", "0o644"),
    ("device/openwrt/newton-guard/newton-guard", "0o755"),
    ("device/openwrt/newton-guard/newton-guard.init", "0o644"),
    ("profiles/openwrt/manifest.toml", "0o644"),
    ("profiles/openwrt/standard.uci", "0o644"),
    ("profiles/openwrt/hardened.uci", "0o644"),
    ("profiles/openwrt/lockdown.uci", "0o644"),
    ("profiles/openwrt/intents.toml", "0o644"),
]

SCRIPT_SOURCE_ROWS = [
    "scripts/newton-scan",
    "scripts/newton-vantage-setup",
]


def run_install_code_root(tmp_path):
    snap = tmp_path / "snap"
    snap.mkdir(parents=True)
    (snap / "scripts").mkdir()
    (snap / "scripts" / "a.sh").write_text("#!/bin/sh\nexit 0\n")
    for rel in SCRIPT_SOURCE_ROWS:
        path = snap / rel
        path.write_text("#!/bin/sh\n# src %s\n" % rel)
    (snap / "mcp").mkdir()
    (snap / "SKILL.md").write_text("skill\n")
    for rel, _mode in DEVICE_SOURCE_ROWS:
        path = snap / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("src %s\n" % rel)
    # planted extras that must NOT be copied: tests directories and a
    # __pycache__ inside the device tree, plus a sibling uci file that is
    # not in the installer's DEVICE_SOURCE_FILES list
    (snap / "device/openwrt/newton-router/tests").mkdir(parents=True)
    (snap / "device/openwrt/newton-router/tests/test_x.py").write_text("t\n")
    (snap / "device/openwrt/newton-router/__pycache__").mkdir()
    (snap / "device/openwrt/newton-router/__pycache__/x.pyc").write_bytes(b"\0")
    (snap / "profiles/openwrt/other.uci").write_text("uci\n")

    code = tmp_path / "code"
    work = tmp_path / "work"
    bash_code = (
        'source "$1"; '
        'WORK=$2; SNAP=$3; CODE_ROOT=$4; '
        'trap cleanup EXIT; '
        'build_venv() { mkdir -p "$CODE_ROOT/venv"; }; '
        'install_code_root'
    )
    return subprocess.run(
        rootless_root_command(
            "bash", "-c", bash_code, "x", str(INSTALL), str(work), str(snap), str(code),
        ),
        env=os.environ, text=True, capture_output=True, timeout=60,
    )


def test_install_code_root_copies_router_sources_with_modes(tmp_path):
    code = tmp_path / "code"
    result = run_install_code_root(tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr

    for rel, mode in DEVICE_SOURCE_ROWS:
        installed = code / rel
        assert installed.exists(), rel
        assert installed.read_text() == "src %s\n" % rel
        assert "0o%o" % stat.S_IMODE(os.stat(installed).st_mode) == mode
        # inside unshare -Ur the mapped root is the test user outside
        assert os.stat(installed).st_uid == os.getuid(), rel
        assert "0o%o" % stat.S_IMODE(os.stat(installed.parent).st_mode) == "0o755"
    # no tests directories, no __pycache__, no extra profile files
    assert not (code / "device/openwrt/newton-router/tests").exists()
    assert not (code / "device/openwrt/newton-router/__pycache__").exists()
    assert not list((code / "device/openwrt").glob("**/*.pyc"))
    assert not (code / "profiles/openwrt/other.uci").exists()
    for rel in SCRIPT_SOURCE_ROWS:
        installed = code / rel
        assert installed.read_text() == "#!/bin/sh\n# src %s\n" % rel
        assert stat.S_IMODE(os.stat(installed).st_mode) == 0o755


def test_preview_lists_device_and_profiles_in_code_root(tmp_path):
    env = install_test_env(tmp_path)
    result = run(INSTALL, "--check", env=env)
    assert result.returncode == 0, result.stderr
    assert "Would install root-owned code: /opt/newton/{scripts,mcp,device,profiles,SKILL.md}" in result.stdout


def test_snapshot_refuses_when_a_router_source_is_missing(tmp_path):
    repo = make_install_repo(tmp_path)
    missing = repo / "device/openwrt/newton-router/grammar.tsv"
    missing.unlink()
    subprocess.run(
        ["git", "-C", str(repo), "add", "-A"],
        check=True, capture_output=True, text=True,
    )
    subprocess.run(
        ["git", "-C", str(repo), "commit", "-q", "-m", "drop grammar.tsv"],
        check=True, capture_output=True, text=True,
    )

    result = run_make_snapshot(repo)

    assert "SNAPSHOT_FAILED" in result.stdout.splitlines(), result.stdout + result.stderr
    assert "ERROR: " in result.stderr
    assert "; nothing installed" in result.stderr
    assert "missing device/openwrt/newton-router/grammar.tsv" in result.stderr


@pytest.mark.parametrize(
    "tier", ["standard", "hardened", "lockdown"], ids=["standard", "hardened", "lockdown"]
)
def test_snapshot_refuses_when_a_tier_uci_is_missing(tmp_path, tier):
    # the installed MCP server reads <manifest dir>/<tier>.uci from
    # profiles/openwrt/, so make_snapshot must refuse a tree missing one
    repo = make_install_repo(tmp_path)
    missing = repo / f"profiles/openwrt/{tier}.uci"
    missing.unlink()
    subprocess.run(
        ["git", "-C", str(repo), "add", "-A"],
        check=True, capture_output=True, text=True,
    )
    subprocess.run(
        ["git", "-C", str(repo), "commit", "-q", "-m", f"drop {tier}.uci"],
        check=True, capture_output=True, text=True,
    )

    result = run_make_snapshot(repo)

    assert "SNAPSHOT_FAILED" in result.stdout.splitlines(), result.stdout + result.stderr
    assert "ERROR: " in result.stderr
    assert "; nothing installed" in result.stderr
    assert f"missing profiles/openwrt/{tier}.uci" in result.stderr


# ---- the four launchers must not inherit the caller's cwd ----


def make_cwd_aware_launcher(tmp_path, slot):
    """Return a launcher script with /usr/bin/id and /usr/bin/env swapped
    for fakes. The fake env prints `pwd -P` (not its args), so a test that
    runs the launcher from `cwd=tmp_path` and sees `/` on stdout proves
    the launcher changed cwd before exec'ing env."""
    fake_id = tmp_path / "id"
    make_executable(
        fake_id,
        "#!/bin/sh\n"
        'if [ "${2:-}" = newton ]; then echo 4242; else echo "${FAKE_UID:-4242}"; fi\n',
    )
    fake_env = tmp_path / "env"
    make_executable(fake_env, "#!/bin/sh\npwd -P\n")
    text = (
        launcher_text(slot)
        .replace("/usr/bin/id", str(fake_id))
        .replace("/usr/bin/env", str(fake_env))
    )
    launcher = tmp_path / slot
    make_executable(launcher, text)
    return launcher


@pytest.mark.parametrize(
    ("slot", "args", "sudo_user"),
    [
        pytest.param("launcher_tmp", (), None, id="mcp"),
        pytest.param(
            "approve_launcher_tmp",
            ("0123456789abcdef0123456789abcdef",),
            "labuser",
            id="approve",
        ),
        pytest.param("setup_launcher_tmp", ("r1", "check"), "labuser", id="setup"),
        pytest.param(
            "vantage_setup_launcher_tmp", ("edge", "check"), "labuser", id="vantage-setup"
        ),
    ],
)
def test_launcher_exec_runs_with_cwd_root(slot, args, sudo_user, tmp_path):
    # The FastMCP server reads ./.env from cwd; an unreadable cwd crashes
    # it and a caller-writable cwd lets a caller plant settings. The
    # launchers must therefore change cwd to a clean root-owned directory
    # before exec'ing env. We run the launcher with cwd=tmp_path and let
    # the fake env script print its own cwd via `pwd -P`; the only way
    # to see `/` on stdout is for the launcher to have `cd /` before exec.
    launcher = make_cwd_aware_launcher(tmp_path, slot)
    env = os.environ.copy()
    if sudo_user is not None:
        env["SUDO_USER"] = sudo_user

    result = subprocess.run(
        [str(launcher), *args], text=True, capture_output=True,
        env=env, cwd=tmp_path, timeout=10,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "/", result.stdout + result.stderr


@pytest.mark.parametrize(
    "slot",
    [
        pytest.param("launcher_tmp", id="mcp"),
        pytest.param("approve_launcher_tmp", id="approve"),
        pytest.param("setup_launcher_tmp", id="setup"),
        pytest.param("vantage_setup_launcher_tmp", id="vantage-setup"),
    ],
)
def test_launcher_template_cd_to_root_precedes_exec(slot):
    # The cd must be on its own line immediately before the exec, so the
    # caller's cwd is dropped before the FastMCP server is exec'd.
    text = launcher_text(slot)
    cd_offset = text.index("cd /")
    exec_offset = text.index("exec /usr/bin/env -i")
    assert cd_offset < exec_offset, (
        "cd / must appear before exec /usr/bin/env -i in the %s launcher" % slot
    )
    # the cd / line must not be embedded in another command
    line_start = text.rfind("\n", 0, cd_offset) + 1
    line_end = text.find("\n", cd_offset)
    assert line_start <= cd_offset < line_end
    assert text[line_start:line_end].strip() == "cd /", (
        "cd / must be on its own line in the %s launcher (got %r)"
        % (slot, text[line_start:line_end])
    )
    # nothing between cd / and exec /usr/bin/env -i (refusals must come
    # before the cd, so refusals stay unchanged)
    between = text[line_end:exec_offset]
    assert between.strip() == "", (
        "the cd / line must be immediately before the exec line in the %s launcher; "
        "found between: %r" % (slot, between)
    )
