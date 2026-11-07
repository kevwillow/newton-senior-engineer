"""INJ-4: the seam values of scripts/newton-router-setup that leave the host
are shape-checked before the tool does anything.

NEWTON_SETUP_REMOTE_ROOT is interpolated into shell text that runs on the
router (as root, over the admin ssh lane), and NEWTON_SETUP_BIN is
prepended to PATH.  Both are test seams, so a hostile value must be
refused with exit 2 and "error: ..." on stderr instead of travelling to
the router or to the PATH.

The helpers of test_router_setup_cli.py are reused: `base_env` builds the
environment, `run_tool` runs the script and `write_inventory` writes an
inventory file.  The subcommand is `--help`, which exits right after
init() (inside parse_args) without contacting anything.
"""

import pytest

from test_router_setup_cli import base_env, run_tool, write_inventory


def seam_env(tmp_path, **seams):
    """The CLI test's environment with the seam marker on and the given
    seam values; a None value leaves the variable unset."""
    inv = write_inventory(tmp_path)
    env = base_env(tmp_path, inv)
    env["NEWTON_SETUP_SEAMS"] = "1"
    for key, value in seams.items():
        if value is None:
            env.pop(key, None)
        else:
            env[key] = value
    return env


@pytest.mark.parametrize(
    "value",
    [
        "'; rm -rf / #",
        "a b",
        "$(x)",
        "a\nb",
        "`x`",
        "/tmp/root;id",
    ],
)
def test_remote_root_with_a_hostile_shape_is_refused(tmp_path, value):
    env = seam_env(tmp_path, NEWTON_SETUP_REMOTE_ROOT=value)
    r = run_tool(env, "--help")
    assert r.returncode == 2
    assert r.stderr.splitlines()[0].startswith("error: ")
    assert "NEWTON_SETUP_REMOTE_ROOT" in r.stderr
    # the refusal happens in init(), so the usage text is never printed
    assert r.stdout == ""


@pytest.mark.parametrize(
    "value",
    [
        "/tmp/a:/tmp/b",
        "relative/bin",
        "/tmp/a\nb",
        "a b",
    ],
)
def test_bin_with_a_hostile_shape_is_refused(tmp_path, value):
    env = seam_env(tmp_path, NEWTON_SETUP_BIN=value)
    r = run_tool(env, "--help")
    assert r.returncode == 2
    assert r.stderr.splitlines()[0].startswith("error: ")
    assert "NEWTON_SETUP_BIN" in r.stderr
    assert r.stdout == ""


def test_normal_seam_values_pass_the_gate(tmp_path):
    """The fixture values the other tests use (a tmp path each) stay
    accepted: the gate refuses a hostile shape, not a tmp path."""
    env = seam_env(
        tmp_path,
        NEWTON_SETUP_REMOTE_ROOT=str(tmp_path / "fs"),
        NEWTON_SETUP_BIN=str(tmp_path / "bin"),
    )
    r = run_tool(env, "--help")
    assert r.returncode == 0
    assert "newton-router-setup" in r.stdout
    assert r.stderr.splitlines()[0] == "note: test seams active"


def test_absolute_bin_passes_the_gate(tmp_path):
    env = seam_env(tmp_path, NEWTON_SETUP_BIN="/tmp/x")
    r = run_tool(env, "--help")
    assert r.returncode == 0
    assert r.stderr.splitlines()[0] == "note: test seams active"


def test_unset_remote_root_passes_the_gate(tmp_path):
    """An empty remote root is the default (no seam at all) and stays
    accepted."""
    env = seam_env(tmp_path, NEWTON_SETUP_REMOTE_ROOT=None)
    r = run_tool(env, "--help")
    assert r.returncode == 0
    assert r.stderr.splitlines()[0] == "note: test seams active"


@pytest.mark.parametrize(
    "value",
    [
        "/tmp/a:/tmp/b",
        "relative/bin",
        "/tmp/a\nb",
        "a b",
    ],
)
def test_rpcd_with_a_hostile_shape_is_refused(tmp_path, value):
    """NEWTON_SETUP_RPCD is the newton-rpcd program the no-install mode
    runs, so a hostile shape is refused like the other seams."""
    env = seam_env(tmp_path, NEWTON_SETUP_RPCD=value)
    r = run_tool(env, "--help")
    assert r.returncode == 2
    assert r.stderr.splitlines()[0].startswith("error: ")
    assert "NEWTON_SETUP_RPCD" in r.stderr
    assert r.stdout == ""


def test_absolute_rpcd_passes_the_gate(tmp_path):
    env = seam_env(tmp_path, NEWTON_SETUP_RPCD="/tmp/newton-rpcd")
    r = run_tool(env, "--help")
    assert r.returncode == 0
    assert r.stderr.splitlines()[0] == "note: test seams active"
