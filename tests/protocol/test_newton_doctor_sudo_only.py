"""The doctor's sudo-only-mcp check passes only when sudo itself refused the probes.

The check runs `sudo -n -u newton /usr/bin/id` and `sudo -n -u newton
newton-mcp --x`, which must both be refused.  A probe that fails for any
other reason (the newton account missing, an unparseable sudoers file,
the tool itself failing after sudo let it run) never consulted a refusal,
so it is INCONCLUSIVE, never a PASS.

Uses the NEWTON_DOCTOR_* seams only (the shared doctor_env fixture fakes
sudo/ssh and the filesystem root); nothing touches the real system.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_newton_isolation import DOCTOR, doctor_env, run  # noqa: E402,F401


def doctor(doctor_env, mode):
    env = doctor_env["env"]
    env["DOCTOR_STUB_MODE"] = mode
    return run(DOCTOR, "--router", "root@192.0.2.1", env=env)


def test_sudo_layer_failure_is_inconclusive_not_pass(doctor_env):
    result = doctor(doctor_env, "sudo-broken")
    lines = result.stdout.splitlines()
    assert "PASS sudo-only-mcp" not in lines, result.stdout
    assert (
        "INCONCLUSIVE sudo-only-mcp: sudo did not refuse /usr/bin/id, it failed: "
        "sudo: unknown user newton" in lines
    ), result.stdout
    assert result.returncode != 0


def test_tool_failure_after_sudo_let_it_run_is_inconclusive(doctor_env):
    result = doctor(doctor_env, "args-tool-fails")
    lines = result.stdout.splitlines()
    assert "PASS sudo-only-mcp" not in lines, result.stdout
    assert (
        "INCONCLUSIVE sudo-only-mcp: sudo did not refuse newton-mcp with arguments, it failed: "
        "newton-mcp: error: unrecognized arguments: --x" in lines
    ), result.stdout


@pytest.mark.parametrize("mode", ["ok", "password", "no-rules"])
def test_a_refusal_by_sudo_passes(doctor_env, mode):
    """"not allowed to execute", "a password is required" and "may not
    run sudo" are each sudo refusing to run the probe without a password."""
    result = doctor(doctor_env, mode)
    assert "PASS sudo-only-mcp" in result.stdout.splitlines(), result.stdout
