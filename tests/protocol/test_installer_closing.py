"""Installer, doctor and CI fixes.

* the plain install says "installed successfully" only after the
  bootstrap is installed too, and says what to do when the bootstrap
  step fails;
* a failed upgrade says "restored" only when the old tree was moved
  back, and names the backup when it was not;
* the update steps tell the owner not to use the running server until
  it is restarted;
* the managed-settings advice is valid JSON for the state the file is
  in: the whole object when the file is missing or not JSON, the one
  line only for a JSON object without the key;
* the doctor counts a sudo-rs refusal as a refusal;
* CI runs every Python the installer accepts.

Everything runs against temporary directories and stubs; nothing
touches the real system.
"""

import re
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_newton_install_perform import (  # noqa: E402
    PERFORM_INSTALL_HARNESS,
    _extract_function_body,
    make_snap,
    needs_ns,
)
from test_newton_isolation import DOCTOR, doctor_env, run  # noqa: E402,F401

REPO = Path(__file__).resolve().parents[2]
INSTALL = REPO / "scripts" / "newton-install"
CI = REPO / ".github" / "workflows" / "ci.yml"

GUARD_OBJECT = '{"allowManagedHooksOnly": true}'
GUARD_LINE = '"allowManagedHooksOnly": true'


# ---- success is printed only after the bootstrap ----


def plain_mode_tail():
    """main()'s plain-mode steps after the 'bootstrap already installed'
    refusal: the part that installs Newton and then the bootstrap."""
    body = _extract_function_body(INSTALL.read_text(), "main").splitlines()
    marker = next(
        i for i, line in enumerate(body)
        if "newton-bootstrap is already installed" in line
    )
    end = next(i for i in range(marker, len(body)) if body[i].strip() == "fi")
    return "\n".join(body[end + 1:])


def run_plain_tail(tmp_path, bootstrap_ok):
    make_snap(tmp_path / "snap")
    (tmp_path / "snap" / "scripts" / "newton-bootstrap").write_text(
        "#!/bin/bash\n# boot\n"
    )
    sbin = tmp_path / "sbin"
    if bootstrap_ok:
        sbin.mkdir()
    # without the sbin directory, the bootstrap's mktemp fails
    harness = PERFORM_INSTALL_HARNESS.replace("##INSTALL##", str(INSTALL))
    head, _, _ = harness.partition("\nperform_install\nrc=$?")
    script = (
        head
        + f'\nBOOTSTRAP_DEST="{sbin}/newton-bootstrap"\n'
        + f'BOOTSTRAP_SOURCE="{sbin}/newton-bootstrap.source"\n'
        + "COMMIT_ID=0123456789abcdef0123456789abcdef01234567\n"
        + "arm_cleanup_traps\n"
        + plain_mode_tail()
        + "\necho RC=0\n"
    )
    path = tmp_path / "plain.sh"
    path.write_text(script)
    return subprocess.run(
        ["unshare", "-Ur", "bash", str(path), str(tmp_path)],
        capture_output=True, text=True, timeout=120,
    )


@needs_ns
def test_a_failed_bootstrap_step_prints_no_success(tmp_path):
    r = run_plain_tail(tmp_path, bootstrap_ok=False)
    assert r.returncode != 0, (r.stdout, r.stderr)
    assert "Newton installed successfully." not in r.stdout, r.stdout
    assert "MCP client command" not in r.stdout, r.stdout
    dest = tmp_path / "sbin" / "newton-bootstrap"
    assert (
        f"ERROR: Newton was installed but newton-bootstrap was not; remove {dest} "
        "if it is there and run this installer again"
    ) in r.stderr, r.stderr


@needs_ns
def test_the_success_line_follows_the_bootstrap(tmp_path):
    r = run_plain_tail(tmp_path, bootstrap_ok=True)
    assert r.returncode == 0, (r.stdout, r.stderr)
    assert (tmp_path / "sbin" / "newton-bootstrap").exists()
    assert "Newton installed successfully." in r.stdout, r.stdout
    assert "MCP client command" in r.stdout, r.stdout
    assert "newton-bootstrap was not" not in r.stderr, r.stderr


# ---- "restored" only when the move back worked ----


def run_cleanup(tmp_path, backup_exists):
    code_root = tmp_path / "opt"
    code_root.mkdir()
    (code_root / "half-built").write_text("new\n")
    backup = tmp_path / "opt.old"
    if backup_exists:
        backup.mkdir()
        (backup / "old-marker").write_text("old\n")
    code = (
        'source "$1"\n'
        'CODE_ROOT="$2"\n'
        'CODE_ROOT_BACKUP="$3"\n'
        "CODE_ROOT_PENDING=1\n"
        "WORK=\n"
        "launcher_tmp= approve_launcher_tmp= setup_launcher_tmp= vantage_setup_launcher_tmp=\n"
        "enrol_launcher_tmp= ad_setup_launcher_tmp= rules_launcher_tmp= sudoers_tmp= doctor_tmp=\n"
        "cleanup\n"
    )
    r = subprocess.run(
        ["bash", "-c", code, "cleanup", str(INSTALL), str(code_root), str(backup)],
        capture_output=True, text=True, timeout=30,
    )
    return r, code_root, backup


def test_a_failed_restore_does_not_claim_the_restore(tmp_path):
    r, code_root, backup = run_cleanup(tmp_path, backup_exists=False)
    assert "previous installation was restored" not in r.stderr, r.stderr
    assert (
        f"ERROR: the upgrade failed and the previous installation could not be moved back; "
        f"it should be in {backup}: move it to {code_root} as root"
    ) in r.stderr, r.stderr


def test_a_working_restore_still_says_so(tmp_path):
    r, code_root, _ = run_cleanup(tmp_path, backup_exists=True)
    assert "WARNING: previous installation was restored after a failed upgrade" in r.stderr
    assert (code_root / "old-marker").exists()
    assert "could not be moved back" not in r.stderr


# ---- the running server must not be used until restarted ----


def test_the_update_steps_say_not_to_use_the_old_server():
    code = (
        'source "$1"\n'
        "SETUP_LAUNCHER=/usr/local/bin/newton-router-setup\n"
        "CLIENT_COMMAND=x\n"
        "print_update_steps\n"
    )
    r = subprocess.run(
        ["bash", "-c", code, "steps", str(INSTALL)],
        capture_output=True, text=True, timeout=30, check=True,
    )
    assert "keeps the old code in memory" not in r.stdout, r.stdout
    assert (
        "Do not use Newton until you have: the running server has its old code loaded "
        "but reads the new files from disk, so a call before the restart can run a mix "
        "of the two."
    ) in r.stdout, r.stdout


# ---- the managed-settings advice is valid JSON ----


def run_ask(managed_settings):
    code = (
        'source "$1"\n'
        'MANAGED_SETTINGS="$2"\n'
        "ask_managed_settings\n"
    )
    r = subprocess.run(
        ["bash", "-c", code, "ask", str(INSTALL), str(managed_settings)],
        input="\n", text=True, capture_output=True, timeout=30,
    )
    return next(line for line in r.stdout.splitlines() if "was not set" in line)


def test_the_skip_line_gives_the_whole_object_when_the_file_is_missing(tmp_path):
    path = tmp_path / "managed-settings.json"
    line = run_ask(path)
    assert f"as root, create {path} with this content: {GUARD_OBJECT}" in line, line
    assert "add the line" not in line, line


def test_the_skip_line_gives_the_whole_object_when_the_file_is_not_json(tmp_path):
    path = tmp_path / "managed-settings.json"
    path.write_text("not json\n")
    line = run_ask(path)
    assert (
        f"as root, replace the content of {path}, which is not valid JSON, with: {GUARD_OBJECT}"
    ) in line, line
    assert "add the line" not in line, line


def test_the_skip_line_keeps_the_one_line_for_a_json_object(tmp_path):
    path = tmp_path / "managed-settings.json"
    path.write_text('{"hooks": {}}\n')
    line = run_ask(path)
    assert f'as root, add the line {GUARD_LINE} to {path}.' in line, line


def test_install_managed_settings_gives_the_whole_object_for_a_file_that_is_not_json(tmp_path):
    from test_newton_managed_settings import (
        run_install_managed_settings,
        write_managed_settings,
    )

    path = write_managed_settings(tmp_path, "this is not json\n")
    result = run_install_managed_settings(path)
    assert "RC=0" in result.stdout
    assert path.read_text() == "this is not json\n"
    assert "Add this line" not in result.stderr, result.stderr
    assert (
        f"Replace its content with this, as root:\n  {GUARD_OBJECT}\n"
    ) in result.stderr, result.stderr


def managed_settings_path(doctor_env):
    return doctor_env["root"] / "etc" / "claude-code" / "managed-settings.json"


def doctor_guard_line(doctor_env):
    result = run(DOCTOR, "--router", "root@192.0.2.1", env=doctor_env["env"])
    return next(
        line for line in result.stdout.splitlines()
        if line.startswith("INCONCLUSIVE managed-settings-guard")
    )


def test_doctor_gives_the_whole_object_when_the_file_is_missing(doctor_env):
    path = managed_settings_path(doctor_env)
    path.parent.chmod(0o755)
    path.unlink()
    line = doctor_guard_line(doctor_env)
    assert f"As root, create {path} with this content: {GUARD_OBJECT}." in line, line
    assert "Add this line" not in line, line


def test_doctor_gives_the_whole_object_when_the_file_is_not_json(doctor_env):
    path = managed_settings_path(doctor_env)
    path.parent.chmod(0o755)
    path.write_text("this is not json\n")
    path.chmod(0o644)
    line = doctor_guard_line(doctor_env)
    assert (
        f"As root, replace the content of {path} with: {GUARD_OBJECT}."
    ) in line, line
    assert "Add this line" not in line, line


def test_doctor_keeps_the_one_line_for_a_json_object_without_the_key(doctor_env):
    path = managed_settings_path(doctor_env)
    path.parent.chmod(0o755)
    path.write_text('{"hooks": {}}\n')
    path.chmod(0o644)
    line = doctor_guard_line(doctor_env)
    assert f"Add this line to {path}: {GUARD_LINE}." in line, line


# ---- sudo-rs refusals ----

# The refusal texts of sudo-rs, pinned from its source
# (src/common/error.rs, Error::Authorization and
# Error::InteractionRequired, at commit 81dff9a1ccb3 of
# trifectatechfoundation/sudo-rs).
SUDO_RS_REFUSALS = [
    "sudo: I'm sorry agent. I'm afraid I can't do that",
    "sudo: interactive authentication is required",
]


@pytest.mark.parametrize("refusal", SUDO_RS_REFUSALS)
def test_a_sudo_rs_refusal_passes(doctor_env, tmp_path, refusal):
    wrapper = tmp_path / "sudo-rs"
    wrapper.write_text(
        "#!/bin/sh\n"
        'case "$*" in\n'
        "  *'/usr/bin/id'|*'newton-mcp --x')\n"
        '    printf \'%s\\n\' "$SUDO_RS_REFUSAL" >&2; exit 1 ;;\n'
        "esac\n"
        'exec sudo "$@"\n'
    )
    wrapper.chmod(0o755)
    env = dict(doctor_env["env"], NEWTON_DOCTOR_SUDO=str(wrapper), SUDO_RS_REFUSAL=refusal)
    result = run(DOCTOR, "--router", "root@192.0.2.1", env=env)
    lines = result.stdout.splitlines()
    assert "PASS sudo-only-mcp" in lines, result.stdout


# ---- CI runs every Python the installer accepts ----


def test_ci_runs_every_python_the_installer_accepts():
    source = INSTALL.read_text()
    bounds = re.search(
        r"not \(3, (\d+)\) <= sys\.version_info\[:2\] <= \(3, (\d+)\)", source
    )
    assert bounds, "check_python_version bounds not found"
    low, high = int(bounds.group(1)), int(bounds.group(2))
    accepted = [f"3.{minor}" for minor in range(low, high + 1)]

    matrix = re.search(r"^\s*python: \[([^\]]*)\]", CI.read_text(), re.M)
    assert matrix, "python matrix not found in ci.yml"
    ran = [v.strip().strip('"') for v in matrix.group(1).split(",")]
    assert ran == accepted
