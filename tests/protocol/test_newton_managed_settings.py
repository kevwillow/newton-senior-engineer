"""The Claude Code managed-settings guard.

Claude Code reads /etc/claude-code/managed-settings.json with the highest
priority: a user cannot override it.  Newton needs

    {"allowManagedHooksOnly": true}

there, so that an agent cannot add an Elicitation hook which answers
Newton's approval dialog for the owner.

Three halves are tested here:

* the question:
  the plain install asks ONCE whether the guard should be set.  The
  default is no: only the exact word "lock" sets it.  The upgrade path
  (--from-snapshot) never asks, so it never writes the file;
* the writer (``install_managed_settings`` in scripts/newton-install):
  it writes the file when it is absent and NEVER overwrites one that is
  already there -- the file belongs to the owner, so the installer only
  reports on it;
* the doctor (``check_managed_settings_guard`` in scripts/newton-doctor):
  it reports the state of that file.  A wrong guard is INCONCLUSIVE, not
  FAIL: the install is sound, the owner only has to fix the file.

The "never overwrite" branch is load bearing: without it the installer
would throw away the owner's own Claude Code settings.  The tests that
check an existing file is left byte for byte alone fail when that branch
is removed.
"""

import os

import pytest
import stat
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_newton_isolation import (  # noqa: E402
    DOCTOR,
    INSTALL,
    doctor_env,
    git_out,
    install_test_env,
    make_install_repo,
    run,
    run_install_pty_merged,
)


# The one plain paragraph the owner reads before the install and in the
# check output.
NOTICE = (
    "Newton asks you whether to set Claude Code's managed settings, so that "
    "only hooks from the system settings run (`allowManagedHooksOnly`). "
    "Setting it stops another tool from answering Newton's approval dialog "
    "for you, and your own user and project Claude Code hooks stop running "
    "on this machine. The default is no: your own hooks keep working, and "
    "every approval still needs your passphrase or authenticator code."
)

# The trade-off the question prints before it asks.
TRADEOFF = (
    "Optional: lock Claude Code on this machine to system hooks only "
    "(allowManagedHooksOnly).",
    "Yes: no tool can add a hook that answers Newton's approval dialog. "
    "Your own Claude Code hooks stop running.",
    "No: your hooks keep working. Each approval still needs your passphrase "
    "or authenticator code.",
)

# The prompt itself.
PROMPT = 'Type "lock" to set it, or press Enter to skip:'

GUARD = '{"allowManagedHooksOnly": true}\n'


def run_install_managed_settings(path, prelude=""):
    """Call install_managed_settings with MANAGED_SETTINGS pointing at
    *path*.

    The test runs as the test user, so the root ownership is stubbed out
    (chown does nothing, install drops its -o/-g arguments); everything
    else -- the content, the modes, the warnings -- runs for real.
    """
    code = (
        'source "$1"\n'
        'MANAGED_SETTINGS="$2"\n'
        "chown() { :; }\n"
        + prelude +
        "install() {\n"
        "    local a=()\n"
        "    while (( $# )); do\n"
        '        case "$1" in\n'
        "            -o|-g) shift 2 ;;\n"
        '            *) a+=("$1"); shift ;;\n'
        "        esac\n"
        "    done\n"
        '    command install "${a[@]}"\n'
        "}\n"
        "if install_managed_settings; then rc=0; else rc=$?; fi\n"
        'printf "RC=%s\\n" "$rc"\n'
    )
    return subprocess.run(
        ["bash", "-c", code, "install-source", str(INSTALL), str(path)],
        text=True,
        capture_output=True,
        timeout=30,
    )


def write_managed_settings(tmp_path, content):
    """An existing managed-settings file in a temporary directory."""
    path = tmp_path / "etc" / "claude-code" / "managed-settings.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.parent.chmod(0o755)
    path.write_text(content)
    path.chmod(0o644)
    return path


# ---- the question ----


def run_ask_managed_settings(feed=b"", merged=False):
    """Call ask_managed_settings with *feed* on stdin.

    An empty *feed* is the end of the input: the owner closed the pipe
    instead of answering.  The function prints what the owner sees and
    reports the answer it recorded as LOCK=0 or LOCK=1.  With *merged*,
    stderr goes into stdout as written, so the order of the two streams
    can be checked.
    """
    code = (
        'source "$1"\n'
        "ask_managed_settings\n"
        'printf "LOCK=%s\\n" "$MANAGED_SETTINGS_LOCK"\n'
    )
    return subprocess.run(
        ["bash", "-c", code, "install-source", str(INSTALL)],
        input=feed.decode(),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT if merged else subprocess.PIPE,
        timeout=30,
    )


def test_the_answer_lock_sets_the_guard():
    result = run_ask_managed_settings(b"lock\n")

    assert result.returncode == 0, result.stdout + result.stderr
    assert "LOCK=1" in result.stdout
    assert "was not set" not in result.stdout


@pytest.mark.parametrize(
    "feed",
    [
        pytest.param(b"\n", id="enter"),
        pytest.param(b"yes\n", id="yes"),
        pytest.param(b"no\n", id="no"),
        pytest.param(b"LOCK\n", id="upper-case"),
        pytest.param(b" lock\n", id="leading-space"),
        pytest.param(b"lock it\n", id="extra-word"),
        pytest.param(b"", id="end-of-input"),
    ],
)
def test_any_other_answer_skips_the_guard(feed):
    # The default is no: only the exact word "lock" sets the guard.
    result = run_ask_managed_settings(feed)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "LOCK=0" in result.stdout
    assert "was not set" in result.stdout


def test_the_question_prints_the_trade_off_before_the_prompt():
    result = run_ask_managed_settings(b"lock\n", merged=True)

    text = result.stdout
    for line in TRADEOFF:
        assert line in text
    assert text.index(TRADEOFF[0]) < text.index(PROMPT)
    assert text.index(TRADEOFF[-1]) < text.index(PROMPT)


def test_the_skip_line_says_how_to_set_the_guard_later():
    result = run_ask_managed_settings(b"\n")

    line = next(
        line for line in result.stdout.splitlines() if "was not set" in line
    )
    assert "newton-doctor" in line
    assert "INCONCLUSIVE" in line
    assert '"allowManagedHooksOnly": true' in line
    assert "/etc/claude-code/managed-settings.json" in line


def test_the_question_is_asked_after_the_confirmation(tmp_path):
    repo = make_install_repo(tmp_path)
    head = git_out(repo, "rev-parse", "HEAD")

    rc, merged = run_install_pty_merged(
        repo, tmp_path, feed=f"install {head}\nlock\n".encode()
    )

    text = merged.decode()
    # the test seam stops the install right after the question
    assert rc == 2, text
    assert "test seam" in text
    assert text.index('type "install "') < text.index(PROMPT)
    for line in TRADEOFF:
        assert line in text
    # "lock" is accepted: nothing is skipped
    assert "was not set" not in text


def test_the_question_is_skipped_when_the_owner_presses_enter(tmp_path):
    repo = make_install_repo(tmp_path)
    head = git_out(repo, "rev-parse", "HEAD")

    rc, merged = run_install_pty_merged(
        repo, tmp_path, feed=f"install {head}\n\n".encode()
    )

    text = merged.decode()
    assert rc == 2, text
    assert PROMPT in text
    assert "was not set" in text


def test_check_asks_about_the_guard_instead_of_setting_it(tmp_path):
    env = install_test_env(tmp_path)

    result = run(INSTALL, "--check", env=env)

    assert result.returncode == 0, result.stderr
    assert "Would ask whether to set Claude Code's managed settings" in (
        result.stdout
    )
    assert "Would set Claude Code's managed settings" not in result.stdout
    assert "default: no" in result.stdout
    # --check never asks anything
    assert PROMPT not in result.stdout
    assert PROMPT not in result.stderr


# ---- the installer ----


def test_install_managed_settings_writes_the_guard_when_the_file_is_absent(tmp_path):
    path = tmp_path / "etc" / "claude-code" / "managed-settings.json"

    result = run_install_managed_settings(path)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "RC=0" in result.stdout
    assert path.read_text() == GUARD
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o644
    assert stat.S_IMODE(os.stat(path.parent).st_mode) == 0o755


def test_install_managed_settings_leaves_a_correct_file_untouched(tmp_path):
    path = write_managed_settings(tmp_path, GUARD)

    result = run_install_managed_settings(path)

    assert "RC=0" in result.stdout
    assert path.read_text() == GUARD
    assert "WARNING" not in result.stderr


@pytest.mark.parametrize("mode", [0o666, 0o664, 0o646])
def test_install_managed_settings_warns_when_others_can_write_the_guard(tmp_path, mode):
    # A guard somebody else can edit is no guard.
    path = write_managed_settings(tmp_path, GUARD)
    path.chmod(mode)

    result = run_install_managed_settings(path)

    assert "RC=0" in result.stdout
    assert path.read_text() == GUARD
    assert "already allow only managed hooks" not in result.stdout
    assert "WARNING" in result.stderr
    assert "writable by group or other" in result.stderr


def test_install_managed_settings_warns_when_the_client_cannot_read_the_guard(tmp_path):
    # Claude Code runs as the owner, so a root-only 0600 file is ignored.
    path = write_managed_settings(tmp_path, GUARD)
    path.chmod(0o600)

    result = run_install_managed_settings(path)

    assert "RC=0" in result.stdout
    assert "already allow only managed hooks" not in result.stdout
    assert "WARNING" in result.stderr
    assert "readable by everyone" in result.stderr


def test_install_managed_settings_warns_when_the_key_is_missing(tmp_path):
    path = write_managed_settings(tmp_path, '{"hooks": {}}\n')

    result = run_install_managed_settings(path)

    # the install still succeeds
    assert "RC=0" in result.stdout
    # and the owner's own file is left exactly as it was
    assert path.read_text() == '{"hooks": {}}\n'
    assert "WARNING" in result.stderr
    assert '"allowManagedHooksOnly": true' in result.stderr
    assert "approval dialog" in result.stderr


def test_install_managed_settings_warns_when_the_file_is_not_json(tmp_path):
    path = write_managed_settings(tmp_path, "this is not json\n")

    result = run_install_managed_settings(path)

    assert "RC=0" in result.stdout
    assert path.read_text() == "this is not json\n"
    assert "WARNING" in result.stderr
    assert '"allowManagedHooksOnly": true' in result.stderr


def test_install_managed_settings_refuses_to_write_through_a_symlink(tmp_path):
    target = tmp_path / "target.json"
    target.write_text(GUARD)
    link = tmp_path / "managed-settings.json"
    link.symlink_to(target)

    result = run_install_managed_settings(link)

    assert "RC=0" in result.stdout
    assert link.is_symlink()
    assert target.read_text() == GUARD
    assert "WARNING" in result.stderr


def test_install_managed_settings_never_overwrites_an_existing_file(tmp_path):
    # The mutation-proof of the "never overwrite" branch: with the branch
    # removed the installer would replace the owner's file with its own
    # content and these two assertions would fail.
    original = '{"hooks": {"PreToolUse": []}}\n'
    path = write_managed_settings(tmp_path, original)

    result = run_install_managed_settings(path)

    assert "RC=0" in result.stdout
    assert path.read_text() == original


def test_check_mentions_the_guard_and_writes_nothing(tmp_path):
    env = install_test_env(tmp_path)

    result = run(INSTALL, "--check", env=env)

    assert result.returncode == 0, result.stderr
    assert "/etc/claude-code/managed-settings.json" in result.stdout
    assert "allowManagedHooksOnly" in result.stdout
    assert NOTICE in result.stdout
    assert not (tmp_path / "root").exists()


def test_the_notice_is_printed_before_the_confirmation(tmp_path):
    repo = make_install_repo(tmp_path)

    rc, merged = run_install_pty_merged(repo, tmp_path)

    assert rc == 1
    text = merged.decode()
    assert NOTICE in text
    assert text.index(NOTICE) < text.index('type "install "')


def test_install_managed_settings_refuses_a_directory_others_can_write(tmp_path):
    directory = tmp_path / "etc" / "claude-code"
    directory.mkdir(parents=True)
    directory.chmod(0o775)
    path = directory / "managed-settings.json"

    result = run_install_managed_settings(path)

    assert "RC=0" in result.stdout
    assert not path.exists()
    assert "WARNING" in result.stderr


def test_install_managed_settings_refuses_a_symlinked_directory(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "claude-code"
    link.symlink_to(real)

    result = run_install_managed_settings(link / "managed-settings.json")

    assert "RC=0" in result.stdout
    assert not (real / "managed-settings.json").exists()
    assert "WARNING" in result.stderr


def test_install_managed_settings_does_not_clobber_a_file_that_appears_late(tmp_path):
    # the owner's file shows up between the check and the write
    directory = tmp_path / "etc" / "claude-code"
    directory.mkdir(parents=True)
    directory.chmod(0o755)
    path = directory / "managed-settings.json"
    racer = '{"hooks": {}}\n'
    prelude = (
        'ln() { printf %s \'' + racer.strip() + '\n\' > "$3"; command ln "$@"; }\n'
    )

    result = run_install_managed_settings(path, prelude)

    assert "RC=0" in result.stdout
    assert path.read_text() == racer
    assert "appeared while the installer ran" in result.stderr


# ---- the doctor ----


def managed_settings_path(doctor_env):
    return doctor_env["root"] / "etc" / "claude-code" / "managed-settings.json"


def rewrite_managed_settings(doctor_env, content):
    """Replace the managed settings file in the fake root."""
    path = managed_settings_path(doctor_env)
    path.parent.chmod(0o755)
    path.write_text(content)
    path.chmod(0o644)
    return path


def test_doctor_passes_when_the_guard_is_set(doctor_env):
    result = run(DOCTOR, "--router", "root@192.0.2.1", env=doctor_env["env"])

    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS managed-settings-guard" in result.stdout


def test_doctor_warns_when_the_managed_settings_are_absent(doctor_env):
    path = managed_settings_path(doctor_env)
    path.parent.chmod(0o755)
    path.unlink()

    result = run(DOCTOR, "--router", "root@192.0.2.1", env=doctor_env["env"])

    assert result.returncode == 3, result.stdout + result.stderr
    assert "INCONCLUSIVE managed-settings-guard" in result.stdout
    assert '"allowManagedHooksOnly": true' in result.stdout


def test_doctor_names_the_trade_off_when_the_guard_is_absent(doctor_env):
    # The guard is defence in depth: the approval itself still needs the
    # owner's passphrase or authenticator code.  The doctor says what
    # setting it costs the owner, so the choice is theirs.
    path = managed_settings_path(doctor_env)
    path.parent.chmod(0o755)
    path.unlink()

    result = run(DOCTOR, "--router", "root@192.0.2.1", env=doctor_env["env"])

    assert result.returncode == 3, result.stdout + result.stderr
    assert "INCONCLUSIVE managed-settings-guard" in result.stdout
    assert "your own Claude Code hooks" in result.stdout
    assert "passphrase or authenticator code" in result.stdout


def test_doctor_warns_when_the_key_is_false(doctor_env):
    rewrite_managed_settings(doctor_env, '{"allowManagedHooksOnly": false}\n')

    result = run(DOCTOR, "--router", "root@192.0.2.1", env=doctor_env["env"])

    assert result.returncode == 3, result.stdout + result.stderr
    assert "INCONCLUSIVE managed-settings-guard" in result.stdout
    assert '"allowManagedHooksOnly": true' in result.stdout


def test_doctor_warns_when_the_key_is_missing(doctor_env):
    rewrite_managed_settings(doctor_env, "{}\n")

    result = run(DOCTOR, "--router", "root@192.0.2.1", env=doctor_env["env"])

    assert result.returncode == 3, result.stdout + result.stderr
    assert "INCONCLUSIVE managed-settings-guard" in result.stdout


def test_doctor_warns_when_the_file_is_not_json(doctor_env):
    rewrite_managed_settings(doctor_env, "this is not json\n")

    result = run(DOCTOR, "--router", "root@192.0.2.1", env=doctor_env["env"])

    assert result.returncode == 3, result.stdout + result.stderr
    assert "INCONCLUSIVE managed-settings-guard" in result.stdout


def test_doctor_warns_when_the_file_is_not_owned_by_root(doctor_env):
    env = doctor_env["env"].copy()
    # the fake root is written by the test user, so "root" is that uid;
    # a different one stands for a file another account owns
    env["NEWTON_DOCTOR_ROOT_UID"] = str(os.getuid() + 1)

    result = run(DOCTOR, "--router", "root@192.0.2.1", env=env)

    assert result.returncode == 3, result.stdout + result.stderr
    assert "INCONCLUSIVE managed-settings-guard" in result.stdout
    assert "root" in result.stdout


def test_doctor_warns_when_the_file_is_writable_by_others(doctor_env):
    path = managed_settings_path(doctor_env)
    path.chmod(0o666)

    result = run(DOCTOR, "--router", "root@192.0.2.1", env=doctor_env["env"])

    assert result.returncode == 3, result.stdout + result.stderr
    assert "INCONCLUSIVE managed-settings-guard" in result.stdout
    assert '"allowManagedHooksOnly": true' in result.stdout


def test_doctor_warns_when_the_file_cannot_be_read(doctor_env):
    # the doctor runs as the agent user: a file it cannot read is a file
    # it cannot vouch for
    path = managed_settings_path(doctor_env)
    path.chmod(0o000)

    result = run(DOCTOR, "--router", "root@192.0.2.1", env=doctor_env["env"])

    assert result.returncode == 3, result.stdout + result.stderr
    assert "INCONCLUSIVE managed-settings-guard" in result.stdout


def test_doctor_warns_when_the_directory_is_writable_by_others(doctor_env):
    path = managed_settings_path(doctor_env)
    path.parent.chmod(0o777)

    result = run(DOCTOR, "--router", "root@192.0.2.1", env=doctor_env["env"])

    assert result.returncode == 3, result.stdout + result.stderr
    assert "INCONCLUSIVE managed-settings-guard" in result.stdout
    assert "swapped" in result.stdout


def test_doctor_warns_when_the_file_is_a_symlink(doctor_env):
    path = managed_settings_path(doctor_env)
    path.parent.chmod(0o755)
    target = path.with_name("elsewhere.json")
    path.rename(target)
    path.symlink_to(target)

    result = run(DOCTOR, "--router", "root@192.0.2.1", env=doctor_env["env"])

    assert result.returncode == 3, result.stdout + result.stderr
    assert "INCONCLUSIVE managed-settings-guard" in result.stdout
    assert "symlink" in result.stdout
