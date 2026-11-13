"""newton-install --from-snapshot and the bootstrap installation."""
import os
import re
import shutil
import subprocess
from pathlib import Path
import pytest
from bootstrap_harness import FakeRoot, userns_ok

REPO = Path(__file__).resolve().parents[2]
INSTALL = REPO / "scripts" / "newton-install"
ENV = {"SUDO_USER": "ci-test"}
needs_ns = pytest.mark.skipif(not userns_ok(), reason="unshare -Urm unavailable")


def required_paths():
    """(kind, path) rows from the installer's own required_snapshot_paths function."""
    r = subprocess.run(["bash", "-c", f"source {INSTALL}; required_snapshot_paths"], capture_output=True, text=True,
                       env={"PATH": "/usr/bin:/bin"}, check=True)
    return [tuple(line.split(" ", 1)) for line in r.stdout.splitlines() if line]


def make_snap(dst: Path, skip=None):
    """A snapshot directory with placeholder files for every required path and the REAL installer script."""
    for kind, rel in required_paths():
        if rel == skip:
            continue
        p = dst / rel
        if kind == "d":
            p.mkdir(parents=True, exist_ok=True)
        else:
            p.parent.mkdir(parents=True, exist_ok=True)
            if rel == "scripts/newton-doctor":
                # render_installed_doctor requires a #! first line and exactly
                # one NEWTON_DOCTOR_SEAMS=1 marker line.
                p.write_text("#!/bin/bash -p\nNEWTON_DOCTOR_SEAMS=1\nexit 0\n")
                os.chmod(p, 0o755)
            else:
                p.write_text("# placeholder for %s\n" % rel)
    if skip != "scripts/newton-install":
        shutil.copy2(INSTALL, dst / "scripts/newton-install")
    return dst


def _extract_function_body(source: str, name: str) -> str:
    """Extract the body of `name() { ... }` from a bash script using brace counting.

    Works for this installer because the bodies contain no `{` or `}` inside
    heredocs or quoted strings (their heredocs are pure POSIX shell snippets).
    """
    lines = source.splitlines()
    for i, line in enumerate(lines):
        if re.match(rf"^{re.escape(name)}\s*\(\)\s*\{{\s*$", line):
            depth = 1
            start = i + 1
            for j in range(start, len(lines)):
                for ch in lines[j]:
                    if ch == "{":
                        depth += 1
                    elif ch == "}":
                        depth -= 1
                        if depth == 0:
                            return "\n".join(lines[start:j])
            raise AssertionError(f"function {name} never closed")
    raise AssertionError(f"function {name} not found")


def test_perform_install_is_shared_by_both_modes():
    """perform_install is the shared code path; bootstrap-only markers live only there."""
    src = INSTALL.read_text()

    run_from_snapshot_body = _extract_function_body(src, "run_from_snapshot_mode")
    main_body = _extract_function_body(src, "main")
    perform_install_body = _extract_function_body(src, "perform_install")

    assert run_from_snapshot_body, "could not extract run_from_snapshot_mode body"
    assert main_body, "could not extract main body"
    assert perform_install_body, "could not extract perform_install body"

    # both modes call the same perform_install
    assert any(line.strip() == "perform_install" for line in main_body.splitlines()), \
        "main() does not call perform_install"
    assert any(line.strip() == "perform_install" for line in run_from_snapshot_body.splitlines()), \
        "run_from_snapshot_mode() does not call perform_install"

    # install_bootstrap is called only in main, never in --from-snapshot
    assert any(re.search(r"\binstall_bootstrap\b", line) for line in main_body.splitlines()), \
        "main() does not call install_bootstrap"
    assert not any(re.search(r"\binstall_bootstrap\b", line) for line in run_from_snapshot_body.splitlines()), \
        "run_from_snapshot_mode() unexpectedly calls install_bootstrap"

    # Bootstrap-only code lives in perform_install, NOT in main or run_from_snapshot_mode.
    # The markers must be unambiguous: SETUP_LAUNCHER/SUDOERS_SETUP_LINE are also
    # assigned in main() (they are globals passed to perform_install), and
    # install_code_root is mentioned in a comment in run_from_snapshot_mode --
    # so we use specific call sites instead.
    bootstrap_markers = [
        # function call (tab-indented) -- unique to perform_install (line 882)
        "\tinstall_code_root",
        # root-owned launcher install template -- only in perform_install
        'install -o root -g root -m 0755 "$setup_launcher_tmp" "$SETUP_LAUNCHER"',
        'install -o root -g root -m 0755 "$vantage_setup_launcher_tmp" "$VANTAGE_SETUP_LAUNCHER"',
        'install -o root -g root -m 0755 "$enrol_launcher_tmp" "$ENROL_LAUNCHER"',
        # the visudo -cf call -- only in perform_install
        '"$VISUDO" -cf "$sudoers_tmp"',
        # bootstrap-only sudoers printf template -- unique to perform_install
        "printf '%s\\n%s\\n%s\\n%s\\n%s\\n%s\\n%s\\n%s\\n%s\\n%s\\n%s\\n' \"$SUDOERS_MCP_LINE\"",
    ]
    for marker in bootstrap_markers:
        assert marker in perform_install_body, \
            f"perform_install missing bootstrap marker: {marker!r}"
        assert marker not in main_body, \
            f"main() unexpectedly contains bootstrap marker: {marker!r}"
        assert marker not in run_from_snapshot_body, \
            f"run_from_snapshot_mode() unexpectedly contains bootstrap marker: {marker!r}"


# The harness that runs perform_install in the fake root.  It stubs the
# parts that need a real system (users, groups, the venv build, the root
# ownership) and leaves the file modes real.
PERFORM_INSTALL_HARNESS = r'''
set -e
T="$1"
# the answer to the guard question: only the word "lock"
# sets it, so the default here is the default there.  It is read
# before the source because the installer sets its own default, and
# the environment must never be able to turn the guard on.
ANSWER_LOCK=${NEWTON_TEST_ANSWER_LOCK:-0}
source "##INSTALL##"

export SYSTEM_USER=newton
export SYSTEM_GROUP=newton
export NEWTON_HOME="$T/home"
export CODE_ROOT="$T/opt"
export LAUNCHER="$T/bin/newton-mcp"
export APPROVE_LAUNCHER="$T/bin/newton-approve"
export SETUP_LAUNCHER="$T/bin/newton-router-setup"
export VANTAGE_SETUP_LAUNCHER="$T/bin/newton-vantage-setup"
export ENROL_LAUNCHER="$T/bin/newton-enrol"
export AD_SETUP_LAUNCHER="$T/bin/newton-ad-setup"
export DOCTOR_LAUNCHER="$T/bin/newton-doctor"
export SUDOERS="$T/sudoers.d/newton-mcp"
export MANAGED_SETTINGS="$T/etc/claude-code/managed-settings.json"
export CLIENT_COMMAND=x

SUDOERS_MCP_LINE="alice ALL=(newton) NOPASSWD: /usr/local/bin/newton-mcp"
SUDOERS_APPROVE_LINE="alice ALL=(newton) /usr/local/bin/newton-approve"
SUDOERS_APPROVE_DEFAULTS_LINE="Defaults!/usr/local/bin/newton-approve timestamp_timeout=0"
SUDOERS_SETUP_LINE="alice ALL=(newton) /usr/local/bin/newton-router-setup"
SUDOERS_SETUP_DEFAULTS_LINE="Defaults!/usr/local/bin/newton-router-setup timestamp_timeout=0"
SUDOERS_VANTAGE_SETUP_LINE="alice ALL=(newton) /usr/local/bin/newton-vantage-setup"
SUDOERS_VANTAGE_SETUP_DEFAULTS_LINE="Defaults!/usr/local/bin/newton-vantage-setup timestamp_timeout=0"
SUDOERS_ENROL_LINE="alice ALL=(newton) /usr/local/bin/newton-enrol"
SUDOERS_ENROL_DEFAULTS_LINE="Defaults!/usr/local/bin/newton-enrol timestamp_timeout=0"
SUDOERS_AD_SETUP_LINE="alice ALL=(newton) /usr/local/bin/newton-ad-setup"
SUDOERS_AD_SETUP_DEFAULTS_LINE="Defaults!/usr/local/bin/newton-ad-setup timestamp_timeout=0"
invoking_user=alice
SNAP="$T/snap"
mkdir -p "$T/work" "$T/bin" "$T/home" "$T/sudoers.d"
VISUDO_LOG="$T/visudo-log"

cat > "$T/bin/visudo-stub" <<STUB_EOF
#!/usr/bin/env bash
printf '%s\n' "\$@" >> "$VISUDO_LOG"
exit 0
STUB_EOF
chmod +x "$T/bin/visudo-stub"
VISUDO="$T/bin/visudo-stub"
export VISUDO

getent() {
    if [[ "$1" == "group" ]]; then return 0; fi
    echo "newton:x:1:1::$NEWTON_HOME:/usr/sbin/nologin"
}
id() { echo newton; }
groupadd() { :; }
useradd() { :; }
# the root ownership is stubbed out (the fake root cannot chown to root),
# but the modes are real: the installed files must carry the modes the
# installer gives them
chown() { :; }
build_venv() { mkdir -p "$CODE_ROOT/venv"; }
check_root_programs() { :; }

install() {
    local a=()
    while (( $# )); do
        case "$1" in
            -o|-g) shift 2 ;;
            *) a+=("$1"); shift ;;
        esac
    done
    command install "${a[@]}"
}

# the answer to the guard question, as the question recorded it
MANAGED_SETTINGS_LOCK=$ANSWER_LOCK

perform_install
rc=$?
echo "RC=$rc"
exit $rc
'''


def run_perform_install(tmp_path, managed_settings_lock=None):
    """Run perform_install in the fake root and return the result.

    *managed_settings_lock* is the answer to the guard question: "1" is
    the word "lock", nothing else is the default (no).  It is left to
    the installer's own default when it is None.
    """
    make_snap(tmp_path / "snap")
    script_path = tmp_path / "run.sh"
    script_path.write_text(
        PERFORM_INSTALL_HARNESS.replace("##INSTALL##", str(INSTALL))
    )
    env = os.environ.copy()
    if managed_settings_lock is not None:
        env["NEWTON_TEST_ANSWER_LOCK"] = managed_settings_lock
    return subprocess.run(
        ["unshare", "-Ur", "bash", str(script_path), str(tmp_path)],
        capture_output=True, text=True, env=env,
    )


@needs_ns
def test_perform_install_writes_everything(tmp_path):
    """perform_install writes launchers, sudoers.d, code tree, and invokes visudo -cf."""
    r = run_perform_install(tmp_path)
    assert r.returncode == 0, (
        f"perform_install failed rc={r.returncode}\nstdout:\n{r.stdout}\nstderr:\n{r.stderr}"
    )

    for launcher in [
        tmp_path / "bin/newton-mcp",
        tmp_path / "bin/newton-approve",
        tmp_path / "bin/newton-router-setup",
        tmp_path / "bin/newton-vantage-setup",
        tmp_path / "bin/newton-enrol",
        tmp_path / "bin/newton-ad-setup",
        tmp_path / "bin/newton-doctor",
    ]:
        assert launcher.exists(), f"missing launcher {launcher}"
        mode = launcher.stat().st_mode & 0o777
        assert mode == 0o755, f"launcher {launcher} mode is {oct(mode)}, expected 0o755"

    managed = tmp_path / "etc/claude-code/managed-settings.json"
    assert not managed.exists(), (
        "the Claude Code guard must not be written without the owner's "
        f"answer to the question: {managed}"
    )

    sudoers = tmp_path / "sudoers.d/newton-mcp"
    assert sudoers.exists(), f"missing sudoers file {sudoers}"
    lines = sudoers.read_text().splitlines()
    assert len(lines) == 11, \
        f"sudoers.d/newton-mcp should have exactly 11 lines, got {len(lines)}: {lines!r}"
    assert " NOPASSWD: " in lines[0], \
        f"first sudoers line (mcp) must contain NOPASSWD: {lines[0]!r}"
    for ln in lines[1:]:
        assert "NOPASSWD" not in ln, \
            f"only the first sudoers line may contain NOPASSWD: {ln!r}"
    assert "alice ALL=(newton) /usr/local/bin/newton-enrol" in lines
    assert "Defaults!/usr/local/bin/newton-enrol timestamp_timeout=0" in lines
    assert "alice ALL=(newton) /usr/local/bin/newton-ad-setup" in lines
    assert "Defaults!/usr/local/bin/newton-ad-setup timestamp_timeout=0" in lines

    visudo_log = tmp_path / "visudo-log"
    assert visudo_log.exists(), "visudo stub was not called"
    visudo_args = visudo_log.read_text().splitlines()
    cf_lines = [ln for ln in visudo_args if ln == "-cf"]
    assert len(cf_lines) == 1, \
        f"visudo should be called exactly once with -cf, got: {visudo_args!r}"

    code = tmp_path / "opt"
    assert (code / "scripts").exists(), "CODE_ROOT/scripts missing"
    assert (code / "mcp").exists(), "CODE_ROOT/mcp missing"
    assert (code / "SKILL.md").exists(), "CODE_ROOT/SKILL.md missing"
    assert (code / "device/openwrt/newton-router/newton-router").exists(), \
        "CODE_ROOT/device/openwrt/newton-router/newton-router missing"


@needs_ns
def test_perform_install_writes_the_guard_when_the_owner_answers_lock(tmp_path):
    """The word "lock" is the only thing that writes the guard."""
    r = run_perform_install(tmp_path, managed_settings_lock="1")
    assert r.returncode == 0, (
        f"perform_install failed rc={r.returncode}\nstdout:\n{r.stdout}\nstderr:\n{r.stderr}"
    )

    managed = tmp_path / "etc/claude-code/managed-settings.json"
    assert managed.exists(), f"missing managed settings {managed}"
    assert managed.read_text() == '{"allowManagedHooksOnly": true}\n'
    assert managed.stat().st_mode & 0o777 == 0o644


@needs_ns
def test_perform_install_leaves_an_existing_guard_file_alone(tmp_path):
    """Without the answer the file is not touched at all: an upgrade
    (--from-snapshot) never asks the question, so it never writes the
    file and never disturbs one that is already there."""
    existing = tmp_path / "etc/claude-code/managed-settings.json"
    existing.parent.mkdir(parents=True)
    existing.write_text('{"hooks": {"PreToolUse": []}}\n')
    existing.chmod(0o644)

    r = run_perform_install(tmp_path)
    assert r.returncode == 0, (
        f"perform_install failed rc={r.returncode}\nstdout:\n{r.stdout}\nstderr:\n{r.stderr}"
    )

    assert existing.read_text() == '{"hooks": {"PreToolUse": []}}\n'


# ---- the manual credential steps ---------------------------------


@needs_ns
def test_the_install_prints_the_credential_steps_on_a_fresh_machine(tmp_path):
    """The steps are printed on every install.

    Whether there is a credential set to move cannot be told from here:
    a development install may have kept its inventory anywhere
    (NEWTON_INVENTORY), so the absence of the default one proves
    nothing.  The wording says so, so that on a fresh machine the
    block reads as an offer and not as a failure.
    """
    r = run_perform_install(tmp_path)
    assert r.returncode == 0, (
        f"perform_install failed rc={r.returncode}\nstdout:\n{r.stdout}\nstderr:\n{r.stderr}"
    )

    assert (
        "If you ran Newton from your own account before, move its router "
        "credentials to the newton account:" in r.stdout
    )
    assert "Move devices.toml and each password file into " in r.stdout
    assert "On a new machine there is nothing to move." in r.stdout
    # the old wording read like a failure on a fresh machine
    assert "Credentials were not copied" not in r.stdout
    # the client command is still there: it is how the server is started
    assert "MCP client command (all harnesses):" in r.stdout


@needs_ns
def test_the_install_prints_the_credential_steps_for_a_legacy_set(tmp_path):
    """A development install left its credentials in the owner's home:
    the steps that move them into the newton account are printed, in the
    same wording as everywhere else."""
    legacy = tmp_path / "home" / "alice" / ".config" / "newton"
    legacy.mkdir(parents=True)
    (legacy / "devices.toml").write_text('[devices.quasar]\n', encoding="utf-8")

    r = run_perform_install(tmp_path)
    assert r.returncode == 0, (
        f"perform_install failed rc={r.returncode}\nstdout:\n{r.stdout}\nstderr:\n{r.stderr}"
    )

    assert (
        "If you ran Newton from your own account before, move its router "
        "credentials to the newton account:" in r.stdout
    )
    assert "Move devices.toml and each password file into " in r.stdout
    assert "On a new machine there is nothing to move." in r.stdout
    assert "MCP client command (all harnesses):" in r.stdout


def test_the_from_snapshot_mode_never_asks_the_guard_question():
    """--from-snapshot is the upgrade path: it never asks, so it never
    writes the guard."""
    src = INSTALL.read_text()

    from_snapshot_body = _extract_function_body(src, "run_from_snapshot_mode")
    assert "ask_managed_settings" not in from_snapshot_body
    assert "MANAGED_SETTINGS_LOCK" not in from_snapshot_body
    assert "install_managed_settings" not in from_snapshot_body

    perform_body = _extract_function_body(src, "perform_install")
    assert "MANAGED_SETTINGS_LOCK" in perform_body
    assert "install_managed_settings" in perform_body
