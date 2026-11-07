"""The upgrade path (--from-snapshot) cleans up after itself.

The plain mode arms `trap cleanup EXIT` (and HUP/INT/TERM) inside
make_snapshot, so the first install removes its temporaries and rolls
the code root back when a step fails.  The --from-snapshot mode -- the
path every `newton-bootstrap install` upgrade takes -- never armed the
trap: an upgrade left the launcher temp files and the scratch dir
behind, and an upgrade that failed after the code root had been
swapped could leave /opt/newton half-replaced.

The from-snapshot tests drive the real installer inside the fake root
(the harness of test_newton_install_from_snapshot.py).  The plain-mode
test runs the same installer on the host, with the make_snapshot
pattern of test_newton_isolation.py.
"""
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from bootstrap_harness import FakeRoot, userns_ok

REPO = Path(__file__).resolve().parents[2]
INSTALL = REPO / "scripts" / "newton-install"
DOCTOR = REPO / "scripts" / "newton-doctor"
BOOTSTRAP = REPO / "scripts" / "newton-bootstrap"
ENV = {"SUDO_USER": "ci-test"}
needs_ns = pytest.mark.skipif(not userns_ok(), reason="unshare -Urm unavailable")


@pytest.fixture
def fr(tmp_path):
    return FakeRoot(tmp_path)


def required_paths():
    """(kind, path) rows from the installer's own required_snapshot_paths."""
    r = subprocess.run(
        ["bash", "-c", f"source {INSTALL}; required_snapshot_paths"],
        capture_output=True, text=True,
        env={"PATH": "/usr/bin:/bin"}, check=True,
    )
    return [tuple(line.split(" ", 1)) for line in r.stdout.splitlines() if line]


def make_snap(dst: Path) -> Path:
    """A snapshot directory with the REAL installer and a doctor file the
    installer can render.

    Every required path is a placeholder, except the doctor: the
    installer renders the installed copy from it and refuses a source
    without a #! line or without exactly one NEWTON_DOCTOR_SEAMS=1
    marker.  The root is chmod 0755 so it passes the installer's
    `require_root_owned_chain` (the test runner's umask would
    otherwise leave it group-writable).
    """
    for kind, rel in required_paths():
        p = dst / rel
        if kind == "d":
            p.mkdir(parents=True, exist_ok=True)
        else:
            p.parent.mkdir(parents=True, exist_ok=True)
            if rel == "scripts/newton-doctor":
                p.write_text("#!/bin/bash -p\nNEWTON_DOCTOR_SEAMS=1\nexit 0\n")
                os.chmod(p, 0o755)
            else:
                p.write_text("# placeholder for %s\n" % rel)
    shutil.copy2(INSTALL, dst / "scripts/newton-install")
    dst.chmod(0o755)
    return dst


# ---------------------------------------------------------------------------
# the from-snapshot harness: the real installer, in the fake root
# ---------------------------------------------------------------------------

# The body of the installer run, inside the fake root.  It sources the
# REAL installer out of the snapshot (so the code under test is the
# shipped one), sets the globals main() would have set, stubs the
# steps that need a real system (users, groups, ownership, the venv
# build, the program chain check) and then runs the upgrade path.
FROM_SNAPSHOT_INNER = r'''
set -e
source /snap/scripts/newton-install

SYSTEM_USER=newton
SYSTEM_GROUP=newton
NEWTON_HOME=/work/home
CODE_ROOT=/work/opt
LAUNCHER=/work/bin/newton-mcp
APPROVE_LAUNCHER=/work/bin/newton-approve
SETUP_LAUNCHER=/work/bin/newton-router-setup
VANTAGE_SETUP_LAUNCHER=/work/bin/newton-vantage-setup
ENROL_LAUNCHER=/work/bin/newton-enrol
DOCTOR_LAUNCHER=/work/bin/newton-doctor
SUDOERS=/work/sudoers.d/newton-mcp
MANAGED_SETTINGS=/work/etc/claude-code/managed-settings.json
CLIENT_COMMAND=x

SUDOERS_MCP_LINE="alice ALL=(newton) NOPASSWD: /usr/local/bin/newton-mcp"
SUDOERS_APPROVE_LINE="alice ALL=(newton) /usr/local/bin/newton-approve"
SUDOERS_APPROVE_DEFAULTS_LINE="Defaults!/usr/local/bin/newton-approve timestamp_timeout=0"
SUDOERS_SETUP_LINE="alice ALL=(newton) /usr/local/bin/newton-router-setup"
SUDOERS_SETUP_DEFAULTS_LINE="Defaults!/usr/local/bin/newton-router-setup timestamp_timeout=0"
SUDOERS_VANTAGE_SETUP_LINE="alice ALL=(newton) /usr/local/bin/newton-vantage-setup"
SUDOERS_VANTAGE_SETUP_DEFAULTS_LINE="Defaults!/usr/local/bin/newton-vantage-setup timestamp_timeout=0"
SUDOERS_ENROL_LINE="alice ALL=(newton) /usr/local/bin/newton-enrol"
SUDOERS_ENROL_DEFAULTS_LINE="Defaults!/usr/local/bin/newton-enrol timestamp_timeout=0"
invoking_user=alice
VISUDO=/work/bin/visudo-stub

# the stubs: the fake root cannot create users, cannot chown and does
# not own the host's programs
check_root_programs() { :; }
getent() { if [[ $1 == group ]]; then return 0; fi; echo "newton:x:1:1::/work/home:/usr/sbin/nologin"; }
id() { echo newton; }
groupadd() { :; }
useradd() { :; }
chown() { :; }
build_venv() { __BUILD_VENV__; }
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

run_from_snapshot_mode /snap
'''

# The body of the whole fake-root run.  It writes the installer body
# out, runs it as its own process (so the installer's own EXIT trap
# has run by the time the leftovers are listed) and then lists what is
# left behind.
FROM_SNAPSHOT_OUTER = r'''
set -e
T=/work
mkdir -p "$T/bin" "$T/sudoers.d" "$T/etc/claude-code"
cat > "$T/bin/visudo-stub" <<'STUB_EOF'
#!/usr/bin/env bash
exit 0
STUB_EOF
chmod 0755 "$T/bin/visudo-stub"
# $0 of the installer run must resolve to the installer inside the
# snapshot (the installer checks that), so it is a link to it
ln -s /snap/scripts/newton-install /inlink
cat > "$T/inner.sh" <<'INNER_EOF'
__INNER__
INNER_EOF
__OLD_TREE__
if bash -c "$(cat "$T/inner.sh")" /inlink; then rc=0; else rc=$?; fi
list() { if [[ -d $1 ]]; then ls -A "$1" | tr '\n' ' '; fi; }
printf 'RC=[%s]\n' "$rc"
printf 'VARTMP=[%s]\n' "$(list /var/tmp)"
printf 'BIN=[%s]\n' "$(list "$T/bin")"
printf 'SUDOERSDIR=[%s]\n' "$(list "$T/sudoers.d")"
printf 'CODEROOT=[%s]\n' "$(list "$T/opt")"
printf 'CODEOLD=[%s]\n' "$(list "$T/opt.old")"
exit "$rc"
'''

OLD_TREE = 'mkdir -p "$T/opt"; printf \'old install\\n\' > "$T/opt/old-marker"'


def run_from_snapshot(fr, build_ok=True, old_tree=False):
    """Run the upgrade path inside the fake root and return the fields.

    `build_ok=False` makes the venv build fail, so the install dies
    after the code root has been swapped (the old tree moved aside).
    """
    build = 'mkdir -p "$CODE_ROOT/venv"' if build_ok else "return 1"
    inner = FROM_SNAPSHOT_INNER.replace("__BUILD_VENV__", build)
    outer = FROM_SNAPSHOT_OUTER.replace("__INNER__", inner)
    outer = outer.replace("__OLD_TREE__", OLD_TREE if old_tree else "")
    rc, out, err = fr.run(["bash", "-c", outer, "/inlink"], env=ENV)
    return rc, out, err, parse_fields(out)


def parse_fields(out):
    """The KEY=[value] lines the harness prints."""
    fields = {}
    for line in out.splitlines():
        match = re.match(r"^([A-Z]+)=\[(.*)\]$", line)
        if match:
            fields[match.group(1)] = match.group(2)
    return fields


def entries(listing):
    return [name for name in listing.split(" ") if name]


# ---------------------------------------------------------------------------
# 1. a successful upgrade leaves nothing behind
# ---------------------------------------------------------------------------

@needs_ns
def test_from_snapshot_success_leaves_no_temporary_files(fr):
    make_snap(fr.stage / "snap")
    rc, out, err, fields = run_from_snapshot(fr)

    assert rc == 0, f"rc={rc}\nstdout:\n{out}\nstderr:\n{err}"
    assert "Newton installed successfully." in out

    bin_entries = entries(fields["BIN"])
    assert "newton-mcp" in bin_entries, bin_entries
    assert "newton-doctor" in bin_entries, bin_entries
    leftover = [name for name in bin_entries if ".new." in name]
    assert not leftover, f"the upgrade left launcher temporaries behind: {leftover}"

    sudoers_entries = entries(fields["SUDOERSDIR"])
    assert "newton-mcp" in sudoers_entries, sudoers_entries
    leftover = [name for name in sudoers_entries if ".new." in name]
    assert not leftover, f"the upgrade left a sudoers temporary behind: {leftover}"

    scratch = [name for name in entries(fields["VARTMP"]) if name.startswith("newton-install.")]
    assert not scratch, f"the upgrade left its scratch dir behind: {scratch}"


# ---------------------------------------------------------------------------
# 2. an upgrade that fails after the code root was swapped rolls back
# ---------------------------------------------------------------------------

@needs_ns
def test_from_snapshot_failure_restores_the_previous_install(fr):
    make_snap(fr.stage / "snap")
    rc, out, err, fields = run_from_snapshot(fr, build_ok=False, old_tree=True)

    assert rc != 0, f"the failing upgrade should not succeed\nstdout:\n{out}"
    assert "previous installation was restored" in err, err

    assert entries(fields["CODEROOT"]) == ["old-marker"], (
        f"the previous install was not restored: {fields['CODEROOT']!r}"
    )
    assert entries(fields["CODEOLD"]) == [], (
        f"the moved-aside tree was left behind: {fields['CODEOLD']!r}"
    )
    scratch = [name for name in entries(fields["VARTMP"]) if name.startswith("newton-install.")]
    assert not scratch, f"the failed upgrade left its scratch dir behind: {scratch}"


# ---------------------------------------------------------------------------
# 4. every temporary the installer creates is covered by the cleanup trap
# ---------------------------------------------------------------------------

# Every name the installer hands to mktemp. WORK is the scratch dir
# (removed as a directory); the others are files.
EXPECTED_TEMPS = {
    "WORK",
    "launcher_tmp",
    "approve_launcher_tmp",
    "setup_launcher_tmp",
    "vantage_setup_launcher_tmp",
    "enrol_launcher_tmp",
    "sudoers_tmp",
    "doctor_tmp",
    "managed_settings_tmp",
    "bootstrap_tmp",
    "bootstrap_source_tmp",
}


def function_body(source, name):
    """The body of `name() { ... }` (brace counting)."""
    lines = source.splitlines()
    for i, line in enumerate(lines):
        if re.match(rf"^{re.escape(name)}\s*\(\)\s*\{{\s*$", line):
            depth = 1
            for j in range(i + 1, len(lines)):
                for ch in lines[j]:
                    if ch == "{":
                        depth += 1
                    elif ch == "}":
                        depth -= 1
                        if depth == 0:
                            return "\n".join(lines[i + 1:j])
            raise AssertionError(f"function {name} never closed")
    raise AssertionError(f"function {name} not found")


def test_every_temporary_the_installer_creates_is_removed_by_cleanup():
    """The cleanup trap must know about every temporary.

    A new mktemp has to be added to EXPECTED_TEMPS and to the cleanup
    list, so an upgrade can never leave one behind.
    """
    src = INSTALL.read_text()
    found = set(re.findall(r"([A-Za-z_][A-Za-z0-9_]*)=\$\(mktemp\b", src))
    assert found == EXPECTED_TEMPS, (
        f"the set of temporaries changed: {sorted(found)}"
    )
    body = function_body(src, "cleanup")
    for name in sorted(found):
        assert f'"${name}"' in body, f"the cleanup trap does not remove ${name}"


BOOTSTRAP_HARNESS = r'''
set -e
T="$1"
source "$2"
BOOTSTRAP_DEST="$T/sbin/newton-bootstrap"
BOOTSTRAP_SOURCE="$T/sbin/newton-bootstrap.source"
SNAP="$T/snap"
COMMIT_ID=0123456789abcdef0123456789abcdef01234567
mkdir -p "$T/sbin" "$T/snap/scripts"
printf '#!/bin/sh\nexit 0\n' > "$T/snap/scripts/newton-bootstrap"
trap cleanup EXIT
# the install of the bootstrap copy fails
install() { return 1; }
install_bootstrap
'''


def test_the_bootstrap_temporaries_are_removed_when_the_install_fails(tmp_path):
    """A failed bootstrap install leaves no newton-bootstrap.new.* behind."""
    sbin = tmp_path / "sbin"
    sbin.mkdir()
    harness = tmp_path / "bootstrap.sh"
    harness.write_text(BOOTSTRAP_HARNESS)
    result = subprocess.run(
        ["bash", str(harness), str(tmp_path), str(INSTALL)],
        capture_output=True, text=True, timeout=60,
    )
    assert result.returncode != 0, result.stdout
    leftover = [p.name for p in sbin.iterdir() if ".new." in p.name]
    assert not leftover, f"the failed bootstrap install left temporaries behind: {leftover}"


MANAGED_SETTINGS_HARNESS = r'''
set -e
T="$1"
source "$2"
MANAGED_SETTINGS="$T/etc/claude-code/managed-settings.json"
mkdir -p "$T/etc/claude-code"
trap cleanup EXIT
# the ownership of the temporary file cannot be set
chown() { return 1; }
install_managed_settings
'''


def test_the_managed_settings_temporary_is_removed_when_the_install_fails(tmp_path):
    """A failed guard write leaves no .managed-settings.json.new.* behind."""
    claude = tmp_path / "etc/claude-code"
    claude.mkdir(parents=True)
    # the guard refuses a directory that is writable by group or other
    claude.chmod(0o755)
    harness = tmp_path / "managed.sh"
    harness.write_text(MANAGED_SETTINGS_HARNESS)
    result = subprocess.run(
        ["bash", str(harness), str(tmp_path), str(INSTALL)],
        capture_output=True, text=True, timeout=60,
    )
    assert result.returncode != 0, result.stdout
    leftover = [p.name for p in claude.iterdir() if ".new." in p.name]
    assert not leftover, f"the failed guard write left a temporary behind: {leftover}"


# ---------------------------------------------------------------------------
# 3. the plain mode still behaves as it does today
# ---------------------------------------------------------------------------

PLAIN_MODE_HARNESS = r'''
set -e
REPO="$1"
source "$REPO/scripts/newton-install"
# the rootless seam: git runs as the invoking user, and the work dir
# is under ${TMPDIR:-/tmp}
INSTALL_ROOT="$REPO"
invoking_user=$(id -un)
make_snapshot || exit 1
printf 'WORK=[%s]\n' "$WORK"

SYSTEM_USER=newton
SYSTEM_GROUP=newton
NEWTON_HOME="$T/home"
CODE_ROOT="$T/opt"
LAUNCHER="$T/bin/newton-mcp"
APPROVE_LAUNCHER="$T/bin/newton-approve"
SETUP_LAUNCHER="$T/bin/newton-router-setup"
VANTAGE_SETUP_LAUNCHER="$T/bin/newton-vantage-setup"
ENROL_LAUNCHER="$T/bin/newton-enrol"
DOCTOR_LAUNCHER="$T/bin/newton-doctor"
SUDOERS="$T/sudoers.d/newton-mcp"
MANAGED_SETTINGS="$T/etc/claude-code/managed-settings.json"
CLIENT_COMMAND=x

SUDOERS_MCP_LINE="alice ALL=(newton) NOPASSWD: /usr/local/bin/newton-mcp"
SUDOERS_APPROVE_LINE="alice ALL=(newton) /usr/local/bin/newton-approve"
SUDOERS_APPROVE_DEFAULTS_LINE="Defaults!/usr/local/bin/newton-approve timestamp_timeout=0"
SUDOERS_SETUP_LINE="alice ALL=(newton) /usr/local/bin/newton-router-setup"
SUDOERS_SETUP_DEFAULTS_LINE="Defaults!/usr/local/bin/newton-router-setup timestamp_timeout=0"
SUDOERS_VANTAGE_SETUP_LINE="alice ALL=(newton) /usr/local/bin/newton-vantage-setup"
SUDOERS_VANTAGE_SETUP_DEFAULTS_LINE="Defaults!/usr/local/bin/newton-vantage-setup timestamp_timeout=0"
SUDOERS_ENROL_LINE="alice ALL=(newton) /usr/local/bin/newton-enrol"
SUDOERS_ENROL_DEFAULTS_LINE="Defaults!/usr/local/bin/newton-enrol timestamp_timeout=0"
invoking_user=alice
VISUDO="$T/bin/visudo-stub"

getent() { if [[ $1 == group ]]; then return 0; fi; echo "newton:x:1:1::$T/home:/usr/sbin/nologin"; }
id() { echo newton; }
groupadd() { :; }
useradd() { :; }
chown() { :; }
build_venv() { return 1; }
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

perform_install
'''


def make_install_repo(tmp_path):
    """A git repo with every path the installer's snapshot needs."""
    repo = tmp_path / "repo"
    (repo / "scripts").mkdir(parents=True)
    (repo / "mcp").mkdir()
    shutil.copy2(INSTALL, repo / "scripts/newton-install")
    shutil.copy2(DOCTOR, repo / "scripts/newton-doctor")
    shutil.copy2(BOOTSTRAP, repo / "scripts/newton-bootstrap")
    (repo / "mcp/pyproject.toml").write_text("[project]\nname = 'newton-mcp'\n")
    (repo / "mcp/requirements.lock").write_text("# hash-pinned dependencies\n")
    for rel in (
        "device/openwrt/newton-router/newton-router",
        "device/openwrt/newton-router/router-tools.txt",
        "device/openwrt/newton-router/grammar.tsv",
        "device/openwrt/newton-guard/newton-guard",
        "device/openwrt/newton-guard/newton-guard.init",
        "profiles/openwrt/manifest.toml",
        "profiles/openwrt/standard.uci",
        "profiles/openwrt/hardened.uci",
        "profiles/openwrt/lockdown.uci",
        "profiles/openwrt/intents.toml",
    ):
        path = repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("# fixture source for %s\n" % rel)
    (repo / "SKILL.md").write_text("# Newton\n")
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test Operator"], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.email", "operator@example.test"], check=True
    )
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "trusted source"], check=True)
    return repo


def test_plain_mode_failure_restores_the_previous_install(tmp_path):
    """The plain mode behaves as it does today: the failure rolls the
    previous install back."""
    repo = make_install_repo(tmp_path)
    work = tmp_path / "work"
    (work / "bin").mkdir(parents=True)
    (work / "sudoers.d").mkdir(parents=True)
    (work / "etc/claude-code").mkdir(parents=True)
    (work / "opt").mkdir()
    (work / "opt/old-marker").write_text("old install\n")
    stub = work / "bin/visudo-stub"
    stub.write_text("#!/usr/bin/env bash\nexit 0\n")
    stub.chmod(0o755)

    harness = tmp_path / "plain.sh"
    harness.write_text(PLAIN_MODE_HARNESS.replace("$T", str(work)))
    result = subprocess.run(
        ["bash", str(harness), str(repo)],
        capture_output=True, text=True, timeout=120,
    )

    assert result.returncode != 0, result.stdout
    assert "previous installation was restored" in result.stderr, result.stderr

    assert (work / "opt/old-marker").exists(), "the previous install was not restored"
    assert sorted(p.name for p in (work / "opt").iterdir()) == ["old-marker"], (
        "the half-built tree was left in the code root"
    )
    assert not (work / "opt.old").exists(), "the moved-aside tree was left behind"

    leftover = [p.name for p in (work / "bin").iterdir() if ".new." in p.name]
    assert not leftover, f"the plain mode left launcher temporaries behind: {leftover}"
    leftover = [p.name for p in (work / "sudoers.d").iterdir() if ".new." in p.name]
    assert not leftover, f"the plain mode left a sudoers temporary behind: {leftover}"

    work_dir = parse_fields(result.stdout).get("WORK", "")
    assert work_dir, result.stdout
    assert not Path(work_dir).exists(), f"the plain mode left its scratch dir behind: {work_dir}"
