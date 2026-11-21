"""The setup commands SETUP.md and docs/INSTALL.md give, run as written.

A command the owner (or the agent following SETUP.md) copies must be safe to
run twice and must check before it writes: the skill copy stops before it
touches an existing or linked skill folder, and the inventory append never
adds a second table for a device it already holds (a duplicate table makes
the whole inventory unreadable, so every device stops working).
"""

import os
import sys
import re
import subprocess
import tomllib
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SETUP = REPO / "SETUP.md"
INSTALL = REPO / "docs" / "INSTALL.md"


def _section(text: str, heading: str) -> str:
    start = text.index(heading)
    nxt = text.find("\n## ", start + len(heading))
    return text[start:] if nxt == -1 else text[start:nxt]


def _first_block(text: str) -> str:
    m = re.search(r"```(?:sh|text)?\n(.*?)\n\s*```", text, re.S)
    assert m, text[:400]
    return "\n".join(line.strip() for line in m.group(1).splitlines())


def _skill_copy_block(doc: Path) -> str:
    return _first_block(_section(doc.read_text(encoding="utf-8"), "## 3. Install the skill"))


@pytest.fixture
def home(tmp_path):
    home = tmp_path / "home"
    repo = home / "newton"
    repo.mkdir(parents=True)
    (repo / "SKILL.md").write_text("release skill\n")
    env = dict(os.environ, HOME=str(home), GIT_CONFIG_GLOBAL=os.devnull,
               GIT_CONFIG_NOSYSTEM="1")
    for args in (["init", "-q"], ["add", "SKILL.md"],
                 ["-c", "user.name=t", "-c", "user.email=t@example.invalid",
                  "commit", "-q", "-m", "r"]):
        subprocess.run(["git", "-C", str(repo), *args], check=True, env=env)
    (home / ".claude" / "skills").mkdir(parents=True)
    return home, env


def _run(block: str, env) -> subprocess.CompletedProcess:
    return subprocess.run(["bash", "-c", block], env=env, text=True,
                          capture_output=True, timeout=60)


@pytest.mark.parametrize("doc", [SETUP, INSTALL], ids=["SETUP", "INSTALL"])
def test_skill_copy_never_writes_into_an_existing_folder(home, doc):
    """An existing, non-empty skill folder (the owner's own edits) is left
    exactly as it was: the check runs before the copy."""
    home, env = home
    mine = home / ".claude" / "skills" / "newton"
    mine.mkdir()
    (mine / "SKILL.md").write_text("my edits\n")
    (mine / "old-only.md").write_text("old\n")

    res = _run(_skill_copy_block(doc), env)

    assert (mine / "SKILL.md").read_text() == "my edits\n"
    assert sorted(p.name for p in mine.iterdir()) == ["SKILL.md", "old-only.md"]
    assert "EXISTS" in res.stdout, res.stdout + res.stderr


@pytest.mark.parametrize("doc", [SETUP, INSTALL], ids=["SETUP", "INSTALL"])
def test_skill_copy_never_writes_through_a_link(home, doc, tmp_path):
    home, env = home
    target = tmp_path / "linked"
    target.mkdir()
    (home / ".claude" / "skills" / "newton").symlink_to(target)

    res = _run(_skill_copy_block(doc), env)

    assert list(target.iterdir()) == []
    assert "SYMLINK" in res.stdout, res.stdout + res.stderr


@pytest.mark.parametrize("doc", [SETUP, INSTALL], ids=["SETUP", "INSTALL"])
def test_skill_copy_copies_into_an_absent_or_empty_folder(home, doc):
    home, env = home
    dest = home / ".claude" / "skills" / "newton"

    res = _run(_skill_copy_block(doc), env)
    assert res.returncode == 0, res.stdout + res.stderr
    assert (dest / "SKILL.md").read_text() == "release skill\n"

    for p in dest.iterdir():
        p.unlink()
    res = _run(_skill_copy_block(doc), env)
    assert res.returncode == 0, res.stdout + res.stderr
    assert (dest / "SKILL.md").read_text() == "release skill\n"


def _inventory_block(doc: Path) -> str:
    text = doc.read_text(encoding="utf-8")
    if doc == SETUP:
        part = text[text.index("b. The router entry."):]
    else:
        part = text[text.index("**7b.**"):]
    block = _first_block(part)
    return block.replace("\\\n", " ")


@pytest.mark.parametrize("doc", [SETUP, INSTALL], ids=["SETUP", "INSTALL"])
def test_inventory_append_run_twice_keeps_one_table(doc, tmp_path):
    """Run the documented append twice (the owner retrying an uncertain
    step): the inventory still parses and holds the device once."""
    inv = tmp_path / "devices.toml"
    inv.write_text('[devices.other]\nplatform = "openwrt"\nhost = "192.0.2.9"\nuser = "root"\n')
    block = _inventory_block(doc)
    assert "sudo -u newton " in block
    block = block.replace("sudo -u newton ", "").replace("/var/lib/newton/devices.toml", str(inv))
    block = block.replace("<name>", "router1").replace("<router-ip>", "192.0.2.1")
    block = block.replace(" router1 192.0.2.1 ", " router1 192.0.2.1 ")

    for _ in range(2):
        res = subprocess.run(["bash", "-c", block], text=True, capture_output=True, timeout=30)
        assert res.returncode == 0, res.stdout + res.stderr

    data = tomllib.loads(inv.read_text())
    assert set(data["devices"]) == {"other", "router1"}
    assert data["devices"]["router1"]["host"] == "192.0.2.1"
    assert inv.read_text().count("[devices.router1]") == 1


def test_setup_checkup_step_names_what_each_mode_can_run():
    """The no-install mode (the default) refuses newton_guided_audit, so the
    final checkup names what each mode runs."""
    text = SETUP.read_text(encoding="utf-8")
    step = text[text.index("g. Read-only checkup"):text.index("h. Ask the user")]
    flat = " ".join(step.split())
    assert "no-install" in flat
    assert "`newton_list_devices`" in flat and "`newton_read`" in flat
    assert "the guided audit needs the installed mode" in flat


# ---- every inventory append in the docs checks for the table first ----

RELEASE_README = REPO / "docs" / "release" / "README-1.0.md"
SKILL = REPO / "SKILL.md"
CLIENTS = REPO / "docs" / "SETUP-CLIENTS.md"
INSTALLER = REPO / "scripts" / "newton-install"


def _release_readme() -> Path:
    """The public README: docs/release/README-1.0.md, or README.md in the
    public tree, where the scrub renamed it."""
    return RELEASE_README if RELEASE_README.exists() else REPO / "README.md"


APPEND = "tee -a /var/lib/newton/devices.toml"


@pytest.mark.parametrize("doc", [SETUP, INSTALL, SKILL, CLIENTS, None],
                         ids=["SETUP", "INSTALL", "SKILL", "CLIENTS", "README"])
def test_every_inventory_append_checks_for_its_table_first(doc):
    """A second table for a name the inventory already holds makes the
    whole inventory unreadable, so every documented append (the router,
    the domain controllers, a client machine) is behind its own
    grep -qxF of the table line: nothing between the previous append and
    this one may be missing that check."""
    doc = doc or _release_readme()
    text = doc.read_text(encoding="utf-8")
    start = 0
    for m in re.finditer(re.escape(APPEND), text):
        since_last = text[start:m.start()]
        assert re.search(r"grep -qxF '\[(devices|vantages)\.", since_last), (
            f"{doc.name}: unguarded inventory append near: "
            + text[max(0, m.start() - 200):m.end()]
        )
        start = m.end()


def _block_after(text: str, marker: str) -> str:
    return _first_block(text[text.index(marker):]).replace("\\\n", " ")


def test_dc_inventory_append_run_twice_keeps_one_table_each(tmp_path):
    """INSTALL.md step 10e, run twice (the owner unsure the first run
    worked): the inventory still parses and holds each entry once."""
    text = INSTALL.read_text(encoding="utf-8")
    block = _block_after(text[text.index("**10e.**"):], "Then append both")
    inv = tmp_path / "devices.toml"
    inv.write_text('[devices.router1]\nplatform = "openwrt"\nhost = "192.0.2.1"\nuser = "root"\n')
    (tmp_path / "dc1.toml").write_text(
        '[devices.dc1]\nplatform = "ad-samba"\nhost = "192.0.2.21"\nuser = "newton-audit"\n')
    (tmp_path / "dc1-ops.toml").write_text(
        '[devices.dc1-ops]\nplatform = "ad-samba"\nhost = "192.0.2.21"\nuser = "newton-ops"\n')
    assert "sudo -u newton " in block
    block = block.replace("sudo -u newton ", "").replace("/var/lib/newton/devices.toml", str(inv))

    for _ in range(2):
        res = subprocess.run(["bash", "-c", block], text=True, capture_output=True,
                             timeout=30, cwd=tmp_path)
        assert res.returncode == 0, res.stdout + res.stderr

    data = tomllib.loads(inv.read_text())
    assert set(data["devices"]) == {"router1", "dc1", "dc1-ops"}
    assert inv.read_text().count("[devices.dc1]") == 1
    assert inv.read_text().count("[devices.dc1-ops]") == 1


# ---- the Python the installer needs is named before anything is written ----

def _section_of(doc: Path, heading: str) -> str:
    return _section(doc.read_text(encoding="utf-8"), heading)


@pytest.mark.parametrize("doc,heading", [
    (SETUP, "## 1. Check the prerequisites"),
    (INSTALL, "## 1. Check the prerequisites"),
    (CLIENTS, "## Before you start"),
], ids=["SETUP", "INSTALL", "CLIENTS"])
def test_prerequisites_name_python_3_11(doc, heading):
    """The installer's venv needs Python 3.11 to 3.14 (the lock file has
    only cp311 to cp314 wheels); the prerequisites say so."""
    assert "3.11" in _section_of(doc, heading)


@pytest.mark.parametrize("doc", [SETUP, INSTALL], ids=["SETUP", "INSTALL"])
def test_prerequisite_check_tests_the_python_version(doc):
    """The documented check refuses an older python3, and passes on this
    one (the suite runs on 3.11 or newer)."""
    block = _first_block(_section_of(doc, "## 1. Check the prerequisites"))
    line = next(line for line in block.splitlines() if "python3 -c" in line)
    assert "(3, 11) <= v <= (3, 14)" in line, line
    res = subprocess.run(["bash", "-c", line.split("  #")[0]], text=True,
                         capture_output=True, timeout=30)
    assert res.returncode == 0, res.stdout + res.stderr


def _fake_python(tmp_path: Path, version: str) -> Path:
    """This python3, reporting *version*: it runs the installer's own
    check code (`-I -c CODE`) with sys.version_info set to it."""
    major, minor = (int(part) for part in version.split("."))
    fake = tmp_path / f"python-{version}"
    fake.write_text(
        "#!/bin/sh\n"
        f'exec "{sys.executable}" -I -c "import sys; '
        f"sys.version_info = ({major}, {minor}, 0, 'final', 0); "
        'exec(sys.argv[1])" "$3"\n')
    fake.chmod(0o755)
    return fake


def _main_with_python(tmp_path: Path, python: Path, *args: str):
    env = dict(os.environ, NEWTON_INSTALL_ROOT=str(tmp_path / "root"), SUDO_USER="agent")
    script = f'source "{INSTALLER}"; INSTALL_PYTHON="{python}"; main "$@"'
    return subprocess.run(["bash", "-c", script, "newton-install", *args], text=True,
                          capture_output=True, timeout=120, env=env, cwd=tmp_path)


def test_installer_check_refuses_python_older_than_3_11(tmp_path):
    """--check stops on an old python3 and names the version it found."""
    res = _main_with_python(tmp_path, _fake_python(tmp_path, "3.10"), "--check")
    assert res.returncode != 0
    assert "Python 3.11 to 3.14" in res.stderr, res.stdout + res.stderr
    assert "found 3.10" in res.stderr, res.stderr
    assert "CHECK ONLY" not in res.stdout
    assert not (tmp_path / "root").exists()


def _body(src: str, name: str) -> str:
    start = src.index(f"\n{name}() {{\n")
    return src[start:src.index("\n}\n", start)]


@pytest.mark.parametrize("func,first_write", [
    ("main", "make_snapshot || exit"),
    ("run_from_snapshot_mode", "perform_install"),
], ids=["plain", "from-snapshot"])
def test_installer_checks_python_before_it_writes(func, first_write):
    """The plain and the --from-snapshot mode (both need root, which a
    test cannot be) check python3 right after the root programs and
    before the first step that writes, so a too-old python3 leaves no
    newton user, group or home behind."""
    body = _body(INSTALLER.read_text(encoding="utf-8"), func)
    if func == "main":
        body = body[body.index("# Plain (real install) mode"):]
    roots = body.index("check_root_programs || exit")
    python = body.index("check_python_version || exit 1")
    assert roots < python < body.index(first_write)


def test_installer_check_names_the_python_it_will_use(tmp_path):
    res = _main_with_python(tmp_path, _fake_python(tmp_path, "3.12"), "--check")
    assert res.returncode == 0, res.stderr
    assert "Python 3.12 (3.11 to 3.14 needed)" in res.stdout, res.stdout


def test_failed_first_install_does_not_claim_nothing_was_installed(tmp_path):
    """The user, group and home are created before the venv is built,
    so a failure there must not say nothing was installed."""
    code_root = tmp_path / "opt-newton"
    code_root.mkdir()
    script = (f'source "{INSTALLER}"; CODE_ROOT="{code_root}"; CODE_ROOT_PENDING=1; '
              'CODE_ROOT_BACKUP=; cleanup')
    res = subprocess.run(["bash", "-c", script], text=True, capture_output=True, timeout=30)
    assert "nothing was installed" not in res.stderr, res.stderr
    assert "the newton user" in res.stderr, res.stderr
    assert not code_root.exists()


# ---- the docs list every launcher and sudoers rule the installer writes ----

def _installer_launchers() -> list[str]:
    return re.findall(r"^\t[A-Z_]*LAUNCHER=(/usr/local/bin/[a-z-]+)$",
                      INSTALLER.read_text(encoding="utf-8"), re.M)


def test_setup_clients_table_lists_every_launcher_and_its_sudoers_rule():
    table = _section_of(CLIENTS, "## What `newton-install` creates")
    launchers = _installer_launchers()
    assert len(launchers) >= 7, launchers
    for path in launchers:
        assert f"| `{path}` (" in table, path
        if path.endswith(("newton-mcp", "newton-doctor")):
            continue
        assert f"ALL=(newton) {path}`" in table, path
        assert f"`Defaults!{path} timestamp_timeout=0`" in table, path


def test_setup_clients_approve_row_names_the_ad_change_form():
    table = _section_of(CLIENTS, "## What `newton-install` creates")
    row = next(line for line in table.splitlines() if line.startswith("| Approve launcher"))
    assert "ad-change" in row, row


def test_install_step_4_lists_every_launcher():
    step = " ".join(_section_of(INSTALL, "## 4.").split())
    for path in _installer_launchers():
        assert f"`{path.rsplit('/', 1)[1]}`" in step or f"`{path}`" in step, path


# ---- a client machine for client checks and scans ----

def _vantage_step() -> str:
    return _section_of(INSTALL, "## 11. A client machine for client checks and scans")


def test_install_doc_gives_a_vantage_entry_the_setup_tool_accepts(tmp_path):
    """The [vantages.<name>] example passes newton-vantage-setup's own
    inventory check (the same rules the server applies)."""
    step = _vantage_step()
    m = re.search(r"```toml\n(.*?)\n```", step, re.S)
    assert m, step[:400]
    entry = m.group(1)
    name = re.search(r"^\[vantages\.([a-z0-9-]+)\]$", entry, re.M).group(1)
    ssh_dir = tmp_path / "ssh"
    ssh_dir.mkdir()
    entry = entry.replace("/var/lib/newton/.ssh", str(ssh_dir))
    inv = tmp_path / "devices.toml"
    inv.write_text('[devices.router1]\nplatform = "openwrt"\nhost = "192.0.2.1"\nuser = "root"\n\n'
                   + entry + "\n")
    inv.chmod(0o600)
    src = (REPO / "scripts" / "newton-vantage-setup").read_text(encoding="utf-8")
    checker = src[src.index("<<'PYEOF'\n") + len("<<'PYEOF'\n"):src.index("\nPYEOF\n")]
    res = subprocess.run([sys.executable, "-I", "-c", checker, str(inv), name],
                         text=True, capture_output=True, timeout=30)
    assert res.returncode == 0, res.stderr
    assert "role=inside" in res.stdout
    assert "zone_count=1" in res.stdout


def test_install_doc_vantage_step_runs_install_and_check():
    flat = " ".join(_vantage_step().split())
    for action in ("install", "check", "install-client-checks", "check-client-checks"):
        assert f"sudo -u newton /usr/local/bin/newton-vantage-setup pc1 {action}" in flat, action


def test_readme_and_setup_point_to_the_vantage_step():
    readme = _release_readme().read_text(encoding="utf-8")
    for marker in ("Checks from a client's point of view", "nmap scans from inside your network"):
        line = next(line for line in readme.splitlines() if marker in line)
        assert "`docs/INSTALL.md` step 11" in line, line
    assert "docs/INSTALL.md` step 11" in " ".join(SETUP.read_text(encoding="utf-8").split())


# ---- no-install approval-key asks no authenticator question ----

def test_setup_approval_key_step_says_no_install_has_no_authenticator_offer():
    text = SETUP.read_text(encoding="utf-8")
    step = " ".join(text[text.index("f. `sudo -u newton"):text.index("g. Read-only checkup")].split())
    assert "On a no-install device" in step, step
    assert "does not offer the authenticator" in step, step
    src = (REPO / "scripts" / "newton-router-setup").read_text(encoding="utf-8")
    body = src[src.index("action_approval_key() {"):]
    body = body[:body.index("\n}\n")]
    no_install = body[body.index('"no-install" ]]; then'):body.index("fi")]
    assert "totp_offer" not in no_install


# ---- an update tells the owner to reconnect ----

def test_install_update_step_says_finish_held_changes_and_reconnect():
    text = INSTALL.read_text(encoding="utf-8")
    part = " ".join(text[text.index("**Later updates.**"):text.index("## 5.")].split())
    assert "confirm or abort every held change" in part, part
    assert "`/mcp`" in part and "reconnect" in part, part
    assert "newton-router-setup <device> upgrade" in part, part


# ---- a no-install setup already asked for the passphrase ----

def test_setup_approval_key_step_says_no_install_already_asked():
    text = SETUP.read_text(encoding="utf-8")
    step = " ".join(text[text.index("f. `sudo -u newton"):text.index("g. Read-only checkup")].split())
    assert "no-install setup in step e already asked for the passphrase" in step, step
    assert "only to change the passphrase" in step, step
    four = " ".join(_section(text, "## 4. Give the user").split())
    assert "step 7e (no-install) or step 7f (installed)" in four, four


# ---- a router that refuses root passwords after swap-key ----

@pytest.mark.parametrize("doc,start,end", [
    (INSTALL, "**7e.**", "**7g.**"),
    (SETUP, "e. Choose the access mode", "g. Read-only checkup"),
], ids=["INSTALL", "SETUP"])
def test_refused_password_router_needs_the_admin_key_on_every_later_action(doc, start, end):
    text = doc.read_text(encoding="utf-8")
    part = " ".join(text[text.index(start):text.index(end)].split())
    assert "every later setup command" in part, part
    assert "--admin plain-key --plain-key <admin key>" in part, part
    # the commands run as newton, so the key must be one newton can read
    assert "account can read" in part, part
    assert "/var/lib/newton/.ssh/admin" in part, part
    assert "check still reports the refused password login as a FAIL" in part, part


# ---- the Python check has an upper bound ----
# The lock file's pydantic-core has wheels for cp311 to cp314 only, and
# the venv is built with --only-binary=:all: --require-hashes, so a newer
# Python fails in build_venv after the newton user was created.

def test_lock_file_has_no_wheel_newer_than_cp314():
    """The upper bound below is the lock file's: pydantic-core has no
    cp315 or abi3 wheel.  When it gains one, raise the bound and this."""
    lock = (REPO / "mcp" / "uv.lock").read_text(encoding="utf-8")
    tags = set(re.findall(r"pydantic_core-[0-9.]+-cp3(\d+)-", lock))
    assert tags and max(int(t) for t in tags) == 14, tags
    assert not re.search(r"pydantic_core-[0-9.]+-cp3\d+-abi3", lock)


@pytest.mark.parametrize("version", ["3.15", "3.16", "4.0"])
def test_installer_check_refuses_python_newer_than_3_14(tmp_path, version):
    res = _main_with_python(tmp_path, _fake_python(tmp_path, version), "--check")
    assert res.returncode != 0, res.stdout + res.stderr
    assert "Python 3.11 to 3.14" in res.stderr, res.stderr
    assert f"found {version}" in res.stderr, res.stderr
    assert "CHECK ONLY" not in res.stdout
    assert not (tmp_path / "root").exists()


@pytest.mark.parametrize("version", ["3.11", "3.14"])
def test_installer_check_accepts_the_supported_pythons(tmp_path, version):
    res = _main_with_python(tmp_path, _fake_python(tmp_path, version), "--check")
    assert res.returncode == 0, res.stdout + res.stderr
    assert f"Python {version} (3.11 to 3.14 needed)" in res.stdout, res.stdout


def _doc_python_line(doc: Path) -> str:
    block = _first_block(_section_of(doc, "## 1. Check the prerequisites"))
    return next(line for line in block.splitlines() if "python3 -c" in line).split("  #")[0]


def _doc_fake_python(tmp_path: Path, version: str) -> Path:
    """A python3 for the documented `/usr/bin/python3 -c CODE` line,
    reporting *version*."""
    major, minor = (int(part) for part in version.split("."))
    fake = tmp_path / f"doc-python-{version}"
    fake.write_text(
        "#!/bin/sh\n"
        f'exec "{sys.executable}" -I -c "import sys; '
        f"sys.version_info = ({major}, {minor}, 0, 'final', 0); "
        'exec(sys.argv[1])" "$2"\n')
    fake.chmod(0o755)
    return fake


@pytest.mark.parametrize("doc", [SETUP, INSTALL], ids=["SETUP", "INSTALL"])
@pytest.mark.parametrize("version,ok", [
    ("3.10", False), ("3.11", True), ("3.14", True), ("3.15", False),
])
def test_prerequisite_check_bounds_the_python_version(tmp_path, doc, version, ok):
    line = _doc_python_line(doc)
    assert line.startswith("/usr/bin/python3 -c "), line
    line = line.replace("/usr/bin/python3", str(_doc_fake_python(tmp_path, version)), 1)
    res = subprocess.run(["bash", "-c", line], text=True, capture_output=True, timeout=30)
    assert (res.returncode == 0) is ok, (version, res.stdout + res.stderr)
    if not ok:
        assert "Python 3.11 to 3.14 is needed" in res.stderr, res.stderr


@pytest.mark.parametrize("doc,heading", [
    (SETUP, "## 1. Check the prerequisites"),
    (INSTALL, "## 1. Check the prerequisites"),
    (CLIENTS, "## Before you start"),
], ids=["SETUP", "INSTALL", "CLIENTS"])
def test_prerequisites_name_the_upper_bound(doc, heading):
    section = " ".join(_section_of(doc, heading).split())
    assert "3.11 or newer" not in section, section
    assert "3.11 to 3.14" in section, section


# ---- an inventory append survives a missing final newline ----

def _run_append(block: str, inv: Path, cwd: Path) -> None:
    assert "sudo -u newton " in block
    block = block.replace("sudo -u newton ", "").replace("/var/lib/newton/devices.toml", str(inv))
    res = subprocess.run(["bash", "-c", block], text=True, capture_output=True,
                         timeout=30, cwd=cwd)
    assert res.returncode == 0, res.stdout + res.stderr


def test_dc_inventory_append_survives_entries_without_a_final_newline(tmp_path):
    """INSTALL.md 10e: the owner pastes each entry and stops before its
    final newline (Ctrl-D twice after `cat > dc1.toml`), and the
    inventory itself ends without one: every table still lands on a line
    of its own, and a second run adds nothing."""
    text = INSTALL.read_text(encoding="utf-8")
    block = _block_after(text[text.index("**10e.**"):], "Then append both")
    inv = tmp_path / "devices.toml"
    inv.write_text('[devices.router1]\nplatform = "openwrt"\nhost = "192.0.2.1"\nuser = "root"')
    (tmp_path / "dc1.toml").write_text(
        '[devices.dc1]\nplatform = "ad-samba"\nhost = "192.0.2.21"\nuser = "newton-audit"')
    (tmp_path / "dc1-ops.toml").write_text(
        '[devices.dc1-ops]\nplatform = "ad-samba"\nhost = "192.0.2.21"\nuser = "newton-ops"')
    for _ in range(2):
        _run_append(block, inv, tmp_path)
    data = tomllib.loads(inv.read_text())
    assert set(data["devices"]) == {"router1", "dc1", "dc1-ops"}
    assert inv.read_text().count("[devices.dc1]") == 1
    assert inv.read_text().count("[devices.dc1-ops]") == 1
    # a second router added later with 7b, whose printf starts with the
    # table line: the last entry's missing newline must not glue onto it
    router = _block_after(text, "**7b.**").replace("router1", "router2")
    _run_append(router, inv, tmp_path)
    assert set(tomllib.loads(inv.read_text())["devices"]) == {"router1", "router2", "dc1", "dc1-ops"}


def test_vantage_inventory_append_survives_an_entry_without_a_final_newline(tmp_path):
    """INSTALL.md 11d, with the same pasted entry and inventory."""
    text = INSTALL.read_text(encoding="utf-8")
    block = _block_after(text, "**11d.**")
    inv = tmp_path / "devices.toml"
    inv.write_text('[devices.router1]\nplatform = "openwrt"\nhost = "192.0.2.1"\nuser = "root"')
    (tmp_path / "pc1.toml").write_text('[vantages.pc1]\nhost = "192.0.2.50"\nuser = "newton-check"')
    for _ in range(2):
        _run_append(block, inv, tmp_path)
    data = tomllib.loads(inv.read_text())
    assert set(data["devices"]) == {"router1"}
    assert set(data["vantages"]) == {"pc1"}
    assert inv.read_text().count("[vantages.pc1]") == 1


# ---- Claude Desktop cannot reach a Linux-only install ----

def test_setup_clients_desktop_entry_says_it_is_unsupported():
    """Claude Desktop has no Linux build and newton-install installs on
    Linux only, so the local sudo entry can never start the server: the
    doc says so, and never that a same-machine setup works."""
    section = " ".join(_section_of(CLIENTS, "### Claude Desktop").split("\n### OpenCode")[0].split())
    assert "same machine" not in section, section
    assert "cannot start the server" in section, section
    assert "not supported" in section, section


# ---- the router append survives an inventory without a final newline ----

@pytest.mark.parametrize("doc", [SETUP, INSTALL], ids=["SETUP", "INSTALL"])
def test_router_inventory_append_survives_an_inventory_without_a_final_newline(doc, tmp_path):
    """The owner hand-edited devices.toml and saved it without a final
    newline: step 7b must still put the new table on a line of its own."""
    inv = tmp_path / "devices.toml"
    inv.write_text('[devices.other]\nplatform = "openwrt"\nhost = "192.0.2.9"\nuser = "root"')
    block = _inventory_block(doc).replace("<name>", "router1").replace("<router-ip>", "192.0.2.1")
    for _ in range(2):
        _run_append(block, inv, tmp_path)
    data = tomllib.loads(inv.read_text())
    assert set(data["devices"]) == {"other", "router1"}
    assert data["devices"]["other"]["user"] == "root"
    assert inv.read_text().count("[devices.router1]") == 1
