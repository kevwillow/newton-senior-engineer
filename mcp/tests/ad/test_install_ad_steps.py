"""The AD setup steps of an installed Newton, as docs/INSTALL.md gives them.

An installed Newton keeps its keys and its inventory in the newton
account's home, which the owner cannot read.  The AD setup steps must
therefore make the audit and write keys as that account, hand the
public half to the setup script, pin the host key, and append the
printed entries with the newton account's own ``tee -a``, the way steps
7b and 7c do it for a router.

These tests read the commands of section 10 of docs/INSTALL.md and run
the ones a test can reach, never through a shell: ``ssh-keygen``, the
setup script and the inventory loader, with ``/var/lib/newton`` moved
into a temporary directory.  ``ssh-keyscan`` and the scripts' run on
the domain controller are not run here.
"""

from __future__ import annotations

import re
import shlex
import shutil
import subprocess
from pathlib import Path

import pytest

import newton_mcp.server as server

REPO_ROOT = Path(__file__).resolve().parents[3]
INSTALL_MD = REPO_ROOT / "docs" / "INSTALL.md"
SKILL_MD = REPO_ROOT / "SKILL.md"
CHANGELOG_MD = REPO_ROOT / "CHANGELOG.md"
SETUP_SCRIPT = REPO_ROOT / "scripts" / "newton-ad-setup"
NEWTON_HOME = "/var/lib/newton"
INSTALLED_SETUP = "/opt/newton/scripts/newton-ad-setup"
SYNTHETIC_GUID = "0f2c4b6e-1a3d-4c5e-8f70-9a1b2c3d4e5f"


def _section() -> str:
    """The text of section 10 of docs/INSTALL.md."""
    text = INSTALL_MD.read_text(encoding="utf-8")
    match = re.search(r"^## 10\. .*?(?=^## )", text, re.MULTILINE | re.DOTALL)
    assert match, "docs/INSTALL.md has no section 10 for Active Directory"
    return match.group(0)


def _blocks(lang: str) -> list[str]:
    """The fenced code blocks of one language in section 10."""
    return re.findall(rf"^```{lang}\n(.*?)^```", _section(), re.MULTILINE | re.DOTALL)


def _commands() -> list[list[str]]:
    """Every sh command of section 10, split the way a shell splits words."""
    commands: list[list[str]] = []
    for block in _blocks("sh"):
        for line in block.splitlines():
            if line.strip():
                commands.append(shlex.split(line))
    assert commands, "section 10 of docs/INSTALL.md has no sh commands"
    return commands


def _keygen_targets() -> list[str]:
    """The -f paths of the ssh-keygen commands that make a key."""
    targets: list[str] = []
    for argv in _commands():
        if argv[:3] == ["sudo", "-u", "newton"] and argv[3:4] == ["ssh-keygen"] and "-t" in argv:
            targets.append(argv[argv.index("-f") + 1])
    return targets


def _setup_commands() -> list[list[str]]:
    """The setup-script commands that print a DC script."""
    return [argv for argv in _commands() if argv and argv[0] == INSTALLED_SETUP]


def _toml_paths() -> dict[str, set[str]]:
    """The key_file and known_hosts values the toml blocks of section 10 show."""
    found: dict[str, set[str]] = {"key_file": set(), "known_hosts": set()}
    for block in _blocks("toml"):
        for field, value in re.findall(r'^(key_file|known_hosts) = "([^"]+)"$', block, re.MULTILINE):
            found[field].add(value)
    return found


def test_the_keys_are_made_as_the_newton_account() -> None:
    """The audit and the write key are made by the newton account, in its .ssh."""
    targets = _keygen_targets()
    assert len(targets) >= 2, f"expected an audit and a write key, got {targets}"
    for target in targets:
        assert target.startswith(f"{NEWTON_HOME}/.ssh/"), target
    for argv in _commands():
        if "ssh-keygen" in argv and "-t" in argv:
            assert argv[:4] == ["sudo", "-u", "newton", "ssh-keygen"], argv
            assert argv[argv.index("-N") + 1] == "", argv


def test_every_pubkey_is_the_public_half_of_a_key_made_here() -> None:
    """Every --pubkey file is a copy of the .pub of a key section 10 makes."""
    copies: dict[str, str] = {}
    for argv in _commands():
        if argv[:4] == ["sudo", "-u", "newton", "cat"] and ">" in argv:
            copies[argv[argv.index(">") + 1]] = argv[4]
    targets = set(_keygen_targets())
    setups = _setup_commands()
    assert setups, "section 10 runs no setup script"
    for argv in setups:
        pubkey = argv[argv.index("--pubkey") + 1]
        assert pubkey in copies, f"--pubkey {pubkey} is not copied from a key"
        source = copies[pubkey]
        assert source.endswith(".pub") and source[: -len(".pub")] in targets, source


def test_the_entries_are_appended_by_the_newton_account() -> None:
    """The inventory is appended with the newton account's tee -a, as 7b does."""
    appends = [
        argv
        for argv in _commands()
        if argv[:5] == ["sudo", "-u", "newton", "tee", "-a"]
        and argv[5] == f"{NEWTON_HOME}/devices.toml"
    ]
    assert appends, "section 10 never appends an entry with sudo -u newton tee -a"


def test_the_host_key_is_pinned_where_the_entries_point() -> None:
    """known_hosts is written by the newton account, and the entries name it."""
    pinned: set[str] = set()
    for block in _blocks("sh"):
        for line in block.splitlines():
            if "ssh-keyscan" in line:
                left, _, right = line.partition("|")
                assert shlex.split(left)[0] == "ssh-keyscan", line
                tee = shlex.split(right)
                assert tee[:4] == ["sudo", "-u", "newton", "tee"], line
                pinned.add(tee[4])
    assert pinned, "section 10 pins no host key"
    paths = _toml_paths()
    assert paths["known_hosts"] and paths["known_hosts"] <= pinned, paths
    assert paths["key_file"] and paths["key_file"] <= set(_keygen_targets()), paths


def test_the_approval_key_command_fits_the_launcher() -> None:
    """The launcher takes approval-key and one device name, nothing else."""
    runs = [argv for argv in _commands() if "/usr/local/bin/newton-ad-setup" in argv]
    assert runs, "section 10 does not record the approval key"
    for argv in runs:
        assert argv[:4] == ["sudo", "-u", "newton", "/usr/local/bin/newton-ad-setup"], argv
        assert len(argv) == 6 and argv[4] == "approval-key", argv
        assert re.fullmatch(r"[a-z][a-z0-9-]{0,31}", argv[5]), argv


def _relocate(value: str, home: Path) -> str:
    """A path of the newton account's home, moved into the test's home."""
    return value.replace(NEWTON_HOME, str(home), 1) if value.startswith(NEWTON_HOME) else value


def _script_entry(script: str, guid: str) -> str:
    """The inventory entry a printed Samba script prints, with its variables set."""
    values = dict(re.findall(r"^([A-Z_]+)='([^']*)'$", script, re.MULTILINE))
    values["DOMAIN_GUID"] = guid
    match = re.search(r"^cat <<EOF\n\n(\[devices\..*?)\n\nThe installed", script, re.MULTILINE | re.DOTALL)
    assert match, "the printed script prints no inventory entry"
    return re.sub(r"\$\{([A-Z_]+)\}", lambda m: values[m.group(1)], match.group(1))


@pytest.mark.skipif(shutil.which("ssh-keygen") is None, reason="ssh-keygen is not installed")
@pytest.mark.parametrize("platform", ["samba", "windows"])
def test_the_documented_commands_run_and_the_filled_entries_load(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, platform: str
) -> None:
    """ssh-keygen, the setup script and the filled-in entries work as written."""
    home = tmp_path / "newton"
    owner = tmp_path / "owner"
    (home / ".ssh").mkdir(parents=True, mode=0o700)
    owner.mkdir()
    for target in _keygen_targets():
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", _relocate(target, home)],
            check=True,
        )
    for argv in _commands():
        if argv[:4] == ["sudo", "-u", "newton", "cat"] and ">" in argv:
            source = Path(_relocate(argv[4], home))
            (owner / argv[argv.index(">") + 1]).write_bytes(source.read_bytes())

    scripts: list[str] = []
    for argv in _setup_commands():
        words = argv[1 : argv.index(">")] if ">" in argv else argv[1:]
        words = [platform if word == "samba" else word for word in words]
        result = subprocess.run(
            [str(SETUP_SCRIPT), *words], cwd=owner, capture_output=True, text=True
        )
        assert result.returncode == 0, (words, result.stderr)
        assert result.stderr == ""
        scripts.append(result.stdout)
    assert len(scripts) >= 2, "section 10 prints an audit and a write script"
    if platform != "samba":
        return

    for path in _toml_paths()["known_hosts"]:
        # A synthetic host key line: any public key has the shape ssh-keyscan prints.
        host_key = " ".join((owner / "dc1-audit.pub").read_text(encoding="utf-8").split()[:2])
        Path(_relocate(path, home)).write_text(f"192.0.2.21 {host_key}\n", encoding="utf-8")
    filled = {
        "key_file": sorted(_toml_paths()["key_file"]),
        "known_hosts": sorted(_toml_paths()["known_hosts"]),
    }
    body = ""
    for script in scripts:
        entry = _script_entry(script, SYNTHETIC_GUID)
        write = 'platform = "ad-samba-write"' in entry
        key = next(k for k in filled["key_file"] if k.endswith("-ops") == write)
        entry = re.sub(r'^key_file = "<[^"]*>"$', f'key_file = "{_relocate(key, home)}"', entry, flags=re.MULTILINE)
        entry = re.sub(
            r'^known_hosts = "<[^"]*>"$',
            f'known_hosts = "{_relocate(filled["known_hosts"][0], home)}"',
            entry,
            flags=re.MULTILINE,
        )
        assert "<" not in entry, entry
        body += entry + "\n\n"
    inventory = home / "devices.toml"
    inventory.write_text(body, encoding="utf-8")
    inventory.chmod(0o600)
    monkeypatch.setenv("NEWTON_INVENTORY", str(inventory))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))

    devices = server.load_inventory()

    platforms = sorted(device.platform for device in devices.values())
    assert platforms == ["ad-samba", "ad-samba-write"], platforms


def _skill_ad_setup() -> str:
    """The Setup part of the Active Directory section of SKILL.md."""
    text = SKILL_MD.read_text(encoding="utf-8")
    match = re.search(r"^### Setup \(the owner runs it\)\n(.*?)(?=^### )", text, re.MULTILINE | re.DOTALL)
    assert match, "SKILL.md has no AD setup part"
    return match.group(1)


def test_the_skill_gives_the_installed_key_and_inventory_steps() -> None:
    """SKILL.md says how an installed Newton makes the keys and adds the entries."""
    setup = _skill_ad_setup()
    assert "sudo -u newton ssh-keygen" in setup
    assert f"sudo -u newton tee -a {NEWTON_HOME}/devices.toml" in setup
    assert "known_hosts" in setup and "docs/INSTALL.md" in setup


def test_the_samba_collector_is_said_to_run_as_root_through_sudo() -> None:
    """SKILL.md and the CHANGELOG say the Samba fixed command runs the collector as root."""
    setup = re.sub(r"\s+", " ", _skill_ad_setup())
    assert "as root through sudo, with no arguments" in setup
    changelog = CHANGELOG_MD.read_text(encoding="utf-8")
    unreleased = changelog.split("## [Unreleased]", 1)[1].split("\n## [", 1)[0]
    assert "as root through sudo, with no arguments" in re.sub(r"\s+", " ", unreleased)
