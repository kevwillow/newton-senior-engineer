"""The commands the owner is told to run.

In the installed layout the setup tool lives at
/usr/local/bin/newton-router-setup, and the launcher that scripts/newton-install
writes refuses to run as anyone but the `newton` user.  A command the owner
copies out of a document therefore has to carry the prefix
`sudo -u newton /usr/local/bin/`: the bare form finds no command in the
installed layout, or hits the launcher's user check.

The disclosure block the install prints and the copies of it in the docs use that
form, and no owner-facing doc may show a bare `newton-router-setup <device>`
command again.
"""

import re
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "scripts" / "newton-router-setup"

# the command the owner runs in the installed layout
OWNER_PREFIX = "sudo -u newton /usr/local/bin/newton-router-setup"

# the docs an owner reads
DOCS = (
    "README.md",
    "SETUP.md",
    "SKILL.md",
    "docs/INSTALL.md",
    "docs/release/README-1.0.md",
    "docs/SETUP-CLIENTS.md",
    "docs/SUPPORT.md",
)

RELEASE_README = "docs/release/README-1.0.md"


def doc_path(name: str) -> Path:
    """The path of a doc.  Without docs/release/README-1.0.md,
    README.md is that file, renamed."""
    path = REPO / name
    if name == RELEASE_README and not path.exists():
        return REPO / "README.md"
    return path


# a setup command with a placeholder in it that does not carry the prefix
BARE = re.compile(r"(?<!sudo -u newton /usr/local/bin/)newton-router-setup <")


def disclosure_block() -> str:
    """The block the install prints, as the tool prints it."""
    proc = subprocess.run(
        ["bash", "-c",
         'source "$1"; router_disclosure_block "$DEFAULT_SRC"',
         "bash", str(TOOL)],
        capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


def test_the_disclosure_block_shows_commands_the_owner_can_run():
    """The block's own commands carry the prefix of the installed
    layout: the upgrade and the uninstall."""
    block = disclosure_block()
    assert OWNER_PREFIX + " <device> upgrade" in block, block
    assert OWNER_PREFIX + " <device> uninstall" in block, block
    assert not BARE.search(block), block


def test_the_docs_carry_the_runnable_commands():
    """Every doc that carries the block carries the runnable form of its
    commands."""
    for name in ("README.md", "SETUP.md", "docs/INSTALL.md",
                 "docs/release/README-1.0.md"):
        text = doc_path(name).read_text(encoding="utf-8")
        assert OWNER_PREFIX + " <device> upgrade" in text, name
        assert OWNER_PREFIX + " <device> uninstall" in text, name


def test_no_owner_facing_doc_shows_a_bare_setup_command():
    """A command the owner is told to type names the installed
    launcher.  The CHANGELOG (a record of what was said when) and the
    design documents are not owner instructions."""
    for name in DOCS:
        text = doc_path(name).read_text(encoding="utf-8")
        found = BARE.findall(text)
        assert not found, (name, found)
