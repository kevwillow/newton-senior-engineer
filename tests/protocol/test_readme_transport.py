"""The transport claims.

The README said that Newton changes OpenWrt routers over SSH and that a
change is confirmed after three rounds over new SSH connections.  That
is the installed mode.  The no-install mode runs the same protocol over
the router's own web API, with OpenWrt's own undo timer, so the README
has to say that too and scope the SSH claims to the mode they are true
in.  The same holds for the README's later rails, for SETUP.md and for
docs/INSTALL.md (the claims were still global)
and for SKILL.md (: the operational skill still said it without
a mode, and the table row about owrt-change.sh with it).
"""

from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
README = REPO / "README.md"
SETUP = REPO / "SETUP.md"
INSTALL = REPO / "docs/INSTALL.md"
SKILL = REPO / "SKILL.md"

# the section that names the two modes: the transport and the
# verification claims come before it
MODES_HEADING = "## What Newton puts on your router"


def readme_head() -> str:
    """The README up to the section that names the two modes."""
    text = README.read_text(encoding="utf-8")
    return text[:text.index(MODES_HEADING)]


def test_the_top_line_scopes_the_ssh_claim_to_the_installed_mode():
    """The SSH claim is true of the installed mode only."""
    head = readme_head()
    assert "In the **installed** mode" in head, head[:400]
    assert "over SSH" in head, head[:400]


def test_the_top_line_says_what_the_no_install_mode_uses():
    """One line for the no-install mode: the router's own web API, over
    HTTPS, pinned by the certificate."""
    head = readme_head()
    assert "In the **no-install** mode" in head, head[:600]
    assert "web API" in head, head[:600]
    assert "HTTPS" in head, head[:600]
    assert "pinned" in head, head[:600]


def test_the_change_protocol_paragraph_scopes_the_verification_claim():
    """The verification over new SSH connections is the installed mode's;
    the no-install mode has its own line, with its undo timer and its
    read-back."""
    text = README.read_text(encoding="utf-8")
    protocol = text[text.index("The change protocol is the whole product."):]
    protocol = protocol[:protocol.index(MODES_HEADING)]
    assert "**new** SSH connections" in protocol, protocol
    assert "three consecutive passing rounds" in protocol, protocol
    assert "That is the **installed** mode" in protocol, protocol
    assert "In the **no-install** mode" in protocol, protocol
    assert "rpcd" in protocol, protocol
    assert "read back" in protocol, protocol


def test_the_readme_does_not_say_the_writes_always_go_over_ssh():
    """No place may say the writes always go over SSH: the no-install
    mode writes over the router's web API."""
    head = readme_head()
    assert "to OpenWrt routers over SSH" not in head, head[:400]


# -- the later claims -------------------------


def _line_with(text: str, needle: str) -> str:
    """The one line of the text that carries the needle."""
    found = [line for line in text.splitlines() if needle in line]
    assert len(found) == 1, (needle, found)
    return found[0]


def test_the_verification_rail_names_the_installed_mode():
    """The rail that keeps a change from being confirmed in the session
    that applied it is the installed mode's; the no-install mode has its
    own line next to it."""
    rail = _line_with(README.read_text(encoding="utf-8"),
                       "Never confirm a change from the session")
    assert "**installed** mode" in rail, rail
    assert "**no-install** mode" in rail, rail
    assert "HTTPS" in rail and "pinned" in rail, rail
    assert "read back" in rail, rail


def test_the_how_a_change_works_section_names_the_installed_mode():
    """The diagram is the installed mode's: the no-install way is stated
    next to it, in one line."""
    text = README.read_text(encoding="utf-8")
    section = text[text.index("## How a change works"):
                   text.index("The wrapper takes **probe lists**")]
    assert "**installed** mode" in section, section
    assert "**no-install** mode" in section, section
    assert "HTTPS" in section and "pinned" in section, section
    assert "rpcd" in section, section
    assert "read back" in section, section


def test_the_apply_rail_names_the_installed_mode():
    """The feature line about the rollback timer is the installed mode's:
    the no-install confirmation is named next to it."""
    line = _line_with(README.read_text(encoding="utf-8"),
                       "Apply-with-automatic-rollback over rpcd")
    assert "**installed** mode" in line, line
    assert "**no-install** mode" in line, line
    assert "read back" in line, line


def test_the_setup_guide_scopes_its_ssh_claim_to_the_installed_mode():
    """SETUP.md tells the coding agent what Newton does: the SSH claim
    is the installed mode's."""
    text = SETUP.read_text(encoding="utf-8")
    head = text[:text.index("## Rules you never break")]
    assert "**installed** mode" in head, head
    assert "**no-install** mode" in head, head
    assert "HTTPS" in head and "pinned" in head, head
    assert "rpcd" in head, head
    assert "read back" in head, head


def test_the_install_guide_scopes_its_ssh_claim_to_the_installed_mode():
    """docs/INSTALL.md tells the owner what Newton does: the SSH claim
    is the installed mode's."""
    text = INSTALL.read_text(encoding="utf-8")
    head = text[:text.index("## 1. Check the prerequisites")]
    assert "**installed** mode" in head, head
    assert "**no-install** mode" in head, head
    assert "HTTPS" in head and "pinned" in head, head
    assert "rpcd" in head, head
    assert "read back" in head, head


# -- the operational skill -------------------


def test_the_skill_scopes_the_verification_claim_to_the_installed_mode():
    """The skill's apply step says whose verification it is: the new
    SSH connections and the three passing rounds are the installed
    mode's."""
    line = _line_with(SKILL.read_text(encoding="utf-8"),
                       "Apply through `newton_apply_change(device, session_id)`")
    assert "**installed** mode" in line, line
    assert "new SSH connections" in line, line
    assert "three consecutive passing rounds" in line, line


def test_the_skill_names_the_no_install_verification_next_to_it():
    """The same line says how a no-install change is verified: over the
    router's own web API, and confirmed after the mandatory checks and
    the read-back."""
    line = _line_with(SKILL.read_text(encoding="utf-8"),
                       "Apply through `newton_apply_change(device, session_id)`")
    assert "**no-install** mode" in line, line
    assert "web API" in line, line
    assert "HTTPS" in line and "pinned" in line, line
    assert "read back" in line, line


def test_the_skill_scopes_the_three_round_claim_of_the_wrapper_table():
    """The table row about owrt-change.sh names the mode its verification
    belongs to."""
    line = _line_with(SKILL.read_text(encoding="utf-8"), "**3 consecutive**")
    assert "installed mode" in line, line
    assert "no-install mode" in line, line


def test_no_doc_makes_an_unscoped_three_round_claim():
    """Every claim about the three passing rounds names the mode it is
    true in, in every doc that carries one."""
    for name in ("README.md", "SETUP.md", "docs/INSTALL.md", "SKILL.md"):
        text = (REPO / name).read_text(encoding="utf-8")
        for line in text.splitlines():
            if "consecutive passing rounds" not in line:
                continue
            assert "installed** mode" in line or "installed mode" in line, (
                name, line)


def test_no_doc_makes_an_unscoped_new_ssh_claim():
    """The same for the new SSH connections: the claim belongs to the
    installed mode."""
    for name in ("README.md", "SETUP.md", "docs/INSTALL.md", "SKILL.md"):
        text = (REPO / name).read_text(encoding="utf-8")
        for line in text.splitlines():
            if "new SSH connections" not in line and "new** SSH connections" not in line:
                continue
            assert "installed** mode" in line or "installed mode" in line, (
                name, line)
