"""The opening of the READMEs: what Newton is for, and its edge, each claim
scoped to the mode it holds in.

The opening leads with who Newton is for (an owner at their PC with an AI
agent, changing a home or small-office router and Active Directory) and
names four things: the undo armed on the device before the write, client
checks that can roll a change back, approval bound to the change and the
state it was planned against, and an honest unknown.  Each claim holds in
some modes only, so each line names them.

The release build renames docs/release/README-1.0.md to README.md and drops
the dev README; in that tree the dev-README case is skipped.
"""

from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
RELEASE_SRC = REPO / "docs/release/README-1.0.md"
PRIVATE = RELEASE_SRC.exists()
DEV_README = REPO / "README.md"
RELEASE_README = RELEASE_SRC if PRIVATE else REPO / "README.md"

MODES_HEADING = "## What Newton puts on your router"

READMES = [pytest.param(RELEASE_README, id="release")]
if PRIVATE:
    READMES.append(pytest.param(DEV_README, id="dev"))

# words that sell instead of saying what holds
MARKETING = ("seamless", "powerful", "effortless", "cutting-edge",
             "revolutionary", "best-in-class", "game-chang", "unmatched",
             "bulletproof", "guarantee")


def _opening(path: Path) -> str:
    text = path.read_text(encoding="utf-8")
    return text[:text.index(MODES_HEADING)]


def _edge_line(opening: str, start: str) -> str:
    found = [line for line in opening.splitlines() if line.startswith(start)]
    assert len(found) == 1, (start, found)
    return found[0]


@pytest.mark.parametrize("path", READMES)
def test_the_opening_says_who_newton_is_for(path: Path):
    opening = _opening(path)
    assert "home or small-office" in opening, opening[:800]
    assert "on your own PC" in opening, opening[:800]
    assert "Active Directory" in opening, opening[:800]


@pytest.mark.parametrize("path", READMES)
def test_the_undo_line_scopes_the_reboot_to_the_mode(path: Path):
    line = _edge_line(_opening(path), "- **The undo is armed on the device")
    assert "before it writes" in line, line
    assert "installed** mode" in line and "survives a reboot" in line, line
    assert "no-install** mode" in line and "RAM" in line, line
    assert "domain controller" in line and "unlock" in line, line


@pytest.mark.parametrize("path", READMES)
def test_the_client_check_line_names_the_installed_mode(path: Path):
    line = _edge_line(_opening(path), "- **A check from a client")
    assert "installed** mode" in line, line
    assert "vantage" in line, line
    assert "rolls the change back" in line, line
    assert "only the breaks its checks test for" in line, line


@pytest.mark.parametrize("path", READMES)
def test_the_approval_line_names_each_mode(path: Path):
    line = _edge_line(_opening(path), "- **Your approval is bound")
    assert "installed** mode" in line, line
    assert "the router itself checks the approval" in line, line
    assert "digest" in line and "settings at plan time" in line, line
    assert "no-install** mode" in line, line
    assert "domain controller" in line, line


@pytest.mark.parametrize("path", READMES)
def test_the_unknown_line_says_unknown_not_success(path: Path):
    line = _edge_line(_opening(path), "- **An honest unknown")
    assert "outcome is unknown" in line, line


@pytest.mark.parametrize("path", READMES)
def test_the_opening_carries_no_marketing_words(path: Path):
    opening = _opening(path).lower()
    for word in MARKETING:
        assert word not in opening, word


@pytest.mark.parametrize("path", READMES)
def test_the_coverage_list_is_scoped_to_the_installed_mode(path: Path):
    """In the no-install mode Newton applies only DHCP reservations and DNS
    entries itself; every other change is an owner script."""
    opening = " ".join(_opening(path).split())
    i = opening.index("firewall rules, port forwards")
    sentence = opening[opening.rindex(".", 0, i):opening.index(".", i)]
    assert "in the **installed** mode it covers" in sentence, sentence
    assert "DHCP reservations and DNS entries" in sentence, sentence
    assert "a script you approve and run" in sentence, sentence


@pytest.mark.parametrize("path", READMES)
def test_the_ad_new_user_case_is_a_failed_undo_not_an_unarmed_one(path: Path):
    """The DC arms the undo for a user-create too; when it did not record
    the new user's ID, that undo fails and records undo_failed."""
    line = _edge_line(_opening(path), "- **The undo is armed on the device")
    assert "undo_failed" in line, line
    assert "One undo can fail: a new user" in line and "stays written" in line, line
    assert "for every change but an unlock, which has nothing to put back." in line, line


@pytest.mark.parametrize("path", READMES)
def test_the_lab_exception_names_its_development_checkout(path: Path):
    """The lab carve-out never applies on an installed build; approval is
    given in the terminal or the approval dialog."""
    opening = " ".join(_opening(path).split())
    assert "set the router to lab" not in opening, opening[:1200]
    assert "development checkout" in opening, opening[:1200]
    assert "or the approval dialog" in opening, opening[:1200]
