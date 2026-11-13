"""The docs say what the AD undo does.

The undo is armed on the DC until Newton confirms; the apply confirms or
aborts before it returns, so an abort works only on a change still
armed (an apply cut off before its confirm).  Once confirmed, Newton
does not undo a change: the owner plans the reverse change.  An unlock
has no undo and is written at once, so no doc may list it among the
changes with an undo.
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path
from typing import Any

import pytest

import newton_mcp.server as server


REPO_ROOT = Path(__file__).resolve().parents[4]


def _flat(text: str) -> str:
    return " ".join(text.split())


# The release scrub renames these into place in the public tree.
_RENAMED = {
    "docs/release/README-1.0.md": "README.md",
    "docs/release/ROADMAP-public.md": "docs/ROADMAP.md",
}


def _path(relative: str) -> Path:
    """The path of a doc.  Without the release copy, the public tree holds
    it under the name the release scrub gives it."""
    path = REPO_ROOT / relative
    if relative in _RENAMED and not path.exists():
        return REPO_ROOT / _RENAMED[relative]
    return path


def _read(relative: str) -> str:
    return _flat(_path(relative).read_text(encoding="utf-8"))


def _unreleased() -> str:
    text = _read("CHANGELOG.md")
    start = text.index("## [Unreleased]")
    end = text.index("## [", start + 3)
    return text[start:end]


def _skill_ad_changes() -> str:
    text = _read("SKILL.md")
    start = text.index("### Changes: plan, approve, apply")
    end = text.index("### What Newton does not change", start)
    return text[start:end]


def _roadmap_row(relative: str) -> str:
    for line in _path(relative).read_text(encoding="utf-8").splitlines():
        if line.startswith("| 1.4 |"):
            return _flat(line)
    raise AssertionError(f"{relative} has no 1.4 row")


def _readme_ad_line() -> str:
    text = _read("docs/release/README-1.0.md")
    start = text.index("- **1.4:**")
    end = text.index("- **1.5:**", start)
    return text[start:end]


def _tools() -> dict[str, str]:
    from mcp.shared.memory import create_connected_server_and_client_session

    async def listed() -> Any:
        async with create_connected_server_and_client_session(
            server.mcp._mcp_server
        ) as session:
            await session.initialize()
            return await session.list_tools()

    return {
        tool.name: _flat(str(tool.description))
        for tool in asyncio.run(listed()).tools
    }


def _docs() -> dict[str, str]:
    tools = _tools()
    return {
        "SKILL.md": _skill_ad_changes(),
        "CHANGELOG.md": _unreleased(),
        "README-1.0.md": _readme_ad_line(),
        "ROADMAP.md": _roadmap_row("docs/ROADMAP.md"),
        "ROADMAP-public.md": _roadmap_row("docs/release/ROADMAP-public.md"),
        "abort tool": tools["newton_ad_abort_change"],
        "apply tool": tools["newton_ad_apply_change"],
    }


# A list of the changes with an undo that names unlock among them.
_UNLOCK_IN_UNDO_LIST = re.compile(r"clean undo \([^)]*\bunlock\b")


@pytest.mark.parametrize("name", list(_docs()))
def test_no_doc_says_the_abort_undoes_a_confirmed_change(name: str) -> None:
    text = _docs()[name]
    assert "runs the undo now" not in text, name
    assert "is confirmed once written, so its abort is refused" not in text, name
    assert "Newton writes changes that have a clean undo" not in text, name
    assert "changes that have a clean undo" not in text, name
    assert "changes with a clean undo" not in text, name
    assert not _UNLOCK_IN_UNDO_LIST.search(text), name


@pytest.mark.parametrize(
    "name",
    ["SKILL.md", "CHANGELOG.md", "README-1.0.md", "ROADMAP.md", "ROADMAP-public.md"],
)
def test_the_docs_say_the_undo_lasts_until_the_confirm(name: str) -> None:
    text = _docs()[name]
    assert "armed on the domain controller until Newton confirms" in text, name
    assert "once confirmed, Newton does not undo it" in text.replace("Once", "once"), name
    assert "unlock has no undo and is written at once" in text, name


@pytest.mark.parametrize("name", ["SKILL.md", "CHANGELOG.md", "abort tool"])
def test_the_abort_works_only_on_a_change_still_armed(name: str) -> None:
    text = _docs()[name]
    assert "only on a change still armed" in text, name
    assert "cut off before its confirm" in text, name


@pytest.mark.parametrize("name", ["SKILL.md", "CHANGELOG.md", "apply tool"])
def test_the_apply_confirms_or_aborts_before_it_returns(name: str) -> None:
    assert "confirms or aborts before it returns" in _docs()[name], name


def test_the_two_roadmap_rows_are_the_same() -> None:
    assert _roadmap_row("docs/ROADMAP.md") == _roadmap_row(
        "docs/release/ROADMAP-public.md"
    )
