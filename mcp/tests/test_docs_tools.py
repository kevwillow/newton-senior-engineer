"""Docs and server stay in step (tool table, README counts, experimental section)."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

import newton_mcp.server as server


REPO_ROOT = Path(__file__).resolve().parents[2]
SKILL_MD = REPO_ROOT / "SKILL.md"
README_MD = REPO_ROOT / "README.md"


_BACKTICKED_NAME = re.compile(r"`(newton_[A-Za-z0-9_]+)`")


def _mcp_tool_table_names(skill_text: str) -> set[str]:
    """Collect the backticked ``newton_*`` names from the MCP server tool table.

    Only rows inside the ``## MCP server (``newton-mcp``)`` section count, and
    only rows that begin with ``| `newton_`` (the first table cell).
    """
    lines = skill_text.splitlines()
    in_section = False
    in_table = False
    names: set[str] = set()
    for line in lines:
        stripped = line.lstrip()
        if stripped.startswith("## "):
            if in_section:
                break
            if "newton-mcp" in stripped:
                in_section = True
            continue
        if not in_section:
            continue
        if stripped.startswith("| "):
            in_table = True
        elif in_table:
            # End of the table block (blank line or non-pipe line).
            in_table = False
            continue
        if not in_table:
            continue
        # Only count rows whose first cell starts with a backticked name.
        cell = stripped.split("|", 2)[1] if "|" in stripped else ""
        for match in _BACKTICKED_NAME.finditer(cell):
            names.add(match.group(1))
    return names


def _section_headings(skill_text: str) -> list[tuple[str, int]]:
    """Return ``(heading, line_number)`` for every ``## `` heading in the file."""
    headings: list[tuple[str, int]] = []
    for lineno, line in enumerate(skill_text.splitlines(), start=1):
        if line.startswith("## "):
            headings.append((line[3:].strip(), lineno))
    return headings


def test_skill_table_matches_tool_names() -> None:
    """SKILL.md MCP tool table lists every TOOL_NAMES entry."""
    skill_text = SKILL_MD.read_text(encoding="utf-8")
    table_names = _mcp_tool_table_names(skill_text)
    expected = set(server.TOOL_NAMES)
    missing = expected - table_names
    assert not missing, (
        f"SKILL.md MCP tool table is missing tools {sorted(missing)}"
    )
    extra = table_names - expected
    assert not extra, (
        f"SKILL.md MCP tool table has tools that are not in TOOL_NAMES: "
        f"{sorted(extra)}"
    )


def test_readme_counts_and_tools() -> None:
    """README lists seventeen tools and every tool name."""
    readme_text = README_MD.read_text(encoding="utf-8")
    # The word "eleven tools" must not appear anywhere.
    assert "eleven tools" not in readme_text, (
        "README.md still says 'eleven tools' after the tool count grew"
    )

    # The MCP server feature line mentions 'seventeen tools' and every tool name.
    feature_lines = [
        line for line in readme_text.splitlines()
        if "newton_list_devices" in line and "newton_read" in line
    ]
    assert feature_lines, "README.md has no feature line listing newton tools"
    feature_line = feature_lines[0]
    assert "seventeen tools" in feature_line, (
        f"Feature line does not say 'seventeen tools': {feature_line[:120]!r}"
    )
    for tool_name in sorted(server.TOOL_NAMES):
        assert tool_name in feature_line, (
            f"Feature line does not list {tool_name}"
        )

    # The repository-layout line for mcp/newton_mcp/ says "(seventeen tools)".
    layout_lines = [
        line for line in readme_text.splitlines()
        if line.startswith("mcp/newton_mcp/")
    ]
    assert layout_lines, (
        "README.md has no repository-layout line for mcp/newton_mcp/"
    )
    layout_line = layout_lines[0]
    assert "(seventeen tools)" in layout_line, (
        f"Layout line does not say '(seventeen tools)': {layout_line!r}"
    )


def test_skill_experimental_section() -> None:
    """SKILL.md has an experimental read-only section with both tools."""
    skill_text = SKILL_MD.read_text(encoding="utf-8")
    assert server.EXPERIMENTAL_CAVEAT in skill_text, (
        "SKILL.md does not contain the server.EXPERIMENTAL_CAVEAT text"
    )
    assert "T0-exp" in skill_text, "SKILL.md does not mention the T0-exp tier label"

    headings = _section_headings(skill_text)
    # Map lower-case heading text to (original, line number).
    lowered = {heading.lower(): (heading, lineno) for heading, lineno in headings}
    matches = [
        (heading, lineno)
        for heading_lower, (heading, lineno) in lowered.items()
        if "experimental read-only" in heading_lower
    ]
    assert matches, (
        "SKILL.md has no heading containing 'experimental read-only' "
        "(case-insensitive)"
    )
    # Each matching heading's section (up to the next '## ' heading) must name
    # both new tools.
    for heading, lineno in matches:
        lines = skill_text.splitlines()
        end = len(lines)
        for later_heading, later_lineno in headings:
            if later_lineno > lineno and later_lineno < end:
                end = later_lineno
                break
        section = "\n".join(lines[lineno - 1:end])
        assert "newton_list_getters" in section, (
            f"Section {heading!r} does not name newton_list_getters"
        )
        assert "newton_get_state" in section, (
            f"Section {heading!r} does not name newton_get_state"
        )


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q", "-p", "no:cacheprovider"]))
