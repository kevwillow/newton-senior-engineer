"""Docs and server stay in step (tool table, README counts, experimental section)."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

import newton_mcp.server as server


REPO_ROOT = Path(__file__).resolve().parents[2]
SKILL_MD = REPO_ROOT / "SKILL.md"
README_MD = REPO_ROOT / "README.md"
# The public README.  The release scrub renames it to README.md in the
# public tree, where the private README.md does not exist.
RELEASE_README = REPO_ROOT / "docs" / "release" / "README-1.0.md"
PRIVATE_LAYOUT = RELEASE_README.exists()


_BACKTICKED_NAME = re.compile(r"`(newton_[A-Za-z0-9_]+)`")

# The tools the server has and SKILL.md does not name yet.  The newton-ad
# part of SKILL.md is written by the maintainer, not with the code
# (SPEC-1.3 section 9), so the two AD tools are the exception until
# that text lands.  The four AD write tools (SPEC-1.4) are in the same
# case.  Every other tool must be in the table.
SKILL_TEXT_PENDING = frozenset(
    {
        "newton_ad_audit",
        "newton_ad_list_checks",
        "newton_ad_plan_change",
        "newton_ad_apply_change",
        "newton_ad_change_status",
        "newton_ad_abort_change",
    }
)


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
    """SKILL.md MCP tool table lists every TOOL_NAMES entry.

    The two AD tools are the exception while their SKILL.md text is
    pending (see SKILL_TEXT_PENDING).
    """
    skill_text = SKILL_MD.read_text(encoding="utf-8")
    table_names = _mcp_tool_table_names(skill_text)
    expected = set(server.TOOL_NAMES) - SKILL_TEXT_PENDING
    missing = expected - table_names
    assert not missing, (
        f"SKILL.md MCP tool table is missing tools {sorted(missing)}"
    )
    extra = table_names - set(server.TOOL_NAMES)
    assert not extra, (
        f"SKILL.md MCP tool table has tools that are not in TOOL_NAMES: "
        f"{sorted(extra)}"
    )


def _release_readme() -> Path:
    return RELEASE_README if PRIVATE_LAYOUT else README_MD


AD_TOOL_NAMES = frozenset(name for name in server.TOOL_NAMES if name.startswith("newton_ad_"))


def test_the_release_readme_counts_the_released_tools_and_the_ones_on_main() -> None:
    """The public README names the seventeen released tools on its feature
    line, the six AD tools of the main branch elsewhere, and both counts on
    its layout line."""
    text = _release_readme().read_text(encoding="utf-8")
    released = server.TOOL_NAMES - AD_TOOL_NAMES
    assert len(released) == 17 and len(AD_TOOL_NAMES) == 6
    feature = [
        line
        for line in text.splitlines()
        if "newton_list_devices" in line and "newton_read" in line
    ]
    assert feature, "the release README has no feature line listing newton tools"
    assert "seventeen tools" in feature[0]
    for name in sorted(released):
        assert name in feature[0], f"the feature line does not list {name}"
    for name in sorted(AD_TOOL_NAMES):
        assert f"`{name}`" in text, f"the release README does not name {name}"
    layout = [line for line in text.splitlines() if line.startswith("mcp/newton_mcp/ ")]
    assert layout and "(seventeen tools in 1.1.3, twenty-three on main)" in layout[0]


@pytest.mark.skipif(
    not PRIVATE_LAYOUT,
    reason="README.md is the release README in the public tree; the test above covers it",
)
def test_readme_counts_and_tools() -> None:
    """README lists twenty-three tools and every tool name."""
    readme_text = README_MD.read_text(encoding="utf-8")
    # The word "eleven tools" must not appear anywhere.
    assert "eleven tools" not in readme_text, (
        "README.md still says 'eleven tools' after the tool count grew"
    )

    # The MCP server feature line mentions 'twenty-three tools' and every tool name.
    feature_lines = [
        line
        for line in readme_text.splitlines()
        if "newton_list_devices" in line and "newton_read" in line
    ]
    assert feature_lines, "README.md has no feature line listing newton tools"
    feature_line = feature_lines[0]
    assert "twenty-three tools" in feature_line, (
        f"Feature line does not say 'twenty-three tools': {feature_line[:120]!r}"
    )
    for tool_name in sorted(server.TOOL_NAMES):
        assert tool_name in feature_line, (
            f"Feature line does not list {tool_name}"
        )

    # The repository-layout line for mcp/newton_mcp/ says "(twenty-three tools)".
    layout_lines = [
        line
        for line in readme_text.splitlines()
        if line.startswith("mcp/newton_mcp/")
    ]
    assert layout_lines, (
        "README.md has no repository-layout line for mcp/newton_mcp/"
    )
    layout_line = layout_lines[0]
    assert "(twenty-three tools)" in layout_line, (
        f"Layout line does not say '(twenty-three tools)': {layout_line!r}"
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


SETUP_CLIENTS_MD = REPO_ROOT / "docs" / "SETUP-CLIENTS.md"

_NUMBER_WORD_TOOLS = re.compile(
    r"\b((?:twenty|thirty)(?:-(?:one|two|three|four|five|six|seven|eight|nine))?"
    r"|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen"
    r"|fourteen|fifteen|sixteen|seventeen|eighteen|nineteen)\s+tools\b",
    re.IGNORECASE,
)


def test_setup_clients_tool_count_matches_the_server() -> None:
    """docs/SETUP-CLIENTS.md names no tool count but the server's own."""
    assert len(server.TOOL_NAMES) == 23
    text = SETUP_CLIENTS_MD.read_text(encoding="utf-8")
    counts = {match.group(1).lower() for match in _NUMBER_WORD_TOOLS.finditer(text)}
    assert counts <= {"twenty-three"}, (
        f"docs/SETUP-CLIENTS.md says {sorted(counts)} tools; the server has twenty-three"
    )
