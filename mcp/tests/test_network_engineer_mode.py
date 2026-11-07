"""UX1: Network-engineer mode entry point in SKILL.md and per-client command stubs."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

import newton_mcp.server as server


REPO_ROOT = Path(__file__).resolve().parents[2]
SKILL_MD = REPO_ROOT / "SKILL.md"
SETUP_CLIENTS_MD = REPO_ROOT / "docs" / "SETUP-CLIENTS.md"
COMMANDS_DIR = REPO_ROOT / "commands"


_BACKTICKED_NAME = re.compile(r"`(newton_[A-Za-z0-9_]+)`")


def _section_headings(text: str) -> list[tuple[str, int]]:
    """Return ``(heading, line_number)`` for every ``## `` heading in the file."""
    headings: list[tuple[str, int]] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if line.startswith("## "):
            headings.append((line[3:].strip(), lineno))
    return headings


def _section_text(text: str, headings: list[tuple[str, int]], heading: str) -> str:
    """Return the body lines for ``heading`` (the lines under it up to the next ``## `` heading)."""
    match = next((h for h in headings if h[0] == heading), None)
    assert match is not None, f"no heading {heading!r} found"
    start = match[1]
    end = len(text.splitlines())
    for name, lineno in headings:
        if lineno > start and lineno < end:
            end = lineno
            break
    return "\n".join(text.splitlines()[start - 1:end])


def _skill_frontmatter(skill_text: str) -> tuple[str, str]:
    """Return (raw frontmatter block, description string) from a YAML frontmatter file.

    The description string has no surrounding quotes stripped.
    """
    lines = skill_text.splitlines()
    assert lines and lines[0].strip() == "---", "SKILL.md does not start with YAML frontmatter"
    end = None
    for idx, line in enumerate(lines[1:], start=2):
        if line.strip() == "---":
            end = idx
            break
    assert end is not None, "SKILL.md YAML frontmatter is not terminated"
    block = "\n".join(lines[1:end - 1])
    match = re.search(r"^description:\s*(.*)$", block, re.MULTILINE)
    assert match is not None, "SKILL.md frontmatter has no description:"
    return block, match.group(1).strip()


def _command_files() -> list[Path]:
    """Every ``*.md`` file under ``commands/`` (recursive)."""
    return sorted(p for p in COMMANDS_DIR.rglob("*.md") if p.is_file())


def test_UX1_01_skill_has_network_engineer_mode_before_when_to_use() -> None:
    """UX1 #1: `## Network-engineer mode` comes before `## When to Use`, and is <= 40 lines."""
    skill_text = SKILL_MD.read_text(encoding="utf-8")
    headings = _section_headings(skill_text)
    by_name = {name: lineno for name, lineno in headings}
    assert "Network-engineer mode" in by_name, (
        "SKILL.md has no `## Network-engineer mode` heading"
    )
    assert "When to Use" in by_name, (
        "SKILL.md has no `## When to Use` heading (sanity)"
    )
    assert by_name["Network-engineer mode"] < by_name["When to Use"], (
        f"`## Network-engineer mode` (line {by_name['Network-engineer mode']}) "
        f"must come before `## When to Use` (line {by_name['When to Use']})"
    )

    section = _section_text(skill_text, headings, "Network-engineer mode")
    section_lines = section.splitlines()
    assert len(section_lines) <= 40, (
        f"`## Network-engineer mode` is {len(section_lines)} lines; must be <= 40"
    )


def test_UX1_02_skill_section_tools_match_server() -> None:
    """UX1 #2: every backticked `newton_*` tool name in the section is registered."""
    skill_text = SKILL_MD.read_text(encoding="utf-8")
    headings = _section_headings(skill_text)
    section = _section_text(skill_text, headings, "Network-engineer mode")

    names = {
        match.group(1)
        for match in _BACKTICKED_NAME.finditer(section)
        if match.group(1) != "newton_result"
    }
    assert names, (
        "## Network-engineer mode names no backticked newton_* tools"
    )
    registered = set(server.TOOL_NAMES)
    unknown = names - registered
    assert not unknown, (
        f"`## Network-engineer mode` names tools that are not in the server: "
        f"{sorted(unknown)}"
    )


def test_UX1_03_skill_section_names_required_tools() -> None:
    """UX1 #3: the section names the six required tools."""
    skill_text = SKILL_MD.read_text(encoding="utf-8")
    headings = _section_headings(skill_text)
    section = _section_text(skill_text, headings, "Network-engineer mode")
    required = {
        "newton_list_devices",
        "newton_read",
        "newton_plan_change",
        "newton_apply_change",
        "newton_guided_recommend",
        "newton_guided_audit",
    }
    missing = sorted(name for name in required if f"`{name}`" not in section)
    assert not missing, (
        f"`## Network-engineer mode` does not name required tools: {missing}"
    )


def test_UX1_04_skill_section_mentions_newton_approve_and_no_skip_approval() -> None:
    """UX1 #4: section mentions `newton-approve` and contains no "skip approval" wording."""
    skill_text = SKILL_MD.read_text(encoding="utf-8")
    headings = _section_headings(skill_text)
    section = _section_text(skill_text, headings, "Network-engineer mode")
    assert "newton-approve" in section, (
        "`## Network-engineer mode` does not mention `newton-approve`"
    )
    lowered = section.lower()
    assert "skip approval" not in lowered, (
        "`## Network-engineer mode` contains the phrase 'skip approval'"
    )


def test_UX1_05_skill_frontmatter_description_advertises_slash_command() -> None:
    """UX1 #5: SKILL.md frontmatter description contains `/newton`."""
    skill_text = SKILL_MD.read_text(encoding="utf-8")
    _, description = _skill_frontmatter(skill_text)
    assert "/newton" in description, (
        f"SKILL.md frontmatter description does not contain '/newton': {description[:120]!r}"
    )


def test_UX1_06_command_files_skill_name_and_phrase() -> None:
    """UX1 #6: each command file names the `newton` skill and `Network-engineer mode`."""
    files = _command_files()
    assert files, "no command files under commands/ (none yet implemented)"
    for path in files:
        text = path.read_text(encoding="utf-8")
        lowered = text.lower()
        # Spec: "the word `newton` as the skill name (a line `newton` skill or "`newton` skill")".
        assert "`newton` skill" in lowered or "newton skill" in lowered, (
            f"{path.relative_to(REPO_ROOT)} does not name the `newton` skill"
        )
        assert "Network-engineer mode" in text, (
            f"{path.relative_to(REPO_ROOT)} does not contain 'Network-engineer mode'"
        )
        # YAML frontmatter required.
        lines = text.splitlines()
        assert lines and lines[0].strip() == "---", (
            f"{path.relative_to(REPO_ROOT)} has no YAML frontmatter"
        )
        end = None
        for idx, line in enumerate(lines[1:], start=2):
            if line.strip() == "---":
                end = idx
                break
        assert end is not None, (
            f"{path.relative_to(REPO_ROOT)} YAML frontmatter is not terminated"
        )
        block = "\n".join(lines[1:end - 1])
        assert re.search(r"^description:\s*\S+", block, re.MULTILINE), (
            f"{path.relative_to(REPO_ROOT)} frontmatter has no `description:`"
        )


def test_UX1_07_commands_directory_has_exactly_two_files() -> None:
    """UX1 #7: commands/ contains exactly claude-code/network-engineer.md and opencode/network-engineer.md."""
    expected = {
        COMMANDS_DIR / "claude-code" / "network-engineer.md",
        COMMANDS_DIR / "opencode" / "network-engineer.md",
    }
    actual = set(_command_files())
    assert actual == expected, (
        f"commands/ files mismatch: actual {sorted(p.relative_to(REPO_ROOT) for p in actual)}, "
        f"expected {sorted(p.relative_to(REPO_ROOT) for p in expected)}"
    )


def test_UX1_08_setup_clients_has_slash_commands_section() -> None:
    """UX1 #8: SETUP-CLIENTS.md has ## Slash commands before 'How to check it works', with Codex prompt and per-client paths."""
    text = SETUP_CLIENTS_MD.read_text(encoding="utf-8")
    headings = _section_headings(text)
    by_name = {name: lineno for name, lineno in headings}

    assert "Slash commands" in by_name, (
        "docs/SETUP-CLIENTS.md has no `## Slash commands` section"
    )
    # Must appear before `## How to check it works without a client`.
    check_target = "How to check it works without a client"
    assert check_target in by_name, (
        "docs/SETUP-CLIENTS.md has no `## How to check it works without a client` heading "
        "(sanity)"
    )
    assert by_name["Slash commands"] < by_name[check_target], (
        "`## Slash commands` must come before `## How to check it works without a client`"
    )

    section = _section_text(text, headings, "Slash commands")
    assert "Network-engineer mode" in section, (
        "`## Slash commands` does not contain the Codex starter prompt phrase 'Network-engineer mode'"
    )
    # Codex prompt is the fenced block; the section must reference where each client's
    # command file lives.
    assert ".claude/commands" in section, (
        "`## Slash commands` does not name the Claude Code command directory"
    )
    assert (
        ".config/opencode/commands" in section
    ), "`## Slash commands` does not name the OpenCode command directory"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q", "-p", "no:cacheprovider"]))
