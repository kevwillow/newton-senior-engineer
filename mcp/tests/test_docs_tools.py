"""Docs and server stay in step (tool table, README counts, experimental section)."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

import newton_mcp.server as server


REPO_ROOT = Path(__file__).resolve().parents[2]
SKILL_MD = REPO_ROOT / "SKILL.md"
README_MD = REPO_ROOT / "README.md"
# The release README, in a tree that has docs/release/README-1.0.md.
# Where that file is absent, README.md is the release README.
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
        # The three AD build tools (PLAN-1.5 task 8): their SKILL.md text
        # is task 9's, which needs the maintainer's approval on the exact diff.
        "newton_ad_build_plan",
        "newton_ad_build_run",
        "newton_ad_build_status",
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


def test_the_release_readme_counts_the_tools() -> None:
    """The public README names all twenty-eight tools on its feature line and
    says twenty-eight tools on its layout line."""
    text = _release_readme().read_text(encoding="utf-8")
    assert len(server.TOOL_NAMES) == 28 and len(AD_TOOL_NAMES) == 9
    feature = [
        line
        for line in text.splitlines()
        if "newton_list_devices" in line and "newton_read" in line
    ]
    assert feature, "the release README has no feature line listing newton tools"
    assert "twenty-eight tools" in feature[0]
    for name in sorted(server.TOOL_NAMES):
        assert name in feature[0], f"the feature line does not list {name}"
    layout = [line for line in text.splitlines() if line.startswith("mcp/newton_mcp/ ")]
    assert layout and "(twenty-eight tools)" in layout[0]


@pytest.mark.skipif(
    not PRIVATE_LAYOUT,
    reason="README.md is the release README in the public tree; the test above covers it",
)
def test_readme_counts_and_tools() -> None:
    """README lists twenty-eight tools and every tool name."""
    readme_text = README_MD.read_text(encoding="utf-8")
    # The word "eleven tools" must not appear anywhere.
    assert "eleven tools" not in readme_text, (
        "README.md still says 'eleven tools' after the tool count grew"
    )

    # The MCP server feature line mentions 'twenty-eight tools' and every tool name.
    feature_lines = [
        line
        for line in readme_text.splitlines()
        if "newton_list_devices" in line and "newton_read" in line
    ]
    assert feature_lines, "README.md has no feature line listing newton tools"
    feature_line = feature_lines[0]
    assert "twenty-eight tools" in feature_line, (
        f"Feature line does not say 'twenty-eight tools': {feature_line[:120]!r}"
    )
    for tool_name in sorted(server.TOOL_NAMES):
        assert tool_name in feature_line, (
            f"Feature line does not list {tool_name}"
        )

    # The repository-layout line for mcp/newton_mcp/ says "(twenty-eight tools)".
    layout_lines = [
        line
        for line in readme_text.splitlines()
        if line.startswith("mcp/newton_mcp/")
    ]
    assert layout_lines, (
        "README.md has no repository-layout line for mcp/newton_mcp/"
    )
    layout_line = layout_lines[0]
    assert "(twenty-eight tools)" in layout_line, (
        f"Layout line does not say '(twenty-eight tools)': {layout_line!r}"
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
    assert len(server.TOOL_NAMES) == 28
    text = SETUP_CLIENTS_MD.read_text(encoding="utf-8")
    counts = {match.group(1).lower() for match in _NUMBER_WORD_TOOLS.finditer(text)}
    assert counts <= {"twenty-eight"}, (
        f"docs/SETUP-CLIENTS.md says {sorted(counts)} tools; the server has twenty-eight"
    )


# ---- owner-facing claims: no unscoped guarantee, the evidence named as it is --------------

SECURITY_MD = REPO_ROOT / "SECURITY.md"
SUPPORT_MD = REPO_ROOT / "docs" / "SUPPORT.md"
CHANGELOG_MD = REPO_ROOT / "CHANGELOG.md"
PRIVATE_ROADMAP = REPO_ROOT / "docs" / "ROADMAP.md"
PUBLIC_ROADMAP_SRC = REPO_ROOT / "docs" / "release" / "ROADMAP-public.md"

# Exact strings, not patterns: each is a guarantee these files once made
# with no mode or condition, so a scoped rewording cannot match by
# accident.
FORBIDDEN_CLAIMS = (
    "prevent lockouts",
    "the safe way",
    "never leak",
    "proven rather than",
    "rather than claimed",
    "Proven, not claimed",
    "Every write arms",
    "undoes itself if something breaks",
    "If anything fails, the router reverts on its own",
    "There is no tool that runs arbitrary commands",
)


def _owner_docs() -> list[Path]:
    docs = [README_MD, SECURITY_MD, SKILL_MD]
    if PRIVATE_LAYOUT:
        docs.append(RELEASE_README)
    return docs


def test_owner_docs_make_no_unscoped_guarantee() -> None:
    hits = [
        (path.relative_to(REPO_ROOT).as_posix(), phrase)
        for path in _owner_docs()
        for phrase in FORBIDDEN_CLAIMS
        if phrase in path.read_text(encoding="utf-8")
    ]
    assert hits == []


GUARD_README = REPO_ROOT / "device" / "openwrt" / "newton-guard" / "README.md"
GUARD_ONLY_LIMIT = (
    "running firewall, network and rpcd settings can stay changed until a reboot"
)


def test_the_guard_only_restore_limit_is_stated() -> None:
    """The guard restores files and runs a bare reload_config, which sends no
    reload events when the restored files match its snapshot; until the guard
    sends them, SKILL.md and the guard README say so."""
    for path in (SKILL_MD, GUARD_README):
        text = " ".join(path.read_text(encoding="utf-8").split())
        assert GUARD_ONLY_LIMIT in text, path.relative_to(REPO_ROOT).as_posix()


def test_the_audit_adr_says_it_is_not_built() -> None:
    """No hash-chained journal exists in the code; ADR-012 says so in its status."""
    text = (REPO_ROOT / "docs" / "design" / "11-ADRS.md").read_text(encoding="utf-8")
    adr = text.split("## ADR-012", 1)[1].split("\n## ", 1)[0]
    assert "**Status:** Accepted, not built (2026-11-19)" in adr


def _scenario_files(folder: str) -> int:
    return len(list((REPO_ROOT / folder).rglob("*.toml")))


def test_the_release_readme_counts_scenario_files_not_runs() -> None:
    """The virtual-lab figure is a count of scenario files; no full run of
    them is recorded, so the README says files and keeps them out of a
    "proven" heading."""
    text = _release_readme().read_text(encoding="utf-8")
    n = _scenario_files("lab/scenarios")
    assert f"{n} scenario files in [`lab/scenarios`](lab/scenarios)" in text
    line = next(line for line in text.splitlines() if "scenario files in [`lab/scenarios`]" in line)
    assert "no full run of them is recorded" in line, line


def test_the_release_readme_lists_the_beryl_when_the_support_table_does() -> None:
    support = SUPPORT_MD.read_text(encoding="utf-8")
    if "GL-MT3000" not in support:
        pytest.skip("the support table has no GL-MT3000 row")
    text = _release_readme().read_text(encoding="utf-8")
    assert "does not list the GL-MT3000" not in text
    row = next(line for line in text.splitlines() if line.startswith("| OpenWrt 25.12 |"))
    assert "GL-MT3000" in row, row


def test_security_states_each_approval_and_command_boundary() -> None:
    text = SECURITY_MD.read_text(encoding="utf-8")
    model = text[text.index("## Security model in brief"):text.index("## Known limits")]
    for needle in (
        "No MCP tool runs arbitrary commands",
        "the domain controller checks the approval token itself",
        "only the Newton host checks it",
        "`exec-option`, `exec-config` and `exec-include`",
        "run code as root on the router",
        "the Newton host keeps the router's approval key",
        "a guard rail, not a sandbox",
    ):
        assert needle in model, needle


def _latest_release() -> str:
    m = re.search(r"^## \[(\d+\.\d+\.\d+)\]", CHANGELOG_MD.read_text(encoding="utf-8"), re.M)
    assert m
    return m.group(1)


@pytest.mark.skipif(not PUBLIC_ROADMAP_SRC.exists(), reason="the private roadmap is not in the release build")
def test_the_roadmap_says_where_newton_is_now() -> None:
    text = PRIVATE_ROADMAP.read_text(encoding="utf-8")
    heading = next(line for line in text.splitlines() if line.startswith("## Where Newton is"))
    assert f"v{_latest_release()}" in heading, heading


def _planned_rows() -> list[str]:
    path = PUBLIC_ROADMAP_SRC if PUBLIC_ROADMAP_SRC.exists() else PRIVATE_ROADMAP
    text = path.read_text(encoding="utf-8")
    table = text[text.index("## Planned"):]
    return [line for line in table.splitlines() if line.startswith("| ") and not line.startswith("| Release")]


def test_the_roadmap_plans_hosts_and_the_persona_before_more_vendors() -> None:
    """The maintainer's order (2026-11-19): AD build mode, the protocol
    contract, hosts, the security engineer persona, then more vendors;
    the read-only dashboard is parked at the end of the backlog.  AD
    build mode shipped in 1.5.0, so it is a released row now."""
    rows = _planned_rows()
    path = PUBLIC_ROADMAP_SRC if PUBLIC_ROADMAP_SRC.exists() else PRIVATE_ROADMAP
    text = path.read_text(encoding="utf-8")
    released = text[text.index("## Released"):text.index("## Planned")]
    assert "| 1.5.0 | Active Directory build mode" in released

    def index(needle: str) -> int:
        found = [i for i, row in enumerate(rows) if needle in row]
        assert len(found) == 1, (needle, rows)
        return found[0]

    order = [index(n) for n in ("protocol contract", "Hosts:", "security engineer persona", "More vendors")]
    assert order == sorted(order), order
    assert "dashboard" not in rows[index("Network rules")]
    backlog = rows[index("| Backlog |")]
    for needle in ("read-only local dashboard", "policy engine", "maintenance windows"):
        assert needle in backlog, needle


# ---- the reboot rail, guard= values, support plans, guard-only restore ----------------------------

GUARD_PROGRAM = REPO_ROOT / "device" / "openwrt" / "newton-guard" / "newton-guard"
PLATFORMS_TOML = REPO_ROOT / "docs" / "support" / "platforms.toml"
STALE_REBOOT_CLAIM = "A `reboot` wipes rollback state in tmpfs while the applied config stays on disk."


def _flat(path: Path) -> str:
    return " ".join(path.read_text(encoding="utf-8").split())


def test_the_reboot_rail_is_scoped_to_the_mode() -> None:
    """A reboot keeps the change only in the no-install mode; the installed
    guard restores the last-known-good config at boot."""
    for path in _owner_docs():
        assert STALE_REBOOT_CLAIM not in path.read_text(encoding="utf-8"), path.name
    if not PRIVATE_LAYOUT:
        return  # the rail is in the dev README, which the release build drops
    line = next(
        line for line in README_MD.read_text(encoding="utf-8").splitlines()
        if "group-B" in line and "transaction is open" in line
    )
    assert "**no-install** mode" in line, line
    assert "**installed** mode" in line, line
    assert "restores the last-known-good config" in line, line


def test_the_skill_names_every_guard_restore_reason() -> None:
    """The router passes the guard's own reason through as restored:<reason>;
    the guard's expiry path writes deadline or reboot."""
    reasons = set(re.findall(r"reason=([a-z]+)", GUARD_PROGRAM.read_text(encoding="utf-8")))
    assert {"deadline", "reboot"} <= reasons, reasons
    text = _flat(SKILL_MD)
    para = text[text.index("`newton_change_status` after a rolled-back window"):]
    para = para[:para.index("Rollback restores config, not state.")]
    for reason in sorted(reasons):
        assert f"`restored:{reason}`" in para, reason
    assert "`restored:<reason>`" in para, para


def test_the_support_table_plans_match_the_roadmap() -> None:
    """The support table names the release the roadmap plans hosts and
    firmware upgrades for."""
    import tomllib

    rows = _planned_rows()

    def release_of(needle: str) -> str:
        found = [row for row in rows if needle in row]
        assert len(found) == 1, (needle, found)
        return found[0].strip("|").split("|")[0].strip()

    hosts = release_of("Hosts:")
    firmware = release_of("OpenWrt firmware upgrades")
    data = tomllib.loads(PLATFORMS_TOML.read_text(encoding="utf-8"))["platforms"]
    assert data["linux"]["release"] == hosts
    assert data["linux"]["untested"] == [f"Every shape: planned for {hosts}, tested per network stack"]
    untested = [u for p in data.values() for u in p.get("untested", []) if u.startswith("Firmware upgrade")]
    assert untested, "no firmware row"
    for u in untested:
        assert u == f"Firmware upgrade (planned for {firmware.lower()})", u
    for path in (PLATFORMS_TOML, SUPPORT_MD):
        text = path.read_text(encoding="utf-8")
        assert "planned for 1.3" not in text and "planned for 1.4" not in text, path.name


def test_the_guard_only_restore_limit_reaches_the_owner_docs() -> None:
    """The READMEs' undo bullet and SECURITY.md's undo line carry the
    guard-only restore limit, not only SKILL.md and the guard README."""
    readmes = [README_MD] + ([RELEASE_README] if PRIVATE_LAYOUT else [])
    for path in readmes:
        bullet = next(
            line for line in path.read_text(encoding="utf-8").splitlines()
            if line.startswith("- **The undo is armed on the device before it writes.**")
        )
        assert GUARD_ONLY_LIMIT in bullet, path.name
    model = SECURITY_MD.read_text(encoding="utf-8")
    model = model[model.index("## Security model in brief"):model.index("## Known limits")]
    undo = next(line for line in model.splitlines() if "arms an undo" in line)
    assert GUARD_ONLY_LIMIT in undo, undo
