"""What SKILL.md and the tool descriptions tell the agent to do, held to
what the code does.

Each test pins one instruction that sent an agent into a refusal or a
rollback: a held change planned with a window too short to test in, a
hold on a change the wrapper refuses to hold, a confirm call on a
platform without the tool, a stale test count, an update with no
reconnect, and an environment switch the installed launcher drops.
"""

import asyncio
import re
from pathlib import Path

import pytest

from newton_mcp import server
from newton_mcp.adapters import registry

REPO = Path(__file__).resolve().parents[2]
SKILL = REPO / "SKILL.md"
CHANGE = REPO / "scripts" / "owrt-change.sh"
INSTALLER = REPO / "scripts" / "newton-install"


def _skill() -> str:
    return SKILL.read_text(encoding="utf-8")


def _flat(text: str) -> str:
    return " ".join(text.split())


def _paragraph(text: str, marker: str) -> str:
    """The blank-line separated paragraph that holds *marker*."""
    i = text.index(marker)
    start = text.rfind("\n\n", 0, i)
    end = text.find("\n\n", i)
    return _flat(text[start + 2 if start != -1 else 0:end if end != -1 else len(text)])


def _descriptions() -> dict[str, str]:
    tools = asyncio.run(server.mcp.list_tools())
    return {tool.name: _flat(tool.description or "") for tool in tools}


# ---- a held change needs a window long enough to test in ----

def test_wrapper_hold_window_is_timeout_minus_15_s():
    """The fact the advice rests on: the hold ends where the verify
    rounds' deadline does, timeout_s minus 15 s."""
    src = CHANGE.read_text(encoding="utf-8")
    assert "deadline=$((SECONDS + T - 15))" in src
    assert "held_until=$(( $(date +%s) + deadline - SECONDS ))" in src


def test_skill_says_plan_a_held_change_with_a_longer_timeout():
    para = _paragraph(_skill(), "apply with\n`hold=true`: the rounds run")
    assert "`timeout_s`" in para, para
    assert "minus 15 s" in para, para
    assert "300" in para, para


@pytest.mark.parametrize("tool", ["newton_plan_change", "newton_apply_change"])
def test_tool_descriptions_say_plan_a_held_change_with_a_longer_timeout(tool):
    desc = _descriptions()[tool]
    assert "hold=true" in desc, desc[:300]
    assert "timeout_s" in desc and "minus 15 s" in desc, desc[-900:]


# ---- named nft objects cannot be held ----

def test_wrapper_refuses_hold_for_named_nft_objects():
    assert "--hold cannot be used for a change to named nft objects" in \
        CHANGE.read_text(encoding="utf-8")


def test_skill_hold_advice_excludes_log_limit_and_ipset_changes():
    """The NOT-auto-checked list sends the agent to hold=true; OW-FW-09
    sets a zone log_limit, which the wrapper refuses to hold."""
    para = _paragraph(_skill(), "NOT auto-checked (25 ids")
    assert "OW-FW-09" in para
    tail = para[para.index("apply with `hold=true`"):]
    assert "OW-FW-09" in tail and "log_limit" in tail and "ipset" in tail, tail
    assert "refuse" in tail, tail


def test_skill_named_nft_section_says_hold_is_refused():
    para = _paragraph(_skill(), "keeps existing **named nft objects**")
    assert "`hold=true`" in para and "refuse" in para, para


# ---- the vendor platforms confirm on their own ----

VENDORS = ("vyos", "routeros", "junos")


def test_vendor_platforms_have_no_confirm_tool():
    for platform in VENDORS:
        tools = registry.capabilities(platform).tools
        assert "newton_confirm_change" not in tools, platform
        assert "newton_abort_change" in tools, platform


def test_skill_vendor_write_steps_do_not_send_the_agent_to_confirm():
    text = _skill()
    step = _flat(text[text.index("1. **Same protocol, same tools.**"):
                      text.index("2. **The vendor's own undo")])
    assert "then confirm or abort" not in step, step
    assert "`newton_confirm_change` is OpenWrt-only" in step, step
    assert "confirms by itself" in step, step


# ---- no hard-coded test count ----

def test_skill_quotes_no_test_count():
    assert re.search(r"pytest -q`\s*\(\d+\)", _skill()) is None


# ---- an update ends with a reconnect ----

def test_skill_update_paragraph_says_finish_held_changes_and_reconnect():
    para = _paragraph(_skill(), "Every later install or update.")
    assert "held change" in para, para
    assert "`/mcp`" in para and "reconnect" in para, para
    assert "newton-router-setup <device> upgrade" in para, para


# ---- the receipts switch and the installed launcher ----

def _mcp_launcher() -> str:
    src = INSTALLER.read_text(encoding="utf-8")
    start = src.index('cat >"$launcher_tmp" <<\'EOF\'')
    return src[start:src.index("\nEOF\n", start)]


def test_receipts_switch_is_documented_as_the_launcher_treats_it():
    """Either the installed launcher passes NEWTON_FIELD_RECEIPTS on, or
    SKILL.md says the switch reaches only a development server."""
    row = _flat(next(line for line in _skill().splitlines()
                     if line.startswith("| `newton_get_state` |")))
    if "NEWTON_FIELD_RECEIPTS" in _mcp_launcher():
        return
    assert "development server" in row, row
    assert "installed server" in row, row
