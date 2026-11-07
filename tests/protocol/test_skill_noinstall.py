"""The no-install flow in SKILL.md.

The skill is what the agent reads, so the no-install flow has to be
there in the file's own words: the two access modes, what the agent may
do on a no-install router, the reboot line, the five states of
`newton_change_status` and the offer of the installed mode.

The test pins the phrases, so a later edit cannot quietly drop one of
them.
"""

from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SKILL = REPO / "SKILL.md"


def skill_text():
    return SKILL.read_text(encoding="utf-8")


def test_the_two_access_modes_are_described():
    """The skill names both modes and says which one is the default."""
    text = skill_text()
    assert "## The two access modes (OpenWrt)" in text
    assert "The **no-install** mode is the default for a new" in text
    assert "**no-install:**" in text
    assert "**installed:**" in text


def test_the_skill_does_not_claim_the_modes_are_equally_safe():
    """The no-install mode is not as safe as the installed mode."""
    text = skill_text()
    assert "is **not** as safe as the installed mode" in text
    assert "equally safe" in text


def test_the_skill_says_what_the_agent_may_do_on_a_no_install_router():
    """The reads, the allowlist Newton applies itself, the owner scripts
    and the Wi-Fi rule are all named."""
    text = skill_text()
    assert "### What you can do on a no-install router" in text
    assert "`noinstall_checks.AUTO_APPLY`" in text
    assert "DHCP static leases and DNS entries" in text
    assert "newton-router-setup <device> owner-run <id>" in text
    assert "Wi-Fi changes are" in text
    assert "a Wi-Fi key is set in LuCI" in text


def test_the_skill_says_the_reboot_line():
    """The reboot line is said before the owner says yes."""
    text = skill_text()
    assert "**The reboot line**" in text
    assert "if the router reboots or its web service restarts while the "
    "change waits" in text
    assert "Say that to the owner before they say yes" in text


def test_the_skill_names_the_five_states_of_the_status():
    """The five states of `newton_change_status` are named, and `unknown`
    never becomes a success."""
    text = skill_text()
    assert "### The state of a no-install change" in text
    for state in ("in_progress", "confirmed", "rolled_back", "not_applied",
                  "unknown"):
        assert "`%s`" % state in text, state
    assert "never claim that the change succeeded" in text


def test_the_skill_describes_the_offer():
    """The offer is asked once, the command is named, the agent never runs
    the setup and never asks again after a decline."""
    text = skill_text()
    assert "### The offer of the installed mode" in text
    assert "`installed_offer`" in text
    assert "newton-router-setup <device> offer-installed" in text
    assert "Never run a setup command yourself" in text
    assert '`installed_offer = "declined"`' in text
    assert "Never ask again" in text


def test_the_tool_table_says_what_the_listing_carries():
    """The `newton_list_devices` row says that a no-install device
    carries its access mode and the answer of the offer."""
    text = skill_text()
    row = [line for line in text.splitlines()
           if line.startswith("| `newton_list_devices`")]
    assert row, "no newton_list_devices row in the tool table"
    assert "access" in row[0], row[0]
    assert "installed_offer" in row[0], row[0]
