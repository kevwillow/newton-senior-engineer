"""Static platform capability registry (design section 4)."""

from __future__ import annotations

from .base import READ_ONLY_TOOLS, TIER_EXPERIMENTAL, Capabilities


OPENWRT_TOOLS = frozenset(
    {
        "newton_list_devices",
        "newton_read",
        "newton_backup",
        "newton_plan_change",
        "newton_plan_undo",
        "newton_apply_change",
        "newton_change_status",
        "newton_abort_change",
        "newton_grant_off",
        "newton_list_tiers",
        "newton_plan_tier",
        "newton_guided_recommend",
        "newton_guided_audit",
        "newton_plan_scan",
        "newton_run_scan",
    }
)

# The write tools a vendor platform may offer.  They are the OpenWrt
# change tools under the vendor names: the driver in vendor_change.py
# arms the device-side revert, plans, applies, reports and aborts.
VENDOR_WRITE_TOOL_NAMES = frozenset(
    {
        "newton_backup",
        "newton_plan_change",
        "newton_apply_change",
        "newton_change_status",
        "newton_abort_change",
    }
)

# What a vendor platform with writes may advertise: the read tools plus
# the write tools.
VENDOR_WRITE_TOOLS = READ_ONLY_TOOLS | VENDOR_WRITE_TOOL_NAMES

# The platforms whose devices may use the vendor write tools.  A device
# of one of them still needs ``vendor_write = true`` in the inventory:
# the platform may write, the device may not.
VENDOR_WRITE_PLATFORMS = frozenset({"vyos", "routeros", "junos"})

PLATFORMS = frozenset(
    {
        "openwrt",
        "routeros",
        "vyos",
        "junos",
        "eos",
        "iosxe",
        "fortios",
    }
)

_CAPABILITIES: dict[str, Capabilities] = {
    "openwrt": Capabilities("T1", True, "newton-guard", OPENWRT_TOOLS),
    # The CHR has no soft revert: the undo is a reboot into the backup.
    # The tier is T2 because the revert is disruptive.
    "routeros": Capabilities("T2", True, "reboot-into-backup", VENDOR_WRITE_TOOLS),
    "vyos": Capabilities("T1", True, "commit-confirm", VENDOR_WRITE_TOOLS),
    # A Junos holds the revert itself: the apply commits with "commit
    # confirmed N", so the revert is on the device before the change is.
    "junos": Capabilities("T1", True, "commit confirmed", VENDOR_WRITE_TOOLS),
    "eos": Capabilities(TIER_EXPERIMENTAL, False, None, READ_ONLY_TOOLS),
    "iosxe": Capabilities(TIER_EXPERIMENTAL, False, None, READ_ONLY_TOOLS),
    "fortios": Capabilities(TIER_EXPERIMENTAL, False, None, READ_ONLY_TOOLS),
}


class UnknownPlatform(ValueError):
    """Raised when an inventory names a platform Newton does not model."""


def capabilities(platform: str) -> Capabilities:
    """Return the immutable capabilities for a registered platform."""
    try:
        return _CAPABILITIES[platform]
    except KeyError as exc:
        raise UnknownPlatform(f"unknown platform: {platform}") from exc
