"""Static platform capability registry (design section 4)."""

from __future__ import annotations

from .base import (
    AD_READ_ONLY_TOOLS,
    AD_WRITE_TOOLS,
    READ_ONLY_TOOLS,
    TIER_EXPERIMENTAL,
    Capabilities,
)


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

# The Active Directory platforms (SPEC-1.3 section 9).  Their collector
# runs as a forced command over ssh and the audit they serve is
# read-only: no write, no device-side revert.
AD_PLATFORMS = frozenset({"ad-windows", "ad-samba"})

# The platforms of the Active Directory write entries (SPEC-1.4).  A
# write entry runs the write helper as a forced command and the undo of
# the change is armed on the DC before the write, so the device-side
# revert is the undo timer of the helper.
AD_WRITE_PLATFORMS = frozenset({"ad-windows-write", "ad-samba-write"})

# The tools an AD device may use: the device listing and the two AD
# tools.  No getters, no router tools, no writes.
AD_TOOLS = frozenset({"newton_list_devices"}) | AD_READ_ONLY_TOOLS

# The tools a write entry may use: the device listing and the four AD
# write tools.
AD_WRITE_PLATFORM_TOOLS = frozenset({"newton_list_devices"}) | AD_WRITE_TOOLS

PLATFORMS = frozenset(
    {
        "openwrt",
        "routeros",
        "vyos",
        "junos",
        "eos",
        "iosxe",
        "fortios",
        "ad-windows",
        "ad-samba",
        "ad-windows-write",
        "ad-samba-write",
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
    # The AD platforms are read-only: the audit reads a collector
    # document and the forced command on the far side is the whole
    # session, so there is nothing to revert.
    "ad-windows": Capabilities(TIER_EXPERIMENTAL, False, None, AD_TOOLS),
    "ad-samba": Capabilities(TIER_EXPERIMENTAL, False, None, AD_TOOLS),
    # A write entry runs the write helper as a forced command.  The undo
    # of the change is armed on the DC before the write, so the revert is
    # the undo timer of the helper.
    "ad-windows-write": Capabilities("T1", True, "undo timer on the DC", AD_WRITE_PLATFORM_TOOLS),
    "ad-samba-write": Capabilities("T1", True, "undo timer on the DC", AD_WRITE_PLATFORM_TOOLS),
}


class UnknownPlatform(ValueError):
    """Raised when an inventory names a platform Newton does not model."""


def capabilities(platform: str) -> Capabilities:
    """Return the immutable capabilities for a registered platform."""
    try:
        return _CAPABILITIES[platform]
    except KeyError as exc:
        raise UnknownPlatform(f"unknown platform: {platform}") from exc
