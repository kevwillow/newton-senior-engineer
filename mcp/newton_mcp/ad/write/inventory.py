"""The inventory rules of the AD write entries.

A write entry is a device of platform ``ad-windows-write`` or
``ad-samba-write``.  It carries the SSH fields of a read entry and one
more: ``ad_domain``, the name of the device that stands for its domain.

The DCs of a domain are the write entries that name it.  The device that
stands for the domain is one of them: it names itself.  The domain
controller of the domain is found with the ``read`` facts of the DCs
(``facts.pdc``), not with the inventory, because the domain controller is
the DC that holds the PDC emulator role and the inventory does not know
that.
"""

from __future__ import annotations

from typing import Any, Mapping

from .errors import WriteError


#: The platforms a write entry may have.
WRITE_PLATFORMS = frozenset({"ad-windows-write", "ad-samba-write"})

#: The platforms of an Active Directory device, read or write.
AD_PLATFORMS = frozenset({"ad-windows", "ad-samba"}) | WRITE_PLATFORMS


def is_write_device(device: Any) -> bool:
    """True when the device is a write entry."""
    return getattr(device, "platform", None) in WRITE_PLATFORMS


def domain_device(devices: Mapping[str, Any], domain: str) -> Any:
    """The device that stands for the domain."""
    device = devices.get(domain)
    if device is None:
        raise WriteError("unknown domain")
    if getattr(device, "platform", None) not in AD_PLATFORMS:
        raise WriteError("the domain is not an Active Directory device")
    return device


def domain_dcs(devices: Mapping[str, Any], domain: str) -> list[Any]:
    """The DCs of the domain: the write entries that name it."""
    domain_device(devices, domain)
    dcs = [
        device
        for device in devices.values()
        if is_write_device(device) and getattr(device, "ad_domain", None) == domain
    ]
    return dcs


def domain_guid(devices: Mapping[str, Any], domain: str) -> str:
    """The objectGUID of the domain head, as the inventory holds it."""
    device = domain_device(devices, domain)
    guid = getattr(device, "ad_domain_guid", None)
    if not isinstance(guid, str) or not guid:
        raise WriteError("the inventory holds no guid for the domain head")
    return guid
