"""The lab of the AD write tests: one domain, its DCs and the fake helpers.

The lab holds the inventory of a domain (the device that stands for the
domain and a second DC), the fake helper of every DC and the function
that sends a request to the right helper.
"""

from __future__ import annotations

import copy
import json
from typing import Any, Mapping

import fake_helper

from newton_mcp.server import Device


#: The domain of the lab.
DOMAIN = "win-dc1"

#: The key of the lab.
KEY_HEX = "11" * 32

#: The approval window of the lab.
NBF = 1800000000
EXP = 1800000600

#: The account of the lab.
SEED_GUID = "6f9619ff-8b86-d011-b42d-00c04fc964ff"
SEED_SID = "S-1-5-21-1-2-3-1105"
SEED_SAM = "seed-asrep"

#: The group of the lab.
GROUP_GUID = "8f9619ff-8b86-d011-b42d-00c04fc964ff"
GROUP_SID = "S-1-5-21-1-2-3-1106"
GROUP_SAM = "seed-group"

#: The second account of the lab.
OTHER_GUID = "9f9619ff-8b86-d011-b42d-00c04fc964ff"
OTHER_SID = "S-1-5-21-1-2-3-1107"
OTHER_SAM = "other"

#: The domain head of the lab.
DOMAIN_GUID = "af9619ff-8b86-d011-b42d-00c04fc964ff"


def _device(name: str, domain: str = DOMAIN) -> Device:
    """One write entry of the inventory."""
    return Device(
        name=name,
        platform="ad-windows-write",
        host="192.0.2.10",
        user="newton-ops@win.newton.test",
        ad_domain=domain,
        ad_domain_guid=DOMAIN_GUID,
    )


class Lab:
    """One domain, its DCs and the fake helper of every DC.

    Every helper is configured with the name the setup writes into
    ``device.txt``: the domain device's name, the same on every DC.  A
    DC set up the old way, before the setup took ``--domain-device`` on
    every controller, holds its own name; ``dc2_configured`` builds
    that DC.
    """

    def __init__(
        self,
        *,
        pdc: bool = True,
        lagging: bool = False,
        key_hex: str = KEY_HEX,
        now: int = 1800000000,
        dc2_configured: str = DOMAIN,
    ) -> None:
        self.objects: dict[str, dict[str, Any]] = {}
        self.helpers: dict[str, fake_helper.FakeHelper] = {}
        self.devices: dict[str, Device] = {}
        self.helpers["win-dc1"] = fake_helper.FakeHelper(
            "win-dc1",
            configured=DOMAIN,
            pdc=pdc,
            key_hex=key_hex,
            objects=self.objects,
            now=now,
        )
        self.helpers["win-dc2"] = fake_helper.FakeHelper(
            "win-dc2",
            configured=dc2_configured,
            pdc=False,
            key_hex=key_hex,
            # a lagging DC holds its own copy: it never sees the write
            objects=copy.deepcopy(self.objects) if lagging else self.objects,
            now=now,
        )
        self.devices["win-dc1"] = _device("win-dc1")
        self.devices["win-dc2"] = _device("win-dc2")

    # -- the directory ----------------------------------------------------

    def add_user(
        self,
        guid: str = SEED_GUID,
        sid: str = SEED_SID,
        sam: str = SEED_SAM,
        **fields: Any,
    ) -> dict[str, Any]:
        """Add the account of the lab."""
        return self.helpers["win-dc1"].add(guid, sid, sam, **fields)

    def add_group(
        self,
        guid: str = GROUP_GUID,
        sid: str = GROUP_SID,
        sam: str = GROUP_SAM,
        **fields: Any,
    ) -> dict[str, Any]:
        """Add the group of the lab."""
        return self.helpers["win-dc1"].add(
            guid, sid, sam, kind="group", object_class=["group"], **fields
        )

    def add_other(
        self,
        guid: str = OTHER_GUID,
        sid: str = OTHER_SID,
        sam: str = OTHER_SAM,
        **fields: Any,
    ) -> dict[str, Any]:
        """Add the second account of the lab."""
        return self.helpers["win-dc1"].add(guid, sid, sam, **fields)

    def add_domain_head(self, **fields: Any) -> dict[str, Any]:
        """Add the domain head of the lab."""
        return self.helpers["win-dc1"].add(
            DOMAIN_GUID,
            "S-1-5-21-1-2-3-1",
            "win",
            kind="domain",
            object_class=["top", "domain", "domainDNS"],
            maq=10,
            **fields,
        )

    # -- the transport ----------------------------------------------------

    def lag(self, name: str = "win-dc2") -> None:
        """Make a DC lag: it keeps its own copy of the directory."""
        self.helpers[name].objects = copy.deepcopy(self.objects)

    def send(self, target: Any, request: Mapping[str, Any]) -> dict[str, Any]:
        """Send one request to the helper of the DC."""
        helper = self.helpers[target.name]
        return helper.handle(json.dumps(request).encode("utf-8"))
