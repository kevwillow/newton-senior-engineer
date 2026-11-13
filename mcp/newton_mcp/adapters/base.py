"""Shared adapter contract and capability model (design section 4)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Protocol


TIER_EXPERIMENTAL = "T0-exp"

READ_ONLY_TOOLS = frozenset(
    {
        "newton_list_devices",
        "newton_list_getters",
        "newton_get_state",
        "newton_guided_recommend",
        "newton_guided_audit",
    }
)

# The read-only tools of the AD platforms (SPEC-1.3 section 9).  They
# read a collector document and change nothing, so a read-only
# capability may advertise them.  Which platform gets them is the
# registry's decision, not this module's.
AD_READ_ONLY_TOOLS = frozenset(
    {
        "newton_ad_audit",
        "newton_ad_list_checks",
    }
)

# The write tools of the Active Directory platforms (SPEC-1.4).  They
# plan, apply, show and abort a change in a domain; the approval is out
# of band (newton-approve), so there is no approve tool among them.
AD_WRITE_TOOLS = frozenset(
    {
        "newton_ad_plan_change",
        "newton_ad_apply_change",
        "newton_ad_change_status",
        "newton_ad_abort_change",
    }
)


@dataclass(frozen=True)
class Capabilities:
    """Platform capability envelope (design section 4)."""

    tier: str
    writes: bool
    native_revert: str | None
    tools: frozenset[str]

    def __post_init__(self) -> None:
        """Enforce the capability invariant from design section 4."""
        if (not self.writes or self.tier == TIER_EXPERIMENTAL) and not (
            self.tools <= (READ_ONLY_TOOLS | AD_READ_ONLY_TOOLS)
        ):
            raise ValueError(
                "read-only or experimental capabilities may only advertise "
                "READ_ONLY_TOOLS"
            )
        if self.tier == TIER_EXPERIMENTAL and self.writes:
            raise ValueError("experimental capabilities must not advertise writes")


class ReadOnlyAdapter(Protocol):
    """Vendor read-only adapter contract (design section 4)."""

    platform: str
    capabilities: Capabilities

    def getters(self) -> Mapping[str, Any]:
        """Return allowlisted getter metadata (design section 4)."""
        ...

    def run_getter(
        self,
        device: Any,
        getter_id: str,
        params: Mapping[str, str],
    ) -> dict[str, Any]:
        """Run one allowlisted getter (design section 4)."""
        ...

    def redact(self, getter_id: str, text: str) -> str:
        """Redact getter output (design section 4)."""
        ...

    def setup_instructions(self) -> str:
        """Explain read-only setup (design section 4)."""
        ...
