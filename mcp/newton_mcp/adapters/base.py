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
            self.tools <= READ_ONLY_TOOLS
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
