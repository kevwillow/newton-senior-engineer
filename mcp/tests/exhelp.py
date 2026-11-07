"""Test helper: a valid explanation for a given uci batch.

Not a test module.  ``explained(batch)`` returns the two keyword arguments
every plan call now needs, with exactly one step per change line.
"""

from __future__ import annotations

from typing import Any


def change_line_count(batch: str) -> int:
    return sum(
        1 for line in batch.splitlines() if line.strip() and not line.strip().startswith("#")
    )


def make_explanation(batch: str, **overrides: Any) -> dict[str, Any]:
    count = change_line_count(batch)
    explanation: dict[str, Any] = {
        "intent": "Make the requested change the owner asked for.",
        "steps": [f"Change line {index} does part of the requested change." for index in range(1, count + 1)],
        "expect": [{"kind": "probe", "probe": ["iface-absent", "guestx"]}],
        "risk": "A wrong value could break the feature; the owner would see it fail.",
    }
    explanation.update(overrides)
    return explanation


def explained(batch: str, **overrides: Any) -> dict[str, Any]:
    return {
        "explanation": make_explanation(batch, **overrides),
        "owner_confirmed_in_chat": True,
    }


def record_fields(batch: str) -> dict[str, Any]:
    """The two plan-record fields the explanation added, for tests that build records by hand."""
    return {"explanation": make_explanation(batch), "owner_confirmed_in_chat": True}


def record_fields_display() -> dict[str, Any]:
    """The six plan-record fields made hash-bound, with realistic defaults.

    Tests that build a plan record by hand for ``compute_plan_hash`` (or that
    use it as a hand-rolled basis for ``apply``/``approve`` refusals) include
    these alongside ``record_fields(batch)`` so the record has every field
    the canonical identity needs.  Override any of these in the test body
    by passing a different value when the test specifically exercises one of
    them (the dict is meant to be spread, so callers can ``{**record_fields(),
    "reasons": [...]}`` freely).

    Realistic defaults match what the live planner writes for a lab-carved
    host making a low-risk write:
      reasons:                 a prod-profile-style reason (mirrors what the
                                router-side planner stamps on every change in
                                prod; the lab carve-out does not strip it so
                                the displayed "Risk reasons:" row is not empty)
      router_leash:            one leash code, the typical short-list shape
                                approve.py prints under "Leash codes:"
      router_profile:          "lab" (the typical lab-plan shape; tests in
                                prod-profile scenarios override this)
      router_sections:         one parsed section line, again the typical
                                short-list shape approve.py prints under
                                "Sections:"
      router_requires_approval: False (the typical lab device; prod-profile
                                tests override to True)
      staged_check:            fw4 not needed (firewall untouched), dhcp not checked
    """
    return {
        "reasons": ["profile 'prod': every write requires approval"],
        "router_leash": ["wan-rule firewall.wan_rule.src"],
        "router_profile": "lab",
        "router_sections": ["dhcp skilltest host-reservation skilltest"],
        "router_requires_approval": False,
        "staged_check": {"fw4": "skipped-untouched", "reason": "", "not_checked": ["dhcp"]},
    }


def tier_explained(tier: str, batch_index: int = 0, values: dict[str, str] | None = None) -> dict[str, Any]:
    """``explained`` for a tier batch: one step per change line of the resolved batch.

    If the batch cannot be resolved (a test passing bad values on purpose) the
    call is refused before the explanation matters, so a one-step stand-in is fine.
    """
    from newton_mcp import tiers

    try:
        info = tiers.split_tier(tier)
        names = sorted({n for b in info["batches"] for n in tiers.tier_placeholders(b["text"])})
        text = tiers.resolve_batch(info["batches"][batch_index]["text"], values, tier_names=names)
    except Exception:
        text = "set a.b=c"
    return explained(text)
