"""The token rule of every stage (PLAN-1.5 task 4, DESIGN-1.5 "Tokens").

The design covers the read and the reversible stages with the plan
token and the irreversible ones with a stage token.  Stage 9 is
``final``, and the plan token covers it too (the maintainer, 2026-11-13): it is
never opened by a stage token.
"""

from __future__ import annotations

import pytest

from newton_mcp.ad.build import plan
from newton_mcp.ad.build import stage_token


def test_the_plan_token_covers_the_read_and_the_reversible_stages() -> None:
    assert stage_token.token_kind("0") == "plan"
    assert stage_token.token_kind("1") == "plan"
    assert stage_token.token_kind("5") == "plan"
    assert stage_token.token_kind("8") == "plan"
    assert stage_token.token_kind("10") == "plan"


def test_the_plan_token_covers_the_final_stage() -> None:
    # The maintainer, 2026-11-13: stage 9 is covered by the plan approval.
    assert plan.STAGE_KINDS[stage_token.FINAL_STAGE] == "final"
    assert stage_token.token_kind(stage_token.FINAL_STAGE) == "plan"


def test_the_stage_token_covers_the_irreversible_stages() -> None:
    for stage in ("2", "3", "4", "6", "7"):
        assert stage_token.token_kind(stage) == "stage"


def test_the_kinds_of_the_plan_are_the_ones_the_rule_covers() -> None:
    # The rule is built out of the kinds of the plan, and every kind of
    # the plan is covered by it.
    assert plan.STAGE_KINDS["9"] == "final"
    assert set(plan.STAGE_KINDS.values()) == {
        "read",
        "reversible",
        "irreversible",
        "final",
    }
    covered = {
        stage
        for stage in plan.STAGE_IDS
        if plan.STAGE_KINDS[stage] in stage_token.TOKEN_KINDS
    }
    assert covered == set(plan.STAGE_IDS)
    stage_kinded = {
        stage
        for stage in plan.STAGE_IDS
        if stage_token.token_kind(stage) == "stage"
    }
    assert stage_kinded == {"2", "3", "4", "6", "7"}


def test_a_stage_that_is_not_a_stage_of_the_design_is_refused() -> None:
    for stage in ("11", "", "two", " 2"):
        with pytest.raises(stage_token.StageTokenRefused) as caught:
            stage_token.token_kind(stage)
        assert caught.value.code == "schema"
