"""Apply: two refusals of the stage-age and applied-marker checks that the planted defects A06 and A26 showed untested."""

import pytest

from test_apply import ready_for_arm, nothing_applied


def test_apply_with_only_the_applied_marker_is_already_applied_exit_1(router):
    """A txn that holds `applied` but not `applying` (a state a kill can only leave if something removed
    the other file) is a retried apply: exit 1, never the exit 3 that means "nothing applied" (M38)."""
    plan = router.fresh_plan()
    ready_for_arm(router)
    (plan.txn / "applied").write_text("190 221 boot-one\n")
    res = router.apply(plan.sid, plan.t, "none", 0, 0)
    assert (res.rc, res.out, res.err) == (1, "", "error already-applied\n")


@pytest.mark.parametrize("content", ["", "abc", "10x", "1 2", "-5"], ids=["empty", "word", "digits-and-letter", "two-words", "negative"])
def test_apply_refuses_a_stage_up_file_that_is_not_digits(router, content):
    """The stage age is arithmetic on the `stage-up` file: anything but digits is a stale stage (exit 3),
    never evaluated as an expression."""
    plan = router.fresh_plan()
    ready_for_arm(router)
    (plan.txn / "stage-up").write_text(content + "\n")
    res = router.apply(plan.sid, plan.t, "none", 0, 0)
    assert (res.rc, res.out, res.err) == (3, "", "error stale-stage\n")
    nothing_applied(router, plan.sid)
