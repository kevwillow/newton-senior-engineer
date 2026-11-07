"""Design 6.4: abort compares complete base and post hash lines."""

import pytest

from test_abort import apply_happy


@pytest.mark.parametrize(
    "suffix,want",
    [
        pytest.param("extra", "error inconsistent\n", id="extended"),
        pytest.param("", "error already-confirmed\n", id="exact"),
    ],
)
def test_abort_post_hash_requires_exact_equality(router, suffix, want):
    plan = router.fresh_plan()
    apply_happy(router, plan)
    (router.root / "etc/newton/pending").unlink()
    router.write("control/sessions", b"")

    post = plan.txn / "post"
    live_hash = post.read_text().strip()
    post.write_text(live_hash + suffix + "\n")

    res = router.forced(f"abort {plan.sid}", caller="agent-one", timeout=30)
    assert (res.rc, res.out, res.err) == (1, "", want)


@pytest.mark.parametrize(
    "suffix,want",
    [
        pytest.param("extra", "rolled-back-by-guard", id="extended"),
        pytest.param("", "already-rolled-back", id="exact"),
    ],
)
def test_abort_base_hash_requires_exact_equality(router, suffix, want):
    plan = router.fresh_plan()
    apply_happy(router, plan)
    router.set_uptime(190)
    assert router.rpcd_tick() == 0

    base = plan.txn / "base"
    live_hash = base.read_text().strip()
    base.write_text(live_hash + suffix + "\n")

    res = router.forced(f"abort {plan.sid}", caller="agent-one", timeout=30)
    assert (res.rc, res.out, res.err) == (
        0,
        f"aborted {plan.sid} {want}\n",
        "",
    )
