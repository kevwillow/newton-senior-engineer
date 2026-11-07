"""Design 5.2 and 5.3: the seal-time leash classification.

Each scenario in `leash_corpus.SCENARIOS` (a committed config plus a list of operations,
with a hand-written expected code set, an optional profile and an optional zones override)
is replayed through `seal` in two naming modes: `index` (uci names anonymous sections by
their committed `@type[N]` index) and `id` (uci names them by their internal id). The
test asserts the program's leash-code set lies inside `expect | MAY[name]` and contains
`expect`, the model agrees on the same containment (so the corpus stays honest) and the
`approval required` / `approval not-required` line follows the rule of design 5.3.
"""
import pytest

from leash_corpus import SCENARIOS, SCENARIO_IDS, MAY, base_config
from leash_model import Scenario


@pytest.mark.parametrize(
    "scenario_index, mode",
    [
        (i, mode)
        for i, _ in enumerate(SCENARIOS)
        for mode in ("index", "id")
    ],
    ids=[f"{name}-{mode}" for name in SCENARIO_IDS for mode in ("index", "id")],
)
def test_scenario_codes(router, scenario_index, mode):
    router.use_leash_uci()
    name, ops, expect, profile, zones = SCENARIOS[scenario_index]
    scn = Scenario(base_config(), ops, profile=profile, zones=zones, mode=mode)
    model = scn.expected()
    may = MAY[name] if mode == "index" else set()
    assert expect <= model <= expect | may, (
        f"corpus drift: hand={sorted(expect)} model={sorted(model)} may={sorted(may)}"
    )
    result = router.sealed_scenario(scn)
    assert (result.rc, result.err) == (0, "")
    lines = result.out.splitlines()
    got = {l.split()[1] for l in lines if l.startswith("leash ")}
    approval = [l for l in lines if l.startswith("approval ")]
    want_approval = "approval required" if (expect or profile == "prod") else "approval not-required"
    assert approval == [want_approval], f"approval line: got={approval} want=[{want_approval}]"
    assert expect <= got <= expect | may, (
        f"{name} [{mode}]: got={sorted(got)} expect={sorted(expect)} may={sorted(may)}"
    )


def test_every_scenario_has_a_unique_name():
    names = [s[0] for s in SCENARIOS]
    assert len(names) >= 150
    assert len(set(names)) == len(names), (
        "duplicate scenario names: " + ", ".join(sorted(n for n in names if names.count(n) > 1))
    )