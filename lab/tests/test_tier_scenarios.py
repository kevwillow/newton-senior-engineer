"""R4: three live tier scenario files in lab/scenarios/tiers/.

The runner (lab/newton-lab-test.py) learns the new scenario kind in R3: a
``tier`` field plus optional ``tier_values``, ``tier_batch_lines``,
``tier_fail_probe`` and ``tier_reboot`` fields; the live proof lives in
``lab/scenarios/tiers/*.toml`` and is pinned by this test.

The three files are the R4 deliverable:

* ``10-tier-standard.toml``  - the standard tier, one batch (no
  ``tier_batch_lines``: the runner defaults to the router cap), only
  needs the WAN firewall zone id (``fw_wan_zone``).
* ``11-tier-hardened.toml``  - the hardened tier, ``tier_batch_lines = 16``
  so the splitter emits two ordered batches in the live proof; needs
  ``fw_wan_zone`` AND ``fw_allow_ping``.
* ``12-tier-lockdown.toml``  - the lockdown tier, same shape as hardened.

The test pins the live files against the splitter: the
``tier_values`` table's keys must match the union of placeholders in
the NON-skipped batches (``split_tier`` with the scenario's
``tier_batch_lines``); every ``{var}`` referenced by the values must
exist in ``lab.vars``; the file must NOT carry a ``batch`` or
``approval`` field (tier scenarios are auto-driven batch by batch, never
declare one themselves).

The pin is intentionally strict: any of the following fails the test:
a missing tier, an unexpected tier, an unexpected name, a missing
``{fw_wan_zone}``/``{fw_allow_ping}`` value, a stray ``batch`` or
``approval`` field, a failure to validate the scenario set with
``validate_scenarios``, or a malformed ``tier_fail_probe``.

The test also pins that ``lab/scenarios/*.toml`` (the core nine) and
``lab/scenarios/openwrt/*.toml`` (the per-control scenarios, 63 today)
are unchanged in count by this round.
"""
from __future__ import annotations

from conftest import lab_toml_path

import re
import sys
from pathlib import Path

# Make `newton_lab_test` importable (loaded by lab/tests/conftest.py too,
# but that import only runs when pytest collects from lab/tests; here the
# test module itself wants the same view of the runner).
import importlib.util

import pytest

LAB_DIR = Path(__file__).resolve().parent.parent
_REPO = LAB_DIR.parent
_MCP_DIR = _REPO / "mcp"
for _p in (str(_MCP_DIR),):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import newton_mcp.probes as mcp_probes  # noqa: E402
import newton_mcp.tiers as mcp_tiers  # noqa: E402

# Load the runner the same way the conftest does.  Doing it again here
# is cheap and lets this file be run on its own (not just via pytest).
_spec = importlib.util.spec_from_file_location(
    "newton_lab_test", LAB_DIR / "newton-lab-test.py"
)
_nl = importlib.util.module_from_spec(_spec)
sys.modules.setdefault("newton_lab_test", _nl)
_spec.loader.exec_module(_nl)


LAB_TOML = lab_toml_path()
TIERS_DIR = LAB_DIR / "scenarios" / "tiers"
CORE_DIR = LAB_DIR / "scenarios"
OPENWRT_DIR = LAB_DIR / "scenarios" / "openwrt"

EXPECTED_NAMES = {
    "10-tier-standard",
    "11-tier-hardened",
    "12-tier-lockdown",
}
EXPECTED_TIERS = {
    "10-tier-standard": "standard",
    "11-tier-hardened": "hardened",
    "12-tier-lockdown": "lockdown",
}


@pytest.fixture(scope="module")
def tiers_dir() -> Path:
    """The tiers directory must exist and be readable."""
    assert TIERS_DIR.is_dir(), f"missing tier scenarios dir: {TIERS_DIR}"
    return TIERS_DIR


@pytest.fixture(scope="module")
def lab_and_scenarios(tiers_dir: Path):
    lab = _nl.load_lab(LAB_TOML)
    scens = _nl.load_scenarios(tiers_dir)
    return lab, scens


# ---- file presence -----------------------------------------------------------


def test_three_tier_files_present(tiers_dir: Path):
    """The R4 deliverable: exactly the three tier files, nothing extra."""
    files = {p.stem for p in tiers_dir.glob("*.toml")}
    assert files == EXPECTED_NAMES, (
        f"unexpected tier scenario set: {files!r} != {EXPECTED_NAMES!r}"
    )


# ---- validate cleanly -----------------------------------------------------


def test_validate_scenarios_returns_no_errors(lab_and_scenarios):
    """`validate_scenarios` accepts the new tier files without errors."""
    lab, scens = lab_and_scenarios
    errs = _nl.validate_scenarios(lab, scens)
    assert errs == [], f"validation errors: {errs}"


# ---- exactly three, names + tier fields right ---------------------------


def test_three_scenarios_with_correct_names_and_tiers(lab_and_scenarios):
    """The runner sees exactly three scenarios, named by file stem, with
    the matching `tier` field."""
    _, scens = lab_and_scenarios
    assert len(scens) == 3, scens
    by_name = {s.name: s for s in scens}
    assert set(by_name) == EXPECTED_NAMES, set(by_name)
    for name, tier in EXPECTED_TIERS.items():
        assert by_name[name].tier == tier, (
            f"{name}.tier={by_name[name].tier!r} (expected {tier!r})"
        )
        # tier_reboot is true everywhere (the live proof reboots)
        assert by_name[name].tier_reboot is True, name
        # common expectations from the task description
        assert by_name[name].target == "lab-r1", name
        assert by_name[name].expect == "confirmed", name
        assert by_name[name].reset == ["lab-r1"], name
        assert by_name[name].timeout == 180, name


# ---- no `batch` or `approval` key in the tier files ---------------------


def test_no_batch_or_approval_key_in_tier_files(tiers_dir: Path):
    """Tier scenarios are auto-driven batch-by-batch; they MUST NOT
    declare a `batch` of their own (the runner requires it to be empty)
    nor an `approval` field (tier code uses AUTO approval on every
    batch)."""
    for p in sorted(tiers_dir.glob("*.toml")):
        text = p.read_text()
        # Quick check before tomllib: a `batch =` or `approval =` line
        # (start of line, optional spaces) at the top level of the file.
        # We accept `approval_required` style text inside prose but
        # not a top-level `approval = ` or `batch = ` assignment.
        assert not re.search(r'^batch\s*=', text, re.MULTILINE), (
            f"{p.name}: tier scenario declares a `batch` field; "
            f"the runner plans every batch itself"
        )
        assert not re.search(r'^approval\s*=', text, re.MULTILINE), (
            f"{p.name}: tier scenario declares an `approval` field; "
            f"tier code uses AUTO approval on every batch"
        )


# ---- tier_values keys match the NON-skipped batches' placeholders ------


def test_tier_values_keys_match_splitter_placeholders(lab_and_scenarios):
    """For every tier scenario, the keys in ``tier_values`` are exactly
    the placeholders the splitter finds in that tier's NON-skipped
    batches (the `skipped` blocks are lab-bound or conditional and are
    NEVER planned, so they don't need values).

    The splitter is called with the scenario's own ``tier_batch_lines``
    so a 16-line cap forces the multi-batch split for hardened/lockdown
    and a default cap keeps standard as one batch."""
    _, scens = lab_and_scenarios
    for scen in scens:
        info = mcp_tiers.split_tier(
            scen.tier, max_lines=scen.tier_batch_lines
        )
        expected: set[str] = set()
        for batch in info["batches"]:
            expected.update(batch["placeholders"])
        got = set(scen.tier_values or {})
        assert got == expected, (
            f"{scen.name}: tier_values keys {got!r} != splitter "
            f"placeholders {expected!r} (tier_batch_lines="
            f"{scen.tier_batch_lines}, batches="
            f"{[b['control_ids'] for b in info['batches']]})"
        )


# ---- every {var} referenced by tier_values exists in lab.vars ------------


def test_every_referenced_var_exists_in_lab(lab_and_scenarios):
    """The {var} references inside the values come from lab.toml's
    [vars] block; a name the runner can't resolve fails the live proof.
    The test pins the contract."""
    lab, scens = lab_and_scenarios
    for scen in scens:
        values = scen.tier_values or {}
        for key, raw_value in values.items():
            for ref in re.findall(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}", raw_value):
                assert ref in lab.var_defs, (
                    f"{scen.name}: tier_values.{key} references "
                    f"{{ {ref} }} which is not a [vars] entry"
                )


# ---- tier_batch_lines is None for standard, 16 for the others ----------


def test_tier_batch_lines_per_tier(lab_and_scenarios):
    """Standard uses the router cap (no tier_batch_lines; default None).
    Hardened and lockdown split into two or more batches at cap=16."""
    _, scens = lab_and_scenarios
    by_name = {s.name: s for s in scens}
    assert by_name["10-tier-standard"].tier_batch_lines is None
    assert by_name["11-tier-hardened"].tier_batch_lines == 16
    assert by_name["12-tier-lockdown"].tier_batch_lines == 16


def test_split_counts_match_live_promise(lab_and_scenarios):
    """Hardened and lockdown each split into >= 2 batches with their
    own cap; standard splits into a single batch with the default cap
    (the runner leaves tier_batch_lines as None)."""
    _, scens = lab_and_scenarios
    by_name = {s.name: s for s in scens}
    standard = mcp_tiers.split_tier(
        by_name["10-tier-standard"].tier,
    )
    hardened = mcp_tiers.split_tier(
        by_name["11-tier-hardened"].tier,
        max_lines=by_name["11-tier-hardened"].tier_batch_lines,
    )
    lockdown = mcp_tiers.split_tier(
        by_name["12-tier-lockdown"].tier,
        max_lines=by_name["12-tier-lockdown"].tier_batch_lines,
    )
    assert len(standard["batches"]) == 1, (
        f"standard should be one batch with the default cap; got "
        f"{len(standard['batches'])}: "
        f"{[b['control_ids'] for b in standard['batches']]}"
    )
    assert len(hardened["batches"]) >= 2, (
        f"hardened should be >= 2 batches at cap=16; got "
        f"{len(hardened['batches'])}: "
        f"{[b['control_ids'] for b in hardened['batches']]}"
    )
    assert len(lockdown["batches"]) >= 2, (
        f"lockdown should be >= 2 batches at cap=16; got "
        f"{len(lockdown['batches'])}: "
        f"{[b['control_ids'] for b in lockdown['batches']]}"
    )


# ---- tier_fail_probe is a single valid probe ----------------------------


def test_tier_fail_probe_validates(lab_and_scenarios):
    """The fail-probe must be a single probe the plan can seal."""
    _, scens = lab_and_scenarios
    for scen in scens:
        assert scen.tier_fail_probe is not None, scen.name
        normalized = mcp_probes.validate_probes([scen.tier_fail_probe])
        assert normalized == [scen.tier_fail_probe], (
            f"{scen.name}: tier_fail_probe did not round-trip: "
            f"{normalized!r}"
        )


# ---- core + openwrt scenario counts unchanged ---------------------------


def test_core_and_openwrt_scenario_counts_unchanged():
    """R4 adds lab/scenarios/tiers/, not new core or openwrt files.
    Core is 9 today; openwrt is 63 today.  Any future change must update
    this pin deliberately."""
    core = sorted(p.stem for p in CORE_DIR.glob("*.toml"))
    openwrt = sorted(p.stem for p in OPENWRT_DIR.glob("*.toml"))
    assert len(core) == 9, f"core scenario count drifted: {core}"
    assert len(openwrt) == 63, f"openwrt scenario count drifted: {openwrt}"


# ---- [[post]] checks the new files carry --------------------------------


def test_each_tier_file_has_the_post_check(tiers_dir: Path):
    """Every tier file carries a single [[post]] that proves the staged
    config is empty (`uci changes | wc -l` -> 0)."""
    for p in sorted(tiers_dir.glob("*.toml")):
        text = p.read_text()
        # the post is the only [[post]] table the file declares
        assert "[[post]]" in text, f"{p.name}: no [[post]] block"
        assert "uci changes | wc -l" in text, (
            f"{p.name}: [[post]] does not run `uci changes | wc -l`"
        )
        assert '^0$' in text, (
            f"{p.name}: [[post]] does not pin the empty-staged `^0$` regex"
        )
        assert 'device = "lab-r1"' in text, (
            f"{p.name}: [[post]] is not on lab-r1"
        )