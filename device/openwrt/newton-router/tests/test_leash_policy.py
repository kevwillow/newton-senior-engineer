"""Design 9.2 group 8 (5.2): differential tests between the router-side leash
(run by `seal`) and the host policy (the `newton_mcp.policy.classify` function
read on the same staged diff).

The diff form is exactly what `uci -P staged changes` prints between the
``----- diff`` markers: index mode names anonymous sections by their
committed ``@type[N]`` token (which is what the host policy sees; `id`
mode names them by the internal id and the corpus checks may add a `MAY`
set that the differential test does not). For every scenario in
``leash_corpus.SCENARIOS``:

1. Build the scenario in INDEX mode; take ``scn.build()["changes"]`` joined by LF.
2. Run the host ``classify`` with the minimal staging batch
   ``"set a.b.c=1\\n"`` (the value is irrelevant; `classify` checks that the
   batch is staging verbs only) and ``check="true"``.
3. Run the router: ``use_leash_uci()`` plus ``sealed_scenario(scn)``; the seal
   emits ``approval required`` or ``approval not-required``.
4. Compare the two booleans with the declared relation in
   ``leash_policy_relations.RELATIONS``; default ``same`` for an unlisted scenario.

A second test replays every lab batch (the 67 ``.toml`` files under
``lab/scenarios/**``) through the seal-with-empty-views harness and through
``classify``, with a small uci-batch-to-changes converter: the conversion
rules are listed in ``_convert_batch``. Batches that need a line the rules
cannot convert are skipped and counted; convertible batches are run with
empty views (no staged/committed views) so the seal still emits a complete
``approval`` and ``digest`` line.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tomllib
import types
from pathlib import Path

import pytest

from leash_corpus import SCENARIOS, SCENARIO_IDS, base_config
from leash_model import Scenario
from leash_policy_relations import RELATIONS


_HERE_FILE = Path(__file__).resolve()
HERE = _HERE_FILE.parent
REPO = _HERE_FILE.parents[4]
POLICY_FILE = REPO / "mcp" / "newton_mcp" / "policy.py"
LAB_DIR = REPO / "lab" / "scenarios"

_DEFAULT_ZONES = {"mgmt-interface": "lan", "mgmt-zone": "lan", "wan-zone": ["wan"]}


# ---- import policy.classify: prefer package import (newton_mcp package imports
# nothing in __init__.py and policy.py itself only uses stdlib); fall back to a
# direct spec_from_file_location if the third-party `mcp` SDK is not installed.
try:
    sys.path.insert(0, str(REPO / "mcp"))
    from newton_mcp.policy import classify  # type: ignore[import-not-found]
except Exception:
    if not POLICY_FILE.exists():
        pytest.fail(
            f"missing {POLICY_FILE}; cannot import policy.classify for differential test",
            pytrace=False,
        )
    spec = importlib.util.spec_from_file_location("_leash_policy", str(POLICY_FILE))
    if spec is None or spec.loader is None:
        pytest.fail(
            f"failed to build import spec for {POLICY_FILE}", pytrace=False
        )
    _pol = importlib.util.module_from_spec(spec)
    sys.modules["_leash_policy"] = _pol
    spec.loader.exec_module(_pol)
    classify = _pol.classify


def _zones(zones):
    return zones if zones is not None else _DEFAULT_ZONES


def _device(profile, zones):
    z = _zones(zones)
    return types.SimpleNamespace(
        profile=profile, mgmt_interface=z["mgmt-interface"], mgmt_zone=z["mgmt-zone"],
        wan_zones=tuple(z["wan-zone"]),
    )


def _section_facts(seal_out: str):
    """The host's section facts: the seal's own ``section`` lines for this scenario."""
    facts = {}
    for line in seal_out.splitlines():
        if not line.startswith("section "):
            continue
        rest = line[len("section "):]
        parts = rest.split()
        if len(parts) != 4:
            continue
        cfg, sec, typ, nam = parts
        facts[(cfg, sec)] = (None if typ == "-" else typ, None if nam == "-" else nam)
    return facts


def _relation(pol_req: bool, router_req: bool) -> str:
    if pol_req == router_req:
        return "same"
    return "router-wider" if router_req else "router-narrower"


# ---- per-scenario differential -----------------------------------------------------
@pytest.mark.parametrize("scenario_index", list(range(len(SCENARIOS))), ids=SCENARIO_IDS)
def test_scenario_against_policy(router, scenario_index):
    name, ops, expect, profile, zones = SCENARIOS[scenario_index]
    scn = Scenario(base_config(), ops, profile=profile, zones=zones, mode="index")
    changes = scn.build()["changes"]
    diff = "\n".join(changes)

    router.use_leash_uci()
    result = router.sealed_scenario(scn)
    assert (result.rc, result.err) == (0, ""), (
        f"{name}: router seal crashed rc={result.rc} err={result.err!r} out={result.out!r}"
    )
    assert "approval " in result.out, f"{name}: router seal missing approval line: {result.out!r}"
    assert "digest " in result.out, f"{name}: router seal missing digest line: {result.out!r}"
    router_req = "approval required" in result.out

    # the host sees the diff plus the router's own section facts (exactly
    # what newton_plan_change feeds classify)
    pol = classify(
        _device(profile, zones), "set a.b.c=1\n", diff,
        section_facts=_section_facts(result.out),
    )
    pol_req = pol["requires_approval"]

    declared = RELATIONS.get(name, ("same", ""))
    relation, reason = declared
    if relation != "same" and not reason:
        pytest.fail(f"{name}: relation without a reason (declared={relation!r})")

    actual = _relation(pol_req, router_req)
    assert actual == relation, (
        f"{name}: relation mismatch: actual={actual} declared={relation} "
        f"pol_req={pol_req} router_req={router_req} pol_reasons={pol['reasons']!r}"
    )


# ---- table integrity: every non-same scenario must carry a reason; no name
# that does not exist as a corpus scenario.
def test_relations_table_is_consistent():
    declared_names = set(RELATIONS)
    scenario_names = set(SCENARIO_IDS)
    unknown = sorted(declared_names - scenario_names)
    assert not unknown, f"RELATIONS has entries for unknown scenarios: {unknown}"

    for name, (relation, reason) in RELATIONS.items():
        assert relation in ("same", "router-wider", "router-narrower"), (
            f"{name}: unknown relation {relation!r}"
        )
        if relation != "same":
            assert reason, f"{name}: non-same relation {relation!r} without a reason"

    non_same = sorted(n for n, (rel, _) in RELATIONS.items() if rel != "same")
    assert non_same, "RELATIONS is empty; expected at least one non-same row"


# ---- list-of-non-same scenarios for the report (no pytest.skip; one test that
# prints the rows the differential test depends on)
def test_list_non_same_scenarios(capsys):
    rw = sorted(
        (n, reason) for n, (relation, reason) in RELATIONS.items() if relation == "router-wider"
    )
    rn = sorted(
        (n, reason) for n, (relation, reason) in RELATIONS.items() if relation == "router-narrower"
    )
    out = [f"non-same scenarios: {len(rw) + len(rn)} ({len(rw)} wider, {len(rn)} narrower)"]
    out.append("router-wider:")
    out.extend(f"  {n} | {r}" for n, r in rw)
    out.append("router-narrower:")
    out.extend(f"  {n} | {r}" for n, r in rn)
    print("\n".join(out))
    captured = capsys.readouterr().out
    assert "router-wider" in captured and "router-narrower" in captured, captured


# ---- lab batches: replay with empty views (raw changes only) -----------------------
def _convert_batch(batch_text: str) -> tuple[list[str], str | None]:
    """Translate a uci staging batch into `uci changes`-style lines.

    Recognised forms (the task's rules):
        set a.b.c=v          -> a.b.c='v'         (or a.b.c=v if v is already quoted)
        add_list a.b.c=v     -> a.b.c+='v'        (or ...+=v  if v is already quoted)
        del_list a.b.c=v     -> a.b.c-='v'        (or ...-=v  if v is already quoted)
        delete a.b           -> -a.b
        delete a.b.c         -> -a.b.c
    Anything else marks the WHOLE batch as unconvertible (the first offending
    line is reported).
    """
    out: list[str] = []
    for raw in batch_text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            return [], f"unparsable verb line: {line[:80]!r}"
        verb, rest = parts
        if verb == "set":
            path, _, val = rest.partition("=")
            if not val:
                return [], f"`set` without value: {line[:80]!r}"
            if path.count(".") != 2:
                return [], f"`set` form not a.b.c=v: {line[:80]!r}"
            quoted = val if (val[0] == val[-1] and val[0] in ("'", '"')) else f"'{val}'"
            out.append(f"{path}={quoted}")
        elif verb in ("add_list", "del_list"):
            path, _, val = rest.partition("=")
            if not val:
                return [], f"`{verb}` without value: {line[:80]!r}"
            if path.count(".") != 2:
                return [], f"`{verb}` form not a.b.c=v: {line[:80]!r}"
            quoted = val if (val[0] == val[-1] and val[0] in ("'", '"')) else f"'{val}'"
            marker = "+" if verb == "add_list" else "-"
            out.append(f"{path}{marker}={quoted}")
        elif verb == "delete":
            if rest.count(".") not in (1, 2):
                return [], f"`delete` form not a.b or a.b.c: {line[:80]!r}"
            out.append(f"-{rest}")
        elif verb == "add":
            return [], f"`add` not expressible: {line[:80]!r}"
        else:
            return [], f"unrecognised verb {verb!r}: {line[:80]!r}"
    return out, None


def _seal_raw_changes(router, changes: list[str], profile: str, zones: dict) -> "Result":
    """Mirror of conftest.Router.sealed_scenario for raw uci changes; empty views."""
    import shutil

    r = router.root
    router.write("control/uci.json", json.dumps({
        "changes": changes, "staged": {}, "committed": {}, "full_firewall": [],
    }).encode())
    router.write("etc/newton/profile", profile + "\n")
    zl = (
        f"mgmt-interface {zones['mgmt-interface']}\n"
        f"mgmt-zone {zones['mgmt-zone']}\n"
        + "".join(f"wan-zone {w}\n" for w in zones["wan-zone"])
    )
    router.write("etc/newton/zones", zl)
    diff = ("\n".join(changes) + ("\n" if changes else "")).encode()
    router.write("control/diff.txt", diff)
    sid = "0123456789abcdef0123456789abcdef"
    lock = r / "tmp/owrt-safe-apply.lock"
    txn = lock / f"{sid}.txn"
    if txn.exists():
        shutil.rmtree(txn)
    txn.mkdir(parents=True)
    (txn / "owner").write_text("agent-one\n")
    (txn / "stage-up").write_text("100\n")
    (txn / "boot").write_text("boot-one\n")
    (lock / "sid").write_text(sid + "\n")
    # the helper records the folder rpcd keeps the session's changes in
    (lock / f"{sid}.dir").write_text(f"/var/run/rpcd/uci-{sid}\n")
    sessions = r / "control" / "sessions"
    existing = sessions.read_text() if sessions.exists() else ""
    if sid not in existing.split():
        sessions.write_text(existing + sid + "\n")
    router.use_stub_helper()
    return router.seal(sid, 90)


def test_lab_batches_have_valid_approval_and_digest(router):
    if not LAB_DIR.exists():
        pytest.skip(f"lab scenarios not found at {LAB_DIR}")

    files = sorted(LAB_DIR.glob("**/*.toml"))
    assert files, f"no .toml files under {LAB_DIR}"

    found = converted = skipped = 0
    skipped_examples: list[tuple[str, str]] = []
    bad_run: list[tuple[str, str]] = []

    device = types.SimpleNamespace(profile="lab", mgmt_interface="lan", mgmt_zone="lan", wan_zones=("wan",))
    zones = _DEFAULT_ZONES

    for path in files:
        with open(path, "rb") as fh:
            doc = tomllib.load(fh)
        batch_text = doc.get("batch")
        if not isinstance(batch_text, str) or not batch_text.strip():
            continue
        found += 1
        changes, err = _convert_batch(batch_text)
        if err is not None or not changes:
            skipped += 1
            if len(skipped_examples) < 5:
                skipped_examples.append((path.name, err or "empty changes"))
            continue
        converted += 1

        # router on empty views
        result = _seal_raw_changes(router, changes, "lab", zones)
        if (
            result.rc != 0
            or result.err.strip() != ""
            or "approval " not in result.out
            or "digest " not in result.out
        ):
            bad_run.append((
                path.name,
                f"rc={result.rc} err={result.err!r} out_snip={result.out[:200]!r}",
            ))
            continue

        router_req = "approval required" in result.out

        # POL on the same lines, fed the seal's own section facts where the
        # harness can provide them (the raw-changes seal resolves no types,
        # so every fact is (None, None): the groups stay fail-safe)
        diff_text = "\n".join(changes)
        try:
            pol = classify(device, "set a.b.c=1\n", diff_text,
                           section_facts=_section_facts(result.out))
        except ValueError as e:
            bad_run.append((path.name, f"POL raise: {e}"))
            continue
        pol_req = pol["requires_approval"]

        rel = _relation(pol_req, router_req)
        assert rel in ("same", "router-wider", "router-narrower"), rel

    report = (
        f"\nlab batches: found={found} converted={converted} skipped={skipped}"
        f" files={len(files)} bad_run={len(bad_run)}"
    )
    if skipped_examples:
        report += "\nskipped examples:\n  " + "\n  ".join(
            f"{n}: {e}" for n, e in skipped_examples
        )
    if bad_run:
        report += "\nbad runs:\n  " + "\n  ".join(f"{n}: {e}" for n, e in bad_run)
    print(report)

    assert not bad_run, f"{len(bad_run)} batches did not satisfy the check{report}"
