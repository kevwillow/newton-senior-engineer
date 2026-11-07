"""Fast check that every planted defect's `old` text is still unique in the program.

The full runner (tests/planted/runner.py) is slow -- minutes per defect -- so the maintainer
runs it once, not in the normal suite. This test guards the lists silently going stale: every
defects_*.py beside tests/planted/runner.py must satisfy:

  - `old` text occurs EXACTLY once in device/openwrt/newton-router/newton-router,
  - `old` != `new`,
  - every test path listed in the defect exists,
  - every defect id is unique across all defects_*.py files,
  - the total number of defects is at least 200.

Stale defect ids are named in the failure message so it is clear what to fix.
"""
import importlib.util
import os
from pathlib import Path

import pytest

PLANTED = Path(__file__).resolve().parent / "planted"
PROGRAM = Path(__file__).resolve().parents[1] / "newton-router"
REPO = Path(__file__).resolve().parents[3]


def _load_defects():
    text = PROGRAM.read_text()
    tests = []
    totals = []
    stale = []
    seen = {}
    dup = []
    bad_new = []
    missing_test = []
    for mf in sorted(PLANTED.glob("defects_*.py")):
        spec = importlib.util.spec_from_file_location(mf.stem, mf)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        n = 0
        for mid, desc, old, new, targs in mod.MUTANTS:
            n += 1
            if old == new:
                bad_new.append(mid)
            if text.count(old) != 1:
                stale.append((mid, mf.name, text.count(old), desc))
            for p in targs:
                if not (REPO / p).exists() and not Path(p).exists():
                    missing_test.append((mid, p))
            if mid in seen:
                dup.append((mid, mf.name, seen[mid]))
            seen[mid] = mf.name
        totals.append((mf.name, n))
    return text, totals, stale, dup, bad_new, missing_test


def test_defects_lists_current():
    text, totals, stale, dup, bad_new, missing = _load_defects()
    msgs = []
    if stale:
        ids = ", ".join(f"{mid} ({mf}: x{n})" for mid, mf, n, _d in stale)
        msgs.append(f"STALE defects (old text not unique in program): {ids}")
    if dup:
        ids = ", ".join(f"{mid} in {a} and {b}" for mid, a, b in dup)
        msgs.append(f"DUPLICATE ids across files: {ids}")
    if bad_new:
        ids = ", ".join(bad_new)
        msgs.append(f"defects with old == new: {ids}")
    if missing:
        ids = ", ".join(f"{mid} -> {p}" for mid, p in missing)
        msgs.append(f"missing test paths: {ids}")
    total = sum(n for _, n in totals)
    if total < 200:
        msgs.append(f"only {total} defects planted (need at least 200)")
    if msgs:
        pytest.fail("\n".join(msgs))


def test_defect_counts():
    totals = _load_defects()[1]
    msg = ", ".join(f"{name}={n}" for name, n in totals)
    print("defects per file: " + msg)
    assert sum(n for _, n in totals) >= 200, totals
