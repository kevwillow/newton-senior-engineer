"""Fast check that every planted defect's `old` text is still unique.

The full runner (lab/tests/planted/runner.py) runs one pytest per defect, so
it is separate from the normal suite.  This test guards the lists silently
going stale: every defects_*.py beside lab/tests/planted/runner.py must
satisfy:

  - `old` text occurs EXACTLY once in the file the defect names,
  - `old` != `new`,
  - every test path listed in the defect exists,
  - every defect id is unique across all defects_*.py files,
  - every defect names a file inside lab/.

Stale defect ids are named in the failure message so the maintainer knows
what to fix.
"""
import importlib.util
from pathlib import Path

import pytest

PLANTED = Path(__file__).resolve().parent / "planted"
REPO = Path(__file__).resolve().parents[2]


def _load_defects():
    stale = []
    seen = {}
    dup = []
    bad_new = []
    missing_test = []
    missing_file = []
    total = 0
    for mf in sorted(PLANTED.glob("defects_*.py")):
        spec = importlib.util.spec_from_file_location(mf.stem, mf)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        for mid, desc, path, old, new, targs in mod.MUTANTS:
            total += 1
            if old == new:
                bad_new.append(mid)
            source = REPO / path
            if not source.exists():
                missing_file.append((mid, path))
                continue
            count = source.read_text().count(old)
            if count != 1:
                stale.append((mid, mf.name, count, desc))
            for p in targs:
                test_path = p.split("::")[0]
                if not (REPO / test_path).exists():
                    missing_test.append((mid, test_path))
            if mid in seen:
                dup.append((mid, mf.name, seen[mid]))
            seen[mid] = mf.name
    return total, stale, dup, bad_new, missing_test, missing_file


def test_defects_lists_current():
    total, stale, dup, bad_new, missing, missing_file = _load_defects()
    msgs = []
    if stale:
        ids = ", ".join(f"{mid} ({mf}: x{n})" for mid, mf, n, _d in stale)
        msgs.append(f"STALE defects (old text not unique in the file): {ids}")
    if dup:
        ids = ", ".join(f"{mid} in {a} and {b}" for mid, a, b in dup)
        msgs.append(f"DUPLICATE ids across files: {ids}")
    if bad_new:
        ids = ", ".join(bad_new)
        msgs.append(f"defects with old == new: {ids}")
    if missing:
        ids = ", ".join(f"{mid} -> {p}" for mid, p in missing)
        msgs.append(f"missing test paths: {ids}")
    if missing_file:
        ids = ", ".join(f"{mid} -> {p}" for mid, p in missing_file)
        msgs.append(f"missing source files: {ids}")
    if msgs:
        pytest.fail("\n".join(msgs))
    assert total > 0


def test_every_defect_names_a_test():
    total, _stale, _dup, _bad, missing, _missing_file = _load_defects()
    assert not missing
    assert total >= 3
