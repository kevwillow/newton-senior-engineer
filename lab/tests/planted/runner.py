#!/usr/bin/env python3
"""Planted-defect runner for the lab helper (part of the repo at
lab/tests/planted/).

usage: python3 lab/tests/planted/runner.py <repo root> [--only IDS] [--out FILE]

Each defects_*.py beside this script defines MUTANTS = [(id, description,
path, old, new, [pytest args])].  For each defect this runner copies the lab
tree into a scratch dir, checks `old` occurs EXACTLY once (else STALE),
replaces it, and runs `pytest -x` with the listed test arguments there.
Prints one line per defect: `ID KILLED|SURVIVED|STALE|ERROR first-failing-test
description`.

The full run is slow (seconds per defect); it is intentionally separate from
the normal suite.  The fast staleness check lives in
lab/tests/test_planted_defects_current.py.
"""
import importlib.util
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

runner = Path(__file__).resolve()
wt = Path(sys.argv[1]).resolve()

only = None
out = None
files = None
args = sys.argv[2:]
while args:
    a = args.pop(0)
    if a == "--only":
        only = set(args.pop(0).split(","))
    elif a == "--out":
        out = args.pop(0)
    elif a == "--files":
        files = args.pop(0).split(",")

if files:
    mfiles = [runner.parent / f for f in files]
else:
    mfiles = sorted(runner.parent.glob("defects_*.py"))

mods = []
for mfile in mfiles:
    spec = importlib.util.spec_from_file_location(mfile.stem, mfile)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mods.append(mod)

venv_py = wt / ".venv/bin/python"
py = str(venv_py) if venv_py.exists() else sys.executable
lines = []
tmp = Path(tempfile.mkdtemp(prefix="lab-mutate."))
try:
    for mod in mods:
        for mid, desc, path, old, new, targs in mod.MUTANTS:
            if only and mid not in only:
                continue
            if old == new:
                line = f"{mid}\tSTALE\t(old == new)\t{desc}"
                print(line, flush=True)
                lines.append(line)
                continue
            source = wt / path
            text = source.read_text()
            if text.count(old) != 1:
                line = f"{mid}\tSTALE\t(old text occurs {text.count(old)} times)\t{desc}"
                print(line, flush=True)
                lines.append(line)
                continue
            scratch = tmp / mid
            scratch.mkdir(parents=True)
            # The lab tree is copied whole: the mutant must not touch the
            # working tree.  The results and the caches are not copied.
            shutil.copytree(wt / "lab", scratch / "lab",
                            ignore=shutil.ignore_patterns(".results",
                                                          "__pycache__",
                                                          "*.pyc"))
            target = scratch / path
            target.write_text(text.replace(old, new))
            env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
            cmd = [py, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-x",
                   "--tb=no", "-rf", *targs]
            r = subprocess.run(cmd, cwd=scratch, env=env, capture_output=True,
                               text=True, timeout=1800)
            failed = re.findall(r"^FAILED (\S+)", r.stdout, re.M)
            if r.returncode == 0:
                line = f"{mid}\tSURVIVED\t{desc}"
            elif failed:
                line = f"{mid}\tKILLED\t{failed[0]}\t{desc}"
            else:
                tail = r.stdout.strip().splitlines()[-1] if r.stdout.strip() else ""
                line = f"{mid}\tERROR\trc={r.returncode} {tail}\t{desc}"
            print(line, flush=True)
            lines.append(line)
finally:
    shutil.rmtree(tmp, ignore_errors=True)
if out:
    Path(out).write_text("\n".join(lines) + "\n")
