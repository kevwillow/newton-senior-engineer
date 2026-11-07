#!/usr/bin/env python3
"""Planted-defect runner (part of the repo at tests/planted/).

usage: python3 tests/planted/runner.py <repo root> [--only IDS] [--out FILE] [--files defects_a.py,defects_b.py]

Each defects_*.py beside this script defines MUTANTS = [(id, description, old, new, [pytest args])]
plus a variable B/T/S holding test paths relative to the repo root. For each defect this runner
copies the program to a scratch dir, checks `old` occurs EXACTLY once (else STALE), replaces it,
and runs `pytest -x` with NEWTON_ROUTER_PROGRAM=<scratch copy> on the listed test arguments. Prints
one line per defect: `ID KILLED|SURVIVED|STALE|ERROR first-failing-test description`.

The full run is slow (minutes per defect); it is intentionally separate from the normal suite.
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

prog = wt / "device/openwrt/newton-router/newton-router"
text = prog.read_text()
venv_py = wt / ".venv/bin/python"
py = str(venv_py) if venv_py.exists() else sys.executable
lines = []
tmp = Path(tempfile.mkdtemp(prefix="r1-mutate."))
try:
    for mod in mods:
        for mid, desc, old, new, targs in mod.MUTANTS:
            if only and mid not in only:
                continue
            if old == new:
                line = f"{mid}\tSTALE\t(old == new)\t{desc}"
                print(line, flush=True)
                lines.append(line)
                continue
            if text.count(old) != 1:
                line = f"{mid}\tSTALE\t(old text occurs {text.count(old)} times)\t{desc}"
                print(line, flush=True)
                lines.append(line)
                continue
            scratch = tmp / mid
            scratch.mkdir()
            mp = scratch / "newton-router"
            mp.write_text(text.replace(old, new))
            mp.chmod(0o755)
            env = dict(os.environ, NEWTON_ROUTER_PROGRAM=str(mp), PYTHONDONTWRITEBYTECODE="1")
            cmd = [py, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-x", "--tb=no", "-rf", *targs]
            r = subprocess.run(cmd, cwd=wt, env=env, capture_output=True, text=True, timeout=1800)
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
