"""An ``installed`` (non-editable) layout test for the ``newton-mcp`` package.

The dev venv at ``.venv`` is an editable install: a single ``.pth`` file
points at the repo, so ``newton_mcp.__file__`` AND ``manifest_path()``
both resolve under the repo's ``mcp/`` tree.  That hides two bugs:

* an installed server used to look for its profiles next to the Python
  packages (a path that does not exist once files move under
  site-packages), and
* the launcher used to chdir to the caller's directory (an unreadable
  dir crashed the server, a writable one let the caller plant settings).

This test creates a SECOND venv via ``uv`` that is installed NON-editable
and offline from the local repo, with its own ``profiles/`` tree at
``NEWTON_HOME``, and runs every probe in a subprocess that is isolated
from the repo: ``cwd=tmp`` (NOT the repo), ``HOME=<tmp>``,
``NEWTON_HOME=<tmp>/home``, no ``PYTHONPATH``, no ``NEWTON_MANIFEST`` --
so the answer is the answer an end-user would see, never the answer
from the dev venv.

The fixture is module-scoped because the venv install dominates the
wall time of this file.  Skipped when ``uv`` is not on PATH (a few
machines have it pinned under a non-default prefix).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

# the installed manifest the fixture copies into NEWTON_HOME is
# parsed here with the stdlib TOML reader so the test can
# independently cross-check the control ids the subprocess emits
# (the dev venv cannot be trusted for that cross check -- it is
# the editable copy).
if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover -- the project targets >=3.11
    import tomli as tomllib  # type: ignore[no-redef]

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
REPO_PROFILES = REPO_ROOT / "profiles" / "openwrt"


pytestmark = pytest.mark.skipif(
    shutil.which("uv") is None,
    reason="uv not on PATH (this test creates a non-editable venv via uv)",
)


# ---- helpers ----------------------------------------------------------------


def _isolated_env(home: Path) -> dict[str, str]:
    """The smallest possible environment for the subprocess.

    No ``PYTHONPATH`` (so the subprocess cannot fall back to the dev venv
    via sitecustomize), no ``NEWTON_MANIFEST`` (so the override cannot
    rescue us from a broken ``NEWTON_HOME``), no ``NEWTON_STATE_DIR`` (so
    the redactor picks its key from ``HOME/<state-dir>``-shaped paths).
    """
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(home),
        "NEWTON_HOME": str(home),
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "LC_ALL": os.environ.get("LC_ALL", "C.UTF-8"),
    }


def _python_bin(venv: Path) -> str:
    """``<venv>/bin/python`` for the venv uv just created."""
    return str(venv / "bin" / "python")


# ---- the venv fixture ------------------------------------------------------


@pytest.fixture(scope="module")
def installed_venv(tmp_path_factory):
    """A second venv at ``<tmp>/venv`` with ``newton-mcp`` installed NON-editable
    from the repo, plus a copy of the repo's ``profiles/`` at
    ``<tmp>/home/profiles``.

    The install is offline (``--offline``): the cache was warmed by the
    project's own ``uv.lock`` and ``requirements.lock`` and the
    measurement here is well under a second.
    """
    base = tmp_path_factory.mktemp("installed-venv")
    venv = base / "venv"
    home = base / "home"

    # 1) the venv itself, using the same interpreter as the test process
    subprocess.check_call(
        ["uv", "venv", "-q", str(venv), "--python", sys.executable],
    )

    # 2) the NON-editable install.  We install from a *copy* of the repo's
    #    ``mcp/`` directory so a stray ``build/`` / ``dist/`` / ``*.egg-info``
    #    that the build backend emits lands in ``<tmp>/`` instead of under
    #    the tracked tree.
    pkg_src = base / "pkg"
    pkg_src.mkdir()
    shutil.copytree(REPO_ROOT / "mcp", pkg_src / "mcp")

    subprocess.check_call([
        "uv", "pip", "install", "-q", "--offline",
        "--python", _python_bin(venv),
        str(pkg_src / "mcp"),
    ])

    # 3) the home layout with a populated ``profiles/openwrt/``.  We
    #    copy what the launcher ``newton-install`` actually drops in:
    #    manifest + the three tier files.
    profiles_dest = home / "profiles" / "openwrt"
    profiles_dest.mkdir(parents=True)
    for name in ("manifest.toml", "standard.uci", "hardened.uci", "lockdown.uci", "intents.toml"):
        shutil.copy(REPO_PROFILES / name, profiles_dest / name)

    # 4) tidy the copies the wheel build may have produced, so the
    #    repo's tracked tree stays untouched regardless.
    for leftover in (
        pkg_src / "mcp" / "build",
        pkg_src / "mcp" / "dist",
        pkg_src / "build",
        pkg_src / "dist",
    ):
        if leftover.exists():
            shutil.rmtree(leftover)
    for egg_info in list(pkg_src.rglob("*.egg-info")):
        shutil.rmtree(egg_info)

    return {
        "base": base,
        "venv": venv,
        "home": home,
        "pkg_src": pkg_src,
        "profiles": profiles_dest,
    }


# ---- a small runner ---------------------------------------------------------


def _run(venv: Path, env: dict[str, str], cwd: Path, body: str) -> subprocess.CompletedProcess:
    """``python -c <body>`` in the installed venv, with ``env`` and ``cwd``."""
    return subprocess.run(
        [_python_bin(venv), "-c", body],
        env=env,
        cwd=str(cwd),
        capture_output=True,
        text=True,
    )


# ---- Test 1: the package is the installed copy, the manifest comes from NEWTON_HOME -----


def test_installed_package_uses_newton_home_manifest(installed_venv):
    """An installed server is NOT the editable dev copy, and its
    manifest is the one under ``NEWTON_HOME``, not under the venv."""
    base, venv, home = (
        installed_venv["base"], installed_venv["venv"], installed_venv["home"],
    )
    env = _isolated_env(home)
    proc = _run(venv, env, base, (
        "import newton_mcp.probes as p;"
        " print(p.__file__);"
        " print(p.manifest_path())"
    ))
    assert proc.returncode == 0, proc.stderr
    probes_file, manifest = proc.stdout.strip().splitlines()
    probes_file = Path(probes_file)
    manifest = Path(manifest)

    assert probes_file.is_relative_to(venv), (
        f"newton_mcp.probes resolves under the EDITABLE repo, not the venv: "
        f"{probes_file} (venv={venv}). The dev .pth file leaked into the "
        f"subprocess's import system."
    )
    expected = home / "profiles" / "openwrt" / "manifest.toml"
    assert manifest == expected, (
        f"manifest_path() returned {manifest}, expected {expected}. An "
        f"installed server found the wrong profiles tree (the old bug)."
    )
    assert manifest.is_file(), (
        f"manifest {manifest} does not exist on disk; the install did not "
        f"copy the profiles next to the installed package (NEWTON_HOME)."
    )


# ---- Test 2: the manifest parses AND its sibling tier files are present -----


def test_installed_manifest_loads_and_tier_files_are_under_home(installed_venv):
    """``probes._load_controls`` parses our manifest; the three tier
    files sit next to it.  Without this, even the read-side paths
    (``newton_list_tiers``) blow up on a real install."""
    base, venv, home = (
        installed_venv["base"], installed_venv["venv"], installed_venv["home"],
    )
    env = _isolated_env(home)
    proc = _run(venv, env, base, (
        "import newton_mcp.probes as p;"
        " m = p.manifest_path();"
        " controls = p._load_controls(m);"
        " print(m);"
        " print(len(controls));"
        " print(','.join(sorted((m.parent / t).name for t in "
        "    ('standard.uci', 'hardened.uci', 'lockdown.uci')"
        "    if (m.parent / t).is_file())))"
    ))
    assert proc.returncode == 0, proc.stderr
    manifest_line, count_line, siblings_line = proc.stdout.strip().splitlines()
    manifest = Path(manifest_line)
    assert int(count_line) > 0, (
        f"_load_controls returned no controls from {manifest}; the "
        f"installed copy is loading the wrong manifest."
    )
    siblings = set(siblings_line.split(",")) if siblings_line else set()
    assert siblings == {"standard.uci", "hardened.uci", "lockdown.uci"}, (
        f"tier files missing next to the manifest at {manifest}: got "
        f"{sorted(siblings)}; a real install would 404 the first time the "
        f"operator asks ``newton_list_tiers`` for them."
    )
    # and assert from the test side too, in case the subprocess
    # happened to be inside a profile copy that grew extras
    for name in ("standard.uci", "hardened.uci", "lockdown.uci"):
        assert (manifest.parent / name).is_file(), f"{name} missing next to {manifest}"


# ---- Test 3: the user-visible path -- ``list_tiers`` end-to-end -------------


def test_installed_list_tiers_returns_three_tiers(installed_venv):
    """``newton_mcp.tiers.list_tiers`` (what the ``newton_list_tiers`` tool
    calls) succeeds in the installed venv and reports all three tiers.

    No router, no inventory, no state dir: the tool is read-only and
    just reads the .uci files next to the manifest.
    """
    base, venv, home = (
        installed_venv["base"], installed_venv["venv"], installed_venv["home"],
    )
    env = _isolated_env(home)
    proc = _run(venv, env, base, (
        "from newton_mcp.tiers import TIER_NAMES, list_tiers;"
        " out = list_tiers();"
        " print(','.join(sorted(t['tier'] for t in out)));"
        " print(sum(t['batches'] for t in out));"
        " print(','.join(TIER_NAMES))"
    ))
    assert proc.returncode == 0, proc.stderr
    got, batches_line, expected = proc.stdout.strip().splitlines()
    assert set(got.split(",")) == set(expected.split(",")), (
        f"installed list_tiers returned {got!r}, expected exactly the "
        f"three tier names {expected!r}"
    )
    assert int(batches_line) > 0, (
        "installed list_tiers produced zero batches -- the tier files "
        "under NEWTON_HOME were not picked up."
    )


# ---- Test 4 (optional): the OLD failure mode is GONE -------------------------


def test_installed_no_home_does_not_point_into_the_venv(installed_venv):
    """Without ``NEWTON_HOME``, ``manifest_path()`` falls back to the
    package-relative path.  For an INSTALLED package that path is
    ``<venv>/lib/python3.X/profiles/openwrt/manifest.toml`` -- a
    directory that does not exist and never will (an installed copy
    has no ``profiles/`` tree under site-packages).

    This test exists to document the old failure mode: any future
    refactor that re-introduces a hard-coded ``Path(__file__).parents[2]``
    path will be caught by this assertion.  The path it returns is the
    EXACT path the bug produced; we just assert we are still honest
    about where it points.
    """
    base, venv, home = (
        installed_venv["base"], installed_venv["venv"], installed_venv["home"],
    )
    env = _isolated_env(home)
    env.pop("NEWTON_HOME", None)
    proc = _run(venv, env, base, (
        "import sys, newton_mcp.probes as p;"
        " m = p.manifest_path();"
        " print(m);"
        " print(sys.version_info.major, sys.version_info.minor)"
    ))
    assert proc.returncode == 0, proc.stderr
    manifest_line, pyver_line = proc.stdout.strip().splitlines()
    manifest = Path(manifest_line)
    pyver = pyver_line.split()
    pyglob = f"python{pyver[0]}.{pyver[1]}"

    expected = venv / "lib" / pyglob / "profiles" / "openwrt" / "manifest.toml"
    assert manifest == expected, (
        f"without NEWTON_HOME manifest_path() returned {manifest}, not "
        f"the venv-relative path {expected}. Either the launcher now sets "
        f"NEWTON_HOME for the user (good news -- then update this test) "
        f"or another fallback changed; the old bug path is gone either way."
    )
    assert not manifest.is_file(), (
        f"{manifest} exists in the venv -- a real install does not put "
        f"profiles under site-packages, so this would have meant the "
        f"build tool copied them in by accident."
    )


def test_installed_guided_recommend_finds_intents_toml(installed_venv):
    """The installed server's ``newton_mcp.guided.recommend`` resolves
    the guest segment intent via ``profiles/openwrt/intents.toml`` (both
    the legacy ``guest_network=yes`` and the v2 ``segments=['guest']``
    paths end up recommending OW-ZONE-01); proving the launcher ships
    ``intents.toml`` next to the manifest in a real install.
    """
    base, venv, home = (
        installed_venv["base"], installed_venv["venv"], installed_venv["home"],
    )
    env = _isolated_env(home)
    proc = _run(venv, env, base, (
        "import json;"
        "import newton_mcp.guided as g;"
        "r1 = g.recommend({'strictness': 'normal', 'guest_network': 'yes'});"
        "r2 = g.recommend({'strictness': 'normal', 'segments': ['guest']});"
        "ids1 = sorted(r['control_id'] for r in r1['recommendations']);"
        "ids2 = sorted(r['control_id'] for r in r2['recommendations']);"
        "print(' '.join(ids1));"
        "print(' '.join(ids2))"
    ))
    assert proc.returncode == 0, proc.stderr
    ids1_line, ids2_line = proc.stdout.strip().splitlines()
    ids1 = ids1_line.split() if ids1_line else []
    ids2 = ids2_line.split() if ids2_line else []
    assert "OW-ZONE-01" in ids1, ids1
    assert "OW-ZONE-01" in ids2, ids2


# ---- Test 5: the guided-setup report end-to-end ----------------------------


def test_installed_guided_recommend_builds_report_from_home_manifest(installed_venv):
    """``newton_mcp.guided`` is shipped in the NON-editable install, and
    the core path of ``newton_guided_recommend`` (``guided.recommend``)
    reads the manifest from ``NEWTON_HOME``, derives statuses from the
    real controls and tier files, and emits a ``guided_setup_report``
    whose recommendations name at least one manifest control id that
    exists in the loaded manifest.

    Failure modes the assertion catches:

    * ``newton_mcp.guided`` missing from the installed package ->
      ``ModuleNotFoundError: No module named 'newton_mcp.guided'`` and
      ``proc.returncode != 0`` (the subprocess can't even start).
    * Manifest missing under ``NEWTON_HOME`` -> ``recommend`` loads
      controls via ``probes._load_controls(probes.manifest_path())``
      which raises ``_ManifestError("manifest not found: ...")``;
      ``proc.returncode != 0``.
    * Wrong manifest path silently resolved (e.g. the venv-relative
      fallback) -> ``_find_entry`` returns None for every mapping and
      ``report['recommendations']`` carries ``status == 'gap'`` /
      ``"not in manifest"``; ``rec_ids - manifest_ids`` is non-empty
      and the ``matched`` assertion catches it.

    The fixed answer set is the minimum that exercises the documented
    paths and crosses the manifest boundary on a non-empty set of
    control ids:

    * ``strictness=stricter`` -- picks the tier through the question
      table (not via a mapping), so the report key ``tier`` is filled.
    * ``iot_network=yes``     -- hardens -> ``OW-ZONE-02``.
    * ``dnssec=yes``          -- opt-in -> ``OW-DNS-04``.
    * ``ipv6_off=unsure``     -- ``no_op`` -> no recommendation; the
                                  branch is exercised without polluting
                                  the id set the smoke check inspects.
    * ``fw_update_check=no``  -- ``no_op`` -> no recommendation.
    """
    base, venv, home = (
        installed_venv["base"], installed_venv["venv"], installed_venv["home"],
    )
    env = _isolated_env(home)
    proc = _run(venv, env, base, (
        # prove we are importing from the installed package, not the dev
        # venv that pytest itself runs under.  ``g.__file__`` MUST live
        # under the venv we created; if a stray .pth or sys.path entry
        # pulled the dev copy in, the assertion catches it.
        "import newton_mcp.guided as g;"
        " import newton_mcp.probes as p;"
        " guided_file = g.__file__;"
        " manifest = p.manifest_path();"
        # reload the manifest from disk the same way the test side does,
        # via the file NEWTON_HOME points at.  Anything else (e.g.
        # NEWTON_MANIFEST) was scrubbed by _isolated_env.
        " controls = p._load_controls(manifest);"
        " manifest_ids = {c['id'] for c in controls};"
        # the (question, answer) set: see the docstring for why each
        # entry is in the set.
        " report = g.recommend({"
        "   'strictness': 'stricter',"
        "   'iot_network': 'yes',"
        "   'dnssec': 'yes',"
        "   'ipv6_off': 'unsure',"
        "   'fw_update_check': 'no',"
        " });"
        " rec_ids = sorted({r['control_id'] for r in report['recommendations']});"
        " matched = sorted(set(rec_ids) & manifest_ids);"
        # structured stdout so the test side can parse failures cleanly.
        " print(guided_file);"
        " print(manifest);"
        " print(report['report']);"
        " print(report['tier']);"
        " print(len(report['recommendations']));"
        " print(','.join(rec_ids));"
        " print(','.join(matched));"
        " print(len(manifest_ids))"
    ))
    assert proc.returncode == 0, (
        f"installed interpreter crashed while running the guided path; "
        f"the most common causes are (a) guided.py missing from the "
        f"installed package, (b) manifest not under NEWTON_HOME, or "
        f"(c) tier files not under NEWTON_HOME.  stderr:\n{proc.stderr}"
    )
    out = proc.stdout.strip().splitlines()
    guided_file, manifest_line, report_kind, tier, nrecs, rec_ids, matched, nids = out

    # (1) ``newton_mcp.guided`` is resolved FROM the installed venv,
    # not from the editable dev copy.  If a stray PYTHONPATH or .pth
    # file pulled the repo into the subprocess the rest of the test
    # would silently answer from the repo and miss the bug.
    guided_path = Path(guided_file)
    assert guided_path.is_relative_to(venv), (
        f"newton_mcp.guided resolves under the EDITABLE repo, not the "
        f"installed venv: {guided_path} (venv={venv}). The dev .pth "
        f"file leaked into the subprocess's import system."
    )

    # (2) the manifest path is NEWTON_HOME, not the venv fallback.
    manifest = Path(manifest_line)
    expected_manifest = home / "profiles" / "openwrt" / "manifest.toml"
    assert manifest == expected_manifest, (
        f"guided.recommend() loaded manifest {manifest}, expected "
        f"{expected_manifest}. An installed server found the wrong "
        f"profiles tree; status derivation would be silently wrong."
    )

    # (3) the report is well-shaped.
    assert report_kind == "guided_setup_report", (
        f"installed guided.recommend returned a report whose ``report`` "
        f"key was {report_kind!r}, expected 'guided_setup_report'."
    )
    assert tier == "hardened", (
        f"installed guided.recommend returned tier={tier!r}, expected "
        f"'hardened' (the tier the strictness=stricter answer in the fixed answer set)."
    )

    # (4) at least one named recommendation control id exists in the
    # manifest loaded from disk.  This is the SMOKE: any path through
    # guided.recommend that loses the manifest (wrong path, empty
    # controls, NEWTON_MANIFEST override bypassing the file the test
    # just re-read) collapses ``matched`` to empty.
    nrecs_int = int(nrecs)
    assert nrecs_int > 0, (
        f"installed guided.recommend produced zero recommendations "
        f"for a fixed answer set that picks two control ids; the "
        f"branch that emits recommendations (or the strictness / "
        f"_find_entry paths) is gone."
    )
    # Re-read the manifest from disk on the TEST side.  The dev
    # venv's manifest is editable and could answer from a different
    # .toml than the one the install copied next to NEWTON_HOME; we
    # cross-check only against the file the fixture put there.
    home_manifest_data = tomllib.loads(
        expected_manifest.read_text(encoding="utf-8")
    )
    home_manifest_ids = {
        c["id"] for c in home_manifest_data.get("control", [])
    }
    rec_id_set = set(rec_ids.split(",")) if rec_ids else set()
    matched_set = set(matched.split(",")) if matched else set()
    assert matched_set, (
        f"installed guided.recommend emitted control ids "
        f"{sorted(rec_id_set)!r}, none of which exist in the manifest "
        f"loaded from {expected_manifest} ({len(home_manifest_ids)} "
        f"ids). The control ids probably come from a different "
        f"manifest than the one on disk -- a real install would plan "
        f"against the wrong set."
    )
    # and, for the same reason, every emitted id must exist in the
    # on-disk manifest.  ``matched`` is reported but ``rec_id_set`` is
    # the full set; the difference is what's missing.
    missing = rec_id_set - home_manifest_ids
    assert not missing, (
        f"installed guided.recommend emitted control ids that the "
        f"manifest at {expected_manifest} does NOT contain: "
        f"{sorted(missing)}. The recommendation table references ids "
        f"the manifest lost."
    )
