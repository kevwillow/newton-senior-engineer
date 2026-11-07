"""F2: mcp/requirements.lock must cover everything mcp/uv.lock says newton-mcp needs, with hashes.

The installer runs `pip install --require-hashes --no-deps -r mcp/requirements.lock` as root, so a package that is missing
from the lock would not be installed and a package that is listed without a hash (or with a hash uv.lock does not know)
would make root run something nobody pinned.  This test reads both files and compares them; it needs no network.
"""
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LOCK = ROOT / "mcp" / "requirements.lock"
UV_LOCK = ROOT / "mcp" / "uv.lock"
PYPROJECT = ROOT / "mcp" / "pyproject.toml"

# hatchling (the build backend named in pyproject) and what hatchling 1.32 itself requires.  uv does not lock
# [build-system].requires, so these cannot be derived from uv.lock; the lock holds them because the installer builds the
# package with --no-build-isolation and therefore needs the backend inside the venv.
BUILD_CLOSURE = {"hatchling", "packaging", "pathspec", "pluggy", "tomlkit", "trove-classifiers"}


def norm(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def uv_packages():
    data = tomllib.loads(UV_LOCK.read_text())
    return {norm(p["name"]): p for p in data["package"]}


def runtime_closure(packages):
    """Names reachable from newton-mcp's own `dependencies` (every marker; an `extra` on an edge pulls in that
    package's optional dependencies for the extra)."""
    seen = set()
    todo = [(norm(d["name"]), tuple(d.get("extra", ()))) for d in packages["newton-mcp"].get("dependencies", [])]
    while todo:
        name, extras = todo.pop()
        first_visit = name not in seen
        seen.add(name)
        package = packages[name]
        if first_visit:
            todo.extend((norm(d["name"]), tuple(d.get("extra", ()))) for d in package.get("dependencies", []))
        for extra in extras:
            for dep in package.get("optional-dependencies", {}).get(extra, []):
                dep_name = norm(dep["name"])
                if dep_name not in seen:
                    todo.append((dep_name, tuple(dep.get("extra", ()))))
    return seen


def parse_lock():
    """{name: (version, marker, [sha256 hex, ...])} from requirements.lock; every logical line must be a pinned
    requirement followed only by --hash=sha256 options."""
    logical = []
    pending = ""
    for raw in LOCK.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            assert not pending, f"comment or blank line inside a continued requirement: {raw!r}"
            continue
        pending += " " + line.rstrip("\\").strip() if pending else line.rstrip("\\").strip()
        if not line.endswith("\\"):
            logical.append(pending)
            pending = ""
    assert not pending, "requirements.lock ends inside a continued line"
    entries = {}
    for text in logical:
        match = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;]+)(?:\s*;\s*(.*?))?((?:\s+--hash=sha256:[0-9a-f]{64})+)", text)
        assert match, f"not a pinned requirement with sha256 hashes: {text!r}"
        name = norm(match.group(1))
        assert name not in entries, f"{name} is listed twice"
        hashes = re.findall(r"--hash=sha256:([0-9a-f]{64})", match.group(4))
        assert len(set(hashes)) == len(hashes), f"{name} repeats a hash"
        entries[name] = (match.group(2), (match.group(3) or "").strip(), hashes)
    return entries


def test_every_runtime_package_of_uv_lock_is_pinned_with_its_wheel_hashes_f2():
    packages = uv_packages()
    entries = parse_lock()
    closure = runtime_closure(packages)
    assert "mcp" in closure and "cryptography" in closure, "closure walk lost the extra edge or the root"
    for name in sorted(closure):
        assert name in entries, f"{name} is in the uv.lock runtime closure but not in requirements.lock"
        version, _marker, hashes = entries[name]
        assert version == packages[name]["version"], f"{name}: lock pins {version}, uv.lock has {packages[name]['version']}"
        wheel_hashes = {w["hash"].split(":", 1)[1] for w in packages[name].get("wheels", [])}
        assert wheel_hashes, f"{name} has no wheels in uv.lock; a source build as root is not allowed"
        assert hashes, f"{name} has no hash"
        assert set(hashes) <= wheel_hashes, f"{name}: hashes not found among uv.lock's wheel hashes: {set(hashes) - wheel_hashes}"


def test_requirements_lock_holds_no_source_distribution_hash_f2():
    packages = uv_packages()
    entries = parse_lock()
    for name, (_version, _marker, hashes) in entries.items():
        package = packages.get(name)
        if package and "sdist" in package:
            sdist_hash = package["sdist"]["hash"].split(":", 1)[1]
            assert sdist_hash not in hashes, f"{name}: the sdist hash is listed, so pip could build it from source as root"


def test_build_backend_and_its_requirements_are_pinned_with_hashes_f2():
    backend = {norm(r.split(">=", 1)[0].split("==", 1)[0].strip()) for r in tomllib.loads(PYPROJECT.read_text())["build-system"]["requires"]}
    assert backend == {"hatchling"}, "the build backend changed: update BUILD_CLOSURE and requirements.lock together"
    entries = parse_lock()
    for name in sorted(BUILD_CLOSURE):
        assert name in entries, f"build requirement {name} is missing from requirements.lock"
        assert entries[name][2], f"{name} has no hash"


def test_requirements_lock_contains_nothing_beyond_the_two_closures_f2():
    entries = parse_lock()
    expected = runtime_closure(uv_packages()) | BUILD_CLOSURE
    assert set(entries) == expected, (
        f"unexpected: {sorted(set(entries) - expected)}; missing: {sorted(expected - set(entries))}"
    )


def test_pytest_and_other_test_only_packages_are_not_installed_as_root_f2():
    assert not ({"pytest", "iniconfig", "pygments"} & set(parse_lock())), "test-extra packages must not be in the root install set"
