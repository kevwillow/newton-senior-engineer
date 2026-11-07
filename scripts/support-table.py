#!/usr/bin/env python3
"""Generate docs/SUPPORT.md from the recorded lab runs (ROADMAP 10c).

Inputs, all committed: docs/support/platforms.toml (what each platform is, its undo type, its seven
scenario shapes, what is untested) and docs/support/runs.toml (one [[run]] per recorded lab run).
`record` appends a run from the lab runner's results file; only scenario names and counts are kept,
never addresses, VM ids or host names. `render` writes the table; `check` fails when the committed
table is not what `render` would write now.

  support-table.py record --results FILE --platform P --version V --target TEXT --kind virtual|hardware
  support-table.py render [--out docs/SUPPORT.md]
  support-table.py check  [--out docs/SUPPORT.md]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tomllib
from pathlib import Path
from typing import Any

UNDO_TYPES = ("on-router guard", "commit-confirm", "reboot", "timer")
KINDS = ("virtual", "hardware")
_ADDRESS = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")
_VERSION = re.compile(r"^[0-9A-Za-z._+-]{1,32}$")


class SupportError(ValueError):
    """The data files do not describe a valid, honest table."""


def repo_scenario_names(repo: Path) -> set[str]:
    """Every scenario name under lab/scenarios*/ (the `name` key of each TOML file), plus the vendor lab shape ids."""
    names: set[str] = set()
    for path in sorted((repo / "lab").glob("scenarios*/**/*.toml")):
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise SupportError(f"cannot read scenario file {path.name}: {exc}") from exc
        if isinstance(data.get("name"), str):
            names.add(data["name"])
    vendor = repo / "lab" / "vendor-shapes.toml"
    if vendor.exists():
        try:
            shapes = tomllib.loads(vendor.read_text(encoding="utf-8")).get("shapes", {})
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise SupportError(f"cannot read {vendor.name}: {exc}") from exc
        names.update(k for k in shapes if isinstance(k, str))
    return names


def _text(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 200 or any(ord(c) < 0x20 for c in value):
        raise SupportError(f"{what} must be a short single-line text")
    if _ADDRESS.search(value):
        raise SupportError(f"{what} must not contain an address")
    return value


def _names(value: Any, what: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise SupportError(f"{what} must be a list of scenario names")
    return list(value)


def load(platforms_path: Path, runs_path: Path, scenario_names: set[str]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    raw_p = tomllib.loads(Path(platforms_path).read_text(encoding="utf-8")).get("platforms", {})
    if not isinstance(raw_p, dict) or not raw_p:
        raise SupportError("platforms.toml has no platforms")
    platforms: dict[str, Any] = {}
    for key, entry in raw_p.items():
        shapes = entry.get("shape")
        if not isinstance(shapes, list) or not shapes:
            raise SupportError(f"{key}: no shapes")
        seen: set[str] = set()
        for shape in shapes:
            sid = _text(shape.get("id"), f"{key} shape id")
            if sid in seen:
                raise SupportError(f"{key}: duplicate shape id {sid}")
            seen.add(sid)
            _text(shape.get("name"), f"{key} shape {sid} name")
            for name in _names(shape.get("scenarios"), f"{key} shape {sid} scenarios"):
                if name not in scenario_names:
                    raise SupportError(f"{key} shape {sid}: scenario {name} does not exist under lab/scenarios*")
        # The access modes of the platform (ADR-021 point 1): a platform
        # with one way in has none, a platform with two (installed and
        # no-install) has both.  The table shows which mode a recorded
        # run was made in: support is gated on the capabilities detected
        # at setup, not on a claim.
        access_modes: list[dict[str, Any]] = []
        seen_modes: set[str] = set()
        for mode in entry.get("access_mode", []) or []:
            if not isinstance(mode, dict):
                raise SupportError(f"{key}: access_mode must be a table")
            mid = mode.get("id")
            if not isinstance(mid, str) or not mid.strip() or len(mid) > 40:
                raise SupportError(f"{key}: access mode id must be a short text")
            if mid in seen_modes:
                raise SupportError(f"{key}: duplicate access mode {mid}")
            seen_modes.add(mid)
            name = mode.get("name")
            _text(name, f"{key} access mode {mid} name")
            mode_undo = mode.get("undo")
            if mode_undo is not None and mode_undo not in UNDO_TYPES:
                raise SupportError(
                    f"{key} access mode {mid}: undo type must be one of "
                    f"{', '.join(UNDO_TYPES)}")
            mode_release = mode.get("release")
            if mode_release is not None:
                mode_release = _text(mode_release, f"{key} access mode {mid} release")
            undo_note = mode.get("undo_note")
            if undo_note is not None:
                undo_note = _text(undo_note, f"{key} access mode {mid} undo_note")
            access_modes.append({"id": mid, "name": name,
                                  "release": mode_release, "undo": mode_undo,
                                  "undo_note": undo_note})
        if access_modes:
            # The release and the undo type belong to the access mode:
            # the no-install mode is not the installed one (its undo is
            # OpenWrt's own timer, which lives in RAM).  A platform that
            # has modes must not carry a second copy of them.
            if entry.get("release") is not None or entry.get("undo") is not None:
                raise SupportError(
                    f"{key}: the release and the undo type belong to the "
                    "access mode, not to the platform: remove them here")
            for mode in access_modes:
                if not mode["release"] or not mode["undo"]:
                    raise SupportError(
                        f"{key}: access mode {mode['id']} needs a release and "
                        "an undo type")
            release = ""
            undo = ""
        else:
            release = _text(entry.get("release"), f"{key} release")
            undo = entry.get("undo")
            if undo not in UNDO_TYPES:
                raise SupportError(
                    f"{key}: undo type must be one of {', '.join(UNDO_TYPES)}")
        platforms[key] = {
            "label": _text(entry.get("label"), f"{key} label"),
            "release": release,
            "undo": undo,
            "untested": [_text(u, f"{key} untested") for u in entry.get("untested", [])],
            "shapes": shapes,
            "access_modes": access_modes,
        }
    runs = tomllib.loads(Path(runs_path).read_text(encoding="utf-8")).get("run", [])
    if not isinstance(runs, list):
        raise SupportError("runs.toml: run must be a list of tables")
    for run in runs:
        plat = run.get("platform")
        if plat not in platforms:
            raise SupportError(f"run names platform {plat!r}, which platforms.toml does not define")
        _text(run.get("target"), "run target")
        if not isinstance(run.get("version"), str) or not _VERSION.fullmatch(run["version"]):
            raise SupportError("run version must be a plain version string")
        if run.get("kind") not in KINDS:
            raise SupportError(f"run kind must be one of {', '.join(KINDS)}")
        if not isinstance(run.get("date"), str) or not _DATE.fullmatch(run["date"]):
            raise SupportError("run date must be YYYY-MM-DD")
        if not isinstance(run.get("results_sha256"), str) or not _SHA.fullmatch(run["results_sha256"]):
            raise SupportError("run results_sha256 must be 64 hex digits")
        allowed = {n for s in platforms[plat]["shapes"] for n in s["scenarios"]}
        for field in ("shapes_passed", "shapes_failed"):
            for name in _names(run.get(field), field):
                if name not in allowed:
                    raise SupportError(f"run {field}: scenario {name} is not in a {plat} shape")
        for field in ("scenarios_passed", "scenarios_failed"):
            if isinstance(run.get(field), bool) or not isinstance(run.get(field), int) or run[field] < 0:
                raise SupportError(f"run {field} must be a count")
        modes = platforms[plat]["access_modes"]
        access = run.get("access")
        if modes:
            if not isinstance(access, str) or access not in {m["id"] for m in modes}:
                raise SupportError(
                    "run access must be one of %s" % ", ".join(m["id"] for m in modes)
                )
        elif access is not None:
            raise SupportError("run access is only for a platform with access modes")
    return platforms, runs


def _state(shape: dict[str, Any], run: dict[str, Any]) -> str:
    names = set(shape["scenarios"])
    if names & set(run["shapes_failed"]):
        return "FAIL"
    if names & set(run["shapes_passed"]):
        return "pass"
    return "not run"


def render(platforms: dict[str, Any], runs: list[dict[str, Any]]) -> str:
    out = [
        "# Support table",
        "",
        "Generated by `scripts/support-table.py` from `docs/support/platforms.toml` and `docs/support/runs.toml`; do not edit by hand.",
        "A test fails when this file is stale. \"Supported\" means all seven shapes pass on the target named in the row.",
        "`pass` is a recorded lab run, `FAIL` a recorded failure, `not run` a shape that run did not cover.",
        "A platform with no recorded run is untested, whatever its code says.",
        "The access-mode column names the mode a recorded run was made in, with the release and",
        "the undo type of that mode: the no-install mode is not the installed one. Support is",
        "gated on the capabilities detected at setup, not on a claim.",
        "The mode comes from what the run measured (the receipts of its scenarios); a hand-edited",
        "results file is out of scope: the operator is trusted and the lab is private.",
        "",
    ]
    for key in platforms:
        plat = platforms[key]
        shapes = plat["shapes"]
        modes = plat["access_modes"]
        out += [
            f"## {plat['label']}",
            "",
        ]
        if modes:
            out += [
                "Access modes: "
                + "; ".join(f"{m['id']} ({m['name']})" for m in modes) + ".",
                "",
            ]
        else:
            out += [
                f"Release: {plat['release']}. Undo type: {plat['undo']}.",
                "",
            ]
        out += [
            "Shapes: " + "; ".join(f"{s['id']} = {s['name']}" for s in shapes) + ".",
            "",
            "| Platform | Version | Target | "
            + ("Access | Release | Undo | " if modes else "")
            + " | ".join(s["id"] for s in shapes) + " | Run date |",
            "|---|---|---|" + ("---|---|---|" if modes else "") + "---|" * len(shapes) + "---|",
        ]
        mine = [r for r in runs if r["platform"] == key]
        latest: dict[tuple[str, str, str], dict[str, Any]] = {}
        for run in sorted(mine, key=lambda r: r["date"]):
            latest[(run["version"], run["target"], run.get("access", ""))] = run
        if modes:
            for mode in modes:
                # the release and the undo of the row are the ones of
                # its mode: the no-install mode is release 1.1 with
                # OpenWrt's own undo timer, not the installed guard
                undo = mode["undo"]
                if mode["undo_note"]:
                    undo = f"{undo} ({mode['undo_note']})"
                rows = [(k, r) for k, r in latest.items() if k[2] == mode["id"]]
                if not rows:
                    out.append(
                        f"| {plat['label']} | - | no recorded run (untested) | {mode['id']} | "
                        f"{mode['release']} | {undo} | "
                        + " | ".join("not run" for _ in shapes) + " | - |"
                    )
                    continue
                for (version, target, _mode), run in sorted(
                        rows, key=lambda kv: (kv[1]["date"], kv[0])):
                    out.append(
                        f"| {plat['label']} | {version} | {target} ({run['kind']}) | {mode['id']} | "
                        f"{mode['release']} | {undo} | "
                        + " | ".join(_state(s, run) for s in shapes)
                        + f" | {run['date']} |"
                    )
        else:
            if not latest:
                out.append(f"| {plat['label']} | - | no recorded run (untested) | " + " | ".join("not run" for _ in shapes) + " | - |")
            for (version, target, _mode), run in sorted(latest.items(), key=lambda kv: (kv[1]["date"], kv[0])):
                out.append(
                    f"| {plat['label']} | {version} | {target} ({run['kind']}) | "
                    + " | ".join(_state(s, run) for s in shapes)
                    + f" | {run['date']} |"
                )
        out += ["", "Untested: " + ("; ".join(plat["untested"]) if plat["untested"] else "nothing listed") + ".", ""]
    return "\n".join(out)


def _toml_str(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def results_access_fact(parsed: dict[str, Any]) -> str:
    """The access mode of a recorded run, from the evidence the runner
    wrote (ADR-021 point 1).

    The mode is what the run measured, not what anybody typed: the
    scenarios that exercised a transport carry the mode it was, they
    are all the same mode, the run's own fact says the same, and the
    device facts agree.  A scenario that exercised no transport
    carries no fact at all.  A results file with no fact cannot back a
    label, so a flag on its own is refused.
    """
    scenarios = parsed.get("scenarios")
    if not isinstance(scenarios, list) or not scenarios:
        raise SupportError(
            "the results carry no scenario records; the access mode cannot "
            "be taken from a flag")
    modes: set[str] = set()
    for scenario in scenarios:
        if not isinstance(scenario, dict):
            continue
        mode = scenario.get("access")
        if mode is None:
            # the scenario exercised no transport: it carries no fact
            continue
        if mode not in ("installed", "no-install"):
            raise SupportError(
                "a scenario record carries no access fact; the access mode "
                "cannot be taken from a flag")
        modes.add(mode)
    if not modes:
        raise SupportError(
            "the results carry no access fact (no scenario exercised a "
            "transport); the access mode cannot be taken from a flag")
    if len(modes) > 1:
        raise SupportError(
            "the results mix the access modes %s" % ", ".join(sorted(modes)))
    fact = modes.pop()
    recorded = parsed.get("access")
    if recorded != fact:
        raise SupportError(
            "the results record the access mode %r, not %r"
            % (recorded, fact))
    devices = parsed.get("devices")
    if isinstance(devices, list):
        for device in devices:
            if not isinstance(device, dict):
                continue
            access = device.get("access")
            if access is None:
                # the device has no fact of its own
                continue
            if access != fact:
                raise SupportError(
                    "the results record the access mode %r for the device "
                    "%r, not %r"
                    % (access, device.get("name"), fact))
    return fact


def record(
    platforms_path: Path, runs_path: Path, results: Path, *, platform: str, version: str, target: str,
    kind: str, scenario_names: set[str], access: str | None = None,
) -> dict[str, Any]:
    """Append one run from a runner results file. Keeps names of shape scenarios and counts only."""
    platforms, runs = load(platforms_path, runs_path, scenario_names)
    if platform not in platforms:
        raise SupportError(f"platform {platform!r} is not in platforms.toml")
    data = Path(results).read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if any(r["results_sha256"] == digest for r in runs):
        raise SupportError("these results are already recorded")
    parsed = json.loads(data)
    # The access mode of the run (ADR-021 point 1): the runner records
    # the mode the run measured (the mode its scenarios exercised), so
    # the table is gated on what the run did and not on what an
    # operator typed.  A flag may only confirm what the results say;
    # it can never stand in for them.
    modes = platforms[platform]["access_modes"]
    if modes:
        fact = results_access_fact(parsed)
        if access is not None and access != fact:
            raise SupportError(
                "the results record the access mode %r, not %r"
                % (fact, access)
            )
        access = fact
        if access not in {m["id"] for m in modes}:
            raise SupportError(
                "access must be one of %s" % ", ".join(m["id"] for m in modes)
            )
    # A platform with one way in has no mode to record.
    elif access is not None:
        raise SupportError("this platform has no access modes")
    scenarios = [s for s in parsed.get("scenarios", []) if isinstance(s, dict) and isinstance(s.get("name"), str)]
    shape_names = {n for s in platforms[platform]["shapes"] for n in s["scenarios"]}
    entry = {
        "platform": platform,
        "version": version,
        "target": target,
        "kind": kind,
        "date": str(parsed.get("timestamp", ""))[:10],
        "results_sha256": digest,
        "scenarios_passed": sum(1 for s in scenarios if s.get("passed") is True),
        "scenarios_failed": sum(1 for s in scenarios if s.get("passed") is not True),
        "shapes_passed": sorted(s["name"] for s in scenarios if s["name"] in shape_names and s.get("passed") is True),
        "shapes_failed": sorted(s["name"] for s in scenarios if s["name"] in shape_names and s.get("passed") is not True),
    }
    if access is not None:
        entry["access"] = access
    lines = ["", "[[run]]"]
    for key in ("platform", "version", "target", "kind", "date", "results_sha256"):
        lines.append(f"{key} = {_toml_str(entry[key])}")
    if access is not None:
        lines.append(f"access = {_toml_str(access)}")
    for key in ("scenarios_passed", "scenarios_failed"):
        lines.append(f"{key} = {entry[key]}")
    for key in ("shapes_passed", "shapes_failed"):
        lines.append(f"{key} = [" + ", ".join(_toml_str(n) for n in entry[key]) + "]")
    old = Path(runs_path).read_text(encoding="utf-8")
    Path(runs_path).write_text(old.rstrip("\n") + "\n" + "\n".join(lines) + "\n", encoding="utf-8")
    try:
        load(platforms_path, runs_path, scenario_names)
    except SupportError:
        Path(runs_path).write_text(old, encoding="utf-8")
        raise
    return entry


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("render", "check", "record"):
        p = sub.add_parser(name)
        p.add_argument("--repo", default=str(Path(__file__).resolve().parents[1]))
        p.add_argument("--out", default=None)
        if name == "record":
            p.add_argument("--results", required=True)
            p.add_argument("--platform", required=True)
            p.add_argument("--version", required=True)
            p.add_argument("--target", required=True)
            p.add_argument("--kind", required=True, choices=KINDS)
            p.add_argument("--access", default=None,
                           help="the access mode the run was made in")
    args = ap.parse_args(argv)
    repo = Path(args.repo)
    pf, rf = repo / "docs/support/platforms.toml", repo / "docs/support/runs.toml"
    out = Path(args.out) if args.out else repo / "docs/SUPPORT.md"
    names = repo_scenario_names(repo)
    try:
        if args.cmd == "record":
            entry = record(pf, rf, Path(args.results), platform=args.platform, version=args.version,
                           target=args.target, kind=args.kind, scenario_names=names,
                           access=args.access)
            print(f"recorded {entry['platform']} {entry['version']} {entry['date']}: "
                  f"{len(entry['shapes_passed'])} shape scenarios passed, {len(entry['shapes_failed'])} failed; now run render")
            return 0
        text = render(*load(pf, rf, names))
    except (SupportError, OSError, ValueError) as exc:
        print(f"support-table: {exc}", file=sys.stderr)
        return 2
    if args.cmd == "render":
        out.write_text(text, encoding="utf-8")
        return 0
    current = out.read_text(encoding="utf-8") if out.exists() else None
    if current != text:
        print(f"support-table: {out} is stale; run: scripts/support-table.py render", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
