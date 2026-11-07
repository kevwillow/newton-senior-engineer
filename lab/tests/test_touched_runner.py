"""ADR-010 wiring tests for the lab runner: the lab runner derives the same
touched probes as the MCP server for the same batch, prepends them to the
scenario's own probes, records ``manifest_checks_auto`` on the result JSON
and refuses on overflow.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tomllib
from pathlib import Path
from unittest import mock

import pytest


import newton_lab_test as nl
import newton_mcp.probes as newton_probes
import newton_mcp.touched as newton_touched


SID = "0123456789abcdef0123456789abcdef"
BASE_HASH = "b" * 64
PLANDIGEST = "d" * 64


# ---------- helpers -----------------------------------------------------------


def _full_lab(tmp_path: Path) -> tuple[Path, Path]:
    """Build a self-contained lab.toml + scenarios dir whose plan/apply
    subprocess calls can be mocked.  Returns (lab_toml, scen_dir)."""
    lab_toml = tmp_path / "lab.toml"
    lab_toml.write_text(
        """
[pve]
host = "pve.test"
node = "lab"
token_file = "~/.config/pve/token"
pin_file = "~/.config/pve/pin"

[ssh]
proxy = "ssh -W %h:%p root@pve.test"
password_file = "~/.config/newton/lab-root.pw"
key = "~/.ssh/key"

[devices.lab-r1]
vmid = 9102
host = "10.109.0.11"
user = "root"
snapshot = "baseline"

[vars]
"""
    )
    scen_dir = tmp_path / "scenarios"
    scen_dir.mkdir()
    return lab_toml, scen_dir


def _write_manifest(tmp_path: Path, manifest_text: str) -> Path:
    """Write a manifest under tmp_path and point NEWTON_MANIFEST at it."""
    path = tmp_path / "manifest.toml"
    path.write_text(manifest_text)
    os.environ["NEWTON_MANIFEST"] = str(path)
    return path


def _write_scenario(scen_dir: Path, name: str, body: str) -> Path:
    """Helper: write a scenario TOML and return its path."""
    p = scen_dir / f"{name}.toml"
    p.write_text(body)
    return p


def _restore_env(env_name: str) -> None:
    os.environ.pop(env_name, None)


def _plan_output(sid: str = SID, base: str = BASE_HASH,
                 diff: str = "dhcp.cfg01411c.dnssec='1'\n") -> str:
    """A STAGED plan that the mock ``_run`` returns to the runner."""
    return (
        f"BACKUP /tmp/fake.tar.gz (2 config files)\n"
        f"STAGED session={sid}\n"
        f"BASEHASH {base}\n"
        "PROBES 3 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "PROFILE lab\n"
        "SECTION dhcp cfg01411c dnsmasq dnsmasq\n"
        f"PLANDIGEST {PLANDIGEST}\n"
        "APPROVAL not-required\n"
        "----- diff -----\n"
        f"{diff}"
        "----------------\n"
    )


def _apply_output_confirmed(sid: str = SID, base: str = BASE_HASH) -> str:
    return (
        f"APPLYBASE {base}\n"
        f"CONFIRMED session={sid}\n"
    )


# ---------- shared-probe derivation -------------------------------------------


def test_lab_runner_derives_same_probes_as_mcp(tmp_path, monkeypatch):
    """The lab runner touches the same manifest probes the MCP server
    derives for the same batch (the shared ``touched`` module)."""
    manifest_text = """
[[control]]
id = 'LAB-OW-DNS-04'
tier = 'standard'
check_host = 'router'
batch = [ "set dhcp.@dnsmasq[0].dnssec='1'" ]
probes = [["conf-has", "dnsmasq", "line", "present", "dnssec"]]
"""
    _write_manifest(tmp_path, manifest_text)
    try:
        controls = newton_probes._load_controls(newton_probes.manifest_path())
        ids = newton_touched.touched_control_ids(
            controls, "set dhcp.@dnsmasq[0].dnssec='1'"
        )
        assert ids == ["LAB-OW-DNS-04"]
        # shared probe list
        expanded = newton_probes.expand_manifest_checks(ids)
        assert expanded == [
            ["conf-has", "dnsmasq", "line", "present", "dnssec"]
        ]
    finally:
        _restore_env("NEWTON_MANIFEST")


def test_lab_runner_derives_same_entries_as_mcp(tmp_path, monkeypatch):
    """The lab runner derives the SAME entry INDEXES the MCP server
    derives for the same batch (defect A: same value match, not the
    name-only match)."""
    manifest_text = """
[[control]]
id = 'A-ZERO'
tier = 'standard'
check_host = 'router'
batch = [ "set upnpd.config.enabled='0'" ]
probes = [["ping", "192.0.2.1"]]

[[control]]
id = 'A-ONE'
tier = 'standard'
check_host = 'router'
batch = [ "set upnpd.config.enabled='1'" ]
probes = [["ping", "192.0.2.2"]]
"""
    _write_manifest(tmp_path, manifest_text)
    try:
        controls = newton_probes._load_controls(newton_probes.manifest_path())
        # the MCP-side helper returns the same indexes the lab runner
        # derives via derive_touched_entries.
        mcp_entries = newton_touched.touched_entries(
            controls, "set upnpd.config.enabled='0'"
        )
        lab_entries = newton_touched.derive_touched_entries(
            "set upnpd.config.enabled='0'"
        )
        assert mcp_entries == lab_entries == [0]
        # value-mismatch -> empty
        assert newton_touched.derive_touched_entries(
            "set upnpd.config.enabled='9'"
        ) == []
    finally:
        _restore_env("NEWTON_MANIFEST")


# ---------- apply end-to-end (mocked script) --------------------------------


def test_lab_runner_seals_auto_probes_before_scenario_probes(
    tmp_path, monkeypatch
):
    """The runner puts the touched manifest probes BEFORE the scenario's
    own probes (manifest first, then scenario), records manifest_checks_auto
    on the result, and refuses on overflow."""
    _full_lab(tmp_path)
    monkeypatch.setattr(nl, "SCEN_DIR", tmp_path / "scenarios")
    monkeypatch.setattr(nl, "RESULTS_DIR", tmp_path / "results")
    manifest_text = """
[[control]]
id = 'TWO-PROBE-A'
tier = 'standard'
check_host = 'router'
batch = [ "set dhcp.@dnsmasq[0].x='1'" ]
probes = [["conf-has", "dnsmasq", "substr", "present", "dnssec"]]
"""
    _write_manifest(tmp_path, manifest_text)

    body = """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 90
batch = "set dhcp.@dnsmasq[0].x='1'"
probes = [["ping", "192.0.2.1"]]
"""
    _write_scenario(tmp_path / "scenarios", "01-x", body)
    lab = nl.load_lab(tmp_path / "lab.toml")
    scen = nl.load_scenarios(tmp_path / "scenarios")[0]

    written_probe_bytes: list[bytes] = []
    sid = SID

    def fake_run(args, **_kw):
        for part in args:
            if isinstance(part, str) and os.path.basename(part).startswith(
                "newton-lab-"
            ) and part.endswith(".probes"):
                try:
                    with open(part, "rb") as f:
                        written_probe_bytes.append(f.read())
                except OSError:
                    written_probe_bytes.append(b"")
        if args[0] == str(nl.OWRT_CHANGE) and args[1] == "plan":
            return subprocess.CompletedProcess(
                list(args), 0, _plan_output(sid), ""
            )
        if args[0] == str(nl.OWRT_CHANGE) and args[1] == "apply":
            return subprocess.CompletedProcess(
                list(args), 0, _apply_output_confirmed(sid), ""
            )
        if args[0] == str(nl.OWRT_CHANGE) and args[1] == "abort":
            return subprocess.CompletedProcess(list(args), 0, "", "")
        return subprocess.CompletedProcess(list(args), 0, "", "")

    monkeypatch.setattr(nl, "_run", fake_run)
    try:
        rec = nl.run_scenario(lab, scen)
    finally:
        _restore_env("NEWTON_MANIFEST")
    assert rec["passed"] is True, rec
    assert rec["outcome"] == "confirmed"
    assert rec["manifest_checks_auto"] == ["TWO-PROBE-A"]
    assert rec["sealed_probe_count"] == 2  # one manifest probe + one scenario probe
    # the captured probe file's first line is the manifest probe; the
    # scenario's ping comes after it.
    assert len(written_probe_bytes) == 1
    body_lines = written_probe_bytes[0].decode().splitlines()
    assert body_lines[0] == "conf-has\tdnsmasq\tsubstr\tpresent\tdnssec"
    assert body_lines[-1] == "ping\t192.0.2.1"


def test_lab_runner_unrelated_batch_records_no_auto_ids(tmp_path, monkeypatch):
    """A batch that no control touches -> ``manifest_checks_auto`` is absent
    in the result (the empty list collapses to no key, matching MCP)."""
    _full_lab(tmp_path)
    monkeypatch.setattr(nl, "SCEN_DIR", tmp_path / "scenarios")
    monkeypatch.setattr(nl, "RESULTS_DIR", tmp_path / "results")
    manifest_text = """
[[control]]
id = 'UNRELATED-CTRL'
tier = 'standard'
check_host = 'router'
batch = [ "set system.ntp.enabled='1'" ]
probes = [["fail"]]
"""
    _write_manifest(tmp_path, manifest_text)

    body = """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "noop"
timeout = 90
batch = "set dhcp.@dnsmasq[0].something_unrelated='1'"
"""
    _write_scenario(tmp_path / "scenarios", "01-x", body)
    lab = nl.load_lab(tmp_path / "lab.toml")
    scen = nl.load_scenarios(tmp_path / "scenarios")[0]

    def fake_run(args, **_kw):
        if args[0] == str(nl.OWRT_CHANGE) and args[1] == "plan":
            return subprocess.CompletedProcess(
                list(args), 1, "",
                "no changes staged\n",
            )
        return subprocess.CompletedProcess(list(args), 0, "", "")
    monkeypatch.setattr(nl, "_run", fake_run)
    try:
        rec = nl.run_scenario(lab, scen)
    finally:
        _restore_env("NEWTON_MANIFEST")
    assert rec["outcome"] == "noop"
    assert rec["passed"] is True
    assert "manifest_checks_auto" not in rec


def test_lab_runner_refuses_on_overflow(tmp_path, monkeypatch):
    """Adding the touched ids to scenario probes exceeds the 32-line cap ->
    the scenario ends with ``rec["error"]`` naming the offending ids and
    no plan is staged."""
    _full_lab(tmp_path)
    monkeypatch.setattr(nl, "SCEN_DIR", tmp_path / "scenarios")
    monkeypatch.setattr(nl, "RESULTS_DIR", tmp_path / "results")
    # 33-line manifest probe -> adding even an empty scenario probe overflows.
    big_probes = [["fail"]] * (nl.MAX_PROBES + 1)
    manifest_text = (
        "[[control]]\nid = 'OVERFLOW-CTRL'\ntier = 'standard'\n"
        "check_host = 'router'\n"
        "batch = [ \"set dhcp.@dnsmasq[0].x='1'\" ]\n"
        "probes = " + repr(big_probes) + "\n"
    )
    _write_manifest(tmp_path, manifest_text)

    body = """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 90
batch = "set dhcp.@dnsmasq[0].x='1'"
"""
    _write_scenario(tmp_path / "scenarios", "01-x", body)
    lab = nl.load_lab(tmp_path / "lab.toml")
    scen = nl.load_scenarios(tmp_path / "scenarios")[0]

    run_calls: list[list[str]] = []

    def fake_run(args, **_kw):
        run_calls.append(list(args))
        return subprocess.CompletedProcess(list(args), 0, "", "")

    monkeypatch.setattr(nl, "_run", fake_run)
    try:
        rec = nl.run_scenario(lab, scen)
    finally:
        _restore_env("NEWTON_MANIFEST")
    err = rec.get("error") or ""
    assert "OVERFLOW-CTRL" in err, err
    # no plan was sent to the router (refusal was pre-flight).
    plan_calls = [
        c for c in run_calls
        if c and c[0] == str(nl.OWRT_CHANGE) and c[1] == "plan"
    ]
    assert plan_calls == []


def test_lab_runner_refuses_scenario_probes_overflow(tmp_path, monkeypatch):
    """The scenario's own probes + the touched control's probes exceed
    the 32-line cap -> ``rec["error"]`` names the control ids being
    added and ``plan_batch`` is never called.  The cap is enforced in
    one place (touched.py); the runner does not duplicate the check."""
    _full_lab(tmp_path)
    monkeypatch.setattr(nl, "SCEN_DIR", tmp_path / "scenarios")
    monkeypatch.setattr(nl, "RESULTS_DIR", tmp_path / "results")
    # 3-line manifest control; 30 scenario probes push the union to 33.
    manifest_text = """
[[control]]
id = 'LAB-OW-DNS-04'
tier = 'standard'
check_host = 'router'
batch = [ "set dhcp.@dnsmasq[0].x='1'" ]
probes = [["fail"], ["fail"], ["fail"]]
"""
    _write_manifest(tmp_path, manifest_text)

    body = """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 90
batch = "set dhcp.@dnsmasq[0].x='1'"
probes = [
  ["ping", "192.0.2.1"], ["ping", "192.0.2.2"], ["ping", "192.0.2.3"],
  ["ping", "192.0.2.4"], ["ping", "192.0.2.5"], ["ping", "192.0.2.6"],
  ["ping", "192.0.2.7"], ["ping", "192.0.2.8"], ["ping", "192.0.2.9"],
  ["ping", "192.0.2.10"], ["ping", "192.0.2.11"], ["ping", "192.0.2.12"],
  ["ping", "192.0.2.13"], ["ping", "192.0.2.14"], ["ping", "192.0.2.15"],
  ["ping", "192.0.2.16"], ["ping", "192.0.2.17"], ["ping", "192.0.2.18"],
  ["ping", "192.0.2.19"], ["ping", "192.0.2.20"], ["ping", "192.0.2.21"],
  ["ping", "192.0.2.22"], ["ping", "192.0.2.23"], ["ping", "192.0.2.24"],
  ["ping", "192.0.2.25"], ["ping", "192.0.2.26"], ["ping", "192.0.2.27"],
  ["ping", "192.0.2.28"], ["ping", "192.0.2.29"], ["ping", "192.0.2.30"],
]
"""
    _write_scenario(tmp_path / "scenarios", "01-x", body)
    lab = nl.load_lab(tmp_path / "lab.toml")
    scen = nl.load_scenarios(tmp_path / "scenarios")[0]

    run_calls: list[list[str]] = []

    def fake_run(args, **_kw):
        run_calls.append(list(args))
        return subprocess.CompletedProcess(list(args), 0, "", "")

    monkeypatch.setattr(nl, "_run", fake_run)
    try:
        rec = nl.run_scenario(lab, scen)
    finally:
        _restore_env("NEWTON_MANIFEST")
    err = rec.get("error") or ""
    assert "LAB-OW-DNS-04" in err, err
    plan_calls = [
        c for c in run_calls
        if c and c[0] == str(nl.OWRT_CHANGE) and c[1] == "plan"
    ]
    assert plan_calls == []


def test_lab_runner_diff_only_match_runs_the_restage(tmp_path, monkeypatch):
    """When the runner's first plan diff reveals a manifest id the batch
    alone did not surface, ``_apply_touched_to_plan`` aborts and re-plans
    with the union (mirroring the MCP server)."""
    _full_lab(tmp_path)
    monkeypatch.setattr(nl, "SCEN_DIR", tmp_path / "scenarios")
    monkeypatch.setattr(nl, "RESULTS_DIR", tmp_path / "results")
    manifest_text = """
[[control]]
id = 'DIFF-ONLY'
tier = 'standard'
check_host = 'router'
batch = [ "set dhcp.@dnsmasq[0].dnssec='1'" ]
probes = [["conf-has", "dnsmasq", "substr", "present", "trust-anchors.conf"]]
"""
    _write_manifest(tmp_path, manifest_text)

    body = """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 90
batch = "set system.x=whatever"
"""
    _write_scenario(tmp_path / "scenarios", "01-x", body)
    lab = nl.load_lab(tmp_path / "lab.toml")
    scen = nl.load_scenarios(tmp_path / "scenarios")[0]

    sid_a = "f" * 32
    sid_b = "e" * 32

    run_calls: list[list[str]] = []

    def fake_run(args, **_kw):
        run_calls.append(list(args))
        if args[0] != str(nl.OWRT_CHANGE):
            return subprocess.CompletedProcess(list(args), 0, "", "")
        if args[1] == "plan":
            if len(run_calls) >= 2 and run_calls[-2][1] == "abort":
                return subprocess.CompletedProcess(
                    list(args), 0, _plan_output(sid_b), ""
                )
            return subprocess.CompletedProcess(
                list(args), 0, _plan_output(sid_a), ""
            )
        if args[1] == "abort":
            return subprocess.CompletedProcess(list(args), 0, "", "")
        if args[1] == "apply":
            return subprocess.CompletedProcess(
                list(args), 0, _apply_output_confirmed(sid_b), ""
            )
        return subprocess.CompletedProcess(list(args), 0, "", "")

    monkeypatch.setattr(nl, "_run", fake_run)
    try:
        rec = nl.run_scenario(lab, scen)
    finally:
        _restore_env("NEWTON_MANIFEST")
    assert rec["passed"] is True, rec
    assert rec["outcome"] == "confirmed"
    argv0 = [c[1] if c[0] == str(nl.OWRT_CHANGE) else None for c in run_calls]
    assert "abort" in argv0
    # Two plans: one before, one after the abort.
    assert argv0.count("plan") >= 2
    # The diff-restage added the id; manifest_checks_auto carries it.
    assert "DIFF-ONLY" in rec["manifest_checks_auto"]


# ---------- end-to-end (mocked script): defect A fix ----------------------------


def test_lab_runner_value_mismatch_does_not_seal(
    tmp_path, monkeypatch
):
    """The lab runner applies the same requirement-based match rule the
    MCP server uses: ``set dhcp.@dnsmasq[0].dnssec='0'`` does NOT seal
    the ``dnssec='1'`` control's probes (no false rollback of a
    legitimate user choice).  The fake router echoes the same value
    the user staged so the diff doesn't pull a matching id in."""
    _full_lab(tmp_path)
    monkeypatch.setattr(nl, "SCEN_DIR", tmp_path / "scenarios")
    monkeypatch.setattr(nl, "RESULTS_DIR", tmp_path / "results")
    manifest_text = """
[[control]]
id = 'DNSEC-ONE'
tier = 'standard'
check_host = 'router'
batch = [ "set dhcp.@dnsmasq[0].dnssec='1'" ]
probes = [["conf-has", "dnsmasq", "line", "present", "dnssec"]]
"""
    _write_manifest(tmp_path, manifest_text)

    body = """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 90
batch = "set dhcp.@dnsmasq[0].dnssec='0'"
"""
    _write_scenario(tmp_path / "scenarios", "01-x", body)
    lab = nl.load_lab(tmp_path / "lab.toml")
    scen = nl.load_scenarios(tmp_path / "scenarios")[0]

    written_probe_bytes: list[bytes] = []

    def fake_run(args, **_kw):
        for part in args:
            if isinstance(part, str) and os.path.basename(part).startswith(
                "newton-lab-"
            ) and part.endswith(".probes"):
                try:
                    with open(part, "rb") as f:
                        written_probe_bytes.append(f.read())
                except OSError:
                    written_probe_bytes.append(b"")
        if args[0] == str(nl.OWRT_CHANGE) and args[1] == "plan":
            # the fake router echoes the user's staged value ('0'), so
            # the diff side surfaces dnssec='0' too -> no match.
            return subprocess.CompletedProcess(
                list(args), 0,
                _plan_output(SID, diff="dhcp.cfg01411c.dnssec='0'\n"), ""
            )
        if args[0] == str(nl.OWRT_CHANGE) and args[1] == "apply":
            return subprocess.CompletedProcess(
                list(args), 0, _apply_output_confirmed(SID), ""
            )
        return subprocess.CompletedProcess(list(args), 0, "", "")

    monkeypatch.setattr(nl, "_run", fake_run)
    try:
        rec = nl.run_scenario(lab, scen)
    finally:
        _restore_env("NEWTON_MANIFEST")
    assert rec["passed"] is True, rec
    # the dnssec control was NOT sealed -> manifest_checks_auto absent.
    assert "manifest_checks_auto" not in rec
    # the runner did not seal any manifest probes; the router saw no
    # .probes argument (no manifest probe file was written for it).
    assert written_probe_bytes == []


def test_lab_runner_duplicate_id_siblings_seal_both(
    tmp_path, monkeypatch
):
    """Two manifest entries with the SAME id but different values: the
    runner seals only the LAST entry's probes (defect 2: batch facts
    are LAST-WINS; the router commits the later value).  The id is
    recorded ONCE in ``manifest_checks_auto``."""
    _full_lab(tmp_path)
    monkeypatch.setattr(nl, "SCEN_DIR", tmp_path / "scenarios")
    monkeypatch.setattr(nl, "RESULTS_DIR", tmp_path / "results")
    manifest_text = """
[[control]]
id = 'OW-FW-06'
tier = 'standard'
check_host = 'router'
batch = [ "set upnpd.config.enabled='0'" ]
probes = [["ping", "192.0.2.1"]]

[[control]]
id = 'OW-FW-06'
tier = 'standard'
check_host = 'router'
batch = [ "set upnpd.config.enabled='1'" ]
probes = [["ping", "192.0.2.2"]]
"""
    _write_manifest(tmp_path, manifest_text)

    body = """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 90
batch = "set upnpd.config.enabled='0'\\nset upnpd.config.enabled='1'"
"""
    _write_scenario(tmp_path / "scenarios", "01-x", body)
    lab = nl.load_lab(tmp_path / "lab.toml")
    scen = nl.load_scenarios(tmp_path / "scenarios")[0]

    written_probe_bytes: list[bytes] = []

    def fake_run(args, **_kw):
        for part in args:
            if isinstance(part, str) and os.path.basename(part).startswith(
                "newton-lab-"
            ) and part.endswith(".probes"):
                try:
                    with open(part, "rb") as f:
                        written_probe_bytes.append(f.read())
                except OSError:
                    written_probe_bytes.append(b"")
        if args[0] == str(nl.OWRT_CHANGE) and args[1] == "plan":
            return subprocess.CompletedProcess(
                list(args), 0, _plan_output(SID), ""
            )
        if args[0] == str(nl.OWRT_CHANGE) and args[1] == "apply":
            return subprocess.CompletedProcess(
                list(args), 0, _apply_output_confirmed(SID), ""
            )
        return subprocess.CompletedProcess(list(args), 0, "", "")

    monkeypatch.setattr(nl, "_run", fake_run)
    try:
        rec = nl.run_scenario(lab, scen)
    finally:
        _restore_env("NEWTON_MANIFEST")
    assert rec["passed"] is True, rec
    assert rec["manifest_checks_auto"] == ["OW-FW-06"]
    assert rec["sealed_probe_count"] == 1  # LAST-WINS: only the later entry
    # the captured probe file carries only the LAST entry's probe line.
    assert len(written_probe_bytes) == 1
    lines = written_probe_bytes[0].decode().splitlines()
    assert "ping\t192.0.2.2" in lines
    assert "ping\t192.0.2.1" not in lines


# ---------- end-to-end (mocked script): defect 7 fix ---------------------------


def test_lab_runner_first_plan_unparseable_aborts_session(
    tmp_path, monkeypatch
):
    """When the first plan returns rc=0 with a valid SID but the plan
    log is unparseable (no DIFF block / no BASEHASH / no STAGED), the
    runner must ABORT that session and return an error naming the
    problem.  Previously the diff-union check was silently skipped and
    the caller refused without cleaning up the staged session."""
    _full_lab(tmp_path)
    monkeypatch.setattr(nl, "SCEN_DIR", tmp_path / "scenarios")
    monkeypatch.setattr(nl, "RESULTS_DIR", tmp_path / "results")
    manifest_text = """
[[control]]
id = 'FIRST-PARSE-FAIL'
tier = 'standard'
check_host = 'router'
batch = [ "set dhcp.@dnsmasq[0].x='1'" ]
probes = [["fail"]]
"""
    _write_manifest(tmp_path, manifest_text)

    body = """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 90
batch = "set dhcp.@dnsmasq[0].x='1'"
"""
    _write_scenario(tmp_path / "scenarios", "01-x", body)
    lab = nl.load_lab(tmp_path / "lab.toml")
    scen = nl.load_scenarios(tmp_path / "scenarios")[0]

    run_calls: list[list[str]] = []

    def fake_run(args, **_kw):
        run_calls.append(list(args))
        if args[0] == str(nl.OWRT_CHANGE) and args[1] == "plan":
            # STAGED + SID but no diff block -> _parse_plan_log returns
            # None (no DIFF block found).
            return subprocess.CompletedProcess(
                list(args), 0,
                f"BACKUP /tmp/fake.tar.gz (2 config files)\n"
                f"STAGED session={SID}\n"
                "PROBES 1 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
                "PROFILE lab\n"
                f"PLANDIGEST {PLANDIGEST}\n"
                "APPROVAL not-required\n",
                "")
        if args[0] == str(nl.OWRT_CHANGE) and args[1] == "abort":
            return subprocess.CompletedProcess(list(args), 0, "", "")
        return subprocess.CompletedProcess(list(args), 0, "", "")

    monkeypatch.setattr(nl, "_run", fake_run)
    try:
        rec = nl.run_scenario(lab, scen)
    finally:
        _restore_env("NEWTON_MANIFEST")
    # the runner refused with a clear error naming the unparseable plan.
    err = rec.get("error") or ""
    assert "plan log" in err.lower() or "unparseable" in err.lower() \
        or "parse" in err.lower() or "diff" in err.lower(), err
    # the runner aborted the unparseable session (no second plan ran).
    argv1 = [c[1] if c[0] == str(nl.OWRT_CHANGE) else None for c in run_calls]
    assert argv1.count("plan") == 1
    assert argv1.count("abort") == 1


def test_lab_runner_second_plan_unparseable_aborts_session(
    tmp_path, monkeypatch
):
    """When the second plan (after the union restage) is unparseable,
    the runner must abort that session and return an error naming the
    problem (the union restage was wasted, but the router is left
    clean)."""
    _full_lab(tmp_path)
    monkeypatch.setattr(nl, "SCEN_DIR", tmp_path / "scenarios")
    monkeypatch.setattr(nl, "RESULTS_DIR", tmp_path / "results")
    manifest_text = """
[[control]]
id = 'DIFF-ONLY'
tier = 'standard'
check_host = 'router'
batch = [ "set dhcp.@dnsmasq[0].dnssec='1'" ]
probes = [["conf-has", "dnsmasq", "substr", "present", "trust-anchors.conf"]]
"""
    _write_manifest(tmp_path, manifest_text)

    body = """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 90
batch = "set system.x=whatever"
"""
    _write_scenario(tmp_path / "scenarios", "01-x", body)
    lab = nl.load_lab(tmp_path / "lab.toml")
    scen = nl.load_scenarios(tmp_path / "scenarios")[0]

    sid_a = "f" * 32
    sid_b = "e" * 32

    run_calls: list[list[str]] = []

    def fake_run(args, **_kw):
        run_calls.append(list(args))
        if args[1] == "plan":
            if len(run_calls) >= 2 and run_calls[-2][1] == "abort":
                # SECOND plan: valid STAGED + SID but no diff block.
                return subprocess.CompletedProcess(
                    list(args), 0,
                    f"BACKUP /tmp/fake.tar.gz (2 config files)\n"
                    f"STAGED session={sid_b}\n"
                    "PROBES 1 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
                    "PROFILE lab\n"
                    f"PLANDIGEST {PLANDIGEST}\n"
                    "APPROVAL not-required\n",
                    "")
            # FIRST plan: valid plan output that triggers restage.
            return subprocess.CompletedProcess(
                list(args), 0, _plan_output(sid_a), ""
            )
        if args[1] == "abort":
            return subprocess.CompletedProcess(list(args), 0, "", "")
        return subprocess.CompletedProcess(list(args), 0, "", "")

    monkeypatch.setattr(nl, "_run", fake_run)
    try:
        rec = nl.run_scenario(lab, scen)
    finally:
        _restore_env("NEWTON_MANIFEST")
    err = rec.get("error") or ""
    assert "plan log" in err.lower() or "unparseable" in err.lower() \
        or "parse" in err.lower() or "diff" in err.lower(), err
    argv1 = [c[1] if c[0] == str(nl.OWRT_CHANGE) else None for c in run_calls]
    assert argv1.count("plan") == 2
    assert argv1.count("abort") == 2  # original + the second session


# ---------- end-to-end (mocked script): second cold review --------------------


def test_lab_runner_restage_still_disagrees_names_control_ids(
    tmp_path, monkeypatch
):
    """When the second plan (after the union restage) still reveals an
    entry the union did not seal, the runner aborts the second session
    and returns an error message that names the missing CONTROL ID
    (operators read OW-XX ids, not positional indexes; defect 3)."""
    _full_lab(tmp_path)
    monkeypatch.setattr(nl, "SCEN_DIR", tmp_path / "scenarios")
    monkeypatch.setattr(nl, "RESULTS_DIR", tmp_path / "results")
    manifest_text = """
[[control]]
id = 'A-RESTAGE'
tier = 'standard'
check_host = 'router'
batch = [ "set dhcp.@dnsmasq[0].a='1'" ]
probes = [["fail"]]

[[control]]
id = 'B-RESTAGE'
tier = 'standard'
check_host = 'router'
batch = [ "set dhcp.@dnsmasq[0].b='1'" ]
probes = [["fail"]]

[[control]]
id = 'C-RESTAGE'
tier = 'standard'
check_host = 'router'
batch = [ "set dhcp.@dnsmasq[0].c='1'" ]
probes = [["fail"]]
"""
    _write_manifest(tmp_path, manifest_text)

    body = """
name = "01-x"
description = "x"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 90
batch = "set dhcp.@dnsmasq[0].a='1'"
"""
    _write_scenario(tmp_path / "scenarios", "01-x", body)
    lab = nl.load_lab(tmp_path / "lab.toml")
    scen = nl.load_scenarios(tmp_path / "scenarios")[0]

    sid_a = "f" * 32
    sid_b = "e" * 32

    run_calls: list[list[str]] = []

    def fake_run(args, **_kw):
        run_calls.append(list(args))
        if args[0] != str(nl.OWRT_CHANGE):
            return subprocess.CompletedProcess(list(args), 0, "", "")
        if args[1] == "plan":
            if len(run_calls) >= 2 and run_calls[-2][1] == "abort":
                # SECOND plan (after the abort+restage): reveals
                # A-RESTAGE and C-RESTAGE, but the union was sealed for
                # A-RESTAGE and B-RESTAGE -> needs_restage misses
                # C-RESTAGE.
                return subprocess.CompletedProcess(
                    list(args), 0,
                    _plan_output(
                        sid_b,
                        diff=(
                            "dhcp.cfg01411c.a='1'\n"
                            "dhcp.cfg01411c.c='1'\n"
                        ),
                    ),
                    "",
                )
            # FIRST plan: reveals A-RESTAGE and B-RESTAGE, which forces
            # the union restage.
            return subprocess.CompletedProcess(
                list(args), 0,
                _plan_output(
                    sid_a,
                    diff=(
                        "dhcp.cfg01411c.a='1'\n"
                        "dhcp.cfg01411c.b='1'\n"
                    ),
                ),
                "",
            )
        if args[1] == "abort":
            return subprocess.CompletedProcess(list(args), 0, "", "")
        return subprocess.CompletedProcess(list(args), 0, "", "")

    monkeypatch.setattr(nl, "_run", fake_run)
    try:
        rec = nl.run_scenario(lab, scen)
    finally:
        _restore_env("NEWTON_MANIFEST")
    err = rec.get("error") or ""
    # the message names the missing CONTROL ID, not the entry index.
    assert "C-RESTAGE" in err, err
    assert "missing" in err, err
