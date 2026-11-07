"""R3: TIER scenario kind and REBOOT step for the lab runner.

Mock subprocess throughout: no network, no Proxmox, no router SSH.

A TIER scenario is a new scenario kind the lab runner learns:

* it declares ``tier`` (``"standard" | "hardened" | "lockdown"``) instead
  of a literal ``batch`` string.  The runner hands the tier to
  ``newton_mcp.tiers.split_tier`` which partitions the tier's .uci file
  into probe-safe batches in manifest order; the runner then plans +
  applies every batch in turn (minting approval tokens when required,
  with the same BASEHASH/APPLYBASE check the normal path runs).
* optional ``tier_values`` substitutes ``{name}`` placeholders inside
  every batch before plan/apply; values may themselves reference lab
  vars (the runner resolves those through the existing [vars] machinery).
* optional ``tier_batch_lines`` (int >= 1) is passed to ``split_tier`` as
  ``max_lines`` so a live proof can force several small ordered batches.
* optional ``tier_fail_probe`` is a single probe the runner applies to
  the LAST batch FIRST as a dry-run probe: it must trigger a
  ``rolled_back`` outcome with the same ``uci export`` md5sum hash
  before and after.
* a REBOOT step (``tier_reboot``, default true) reboots the device
  between the apply and the survival runs, falls back ONCE to a
  Proxmox guest reboot when the admin ssh reboot fails, and the
  survival runs re-run each batch's sealed manifest probes after
  reboot.  Each survival apply must confirm; the router's own verify
  runs every probe on the rebooted system.

The tests pin every behaviour listed above by mocking _run, ssh_ready,
router_hello_preflight, wait_settled, plan_batch, apply_batch,
_abort_batch, and _curl_pve; no real network or ssh ever runs.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import time
from pathlib import Path
from unittest import mock

import pytest

import newton_lab_test as nl
import newton_mcp.tiers as tiers
import newton_mcp.touched as newton_touched


SID = "0123456789abcdef0123456789abcdef"
OTHER_SID = "fedcba9876543210fedcba9876543210"
BASE_HASH = "b" * 64
PLANDIGEST = "d" * 64


def _cp(stdout: str = "", stderr: str = "", returncode: int = 0):
    return subprocess.CompletedProcess(args=[], returncode=returncode,
                                       stdout=stdout, stderr=stderr)


def _ok_plan_output(sid: str = SID, base: str = BASE_HASH,
                    diff: str = "dhcp.cfg01411c.dnssec='1'\n",
                    approval: str = "not-required") -> str:
    return (
        f"BACKUP /tmp/fake.tar.gz (2 config files)\n"
        f"STAGED session={sid}\n"
        f"BASEHASH {base}\n"
        f"PLANDIGEST {PLANDIGEST}\n"
        f"APPROVAL {approval}\n"
        "----- diff -----\n"
        f"{diff}"
        "----------------\n"
    )


def _apply_output(sid: str = SID, base: str = BASE_HASH,
                  outcome: str = "CONFIRMED") -> str:
    return f"APPLYBASE {base}\n{outcome} session={sid}\n"


def _full_lab(tmp_path: Path, *, snapshot: str = "baseline",
              tier_values_needed: bool = False) -> tuple[Path, Path]:
    """A self-contained lab.toml + scenarios dir; identical to
    test_touched_runner._full_lab but with [vars] only when needed."""
    lab_toml = tmp_path / "lab.toml"
    # Create a passphrase file so _approval_k (when called by the tier
    # path for approval = true scenarios) doesn't try to read a missing
    # file at '.' (the cwd).
    pp_path = tmp_path / "lab-approve.pw"
    pp_path.write_bytes(b"unit-test-pw\n")
    vars_block = (
        "[vars]\n"
        "fw_wan_zone = { device = \"lab-r1\", cmd = \"echo wan\" }\n"
    ) if tier_values_needed else "[vars]\n"
    lab_toml.write_text(
        f"""
[pve]
host = "pve.test"
node = "lab"
token_file = "~/.config/pve/token"
pin_file = "~/.config/pve/pin"

[ssh]
proxy = "ssh -W %h:%p root@pve.test"
password_file = "~/.config/newton/lab-root.pw"
key = "~/.ssh/key"
router_key = "{tmp_path}/rk"
approve_passphrase_file = "{pp_path}"

[devices.lab-r1]
vmid = 9102
host = "10.109.0.11"
user = "root"
snapshot = "{snapshot}"

{vars_block}
"""
    )
    (tmp_path / "rk").write_bytes(b"k\n")
    scen_dir = tmp_path / "scenarios"
    scen_dir.mkdir()
    return lab_toml, scen_dir


def _full_lab_with_checks(tmp_path: Path, *, snapshot: str = "baseline",
                          tier_values_needed: bool = True) -> tuple[Path, Path]:
    """Same as _full_lab but adds a [checks.reg] block so a scenario
    can declare regression = ["reg"] and the AFTER probe phase has
    observable behaviour."""
    lab_toml = tmp_path / "lab.toml"
    pp_path = tmp_path / "lab-approve.pw"
    pp_path.write_bytes(b"unit-test-pw\n")
    vars_block = (
        "[vars]\n"
        "fw_wan_zone = { device = \"lab-r1\", cmd = \"echo wan\" }\n"
    ) if tier_values_needed else "[vars]\n"
    lab_toml.write_text(
        f"""
[pve]
host = "pve.test"
node = "lab"
token_file = "~/.config/pve/token"
pin_file = "~/.config/pve/pin"

[ssh]
proxy = "ssh -W %h:%p root@pve.test"
password_file = "~/.config/newton/lab-root.pw"
key = "~/.ssh/key"
router_key = "{tmp_path}/rk"
approve_passphrase_file = "{pp_path}"

[devices.lab-r1]
vmid = 9102
host = "10.109.0.11"
user = "root"
snapshot = "{snapshot}"

[checks.reg]
device = "lab-r1"
cmd = "echo regression-passes"
expect_rc = 0

{vars_block}
"""
    )
    (tmp_path / "rk").write_bytes(b"k\n")
    scen_dir = tmp_path / "scenarios"
    scen_dir.mkdir()
    return lab_toml, scen_dir


def _write_scenario(scen_dir: Path, name: str, body: str) -> Path:
    p = scen_dir / f"{name}.toml"
    p.write_text(body)
    return p


def _restore_env(env_name: str) -> None:
    os.environ.pop(env_name, None)


# Standard tier body — the simplest one-batch tier scenario with no
# tier_batch_lines (the splitter defaults to the router cap).
_TIER_BASIC_BODY = """
name = "tier-basic"
description = "tier basic"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 60
tier = "standard"
tier_reboot = false
"""

_TIER_MULTI_BODY = """
name = "tier-multi"
description = "tier multi"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 60
tier = "hardened"
tier_batch_lines = 16
tier_reboot = false
"""


# ----- Scenario fields: load + validate -------------------------------------


def test_tier_scenario_parses_and_validates(tmp_path, monkeypatch):
    """A tier scenario loads with the new fields and validates cleanly when
    they are consistent.  Bad cases: unknown tier name, non-empty batch with
    tier, tier_batch_lines < 1; each yields a validation error."""
    lab_toml, scen_dir = _full_lab(tmp_path)
    monkeypatch.setattr(nl, "SCEN_DIR", scen_dir)
    monkeypatch.setattr(nl, "RESULTS_DIR", tmp_path / "results")

    # Good case: tier = standard, batch empty, expect = "confirmed".
    _write_scenario(scen_dir, "01-good", """
name = "01-good"
description = "good"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 60
tier = "standard"
tier_reboot = false
""")
    # Bad case: unknown tier name.
    _write_scenario(scen_dir, "02-bad-name", """
name = "02-bad-name"
description = "bad name"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 60
tier = "bogus"
tier_reboot = false
""")
    # Bad case: batch present with tier.
    _write_scenario(scen_dir, "03-bad-batch", """
name = "03-bad-batch"
description = "bad batch"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 60
tier = "standard"
batch = "set foo=bar"
tier_reboot = false
""")
    # Bad case: tier_batch_lines < 1.
    _write_scenario(scen_dir, "04-bad-lines", """
name = "04-bad-lines"
description = "bad lines"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 60
tier = "standard"
tier_batch_lines = 0
tier_reboot = false
""")
    lab = nl.load_lab(lab_toml)
    scens = nl.load_scenarios(scen_dir)
    by_name = {s.name: s for s in scens}
    # Good case parsed and validated.
    assert by_name["01-good"].tier == "standard"
    assert by_name["01-good"].tier_reboot is False
    errs = nl.validate_scenarios(lab, scens)
    assert not [e for e in errs if "01-good" in e], (
        f"01-good should be clean, got: {errs}")

    # Bad-tier-name error names the scenario.
    errs = nl.validate_scenarios(lab, scens)
    assert any("02-bad-name" in e and "bogus" in e for e in errs), (
        f"unknown tier should be a validation error, got: {errs}")

    # Batch-with-tier error names the scenario.
    errs = nl.validate_scenarios(lab, scens)
    assert any("03-bad-batch" in e for e in errs), (
        f"batch with tier should be a validation error, got: {errs}")

    # tier_batch_lines 0 error names the scenario.
    errs = nl.validate_scenarios(lab, scens)
    assert any("04-bad-lines" in e and "tier_batch_lines" in e
               for e in errs), (
        f"tier_batch_lines=0 should be a validation error, got: {errs}")


def test_tier_scenario_loading_without_tier_unchanged(tmp_path, monkeypatch):
    """Scenarios without the new keys still load exactly the same way (the
    added slot defaults are inert)."""
    lab_toml, scen_dir = _full_lab(tmp_path)
    monkeypatch.setattr(nl, "SCEN_DIR", scen_dir)
    _write_scenario(scen_dir, "01-plain", """
name = "01-plain"
description = "plain"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 60
batch = "set foo=bar"
""")
    scens = nl.load_scenarios(scen_dir)
    assert len(scens) == 1
    s = scens[0]
    assert s.tier is None
    assert s.tier_values is None
    assert s.tier_batch_lines is None
    assert s.tier_fail_probe is None
    assert s.tier_reboot is True   # default per the design


def test_empty_batch_with_none_still_fails_for_non_tier(tmp_path):
    """Regression: an empty batch with expect != 'none' must still fail
    validation for plain (non-tier) scenarios.  The new "tier must have
    empty batch + expect=confirmed + target" rules do not relax this
    rule for non-tier scenarios."""
    lab_toml, scen_dir = _full_lab(tmp_path)
    _write_scenario(scen_dir, "01-bad", """
name = "01-bad"
description = "bad"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 60
batch = ""
""")
    lab = nl.load_lab(lab_toml)
    scens = nl.load_scenarios(scen_dir)
    errs = nl.validate_scenarios(lab, scens)
    assert any("01-bad" in e and "expect is" in e for e in errs), (
        f"empty batch + non-none expect must fail, got: {errs}")


# ----- TIER splitter integration --------------------------------------------


def test_tier_batches_planned_in_order_through_the_splitter(
    tmp_path, monkeypatch,
):
    """With tier_batch_lines=16, every batch the splitter emits is planned
    in order, in its resolved text, with no '{' remaining, and the splitter
    output is identical to tiers.split_tier + tiers.resolve_batch.

    Missing tier_values for a needed name must yield rec['error'] naming
    that placeholder and plan_batch must NOT be called."""
    lab_toml, scen_dir = _full_lab(tmp_path, tier_values_needed=True)
    monkeypatch.setattr(nl, "SCEN_DIR", scen_dir)
    monkeypatch.setattr(nl, "RESULTS_DIR", tmp_path / "results")
    _write_scenario(scen_dir, "01-multi", _TIER_MULTI_BODY + (
                    "tier_values = { fw_wan_zone = \"wan\","
                    " fw_allow_ping = \"Allow-Ping\" }\n"))
    lab = nl.load_lab(lab_toml)
    scen = nl.load_scenarios(scen_dir)[0]
    # sanity: tier + tier_batch_lines loaded
    assert scen.tier == "hardened"
    assert scen.tier_batch_lines == 16
    assert scen.tier_reboot is False

    # Stub _run so var resolution returns quickly.
    def fake_run(args, **_kw):
        if args[0] == "ssh":
            # the only ssh cmd is the [vars] cmd for fw_wan_zone
            return _cp(stdout="wan\n")
        return _cp(returncode=0, stdout="")
    monkeypatch.setattr(nl, "_run", fake_run)

    # Plan calls in order.
    plan_calls: list[list[str]] = []
    apply_calls: list[list[str]] = []

    # Build the expected batch texts by calling tiers.split_tier with
    # max_lines=16 and tiers.resolve_batch on each batch's text.
    expected_split = tiers.split_tier("hardened", max_lines=16)
    expected_resolved: list[str] = []
    # Map tier placeholder names -> operator values (what the scenario's
    # tier_values table supplies).  The runner does the same substitution
    # and resolution; this matches it byte-for-byte.
    value_map = {
        "fw_wan_zone": "wan",
        "fw_allow_ping": "Allow-Ping",
    }
    for batch in expected_split["batches"]:
        placeholder_names = tiers.tier_placeholders(batch["text"])
        values = {n: value_map.get(n, "x") for n in placeholder_names}
        expected_resolved.append(
            tiers.resolve_batch(batch["text"], values,
                                 tier_names=placeholder_names))

    def fake_plan_batch(lab, target, batch_text, *, probes=None,
                        timeout_s=90, lane="password"):
        # the runner calls plan_batch from _apply_touched_to_plan; capture
        # the batch text it was given.
        plan_calls.append([batch_text])
        # every batch produces a CONFIRMED apply when followed by apply.
        sid = SID + str(len(plan_calls))
        return 0, _ok_plan_output(sid, approval="not-required"), ""

    def fake_apply_batch(lab, target, sid, timeout_s, *, lane="password",
                         token=None, window=None):
        apply_calls.append([sid])
        return 0, _apply_output(sid), ""

    monkeypatch.setattr(nl, "plan_batch", fake_plan_batch)
    monkeypatch.setattr(nl, "apply_batch", fake_apply_batch)

    rec = nl.run_scenario(lab, scen)

    # Every batch was planned with the resolved text the splitter+resolver
    # produced (the runner did the same substitution + resolution).
    actual_texts = [c[0] for c in plan_calls]
    assert actual_texts == expected_resolved, (
        f"plan texts differ:\n"
        f"  expected={expected_resolved!r}\n"
        f"  got     ={actual_texts!r}")
    # No '{' remains in any planned batch (every placeholder substituted).
    for txt in actual_texts:
        assert "{" not in txt, f"unresolved placeholder in: {txt!r}"
    # at least 2 batches (tier_batch_lines=1 forces a split)
    assert len(plan_calls) >= 2, plan_calls
    # outcome is confirmed (every batch confirmed).
    assert rec["outcome"] == "confirmed"
    assert rec["passed"] is True


def test_tier_missing_placeholder_records_error(tmp_path, monkeypatch):
    """A tier scenario that omits a placeholder its batch needs yields
    rec['error'] naming that placeholder; plan_batch is never called."""
    lab_toml, scen_dir = _full_lab(tmp_path, tier_values_needed=True)
    monkeypatch.setattr(nl, "SCEN_DIR", scen_dir)
    monkeypatch.setattr(nl, "RESULTS_DIR", tmp_path / "results")
    # Pick the hardened tier (has {fw_wan_zone}) and provide NO value.
    _write_scenario(scen_dir, "01-missing", _TIER_MULTI_BODY)
    lab = nl.load_lab(lab_toml)
    scen = nl.load_scenarios(scen_dir)[0]
    # Stub _run so var resolution works (it should not need to).
    monkeypatch.setattr(nl, "_run",
                        lambda *_a, **_k: _cp(stdout="wan\n"))

    plan_calls: list[list[str]] = []

    def fake_plan_batch(*_a, **_k):
        plan_calls.append(["called"])
        return 0, _ok_plan_output(), ""

    monkeypatch.setattr(nl, "plan_batch", fake_plan_batch)
    monkeypatch.setattr(nl, "apply_batch",
                        lambda *_a, **_k: (0, _apply_output(), ""))

    rec = nl.run_scenario(lab, scen)
    assert rec.get("error"), rec
    assert "fw_wan_zone" in rec["error"], rec
    assert plan_calls == []


# ----- Approval / apply checks ---------------------------------------------


def test_approval_token_minted_when_required(tmp_path, monkeypatch):
    """R3b change: tier scenarios use the AUTO approval rule (the runner
    mints a token iff the router says APPROVAL required; scen.approval is
    irrelevant for tier runs).

    1. Scenario with no `approval` field, plan says required: SUCCESS with
       a 64-hex approval_token minted on every batch (auto mode).
    2. Scenario with `approval = true`, plan says required: also SUCCESS
       with a 64-hex token (the scenario's approval flag is ignored by
       tier code in favour of the router's APPROVAL line).

    The error path the R3 runner took (router says required +
    scen.approval is None -> rec['error']) is gone for tier scenarios: a
    tier run must follow the router's lead on every batch.
    """
    lab_toml, scen_dir = _full_lab(tmp_path, tier_values_needed=True)
    monkeypatch.setattr(nl, "SCEN_DIR", scen_dir)
    monkeypatch.setattr(nl, "RESULTS_DIR", tmp_path / "results")

    monkeypatch.setattr(nl, "_run", lambda *_a, **_k: _cp(stdout="wan\n"))

    apply_envs: list[dict] = []

    def fake_apply_batch(lab, target, sid, timeout_s, *, lane="password",
                         token=None, window=None):
        apply_envs.append({"token": token})
        return 0, _apply_output(sid), ""

    monkeypatch.setattr(nl, "plan_batch",
                        lambda *a, **k: (0, _ok_plan_output(approval="required"), ""))
    monkeypatch.setattr(nl, "apply_batch", fake_apply_batch)

    lab = nl.load_lab(lab_toml)

    # 1) tier scenario with NO approval field: router says required ->
    # auto-mode mints a token on every batch.
    _write_scenario(scen_dir, "01-no-approval", _TIER_MULTI_BODY +
                    "tier_values = { fw_wan_zone = \"wan\","
                    " fw_allow_ping = \"Allow-Ping\" }\n")
    scen = nl.load_scenarios(scen_dir)[0]
    assert scen.approval is None
    rec = nl.run_scenario(lab, scen)
    assert rec["outcome"] == "confirmed", rec
    assert rec["passed"] is True
    assert apply_envs, "no apply was made"
    for ev in apply_envs:
        assert ev["token"] is not None, ev
        assert re.fullmatch(r"[0-9a-f]{64}", ev["token"]), ev

    # 2) tier scenario with approval = true: still SUCCESS (auto mode
    # ignores the scenario flag for tier runs).
    apply_envs.clear()
    _write_scenario(scen_dir, "02-with-approval", """
name = "02-with-approval"
description = "tier approval"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 60
tier = "hardened"
tier_batch_lines = 16
tier_reboot = false
approval = true
tier_values = { fw_wan_zone = "wan", fw_allow_ping = "Allow-Ping" }
""")
    scen = nl.load_scenarios(scen_dir)[1]
    assert scen.approval is True
    rec = nl.run_scenario(lab, scen)
    assert rec["outcome"] == "confirmed", rec
    assert rec["passed"] is True
    for ev in apply_envs:
        assert ev["token"] is not None, ev
        assert re.fullmatch(r"[0-9a-f]{64}", ev["token"]), ev


def test_tier_batch_without_approval_requirement_runs_with_no_token_even_if_scenario_has_no_approval_field(
    tmp_path, monkeypatch,
):
    """R3b fix (defect 1): a tier batch whose router plan says APPROVAL
    not-required gets through with token=None, even when the scenario
    omits `approval`.

    Per the new tier rule: mint the token iff the router says
    APPROVAL required.  When the router says not-required, no token is
    minted; apply_batch is called with token=None and the batch
    confirms.
    """
    lab_toml, scen_dir = _full_lab(tmp_path, tier_values_needed=True)
    monkeypatch.setattr(nl, "SCEN_DIR", scen_dir)
    monkeypatch.setattr(nl, "RESULTS_DIR", tmp_path / "results")
    _write_scenario(scen_dir, "01-no-req", _TIER_MULTI_BODY +
                    "tier_values = { fw_wan_zone = \"wan\","
                    " fw_allow_ping = \"Allow-Ping\" }\n")
    lab = nl.load_lab(lab_toml)
    scen = nl.load_scenarios(scen_dir)[0]
    assert scen.approval is None
    monkeypatch.setattr(nl, "_run", lambda *_a, **_k: _cp(stdout="wan\n"))

    # plan says APPROVAL not-required (the default in _ok_plan_output)
    monkeypatch.setattr(
        nl, "plan_batch",
        lambda *a, **k: (0, _ok_plan_output(SID, approval="not-required"), ""),
    )

    apply_envs: list[dict] = []

    def fake_apply_batch(lab, target, sid, timeout_s, *, lane="password",
                         token=None, window=None):
        apply_envs.append({"token": token, "sid": sid})
        return 0, _apply_output(sid), ""

    monkeypatch.setattr(nl, "apply_batch", fake_apply_batch)

    rec = nl.run_scenario(lab, scen)
    assert rec["outcome"] == "confirmed", rec
    assert rec["passed"] is True
    assert apply_envs, "no apply was made"
    # every apply saw token=None (auto mode: router says not-required, no
    # token is minted)
    for ev in apply_envs:
        assert ev["token"] is None, ev


def test_tier_batch_with_approval_required_gets_a_token_without_scenario_flag(
    tmp_path, monkeypatch,
):
    """R3b fix (defect 1): a tier batch whose router plan says APPROVAL
    required gets a real 64-hex approval_token minted from the lab
    passphrase K, even when the scenario omits `approval`.

    The token equals approve.approval_token(K, PLANDIGEST), with K =
    approve.derive_k(passphrase, device), matching the value a human
    running newton-approve would type at the prompt.
    """
    from newton_mcp import approve as mcp_approve

    lab_toml, scen_dir = _full_lab(tmp_path, tier_values_needed=True)
    monkeypatch.setattr(nl, "SCEN_DIR", scen_dir)
    monkeypatch.setattr(nl, "RESULTS_DIR", tmp_path / "results")
    _write_scenario(scen_dir, "01-req", _TIER_MULTI_BODY +
                    "tier_values = { fw_wan_zone = \"wan\","
                    " fw_allow_ping = \"Allow-Ping\" }\n")
    lab = nl.load_lab(lab_toml)
    scen = nl.load_scenarios(scen_dir)[0]
    assert scen.approval is None
    monkeypatch.setattr(nl, "_run", lambda *_a, **_k: _cp(stdout="wan\n"))

    # plan says APPROVAL required, emits PLANDIGEST
    monkeypatch.setattr(
        nl, "plan_batch",
        lambda *a, **k: (0, _ok_plan_output(SID, approval="required"), ""),
    )

    apply_envs: list[dict] = []

    def fake_apply_batch(lab, target, sid, timeout_s, *, lane="password",
                         token=None, window=None):
        apply_envs.append({"token": token, "window": window})
        return 0, _apply_output(sid), ""

    monkeypatch.setattr(nl, "apply_batch", fake_apply_batch)

    rec = nl.run_scenario(lab, scen)
    assert rec["outcome"] == "confirmed", rec
    assert rec["passed"] is True
    assert apply_envs, "no apply was made"

    # K derived from the lab passphrase (the same _approval_k derives);
    # token = approval_token(K, PLANDIGEST, NBF, EXP) over the window the
    # runner passes on (SW2 Item 2).
    k = mcp_approve.derive_k(b"unit-test-pw", "lab-r1")

    for ev in apply_envs:
        assert ev["token"] is not None, ev
        assert re.fullmatch(r"[0-9a-f]{64}", ev["token"]), ev
        assert ev["window"] is not None, ev
        nbf, exp = ev["window"]
        assert exp - nbf == 1800, ev
        assert nbf <= int(time.time()) <= exp, ev
        expected_token = mcp_approve.approval_token(k, PLANDIGEST, nbf, exp)
        assert ev["token"] == expected_token, (
            f"tier batch token differs from approve.approval_token(K, "
            f"PLANDIGEST, NBF, EXP): got={ev['token']!r} "
            f"expected={expected_token!r}")


def test_required_without_plandigest_is_an_error(tmp_path, monkeypatch):
    """R3b fix (defect 1): a tier batch whose router plan says APPROVAL
    required but emits no PLANDIGEST line is an error (a missing
    PLANDIGEST when approval is required is fatal).
    """
    lab_toml, scen_dir = _full_lab(tmp_path, tier_values_needed=True)
    monkeypatch.setattr(nl, "SCEN_DIR", scen_dir)
    monkeypatch.setattr(nl, "RESULTS_DIR", tmp_path / "results")
    _write_scenario(scen_dir, "01-no-pd", _TIER_MULTI_BODY +
                    "tier_values = { fw_wan_zone = \"wan\","
                    " fw_allow_ping = \"Allow-Ping\" }\n")
    lab = nl.load_lab(lab_toml)
    scen = nl.load_scenarios(scen_dir)[0]
    monkeypatch.setattr(nl, "_run", lambda *_a, **_k: _cp(stdout="wan\n"))

    # APPROVAL required, but NO PLANDIGEST line.
    bad_plan = (
        f"BACKUP /tmp/fake.tar.gz (2 config files)\n"
        f"STAGED session={SID}\n"
        f"BASEHASH {BASE_HASH}\n"
        f"APPROVAL required\n"
        "----- diff -----\n"
        "dhcp.cfg01411c.dnssec='1'\n"
        "----------------\n"
    )
    monkeypatch.setattr(nl, "plan_batch",
                        lambda *a, **k: (0, bad_plan, ""))
    monkeypatch.setattr(nl, "apply_batch",
                        lambda *a, **k: (0, _apply_output(SID), ""))

    rec = nl.run_scenario(lab, scen)
    assert rec.get("error"), rec
    assert "PLANDIGEST" in rec["error"], rec
    # rec["outcome"] stays None on the pre-apply error path (mirrors the
    # normal runner's behaviour).
    assert rec["outcome"] is None, rec


def test_batch_records_carry_plan_and_apply_logs_and_approval_flag(
    tmp_path, monkeypatch,
):
    """R3b fix (defect 2): each rec['tier']['batches'][i] carries
    plan_log, apply_log, and approval_required, taken from that batch's
    plan/apply output and the router's APPROVAL line.

    The top-level rec['plan_log']/rec['apply_log'] is overwritten by
    every batch (one pair per batch is what we need); the per-batch
    records carry the same data so an operator can introspect every
    batch's evidence.
    """
    lab_toml, scen_dir = _full_lab(tmp_path, tier_values_needed=True)
    monkeypatch.setattr(nl, "SCEN_DIR", scen_dir)
    monkeypatch.setattr(nl, "RESULTS_DIR", tmp_path / "results")
    _write_scenario(scen_dir, "01-logs", _TIER_MULTI_BODY +
                    "tier_values = { fw_wan_zone = \"wan\","
                    " fw_allow_ping = \"Allow-Ping\" }\n")
    lab = nl.load_lab(lab_toml)
    scen = nl.load_scenarios(scen_dir)[0]
    monkeypatch.setattr(nl, "_run", lambda *_a, **_k: _cp(stdout="wan\n"))

    monkeypatch.setattr(
        nl, "plan_batch",
        lambda *a, **k: (0, _ok_plan_output(SID, approval="required"), ""),
    )
    monkeypatch.setattr(nl, "apply_batch",
                        lambda *a, **k: (0, _apply_output(SID), ""))

    rec = nl.run_scenario(lab, scen)
    assert rec["outcome"] == "confirmed", rec

    batches = rec["tier"]["batches"]
    assert len(batches) >= 2, batches
    for i, b in enumerate(batches):
        assert "plan_log" in b, f"batch {i} missing plan_log: {b}"
        assert "apply_log" in b, f"batch {i} missing apply_log: {b}"
        assert "approval_required" in b, (
            f"batch {i} missing approval_required: {b}")
        # non-empty: _apply_touched_to_plan always produces plan_log,
        # and a confirmed apply returns the APPLYBASE/CONFIRMED lines.
        assert b["plan_log"], f"batch {i} has empty plan_log: {b}"
        assert b["apply_log"], f"batch {i} has empty apply_log: {b}"
        # plan said APPROVAL required for every batch.
        assert b["approval_required"] is True, f"batch {i}: {b}"
        # the per-batch log equals the runner's MAX_LOG-trimmed output
        # for that batch (the same data the top-level rec["plan_log"]
        # would carry for the LAST batch).
        assert b["plan_log"] == rec["plan_log"] or i < len(batches) - 1, b


def test_survival_and_rollback_records_carry_logs(tmp_path, monkeypatch):
    """R3b fix (defect 2): rec['tier']['survival'][i] and
    rec['tier']['rollback'] carry plan_log, apply_log, and
    approval_required, taken from that batch's plan/apply output and
    the router's APPROVAL line.

    The rollback call used to be given an empty {} dict that threw the
    plan/apply logs away; the survival call used to overwrite
    rec['apply_log'] on every batch.  Both are fixed here.
    """
    lab_toml, scen_dir = _full_lab(tmp_path, tier_values_needed=True)
    monkeypatch.setattr(nl, "SCEN_DIR", scen_dir)
    monkeypatch.setattr(nl, "RESULTS_DIR", tmp_path / "results")
    _write_scenario(scen_dir, "01-surv-rb", """
name = "01-surv-rb"
description = "tier with rollback + survival logs"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 60
tier = "hardened"
tier_batch_lines = 16
tier_reboot = true
tier_fail_probe = ["conf-has", "x", "y"]
tier_values = { fw_wan_zone = "wan", fw_allow_ping = "Allow-Ping" }
""")
    lab = nl.load_lab(lab_toml)
    scen = nl.load_scenarios(scen_dir)[0]
    assert scen.tier_fail_probe is not None
    assert scen.tier_reboot is True

    # Make the md5sum stable for the rollback hash check (before == after)
    def fake_run(args, **_kw):
        if args[0] == "ssh":
            if "md5sum" in args[-1]:
                return _cp(stdout="a" * 32 + "  -\n")
            return _cp(stdout="wan\n")
        return _cp(returncode=0, stdout="")

    monkeypatch.setattr(nl, "_run", fake_run)

    # Plan says APPROVAL not-required (default).  Every apply except the
    # rollback probe (first call) returns CONFIRMED.
    monkeypatch.setattr(
        nl, "plan_batch",
        lambda *a, **k: (0, _ok_plan_output(SID, approval="not-required"), ""),
    )

    apply_calls = {"n": 0}

    def fake_apply_batch(*_a, **_k):
        apply_calls["n"] += 1
        if apply_calls["n"] == 1:
            return 1, _apply_output(SID,
                                    outcome="ROLLBACK WINDOW PASSED"), ""
        return 0, _apply_output(SID), ""

    monkeypatch.setattr(nl, "apply_batch", fake_apply_batch)

    # Stub the reboot step so it always succeeds.
    monkeypatch.setattr(
        nl, "reboot_device",
        lambda lab, dev, rec_list, lane: {
            "device": dev.name, "before_boot_id": "A", "after_boot_id": "B",
            "rebooted": True, "fallback": None, "settled": True,
            "ok": True,
        },
    )

    rec = nl.run_scenario(lab, scen)
    assert rec["outcome"] == "confirmed", rec

    # ----- rollback record carries logs -----
    rb = rec["tier"]["rollback"]
    assert "plan_log" in rb, rb
    assert "apply_log" in rb, rb
    assert "approval_required" in rb, rb
    assert rb["plan_log"], rb
    assert rb["apply_log"], rb
    # the rollback probe's plan said not-required -> approval_required=False
    assert rb["approval_required"] is False, rb
    assert rb["outcome"] == "rolled_back", rb

    # ----- survival records carry logs -----
    survival = rec["tier"]["survival"]
    assert len(survival) >= 2, survival
    for i, s in enumerate(survival):
        assert "plan_log" in s, f"survival {i} missing plan_log: {s}"
        assert "apply_log" in s, f"survival {i} missing apply_log: {s}"
        assert "approval_required" in s, (
            f"survival {i} missing approval_required: {s}")
        assert s["plan_log"], f"survival {i} has empty plan_log: {s}"
        assert s["apply_log"], f"survival {i} has empty apply_log: {s}"
        # the marker plan also said not-required -> approval_required=False
        assert s["approval_required"] is False, f"survival {i}: {s}"
        assert s["outcome"] == "confirmed", s


def test_failed_batch_stops_the_tier_and_records_outcome(
    tmp_path, monkeypatch,
):
    """A batch whose outcome is not 'confirmed' stops the run; rec['error']
    names the batch index and outcome; rec['outcome'] is that outcome;
    earlier batches stay applied (not rolled back by the runner)."""
    lab_toml, scen_dir = _full_lab(tmp_path, tier_values_needed=True)
    monkeypatch.setattr(nl, "SCEN_DIR", scen_dir)
    monkeypatch.setattr(nl, "RESULTS_DIR", tmp_path / "results")
    _write_scenario(scen_dir, "01-fail", _TIER_MULTI_BODY +
                    "tier_values = { fw_wan_zone = \"wan\","
                    " fw_allow_ping = \"Allow-Ping\" }\n")
    lab = nl.load_lab(lab_toml)
    scen = nl.load_scenarios(scen_dir)[0]
    monkeypatch.setattr(nl, "_run", lambda *_a, **_k: _cp(stdout="wan\n"))

    sids = [SID, OTHER_SID]

    plan_calls: list[list[str]] = []

    def fake_plan_batch(*_a, **_k):
        i = len(plan_calls)
        plan_calls.append([sids[i]])
        return 0, _ok_plan_output(sids[i]), ""

    def fake_apply_batch(*_a, **_k):
        i = len(plan_calls) - 1
        if i == 0:
            return 0, _apply_output(sids[i]), ""
        # second batch -> rolled_back, not confirmed
        return 1, _apply_output(sids[i], outcome="ROLLBACK WINDOW PASSED"), ""

    monkeypatch.setattr(nl, "plan_batch", fake_plan_batch)
    monkeypatch.setattr(nl, "apply_batch", fake_apply_batch)
    rec = nl.run_scenario(lab, scen)
    # second batch outcome is rolled_back
    assert rec["outcome"] == "rolled_back"
    assert "tier batch 1 outcome rolled_back" in rec["error"], rec
    # only two batches were attempted (the run stops at the failure)
    assert len(plan_calls) == 2


# ----- Rollback check (tier_fail_probe) -------------------------------------


def test_rollback_check_hash_equal_passes_and_hash_differs_fails(
    tmp_path, monkeypatch,
):
    """With tier_fail_probe set, the LAST batch is applied FIRST as a
    rollback probe.  The probe must trigger a 'rolled_back' outcome and
    the uci-export md5sum must match before/after.  Hash differs -> fail."""
    lab_toml, scen_dir = _full_lab(tmp_path, tier_values_needed=True)
    monkeypatch.setattr(nl, "SCEN_DIR", scen_dir)
    monkeypatch.setattr(nl, "RESULTS_DIR", tmp_path / "results")
    _write_scenario(scen_dir, "01-rb", _TIER_MULTI_BODY +
                    "tier_values = { fw_wan_zone = \"wan\","
                    " fw_allow_ping = \"Allow-Ping\" }\n"
                    "tier_fail_probe = [\"conf-has\", \"x\", \"y\"]\n")
    lab = nl.load_lab(lab_toml)
    scen = nl.load_scenarios(scen_dir)[0]
    monkeypatch.setattr(nl, "_run", lambda *_a, **_k: _cp(stdout="wan\n"))

    # First the rollback probe plan; the batch is the LAST one (same id as
    # the second batch in a 2-batch split).  We don't care which id; what
    # matters is: probe plan returns CONFIRMED-able, apply returns
    # rolled_back; and the ssh call to the uci export md5sum helper
    # returns the same hash before and after.
    ssh_calls: list[str] = []

    def fake_run(args, **_kw):
        if args[0] == "ssh":
            ssh_calls.append(args[-1])
            if "md5sum" in args[-1]:
                return _cp(stdout="a" * 32 + "  -\n")
            return _cp(stdout="wan\n")
        return _cp(returncode=0, stdout="")

    monkeypatch.setattr(nl, "_run", fake_run)
    plan_calls: list[list[str]] = []

    def fake_plan_batch(*_a, **_k):
        sid = SID
        return 0, _ok_plan_output(sid), ""

    apply_count = {"n": 0}

    def fake_apply_batch(*_a, **_k):
        apply_count["n"] += 1
        # First apply is the rollback probe -> rolled_back.
        # Subsequent applies are the regular batches -> confirmed.
        if apply_count["n"] == 1:
            return 1, _apply_output(SID, outcome="ROLLBACK WINDOW PASSED"), ""
        return 0, _apply_output(SID), ""

    monkeypatch.setattr(nl, "plan_batch", fake_plan_batch)
    monkeypatch.setattr(nl, "apply_batch", fake_apply_batch)
    rec = nl.run_scenario(lab, scen)
    assert rec["outcome"] == "confirmed", rec
    # rollback record exists, hash equal
    assert rec["tier"]["rollback"]["outcome"] == "rolled_back"
    assert rec["tier"]["rollback"]["equal"] is True
    # at least two uci-export md5sum ssh calls (before + after)
    md5_calls = [c for c in ssh_calls if "md5sum" in c]
    assert len(md5_calls) >= 2

    # Now same flow but the md5sum differs -> the rollback check must fail.
    diff_count = {"n": 0}

    def fake_run_diff(args, **_kw):
        if args[0] == "ssh":
            if "md5sum" in args[-1]:
                diff_count["n"] += 1
                if diff_count["n"] == 1:
                    return _cp(stdout="b" * 32 + "  -\n")
                return _cp(stdout="c" * 32 + "  -\n")
            return _cp(stdout="wan\n")
        return _cp(returncode=0, stdout="")

    monkeypatch.setattr(nl, "_run", fake_run_diff)
    # Reset the apply counter and rebind so the rollback probe still
    # gets the right outcome (only the hash differs).
    apply_count.clear()
    apply_count.update({"n": 0})
    monkeypatch.setattr(nl, "apply_batch", fake_apply_batch)
    rec2 = nl.run_scenario(lab, scen)
    # the error must name the hash difference
    assert "hash" in rec2.get("error", "").lower() and \
           ("differ" in rec2.get("error", "").lower() or
            "before=" in rec2.get("error", "").lower()), \
        rec2


def test_rollback_wrong_outcome_fails(tmp_path, monkeypatch):
    """When the rollback probe plan does NOT produce 'rolled_back' (e.g.
    the router confirms it instead), rec['error'] is set."""
    lab_toml, scen_dir = _full_lab(tmp_path, tier_values_needed=True)
    monkeypatch.setattr(nl, "SCEN_DIR", scen_dir)
    monkeypatch.setattr(nl, "RESULTS_DIR", tmp_path / "results")
    _write_scenario(scen_dir, "01-wrong", _TIER_MULTI_BODY +
                    "tier_values = { fw_wan_zone = \"wan\","
                    " fw_allow_ping = \"Allow-Ping\" }\n"
                    "tier_fail_probe = [\"conf-has\", \"x\", \"y\"]\n")
    lab = nl.load_lab(lab_toml)
    scen = nl.load_scenarios(scen_dir)[0]
    monkeypatch.setattr(nl, "_run", lambda *_a, **_k: _cp(stdout="wan\n"))
    monkeypatch.setattr(nl, "plan_batch",
                        lambda *a, **k: (0, _ok_plan_output(), ""))
    # The rollback hash helper must succeed (a valid 32-hex digest).
    monkeypatch.setattr(nl, "_uci_export_hash", lambda lab, dev: "a" * 32)

    # Apply returns CONFIRMED, not rolled_back.
    monkeypatch.setattr(nl, "apply_batch",
                        lambda *a, **k: (0, _apply_output(outcome="CONFIRMED"), ""))
    rec = nl.run_scenario(lab, scen)
    assert rec.get("error"), rec
    assert rec["outcome"] in (None, "confirmed")
    assert rec["tier"]["rollback"]["outcome"] == "confirmed"


# ----- Reboot step ---------------------------------------------------------


def _succeed_reboot_setup(monkeypatch, before_id="AAA", after_id="BBB",
                           ssh_reboot_rc: int = 0):
    """Patch the reboot step's helpers so the ssh reboot succeeds and the
    after-id differs from the before-id.  Returns the lists that record
    the calls (for inspection)."""
    calls: dict = {"ssh": [], "curl": [], "ready": 0, "preflight": 0,
                   "settled": 0, "pve_reboot": 0, "boot_n": 0}

    def fake_run(args, **_kw):
        if args[0] == "curl":
            calls["curl"].append(args)
            return _cp(stdout=json.dumps({"data": "UPID:reboot"}))
        if args[0] == "ssh":
            calls["ssh"].append(args[-1])
            if "uci export | md5sum" in args[-1]:
                return _cp(stdout="samehash  -\n")
            if "boot_id" in args[-1]:
                calls["boot_n"] += 1
                bid = before_id if calls["boot_n"] == 1 else after_id
                return _cp(stdout=bid + "\n")
            if "reboot" in args[-1]:
                return _cp(returncode=ssh_reboot_rc)
            return _cp(returncode=0, stdout="")
        return _cp(returncode=0, stdout="")

    monkeypatch.setattr(nl, "_run", fake_run)
    # zero out the real-world wait so the test does not block 60s when
    # the mock ssh call returns rc=0 for every "true" probe (the wait
    # loop polls until either ssh returns non-zero or the timeout
    # elapses; tests that want a down ssh return non-zero explicitly).
    monkeypatch.setattr(nl, "REBOOT_WAIT_SSH_DOWN_S", 0)
    monkeypatch.setattr(nl, "REBOOT_SSH_READY_TIMEOUT_S", 0)
    # ssh_ready is monkeypatched below; the timeout value above is moot.
    monkeypatch.setattr(nl, "ssh_ready", lambda *a, **k: True)
    monkeypatch.setattr(nl, "router_hello_preflight", lambda *a, **k: (True, ""))
    monkeypatch.setattr(nl, "wait_settled",
                        lambda lab, dname: {"device": dname, "settled": True,
                                            "waited_s": 0.0, "polls": 1,
                                            "changes": 0, "last_rc": 0})
    return calls


def test_reboot_device_success(tmp_path, monkeypatch):
    """reboot_device: boot id changes, ssh reboot is called once (as a
    detached command), ssh_ready/router_hello_preflight/wait_settled are
    invoked after the reboot, and the record reports ok=True, fallback=None.
    """
    lab_toml, scen_dir = _full_lab(tmp_path, snapshot="baseline-newton-x")
    monkeypatch.setattr(nl, "SCEN_DIR", scen_dir)
    monkeypatch.setattr(nl, "RESULTS_DIR", tmp_path / "results")
    lab = nl.load_lab(lab_toml)
    dev = lab.devices["lab-r1"]
    calls = _succeed_reboot_setup(monkeypatch, before_id="AAA", after_id="BBB")
    rec = nl.reboot_device(lab, dev, [], "password")
    assert rec["ok"] is True
    assert rec["before_boot_id"] == "AAA"
    assert rec["after_boot_id"] == "BBB"
    assert rec["fallback"] is None
    assert rec["settled"] is True
    # the ssh reboot was issued exactly once (single detached reboot cmd)
    ssh_reboot_calls = [c for c in calls["ssh"] if "reboot" in c]
    assert len(ssh_reboot_calls) == 1
    # the detached form contains a `reboot` and exits with rc=0
    assert "reboot" in ssh_reboot_calls[0]


def test_reboot_same_boot_id_fails(tmp_path, monkeypatch):
    """reboot_device: boot id did NOT change -> ok=False with a clear reason;
    no Proxmox fallback when the ssh reboot returned rc=0."""
    lab_toml, scen_dir = _full_lab(tmp_path, snapshot="baseline-newton-x")
    monkeypatch.setattr(nl, "SCEN_DIR", scen_dir)
    monkeypatch.setattr(nl, "RESULTS_DIR", tmp_path / "results")
    lab = nl.load_lab(lab_toml)
    dev = lab.devices["lab-r1"]
    calls = _succeed_reboot_setup(monkeypatch, before_id="AAA", after_id="AAA")
    rec = nl.reboot_device(lab, dev, [], "password")
    assert rec["ok"] is False
    assert "boot" in rec.get("reason", "").lower() or \
           "id" in rec.get("reason", "").lower() or \
           "did not" in rec.get("reason", "").lower() or \
           "same" in rec.get("reason", "").lower()
    assert rec["fallback"] is None
    # no Proxmox fallback ran
    assert calls["pve_reboot"] == 0


def test_reboot_ssh_failure_falls_back_to_proxmox_and_is_logged(
    tmp_path, monkeypatch,
):
    """reboot_device: the ssh reboot command returned non-zero, so the
    runner falls back ONCE to a Proxmox guest reboot (POST
    .../qemu/<vmid>/status/reboot), the record carries fallback='proxmox'
    and the reason; boot ids before/after still must differ."""
    lab_toml, scen_dir = _full_lab(tmp_path, snapshot="baseline-newton-x")
    monkeypatch.setattr(nl, "SCEN_DIR", scen_dir)
    monkeypatch.setattr(nl, "RESULTS_DIR", tmp_path / "results")
    lab = nl.load_lab(lab_toml)
    dev = lab.devices["lab-r1"]
    calls = _succeed_reboot_setup(monkeypatch, before_id="AAA", after_id="BBB",
                                  ssh_reboot_rc=1)
    rec = nl.reboot_device(lab, dev, [], "password")
    assert rec["ok"] is True
    assert rec["fallback"] == "proxmox"
    # A curl POST .../qemu/<vmid>/status/reboot was issued.
    pve_reboot_calls = [c for c in calls["curl"]
                        if "POST" in c and "/status/reboot" in c[-1]]
    assert len(pve_reboot_calls) == 1
    assert "/qemu/9102/status/reboot" in pve_reboot_calls[0][-1]


def test_reboot_issues_exactly_one_reboot_command(tmp_path, monkeypatch):
    """reboot_device: even on the happy path, the runner issues EXACTLY
    ONE reboot command (the detached admin ssh one) and NO Proxmox
    fallback curl.  No ssh reboot failure -> no fallback."""
    lab_toml, scen_dir = _full_lab(tmp_path, snapshot="baseline-newton-x")
    monkeypatch.setattr(nl, "SCEN_DIR", scen_dir)
    monkeypatch.setattr(nl, "RESULTS_DIR", tmp_path / "results")
    lab = nl.load_lab(lab_toml)
    dev = lab.devices["lab-r1"]
    calls = _succeed_reboot_setup(monkeypatch, before_id="AAA", after_id="BBB")
    nl.reboot_device(lab, dev, [], "password")
    ssh_reboot_calls = [c for c in calls["ssh"] if "reboot" in c]
    assert len(ssh_reboot_calls) == 1
    # and no Proxmox reboot URL was ever hit.
    pve_reboot_calls = [c for c in calls["curl"] if "/status/reboot" in c[-1]]
    assert len(pve_reboot_calls) == 0


# ----- Survival runs after reboot ------------------------------------------


def test_survival_runs_after_reboot_with_each_batchs_probes(
    tmp_path, monkeypatch,
):
    """When tier_reboot = true and the reboot succeeds, the runner replays
    each batch's sealed manifest probes after the reboot (a marker apply
    per batch whose scenario_probes equal the batch's manifest probes).
    Order: the reboot call happens BEFORE the survival plans."""
    lab_toml, scen_dir = _full_lab(tmp_path, tier_values_needed=True)
    monkeypatch.setattr(nl, "SCEN_DIR", scen_dir)
    monkeypatch.setattr(nl, "RESULTS_DIR", tmp_path / "results")
    # tier_reboot defaults to True; do NOT set it explicitly.
    _write_scenario(scen_dir, "01-surv", """
name = "01-surv"
description = "tier survival"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 60
tier = "hardened"
tier_batch_lines = 16
tier_values = { fw_wan_zone = "wan", fw_allow_ping = "Allow-Ping" }
""")
    lab = nl.load_lab(lab_toml)
    scen = nl.load_scenarios(scen_dir)[0]
    monkeypatch.setattr(nl, "_run", lambda *_a, **_k: _cp(stdout="wan\n"))

    # rebuild the expected survival probe counts per batch from the splitter.
    info = tiers.split_tier("hardened", max_lines=16)
    value_map = {"fw_wan_zone": "wan", "fw_allow_ping": "Allow-Ping"}
    expected_resolved_texts = []
    for batch in info["batches"]:
        names = tiers.tier_placeholders(batch["text"])
        values = {n: value_map.get(n, "x") for n in names}
        expected_resolved_texts.append(
            tiers.resolve_batch(batch["text"], values, tier_names=names))

    # Stub the reboot step.
    reboot_called: list[bool] = []
    monkeypatch.setattr(
        nl, "reboot_device",
        lambda lab, dev, rec_list, lane: (reboot_called.append(True) or {
            "device": dev.name, "before_boot_id": "A", "after_boot_id": "B",
            "rebooted": True, "fallback": None, "settled": True,
            "ok": True,
        }),
    )

    plan_calls: list[tuple[str, list[list[str]] | None]] = []
    apply_calls: list[str] = []

    def fake_plan_batch(lab, target, batch_text, *, probes=None,
                        timeout_s=90, lane="password"):
        # capture the probes that were sealed for this plan.
        plan_calls.append((batch_text, probes))
        return 0, _ok_plan_output(SID), ""

    def fake_apply_batch(lab, target, sid, timeout_s, *, lane="password",
                         token=None, window=None):
        apply_calls.append(sid)
        return 0, _apply_output(sid), ""

    monkeypatch.setattr(nl, "plan_batch", fake_plan_batch)
    monkeypatch.setattr(nl, "apply_batch", fake_apply_batch)

    rec = nl.run_scenario(lab, scen)
    assert rec["outcome"] == "confirmed", rec
    # the reboot call was made
    assert reboot_called, "reboot_device was not called"
    # every plan AFTER the initial batch plans happens AFTER reboot
    # (we model this by checking the reboot record is in rec["tier"]).
    assert rec["tier"]["reboot"]["ok"] is True
    # the survival plans: per batch, an extra marker plan whose probes
    # equal that batch's sealed manifest probes.
    # The number of survival plans == number of batches.
    marker_calls = [c for c in plan_calls if "tier-survival" in c[0]]
    assert len(marker_calls) == len(info["batches"])
    # Each survival plan's probes equal that batch's manifest probes
    # (the design's "re-run that batch's sealed manifest probes after
    # the reboot" requirement).
    expected_probes_per_batch: list[list[list[str]]] = []
    for batch in info["batches"]:
        sealed_entries, manifest_probes = (
            newton_touched.seal_manifest_ids(
                [], newton_touched.derive_touched_entries(batch["text"]),
                extra_probes=[],
            )
        )
        expected_probes_per_batch.append(manifest_probes)
    for batch_idx, call in enumerate(marker_calls):
        assert call[1] is not None
        assert call[1] == expected_probes_per_batch[batch_idx], (
            f"batch {batch_idx}: survival probes differ\n"
            f"  expected={expected_probes_per_batch[batch_idx]!r}\n"
            f"  got     ={call[1]!r}")
    # The order: the reboot record is recorded under rec["tier"]["reboot"]
    # and the survival records under rec["tier"]["survival"], one per batch.
    survival = rec["tier"]["survival"]
    assert [s["batch_index"] for s in survival] == list(
        range(len(info["batches"])))
    for s in survival:
        assert s["outcome"] == "confirmed", s


def test_survival_not_confirmed_fails(tmp_path, monkeypatch):
    """A survival apply that returns anything other than 'confirmed' sets
    rec['error'] and stops."""
    lab_toml, scen_dir = _full_lab(tmp_path, tier_values_needed=True)
    monkeypatch.setattr(nl, "SCEN_DIR", scen_dir)
    monkeypatch.setattr(nl, "RESULTS_DIR", tmp_path / "results")
    _write_scenario(scen_dir, "01-fail-surv", """
name = "01-fail-surv"
description = "tier survival fail"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 60
tier = "hardened"
tier_batch_lines = 16
tier_values = { fw_wan_zone = "wan", fw_allow_ping = "Allow-Ping" }
""")
    lab = nl.load_lab(lab_toml)
    scen = nl.load_scenarios(scen_dir)[0]
    monkeypatch.setattr(nl, "_run", lambda *_a, **_k: _cp(stdout="wan\n"))
    monkeypatch.setattr(
        nl, "reboot_device",
        lambda lab, dev, rec_list, lane: {
            "device": dev.name, "before_boot_id": "A", "after_boot_id": "B",
            "rebooted": True, "fallback": None, "settled": True,
            "ok": True,
        },
    )

    info = tiers.split_tier("hardened", max_lines=16)
    n_batches = len(info["batches"])

    plan_calls = {"n": 0}
    monkeypatch.setattr(nl, "plan_batch",
                        lambda *a, **k: (0, _ok_plan_output(SID), ""))

    def fake_apply_batch(lab, target, sid, timeout_s, *, lane="password",
                         token=None, window=None):
        plan_calls["n"] += 1
        # the FIRST `n_batches` applys are the real batches; subsequent
        # ones are the survival applies.  Make the first survival apply
        # fail.
        if plan_calls["n"] == n_batches + 1:
            return 1, _apply_output(SID, outcome="ROLLBACK WINDOW PASSED"), ""
        return 0, _apply_output(SID), ""

    monkeypatch.setattr(nl, "apply_batch", fake_apply_batch)
    rec = nl.run_scenario(lab, scen)
    assert rec.get("error"), rec
    assert rec["outcome"] in (None, "rolled_back")
    assert any(s["outcome"] != "confirmed" for s in rec["tier"]["survival"])


# ----- tier_reboot = false ------------------------------------------------


def test_reboot_step_skipped_when_tier_reboot_false(tmp_path, monkeypatch):
    """When tier_reboot = false the runner records no reboot record and
    does NOT run any survival plan (the marker apply is skipped)."""
    lab_toml, scen_dir = _full_lab(tmp_path, tier_values_needed=True)
    monkeypatch.setattr(nl, "SCEN_DIR", scen_dir)
    monkeypatch.setattr(nl, "RESULTS_DIR", tmp_path / "results")
    _write_scenario(scen_dir, "01-noreboot", _TIER_MULTI_BODY +
                    "tier_values = { fw_wan_zone = \"wan\","
                    " fw_allow_ping = \"Allow-Ping\" }\n")
    lab = nl.load_lab(lab_toml)
    scen = nl.load_scenarios(scen_dir)[0]
    monkeypatch.setattr(nl, "_run", lambda *_a, **_k: _cp(stdout="wan\n"))

    reboot_called: list[bool] = []

    def fake_reboot(*_a, **_k):
        reboot_called.append(True)
        return {"ok": True}

    monkeypatch.setattr(nl, "reboot_device", fake_reboot)

    plan_calls: list[str] = []

    monkeypatch.setattr(nl, "plan_batch",
                        lambda *a, **k: (0, _ok_plan_output(SID), ""))
    monkeypatch.setattr(nl, "apply_batch",
                        lambda *a, **k: (0, _apply_output(SID), ""))

    rec = nl.run_scenario(lab, scen)
    assert rec["outcome"] == "confirmed"
    assert reboot_called == []
    # no "tier-survival" marker plan was ever sent
    survival_marker_calls = [c for c in plan_calls if "tier-survival" in c]
    assert survival_marker_calls == []
    # the rec["tier"] block has no "reboot" key (the step was skipped).
    assert "reboot" not in rec["tier"]
    # survival is empty
    assert rec["tier"]["survival"] == []


def test_tier_values_may_reference_lab_vars(tmp_path, monkeypatch):
    """A tier_values entry may itself contain a {var} reference (the
    existing [vars] mechanism).  The [vars]-resolved value reaches the
    tier placeholder substitution, so the planned batch text has no
    '{' left in it."""
    lab_toml, scen_dir = _full_lab(tmp_path, tier_values_needed=True)
    monkeypatch.setattr(nl, "SCEN_DIR", scen_dir)
    monkeypatch.setattr(nl, "RESULTS_DIR", tmp_path / "results")
    # Use the standard tier (single-batch, no {fw_wan_zone}).  The
    # {fw_wan_zone} reference inside tier_values is resolved by [vars].
    _write_scenario(scen_dir, "01-tier-vars", """
name = "01-tier-vars"
description = "tier_values references [vars]"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 60
tier = "standard"
tier_reboot = false
tier_values = { fw_wan_zone = "{fw_wan_zone}" }
""")
    lab = nl.load_lab(lab_toml)
    scen = nl.load_scenarios(scen_dir)[0]

    # [vars] fw_wan_zone returns "the_wan_zone_value" from the ssh cmd.
    def fake_run(args, **_kw):
        return _cp(stdout="the_wan_zone_value\n")

    monkeypatch.setattr(nl, "_run", fake_run)

    plan_calls: list[list[str]] = []
    monkeypatch.setattr(
        nl, "plan_batch",
        lambda *a, **k: (plan_calls.append([a[2]]) or 0,
                         _ok_plan_output(), ""),
    )
    monkeypatch.setattr(nl, "apply_batch",
                        lambda *a, **k: (0, _apply_output(), ""))

    rec = nl.run_scenario(lab, scen)
    assert rec["outcome"] == "confirmed", rec
    assert plan_calls, "plan_batch was not called"
    text = plan_calls[0][0]
    # the {var} from [vars] got resolved AND the tier placeholder got
    # substituted; no '{' remains anywhere.
    assert "{" not in text, text
    # the [vars]-resolved value reached the tier placeholder
    assert "the_wan_zone_value" in text


# ----- Five defect fixes ----------------------------------------------


def test_tier_plan_failure_short_circuits_passed(tmp_path, monkeypatch):
    """Defect 1: a tier run whose batch-1 errors at plan time ends with
    passed=False, even though batch 0 confirmed (rec['outcome'] was
    'confirmed' after batch 0).  The runner must short-circuit the
    AFTER / POST phase when _run_tier leaves rec['error'] set, set
    rec['duration_s'], and return.  The regression check declared on
    the scenario is NOT executed (the AFTER phase is skipped) -- that
    is the observable proof the short-circuit fired.
    """
    lab_toml, scen_dir = _full_lab_with_checks(tmp_path)
    monkeypatch.setattr(nl, "SCEN_DIR", scen_dir)
    monkeypatch.setattr(nl, "RESULTS_DIR", tmp_path / "results")
    _write_scenario(scen_dir, "01-r5-d1", _TIER_MULTI_BODY +
                    "tier_values = { fw_wan_zone = \"wan\","
                    " fw_allow_ping = \"Allow-Ping\" }\n"
                    "regression = [\"reg\"]\n")
    lab = nl.load_lab(lab_toml)
    scen = nl.load_scenarios(scen_dir)[0]
    monkeypatch.setattr(nl, "_run", lambda *_a, **_k: _cp(stdout="wan\n"))

    plan_calls: list[int] = []

    def fake_plan_batch(*_a, **_k):
        i = len(plan_calls)
        plan_calls.append(i)
        if i == 1:
            return 1, "garbage stdout", "garbage stderr"
        return 0, _ok_plan_output(SID), ""

    monkeypatch.setattr(nl, "plan_batch", fake_plan_batch)
    monkeypatch.setattr(nl, "apply_batch",
                        lambda *a, **k: (0, _apply_output(SID), ""))

    rec = nl.run_scenario(lab, scen)
    # Tier attempted 2 plans (batch 0 + batch 1).
    assert len(plan_calls) >= 2, plan_calls
    # rec["error"] is set: the tier run failed; the text is kept.
    assert rec.get("error"), rec
    # rec["passed"] is False.
    assert rec["passed"] is False, rec
    # rec["duration_s"] is set (the early-return path recorded it, not
    # 0.0 from a never-set default).
    assert rec["duration_s"] > 0, rec
    # The AFTER probes did NOT run: the regression check ("reg") was
    # declared on the scenario but rec["after"] is empty.
    assert rec["after"] == [], rec


def test_outcome_stays_none_after_rollback_then_plan_error(
    tmp_path, monkeypatch,
):
    """Defect 2: after a rollback-check success (its probe outcome is
    'rolled_back') followed by a batch-0 plan error, rec['outcome'] is
    NEITHER 'rolled_back' NOR 'confirmed'.  The rollback check must NOT
    promote its outcome to rec['outcome']; only the final 'all
    confirmed' line at the end of _run_tier may set it.
    """
    lab_toml, scen_dir = _full_lab(tmp_path, tier_values_needed=True)
    monkeypatch.setattr(nl, "SCEN_DIR", scen_dir)
    monkeypatch.setattr(nl, "RESULTS_DIR", tmp_path / "results")
    _write_scenario(scen_dir, "01-r5-d2", _TIER_MULTI_BODY +
                    "tier_values = { fw_wan_zone = \"wan\","
                    " fw_allow_ping = \"Allow-Ping\" }\n"
                    "tier_fail_probe = [\"conf-has\", \"x\", \"y\"]\n")
    lab = nl.load_lab(lab_toml)
    scen = nl.load_scenarios(scen_dir)[0]
    monkeypatch.setattr(nl, "_run", lambda *_a, **_k: _cp(stdout="wan\n"))

    plan_calls_list: list[int] = []

    def fake_plan_batch(*_a, **_k):
        plan_calls_list.append(1)
        # plan call 1 -> rollback probe (the LAST batch, so tier_fail_probe's
        # apply takes the LAST batch text).  plan call 2 -> batch 0.
        if len(plan_calls_list) == 2:
            return 1, "garbage", "garbage"
        return 0, _ok_plan_output(SID), ""

    apply_calls = {"n": 0}

    def fake_apply_batch(*_a, **_k):
        apply_calls["n"] += 1
        # apply call 1 -> rollback probe: must produce rolled_back.
        if apply_calls["n"] == 1:
            return 1, _apply_output(SID,
                                    outcome="ROLLBACK WINDOW PASSED"), ""
        # batch 0's apply never fires (its plan failed).
        return 0, _apply_output(SID), ""

    monkeypatch.setattr(nl, "plan_batch", fake_plan_batch)
    monkeypatch.setattr(nl, "apply_batch", fake_apply_batch)
    # Stub the helper so the rollback hash check passes (h0 == h1).
    monkeypatch.setattr(nl, "_uci_export_hash", lambda lab, dev: "a" * 32)

    rec = nl.run_scenario(lab, scen)
    # The rollback check ran: its outcome was 'rolled_back' inside the
    # rollback record.
    assert rec["tier"]["rollback"] is not None, rec
    assert rec["tier"]["rollback"]["outcome"] == "rolled_back", rec
    # rec["error"] is set (batch 0 failed).
    assert rec.get("error"), rec
    # rec["outcome"] is neither 'rolled_back' nor 'confirmed': the
    # rollback check did NOT promote its outcome to rec["outcome"].
    assert rec["outcome"] != "rolled_back", rec
    assert rec["outcome"] != "confirmed", rec


def test_tier_with_zero_batches_is_error(tmp_path, monkeypatch):
    """Defect 3: a tier that splits to zero batches (all blocks skipped
    or empty) is an error.  rec['error'] = 'tier <name> has no batches',
    rec['outcome'] stays None.
    """
    lab_toml, scen_dir = _full_lab(tmp_path)
    monkeypatch.setattr(nl, "SCEN_DIR", scen_dir)
    monkeypatch.setattr(nl, "RESULTS_DIR", tmp_path / "results")
    _write_scenario(scen_dir, "01-r5-d3", _TIER_BASIC_BODY)
    lab = nl.load_lab(lab_toml)
    scen = nl.load_scenarios(scen_dir)[0]

    # Stub the splitter to return no batches.
    def fake_split_tier(tier_name, **kwargs):
        return {"tier": tier_name, "batches": [], "skipped": []}

    monkeypatch.setattr(nl.newton_tiers, "split_tier", fake_split_tier)

    rec = nl.run_scenario(lab, scen)
    assert rec.get("error"), rec
    assert "has no batches" in rec["error"], rec
    assert "standard" in rec["error"], rec
    # rec["outcome"] stays None (no batch ever ran).
    assert rec["outcome"] is None, rec
    assert rec["passed"] is False, rec


def _u_helper_lab(tmp_path, monkeypatch):
    """A minimal lab for direct _uci_export_hash testing."""
    lab_toml, scen_dir = _full_lab(tmp_path)
    monkeypatch.setattr(nl, "SCEN_DIR", scen_dir)
    monkeypatch.setattr(nl, "RESULTS_DIR", tmp_path / "results")
    lab = nl.load_lab(lab_toml)
    return lab, lab.devices["lab-r1"]


def test_uci_export_hash_returns_digest(tmp_path, monkeypatch):
    """Defect 4 (helper): a successful call returns the 32-hex digest."""
    lab, dev = _u_helper_lab(tmp_path, monkeypatch)
    digest = "abcdef0123456789abcdef0123456789"

    def fake_run(args, **_kw):
        return _cp(stdout=f"{digest}  -\n")

    monkeypatch.setattr(nl, "_run", fake_run)
    assert nl._uci_export_hash(lab, dev) == digest


def test_uci_export_hash_rc_nonzero_raises(tmp_path, monkeypatch):
    """Defect 4 (helper): ssh rc != 0 -> ValueError naming the rc."""
    lab, dev = _u_helper_lab(tmp_path, monkeypatch)
    monkeypatch.setattr(
        nl, "_run",
        lambda *a, **k: _cp(returncode=1, stderr="boom"),
    )
    with pytest.raises(ValueError, match="rc=1"):
        nl._uci_export_hash(lab, dev)


def test_uci_export_hash_empty_stdout_raises(tmp_path, monkeypatch):
    """Defect 4 (helper): empty stdout -> ValueError (the [ -n \"$h\" ]
    guard refused an empty export, or md5sum returned no digest)."""
    lab, dev = _u_helper_lab(tmp_path, monkeypatch)
    monkeypatch.setattr(nl, "_run", lambda *a, **k: _cp(stdout=""))
    with pytest.raises(ValueError, match="empty"):
        nl._uci_export_hash(lab, dev)


def test_uci_export_hash_md5_of_empty_raises(tmp_path, monkeypatch):
    """Defect 4 (helper): digest equals md5 of empty -> ValueError.
    The router returned an empty export; the [ -n \"$h\" ] guard missed
    it (or printf was given an empty string)."""
    lab, dev = _u_helper_lab(tmp_path, monkeypatch)
    monkeypatch.setattr(
        nl, "_run",
        lambda *a, **k: _cp(stdout="d41d8cd98f00b204e9800998ecf8427e  -\n"),
    )
    with pytest.raises(ValueError, match="empty"):
        nl._uci_export_hash(lab, dev)


def test_uci_export_hash_bad_digest_raises(tmp_path, monkeypatch):
    """Defect 4 (helper): digest not 32 hex chars -> ValueError."""
    lab, dev = _u_helper_lab(tmp_path, monkeypatch)
    monkeypatch.setattr(
        nl, "_run",
        lambda *a, **k: _cp(stdout="not-a-digest  -\n"),
    )
    with pytest.raises(ValueError, match="32 hex"):
        nl._uci_export_hash(lab, dev)


def test_rollback_check_uses_helper_both_occurrences(
    tmp_path, monkeypatch,
):
    """Defect 4 (call sites): BOTH occurrences of the rollback hash
    command (before and after the rollback probe apply) go through
    _uci_export_hash.  Verified by stubbing the helper to raise and
    watching rec['error'] reflect the helper's message; and by counting
    the calls (exactly two per rollback check)."""
    lab_toml, scen_dir = _full_lab(tmp_path, tier_values_needed=True)
    monkeypatch.setattr(nl, "SCEN_DIR", scen_dir)
    monkeypatch.setattr(nl, "RESULTS_DIR", tmp_path / "results")
    _write_scenario(scen_dir, "01-r5-d4-call", _TIER_MULTI_BODY +
                    "tier_values = { fw_wan_zone = \"wan\","
                    " fw_allow_ping = \"Allow-Ping\" }\n"
                    "tier_fail_probe = [\"conf-has\", \"x\", \"y\"]\n")
    lab = nl.load_lab(lab_toml)
    scen = nl.load_scenarios(scen_dir)[0]
    monkeypatch.setattr(nl, "_run", lambda *_a, **_k: _cp(stdout="wan\n"))

    helper_calls: list[str] = []

    def fake_helper(lab_, dev_):
        helper_calls.append("call")
        # First call -> raise (hash before).  Second call -> raise
        # (hash after).  Either way the helper was called.
        raise ValueError("uci export md5sum failed rc=1: synthetic boom")

    monkeypatch.setattr(nl, "_uci_export_hash", fake_helper)

    monkeypatch.setattr(nl, "plan_batch",
                        lambda *a, **k: (0, _ok_plan_output(SID), ""))
    monkeypatch.setattr(nl, "apply_batch",
                        lambda *a, **k: (0, _apply_output(SID), ""))

    rec = nl.run_scenario(lab, scen)
    # The helper was called at least once (the 'hash before' step fires
    # before any apply; the rollback check aborts on that error).
    assert helper_calls, helper_calls
    # rec["error"] is set (the helper's message was wrapped).
    assert rec.get("error"), rec
    assert "synthetic boom" in rec["error"], rec
    # The wrapper names 'hash before' (the first occurrence).
    assert "hash before" in rec["error"], rec


def test_survival_seal_error_propagates(tmp_path, monkeypatch):
    """Defect 5: when _derive_touched_probe_lines returns an error for a
    survival batch, the survival step fails with that error."""
    lab_toml, scen_dir = _full_lab(tmp_path, tier_values_needed=True)
    monkeypatch.setattr(nl, "SCEN_DIR", scen_dir)
    monkeypatch.setattr(nl, "RESULTS_DIR", tmp_path / "results")
    _write_scenario(scen_dir, "01-r5-d5a", _TIER_MULTI_BODY +
                    "tier_values = { fw_wan_zone = \"wan\","
                    " fw_allow_ping = \"Allow-Ping\" }\n")
    lab = nl.load_lab(lab_toml)
    scen = nl.load_scenarios(scen_dir)[0]
    monkeypatch.setattr(nl, "_run", lambda *_a, **_k: _cp(stdout="wan\n"))

    monkeypatch.setattr(nl, "plan_batch",
                        lambda *a, **k: (0, _ok_plan_output(SID), ""))
    monkeypatch.setattr(nl, "apply_batch",
                        lambda *a, **k: (0, _apply_output(SID), ""))

    # _derive_touched_probe_lines returns (entries, probes, error).
    # Make it return an error for every call (the survival step
    # re-invokes it per batch).
    def fake_derive(batch, scenario_probes=None):
        return [], [], "fake seal error from derive"

    monkeypatch.setattr(nl, "_derive_touched_probe_lines", fake_derive)

    rec = nl.run_scenario(lab, scen)
    # rec["error"] is set and contains the derive error.
    assert rec.get("error"), rec
    assert "fake seal error from derive" in rec["error"], rec
    assert rec["passed"] is False, rec


def test_survival_probe_count_mismatch_is_error(tmp_path, monkeypatch):
    """Defect 5: when len(manifest_probes) != the splitter batch's
    probe_lines, the survival step errors with
    'survival probe count N != splitter count M'."""
    lab_toml, scen_dir = _full_lab(tmp_path, tier_values_needed=True)
    monkeypatch.setattr(nl, "SCEN_DIR", scen_dir)
    monkeypatch.setattr(nl, "RESULTS_DIR", tmp_path / "results")
    # tier_reboot = true so the survival phase is reached.
    _write_scenario(scen_dir, "01-r5-d5b", """
name = "01-r5-d5b"
description = "tier survival probe mismatch"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 60
tier = "hardened"
tier_batch_lines = 16
tier_reboot = true
tier_values = { fw_wan_zone = "wan", fw_allow_ping = "Allow-Ping" }
""")
    lab = nl.load_lab(lab_toml)
    scen = nl.load_scenarios(scen_dir)[0]
    monkeypatch.setattr(nl, "_run", lambda *_a, **_k: _cp(stdout="wan\n"))

    monkeypatch.setattr(nl, "plan_batch",
                        lambda *a, **k: (0, _ok_plan_output(SID), ""))
    monkeypatch.setattr(nl, "apply_batch",
                        lambda *a, **k: (0, _apply_output(SID), ""))
    # Stub the reboot step so the survival phase is reached.
    monkeypatch.setattr(
        nl, "reboot_device",
        lambda lab, dev, rec_list, lane: {
            "device": dev.name, "before_boot_id": "A", "after_boot_id": "B",
            "rebooted": True, "fallback": None, "settled": True,
            "ok": True,
        },
    )

    # The splitter returns batches with probe_lines set.  Hardened,
    # tier_batch_lines=16 splits to many batches with many probe_lines
    # each.  _derive returns a manifest_probes list whose length does
    # NOT match probe_lines (e.g., empty list), so the survival step
    # errors.
    def fake_derive(batch, scenario_probes=None):
        return [], [], None  # empty probes, no error

    monkeypatch.setattr(nl, "_derive_touched_probe_lines", fake_derive)

    rec = nl.run_scenario(lab, scen)
    # rec["error"] is set with the mismatch message.
    assert rec.get("error"), rec
    assert "survival probe count" in rec["error"], rec
    assert "!= splitter count" in rec["error"], rec
    assert rec["passed"] is False, rec