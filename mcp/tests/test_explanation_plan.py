"""the explanation and the owner's chat yes are required to plan, sit
inside the plan hash, and every change needs out-of-band approval (lab carve-out
in one named place).

Design: explanation rules 1-3.  The router is
faked at ``run_script``; nothing here reaches a device.
"""

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
from datetime import datetime, timedelta, timezone

import pytest

import newton_mcp.server as server
from exhelp import explained, make_explanation
from newton_mcp import approval_gate
from newton_mcp.plan import PLAN_HASH_FIELDS, compute_plan_hash

SID = "0123456789abcdef0123456789abcdef"
BASE = "b" * 64
DIGEST = "d" * 64
BATCH = "set dhcp.skilltest=host\nset dhcp.skilltest.name='skilltest'"
INVENTORY = """\
[devices.quasar]
platform = "openwrt"
host = "192.0.2.1"
user = "root"

[devices.labplain]
platform = "openwrt"
host = "192.0.2.2"
user = "root"
profile = "lab"

[devices.lab1]
platform = "openwrt"
host = "192.0.2.3"
user = "root"
profile = "lab"
lab = true
"""


def plan_output(*, router_requires=False):
    return (
        "BACKUP /tmp/fake.tar.gz (2 config files)\n"
        f"STAGED session={SID}\n"
        f"BASEHASH {BASE}\n"
        f"PROBES 0 {'a' * 64}\n"
        "PROFILE lab\n"
        f"SECTION dhcp skilltest host skilltest\n"
        f"APPROVAL {'required' if router_requires else 'not-required'}\n"
        f"PLANDIGEST {DIGEST}\n"
        "----- diff -----\n"
        "dhcp.skilltest='host'\n"
        "dhcp.skilltest.name='skilltest'\n"
        "----------------\n"
    )


@pytest.fixture
def env(tmp_path, monkeypatch):
    inventory = tmp_path / "devices.toml"
    inventory.write_text(INVENTORY)
    monkeypatch.setenv("NEWTON_INVENTORY", str(inventory))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))
    calls = []

    def fake(self, device, *args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, plan_output(), "")

    monkeypatch.setattr(server.NewtonService, "run_script", fake)
    return tmp_path, calls


def plan_call(device="quasar", batch=BATCH, **kw):
    return server.newton_plan_change(device, batch, **kw)


def stored(tmp_path):
    return json.loads((tmp_path / "state" / "plans" / f"{SID}.json").read_text())


# ---- required fields ---------------------------------------------------------


def test_missing_explanation_is_refused_with_a_next_step(env):
    tmp, calls = env
    result = plan_call(owner_confirmed_in_chat=True)
    assert "explanation" in result["error"]
    assert "intent" in result["error"] and "steps" in result["error"] and "expect" in result["error"] and "risk" in result["error"]
    assert calls == []
    assert not (tmp / "state" / "plans").exists() or not list((tmp / "state" / "plans").glob("*.json"))


@pytest.mark.parametrize("value", [None, False, "true", 1, "yes", 0])
def test_owner_confirmation_must_be_boolean_true(env, value):
    tmp, calls = env
    kw = explained(BATCH)
    kw["owner_confirmed_in_chat"] = value
    result = plan_call(**kw)
    assert "owner_confirmed_in_chat" in result["error"]
    assert "ask the owner" in result["error"].lower() or "ask them" in result["error"].lower()
    assert "explain" in result["error"].lower()
    assert calls == []


def test_omitted_owner_confirmation_is_refused(env):
    tmp, calls = env
    result = plan_call(explanation=make_explanation(BATCH))
    assert "owner_confirmed_in_chat" in result["error"]
    assert calls == []


def test_step_count_mismatch_is_refused_before_any_device_call_and_names_the_count(env):
    tmp, calls = env
    result = plan_call(**explained(BATCH, steps=["only one"]))
    assert "2 change lines" in result["error"] or "has 2" in result["error"]
    assert calls == []


def test_comments_and_blank_lines_are_not_change_lines(env):
    tmp, calls = env
    batch = "# why\nset dhcp.skilltest=host\n\nset dhcp.skilltest.name='skilltest'\n"
    assert "error" not in plan_call(**explained(batch))
    assert len(calls) == 1


def test_bad_claim_is_refused_before_any_device_call(env):
    tmp, calls = env
    result = plan_call(**explained(BATCH, expect=[{"kind": "shell", "cmd": "reboot"}]))
    assert "expect" in result["error"]
    assert calls == []


# ---- the record, the hash --------------------------------------------------------


def test_record_carries_the_masked_explanation_and_the_owner_flag(env):
    tmp, _ = env
    secret = "Hunter2-very-secret-value"
    result = plan_call(**explained(BATCH, intent=f"Set wireless.ap.key='{secret}' later"))
    assert "error" not in result, result
    record = stored(tmp)
    assert record["owner_confirmed_in_chat"] is True
    assert secret not in json.dumps(record)
    assert "<redacted:" in record["explanation"]["intent"]
    assert set(record["explanation"]) == {"intent", "steps", "expect", "risk"}
    assert record["plan_hash"] == compute_plan_hash(record)


def test_explanation_and_owner_flag_are_hash_fields():
    assert "explanation" in PLAN_HASH_FIELDS
    assert "owner_confirmed_in_chat" in PLAN_HASH_FIELDS


def _mutations():
    def intent(r): r["explanation"]["intent"] += "."
    def step(r): r["explanation"]["steps"][0] += "."
    def swap(r): r["explanation"]["steps"].reverse()
    def risk(r): r["explanation"]["risk"] += "."
    def claim_value(r): r["explanation"]["expect"][0] = {"kind": "uci_equals", "path": "dhcp.skilltest.name", "equals": "other"}
    def claim_add(r): r["explanation"]["expect"].append({"kind": "probe", "probe": ["iface-absent", "guesty"]})
    def owner(r): r["owner_confirmed_in_chat"] = False
    return [intent, step, swap, risk, claim_value, claim_add, owner]


@pytest.mark.parametrize("mutate", _mutations(), ids=lambda f: f.__name__)
def test_changing_any_explanation_field_changes_the_plan_hash(env, mutate):
    tmp, _ = env
    assert "error" not in plan_call(**explained(BATCH))
    record = stored(tmp)
    before = record["plan_hash"]
    changed = copy.deepcopy(record)
    mutate(changed)
    assert changed != record
    assert compute_plan_hash(changed) != before


def test_an_edited_explanation_on_disk_without_a_new_hash_is_refused_at_apply(env, monkeypatch):
    tmp, calls = env
    assert "error" not in plan_call(**explained(BATCH))
    record = stored(tmp)
    record["explanation"]["intent"] = "Something the owner never saw"
    (tmp / "state" / "plans" / f"{SID}.json").write_text(json.dumps(record))
    calls.clear()
    result = server.newton_apply_change("quasar", SID)
    assert "plan record was modified or is invalid" in result["error"]
    assert calls == []


def _write_approval(tmp, record, plan_hash=None):
    path = tmp / "state" / "approvals"
    path.mkdir(parents=True, exist_ok=True)
    (path / f"{SID}.json").write_text(json.dumps({
        "plan_id": SID,
        "plan_hash": plan_hash or record["plan_hash"],
        "device": record["device"],
        "base_hash": record["base_hash"],
        "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=20)).isoformat(),
        "token": "e" * 64,
    }))


def test_approval_of_the_old_hash_does_not_apply_to_a_changed_explanation(env):
    tmp, calls = env
    assert "error" not in plan_call(**explained(BATCH))
    old = stored(tmp)
    _write_approval(tmp, old)
    # the plan is re-recorded with a different explanation (and its own correct hash)
    new = copy.deepcopy(old)
    new["explanation"]["risk"] = "A different risk statement the owner never approved."
    new["plan_hash"] = compute_plan_hash(new)
    assert new["plan_hash"] != old["plan_hash"]
    (tmp / "state" / "plans" / f"{SID}.json").write_text(json.dumps(new))
    calls.clear()
    result = server.newton_apply_change("quasar", SID)
    assert "approval plan hash mismatch" in result["error"]
    assert calls == []


def test_apply_refuses_a_record_whose_explanation_is_not_valid(env):
    tmp, calls = env
    assert "error" not in plan_call(**explained(BATCH))
    record = stored(tmp)
    record["explanation"]["steps"] = ["one"]          # count no longer matches the batch
    record["plan_hash"] = compute_plan_hash(record)
    (tmp / "state" / "plans" / f"{SID}.json").write_text(json.dumps(record))
    _write_approval(tmp, record)
    calls.clear()
    result = server.newton_apply_change("quasar", SID)
    assert "explanation" in result["error"]
    assert calls == []


def test_apply_refuses_a_record_without_the_owner_confirmation(env):
    tmp, calls = env
    assert "error" not in plan_call(**explained(BATCH))
    record = stored(tmp)
    record["owner_confirmed_in_chat"] = False
    record["plan_hash"] = compute_plan_hash(record)
    (tmp / "state" / "plans" / f"{SID}.json").write_text(json.dumps(record))
    _write_approval(tmp, record)
    calls.clear()
    result = server.newton_apply_change("quasar", SID)
    assert "owner_confirmed_in_chat" in result["error"]
    assert calls == []


def test_a_pre_ex3_record_without_the_fields_is_refused(env):
    tmp, calls = env
    assert "error" not in plan_call(**explained(BATCH))
    record = stored(tmp)
    del record["explanation"]
    del record["owner_confirmed_in_chat"]
    (tmp / "state" / "plans" / f"{SID}.json").write_text(json.dumps(record))
    calls.clear()
    result = server.newton_apply_change("quasar", SID)
    assert "plan record was modified or is invalid" in result["error"]
    assert calls == []


def test_the_explanation_is_logged_to_the_audit_trail(env):
    tmp, _ = env
    intent_text = "Reserve an address for the printer"
    assert "error" not in plan_call(**explained(BATCH, intent=intent_text))
    log = (tmp / "state" / "mcp-audit.log").read_text()
    assert f"session={SID}" in log
    assert f"intent_len={len(intent_text)}" in log
    assert f"intent_sha256={hashlib.sha256(intent_text.encode('utf-8')).hexdigest()[:12]}" in log
    assert "Reserve an address for the printer" not in log
    assert "\x1b" not in log


# ---- every change needs out-of-band approval --------------------------------------


def test_prod_device_always_requires_approval(env):
    result = plan_call("quasar", **explained(BATCH))
    assert result["requires_approval"] is True and result["approval_required"] is True


def test_a_profile_lab_device_without_the_lab_flag_now_requires_approval(env):
    result = plan_call("labplain", **explained(BATCH))
    assert result["requires_approval"] is True


def test_a_lab_flagged_lab_profile_device_keeps_the_router_and_leash_rule(env):
    result = plan_call("lab1", **explained(BATCH))
    assert result["requires_approval"] is False


def test_lab_carve_out_still_requires_approval_when_the_router_says_so(env, monkeypatch):
    monkeypatch.setattr(
        server.NewtonService, "run_script",
        lambda self, device, *a, **k: subprocess.CompletedProcess(a, 0, plan_output(router_requires=True), ""),
    )
    assert plan_call("lab1", **explained(BATCH))["requires_approval"] is True


def test_the_carve_out_is_one_switch_and_turning_it_off_makes_lab_require_approval(env, monkeypatch):
    monkeypatch.setattr(approval_gate, "LAB_APPROVAL_CARVEOUT", False)
    assert plan_call("lab1", **explained(BATCH))["requires_approval"] is True


def test_gate_unit_cases():
    class D:
        def __init__(self, lab, profile):
            self.lab, self.profile = lab, profile

    assert approval_gate.plan_requires_approval(D(False, "prod"), router_requires=False, policy_requires=False) is True
    assert approval_gate.plan_requires_approval(D(False, "lab"), router_requires=False, policy_requires=False) is True
    assert approval_gate.plan_requires_approval(D(True, "prod"), router_requires=False, policy_requires=False) is True
    assert approval_gate.plan_requires_approval(D(True, "lab"), router_requires=False, policy_requires=False) is False
    assert approval_gate.plan_requires_approval(D(True, "lab"), router_requires=True, policy_requires=False) is True
    assert approval_gate.plan_requires_approval(D(True, "lab"), router_requires=False, policy_requires=True) is True


def test_apply_refuses_a_non_lab_record_that_says_no_approval_needed(env):
    tmp, calls = env
    assert "error" not in plan_call("quasar", **explained(BATCH))
    record = stored(tmp)
    record["requires_approval"] = False
    record["plan_hash"] = compute_plan_hash(record)       # a self-consistent forged record
    (tmp / "state" / "plans" / f"{SID}.json").write_text(json.dumps(record))
    calls.clear()
    result = server.newton_apply_change("quasar", SID)
    assert "requires approval" in result["error"] or "approval" in result["error"]
    assert calls == []


def test_apply_on_a_lab_flagged_device_without_approval_still_runs(env):
    tmp, calls = env
    assert "error" not in plan_call("lab1", **explained(BATCH))
    calls.clear()
    server.newton_apply_change("lab1", SID)
    assert len(calls) == 1


def test_openwrt_inventory_reads_the_lab_flag_and_only_true_counts(tmp_path, monkeypatch):
    inventory = tmp_path / "d.toml"
    monkeypatch.setenv("NEWTON_INVENTORY", str(inventory))
    for value, expected in (("true", True), ("false", False), ('"yes"', False), ("1", False)):
        inventory.write_text(
            f'[devices.a]\nplatform = "openwrt"\nhost = "h"\nuser = "root"\nlab = {value}\n'
        )
        assert server.load_inventory()["a"].lab is expected, value
    inventory.write_text('[devices.a]\nplatform = "openwrt"\nhost = "h"\nuser = "root"\n')
    assert server.load_inventory()["a"].lab is False


# ---- placeholder plans: one count, one representation ---------------------


PH_BATCH = "set wireless.default_radio0.key=<redacted:{fp}>\nset dhcp.skilltest=host"


def _placeholder_env(monkeypatch):
    from newton_mcp import envelope, redact

    redact.reset_key_cache()
    fp = redact.fingerprint("wireless.default_radio0.key", "fake-current-secret")
    monkeypatch.setattr(
        server.NewtonService, "read",
        lambda self, device, command: {
            "exit_code": 0,
            "stdout": envelope.envelope(f"{device}:{command}", f"<redacted:{fp}>\n"),
            "stderr": envelope.envelope(f"{device}:{command}", ""),
            "truncated": False,
        },
    )
    return PH_BATCH.format(fp=fp)


def _write_approval_for(tmp_path, record):
    approvals = tmp_path / "state" / "approvals"
    approvals.mkdir(parents=True, exist_ok=True)
    (approvals / f"{SID}.json").write_text(json.dumps({
        "plan_id": SID, "plan_hash": record["plan_hash"], "device": "quasar",
        "base_hash": record["base_hash"], "approved_by": "operator",
        "created_at": "2099-01-01T00:00:00+00:00", "expires_at": "2099-01-01T00:30:00+00:00",
        "not_before": 4070908800, "not_after": 4070910600,
        "token": "e" * 64,
    }))


def test_a_placeholder_plan_can_be_approved_and_applied(env, monkeypatch, capsys):
    import io

    import newton_mcp.approve as approve

    tmp, calls = env
    batch = _placeholder_env(monkeypatch)
    result = plan_call("quasar", batch, **explained(batch))      # two steps, two submitted lines
    assert "error" not in result, result

    class TTY(io.StringIO):
        def isatty(self):
            return True

    # newton-approve shows the plan (it re-validates the explanation first)
    monkeypatch.setattr(approve.sys, "stdin", TTY("no\n"))
    assert approve.main([SID]) == 1
    shown = capsys.readouterr()
    assert "Agent's explanation" in shown.out and "no valid explanation" not in shown.err

    # apply gets past the explanation re-check and reaches the router
    _write_approval_for(tmp, stored(tmp))
    calls.clear()
    monkeypatch.setattr(
        server.NewtonService, "run_script",
        lambda self, device, *a, **k: calls.append(a) or subprocess.CompletedProcess(a, 0, f"CONFIRMED session={SID}", ""),
    )
    applied = server.newton_apply_change("quasar", SID)
    assert applied.get("result") == "confirmed", applied
    assert len(calls) == 1


def test_a_placeholder_plan_with_the_wrong_step_count_is_still_refused(env, monkeypatch):
    tmp, calls = env
    batch = _placeholder_env(monkeypatch)
    one = plan_call("quasar", batch, **explained(batch, steps=["only the dhcp host"]))
    assert "steps has 1 entries" in one["error"]
    three = plan_call("quasar", batch, **explained(batch, steps=["a", "b", "c"]))
    assert "steps has 3 entries" in three["error"]
    assert calls == []


def test_a_stored_placeholder_record_with_a_dropped_step_is_refused_at_apply(env, monkeypatch):
    tmp, calls = env
    batch = _placeholder_env(monkeypatch)
    assert "error" not in plan_call("quasar", batch, **explained(batch))
    record = stored(tmp)
    record["explanation"]["steps"] = record["explanation"]["steps"][:1]
    record["plan_hash"] = compute_plan_hash(record)             # self-consistent forgery
    (tmp / "state" / "plans" / f"{SID}.json").write_text(json.dumps(record))
    _write_approval_for(tmp, record)
    calls.clear()
    assert "invalid explanation" in server.newton_apply_change("quasar", SID)["error"]
    assert calls == []


# ---- tiers ------------------------------------------------------------------------


def test_plan_tier_requires_the_same_fields_and_names_the_expected_count(env, monkeypatch):
    from newton_mcp import explanation as ex, tiers

    tmp, calls = env
    monkeypatch.setattr(server.NewtonService, "read", lambda self, d, c: {"exit_code": 1, "stdout": "", "stderr": "", "truncated": False})
    values = {"fw_wan_zone": "wan", "fw_allow_ping": "Allow-Ping"}
    info = tiers.split_tier("hardened")
    names = sorted({n for b in info["batches"] for n in tiers.tier_placeholders(b["text"])})
    text = tiers.resolve_batch(info["batches"][0]["text"], values, tier_names=names)
    count = ex.change_lines(text)
    assert count > 2

    result = server.newton_plan_tier("quasar", "hardened", 0, values)
    assert "owner_confirmed_in_chat" in result["error"]
    result = server.newton_plan_tier("quasar", "hardened", 0, values, owner_confirmed_in_chat=True)
    assert "explanation is required" in result["error"]
    result = server.newton_plan_tier("quasar", "hardened", 0, values, owner_confirmed_in_chat=True,
                                     explanation=make_explanation("set a.b=c"))
    assert f"{count} change lines" in result["error"]
    assert calls == []

    result = server.newton_plan_tier("quasar", "hardened", 0, values, owner_confirmed_in_chat=True,
                                     explanation=make_explanation(text))
    assert "error" not in result, result
    record = stored(tmp)
    assert len(record["explanation"]["steps"]) == count
    assert record["owner_confirmed_in_chat"] is True and record["plan_hash"] == compute_plan_hash(record)
