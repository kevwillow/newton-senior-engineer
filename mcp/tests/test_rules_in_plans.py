"""The owner's network rules join every installed-OpenWrt plan.

The rules live in ``rules.toml`` next to the inventory and only the owner
writes them (``scripts/newton-rules``).  From 1.6.0 every installed-OpenWrt
plan carries the rules of the device it is for: the plan's ``expect`` ends
with the rules' client claims, they are sealed into the plan like the
agent's own claims, and a device whose rules cannot run (a broken rules
file, a zone with no registered vantage, a mode that cannot check them)
has its plan refused.  The reads still work.

RIP-08 to RIP-11 test the claim cap of the agent's own claims, a reach rule
that plans and whose check reaches the vantage, the words of a rule claim,
and a default plan and an undo on a device with rules.

Test IDs
  RIP-01 the rules of the device join the plan and are sealed into it;
  RIP-02 a broken rules file refuses the plan, and the reads still work;
  RIP-03 a rule zone with no registered vantage refuses the plan;
  RIP-04 a device that is not an installed OpenWrt router refuses the plan;
  RIP-05 the agent may not mark a claim as a rule;
  RIP-06 the approval text lists the rules and escapes their labels;
  RIP-07 a rules file changed after the plan does not change the apply;
  RIP-08 the claim cap counts the agent's claims only;
  RIP-09 a reach rule plans, and its check reaches the vantage;
  RIP-10 the words of a rule claim say what it is about;
  RIP-11 a default plan and an undo on a device with rules plan;
  RIP-12 a tier plan on a device with a rule plans with the minimum timeout.
  RIP-13 a rule whose target the zone's vantage may not probe refuses the
  plan.

Nothing here touches a device, a router or a vantage: every subprocess is
stubbed and every inventory is synthetic.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest

from exhelp import make_explanation, record_fields_display, tier_explained

import newton_mcp.approve as approve
import newton_mcp.server as server
from newton_mcp import net_rules
from newton_mcp.explanation import describe_claim
from newton_mcp.plan import compute_plan_hash
from test_undo_server import (  # noqa: F401
    AGENT, UNDO_SID, _confirmed_change, _install_fake_script,
)

SID = "fd595e20f2cd6c2b928fe3156f82d5db"
BATCH = "set dhcp.skilltest=host"
BASE_HASH = "8" * 64
ROUTER_DIGEST = "3" * 64
PROBES_SHA = "1" * 64

#: The agent's own claim: one client claim in the guest zone.
C_DNS = {"kind": "client_dns", "zone": "guest"}

#: A router claim of the agent's own: a plan with it carries no client claim
#: of the agent's, so the client claim of the plan is the rule's alone.
C_UCI = {"kind": "uci_equals", "path": "dhcp.skilltest.host", "equals": "host"}

DUMP = {
    "interface": [
        {
            "interface": "guest",
            "up": True,
            "ipv4-address": [{"address": "10.0.0.1", "mask": 8}],
        }
    ]
}

PLAN_OUTPUT = f"""BACKUP /tmp/newton-backup.tar.gz (2 config files)
STAGED session={SID} from f
BASEHASH {BASE_HASH}
PROBES 0 {PROBES_SHA}
PROFILE lab
APPROVAL not-required
PLANDIGEST {ROUTER_DIGEST}
----- diff -----
dhcp.skilltest='host'
----------------
"""

#: The two rules of the test device: one DNS rule and one blocked rule.
RULE_DNS = {"id": "r-dns", "device": "quasar", "zone": "guest", "kind": "dns"}
RULE_BLOCKED = {
    "id": "r-no-admin",
    "device": "quasar",
    "zone": "guest",
    "kind": "blocked",
    "to": "router",
    "label": "The guest zone cannot reach the router admin",
}


# ---- the fixtures ---------------------------------------------------------------


#: A synthetic pin (the sha256 of a fixed string): the shape matters, the
#: value does not, and no lab certificate's fingerprint belongs in git.
PIN = base64.b64encode(hashlib.sha256(b"newton-rules-in-plans-test-pin").digest()).decode()


def write_inventory(
    tmp_path,
    monkeypatch,
    *,
    zones=(("guest", "192.0.2.50"),),
    access="installed",
    check_targets=None,
):
    """The inventory: one lab device and one inside vantage for the zones."""
    key = tmp_path / "scan.key"
    key.write_text("synthetic-key", encoding="utf-8")
    key.chmod(0o600)
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("synthetic host key\n", encoding="utf-8")
    lines = [
        '[devices.quasar]',
        'platform = "openwrt"',
        'host = "192.0.2.1"',
        'user = "root"',
        'profile = "lab"',
        "lab = true",
    ]
    if access == "no-install":
        password_file = tmp_path / "rpcd-password"
        password_file.write_text("synthetic-password\n", encoding="utf-8")
        password_file.chmod(0o600)
        lines.append('access = "no-install"')
        lines.append(f'rpcd_password_file = "{password_file}"')
        lines.append(f'https_spki = "{PIN}"')
    else:
        lines.extend(
            [
                "",
                "[vantages.inside-a]",
                'host = "vantage.example.invalid"',
                'user = "newton"',
                f'key_file = "{key}"',
                f'known_hosts = "{known_hosts}"',
                'role = "inside"',
                'devices = ["quasar"]',
                "zones = [",
            ]
        )
        for name, src in zones:
            lines.append(
                f'  {{ name = "{name}", src = "{src}", canary = "192.0.2.1:53" }},'
            )
        lines.append("]")
        if check_targets is not None:
            rows = ", ".join(f'"{target}"' for target in check_targets)
            lines.append(f"check_targets = [ {rows} ]")
    inventory = tmp_path / "devices.toml"
    inventory.write_text("\n".join(lines) + "\n", encoding="utf-8")
    monkeypatch.setenv("NEWTON_INVENTORY", str(inventory))
    return inventory


def write_rules(tmp_path, rows, *, mode=0o644):
    """The rules file next to the inventory, written the way the owner writes it."""
    blocks = []
    for row in rows:
        lines = ["[[rule]]"]
        for key in ("id", "device", "zone", "kind", "to", "label"):
            value = row.get(key)
            if value is not None:
                lines.append(f"{key} = {json.dumps(value)}")
        blocks.append("\n".join(lines))
    path = tmp_path / "rules.toml"
    path.write_text("\n\n".join(blocks) + "\n", encoding="utf-8")
    path.chmod(mode)
    return path


def write_script_directory(tmp_path, monkeypatch):
    """The scripts directory with the vantage runner the apply needs."""
    home = tmp_path / "newton-home"
    scripts = home / "scripts"
    scripts.mkdir(parents=True)
    change = scripts / "owrt-change.sh"
    change.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    change.chmod(0o755)
    runner = scripts / "newton-vantage-run"
    runner.write_text("#!/usr/bin/env python3\nexit 0\n", encoding="utf-8")
    runner.chmod(0o755)
    monkeypatch.setenv("NEWTON_HOME", str(home))
    return scripts


def dump_result():
    return {
        "exit_code": 0,
        "stdout": {
            "kind": "untrusted-device-data",
            "source": "quasar:ubus call network.interface dump",
            "text": json.dumps(DUMP),
        },
        "stderr": {
            "kind": "untrusted-device-data",
            "source": "quasar:ubus call network.interface dump",
            "text": "",
        },
        "truncated": False,
    }


def plan(service, expect=None, *, timeout_s=180):
    """Plan one change with the given agent claims."""
    explanation = make_explanation(
        BATCH, expect=expect if expect is not None else [C_DNS]
    )
    return service.plan(
        "quasar",
        BATCH,
        timeout_s=timeout_s,
        explanation=explanation,
        owner_confirmed_in_chat=True,
    )


def stub_plan_script(monkeypatch):
    """The plan script returns a synthetic staged plan; nothing is contacted."""
    monkeypatch.setattr(
        server.NewtonService,
        "run_script",
        lambda *args, **kwargs: subprocess.CompletedProcess([], 0, PLAN_OUTPUT, ""),
    )


def stub_interface_dump(monkeypatch):
    """The router's interface dump, for the rules that name the router."""
    monkeypatch.setattr(
        server.NewtonService,
        "read",
        lambda self, device, command: dump_result(),
    )


def stored_record(tmp_path):
    """The plan record the planner wrote."""
    path = tmp_path / "state" / "plans" / f"{SID}.json"
    return json.loads(path.read_text(encoding="utf-8"))


# ---- RIP-01: the rules join the plan and are sealed into it ---------------------


def test_rip01_01_the_rules_of_the_device_join_the_stored_plan(tmp_path, monkeypatch):
    write_inventory(tmp_path, monkeypatch)
    write_rules(tmp_path, [RULE_DNS, RULE_BLOCKED])
    stub_plan_script(monkeypatch)
    stub_interface_dump(monkeypatch)
    planned = plan(server.NewtonService())
    record = stored_record(tmp_path)
    assert record["explanation"]["expect"] == [
        C_DNS,
        {"kind": "client_dns", "zone": "guest", "source": "rule", "rule": "r-dns"},
        {
            "kind": "client_blocked",
            "zone": "guest",
            "to": "router",
            "source": "rule",
            "rule": "r-no-admin",
            "targets": ["10.0.0.1:22", "10.0.0.1:443", "10.0.0.1:80"],
        },
    ]
    assert record["plan_hash"] == planned["plan_hash"]
    assert record["plan_hash"] == compute_plan_hash(record)


def test_rip01_02_a_rule_claim_edited_on_disk_changes_the_hash_and_the_apply_refuses(
    tmp_path, monkeypatch
):
    write_inventory(tmp_path, monkeypatch)
    write_rules(tmp_path, [RULE_DNS, RULE_BLOCKED])
    stub_plan_script(monkeypatch)
    stub_interface_dump(monkeypatch)
    planned = plan(server.NewtonService())
    record = stored_record(tmp_path)
    assert record["explanation"]["expect"][-1]["rule"] == "r-no-admin"
    record["explanation"]["expect"][-1]["rule"] = "r-other"
    assert compute_plan_hash(record) != planned["plan_hash"]
    (tmp_path / "state" / "plans" / f"{SID}.json").write_text(
        json.dumps(record), encoding="utf-8"
    )
    monkeypatch.setattr(
        server.NewtonService,
        "run_script",
        lambda *args, **kwargs: pytest.fail("must not run the change script"),
    )
    with pytest.raises(
        server.NewtonError, match="plan record was modified or is invalid"
    ):
        server.NewtonService().apply("quasar", SID)


def test_rip01_03_the_rule_claims_are_sealed_into_the_checks_the_vantage_runs(
    tmp_path, monkeypatch
):
    write_inventory(tmp_path, monkeypatch)
    write_rules(tmp_path, [RULE_DNS, RULE_BLOCKED])
    stub_plan_script(monkeypatch)
    stub_interface_dump(monkeypatch)
    plan(server.NewtonService())
    write_script_directory(tmp_path, monkeypatch)
    seen = {}

    def fake_run(self, device, *args, **kwargs):
        env = self.script_env(device)
        env.update(kwargs.get("extra_env") or {})
        spec = Path(env["NEWTON_VANTAGE_SPEC_DIR"]) / f"{SID}.json"
        seen["spec"] = json.loads(spec.read_text(encoding="utf-8"))
        return subprocess.CompletedProcess([], 0, f"CONFIRMED session={SID}", "")

    monkeypatch.setattr(server.NewtonService, "run_script", fake_run)
    result = server.NewtonService().apply("quasar", SID)
    assert result["result"] == "confirmed"
    assert seen["spec"]["groups"][0]["zone"] == "guest"
    assert seen["spec"]["groups"][0]["checks"] == [
        {"claim": 1, "kind": "client_dns"},
        {"claim": 2, "kind": "client_dns"},
        {
            "claim": 3,
            "kind": "client_blocked",
            "to": "router",
            "targets": ["10.0.0.1:22", "10.0.0.1:443", "10.0.0.1:80"],
        },
    ]


# ---- RIP-02: a broken rules file refuses the plan, the reads still work --------


def test_rip02_01_a_broken_rules_file_refuses_the_plan_and_the_read_still_works(
    tmp_path, monkeypatch
):
    write_inventory(tmp_path, monkeypatch)
    (tmp_path / "rules.toml").write_text("id = \n", encoding="utf-8")
    monkeypatch.setattr(
        server.NewtonService,
        "run_script",
        lambda *args, **kwargs: pytest.fail("must not run the change script"),
    )
    with pytest.raises(server.NewtonError) as err:
        plan(server.NewtonService())
    message = str(err.value)
    assert message.startswith("network rules: ")
    assert message.endswith("; nothing planned")
    # the reads are not gated by the rules file
    monkeypatch.setattr(
        server.subprocess,
        "run",
        lambda args, **kwargs: subprocess.CompletedProcess(args, 0, "dhcp.skilltest='host'", ""),
    )
    read = server.newton_read("quasar", "uci get dhcp.skilltest")
    assert read["exit_code"] == 0
    assert "dhcp.skilltest" in read["stdout"]["text"]


# ---- RIP-03: a rule zone with no registered vantage ----------------------------


def test_rip03_01_a_rule_zone_with_no_vantage_refuses_the_plan_naming_the_rule(
    tmp_path, monkeypatch
):
    write_inventory(tmp_path, monkeypatch, zones=(("guest", "192.0.2.50"),))
    write_rules(
        tmp_path,
        [dict(RULE_DNS, id="r-nowhere", zone="nowhere")],
    )
    monkeypatch.setattr(
        server.NewtonService,
        "run_script",
        lambda *args, **kwargs: pytest.fail("must not run the change script"),
    )
    with pytest.raises(server.NewtonError) as err:
        plan(server.NewtonService())
    message = str(err.value)
    assert "no inside vantage serves zone nowhere" in message
    assert "r-nowhere" in message


# ---- RIP-04: a device that is not an installed OpenWrt router --------------------


def test_rip04_01_a_no_install_device_with_a_rule_refuses_the_plan(tmp_path, monkeypatch):
    write_inventory(tmp_path, monkeypatch, access="no-install")
    write_rules(tmp_path, [RULE_DNS])
    with pytest.raises(server.NewtonError) as err:
        plan(server.NewtonService())
    assert str(err.value) == (
        "network rules: quasar has rules, and Newton cannot run them in this mode; "
        "nothing planned"
    )


# ---- RIP-05: the agent may not mark a claim as a rule ----------------------------


def test_rip05_01_an_agent_claim_carrying_a_rule_mark_is_refused(tmp_path, monkeypatch):
    write_inventory(tmp_path, monkeypatch)
    monkeypatch.setattr(
        server.NewtonService,
        "run_script",
        lambda *args, **kwargs: pytest.fail("must not run the change script"),
    )
    with pytest.raises(server.NewtonError) as err:
        plan(server.NewtonService(), [dict(C_DNS, source="rule")])
    message = str(err.value)
    assert "explanation.expect[0]" in message
    assert "source" in message


# ---- RIP-06: the approval text lists the rules ----------------------------------


def approval_record(expect):
    """A plan record whose stored explanation carries the given claims."""
    record = {
        "device": "quasar",
        "host": "192.0.2.1",
        "session_id": SID,
        "uci_batch": BATCH,
        "diff": "dhcp.skilltest='host'",
        "probes": [],
        "timeout_s": 180,
        "base_hash": BASE_HASH,
        "requires_approval": True,
        "router_digest": ROUTER_DIGEST,
        "explanation": {
            "intent": "Make the requested change the owner asked for.",
            "steps": ["Change line 1 does part of the requested change."],
            "expect": expect,
            "risk": "A wrong value could break the feature.",
        },
        "owner_confirmed_in_chat": True,
        "created_at": "2026-11-26T09:00:00+00:00",
        "staged_at": datetime.now(timezone.utc).isoformat(),
        **record_fields_display(),
    }
    record["plan_hash"] = compute_plan_hash(record)
    return record


def render(record):
    """The approval text of a plan record, as the dialog shows it."""
    explanation, digest = approve.validate_plan_for_approval(record)
    return approve.render_plan_text(SID, record, explanation, digest)


def test_rip06_01_the_approval_text_lists_the_rules_with_their_sentence_and_label(
    tmp_path, monkeypatch
):
    write_inventory(tmp_path, monkeypatch)
    write_rules(tmp_path, [RULE_DNS, RULE_BLOCKED])
    text = render(
        approval_record(
            [
                C_DNS,
                {"kind": "client_dns", "zone": "guest", "source": "rule", "rule": "r-dns"},
                {
                    "kind": "client_blocked",
                    "zone": "guest",
                    "to": "router",
                    "source": "rule",
                    "rule": "r-no-admin",
                    "targets": ["10.0.0.1:22"],
                },
            ]
        )
    )
    assert "Your network rules checked on this change:" in text
    assert "- r-dns: from guest: DNS names resolve through the zone router" in text
    assert (
        "- r-no-admin: from guest: router admin blocked "
        "(The guest zone cannot reach the router admin)"
    ) in text


def test_rip06_02_a_label_with_markup_or_a_control_character_is_refused_by_the_loader(
    tmp_path, monkeypatch
):
    """The loader refuses a label with markup or a control character: the
    rules file is refused whole, so no such label is ever read, and the
    approval text shows the rule without a label."""
    write_inventory(tmp_path, monkeypatch)
    path = write_rules(
        tmp_path,
        [dict(RULE_BLOCKED, label="<b>bold</b> and a bell\x07")],
    )
    with pytest.raises(net_rules.NetRuleError) as err:
        net_rules.load_rules(path)
    assert "label must be 1-80 characters" in str(err.value)
    text = render(
        approval_record(
            [
                {
                    "kind": "client_blocked",
                    "zone": "guest",
                    "to": "router",
                    "source": "rule",
                    "rule": "r-no-admin",
                    "targets": ["10.0.0.1:22"],
                }
            ]
        )
    )
    assert "<b>" not in text
    assert "\x07" not in text
    # the rule itself is still shown, without a label it may not carry
    assert "- r-no-admin: from guest: router admin blocked" in text


def test_rip06_03_the_label_of_the_approval_text_is_escaped(tmp_path, monkeypatch):
    """The label the approval text shows is escaped the way approve.py
    escapes every other piece of owner text: a control byte is printed as
    its escape and never reaches the terminal.

    The loader refuses such a label, so the escaping is called here with the
    label the approval text renders.
    """
    write_inventory(tmp_path, monkeypatch)
    label = "<b>bold</b> and a bell\x07"
    escaped = approve._sanitize_terminal_value(label)
    assert "\x07" not in escaped
    assert "\\x07" in escaped
    claim = {
        "kind": "client_blocked",
        "zone": "guest",
        "to": "router",
        "source": "rule",
        "rule": "r-no-admin",
        "targets": ["10.0.0.1:22"],
    }
    monkeypatch.setattr(
        approve, "_rule_labels", lambda rule_ids: {"r-no-admin": label}
    )
    lines = approve._rule_lines([claim])
    assert len(lines) == 1
    assert lines[0].startswith("- r-no-admin: from guest: router admin blocked")
    assert "\x07" not in lines[0]
    assert "\\x07" in lines[0]


# ---- RIP-07: the rules file changed after the plan -----------------------------


def test_rip07_01_a_rule_removed_after_the_plan_does_not_change_the_apply(
    tmp_path, monkeypatch
):
    write_inventory(tmp_path, monkeypatch)
    write_rules(tmp_path, [RULE_DNS, RULE_BLOCKED])
    stub_plan_script(monkeypatch)
    stub_interface_dump(monkeypatch)
    plan(server.NewtonService())
    # the owner removes one of the rules after the plan was made
    write_rules(tmp_path, [RULE_DNS])
    write_script_directory(tmp_path, monkeypatch)
    seen = {}

    def fake_run(self, device, *args, **kwargs):
        env = self.script_env(device)
        env.update(kwargs.get("extra_env") or {})
        spec = Path(env["NEWTON_VANTAGE_SPEC_DIR"]) / f"{SID}.json"
        seen["spec"] = json.loads(spec.read_text(encoding="utf-8"))
        return subprocess.CompletedProcess([], 0, f"CONFIRMED session={SID}", "")

    monkeypatch.setattr(server.NewtonService, "run_script", fake_run)
    result = server.NewtonService().apply("quasar", SID)
    assert result["result"] == "confirmed"
    assert seen["spec"]["groups"][0]["checks"] == [
        {"claim": 1, "kind": "client_dns"},
        {"claim": 2, "kind": "client_dns"},
        {
            "claim": 3,
            "kind": "client_blocked",
            "to": "router",
            "targets": ["10.0.0.1:22", "10.0.0.1:443", "10.0.0.1:80"],
        },
    ]


# ---- RIP-08: the claim cap counts the agent's claims only ------------------------


def test_rip08_01_sixteen_rules_and_eight_agent_claims_plan(tmp_path, monkeypatch):
    """The rule claims do not count toward the agent's claim cap: a device
    with the most rules it may have and an explanation with the most claims
    the agent may write still plans, and nothing is trimmed."""
    write_inventory(tmp_path, monkeypatch)
    write_rules(
        tmp_path,
        [
            {"id": f"r{index:02d}", "device": "quasar", "zone": "guest", "kind": "dns"}
            for index in range(16)
        ],
    )
    stub_plan_script(monkeypatch)
    stub_interface_dump(monkeypatch)
    planned = plan(server.NewtonService(), [C_DNS] * 8)
    record = stored_record(tmp_path)
    assert len(record["explanation"]["expect"]) == 24
    assert record["explanation"]["expect"][:8] == [C_DNS] * 8
    assert record["plan_hash"] == planned["plan_hash"]
    assert record["plan_hash"] == compute_plan_hash(record)


def test_rip08_02_nine_agent_claims_are_refused(tmp_path, monkeypatch):
    """The agent's own cap still stands: nine claims are refused, and
    nothing is planned."""
    write_inventory(tmp_path, monkeypatch)
    write_rules(tmp_path, [RULE_DNS])
    monkeypatch.setattr(
        server.NewtonService,
        "run_script",
        lambda *args, **kwargs: pytest.fail("must not run the change script"),
    )
    with pytest.raises(server.NewtonError):
        plan(server.NewtonService(), [C_DNS] * 9)
    plans = tmp_path / "state" / "plans"
    assert not plans.exists() or list(plans.glob("*.json")) == []


# ---- RIP-09: a reach rule --------------------------------------------------------


#: The rule the work laptop reaches the printer through.
RULE_REACH = {
    "id": "r-printer",
    "device": "quasar",
    "zone": "guest",
    "kind": "reach",
    "to": "10.0.0.50:631",
}

#: The claim the rule becomes.
C_REACHES = {
    "kind": "client_reaches",
    "zone": "guest",
    "to": "10.0.0.50:631",
    "source": "rule",
    "rule": "r-printer",
    "targets": ["10.0.0.50:631"],
}


def test_rip09_01_a_device_with_a_reach_rule_plans_and_the_claim_is_sealed(
    tmp_path, monkeypatch
):
    """A rule that says the client reaches an address is a claim Newton
    carries: the plan is made and the claim is sealed into it."""
    write_inventory(tmp_path, monkeypatch)
    write_rules(tmp_path, [RULE_REACH])
    stub_plan_script(monkeypatch)
    stub_interface_dump(monkeypatch)
    planned = plan(server.NewtonService())
    record = stored_record(tmp_path)
    assert record["explanation"]["expect"] == [C_DNS, C_REACHES]
    assert record["plan_hash"] == planned["plan_hash"]
    assert record["plan_hash"] == compute_plan_hash(record)


def test_rip09_02_the_vantage_spec_carries_the_reach_check(tmp_path, monkeypatch):
    """The reach check reaches the vantage: the spec the vantage runner
    reads names the claim and the target it is about."""
    write_inventory(tmp_path, monkeypatch)
    write_rules(tmp_path, [RULE_REACH])
    stub_plan_script(monkeypatch)
    stub_interface_dump(monkeypatch)
    plan(server.NewtonService())
    write_script_directory(tmp_path, monkeypatch)
    seen = {}

    def fake_run(self, device, *args, **kwargs):
        env = self.script_env(device)
        env.update(kwargs.get("extra_env") or {})
        spec = Path(env["NEWTON_VANTAGE_SPEC_DIR"]) / f"{SID}.json"
        seen["spec"] = json.loads(spec.read_text(encoding="utf-8"))
        return subprocess.CompletedProcess([], 0, f"CONFIRMED session={SID}", "")

    monkeypatch.setattr(server.NewtonService, "run_script", fake_run)
    result = server.NewtonService().apply("quasar", SID)
    assert result["result"] == "confirmed"
    assert seen["spec"]["groups"][0]["checks"] == [
        {"claim": 1, "kind": "client_dns"},
        {
            "claim": 2,
            "kind": "client_reaches",
            "to": "10.0.0.50:631",
            "targets": ["10.0.0.50:631"],
        },
    ]


def test_rip09_03_the_agent_may_not_claim_client_reaches(tmp_path, monkeypatch):
    """``client_reaches`` is a network rule's check: the agent may not
    write one, and the plan says so."""
    write_inventory(tmp_path, monkeypatch)
    monkeypatch.setattr(
        server.NewtonService,
        "run_script",
        lambda *args, **kwargs: pytest.fail("must not run the change script"),
    )
    with pytest.raises(server.NewtonError) as err:
        plan(
            server.NewtonService(),
            [{"kind": "client_reaches", "zone": "guest", "to": "10.0.0.50:631"}],
        )
    message = str(err.value)
    assert "explanation.expect[0]" in message
    assert "client_reaches is a network rule's check; the agent may not set it" in message


# ---- RIP-10: the words of a rule claim -------------------------------------------


def test_rip10_01_a_blocked_rule_claim_to_an_address_is_described_by_its_target():
    """A claim about one address is described by that address, not as
    "the internet"."""
    claim = {
        "kind": "client_blocked",
        "zone": "guest",
        "to": "10.0.0.50:631",
        "source": "rule",
        "rule": "r-printer",
        "targets": ["10.0.0.50:631"],
    }
    assert describe_claim(claim) == "10.0.0.50:631 blocked from guest"


def test_rip10_02_a_reach_rule_claim_is_described_as_reachable():
    """A claim that the client reaches an address says so."""
    claim = {
        "kind": "client_reaches",
        "zone": "guest",
        "to": "10.0.0.50:631",
        "source": "rule",
        "rule": "r-printer",
        "targets": ["10.0.0.50:631"],
    }
    assert describe_claim(claim) == "10.0.0.50:631 reachable from guest"


# ---- RIP-11: the timeout of a plan with client claims ----------------------------


def test_rip11_01_a_default_plan_on_a_device_with_a_rule_plans_with_the_minimum_timeout(
    tmp_path, monkeypatch
):
    """The caller gave no timeout: a plan that carries client claims takes
    the minimum the vantage round needs.

    The agent's own claim is a router claim, so the client claim of the plan
    is the rule's alone: the minimum comes from the rule.
    """
    write_inventory(tmp_path, monkeypatch)
    write_rules(tmp_path, [RULE_DNS])
    stub_plan_script(monkeypatch)
    stub_interface_dump(monkeypatch)
    explanation = make_explanation(BATCH, expect=[C_UCI])
    server.NewtonService().plan(
        "quasar",
        BATCH,
        explanation=explanation,
        owner_confirmed_in_chat=True,
    )
    record = stored_record(tmp_path)
    assert record["explanation"]["expect"] == [
        C_UCI,
        {"kind": "client_dns", "zone": "guest", "source": "rule", "rule": "r-dns"},
    ]
    assert record["timeout_s"] == 150


def test_rip11_02_an_undo_on_a_device_with_a_rule_plans(tmp_path, monkeypatch):
    """The undo takes no timeout of its own: on a device with rules it
    plans like any other change."""
    write_inventory(tmp_path, monkeypatch)
    write_rules(tmp_path, [RULE_DNS])
    monkeypatch.setenv("OWRT_AUDIT_LOG", str(tmp_path / "audit.log"))
    _original, current = _confirmed_change(tmp_path)
    _install_fake_script(monkeypatch, current)
    result = server.NewtonService().plan_undo("quasar", SID, AGENT, True)
    assert result["undo_of"] == SID
    record = json.loads(
        (tmp_path / "state" / "plans" / f"{UNDO_SID}.json").read_text(encoding="utf-8")
    )
    assert record["timeout_s"] == 150
    assert {
        "kind": "client_dns",
        "zone": "guest",
        "source": "rule",
        "rule": "r-dns",
    } in record["explanation"]["expect"]


def test_rip11_03_an_explicit_timeout_below_the_minimum_is_refused_with_a_rule(
    tmp_path, monkeypatch
):
    """A caller who names a timeout that is too short for the vantage round
    is refused, as before.

    The agent's own claim is a router claim, so the client claim of the plan
    is the rule's alone: the refusal comes from the rule.
    """
    write_inventory(tmp_path, monkeypatch)
    write_rules(tmp_path, [RULE_DNS])
    monkeypatch.setattr(
        server.NewtonService,
        "run_script",
        lambda *args, **kwargs: pytest.fail("must not run the change script"),
    )
    with pytest.raises(server.NewtonError) as err:
        plan(server.NewtonService(), [C_UCI], timeout_s=90)
    assert "timeout_s must be at least 150" in str(err.value)


# ---- RIP-12: a tier plan on a device with a rule ------------------------------


def test_rip12_01_a_tier_plan_on_a_device_with_a_rule_plans_with_the_minimum_timeout(
    tmp_path, monkeypatch
):
    """A tier plan names no timeout of its own: on a device with rules it
    plans like any other change and takes the time the vantage round needs."""
    write_inventory(tmp_path, monkeypatch)
    write_rules(tmp_path, [RULE_DNS])
    stub_plan_script(monkeypatch)
    stub_interface_dump(monkeypatch)
    values = {"fw_wan_zone": "wan"}
    server.NewtonService().plan_tier(
        "quasar",
        "standard",
        batch_index=0,
        values=values,
        **tier_explained("standard", 0, values),
    )
    record = stored_record(tmp_path)
    assert record["timeout_s"] == 150


def test_rip12_02_the_rules_note_is_said_once_in_the_server_instructions():
    """The note about the owner's rules is in the server instructions: the
    tool descriptions have a budget (the whole list stays under 31700
    characters) and the rules join EVERY plan, not one tool."""
    instructions = server.mcp.instructions
    # the rules join every installed-OpenWrt plan, from the zone's vantage
    assert "rules.toml" in instructions
    assert "join every installed-OpenWrt plan" in instructions
    assert "the registered inside vantage of the rule's zone" in instructions
    # a failed rule means no confirm; a rule that cannot run refuses the plan
    assert "A rule that fails means the change is not confirmed" in instructions
    assert "a rule that cannot run" in instructions
    assert "refuses the plan" in instructions
    # the rules' claims do not count against the 1-8, and the timeout is 150
    assert "do not count against your 1-8 claims" in instructions
    assert "timeout_s of 150" in instructions
    # the note is said once: in the instructions, and in no tool description
    assert instructions.count(server.NETWORK_RULES_NOTE) == 1
    for tool in asyncio.run(server.mcp.list_tools()):
        assert server.NETWORK_RULES_NOTE not in (tool.description or ""), tool.name


# ---- RIP-13: a rule the zone's vantage may not probe refuses the plan ------------


#: The ranges the vantage may probe: the guest zone of the lab router only.
NARROW_TARGETS = ("192.168.30.0/24",)


def test_rip13_01_a_rule_whose_target_the_vantage_may_not_probe_refuses_the_plan(
    tmp_path, monkeypatch
):
    """A rule that cannot run refuses the plan.

    The rule is blocked to the router, so its targets are the router's own
    addresses: one of them is outside the ranges the vantage may probe,
    the forced command would answer NOT-TESTED not-allowed, and the change
    would roll back after the whole window.
    """
    write_inventory(tmp_path, monkeypatch, check_targets=NARROW_TARGETS)
    write_rules(tmp_path, [RULE_BLOCKED])
    stub_interface_dump(monkeypatch)
    monkeypatch.setattr(
        server.NewtonService,
        "run_script",
        lambda *args, **kwargs: pytest.fail("must not run the change script"),
    )
    with pytest.raises(server.NewtonError) as err:
        plan(server.NewtonService())
    assert str(err.value) == (
        "client check 2 (r-no-admin) cannot run from vantage inside-a: "
        "10.0.0.1:22 is outside its check_targets; nothing planned"
    )
    # nothing is planned
    plans = tmp_path / "state" / "plans"
    assert not plans.exists() or list(plans.glob("*.json")) == []


def test_rip13_02_the_same_rule_plans_when_the_check_targets_cover_every_address(
    tmp_path, monkeypatch
):
    """The same rule, with the vantage's ranges covering the router's
    addresses, plans as before."""
    write_inventory(tmp_path, monkeypatch, check_targets=("10.0.0.0/8",))
    write_rules(tmp_path, [RULE_BLOCKED])
    stub_plan_script(monkeypatch)
    stub_interface_dump(monkeypatch)
    planned = plan(server.NewtonService())
    record = stored_record(tmp_path)
    assert record["explanation"]["expect"][-1]["targets"] == [
        "10.0.0.1:22",
        "10.0.0.1:443",
        "10.0.0.1:80",
    ]
    assert record["plan_hash"] == planned["plan_hash"]
