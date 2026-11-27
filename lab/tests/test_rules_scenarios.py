"""The lab runner runs the owner's network rules.

A scenario may carry the owner's own rules about the device's network.  The
runner writes them into a rules.toml the REAL loader reads (newton_mcp.
net_rules), turns them into the client claims the vantage runs (newton_mcp.
client_checks) and runs them like the scenario's own client checks: the same
spec file, the same OWRT_LOCAL_CHECK, the same failed-claim reporting.

Nothing here touches a router: the plan, the apply, the confirm and the
router's interface dump are answered by a fake subprocess wrapper, and the
vantage inventory is a synthetic file in a temp dir.
"""
from __future__ import annotations

from conftest import lab_toml_path

import copy
import json
import stat
import subprocess
import tomllib
from pathlib import Path
from unittest import mock

import pytest

import newton_lab_test as nl
from newton_mcp import client_checks
from newton_mcp import explanation

LAB_DIR = Path(__file__).resolve().parent.parent
LAB_TOML = lab_toml_path()
EVERYDAY_DIR = LAB_DIR / "scenarios" / "everyday"
HOLDS = "ev-clientcheck-block-holds"
RULES_01 = "ev-rules-01-hold-across-change"
RULES_02 = "ev-rules-02-break-is-rolled-back"
RULES_03 = "ev-rules-03-hold-confirm"
RULES_04 = "ev-rules-04-hold-break-before-confirm"
SID = "a" * 32
BASEHASH = "b" * 64

# The plan the fake wrapper answers with: a staged session with a diff the
# runner can read.
PLAN_OUT = (
    f"STAGED session={SID}\n"
    f"BASEHASH {BASEHASH}\n"
    "----- diff -----\n"
    "set foo=bar\n"
    "----------------\n"
)
APPLY_CONFIRMED = f"APPLYBASE {BASEHASH}\nCONFIRMED session={SID}"

# The router's own interface dump, as `ubus call network.interface dump`
# prints it: one private address on the lan.
DUMP = {
    "interface": [
        {
            "interface": "lan",
            "up": True,
            "ipv4-address": [{"address": "192.168.150.1", "mask": 24}],
        }
    ]
}


def _cp(stdout: str = "", stderr: str = "", returncode: int = 0):
    return subprocess.CompletedProcess(args=[], returncode=returncode,
                                       stdout=stdout, stderr=stderr)


@pytest.fixture(scope="module")
def lab():
    return nl.load_lab(LAB_TOML)


@pytest.fixture(scope="module")
def everyday():
    return {scen.name: scen for scen in nl.load_scenarios(EVERYDAY_DIR)}


def _inventory(tmp_path: Path) -> Path:
    """A synthetic vantage inventory: one inside vantage for the guest zone."""
    root = tmp_path / "vantage"
    root.mkdir()
    key = root / "scan-key"
    key.write_text("synthetic\n", encoding="utf-8")
    key.chmod(0o600)
    known_hosts = root / "known-hosts"
    known_hosts.write_text("synthetic\n", encoding="utf-8")
    inventory = root / "inventory.toml"
    inventory.write_text(
        f"""
[devices.lab-r1]
host = "10.109.0.11"

[vantages.lab-client]
host = "192.0.2.50"
user = "labuser"
key_file = "{key.as_posix()}"
known_hosts = "{known_hosts.as_posix()}"
proxy_command = "ssh -W %h:%p root@lab-proxy"
role = "inside"
devices = ["lab-r1"]

[[vantages.lab-client.zones]]
name = "guest"
src = "192.0.2.50"
canary = "192.0.2.1:53"
""",
        encoding="utf-8",
    )
    inventory.chmod(0o600)
    return inventory


def _scenario(tmp_path: Path, body: str, name: str = "rules-test"):
    """A scenario written to disk and loaded through the runner's loader."""
    directory = tmp_path / "scenarios"
    directory.mkdir(exist_ok=True)
    (directory / f"{name}.toml").write_text(body, encoding="utf-8")
    return nl.load_scenarios(directory)[0]


RULES_BODY = """
name = "rules-test"
description = "the owner's rules join the client checks"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 300
batch = "set foo=bar"

rules = [
  { id = "guest-internet", zone = "guest", kind = "internet" },
  { id = "guest-blocked", zone = "guest", kind = "blocked", to = "router" },
]
"""

# The same scenario with the one rule the guest zone has that names an
# address of its own: the guest zone reaches the router's DNS.
REACH_BODY = """
name = "rules-test"
description = "a reach rule joins the client claims"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 300
batch = "set foo=bar"

rules = [
  { id = "guest-reaches-router-dns", zone = "guest", kind = "reach", to = "192.168.30.1:53", label = "the guest zone reaches the router's DNS" },
]
"""


class _Runner:
    """The fake subprocess wrapper: it records every call and answers the
    plan, the apply and the router's interface dump."""

    def __init__(self, *, apply_out: str = APPLY_CONFIRMED,
                 plan_out: str = PLAN_OUT, dump: dict | None = None):
        self.calls: list[list[str]] = []
        self.specs: list[dict] = []
        self.envs: list[dict] = []
        self.apply_out = apply_out
        self.plan_out = plan_out
        self.dump = DUMP if dump is None else dump

    def __call__(self, args, **kw):
        args = list(args)
        self.calls.append(args)
        env = kw.get("env") or {}
        self.envs.append(dict(env))
        if args and args[0] == str(nl.OWRT_CHANGE):
            verb = args[1] if len(args) > 1 else ""
            if verb == "plan":
                return _cp(stdout=self.plan_out)
            if verb == "apply":
                # the vantage spec must be there while the apply runs
                spec_dir = env.get("NEWTON_VANTAGE_SPEC_DIR")
                if spec_dir:
                    spec = Path(spec_dir) / f"{SID}.json"
                    if spec.is_file():
                        self.specs.append(json.loads(spec.read_text()))
                return _cp(stdout=self.apply_out)
            return _cp()
        if args and "ubus call network.interface dump" in args[-1]:
            return _cp(stdout=json.dumps(self.dump))
        return _cp()


def _run(lab, scen, tmp_path, monkeypatch, fake: _Runner):
    """Run one scenario against the fake wrapper."""
    monkeypatch.setenv("NEWTON_LAB_VANTAGE_INVENTORY",
                       str(_inventory(tmp_path)))
    monkeypatch.setattr(nl, "RESULTS_DIR", tmp_path / "results")
    with mock.patch.object(nl, "_run", side_effect=fake):
        return nl.run_scenario(lab, scen)


# ---------- the loader is the real one ----------

def test_the_rules_go_through_the_real_loader(tmp_path, monkeypatch):
    """The runner writes a rules.toml and loads it with net_rules.load_rules:
    the loader's own rules decide what a rule is, and the runner adds only
    the device the scenario targets."""
    lab = nl.load_lab(LAB_TOML)
    scen = _scenario(tmp_path, RULES_BODY)
    seen: dict = {}
    real = nl.net_rules.load_rules

    def spy(path, known_devices=None):
        seen["path"] = Path(path)
        seen["known_devices"] = known_devices
        seen["mode"] = stat.S_IMODE(Path(path).stat().st_mode)
        seen["text"] = Path(path).read_text(encoding="utf-8")
        return real(path, known_devices)

    monkeypatch.setattr(nl.net_rules, "load_rules", spy)
    fake = _Runner()
    rec = _run(lab, scen, tmp_path, monkeypatch, fake)
    assert rec["passed"] is True
    assert seen["known_devices"] == {"lab-r1"}
    assert seen["mode"] == 0o600
    data = tomllib.loads(seen["text"])
    assert [rule["id"] for rule in data["rule"]] == ["guest-internet",
                                                      "guest-blocked"]
    assert {rule["device"] for rule in data["rule"]} == {"lab-r1"}


def test_the_rules_file_is_gone_after_the_run(tmp_path, monkeypatch):
    """The rules file lives in a fresh temp dir that the run removes."""
    lab = nl.load_lab(LAB_TOML)
    scen = _scenario(tmp_path, RULES_BODY)
    seen: dict = {}
    real = nl.net_rules.load_rules

    def spy(path, known_devices=None):
        seen["path"] = Path(path)
        seen["dir"] = Path(path).parent
        return real(path, known_devices)

    monkeypatch.setattr(nl.net_rules, "load_rules", spy)
    fake = _Runner()
    rec = _run(lab, scen, tmp_path, monkeypatch, fake)
    assert rec["passed"] is True
    assert not seen["dir"].exists()
    assert not seen["path"].exists()


def test_a_bad_rule_fails_the_run_with_the_loaders_own_message(tmp_path,
                                                                monkeypatch):
    """A rule the loader refuses stops the run before anything is applied,
    and the runner says what the loader said."""
    lab = nl.load_lab(LAB_TOML)
    scen = _scenario(tmp_path, RULES_BODY.replace(
        'kind = "internet"', 'kind = "internett"'))
    fake = _Runner()
    rec = _run(lab, scen, tmp_path, monkeypatch, fake)
    assert rec["passed"] is False
    assert rec["error"].startswith("rules could not be loaded: ")
    assert "kind must be one of" in rec["error"]
    # nothing was applied: the apply never ran
    assert not any(c[1:2] == ["apply"] for c in fake.calls)


def test_every_rule_is_written_with_the_target_as_its_device(tmp_path,
                                                              monkeypatch):
    """The rules of a scenario are the rules of its target: the device the
    runner writes is the scenario's target, whatever a rule says."""
    lab = nl.load_lab(LAB_TOML)
    scen = _scenario(tmp_path, RULES_BODY.replace(
        '{ id = "guest-internet", zone = "guest", kind = "internet" }',
        '{ id = "guest-internet", zone = "guest", kind = "internet", '
        'device = "quasar" }'))
    seen: dict = {}
    real = nl.net_rules.load_rules

    def spy(path, known_devices=None):
        seen["text"] = Path(path).read_text(encoding="utf-8")
        return real(path, known_devices)

    monkeypatch.setattr(nl.net_rules, "load_rules", spy)
    fake = _Runner()
    rec = _run(lab, scen, tmp_path, monkeypatch, fake)
    assert rec["passed"] is True
    data = tomllib.loads(seen["text"])
    assert {rule["device"] for rule in data["rule"]} == {"lab-r1"}


# ---------- the claims the vantage runs ----------

def test_the_rule_claims_join_the_scenarios_client_checks(tmp_path, monkeypatch):
    """The scenario's own client checks come first and the rule claims
    follow them: the vantage spec carries every claim, numbered in that
    order."""
    lab = nl.load_lab(LAB_TOML)
    body = RULES_BODY + """
[[client_checks]]
kind = "client_dhcp"
zone = "guest"
"""
    scen = _scenario(tmp_path, body)
    fake = _Runner()
    rec = _run(lab, scen, tmp_path, monkeypatch, fake)
    assert rec["passed"] is True
    assert len(fake.specs) == 1
    checks = fake.specs[0]["groups"][0]["checks"]
    assert [check["claim"] for check in checks] == [1, 2, 3]
    assert [check["kind"] for check in checks] == ["client_dhcp",
                                                   "client_internet",
                                                   "client_blocked"]
    # the rule's own marks stay in the claim: the spec carries the kind, the
    # target and the targets, never the rule's id
    assert "source" not in checks[1]
    assert "rule" not in checks[1]


def test_the_blocked_rule_gets_the_targets_the_server_derives(tmp_path,
                                                               monkeypatch):
    """A blocked rule about the router is checked against the router's own
    addresses: the targets are the ones client_checks.fill_targets derives
    from the router's interface dump."""
    lab = nl.load_lab(LAB_TOML)
    scen = _scenario(tmp_path, RULES_BODY)
    calls: list[int] = []
    real = nl.client_checks.fill_targets

    def spy(claims, dump_loader):
        calls.append(1)
        return real(claims, dump_loader)

    monkeypatch.setattr(nl.client_checks, "fill_targets", spy)
    fake = _Runner()
    rec = _run(lab, scen, tmp_path, monkeypatch, fake)
    assert rec["passed"] is True
    # the runner calls the server's own function, it does not copy it
    assert calls == [1]
    blocked = fake.specs[0]["groups"][0]["checks"][-1]
    assert blocked["kind"] == "client_blocked"
    assert blocked["to"] == "router"
    assert blocked["targets"] == ["192.168.150.1:22", "192.168.150.1:443",
                                  "192.168.150.1:80"]
    # the dump was read over the runner's own path, once
    dumps = [c for c in fake.calls
             if "ubus call network.interface dump" in c[-1]]
    assert len(dumps) == 1


def test_a_rule_claim_fails_like_an_agent_claim():
    """What failed_claim returns for a rule claim: the same words as an
    agent claim of the same kind.  The rule's id is not part of the text."""
    claims = [{"kind": "client_internet", "zone": "guest",
               "source": "rule", "rule": "guest-internet"}]
    log = (
        f"VERIFY DETAIL session={SID} round=3 exit=1 stage=local-check "
        "(last failed round; unknown)\n"
        f"VERIFY STDERR session={SID}: vantage-check: claim 1 FAIL no-internet\n"
    )
    failed = explanation.failed_claim(log, SID, [], claims)
    assert failed == {
        "claim": 1,
        "text": "expect claim 1 failed: client in zone guest reaches the "
        "internet (no-internet)",
    }
    # the rule's id is nowhere in the text
    assert "guest-internet" not in failed["text"]


# ---------- the validation of the field ----------

def test_the_rules_need_the_lab_router_a_long_timeout_and_no_tier(everyday):
    """The rules of a scenario follow the same rules as its client checks."""
    lab = nl.load_lab(LAB_TOML)
    scen = copy.copy(everyday[RULES_01])

    scen.target = "lab-client"
    errors = nl.validate_scenarios(lab, [scen])
    assert any("lab-r1" in error for error in errors), errors

    scen = copy.copy(everyday[RULES_01])
    scen.tier = "standard"
    errors = nl.validate_scenarios(lab, [scen])
    assert any("tier" in error for error in errors), errors

    scen = copy.copy(everyday[RULES_01])
    scen.timeout = client_checks.MIN_TIMEOUT_S - 1
    errors = nl.validate_scenarios(lab, [scen])
    assert any("timeout" in error for error in errors), errors


def test_the_rules_are_not_validated_as_agent_claims(everyday):
    """The agent's own Explanation refuses a claim that carries source or
    rule, so the rules of a scenario are checked by the loader alone: the
    validation says nothing about them."""
    lab = nl.load_lab(LAB_TOML)
    scen = copy.copy(everyday[RULES_01])
    # a rule the agent-form Explanation would refuse (it carries a key the
    # Explanation does not know) is not refused by the validation
    scen.rules = [dict(rule, source="rule") for rule in scen.rules]
    assert nl.validate_scenarios(lab, [scen]) == []


# ---------- the four scenarios ----------

def test_the_four_rule_scenarios_load_and_validate(lab, everyday):
    names = {RULES_01, RULES_02, RULES_03, RULES_04}
    assert names <= set(everyday)
    scen = [everyday[name] for name in sorted(names)]
    assert nl.validate_scenarios(lab, scen) == []


def test_the_rule_scenarios_carry_the_owners_three_rules(everyday):
    """Every one of the four carries the three rules the guest zone has."""
    for name in (RULES_01, RULES_02, RULES_03, RULES_04):
        scen = everyday[name]
        assert [(rule["id"], rule["zone"], rule["kind"])
                for rule in scen.rules][:3] == [
            ("guest-internet", "guest", "internet"),
            ("guest-dns", "guest", "dns"),
            ("guest-router-blocked", "guest", "blocked"),
        ]
        blocked = scen.rules[2]
        assert blocked["to"] == "router"


def test_the_two_holding_scenarios_carry_a_reach_rule(everyday):
    """The two of them whose batch keeps the guest forwarding carry one
    more rule: the guest zone reaches the router's own DNS."""
    for name in (RULES_01, RULES_03):
        rules = everyday[name].rules
        reach = [rule for rule in rules if rule["kind"] == "reach"]
        assert len(reach) == 1, rules
        assert reach[0]["id"] == "guest-reaches-router-dns"
        assert reach[0]["zone"] == "guest"
        assert reach[0]["to"] == "192.168.30.1:53"
        assert reach[0]["label"] == "the guest zone reaches the router's DNS"


def test_the_reach_rule_is_a_client_reaches_claim_with_the_owner_target(
        tmp_path, monkeypatch):
    """The reach rule goes through the real loader and the server's own
    fill_targets: the claim is a client_reaches claim and its target is the
    address the owner named."""
    lab = nl.load_lab(LAB_TOML)
    scen = _scenario(tmp_path, REACH_BODY)
    fake = _Runner()
    rec = _run(lab, scen, tmp_path, monkeypatch, fake)
    assert rec["passed"] is True
    checks = fake.specs[0]["groups"][0]["checks"]
    assert [check["kind"] for check in checks] == ["client_reaches"]
    assert checks[0]["to"] == "192.168.30.1:53"
    assert checks[0]["targets"] == ["192.168.30.1:53"]


def test_the_rule_scenarios_are_modelled_on_the_client_check_scenario(lab,
                                                                     everyday):
    """The same setup, cleanup, reset and probes as the scenario they are
    modelled on.  Their timeout is not the model's: the rules scenarios wait
    longer, because their rounds run the rules' checks as well."""
    model = everyday[HOLDS]
    for name in (RULES_01, RULES_02, RULES_03, RULES_04):
        scen = everyday[name]
        assert scen.target == model.target
        assert scen.reset == model.reset
        assert scen.setup == model.setup
        assert scen.cleanup == model.cleanup
        assert scen.probes == model.probes
        assert scen.timeout == 300
        assert scen.regression == model.regression


def test_the_break_scenario_leaves_out_the_guest_forwarding(everyday):
    """The batch of the break scenario is the batch of the holding one
    without the guest_wan forwarding: the guest zone cannot reach the
    internet, so the internet rule fails."""
    holds = everyday[RULES_01]
    breaks = everyday[RULES_02]
    assert breaks.expect == "rolled_back"
    assert holds.expect == "confirmed"
    removed = [line for line in holds.batch.splitlines()
               if line not in breaks.batch.splitlines()]
    assert removed == [
        "set firewall.guest_wan=forwarding",
        "set firewall.guest_wan.src='guest'",
        "set firewall.guest_wan.dest='wan'",
    ]
    assert breaks.expect_failed_claim is not None
    assert "reaches the internet" in breaks.expect_failed_claim


def test_the_break_scenario_pins_the_refused_confirm(everyday):
    """The refusal of EV-RULES-04's confirm is the wrapper's own words and
    they do not name the rule: the scenario pins them."""
    scen = everyday[RULES_04]
    assert scen.expect_confirm_refused == (
        "the local check failed before the confirm")


def test_the_hold_scenarios_hold(everyday):
    """C is A with a hold, D is C with a break before the confirm."""
    plain = everyday[RULES_01]
    held = everyday[RULES_03]
    broken = everyday[RULES_04]
    assert plain.hold is False
    assert held.hold is True
    assert held.expect == "confirmed"
    assert broken.hold is True
    assert broken.expect == "rolled_back"
    assert broken.before_confirm == ["vantage_internet_break"]
    assert held.before_confirm == []
    assert held.batch == plain.batch
    assert broken.batch == plain.batch
