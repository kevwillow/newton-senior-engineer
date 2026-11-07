"""VC-16: client-check scenarios and the lab runner wiring."""
from __future__ import annotations

from conftest import lab_toml_path

import copy
import json
import stat
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
OPENWRT_ZONE = LAB_DIR / "scenarios" / "openwrt" / "ow-zone-01-guest.toml"
HOLDS = "ev-clientcheck-block-holds"
OPENS = "ev-clientcheck-block-opens"
SID = "a" * 32
TARGETS = [
    "192.168.30.1:22",
    "192.168.30.1:80",
    "192.168.30.1:443",
    "10.109.0.11:22",
    "10.109.0.11:443",
    "192.168.150.1:22",
    "192.168.150.1:443",
]


@pytest.fixture(scope="module")
def lab():
    return nl.load_lab(LAB_TOML)


@pytest.fixture(scope="module")
def client_scenarios():
    return {
        scen.name: scen
        for scen in nl.load_scenarios(EVERYDAY_DIR)
        if scen.name in {HOLDS, OPENS}
    }


@pytest.fixture
def claim_scenario():
    claims = [
        {"kind": "client_dns", "zone": "guest"},
        {
            "kind": "client_blocked",
            "zone": "guest",
            "to": "router",
            "targets": ["192.0.2.1:22"],
        },
    ]
    return nl.Scenario(
        name="client-check-test",
        description="",
        target="lab-r1",
        reset=[],
        expect="confirmed",
        timeout=180,
        batch="set firewall.guest_zone.input='REJECT'",
        post=[],
        path=Path("client-check-test.toml"),
        client_checks=claims,
    )


def _inventory(tmp_path: Path, *, serve_guest: bool = True) -> Path:
    root = tmp_path / "vantage"
    root.mkdir()
    key = root / "scan-key"
    key.write_text("synthetic\n", encoding="utf-8")
    key.chmod(0o600)
    known_hosts = root / "known-hosts"
    known_hosts.write_text("synthetic\n", encoding="utf-8")
    zones = ""
    if serve_guest:
        zones = """
[[vantages.lab-client.zones]]
name = "guest"
src = "192.0.2.50"
canary = "192.0.2.1:53"
"""
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
{zones}
""",
        encoding="utf-8",
    )
    inventory.chmod(0o600)
    return inventory


def test_the_two_client_check_scenarios_load_and_validate(lab, client_scenarios):
    assert set(client_scenarios) == {HOLDS, OPENS}
    assert nl.validate_scenarios(lab, list(client_scenarios.values())) == []


@pytest.mark.parametrize(
    "name,kinds,targets,failed_pattern",
    [
        (
            HOLDS,
            ["client_dns", "client_dhcp", "client_internet", "client_blocked"],
            TARGETS,
            None,
        ),
        (OPENS, ["client_blocked", "client_dns"], TARGETS, "open"),
    ],
)
def test_client_check_fields_are_parsed(
    client_scenarios, name, kinds, targets, failed_pattern
):
    scen = client_scenarios[name]
    assert [claim["kind"] for claim in scen.client_checks] == kinds
    blocked = [claim for claim in scen.client_checks if claim["kind"] == "client_blocked"]
    assert len(blocked) == 1
    assert blocked[0]["to"] == "router"
    assert blocked[0]["targets"] == targets
    if failed_pattern is None:
        assert scen.expect_failed_claim is None
    else:
        assert scen.expect_failed_claim is not None
        assert failed_pattern in scen.expect_failed_claim


@pytest.mark.parametrize(
    "change,message",
    [
        ({"client_checks": [{"kind": "client_unknown", "zone": "guest"}]}, "client_checks"),
        (
            {
                "client_checks": [
                    {"kind": "client_blocked", "zone": "guest", "to": "router"}
                ]
            },
            "targets",
        ),
        ({"timeout": 90}, "timeout"),
        ({"expect_failed_claim": "expect claim 1 failed"}, "expect_failed_claim"),
        ({"expect_failed_claim": "["}, "expect_failed_claim"),
    ],
)
def test_bad_client_check_scenarios_are_refused(
    lab, client_scenarios, change, message
):
    scen = copy.copy(client_scenarios[HOLDS])
    for key, value in change.items():
        setattr(scen, key, value)
    errors = nl.validate_scenarios(lab, [scen])
    assert errors
    assert any(message in error for error in errors), errors


def test_expect_failed_claim_is_only_allowed_with_rolled_back(
    lab, client_scenarios
):
    scen = copy.copy(client_scenarios[OPENS])
    scen.expect = "confirmed"
    errors = nl.validate_scenarios(lab, [scen])
    assert any("expect_failed_claim" in error for error in errors), errors


def test_client_check_scenarios_require_the_lab_router_and_no_tier(
    lab, client_scenarios
):
    scen = copy.copy(client_scenarios[HOLDS])
    scen.target = "lab-client"
    errors = nl.validate_scenarios(lab, [scen])
    assert any("lab-r1" in error for error in errors), errors

    scen = copy.copy(client_scenarios[HOLDS])
    scen.tier = "standard"
    errors = nl.validate_scenarios(lab, [scen])
    assert any("tier" in error for error in errors), errors


def test_client_check_env_writes_a_private_spec_and_local_check(
    tmp_path, monkeypatch, claim_scenario
):
    inventory = _inventory(tmp_path)
    monkeypatch.setenv("NEWTON_LAB_VANTAGE_INVENTORY", str(inventory))
    monkeypatch.setattr(nl, "RESULTS_DIR", tmp_path / "results")
    env, spec_path = nl.client_check_env(claim_scenario, SID)
    assert client_checks.LOCAL_CHECK_RE.fullmatch(env["OWRT_LOCAL_CHECK"])
    assert env["OWRT_LOCAL_CHECK"] == client_checks.local_check_string(
        nl.OWRT_CHANGE.parent / "newton-vantage-run", SID
    )
    assert env["NEWTON_VANTAGE_SPEC_DIR"] == str(spec_path.parent)
    assert stat.S_IMODE(spec_path.stat().st_mode) == 0o600
    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    assert spec["version"] == 1
    assert spec["sid"] == SID
    assert len(spec["groups"]) == 1
    assert spec["groups"][0]["zone"] == "guest"
    assert [check["claim"] for check in spec["groups"][0]["checks"]] == [1, 2]


def test_client_check_env_refuses_a_missing_vantage(
    tmp_path, monkeypatch, claim_scenario
):
    inventory = _inventory(tmp_path, serve_guest=False)
    monkeypatch.setenv("NEWTON_LAB_VANTAGE_INVENTORY", str(inventory))
    monkeypatch.setattr(nl, "RESULTS_DIR", tmp_path / "results")
    with pytest.raises(
        client_checks.ClientCheckError,
        match="no inside vantage serves zone guest for this device",
    ):
        nl.client_check_env(claim_scenario, SID)


def test_failed_claim_reads_the_local_check_block():
    claims = [
        {
            "kind": "client_blocked",
            "zone": "guest",
            "to": "router",
            "targets": ["192.0.2.1:22"],
        },
        {"kind": "client_dns", "zone": "guest"},
    ]
    log = (
        f"VERIFY DETAIL session={SID} round=3 exit=1 stage=local-check "
        "(last failed round; unknown)\n"
        f"VERIFY STDERR session={SID}: vantage-check: claim 1 FAIL open\n"
    )
    failed = explanation.failed_claim(log, SID, [], claims)
    assert failed == {
        "claim": 1,
        "text": "expect claim 1 failed: client in zone guest cannot reach "
        "router addresses (1 targets) (open)",
    }


def test_vantage_check_steps_exist_and_carry_no_secret_material():
    data = tomllib.loads(LAB_TOML.read_text(encoding="utf-8"))
    steps = data["steps"]
    assert steps["vantage_checks_on"]["device"] == "local"
    assert steps["vantage_checks_on"]["timeout"] == 180
    assert steps["vantage_checks_off"]["device"] == "lab-client"
    on = steps["vantage_checks_on"]["cmd"]
    assert "${" not in on
    assert "password" not in on.lower()
    assert "BEGIN OPENSSH PRIVATE KEY" not in on
    assert "BEGIN PRIVATE KEY" not in on
    # no secret var in the cmd (a plain var, like the client user name, is fine)
    assert not (nl.used_placeholders(on) & nl.secret_var_names(nl.load_lab(LAB_TOML)))
    off = steps["vantage_checks_off"]["cmd"]
    assert "authorized_keys" in off
    assert "newton-vantage-check" in off


def test_local_env_exposes_the_repository_to_local_steps(lab):
    env = nl._local_env(lab)
    assert env["NEWTON_REPO"] == str(nl.HERE.parent)


def test_local_env_carries_the_lab_client_user(lab):
    """A local cmd that ssh's the lab-client takes its user name from the
    lab file, so the tree that ships holds no user name."""
    env = nl._local_env(lab)
    assert env["LAB_CLIENT_USER"] == lab.devices["lab-client"].user


def test_apply_batch_merges_extra_environment(lab):
    sid = "b" * 32
    with mock.patch.object(
        nl, "_run", return_value=mock.Mock(returncode=0, stdout="", stderr="")
    ) as run:
        nl.apply_batch(
            lab,
            lab.devices["lab-r1"],
            sid,
            180,
            extra_env={"OWRT_LOCAL_CHECK": "'/x/newton-vantage-run' " + sid},
        )
    env = run.call_args.kwargs["env"]
    assert env["OWRT_LOCAL_CHECK"] == "'/x/newton-vantage-run' " + sid


def test_the_client_check_scenarios_have_no_free_text_claims(client_scenarios):
    allowed = {"kind", "zone", "to", "targets"}
    for scen in client_scenarios.values():
        for claim in scen.client_checks:
            assert set(claim) <= allowed, claim
            assert "text" not in claim
            assert "description" not in claim


def test_the_blocked_and_open_scenarios_change_only_the_guest_input(
    client_scenarios
):
    source = tomllib.loads(OPENWRT_ZONE.read_text(encoding="utf-8"))
    holds = client_scenarios[HOLDS]
    opens = client_scenarios[OPENS]
    assert holds.batch == source["batch"]
    source_lines = source["batch"].splitlines()
    holds_lines = holds.batch.splitlines()
    open_lines = opens.batch.splitlines()
    assert len(holds_lines) == len(open_lines) == len(source_lines)
    differences = [
        (left, right)
        for left, right in zip(holds_lines, open_lines)
        if left != right
    ]
    assert differences == [
        (
            "set firewall.guest_zone.input='REJECT'",
            "set firewall.guest_zone.input='ACCEPT'",
        )
    ]


def test_the_client_check_scenarios_use_the_vantage_steps(client_scenarios):
    for scen in client_scenarios.values():
        assert scen.setup[-1] == "vantage_checks_on"
        assert scen.cleanup[0] == "vantage_checks_off"
        assert scen.probes == [["iface-field", "guest", "up", "true"]]
        assert scen.timeout == 180
        assert scen.target == "lab-r1"


def test_the_open_scenario_expects_only_the_client_block_claim_to_fail(
    client_scenarios
):
    scen = client_scenarios[OPENS]
    assert scen.expect == "rolled_back"
    assert scen.expect_failed_claim is not None
    assert "cannot reach router addresses" in scen.expect_failed_claim
    assert not scen.effects
    posts = [post.cmd for post in scen.post]
    assert any("ubus call network.interface.guest status" in cmd for cmd in posts)
