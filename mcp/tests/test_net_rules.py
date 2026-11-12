"""The owner's network rules: the loader and the pure mapping to claims.

A network rule is a short statement the OWNER writes about a device's
network that must stay true ("from the iot zone, the router admin is
blocked").  The rules live in ``rules.toml`` next to the inventory
``devices.toml`` and only the owner writes them (``scripts/newton-rules``);
no MCP tool can.  This module is the read side the server and the plan
path share: it loads the file with the inventory's own file checks,
refuses a file that is not exactly the contract, and maps each rule to
the client claim a plan carries.

Test IDs
  NR-01 the file checks and the load (missing, empty, symlink, mode, owner);
  NR-02 the grammar of one rule (every refusal names the rule id and field);
  NR-03 devices that are not in the inventory;
  NR-04 the cap of sixteen rules per device;
  NR-05 ``rule_claims``: the mapping to client claims, marked source=rule;
  NR-06 the sentence built from the fields;
  NR-07 the path next to the inventory;
  NR-08 the round trip with scripts/newton-rules.

Nothing here touches a device, a router or a vantage.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from newton_mcp import client_checks as cc
from newton_mcp import inventory_file
from newton_mcp import net_rules as nr


def _toml(value):
    """One python value as a TOML right-hand side."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    return json.dumps(value)


def write_rules(tmp_path, text, *, mode=0o644):
    path = tmp_path / "rules.toml"
    path.write_text(text)
    if mode is not None:
        path.chmod(mode)
    return path


def rules_file(rows):
    """A rules.toml text built from row dicts (None omits the key)."""
    blocks = []
    for row in rows:
        lines = ["[[rule]]"]
        for key in ("id", "device", "zone", "kind", "to", "label"):
            if row.get(key) is not None:
                lines.append(f"{key} = {_toml(row[key])}")
        for key in sorted(set(row) - {"id", "device", "zone", "kind", "to", "label"}):
            lines.append(f"{key} = {_toml(row[key])}")
        blocks.append("\n".join(lines))
    return "\n\n".join(blocks) + "\n"


SPEC_EXAMPLE = """# rules.toml, owned by the MCP server user, mode 0600 or 0644
[[rule]]
id = "iot-no-admin"
device = "pulsar"
zone = "iot"
kind = "blocked"
to = "router"
label = "IoT cannot reach the router admin"
"""

A_RULE = {
    "id": "iot-no-admin",
    "device": "pulsar",
    "zone": "iot",
    "kind": "blocked",
    "to": "router",
    "label": "IoT cannot reach the router admin",
}


# ---- NR-01: the file checks and the load --------------------------------------


def test_nr01_01_loads_the_spec_example_keyed_by_device(tmp_path):
    path = write_rules(tmp_path, SPEC_EXAMPLE)
    loaded = nr.load_rules(path)
    assert loaded == {
        "pulsar": (
            nr.Rule(
                id="iot-no-admin",
                device="pulsar",
                zone="iot",
                kind="blocked",
                to="router",
                label="IoT cannot reach the router admin",
            ),
        )
    }


def test_nr01_02_rules_of_two_devices_stay_in_file_order(tmp_path):
    path = write_rules(
        tmp_path,
        rules_file(
            [
                dict(A_RULE, id="a-one"),
                {"id": "b-one", "device": "quasar", "zone": "lan", "kind": "dns"},
                dict(A_RULE, id="a-two", kind="dns", to=None),
            ]
        ),
    )
    loaded = nr.load_rules(path)
    assert list(loaded) == ["pulsar", "quasar"]
    assert [rule.id for rule in loaded["pulsar"]] == ["a-one", "a-two"]
    assert [rule.id for rule in loaded["quasar"]] == ["b-one"]


def test_nr01_03_a_missing_file_is_no_rules(tmp_path):
    assert nr.load_rules(tmp_path / "rules.toml") == {}


def test_nr01_04_an_empty_or_comment_only_file_is_no_rules(tmp_path):
    assert nr.load_rules(write_rules(tmp_path, "")) == {}
    assert nr.load_rules(write_rules(tmp_path, "# nothing yet\n")) == {}


def test_nr01_05_a_symlinked_rules_file_is_refused(tmp_path):
    real = tmp_path / "real.toml"
    real.write_text(rules_file([A_RULE]))
    real.chmod(0o644)
    link = tmp_path / "rules.toml"
    link.symlink_to(real)
    with pytest.raises(nr.NetRuleError, match=r"must be a regular file, not a symlink"):
        nr.load_rules(link)


def test_nr01_06_a_directory_is_refused(tmp_path):
    directory = tmp_path / "rules.toml"
    directory.mkdir()
    with pytest.raises(nr.NetRuleError, match=r"must be a regular file, not a symlink"):
        nr.load_rules(directory)


@pytest.mark.parametrize("bad_mode", [0o664, 0o666, 0o620])
def test_nr01_07_a_group_or_world_writable_file_is_refused(tmp_path, bad_mode):
    path = write_rules(tmp_path, rules_file([A_RULE]), mode=bad_mode)
    with pytest.raises(nr.NetRuleError, match=r"group- or world-writable"):
        nr.load_rules(path)


def test_nr01_08_a_file_not_owned_by_the_server_user_is_refused(tmp_path, monkeypatch):
    path = write_rules(tmp_path, rules_file([A_RULE]))
    monkeypatch.setattr(
        inventory_file, "_effective_uid", lambda: path.stat().st_uid + 1
    )
    with pytest.raises(nr.NetRuleError, match=r"owned by the user"):
        nr.load_rules(path)


def test_nr01_09_the_modes_of_the_contract_are_accepted(tmp_path):
    for mode in (0o600, 0o644):
        path = write_rules(tmp_path, rules_file([A_RULE]), mode=mode)
        assert "pulsar" in nr.load_rules(path)


def test_nr01_10_a_file_that_is_not_toml_is_refused(tmp_path):
    path = write_rules(tmp_path, "id = \n")
    with pytest.raises(nr.NetRuleError):
        nr.load_rules(path)


# ---- NR-02: the grammar of one rule -------------------------------------------


@pytest.mark.parametrize(
    "row, needle",
    [
        pytest.param(dict(A_RULE, extra="x"), "unknown keys: extra", id="unknown-key"),
        pytest.param({k: v for k, v in A_RULE.items() if k != "id"}, "missing required keys: id", id="missing-id"),
        pytest.param({k: v for k, v in A_RULE.items() if k != "device"}, "missing required keys: device", id="missing-device"),
        pytest.param({k: v for k, v in A_RULE.items() if k != "zone"}, "missing required keys: zone", id="missing-zone"),
        pytest.param({k: v for k, v in A_RULE.items() if k != "kind"}, "missing required keys: kind", id="missing-kind"),
        pytest.param(dict(A_RULE, id=7), "rule #1: id must match", id="id-wrong-type"),
        pytest.param(dict(A_RULE, id="IOT"), "rule #1: id must match", id="id-uppercase"),
        pytest.param(dict(A_RULE, id="iot_rule"), "rule #1: id must match", id="id-underscore"),
        pytest.param(dict(A_RULE, id="x" * 33), "rule #1: id must match", id="id-too-long"),
        pytest.param(dict(A_RULE, device="Pulsar"), "device must match", id="device-uppercase"),
        pytest.param(dict(A_RULE, device=9), "device must match", id="device-wrong-type"),
        pytest.param(dict(A_RULE, zone="Iot"), "zone must match", id="zone-uppercase"),
        pytest.param(dict(A_RULE, zone="9iot"), "zone must match", id="zone-leading-digit"),
        pytest.param(dict(A_RULE, zone="iot;ls"), "zone must match", id="zone-semicolon"),
        pytest.param(dict(A_RULE, zone=True), "zone must match", id="zone-wrong-type"),
        pytest.param(dict(A_RULE, kind="scan"), "kind must be one of", id="kind-unknown"),
        pytest.param(dict(A_RULE, kind=True), "kind must be one of", id="kind-wrong-type"),
        pytest.param({"id": "r", "device": "pulsar", "zone": "iot", "kind": "dns", "to": "router"}, "kind dns must not carry to", id="dns-with-to"),
        pytest.param({"id": "r", "device": "pulsar", "zone": "iot", "kind": "dhcp", "to": "10.0.0.1:53"}, "kind dhcp must not carry to", id="dhcp-with-to"),
        pytest.param({"id": "r", "device": "pulsar", "zone": "iot", "kind": "internet", "to": "internet"}, "kind internet must not carry to", id="internet-with-to"),
        pytest.param({"id": "r", "device": "pulsar", "zone": "iot", "kind": "blocked"}, 'kind blocked requires to of "router", "internet" or "<ipv4>:<port>"', id="blocked-without-to"),
        pytest.param(dict(A_RULE, to="lan"), 'kind blocked requires to of "router", "internet" or "<ipv4>:<port>"', id="blocked-bad-to"),
        pytest.param(dict(A_RULE, to="10.0.0.1:0"), 'kind blocked requires to of "router", "internet" or "<ipv4>:<port>"', id="blocked-port-zero"),
        pytest.param(dict(A_RULE, to="10.0.0.1:65536"), 'kind blocked requires to of "router", "internet" or "<ipv4>:<port>"', id="blocked-port-too-big"),
        pytest.param(dict(A_RULE, to="10.0.0.1:053"), 'kind blocked requires to of "router", "internet" or "<ipv4>:<port>"', id="blocked-port-leading-zero"),
        pytest.param(dict(A_RULE, to="010.0.0.1:22"), 'kind blocked requires to of "router", "internet" or "<ipv4>:<port>"', id="blocked-ip-leading-zero"),
        pytest.param(dict(A_RULE, to="10.0.0.256:22"), 'kind blocked requires to of "router", "internet" or "<ipv4>:<port>"', id="blocked-large-octet"),
        pytest.param(dict(A_RULE, to="10.0.0.1:22;reboot"), 'kind blocked requires to of "router", "internet" or "<ipv4>:<port>"', id="blocked-shell-chars"),
        pytest.param(dict(A_RULE, to="2001:db8::1:22"), 'kind blocked requires to of "router", "internet" or "<ipv4>:<port>"', id="blocked-ipv6"),
        pytest.param({"id": "r", "device": "pulsar", "zone": "iot", "kind": "reach"}, 'kind reach requires to of "<ipv4>:<port>"', id="reach-without-to"),
        pytest.param({"id": "r", "device": "pulsar", "zone": "iot", "kind": "reach", "to": "router"}, 'kind reach requires to of "<ipv4>:<port>"', id="reach-to-router"),
        pytest.param({"id": "r", "device": "pulsar", "zone": "iot", "kind": "reach", "to": "internet"}, 'kind reach requires to of "<ipv4>:<port>"', id="reach-to-internet"),
        pytest.param({"id": "r", "device": "pulsar", "zone": "iot", "kind": "reach", "to": "10.0.0.1:0"}, 'kind reach requires to of "<ipv4>:<port>"', id="reach-port-zero"),
        pytest.param({"id": "r", "device": "pulsar", "zone": "iot", "kind": "reach", "to": "10.0.0.1:70000"}, 'kind reach requires to of "<ipv4>:<port>"', id="reach-port-too-big"),
        pytest.param(dict(A_RULE, label="x" * 81), "label must be 1-80 characters of", id="label-too-long"),
        pytest.param(dict(A_RULE, label='say "hi"'), "label must be 1-80 characters of", id="label-quote"),
        pytest.param(dict(A_RULE, label="a;b"), "label must be 1-80 characters of", id="label-semicolon"),
        pytest.param(dict(A_RULE, label="a\nb"), "label must be 1-80 characters of", id="label-newline"),
        pytest.param(dict(A_RULE, label=""), "label must be 1-80 characters of", id="label-empty"),
        pytest.param(dict(A_RULE, label=4), "label must be 1-80 characters of", id="label-wrong-type"),
    ],
)
def test_nr02_01_a_rule_outside_the_grammar_is_refused_naming_id_and_field(
    tmp_path, row, needle
):
    path = write_rules(tmp_path, rules_file([row]))
    with pytest.raises(nr.NetRuleError) as err:
        nr.load_rules(path)
    message = str(err.value)
    # every refusal names the rule (by id when the id is usable, by
    # position when it is not) and the field
    raw_id = row.get("id")
    if isinstance(raw_id, str) and nr.RULE_ID_RE.fullmatch(raw_id):
        assert f"rule {raw_id}" in message
    else:
        assert "rule #1" in message
    assert needle in message


def test_nr02_02_the_second_rule_of_a_bad_file_is_named_by_its_own_id(tmp_path):
    path = write_rules(
        tmp_path,
        rules_file([dict(A_RULE, id="good-one"), dict(A_RULE, id="bad-two", zone="Lan")]),
    )
    with pytest.raises(nr.NetRuleError) as err:
        nr.load_rules(path)
    assert "rule bad-two" in str(err.value)
    assert "zone must match" in str(err.value)


def test_nr02_03_a_duplicate_id_is_refused_even_across_devices(tmp_path):
    path = write_rules(
        tmp_path,
        rules_file(
            [
                A_RULE,
                dict(A_RULE, device="quasar", zone="lan", kind="dns", to=None, label=None),
            ]
        ),
    )
    with pytest.raises(nr.NetRuleError) as err:
        nr.load_rules(path)
    assert "rule iot-no-admin" in str(err.value)
    assert "unique" in str(err.value)


def test_nr02_04_an_unknown_top_level_key_is_refused(tmp_path):
    path = write_rules(
        tmp_path,
        rules_file([A_RULE]) + '\nrules = ["hand-written"]\n',
    )
    with pytest.raises(nr.NetRuleError) as err:
        nr.load_rules(path)
    assert "unknown keys: rules" in str(err.value)


def test_nr02_05_a_rule_that_is_not_a_table_is_refused(tmp_path):
    path = write_rules(tmp_path, 'rule = "not a table"\n')
    with pytest.raises(nr.NetRuleError):
        nr.load_rules(path)


def test_nr02_06_a_single_rule_table_is_refused(tmp_path):
    path = write_rules(tmp_path, rules_file([A_RULE]).replace("[[rule]]", "[rule]"))
    with pytest.raises(nr.NetRuleError):
        nr.load_rules(path)


def test_nr02_07_the_whole_file_is_refused_not_only_the_bad_rule(tmp_path):
    path = write_rules(
        tmp_path, rules_file([dict(A_RULE, id="fine"), dict(A_RULE, id="bad", kind="scan")])
    )
    with pytest.raises(nr.NetRuleError):
        nr.load_rules(path)


@pytest.mark.parametrize(
    "to",
    ["router", "internet", "10.0.0.1:631", "192.168.1.50:22", "100.64.0.9:443"],
)
def test_nr02_08_the_to_values_of_the_contract_are_accepted(tmp_path, to):
    path = write_rules(tmp_path, rules_file([dict(A_RULE, to=to)]))
    assert nr.load_rules(path)["pulsar"][0].to == to


# ---- NR-03: devices that are not in the inventory ------------------------------


def test_nr03_01_a_rule_for_an_unknown_device_is_refused(tmp_path):
    path = write_rules(
        tmp_path, rules_file([dict(A_RULE, device="quasar", zone="lan", kind="dns", to=None)])
    )
    with pytest.raises(nr.NetRuleError) as err:
        nr.load_rules(path, known_devices={"pulsar"})
    assert "rule iot-no-admin" in str(err.value)
    assert "device quasar is not in the inventory" in str(err.value)


def test_nr03_02_without_known_devices_the_device_name_is_still_checked(tmp_path):
    path = write_rules(
        tmp_path, rules_file([dict(A_RULE, device="quasar", zone="lan", kind="dns", to=None)])
    )
    # no inventory to compare with: the shape alone decides
    assert "quasar" in nr.load_rules(path)
    with pytest.raises(nr.NetRuleError, match=r"device must match"):
        nr.load_rules(write_rules(tmp_path, rules_file([dict(A_RULE, device="Not A Name")])))


# ---- NR-04: the cap of sixteen rules per device ---------------------------------


def test_nr04_01_sixteen_rules_per_device_are_accepted(tmp_path):
    rows = [
        {"id": f"r{i:02d}", "device": "pulsar", "zone": "iot", "kind": "dns"}
        for i in range(16)
    ]
    path = write_rules(tmp_path, rules_file(rows))
    assert len(nr.load_rules(path)["pulsar"]) == 16


def test_nr04_02_the_seventeenth_rule_is_refused_at_load(tmp_path):
    rows = [
        {"id": f"r{i:02d}", "device": "pulsar", "zone": "iot", "kind": "dns"}
        for i in range(17)
    ]
    path = write_rules(tmp_path, rules_file(rows))
    with pytest.raises(nr.NetRuleError) as err:
        nr.load_rules(path)
    assert "device pulsar has 17 rules" in str(err.value)
    assert "cap is 16" in str(err.value)


def test_nr04_03_the_cap_is_per_device(tmp_path):
    rows = [
        {"id": f"a{i:02d}", "device": "pulsar", "zone": "iot", "kind": "dns"}
        for i in range(16)
    ] + [
        {"id": "b00", "device": "quasar", "zone": "lan", "kind": "dns"},
    ]
    path = write_rules(tmp_path, rules_file(rows))
    loaded = nr.load_rules(path)
    assert len(loaded["pulsar"]) == 16
    assert len(loaded["quasar"]) == 1


# ---- NR-05: rule_claims ---------------------------------------------------------


def test_nr05_01_every_kind_maps_to_its_client_claim():
    rules = [
        nr.Rule(id="r-dns", device="p", zone="iot", kind="dns"),
        nr.Rule(id="r-dhcp", device="p", zone="iot", kind="dhcp"),
        nr.Rule(id="r-inet", device="p", zone="iot", kind="internet"),
        nr.Rule(id="r-blocked-router", device="p", zone="iot", kind="blocked", to="router"),
        nr.Rule(id="r-blocked-inet", device="p", zone="iot", kind="blocked", to="internet"),
        nr.Rule(id="r-blocked-target", device="p", zone="iot", kind="blocked", to="10.0.0.1:631"),
        nr.Rule(id="r-reach", device="p", zone="iot", kind="reach", to="10.0.0.1:631"),
    ]
    assert nr.rule_claims(rules) == [
        {"kind": "client_dns", "zone": "iot", "source": "rule", "rule": "r-dns"},
        {"kind": "client_dhcp", "zone": "iot", "source": "rule", "rule": "r-dhcp"},
        {"kind": "client_internet", "zone": "iot", "source": "rule", "rule": "r-inet"},
        {"kind": "client_blocked", "zone": "iot", "to": "router", "source": "rule", "rule": "r-blocked-router"},
        {"kind": "client_blocked", "zone": "iot", "to": "internet", "source": "rule", "rule": "r-blocked-inet"},
        {"kind": "client_blocked", "zone": "iot", "to": "10.0.0.1:631", "source": "rule", "rule": "r-blocked-target"},
        {"kind": "client_reaches", "zone": "iot", "to": "10.0.0.1:631", "source": "rule", "rule": "r-reach"},
    ]


def test_nr05_02_every_rule_claim_is_a_client_claim_of_the_plan():
    rules = [
        nr.Rule(id="r-dns", device="p", zone="iot", kind="dns"),
        nr.Rule(id="r-reach", device="p", zone="iot", kind="reach", to="10.0.0.1:631"),
    ]
    for claim in nr.rule_claims(rules):
        assert cc.is_client_claim(claim) is True
        assert claim["kind"] in cc.CLIENT_KINDS


def test_nr05_03_the_label_is_never_sealed_into_a_claim():
    rule = nr.Rule(
        id="r", device="p", zone="iot", kind="blocked", to="router",
        label="printer must stay blocked",
    )
    claims_text = json.dumps(nr.rule_claims([rule]))
    assert "printer" not in claims_text
    assert "label" not in claims_text


def test_nr05_04_fill_targets_fills_rule_claims_like_agent_claims():
    dump = {"interface": [{"interface": "lan", "up": True,
                           "ipv4-address": [{"address": "192.168.1.1", "mask": 24}]}]}
    calls = []
    rules = [
        nr.Rule(id="r1", device="p", zone="iot", kind="blocked", to="router"),
        nr.Rule(id="r2", device="p", zone="iot", kind="blocked", to="10.0.0.9:631"),
        nr.Rule(id="r3", device="p", zone="iot", kind="reach", to="10.0.0.9:631"),
    ]

    def loader():
        calls.append(1)
        return dump

    filled = cc.fill_targets(nr.rule_claims(rules), loader)
    assert filled[0]["targets"] == ["192.168.1.1:22", "192.168.1.1:443", "192.168.1.1:80"]
    assert filled[1]["targets"] == ["10.0.0.9:631"]
    assert filled[2]["targets"] == ["10.0.0.9:631"]
    # the owner-supplied targets need no router dump
    assert calls == [1]
    # the markers survive the fill
    assert filled[1]["source"] == "rule"
    assert filled[1]["rule"] == "r2"


# ---- NR-06: the sentence built from the fields -----------------------------------


def test_nr06_01_the_sentences_are_built_from_the_fields():
    cases = [
        (nr.Rule(id="r", device="p", zone="iot", kind="dns"),
         "from iot: DNS names resolve through the zone router"),
        (nr.Rule(id="r", device="p", zone="iot", kind="dhcp"),
         "from iot: DHCP offers arrive from the zone router"),
        (nr.Rule(id="r", device="p", zone="iot", kind="internet"),
         "from iot: the internet is reachable"),
        (nr.Rule(id="r", device="p", zone="iot", kind="blocked", to="router"),
         "from iot: router admin blocked"),
        (nr.Rule(id="r", device="p", zone="iot", kind="blocked", to="internet"),
         "from iot: the internet is blocked"),
        (nr.Rule(id="r", device="p", zone="iot", kind="blocked", to="192.168.1.50:631"),
         "from iot: 192.168.1.50:631 blocked"),
        (nr.Rule(id="r", device="p", zone="iot", kind="reach", to="192.168.1.50:631"),
         "from iot: 192.168.1.50:631 reachable"),
    ]
    for rule, sentence in cases:
        assert nr.rule_sentence(rule) == sentence


def test_nr06_02_the_sentence_never_contains_device_data():
    rule = nr.Rule(id="r", device="pulsar", zone="iot", kind="blocked", to="router",
                   label="IoT cannot reach the router admin")
    sentence = nr.rule_sentence(rule)
    assert "pulsar" not in sentence
    assert "IoT cannot reach" not in sentence


# ---- NR-07: the path next to the inventory ---------------------------------------


def test_nr07_01_rules_toml_lives_next_to_devices_toml():
    inventory = Path("/var/lib/newton/devices.toml")
    assert nr.rules_path(inventory) == Path("/var/lib/newton/rules.toml")


# ---- NR-08: the round trip with scripts/newton-rules ------------------------------


INVENTORY = """\
[devices.pulsar]
platform = "openwrt"
host = "192.0.2.1"
user = "root"

[vantages.inside-a]
host = "vantage.example.invalid"
user = "newton"
key_file = "/tmp/synthetic-inside-a.key"
known_hosts = "/tmp/synthetic-inside-a.hosts"
role = "inside"
devices = ["pulsar"]
zones = [{ name = "iot", src = "10.0.0.50", canary = "10.0.0.1:53" }]
check_targets = ["10.0.0.0/8"]
"""


def _run_rules_cli(tmp_path, *args):
    inventory = tmp_path / "devices.toml"
    inventory.write_text(INVENTORY)
    inventory.chmod(0o644)
    env = os.environ.copy()
    env["NEWTON_INVENTORY"] = str(inventory)
    script = Path(__file__).resolve().parents[2] / "scripts" / "newton-rules"
    return subprocess.run(
        [sys.executable, str(script), *args],
        text=True,
        capture_output=True,
        env=env,
        timeout=30,
    )


def test_nr08_01_what_the_cli_writes_the_loader_reads(tmp_path):
    result = _run_rules_cli(
        tmp_path,
        "add", "pulsar", "iot-no-admin", "iot", "blocked", "router",
        "--label", "IoT cannot reach the router admin",
    )
    assert result.returncode == 0, result.stderr
    loaded = nr.load_rules(tmp_path / "rules.toml")
    assert loaded == {
        "pulsar": (
            nr.Rule(
                id="iot-no-admin",
                device="pulsar",
                zone="iot",
                kind="blocked",
                to="router",
                label="IoT cannot reach the router admin",
            ),
        )
    }


def test_nr08_02_the_cli_sentence_and_the_loader_sentence_agree(tmp_path):
    result = _run_rules_cli(tmp_path, "add", "pulsar", "r-reach", "iot", "reach", "10.0.0.9:631")
    assert result.returncode == 0, result.stderr
    result = _run_rules_cli(tmp_path, "list")
    assert "from iot: 10.0.0.9:631 reachable" in result.stdout
    (rule,) = nr.load_rules(tmp_path / "rules.toml")["pulsar"]
    assert nr.rule_sentence(rule) == "from iot: 10.0.0.9:631 reachable"


def test_nr08_03_the_cli_never_writes_something_the_loader_refuses(tmp_path):
    result = _run_rules_cli(
        tmp_path, "add", "pulsar", "r-label", "iot", "internet", "--label", 'say "hi"'
    )
    assert result.returncode == 1
    assert not (tmp_path / "rules.toml").exists()
