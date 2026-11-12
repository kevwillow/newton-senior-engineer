"""NR-20..NR-23: the owner CLI scripts/newton-rules.

Network rules are the owner's: only ``newton-rules`` (run as the newton
user, like newton-enrol) writes ``rules.toml``, which lives next to the
inventory ``devices.toml``.  The CLI is a standalone program: no network,
no ssh, no device.  Every test drives it as a subprocess with a synthetic
inventory under tmp_path.

Test IDs
  NR-20 add: the refusals of the contract (no-install device, unknown
         device, zone without an inside vantage, the 17th rule, a target
         outside check_targets, the label grammar) and the write itself;
  NR-21 remove;
  NR-22 list;
  NR-23 the file checks and the atomic write (mkstemp + fsync + replace,
         mode 0600, no temporary file left behind, a refusal changes
         nothing).
"""

from __future__ import annotations

import os
import stat
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / "scripts" / "newton-rules"

NO_INSTALL_MESSAGE = (
    "newton-rules: network rules need the installed mode; "
    "Newton cannot run client checks in the no-install mode"
)

INVENTORY = """\
[devices.pulsar]
platform = "openwrt"
host = "192.0.2.1"
user = "root"

[devices.watch]
platform = "openwrt"
host = "192.0.2.9"
user = "root"
access = "no-install"

[vantages.inside-a]
host = "vantage.example.invalid"
user = "newton"
key_file = "/tmp/synthetic-inside-a.key"
known_hosts = "/tmp/synthetic-inside-a.hosts"
role = "inside"
devices = ["pulsar"]
zones = [{ name = "iot", src = "10.0.0.50", canary = "10.0.0.1:53" }]
check_targets = ["10.0.0.0/8"]

[vantages.outside-o]
host = "outside.example.invalid"
user = "newton"
key_file = "/tmp/synthetic-outside-o.key"
known_hosts = "/tmp/synthetic-outside-o.hosts"
role = "outside"
devices = ["pulsar"]
zones = [{ name = "iot", src = "198.51.100.50", canary = "198.51.100.1:53" }]
"""

SECOND_INSIDE = """\

[vantages.inside-b]
host = "vantage-b.example.invalid"
user = "newton"
key_file = "/tmp/synthetic-inside-b.key"
known_hosts = "/tmp/synthetic-inside-b.hosts"
role = "inside"
devices = ["pulsar"]
zones = [{ name = "iot", src = "10.0.0.51", canary = "10.0.0.1:53" }]
check_targets = ["10.0.0.0/8"]
"""

NO_TARGETS_OVERRIDE = INVENTORY.replace('check_targets = ["10.0.0.0/8"]\n', "")


def write_inventory(tmp_path, *, text=INVENTORY):
    inventory = tmp_path / "devices.toml"
    inventory.write_text(text)
    inventory.chmod(0o644)
    return inventory


def run_rules(tmp_path, *args, inventory=True, env_extra=None):
    env = os.environ.copy()
    if inventory:
        if isinstance(inventory, bool):
            inventory = write_inventory(tmp_path)
        env["NEWTON_INVENTORY"] = str(inventory)
    else:
        env.pop("NEWTON_INVENTORY", None)
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [sys.executable, str(RULES), *args],
        text=True,
        capture_output=True,
        env=env,
        timeout=30,
    )


def add(tmp_path, *args, inventory=True):
    return run_rules(tmp_path, "add", *args, inventory=inventory)


def rules_path(tmp_path):
    return tmp_path / "rules.toml"


def add_simple(tmp_path, rule_id="r-one", inventory=True):
    return add(tmp_path, "pulsar", rule_id, "iot", "blocked", "router",
               inventory=inventory)


# ---- NR-20: add ---------------------------------------------------------------


def test_nr20_01_add_writes_rules_toml_next_to_the_inventory(tmp_path):
    result = add_simple(tmp_path)
    path = rules_path(tmp_path)
    assert result.returncode == 0, result.stderr
    assert path.is_file()
    assert path.stat().st_mode & 0o777 == 0o600
    data = tomllib.loads(path.read_text())
    assert data == {
        "rule": [
            {
                "id": "r-one",
                "device": "pulsar",
                "zone": "iot",
                "kind": "blocked",
                "to": "router",
            }
        ]
    }
    assert result.stdout == (
        "added rule r-one on pulsar: from iot: router admin blocked\n"
    )


def test_nr20_02_the_file_carries_the_contract_header(tmp_path):
    assert add_simple(tmp_path).returncode == 0
    text = rules_path(tmp_path).read_text()
    assert text.startswith("# rules.toml, owned by the MCP server user")
    assert "[[rule]]" in text


def test_nr20_03_add_with_a_label(tmp_path):
    result = add(
        tmp_path, "pulsar", "r-label", "iot", "blocked", "router",
        "--label", "IoT cannot reach the router admin",
    )
    assert result.returncode == 0, result.stderr
    data = tomllib.loads(rules_path(tmp_path).read_text())
    assert data["rule"][0]["label"] == "IoT cannot reach the router admin"


@pytest.mark.parametrize(
    "label",
    [
        "printer (basement) can't print",
        "UPS, basement shelf",
        "block it.",
    ],
)
def test_nr20_04_the_labels_of_the_contract_are_accepted(tmp_path, label):
    result = add(tmp_path, "pulsar", "r-label", "iot", "blocked", "router", "--label", label)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    "label",
    [
        'say "hi"',
        "a;b",
        "a&b",
        "a|b",
        "a\nb",
        "x" * 81,
        "",
    ],
)
def test_nr20_05_a_label_outside_the_grammar_is_refused(tmp_path, label):
    result = add(tmp_path, "pulsar", "r-label", "iot", "blocked", "router", "--label", label)
    assert result.returncode == 1
    assert "label must be 1-80 characters of [A-Za-z0-9 ,.'()-]" in result.stderr
    assert not rules_path(tmp_path).exists()


def test_nr20_06_an_unknown_device_is_refused(tmp_path):
    result = add(tmp_path, "quasar", "r-one", "iot", "blocked", "router")
    assert result.returncode == 1
    assert "newton-rules: unknown device quasar" in result.stderr


@pytest.mark.parametrize("bad", ["Pulsar", "1pulsar", "pulsar/x", "x" * 33, "pul sar"])
def test_nr20_07_a_bad_device_name_is_refused(tmp_path, bad):
    result = add(tmp_path, bad, "r-one", "iot", "blocked", "router")
    assert result.returncode == 1
    assert "device must be 1-32 characters of [a-z][a-z0-9-]" in result.stderr


def test_nr20_08_a_no_install_device_takes_no_rules(tmp_path):
    result = add(tmp_path, "watch", "r-one", "iot", "blocked", "router")
    assert result.returncode == 1
    assert NO_INSTALL_MESSAGE in result.stderr
    assert not rules_path(tmp_path).exists()


@pytest.mark.parametrize(
    "bad_id", ["IOT", "iot_rule", "x" * 33, "iot/rule", "iot rule", "$(id)"]
)
def test_nr20_09_a_bad_rule_id_is_refused(tmp_path, bad_id):
    result = add(tmp_path, "pulsar", bad_id, "iot", "blocked", "router")
    assert result.returncode == 1
    assert "id must be 1-32 characters of [a-z0-9-]" in result.stderr


def test_nr20_10_a_zone_without_an_inside_vantage_is_refused(tmp_path):
    result = add(tmp_path, "pulsar", "r-one", "guest", "blocked", "router")
    assert result.returncode == 1
    assert "newton-rules: rule r-one has no vantage for zone guest" in result.stderr


def test_nr20_11_an_outside_vantage_is_not_an_inside_vantage(tmp_path):
    # outside-o lists the device and the zone, but only role inside serves
    # a client check; the answer is the same refusal.
    result = add(tmp_path, "pulsar", "r-one", "iot", "blocked", "router")
    assert result.returncode == 0, result.stderr


def test_nr20_12_two_inside_vantages_for_one_zone_are_refused(tmp_path):
    inventory = write_inventory(tmp_path, text=INVENTORY + SECOND_INSIDE)
    result = add(tmp_path, "pulsar", "r-one", "iot", "blocked", "router",
                 inventory=inventory)
    assert result.returncode == 1
    assert "more than one inside vantage serves zone iot" in result.stderr


def test_nr20_13_a_duplicate_id_is_refused(tmp_path):
    assert add_simple(tmp_path).returncode == 0
    result = add(tmp_path, "pulsar", "r-one", "iot", "dns")
    assert result.returncode == 1
    assert "newton-rules: rule r-one already exists" in result.stderr


def test_nr20_14_the_seventeenth_rule_is_refused(tmp_path):
    for index in range(16):
        result = add(tmp_path, "pulsar", f"r-{index:02d}", "iot", "dns")
        assert result.returncode == 0, result.stderr
    result = add(tmp_path, "pulsar", "r-16", "iot", "dns")
    assert result.returncode == 1
    assert "device pulsar already has 16 rules; the cap is 16" in result.stderr
    data = tomllib.loads(rules_path(tmp_path).read_text())
    assert len(data["rule"]) == 16


def test_nr20_15_dns_dhcp_internet_take_no_to(tmp_path):
    for kind in ("dns", "dhcp", "internet"):
        result = add(tmp_path, "pulsar", f"r-{kind}", "iot", kind, "router")
        assert result.returncode == 1, kind
        assert f"kind {kind} takes no to" in result.stderr


def test_nr20_16_blocked_requires_a_to(tmp_path):
    result = add(tmp_path, "pulsar", "r-one", "iot", "blocked")
    assert result.returncode == 1
    assert 'kind blocked requires to of "router", "internet" or "<ipv4>:<port>"' in result.stderr


@pytest.mark.parametrize(
    "to", ["lan", "10.0.0.1:0", "10.0.0.1:65536", "10.0.0.1:053", "010.0.0.1:22", "10.0.0.256:22"]
)
def test_nr20_17_blocked_refuses_a_bad_to(tmp_path, to):
    result = add(tmp_path, "pulsar", "r-one", "iot", "blocked", to)
    assert result.returncode == 1
    assert 'kind blocked requires to of "router", "internet" or "<ipv4>:<port>"' in result.stderr


def test_nr20_18_reach_requires_an_ip_port_to(tmp_path):
    for to in (None, "router", "internet"):
        args = ["pulsar", "r-one", "iot", "reach"] + ([to] if to else [])
        result = add(tmp_path, *args)
        assert result.returncode == 1, to
        assert 'kind reach requires to of "<ipv4>:<port>"' in result.stderr


@pytest.mark.parametrize("to", ["10.0.0.9:631", "10.255.255.255:1", "10.0.0.9:65535"])
def test_nr20_19_an_owner_target_inside_check_targets_is_accepted(tmp_path, to):
    result = add(tmp_path, "pulsar", "r-one", "iot", "blocked", to)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("kind", ["blocked", "reach"])
def test_nr20_20_a_target_outside_check_targets_is_refused(tmp_path, kind):
    result = add(tmp_path, "pulsar", "r-one", "iot", kind, "192.168.1.50:631")
    assert result.returncode == 1
    assert (
        "newton-rules: rule r-one: target 192.168.1.50:631 is not in the "
        "check_targets of vantage inside-a" in result.stderr
    )
    assert not rules_path(tmp_path).exists()


def test_nr20_21_the_default_check_targets_cover_the_private_ranges(tmp_path):
    inventory = write_inventory(tmp_path, text=NO_TARGETS_OVERRIDE)
    result = add(tmp_path, "pulsar", "r-one", "iot", "reach", "192.168.1.50:631",
                 inventory=inventory)
    assert result.returncode == 0, result.stderr


def test_nr20_22_router_and_internet_targets_skip_the_check_targets_test(tmp_path):
    for to in ("router", "internet"):
        result = add(tmp_path, "pulsar", f"r-{to}", "iot", "blocked", to)
        assert result.returncode == 0, to


# ---- NR-21: remove -------------------------------------------------------------


def test_nr21_01_remove_deletes_exactly_one_rule(tmp_path):
    assert add_simple(tmp_path, "r-one").returncode == 0
    assert add(tmp_path, "pulsar", "r-two", "iot", "dns").returncode == 0
    result = run_rules(tmp_path, "remove", "pulsar", "r-one")
    assert result.returncode == 0, result.stderr
    assert result.stdout == "removed rule r-one on pulsar\n"
    data = tomllib.loads(rules_path(tmp_path).read_text())
    assert [row["id"] for row in data["rule"]] == ["r-two"]


def test_nr21_02_remove_refuses_an_unknown_id(tmp_path):
    assert add_simple(tmp_path).returncode == 0
    before = rules_path(tmp_path).read_text()
    result = run_rules(tmp_path, "remove", "pulsar", "no-such")
    assert result.returncode == 1
    assert "newton-rules: no rule no-such" in result.stderr
    assert rules_path(tmp_path).read_text() == before


def test_nr21_03_remove_names_the_device_the_rule_belongs_to(tmp_path):
    assert add_simple(tmp_path).returncode == 0
    result = run_rules(tmp_path, "remove", "watch", "r-one")
    assert result.returncode == 1
    assert "newton-rules: rule r-one is a rule of device pulsar" in result.stderr


def test_nr21_04_removing_the_last_rule_leaves_a_loadable_file(tmp_path):
    assert add_simple(tmp_path).returncode == 0
    assert run_rules(tmp_path, "remove", "pulsar", "r-one").returncode == 0
    assert tomllib.loads(rules_path(tmp_path).read_text()) == {}


# ---- NR-22: list ---------------------------------------------------------------


def test_nr22_01_list_without_a_file_says_no_rules(tmp_path):
    result = run_rules(tmp_path, "list")
    assert result.returncode == 0
    assert result.stdout == "no rules\n"


def test_nr22_02_list_prints_fields_and_sentence(tmp_path):
    assert add(
        tmp_path, "pulsar", "iot-no-admin", "iot", "blocked", "router",
        "--label", "IoT cannot reach the router admin",
    ).returncode == 0
    assert add(tmp_path, "pulsar", "lan-print", "iot", "reach", "10.0.0.9:631").returncode == 0
    result = run_rules(tmp_path, "list")
    assert result.returncode == 0
    assert result.stdout.splitlines() == [
        "pulsar\tiot-no-admin\tiot\tblocked\trouter\t"
        "IoT cannot reach the router admin\tfrom iot: router admin blocked",
        "pulsar\tlan-print\tiot\treach\t10.0.0.9:631\t\t"
        "from iot: 10.0.0.9:631 reachable",
    ]


def test_nr22_03_list_filters_by_device(tmp_path):
    assert add_simple(tmp_path, "r-one").returncode == 0
    result = run_rules(tmp_path, "list", "watch")
    assert result.returncode == 0
    assert result.stdout == "no rules for device watch\n"


# ---- NR-23: the file checks and the atomic write --------------------------------


def test_nr23_01_a_symlinked_rules_file_is_refused(tmp_path):
    write_inventory(tmp_path)
    real = tmp_path / "real.toml"
    real.write_text("")
    real.chmod(0o644)
    rules_path(tmp_path).symlink_to(real)
    for args in (
        ("add", "pulsar", "r-one", "iot", "dns"),
        ("remove", "pulsar", "r-one"),
        ("list",),
    ):
        result = run_rules(tmp_path, *args)
        assert result.returncode == 1, args
        assert "rules file must be a regular file, not a symlink" in result.stderr


def test_nr23_02_a_group_writable_rules_file_is_refused(tmp_path):
    write_inventory(tmp_path)
    path = rules_path(tmp_path)
    path.write_text("")
    path.chmod(0o664)
    result = add_simple(tmp_path)
    assert result.returncode == 1
    assert "rules file must not be group- or world-writable" in result.stderr


def test_nr23_03_a_rules_file_of_another_user_is_refused(tmp_path):
    write_inventory(tmp_path)
    path = rules_path(tmp_path)
    path.write_text("")
    path.chmod(0o644)
    try:
        os.chown(path, os.getuid() + 1, os.getgid())
    except PermissionError:
        pytest.skip("the test user cannot change file ownership")
    result = add_simple(tmp_path)
    assert result.returncode == 1
    assert "rules file must be owned by" in result.stderr


def test_nr23_04_a_missing_inventory_is_refused(tmp_path):
    result = run_rules(
        tmp_path, "add", "pulsar", "r-one", "iot", "dns",
        inventory=tmp_path / "no-such.toml",
    )
    assert result.returncode == 1
    assert "inventory file not found" in result.stderr


def test_nr23_05_a_group_writable_inventory_is_refused(tmp_path):
    inventory = write_inventory(tmp_path)
    inventory.chmod(0o664)
    result = add_simple(tmp_path, inventory=inventory)
    assert result.returncode == 1
    assert "inventory file must not be group- or world-writable" in result.stderr


def test_nr23_06_no_temporary_file_is_left_behind(tmp_path):
    assert add_simple(tmp_path, "r-one").returncode == 0
    assert add(tmp_path, "pulsar", "r-two", "iot", "dns").returncode == 0
    assert run_rules(tmp_path, "remove", "pulsar", "r-one").returncode == 0
    # the conftest adds its own state dirs; the CLI must leave nothing
    # but the inventory and the rules file behind (no mkstemp leftovers)
    newton_files = sorted(
        entry.name
        for entry in tmp_path.iterdir()
        if entry.name not in ("conftest_state", "conftest_home")
    )
    assert newton_files == ["devices.toml", "rules.toml"]


def test_nr23_07_the_written_file_is_private_and_owned_by_the_runner(tmp_path):
    assert add_simple(tmp_path).returncode == 0
    info = rules_path(tmp_path).stat()
    assert stat.S_IMODE(info.st_mode) == 0o600
    assert info.st_uid == os.getuid()


def test_nr23_08_a_refused_add_changes_nothing(tmp_path):
    assert add_simple(tmp_path, "r-one").returncode == 0
    before = rules_path(tmp_path).read_text()
    result = add(tmp_path, "pulsar", "r-two", "guest", "blocked", "router")
    assert result.returncode == 1
    assert rules_path(tmp_path).read_text() == before


def test_nr23_09_usage_errors_exit_two(tmp_path):
    for args in (
        ("frobnicate",),
        ("add", "pulsar"),
        ("add", "pulsar", "r-one", "iot", "scan"),
        ("remove", "pulsar"),
    ):
        result = run_rules(tmp_path, *args)
        assert result.returncode == 2, args
