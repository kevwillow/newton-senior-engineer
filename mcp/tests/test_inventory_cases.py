"""Every case in inventory_cases.json through the MCP's load_inventory.

The same file is run through the REAL setup loader
(scripts/newton-router-setup load_inventory) by
tests/protocol/test_inventory_cases.py; both must agree with "ok".  A
literal "{tmp}" in a string value is replaced by the test's tmp dir, and an
ok key_file case gets a real mode-0600 key file created there (the MCP-only
filesystem refusals are separate tests in test_inventory_key_file.py)."""

import json
from pathlib import Path

import pytest

import newton_mcp.server as server

DATA = json.loads((Path(__file__).parent / "inventory_cases.json").read_text())
CASES = DATA["cases"]
CASE_BY_ID = {case["id"]: case for case in CASES}


def toml_value(value):
    if isinstance(value, str):
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return json.dumps(value)


def write_inventory(tmp_path, case):
    fields = dict(DATA["base"])
    fields.update(case["fields"])
    name = fields.pop("name", "quasar")
    lines = []
    for key, value in fields.items():
        if isinstance(value, str):
            value = value.replace("{tmp}", str(tmp_path))
        lines.append(f"{key} = {toml_value(value)}")
    inventory = tmp_path / "devices.toml"
    inventory.write_text(f"[devices.{name}]\n" + "\n".join(lines) + "\n")
    return inventory


@pytest.fixture(autouse=True)
def key_file(tmp_path):
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text(
        "192.0.2.9 ssh-ed25519 "
        "AAAAC3NzaC1lZDI1NTE5AAAAIFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE\n"
    )
    (tmp_path / "known_hosts_link").symlink_to(known_hosts)
    password = tmp_path / "pw"
    password.write_text("synthetic-password\n")
    password.chmod(0o600)
    path = tmp_path / "newton-key"
    path.write_text("FAKE-KEY-FOR-TESTS\n")
    path.chmod(0o600)
    return path


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_load_inventory_agrees_with_the_case(tmp_path, monkeypatch, case, key_file):
    inventory = write_inventory(tmp_path, case)
    monkeypatch.setenv("NEWTON_INVENTORY", str(inventory))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))
    try:
        server.load_inventory()
        ok = True
    except server.NewtonError:
        ok = False
    assert ok == case["ok"], case["id"]


def load_case_device(tmp_path, monkeypatch, case_id):
    inventory = write_inventory(tmp_path, CASE_BY_ID[case_id])
    monkeypatch.setenv("NEWTON_INVENTORY", str(inventory))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))
    return server.load_inventory()["quasar"]


def test_routeros_ok_loads_experimental_inventory_fields(tmp_path, monkeypatch):
    device = load_case_device(tmp_path, monkeypatch, "routeros-ok")

    assert device.platform == "routeros"
    assert device.experimental_readonly is True
    assert device.lab is False
    assert device.known_hosts == tmp_path / "known_hosts"


def test_openwrt_base_keeps_experimental_defaults(tmp_path, monkeypatch):
    device = load_case_device(tmp_path, monkeypatch, "base")

    assert device.experimental_readonly is False
    assert device.lab is False


def test_openwrt_ignores_experimental_inventory_fields(tmp_path, monkeypatch):
    base = load_case_device(tmp_path, monkeypatch, "base")
    ignored = load_case_device(tmp_path, monkeypatch, "openwrt-ignores-experimental-fields")

    assert ignored == base


def test_valid_case_loads_the_new_device_fields(tmp_path, monkeypatch):
    key = tmp_path / "newton-key"
    key.write_text("FAKE-KEY-FOR-TESTS\n")
    key.chmod(0o600)
    inventory = tmp_path / "devices.toml"
    inventory.write_text(
        '[devices.quasar]\nplatform="openwrt"\nhost="192.0.2.1"\nuser="root"\n'
        f'key_file="{key}"\nknown_hosts="/var/lib/newton/hosts"\n'
        'wan_zones=["wan", "wan2"]\n'
    )
    monkeypatch.setenv("NEWTON_INVENTORY", str(inventory))
    device = server.load_inventory()["quasar"]
    assert device.key_file == key
    assert device.known_hosts == Path("/var/lib/newton/hosts")
    assert device.wan_zones == ("wan", "wan2")


def test_defaults_for_the_new_fields(tmp_path, monkeypatch):
    inventory = tmp_path / "devices.toml"
    inventory.write_text(
        '[devices.quasar]\nplatform="openwrt"\nhost="192.0.2.1"\nuser="root"\n'
    )
    monkeypatch.setenv("NEWTON_INVENTORY", str(inventory))
    device = server.load_inventory()["quasar"]
    assert device.key_file is None
    assert device.known_hosts is None
    assert device.wan_zones == ("wan",)
