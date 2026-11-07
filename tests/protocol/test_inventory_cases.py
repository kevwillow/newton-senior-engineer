"""Every case in mcp/tests/inventory_cases.json through the REAL setup
loader: scripts/newton-router-setup is sourced and its load_inventory runs
on the case's inventory file (the same file the MCP-side test in
mcp/tests/test_inventory_cases.py loads); both loaders must agree with
"ok", except where a case's setup_ok records the setup loader's own verdict."""

import json
import subprocess
from pathlib import Path

import pytest

MODULE_DIR = Path(__file__).resolve().parent
REPO = MODULE_DIR.parent.parent
TOOL = REPO / "scripts/newton-router-setup"

DATA = json.loads((REPO / "mcp/tests/inventory_cases.json").read_text())
CASES = DATA["cases"]

SOURCE_RUN = r'''
source "$1"
valid_device "$3" || { echo "error: bad device: $3" >&2; exit 2; }
INVENTORY="$2"
load_inventory "$3"
'''


def toml_value(value):
    if isinstance(value, str):
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'
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
    # write_text creates 0666 & ~umask, i.e. 0664 under umask 0002, which the
    # inventory-file check in scripts/newton-router-setup refuses; pin it.
    inventory.chmod(0o644)
    return inventory


@pytest.fixture(autouse=True)
def setup_files(tmp_path):
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text(
        "192.0.2.9 ssh-ed25519 "
        "AAAAC3NzaC1lZDI1NTE5AAAAIFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE\n"
    )
    (tmp_path / "known_hosts_link").symlink_to(known_hosts)
    password = tmp_path / "pw"
    password.write_text("synthetic-password\n")
    password.chmod(0o600)


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_setup_load_inventory_agrees_with_the_case(tmp_path, case):
    inventory = write_inventory(tmp_path, case)
    name = inventory.read_text().splitlines()[0][len("[devices."):-1]
    proc = subprocess.run(
        ["bash", "-c", SOURCE_RUN, "bash", str(TOOL), str(inventory), name],
        capture_output=True, text=True, timeout=30,
        stdin=subprocess.DEVNULL, env={"PATH": "/usr/bin:/bin"},
    )
    ok = proc.returncode == 0
    assert ok == case.get("setup_ok", case["ok"]), (
        case["id"], proc.returncode, proc.stderr[-400:]
    )


def test_a_bad_value_is_reported_not_crashed(tmp_path):
    """The setup loader refuses with one `error: ...` line and exit 2."""
    inventory = tmp_path / "devices.toml"
    inventory.write_text('[devices.quasar]\nhost="192.0.2.1"\nuser="root"\nwan_zones=[]\n')
    inventory.chmod(0o644)
    proc = subprocess.run(
        ["bash", "-c", SOURCE_RUN, "bash", str(TOOL), str(inventory), "quasar"],
        capture_output=True, text=True, timeout=30,
        stdin=subprocess.DEVNULL, env={"PATH": "/usr/bin:/bin"},
    )
    assert proc.returncode == 2
    assert proc.stderr.count("\n") == 1
    assert proc.stderr.startswith("error: ")
