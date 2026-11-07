"""The shipped lab example must stay the twin of the live lab file.

lab/lab.toml is the live lab file: it names the maintainer's hypervisor, the lab
VMs and the key and token files, so it is not part of this repository.
lab/lab.example.toml is the shipped twin: the same tables and the same keys, with
synthetic values.  A table or a key that the live file gains and the example does
not is drift, and the example is what a reader of this repository sees.
"""
from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

LAB_DIR = Path(__file__).resolve().parent.parent
LIVE = LAB_DIR / "lab.toml"
EXAMPLE = LAB_DIR / "lab.example.toml"

# Without a live lab file there is nothing to compare the example against.
needs_live = pytest.mark.skipif(
	not LIVE.is_file(),
	reason="lab/lab.toml (the maintainer's live lab file) is not in this tree; "
	"nothing to compare the example against")


def _tables(data: dict) -> dict[str, dict]:
	"""The sub-tables of a table, without the keys of the table itself."""
	out: dict[str, dict] = {}
	for name, value in data.items():
		if isinstance(value, dict):
			out[name] = value
	return out


def test_example_exists_and_loads():
	assert EXAMPLE.is_file()
	with EXAMPLE.open("rb") as fh:
		tomllib.load(fh)


@needs_live
def test_example_has_the_same_tables_and_keys_as_the_live_file():
	live = tomllib.loads(LIVE.read_text(encoding="utf-8"))
	example = tomllib.loads(EXAMPLE.read_text(encoding="utf-8"))
	assert set(example) == set(live)
	for name, table in live.items():
		if isinstance(table, dict):
			assert set(example[name]) == set(table), name
		else:
			assert example[name] == table, name


@needs_live
def test_example_holds_no_house_value():
	"""The example names no address, no host or no path of the live lab."""
	text = EXAMPLE.read_text(encoding="utf-8")
	live = tomllib.loads(LIVE.read_text(encoding="utf-8"))
	example = tomllib.loads(EXAMPLE.read_text(encoding="utf-8"))
	# the hypervisor address and the token and pin files
	assert example["pve"]["host"] != live["pve"]["host"]
	assert example["pve"]["token_file"] != live["pve"]["token_file"]
	assert example["pve"]["pin_file"] != live["pve"]["pin_file"]
	# the ssh paths
	for key in ("proxy", "password_file", "key", "router_key",
				"approve_passphrase_file", "known_hosts"):
		assert example["ssh"][key] != live["ssh"][key], key
	# the VM ids
	for name, device in live["devices"].items():
		assert example["devices"][name]["vmid"] != device["vmid"], name
	# every home path of the example is the placeholder one
	for path in re.findall(r"/home/[^\s\"']+", text):
		assert path.startswith("/home/user/"), path
