"""INJ-1: the inventory host and the inventory user are pasted into an ssh
argv (``<user>@<host>``), so both must match the same grammar the getter
lane already uses, and the destination must be preceded by ``--`` so ssh
can never read it as an option.

A user of ``-oProxyCommand=...`` would otherwise make ssh run the
attacker's command instead of connecting to the router, so the loader
refuses any host or user outside the hostname / username grammar.  The
same rules apply to the scan vantage loader (``scans.load_vantages``),
which has its own host and user fields.

All values here are synthetic (192.0.2.x, ``router1``, ``.invalid``).
"""

from __future__ import annotations

import subprocess

import pytest

import newton_mcp.scans as scans
import newton_mcp.server as server
from newton_mcp.adapters import ssh_cli


BAD_HOSTS = [
    "-oProxyCommand=x",
    "-o",
    "-",
    "a b",
    "a;b",
    "$(x)",
    "a\nb",
    "h" * 254,
]

BAD_USERS = [
    "-oProxyCommand=x",
    "-o",
    "-",
    "a b",
    "a;b",
    "$(x)",
    "a\nb",
    "u" * 33,
]

GOOD_HOSTS = [
    "192.0.2.1",
    "router1.example.invalid",
    "fe80::1",
]

GOOD_USERS = [
    "root",
    "admin_1",
]


def _toml(value: str) -> str:
    """A TOML basic string holding exactly *value* (control chars escaped)."""
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    for char, name in (("\n", "n"), ("\r", "r"), ("\t", "t")):
        escaped = escaped.replace(char, f"\\{name}")
    return f'"{escaped}"'


def _inventory(tmp_path, monkeypatch, host="192.0.2.1", user="root", extra=""):
    """Write a one-device inventory and point the loader at it."""
    path = tmp_path / "devices.toml"
    path.write_text(
        '[devices.quasar]\nplatform = "openwrt"\n'
        f"host = {_toml(host)}\nuser = {_toml(user)}\n{extra}"
    )
    path.chmod(0o644)
    monkeypatch.setenv("NEWTON_INVENTORY", str(path))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))
    return path


def _vantage_inventory(tmp_path, monkeypatch, host="scan.example.invalid", user="newton"):
    """Write an inventory with one vantage whose key/known_hosts files exist."""
    key = tmp_path / "vantage.key"
    key.write_text("synthetic-key\n")
    key.chmod(0o600)
    known_hosts = tmp_path / "vantage.hosts"
    known_hosts.write_text("synthetic host key\n")
    known_hosts.chmod(0o644)
    path = tmp_path / "devices.toml"
    path.write_text(
        '[devices.quasar]\nplatform = "openwrt"\nhost = "192.0.2.1"\nuser = "root"\n'
        "wan_zones=[\"wan\"]\n\n"
        f'[vantages.inside-a]\nhost = {_toml(host)}\nuser = {_toml(user)}\n'
        f'key_file = "{key}"\nknown_hosts = "{known_hosts}"\n'
        'role = "inside"\ndevices = ["quasar"]\n'
    )
    path.chmod(0o644)
    monkeypatch.setenv("NEWTON_INVENTORY", str(path))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))
    return path


# ---- the inventory loader ---------------------------------------------------


@pytest.mark.parametrize("host", BAD_HOSTS)
def test_host_outside_the_grammar_is_refused(tmp_path, monkeypatch, host):
    _inventory(tmp_path, monkeypatch, host=host)
    with pytest.raises(
        server.NewtonError,
        match=r"device quasar: host fails the hostname grammar",
    ):
        server.load_inventory()


@pytest.mark.parametrize("user", BAD_USERS)
def test_user_outside_the_grammar_is_refused(tmp_path, monkeypatch, user):
    _inventory(tmp_path, monkeypatch, user=user)
    with pytest.raises(
        server.NewtonError,
        match=r"device quasar: user fails the username grammar",
    ):
        server.load_inventory()


@pytest.mark.parametrize("host", GOOD_HOSTS)
def test_documented_hosts_still_load(tmp_path, monkeypatch, host):
    _inventory(tmp_path, monkeypatch, host=host)
    assert server.load_inventory()["quasar"].host == host


@pytest.mark.parametrize("user", GOOD_USERS)
def test_documented_users_still_load(tmp_path, monkeypatch, user):
    _inventory(tmp_path, monkeypatch, user=user)
    assert server.load_inventory()["quasar"].user == user


def test_refusal_names_the_device_and_the_rule_not_the_value(tmp_path, monkeypatch):
    _inventory(tmp_path, monkeypatch, host="-oProxyCommand=touch")
    with pytest.raises(server.NewtonError) as exc:
        server.load_inventory()
    message = str(exc.value)
    assert "quasar" in message
    assert "ProxyCommand" not in message


def test_the_loader_uses_the_getter_lane_grammar():
    """One grammar for both lanes: the shared public regexes, not a copy."""
    assert server.HOST_RE.pattern == ssh_cli.HOST_RE.pattern
    assert server.USER_RE.pattern == ssh_cli.USER_RE.pattern


# ---- the ssh argv -----------------------------------------------------------


def test_read_puts_a_double_dash_before_the_destination(tmp_path, monkeypatch):
    _inventory(tmp_path, monkeypatch)
    seen = {}

    def fake_run(args, **kwargs):
        seen["args"] = list(args)
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(server.subprocess, "run", fake_run)
    server.newton_read("quasar", "uci show")

    args = seen["args"]
    separator = args.index("--")
    assert args[separator + 1] == "root@192.0.2.1"
    assert args[separator - 1] != "--"
    assert args[-2] == "root@192.0.2.1"


# ---- the scan vantage loader ------------------------------------------------


@pytest.mark.parametrize("host", BAD_HOSTS)
def test_vantage_host_outside_the_grammar_is_refused(tmp_path, monkeypatch, host):
    _vantage_inventory(tmp_path, monkeypatch, host=host)
    with pytest.raises(scans.ScanError, match=r"vantage inside-a: host"):
        scans.load_vantages()


@pytest.mark.parametrize("user", BAD_USERS)
def test_vantage_user_outside_the_grammar_is_refused(tmp_path, monkeypatch, user):
    _vantage_inventory(tmp_path, monkeypatch, user=user)
    with pytest.raises(scans.ScanError, match=r"vantage inside-a: user"):
        scans.load_vantages()


def test_vantage_puts_a_double_dash_before_the_destination(tmp_path, monkeypatch):
    seen = {}

    def fake_run(argv, **kwargs):
        seen["argv"] = list(argv)
        return subprocess.CompletedProcess(argv, 0, "", "")

    vantage = scans.Vantage(
        name="inside-a",
        host="scan.example.invalid",
        user="newton",
        key_file=tmp_path / "vantage.key",
        known_hosts=tmp_path / "vantage.hosts",
        proxy_command=None,
        role="inside",
        devices=("quasar",),
    )
    scans.run_vantage(
        vantage,
        ["scan", "quick", "outside", "198.51.100.9"],
        run=fake_run,
    )

    argv = seen["argv"]
    separator = argv.index("--")
    assert argv[separator + 1] == "newton@scan.example.invalid"
    assert argv[separator - 1] != "--"
