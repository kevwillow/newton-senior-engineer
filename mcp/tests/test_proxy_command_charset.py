"""proxy_command is run by ssh through ``/bin/sh -c``.

The value is effectively a shell string, so the three sites that take it
from inventory or build argv from it must refuse any character outside
``[A-Za-z0-9 _./:@%~=,+-]`` and any length above 512.  This module drives
each of those sites the same way their existing tests do.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Any

import pytest

from newton_mcp import scans, server
from newton_mcp.adapters.ssh_cli import RunnerRefused, build_argv


@dataclasses.dataclass(frozen=True)
class _Target:
    """Concrete SshTarget for build_argv tests (Protocol can't instantiate)."""

    name: str
    platform: str
    host: str
    user: str
    auth: str
    port: int
    password_file: Path | None
    proxy_command: str | None
    key_file: Path | None
    known_hosts: Path | None


# 12 single-character tokens that are unsafe in a shell string plus an
# embedded newline and a trailing newline.  Each is refused at every site.
REFUSED_TOKENS: list[str] = [
    ";",
    "|",
    "&",
    "$",
    "`",
    "(",
    ")",
    "<",
    ">",
    "'",
    '"',
    "\\",
]
# A multi-character value that places a literal newline in the middle so
# the existing line-break check (not just the new charset check) fires.
EMBEDDED_NEWLINE = "nc\nbad"
# A trailing newline is also out-of-band for the existing check.
TRAILING_NEWLINE = "nc\n"
# An empty value and a value one over the 512-character cap are also
# rejected by the new charset.
TOO_LONG = "a" * 513
DOCUMENTED = "ssh -i ~/.ssh/key -o BatchMode=yes -W %h:%p root@jump"

# Combined parameter set: each entry must be refused at each site.
ALL_BAD: list[str] = [
    *REFUSED_TOKENS,
    EMBEDDED_NEWLINE,
    TRAILING_NEWLINE,
    "",
    TOO_LONG,
]


def _valid_target(known_hosts: Path, **changes: Any) -> _Target:
    """Return an SshTarget that passes every check except proxy_command."""
    values: dict[str, Any] = {
        "name": "lab-r1",
        "platform": "junos",
        "host": "router.test",
        "user": "admin",
        "auth": "key",
        "port": 22,
        "password_file": None,
        "proxy_command": None,
        "key_file": None,
        "known_hosts": known_hosts,
    }
    values.update(changes)
    return _Target(**values)


def _known_hosts(tmp_path: Path) -> Path:
    p = tmp_path / "known-hosts"
    p.write_text("key ssh-ed25519 synthetic\n", encoding="utf-8")
    return p


def _toml_escape(value: str) -> str:
    """Quote ``value`` for inclusion inside a TOML double-quoted string."""
    return (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )


# --- build_argv (ssh_cli) -------------------------------------------------


@pytest.mark.parametrize("bad", ALL_BAD)
def test_build_argv_refuses_bad_proxy_command_charset(
    tmp_path: Path, bad: str
) -> None:
    """build_argv rejects every token outside [A-Za-z0-9 _./:@%~=,+-]."""
    target = _valid_target(_known_hosts(tmp_path), proxy_command=bad)
    with pytest.raises(RunnerRefused) as caught:
        build_argv(target, "show version")
    assert "proxy_command" in str(caught.value)
    assert "lab-r1" in str(caught.value)


def test_build_argv_accepts_documented_proxy_command(tmp_path: Path) -> None:
    """The example in the ssh_cli docstring still loads at build_argv."""
    target = _valid_target(_known_hosts(tmp_path), proxy_command=DOCUMENTED)
    argv = build_argv(target, "show version")
    assert f"ProxyCommand={DOCUMENTED}" in argv


# --- load_inventory (server) ----------------------------------------------


def _device_inventory(tmp_path: Path, proxy_value: str) -> Path:
    inv = tmp_path / "devices.toml"
    inv.write_text(
        "[devices.lab]\n"
        'platform = "openwrt"\n'
        'host = "10.109.0.11"\n'
        'user = "root"\n'
        f'proxy_command = "{_toml_escape(proxy_value)}"\n'
    )
    return inv


@pytest.mark.parametrize("bad", ALL_BAD)
def test_load_inventory_refuses_bad_proxy_command_charset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bad: str
) -> None:
    """load_inventory rejects every token outside [A-Za-z0-9 _./:@%~=,+-]."""
    inv = _device_inventory(tmp_path, bad)
    monkeypatch.setenv("NEWTON_INVENTORY", str(inv))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))
    with pytest.raises(server.NewtonError) as caught:
        server.load_inventory()
    assert "proxy_command" in str(caught.value)
    assert "lab" in str(caught.value)


def test_load_inventory_refuses_charset_violation_with_percent_h(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A value that contains %h but a forbidden char is still refused."""
    inv = _device_inventory(tmp_path, "nc;bad %h")
    monkeypatch.setenv("NEWTON_INVENTORY", str(inv))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))
    with pytest.raises(server.NewtonError) as caught:
        server.load_inventory()
    assert "proxy_command" in str(caught.value)


def test_load_inventory_accepts_documented_proxy_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The documented ssh form still loads at load_inventory."""
    inv = _device_inventory(tmp_path, DOCUMENTED)
    monkeypatch.setenv("NEWTON_INVENTORY", str(inv))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))
    devices = server.load_inventory()
    assert devices["lab"].proxy_command == DOCUMENTED


# --- load_vantages (scans) ------------------------------------------------


def _vantage_inventory(tmp_path: Path, proxy_value: str) -> Path:
    key = tmp_path / "scan.key"
    known_hosts = tmp_path / "known_hosts"
    key.write_text("synthetic-key")
    known_hosts.write_text("synthetic host key\n")
    key.chmod(0o600)
    known_hosts.chmod(0o600)
    inv = tmp_path / "devices.toml"
    inv.write_text(
        "[devices.router]\n"
        'platform = "openwrt"\n'
        'host = "192.0.2.1"\n'
        'user = "root"\n'
        'wan_zones = ["wan"]\n'
        "\n"
        "[vantages.outside-a]\n"
        'host = "scan.example.invalid"\n'
        'user = "newton"\n'
        f'key_file = "{key}"\n'
        f'known_hosts = "{known_hosts}"\n'
        'role = "outside"\n'
        'devices = ["router"]\n'
        f'proxy_command = "{_toml_escape(proxy_value)}"\n'
    )
    return inv


@pytest.mark.parametrize("bad", ALL_BAD)
def test_load_vantages_refuses_bad_proxy_command_charset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bad: str
) -> None:
    """load_vantages rejects every token outside [A-Za-z0-9 _./:@%~=,+-]."""
    inv = _vantage_inventory(tmp_path, bad)
    monkeypatch.setenv("NEWTON_INVENTORY", str(inv))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))
    with pytest.raises(scans.ScanError) as caught:
        scans.load_vantages()
    assert "proxy_command" in str(caught.value)
    assert "outside-a" in str(caught.value)


def test_load_vantages_refuses_charset_violation_with_percent_h(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A value that contains %h but a forbidden char is still refused."""
    inv = _vantage_inventory(tmp_path, "nc;bad %h")
    monkeypatch.setenv("NEWTON_INVENTORY", str(inv))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))
    with pytest.raises(scans.ScanError) as caught:
        scans.load_vantages()
    assert "proxy_command" in str(caught.value)


def test_load_vantages_accepts_documented_proxy_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The documented ssh form still loads at load_vantages."""
    inv = _vantage_inventory(tmp_path, DOCUMENTED)
    monkeypatch.setenv("NEWTON_INVENTORY", str(inv))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))
    vantages = scans.load_vantages()
    assert vantages["outside-a"].proxy_command == DOCUMENTED

# The ALL_BAD rows above are mostly stopped by the earlier "%h" rule at the two
# loaders, so they would pass without the charset check.  These rows contain %h
# and a single unsafe token, so only the charset check can refuse them.
_WITH_PERCENT_H = [f"nc %h {tok}" for tok in REFUSED_TOKENS] + ["nc %h " + "a" * 520]


@pytest.mark.parametrize("bad", _WITH_PERCENT_H)
def test_load_inventory_charset_check_alone_refuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bad: str
) -> None:
    inv = _device_inventory(tmp_path, bad)
    monkeypatch.setenv("NEWTON_INVENTORY", str(inv))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))
    with pytest.raises(server.NewtonError) as caught:
        server.load_inventory()
    assert "characters outside" in str(caught.value)


@pytest.mark.parametrize("bad", _WITH_PERCENT_H)
def test_load_vantages_charset_check_alone_refuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bad: str
) -> None:
    inv = _vantage_inventory(tmp_path, bad)
    monkeypatch.setenv("NEWTON_INVENTORY", str(inv))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))
    with pytest.raises(scans.ScanError) as caught:
        scans.load_vantages()
    assert "characters outside" in str(caught.value)
