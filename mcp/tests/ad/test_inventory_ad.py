"""The inventory entry of an AD collector device.

An AD device is read-only by definition: the registry gives its
platform the two AD tools and no write, so the entry needs no
experimental_readonly flag and may not claim a write.  The login is the
user principal name: the ssh client refuses the ``domain\\user`` form
(measured on the Windows DC).
"""

from __future__ import annotations

from pathlib import Path

import pytest

import newton_mcp.server as server


def _inventory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, body: str) -> None:
    """Write an inventory and point the loader at it."""
    path = tmp_path / "devices.toml"
    path.write_text(body)
    path.chmod(0o644)
    monkeypatch.setenv("NEWTON_INVENTORY", str(path))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))


@pytest.fixture
def known_hosts(tmp_path: Path) -> Path:
    """A known_hosts file for the collector host."""
    path = tmp_path / "known_hosts"
    path.write_text("192.0.2.10 ssh-ed25519 synthetic\n", encoding="utf-8")
    return path


def test_an_ad_device_loads_without_a_read_only_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, known_hosts: Path
) -> None:
    """The platform is read-only, so the entry needs no flag."""
    _inventory(
        tmp_path,
        monkeypatch,
        '[devices.dc1]\n'
        'platform = "ad-windows"\n'
        'host = "192.0.2.10"\n'
        'user = "newton-audit@win.newton.test"\n'
        f'known_hosts = "{known_hosts}"\n',
    )

    device = server.load_inventory()["dc1"]

    assert device.platform == "ad-windows"
    assert device.user == "newton-audit@win.newton.test"
    assert device.experimental_readonly is True
    assert device.vendor_write is False


def test_the_samba_platform_loads_the_same_way(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, known_hosts: Path
) -> None:
    """The Samba collector logs in with a plain user name."""
    _inventory(
        tmp_path,
        monkeypatch,
        '[devices.sambadc]\n'
        'platform = "ad-samba"\n'
        'host = "192.0.2.21"\n'
        'user = "newton-audit"\n'
        f'known_hosts = "{known_hosts}"\n',
    )

    device = server.load_inventory()["sambadc"]

    assert device.platform == "ad-samba"
    assert device.user == "newton-audit"


def test_a_write_is_refused_for_an_ad_device(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, known_hosts: Path
) -> None:
    """An AD device may not claim a write."""
    _inventory(
        tmp_path,
        monkeypatch,
        '[devices.dc1]\n'
        'platform = "ad-windows"\n'
        'host = "192.0.2.10"\n'
        'user = "newton-audit@win.newton.test"\n'
        'vendor_write = true\n'
        f'known_hosts = "{known_hosts}"\n',
    )

    with pytest.raises(server.NewtonError) as caught:
        server.load_inventory()

    assert "vendor_write is not available yet" in str(caught.value)


def test_a_user_outside_the_grammar_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, known_hosts: Path
) -> None:
    """A user that could look like an option is refused."""
    _inventory(
        tmp_path,
        monkeypatch,
        '[devices.dc1]\n'
        'platform = "ad-windows"\n'
        'host = "192.0.2.10"\n'
        'user = "-oProxyCommand=touch"\n'
        f'known_hosts = "{known_hosts}"\n',
    )

    with pytest.raises(server.NewtonError) as caught:
        server.load_inventory()

    assert "user fails the username grammar" in str(caught.value)


def test_the_listing_shows_the_ad_tools_and_no_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, known_hosts: Path
) -> None:
    """The device listing names the tools of the platform."""
    _inventory(
        tmp_path,
        monkeypatch,
        '[devices.dc1]\n'
        'platform = "ad-windows"\n'
        'host = "192.0.2.10"\n'
        'user = "newton-audit@win.newton.test"\n'
        f'known_hosts = "{known_hosts}"\n',
    )

    listed = server.newton_list_devices()
    entry = listed["devices"][0]

    assert entry["platform"] == "ad-windows"
    assert entry["writes"] is False
    assert entry["capabilities"]["writes"] is False
    assert entry["capabilities"]["native_revert"] is None
    assert entry["capabilities"]["tools"] == [
        "newton_ad_audit",
        "newton_ad_list_checks",
        "newton_list_devices",
    ]
