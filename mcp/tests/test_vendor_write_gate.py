"""The registry, the inventory key and the write gate for vendors.

The registry gives VyOS the vendor write tools, the inventory says which
device may use them, and ``NewtonService.device_for`` refuses a write tool
on a device that is not allowed to write.  No device is contacted.


"""

from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest

import newton_mcp.server as server
from newton_mcp.adapters import base, registry
from newton_mcp.server import NewtonError


WRITE_TOOLS = (
    "newton_backup",
    "newton_plan_change",
    "newton_apply_change",
    "newton_change_status",
    "newton_abort_change",
)


@pytest.fixture
def known_hosts(tmp_path: Path) -> Path:
    """A synthetic known_hosts file the loader accepts."""
    path = tmp_path / "known_hosts"
    path.write_text(
        "192.0.2.9 ssh-ed25519 "
        "AAAAC3NzaC1lZDI1NTE5AAAAIFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE\n",
        encoding="utf-8",
    )
    return path


@pytest.fixture
def key_file(tmp_path: Path) -> Path:
    """A synthetic key file with the mode the loader requires."""
    path = tmp_path / "newton-key"
    path.write_text("FAKE-KEY-FOR-TESTS\n", encoding="utf-8")
    path.chmod(0o600)
    return path


def write_inventory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    body: str,
) -> None:
    """Write one inventory file and point the loader at it."""
    inventory = tmp_path / "devices.toml"
    inventory.write_text(body, encoding="utf-8")
    monkeypatch.setenv("NEWTON_INVENTORY", str(inventory))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))


def test_vyos_gets_the_vendor_write_tools(
    known_hosts: Path,
    key_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """VyOS is T1 with the vendor write tools; the others are not.

    RouterOS is the second write platform: it is a T2, because
    its revert is a reboot into the backup.  Junos is the third since
    it is a T1, because its revert is its own commit confirmed.
    """
    vyos = registry.capabilities("vyos")

    assert vyos.tier == "T1"
    assert vyos.writes is True
    assert vyos.native_revert == "commit-confirm"
    assert vyos.tools == base.READ_ONLY_TOOLS | frozenset(WRITE_TOOLS)
    assert registry.VENDOR_WRITE_TOOLS == vyos.tools

    routeros = registry.capabilities("routeros")
    assert routeros.tier == "T2"
    assert routeros.writes is True
    assert routeros.native_revert == "reboot-into-backup"
    assert routeros.tools == vyos.tools

    junos = registry.capabilities("junos")
    assert junos.tier == "T1"
    assert junos.writes is True
    assert junos.native_revert == "commit confirmed"
    assert junos.tools == vyos.tools

    for platform in ("eos", "iosxe", "fortios"):
        caps = registry.capabilities(platform)
        assert caps.tier == "T0-exp"
        assert caps.writes is False
        assert caps.native_revert is None
        assert caps.tools == base.READ_ONLY_TOOLS

    # The capability invariant still holds for a read-only platform.
    with pytest.raises(ValueError):
        base.Capabilities(
            tier="T0-exp",
            writes=False,
            native_revert=None,
            tools=frozenset(WRITE_TOOLS),
        )


def test_a_vendor_write_vyos_device_loads(
    known_hosts: Path,
    key_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Vendor_write = true on a lab VyOS device loads."""
    write_inventory(
        tmp_path,
        monkeypatch,
        '[devices.vy1]\n'
        'platform = "vyos"\n'
        'host = "192.0.2.9"\n'
        'user = "newton"\n'
        'auth = "key"\n'
        'profile = "lab"\n'
        "vendor_write = true\n"
        "lab = true\n"
        f'key_file = "{key_file}"\n'
        f'known_hosts = "{known_hosts}"\n',
    )

    device = server.load_inventory()["vy1"]

    assert device.platform == "vyos"
    assert device.vendor_write is True
    assert device.experimental_readonly is False
    assert device.lab is True
    assert device.key_file == key_file
    assert device.known_hosts == known_hosts


@pytest.mark.parametrize(
    ("case", "fields", "expected"),
    [
        (
            "no-key-file",
            "vendor_write = true\nlab = true\n",
            "vendor_write requires key_file",
        ),
        (
            "password-auth",
            'auth = "password"\n'
            'password_file = "{password}"\n'
            "vendor_write = true\nlab = true\n"
            'key_file = "{key}"\n',
            "vendor_write requires auth = 'key'",
        ),
        (
            "not-lab",
            "vendor_write = true\n"
            'key_file = "{key}"\n',
            "vyos devices are lab-only in this release",
        ),
        (
            "both-flags",
            "vendor_write = true\nexperimental_readonly = true\nlab = true\n"
            'key_file = "{key}"\n',
            "mutually exclusive",
        ),
    ],
)
def test_a_vendor_write_device_must_be_complete(
    known_hosts: Path,
    key_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
    fields: str,
    expected: str,
) -> None:
    """A vendor write device needs a key, key auth and the lab flag."""
    password = tmp_path / "pw"
    password.write_text("synthetic-password\n", encoding="utf-8")
    password.chmod(0o600)
    body = (
        '[devices.vy1]\n'
        'platform = "vyos"\n'
        'host = "192.0.2.9"\n'
        'user = "newton"\n'
        + fields.format(password=password, key=key_file)
        + f'known_hosts = "{known_hosts}"\n'
    )
    write_inventory(tmp_path, monkeypatch, body)

    with pytest.raises(NewtonError) as caught:
        server.load_inventory()

    assert expected in str(caught.value)
    assert "vy1" in str(caught.value)


def test_vendor_write_is_not_available_for_the_other_platforms(
    known_hosts: Path,
    key_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Eos and the other vendors refuse the key for now.

    RouterOS is a write platform and Junos, so
    the refusal moved to the vendors that have no write path yet.
    """
    write_inventory(
        tmp_path,
        monkeypatch,
        '[devices.eo1]\n'
        'platform = "eos"\n'
        'host = "192.0.2.9"\n'
        'user = "newton"\n'
        "vendor_write = true\n"
        f'known_hosts = "{known_hosts}"\n',
    )

    with pytest.raises(NewtonError) as caught:
        server.load_inventory()

    assert "vendor_write is not available yet" in str(caught.value)
    assert "eos" in str(caught.value)


def test_a_read_only_device_still_names_both_ways(
    known_hosts: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The read-only refusal still names experimental_readonly."""
    write_inventory(
        tmp_path,
        monkeypatch,
        '[devices.vy1]\n'
        'platform = "vyos"\n'
        'host = "192.0.2.9"\n'
        'user = "newton"\n'
        "lab = true\n"
        f'known_hosts = "{known_hosts}"\n',
    )

    with pytest.raises(NewtonError) as caught:
        server.load_inventory()

    message = str(caught.value)
    assert "set experimental_readonly = true" in message
    assert "vendor_write" in message


@dataclasses.dataclass
class _Lab:
    """A three-platform inventory for the gate."""

    devices: dict[str, server.Device]


@pytest.fixture
def lab(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> _Lab:
    """An OpenWrt peer, a read-only VyOS peer and a writing VyOS peer."""
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("key ssh-ed25519 synthetic\n", encoding="utf-8")
    devices = {
        "quasar": server.Device(
            name="quasar",
            platform="openwrt",
            host="192.0.2.1",
            user="root",
        ),
        "vy1": server.Device(
            name="vy1",
            platform="vyos",
            host="192.0.2.9",
            user="newton",
            experimental_readonly=True,
            lab=True,
            known_hosts=known_hosts,
        ),
        "vy2": server.Device(
            name="vy2",
            platform="vyos",
            host="192.0.2.10",
            user="newton",
            vendor_write=True,
            lab=True,
            known_hosts=known_hosts,
        ),
        "ros1": server.Device(
            name="ros1",
            platform="routeros",
            host="192.0.2.11",
            user="newton",
            experimental_readonly=True,
            known_hosts=known_hosts,
        ),
        "jn1": server.Device(
            name="jn1",
            platform="junos",
            host="192.0.2.12",
            user="newton",
            experimental_readonly=True,
            known_hosts=known_hosts,
        ),
        "eo1": server.Device(
            name="eo1",
            platform="eos",
            host="192.0.2.13",
            user="newton",
            experimental_readonly=True,
            known_hosts=known_hosts,
        ),
    }
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setattr(server, "load_inventory", lambda: devices)
    return _Lab(devices=devices)


def test_a_read_only_device_refuses_every_write_tool(
    lab: _Lab,
) -> None:
    """A read-only VyOS device refuses all five write tools."""
    service = server.NewtonService()

    for tool in WRITE_TOOLS:
        with pytest.raises(NewtonError) as caught:
            service.device_for(tool, "vy1")
        assert str(caught.value) == (
            "device vy1 is read-only; vendor_write is not enabled"
        )


def test_a_writing_device_passes_the_write_gate(lab: _Lab) -> None:
    """Vendor_write = true opens the five write tools and no more."""
    service = server.NewtonService()

    for tool in WRITE_TOOLS:
        assert service.device_for(tool, "vy2") is lab.devices["vy2"]
    # The read tools are unchanged on a writing device.
    assert service.device_for("newton_get_state", "vy2") is lab.devices["vy2"]
    assert service.device_for("newton_list_getters", "vy2") is lab.devices["vy2"]
    # OpenWrt keeps every tool it had.
    for tool in WRITE_TOOLS:
        assert service.device_for(tool, "quasar") is lab.devices["quasar"]
    # A device of a platform that may write, but that may not write itself,
    # is refused by the vendor_write gate.  A Junos is such a
    # platform.
    with pytest.raises(NewtonError) as caught:
        service.device_for("newton_plan_change", "ros1")
    assert str(caught.value) == (
        "device ros1 is read-only; vendor_write is not enabled"
    )
    with pytest.raises(NewtonError) as caught:
        service.device_for("newton_plan_change", "jn1")
    assert str(caught.value) == (
        "device jn1 is read-only; vendor_write is not enabled"
    )
    # A platform without the vendor write tools still refuses them by platform.
    with pytest.raises(NewtonError) as caught:
        service.device_for("newton_plan_change", "eo1")
    assert str(caught.value) == (
        "newton_plan_change is not available for platform eos"
    )


def test_list_devices_shows_the_write_flag(lab: _Lab) -> None:
    """A non-OpenWrt entry says whether the device may write."""
    listed = server.NewtonService().list_devices()
    entries = {row["name"]: row for row in listed["devices"]}

    assert entries["vy2"]["writes"] is True
    assert entries["vy1"]["writes"] is False
    assert entries["ros1"]["writes"] is False
    # The OpenWrt entry keeps exactly the keys it had.
    assert "writes" not in entries["quasar"]
    assert set(entries["vy1"]) == {
        "name",
        "platform",
        "host",
        "user",
        "auth",
        "profile",
        "tier",
        "capabilities",
        "writes",
        "easy_grant",
    }


def test_the_write_flag_defaults_to_false() -> None:
    """A device without the key is read-only by default."""
    device = server.Device(
        name="vy1",
        platform="vyos",
        host="192.0.2.9",
        user="newton",
    )

    assert device.vendor_write is False
