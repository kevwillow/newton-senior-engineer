"""the inventory fields of the no-install mode, and the choke point.

An OpenWrt device may say ``access = "no-install"``.  Most tools refuse
such a device at the one choke point (``NewtonService.device``) and no
tool reaches ssh.  Two tools work on one: the read asks the router's
own web API instead of ssh, and the plan (ADR-021 point 4) plans the
change over that same web API -- an auto plan for the allowlisted
classes, an owner script for everything else.  The device is still
listed, with its access mode, so the owner can see it.
"""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
from pathlib import Path

import pytest

import newton_mcp.server as server
from newton_mcp import noinstall_read
from newton_mcp.adapters import registry
from noinstall_answers import data
from noinstall_fakes import FakeRouter

# A synthetic pin (the sha256 of a fixed string): the shape matters, the
# value does not, and no lab certificate's fingerprint belongs in git.
PIN = base64.b64encode(hashlib.sha256(b"newton-noinstall-test-pin").digest()).decode()
NO_INSTALL_MESSAGE = (
    "device lab-r1 uses no-install access; Newton cannot manage it yet "
    "in this version"
)

# Every device tool, with the arguments it needs to reach the choke
# point.  A new tool must be added here: the test below iterates the
# server's own tool list.
TOOL_CALLS: dict[str, tuple] = {
    "newton_read": ("lab-r1", "uci show"),
    "newton_backup": ("lab-r1",),
    "newton_plan_change": ("lab-r1", "set network.lan.proto='static'"),
    "newton_plan_undo": ("lab-r1", "0" * 32),
    "newton_apply_change": ("lab-r1", "0" * 32),
    "newton_change_status": ("lab-r1", "0" * 32),
    "newton_abort_change": ("lab-r1", "0" * 32),
    "newton_grant_off": ("lab-r1",),
    "newton_plan_scan": ("lab-r1", "inside", "quick", "lan"),
    "newton_run_scan": ("lab-r1", "0" * 32),
    "newton_plan_tier": ("lab-r1", "standard", 0),
    "newton_guided_audit": ("lab-r1",),
    "newton_list_getters": ("lab-r1",),
    "newton_get_state": ("lab-r1", "running_config"),
    "newton_ad_audit": ("lab-r1",),
    "newton_ad_plan_change": ("lab-r1", "uac-clear"),
    "newton_ad_apply_change": ("lab-r1", "0" * 32),
    "newton_ad_change_status": ("lab-r1", "0" * 32),
    "newton_ad_abort_change": ("lab-r1", "0" * 32),
}

# The tools that take no device at all.
DEVICE_FREE_TOOLS = {
    "newton_list_devices",
    "newton_list_tiers",
    "newton_guided_recommend",
    "newton_ad_list_checks",
}

# The tools that may work on a no-install device.  The read goes to
# the router's own web API, so it does not need anything installed.  The
# plan goes there too (it decides between an auto plan and an owner
# script) and the apply, the status and the abort answer for a plan of
# that device.  Every other tool is refused at the choke point.
# The tools that answer for a no-install device.  This is the server's
# own set (server.NO_INSTALL_TOOLS), never a second hand-written copy:
# the same set says which tools the refusal at the choke point lets
# through and which tools the device listing advertises.
NO_INSTALL_ALLOWED = server.NO_INSTALL_TOOLS


def _password_file(tmp_path: Path, mode: int = 0o600) -> Path:
    path = tmp_path / "rpcd-password"
    path.write_text("synthetic-password\n", encoding="utf-8")
    path.chmod(mode)
    return path


def _write_inventory(tmp_path: Path, monkeypatch, body: str) -> Path:
    inventory = tmp_path / "devices.toml"
    inventory.write_text(body, encoding="utf-8")
    inventory.chmod(0o644)
    monkeypatch.setenv("NEWTON_INVENTORY", str(inventory))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))
    return inventory


def _no_install_body(tmp_path: Path, extra: str = "") -> str:
    password = _password_file(tmp_path)
    return (
        '[devices.lab-r1]\nplatform = "openwrt"\nhost = "192.0.2.1"\nuser = "root"\n'
        'access = "no-install"\n'
        f'rpcd_password_file = "{password}"\n'
        f'https_spki = "{PIN}"\n' + extra
    )


# ---- the defaults ----------------------------------------------------------


def test_an_inventory_without_access_keeps_working(tmp_path, monkeypatch) -> None:
    _write_inventory(
        tmp_path,
        monkeypatch,
        '[devices.lab-r1]\nplatform = "openwrt"\nhost = "192.0.2.1"\nuser = "root"\n',
    )
    device = server.load_inventory()["lab-r1"]
    assert device.access == "installed"
    assert device.rpcd_password_file is None
    assert device.https_spki is None
    assert device.https_host is None
    assert device.https_port == 443


def test_the_no_install_fields_are_read(tmp_path, monkeypatch) -> None:
    _write_inventory(tmp_path, monkeypatch, _no_install_body(tmp_path))
    device = server.load_inventory()["lab-r1"]
    assert device.access == "no-install"
    assert device.https_spki == PIN
    assert device.https_host == "192.0.2.1"
    assert device.https_port == 443
    assert device.rpcd_password_file is not None


def test_the_https_host_and_port_may_be_given(tmp_path, monkeypatch) -> None:
    _write_inventory(
        tmp_path,
        monkeypatch,
        _no_install_body(tmp_path, extra='https_host = "router.test"\nhttps_port = 8443\n'),
    )
    device = server.load_inventory()["lab-r1"]
    assert device.https_host == "router.test"
    assert device.https_port == 8443


# ---- the refusals ----------------------------------------------------------


def test_an_unknown_access_is_refused(tmp_path, monkeypatch) -> None:
    body = (
        '[devices.lab-r1]\nplatform = "openwrt"\nhost = "192.0.2.1"\nuser = "root"\n'
        'access = "maybe"\n'
    )
    _write_inventory(tmp_path, monkeypatch, body)
    with pytest.raises(server.NewtonError) as caught:
        server.load_inventory()
    assert "access" in str(caught.value)


def test_access_on_a_non_openwrt_device_is_refused(tmp_path, monkeypatch) -> None:
    known_hosts = tmp_path / "known-hosts"
    known_hosts.write_text("synthetic\n", encoding="utf-8")
    _write_inventory(
        tmp_path,
        monkeypatch,
        '[devices.jx1]\nplatform = "junos"\nhost = "192.0.2.9"\nuser = "junos"\n'
        'experimental_readonly = true\n'
        f'known_hosts = "{known_hosts}"\n'
        'access = "no-install"\n',
    )
    with pytest.raises(server.NewtonError) as caught:
        server.load_inventory()
    assert "access" in str(caught.value)


def test_no_install_without_a_password_file_is_refused(tmp_path, monkeypatch) -> None:
    body = (
        '[devices.lab-r1]\nplatform = "openwrt"\nhost = "192.0.2.1"\nuser = "root"\n'
        'access = "no-install"\n'
        f'https_spki = "{PIN}"\n'
    )
    _write_inventory(tmp_path, monkeypatch, body)
    with pytest.raises(server.NewtonError) as caught:
        server.load_inventory()
    assert "rpcd_password_file" in str(caught.value)


def test_no_install_without_a_pin_is_refused(tmp_path, monkeypatch) -> None:
    password = _password_file(tmp_path)
    body = (
        '[devices.lab-r1]\nplatform = "openwrt"\nhost = "192.0.2.1"\nuser = "root"\n'
        'access = "no-install"\n'
        f'rpcd_password_file = "{password}"\n'
    )
    _write_inventory(tmp_path, monkeypatch, body)
    with pytest.raises(server.NewtonError) as caught:
        server.load_inventory()
    assert "https_spki" in str(caught.value)


@pytest.mark.parametrize(
    "pin",
    [
        "",
        "short",
        "A" * 43,                                # 43 characters
        "A" * 43 + "==",                          # 32 bytes, 45 characters
        "A" * 42 + "!=",                          # not base64
    ],
)
def test_a_bad_pin_is_refused(tmp_path, monkeypatch, pin) -> None:
    password = _password_file(tmp_path)
    body = (
        '[devices.lab-r1]\nplatform = "openwrt"\nhost = "192.0.2.1"\nuser = "root"\n'
        'access = "no-install"\n'
        f'rpcd_password_file = "{password}"\n'
        f'https_spki = "{pin}"\n'
    )
    _write_inventory(tmp_path, monkeypatch, body)
    with pytest.raises(server.NewtonError) as caught:
        server.load_inventory()
    assert "https_spki" in str(caught.value)


def test_a_pin_of_31_bytes_is_refused(tmp_path, monkeypatch) -> None:
    short = base64.b64encode(b"x" * 31).decode()
    password = _password_file(tmp_path)
    body = (
        '[devices.lab-r1]\nplatform = "openwrt"\nhost = "192.0.2.1"\nuser = "root"\n'
        'access = "no-install"\n'
        f'rpcd_password_file = "{password}"\n'
        f'https_spki = "{short}"\n'
    )
    _write_inventory(tmp_path, monkeypatch, body)
    with pytest.raises(server.NewtonError):
        server.load_inventory()


def test_a_bad_https_host_is_refused(tmp_path, monkeypatch) -> None:
    _write_inventory(
        tmp_path,
        monkeypatch,
        _no_install_body(tmp_path, extra='https_host = "not a host"\n'),
    )
    with pytest.raises(server.NewtonError) as caught:
        server.load_inventory()
    assert "https_host" in str(caught.value)


def test_a_bad_https_port_is_refused(tmp_path, monkeypatch) -> None:
    _write_inventory(tmp_path, monkeypatch, _no_install_body(tmp_path, extra="https_port = 0\n"))
    with pytest.raises(server.NewtonError) as caught:
        server.load_inventory()
    assert "https_port" in str(caught.value)


def test_a_world_readable_rpcd_password_file_is_refused(tmp_path, monkeypatch) -> None:
    body = (
        '[devices.lab-r1]\nplatform = "openwrt"\nhost = "192.0.2.1"\nuser = "root"\n'
        'access = "no-install"\n'
        f'rpcd_password_file = "{_password_file(tmp_path, mode=0o644)}"\n'
        f'https_spki = "{PIN}"\n'
    )
    _write_inventory(tmp_path, monkeypatch, body)
    with pytest.raises(server.NewtonError) as caught:
        server.load_inventory()
    assert "0600" in str(caught.value)


def test_a_symlinked_rpcd_password_file_is_refused(tmp_path, monkeypatch) -> None:
    real = _password_file(tmp_path)
    link = tmp_path / "link"
    link.symlink_to(real)
    body = (
        '[devices.lab-r1]\nplatform = "openwrt"\nhost = "192.0.2.1"\nuser = "root"\n'
        'access = "no-install"\n'
        f'rpcd_password_file = "{link}"\n'
        f'https_spki = "{PIN}"\n'
    )
    _write_inventory(tmp_path, monkeypatch, body)
    with pytest.raises(server.NewtonError):
        server.load_inventory()


def test_a_missing_rpcd_password_file_is_refused(tmp_path, monkeypatch) -> None:
    body = (
        '[devices.lab-r1]\nplatform = "openwrt"\nhost = "192.0.2.1"\nuser = "root"\n'
        'access = "no-install"\n'
        f'rpcd_password_file = "{tmp_path / "nope"}"\n'
        f'https_spki = "{PIN}"\n'
    )
    _write_inventory(tmp_path, monkeypatch, body)
    with pytest.raises(server.NewtonError):
        server.load_inventory()


# ---- the choke point -------------------------------------------------------


def test_every_other_device_tool_refuses_a_no_install_device(
    tmp_path, monkeypatch
) -> None:
    """Every tool but the read and the plan refuses a no-install device.

    The read and the plan ask the router's own web API , so
    they are the two that work; every other tool stops at the choke
    point and reaches no ssh.
    """
    _write_inventory(tmp_path, monkeypatch, _no_install_body(tmp_path))
    ran: list = []
    original_run = subprocess.run

    def guarded_run(argv, *args, **kwargs):
        ran.append(argv)
        return original_run(argv, *args, **kwargs)

    monkeypatch.setattr(subprocess, "run", guarded_run)

    assert set(TOOL_CALLS) | DEVICE_FREE_TOOLS == set(server.TOOL_NAMES)
    for tool, args in TOOL_CALLS.items():
        if tool in NO_INSTALL_ALLOWED:
            continue
        result = getattr(server, tool)(*args)
        assert isinstance(result, dict), tool
        assert result.get("error") == NO_INSTALL_MESSAGE, tool
    assert ran == [], "no tool may reach ssh for a no-install device"


def _refuse_ssh(monkeypatch) -> None:
    """Make every path to ssh fail loudly."""

    def refuse(*args, **kwargs):
        raise AssertionError("a no-install read must not reach ssh")

    refuse.cache_clear = server._ssh_path.resolve_ssh.cache_clear
    monkeypatch.setattr(subprocess, "run", refuse)
    monkeypatch.setattr(server._ssh_path, "resolve_ssh", refuse)


def test_the_read_of_a_no_install_device_never_reaches_ssh(
    tmp_path, monkeypatch
) -> None:
    """the read asks the router's web API, and nothing else."""
    _write_inventory(tmp_path, monkeypatch, _no_install_body(tmp_path))
    _refuse_ssh(monkeypatch)

    router = FakeRouter({("system", "board"): data("system.board")})
    monkeypatch.setattr(
        noinstall_read, "default_client_factory", lambda _device: router
    )

    result = server.newton_read("lab-r1", "ubus call system board")
    assert result["exit_code"] == 0
    assert result["stdout"]["source"] == "lab-r1:ubus call system board"
    assert router.logins, "the read must open its own rpcd session"


def test_the_plan_of_a_no_install_device_never_reaches_ssh(
    tmp_path, monkeypatch
) -> None:
    """the plan of a no-install device is planned over the web API."""
    _write_inventory(tmp_path, monkeypatch, _no_install_body(tmp_path))
    _refuse_ssh(monkeypatch)

    router = FakeRouter(
        {
            ("system", "board"): data("system.board"),
            ("file", "list"): {"entries": []},
            ("uci", "get"): {"values": {}},
        }
    )
    monkeypatch.setattr(
        noinstall_read, "default_client_factory", lambda _device: router
    )

    result = server.newton_plan_change(
        "lab-r1",
        "set dhcp.laptop=host\nset dhcp.laptop.ip='10.109.0.55'\n",
        explanation={
            "intent": "give the laptop a fixed address",
            "steps": ["add the laptop", "give it its address"],
            "expect": [{"kind": "probe", "probe": ["ping", "127.0.0.1"]}],
            "risk": "the laptop keeps its address",
        },
        owner_confirmed_in_chat=True,
    )
    assert "error" not in result, result
    assert result["mode"] == "auto"
    assert router.logins, "the plan reads the router"


def test_the_read_of_a_no_install_device_refuses_a_read_the_web_api_has_not(
    tmp_path, monkeypatch
) -> None:
    """A read the web API cannot answer is refused by name."""
    _write_inventory(tmp_path, monkeypatch, _no_install_body(tmp_path))
    _refuse_ssh(monkeypatch)

    router = FakeRouter()
    monkeypatch.setattr(
        noinstall_read, "default_client_factory", lambda _device: router
    )

    result = server.newton_read("lab-r1", "nft list ruleset")
    assert result["error"].startswith(
        "nft is not available in no-install access"
    ), result
    assert router.calls == [], "a refused read must not reach the router"


def test_the_wifi_scan_still_refuses_a_no_install_device(
    tmp_path, monkeypatch
) -> None:
    """The scan needs the router program, so it stays refused."""
    _write_inventory(tmp_path, monkeypatch, _no_install_body(tmp_path))
    for tool, args in (
        ("newton_plan_scan", ("lab-r1", "inside", "quick", "lan")),
        ("newton_run_scan", ("lab-r1", "0" * 32)),
    ):
        result = getattr(server, tool)(*args)
        assert result.get("error") == NO_INSTALL_MESSAGE, tool


def test_the_apply_the_status_and_the_abort_answer_for_a_no_install_device(
    tmp_path, monkeypatch
) -> None:
    """the change tools get past the choke point for a no-install
    device, and they answer about its plans (there is no plan here, so
    they say so -- they do not refuse the device)."""
    _write_inventory(tmp_path, monkeypatch, _no_install_body(tmp_path))
    _refuse_ssh(monkeypatch)
    for tool in (
        "newton_apply_change",
        "newton_change_status",
        "newton_abort_change",
    ):
        result = getattr(server, tool)("lab-r1", "0" * 32)
        assert result.get("error") != NO_INSTALL_MESSAGE, tool
        assert "no plan record" in result["error"], (tool, result)


def test_the_choke_point_refuses_the_device_itself(tmp_path, monkeypatch) -> None:
    _write_inventory(tmp_path, monkeypatch, _no_install_body(tmp_path))
    service = server.NewtonService()
    with pytest.raises(server.NewtonError) as caught:
        service.device("lab-r1")
    assert str(caught.value) == NO_INSTALL_MESSAGE


def test_a_no_install_device_is_still_listed(tmp_path, monkeypatch) -> None:
    _write_inventory(tmp_path, monkeypatch, _no_install_body(tmp_path))
    listed = server.newton_list_devices()
    rows = {row["name"]: row for row in listed["devices"]}
    assert rows["lab-r1"]["access"] == "no-install"


def test_an_installed_device_is_listed_without_an_access_key(tmp_path, monkeypatch) -> None:
    _write_inventory(
        tmp_path,
        monkeypatch,
        '[devices.lab-r1]\nplatform = "openwrt"\nhost = "192.0.2.1"\nuser = "root"\n',
    )
    listed = server.newton_list_devices()
    rows = {row["name"]: row for row in listed["devices"]}
    assert "access" not in rows["lab-r1"]


# ---- the answer of the installed-mode offer --------------------


def test_the_installed_offer_field_is_read(tmp_path, monkeypatch) -> None:
    """A no-install device may say that the owner declined the offer."""
    _write_inventory(
        tmp_path,
        monkeypatch,
        _no_install_body(tmp_path, extra='installed_offer = "declined"\n'),
    )
    device = server.load_inventory()["lab-r1"]
    assert device.installed_offer == "declined"


def test_a_device_without_the_field_has_no_offer(tmp_path, monkeypatch) -> None:
    """The field is absent when the owner was never asked."""
    _write_inventory(tmp_path, monkeypatch, _no_install_body(tmp_path))
    device = server.load_inventory()["lab-r1"]
    assert device.installed_offer is None


def test_a_bad_installed_offer_value_is_refused(tmp_path, monkeypatch) -> None:
    """Only the value "declined" is a recorded answer."""
    _write_inventory(
        tmp_path,
        monkeypatch,
        _no_install_body(tmp_path, extra='installed_offer = "maybe"\n'),
    )
    with pytest.raises(server.NewtonError) as caught:
        server.load_inventory()
    assert "installed_offer" in str(caught.value)


def test_the_installed_offer_field_is_refused_on_an_installed_device(
    tmp_path, monkeypatch
) -> None:
    """The field belongs to a no-install device only."""
    _write_inventory(
        tmp_path,
        monkeypatch,
        '[devices.lab-r1]\nplatform = "openwrt"\nhost = "192.0.2.1"\n'
        'user = "root"\ninstalled_offer = "declined"\n',
    )
    with pytest.raises(server.NewtonError) as caught:
        server.load_inventory()
    assert "installed_offer" in str(caught.value)


def test_the_installed_offer_field_is_refused_on_a_non_openwrt_device(
    tmp_path, monkeypatch
) -> None:
    """The access modes are an OpenWrt thing; another platform has none."""
    known_hosts = tmp_path / "known-hosts"
    known_hosts.write_text("synthetic\n", encoding="utf-8")
    _write_inventory(
        tmp_path,
        monkeypatch,
        '[devices.jx1]\nplatform = "junos"\nhost = "192.0.2.9"\nuser = "junos"\n'
        'experimental_readonly = true\n'
        f'known_hosts = "{known_hosts}"\n'
        'installed_offer = "declined"\n',
    )
    with pytest.raises(server.NewtonError) as caught:
        server.load_inventory()
    assert "installed_offer" in str(caught.value)


def test_list_devices_shows_the_installed_offer(tmp_path, monkeypatch) -> None:
    """The listing carries the answer, so the agent knows it was asked."""
    _write_inventory(
        tmp_path,
        monkeypatch,
        _no_install_body(tmp_path, extra='installed_offer = "declined"\n'),
    )
    listed = server.newton_list_devices()
    rows = {row["name"]: row for row in listed["devices"]}
    assert rows["lab-r1"]["installed_offer"] == "declined"


def test_list_devices_omits_the_installed_offer_when_it_was_never_answered(
    tmp_path, monkeypatch
) -> None:
    """No answer yet: the key is absent, so the agent may ask once."""
    _write_inventory(tmp_path, monkeypatch, _no_install_body(tmp_path))
    listed = server.newton_list_devices()
    rows = {row["name"]: row for row in listed["devices"]}
    assert "installed_offer" not in rows["lab-r1"]


def test_list_devices_reports_the_web_login_for_a_no_install_device(
    tmp_path, monkeypatch
) -> None:
    """A no-install router logs in over the web API with a password, not an
    ssh key, so the listing must not say "key"."""
    _write_inventory(tmp_path, monkeypatch, _no_install_body(tmp_path))
    listed = server.newton_list_devices()
    rows = {row["name"]: row for row in listed["devices"]}
    assert rows["lab-r1"]["auth"] == "web-password"


def test_list_devices_keeps_the_ssh_auth_of_an_installed_device(
    tmp_path, monkeypatch
) -> None:
    _write_inventory(
        tmp_path,
        monkeypatch,
        '[devices.lab-r1]\nplatform = "openwrt"\nhost = "192.0.2.1"\nuser = "root"\n',
    )
    listed = server.newton_list_devices()
    rows = {row["name"]: row for row in listed["devices"]}
    assert rows["lab-r1"]["auth"] == "key"


# ---- the capabilities a no-install device advertises --


def _device_row(name: str) -> dict:
    """One row of newton_list_devices."""
    listed = server.newton_list_devices()
    return {row["name"]: row for row in listed["devices"]}[name]


def test_the_no_install_device_does_not_advertise_the_guard(
    tmp_path, monkeypatch
) -> None:
    """A no-install router has nothing of Newton on it: no guard, so the
    entry must not name the guard as the way back."""
    _write_inventory(tmp_path, monkeypatch, _no_install_body(tmp_path))
    row = _device_row("lab-r1")
    assert row["capabilities"]["native_revert"] == "openwrt-rpcd-timer"
    assert "newton-guard" not in json.dumps(row)


def test_the_no_install_device_lists_only_the_tools_that_answer(
    tmp_path, monkeypatch
) -> None:
    """The listed tools are the allowed set, and the allowed set is the
    server's own set: never a second hand-written copy."""
    _write_inventory(tmp_path, monkeypatch, _no_install_body(tmp_path))
    row = _device_row("lab-r1")
    assert row["capabilities"]["tools"] == sorted(NO_INSTALL_ALLOWED)


def test_the_no_install_device_advertises_no_installed_only_tool(
    tmp_path, monkeypatch
) -> None:
    """The tools the installed mode has and the no-install mode does not
    (backup, undo, tiers, audit, scans) are not advertised."""
    _write_inventory(tmp_path, monkeypatch, _no_install_body(tmp_path))
    tools = set(_device_row("lab-r1")["capabilities"]["tools"])
    for tool in (
        "newton_backup",
        "newton_plan_undo",
        "newton_plan_tier",
        "newton_guided_audit",
        "newton_plan_scan",
        "newton_run_scan",
        "newton_grant_off",
    ):
        assert tool not in tools, tool
    # the getter catalog is the vendor mechanism: the getter loader
    # refuses the openwrt platform (adapters/getters.py), so a no-install
    # entry must not advertise it either.
    assert "newton_list_getters" not in tools


def test_every_advertised_tool_answers_for_a_no_install_device(
    tmp_path, monkeypatch
) -> None:
    """The promise is checked against the code: each tool the entry
    advertises answers for the device instead of refusing it."""
    _write_inventory(tmp_path, monkeypatch, _no_install_body(tmp_path))
    tools = _device_row("lab-r1")["capabilities"]["tools"]
    for tool in tools:
        args = TOOL_CALLS.get(tool)
        if args is None:
            continue
        result = getattr(server, tool)(*args)
        assert result.get("error") != NO_INSTALL_MESSAGE, tool


def test_an_installed_device_keeps_the_platform_capabilities(
    tmp_path, monkeypatch
) -> None:
    """The installed mode is unchanged: the platform's tools, the guard
    and its own revert."""
    _write_inventory(
        tmp_path,
        monkeypatch,
        '[devices.lab-r1]\nplatform = "openwrt"\nhost = "192.0.2.1"\nuser = "root"\n',
    )
    row = _device_row("lab-r1")
    caps = row["capabilities"]
    assert caps["native_revert"] == "newton-guard"
    assert caps["tools"] == sorted(registry.capabilities("openwrt").tools)
    assert "newton_backup" in caps["tools"]
