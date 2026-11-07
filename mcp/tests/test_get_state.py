"""Experimental read-only getter tools in the MCP server."""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any

import pytest

import newton_mcp.server as server
from newton_mcp.adapters import registry
from newton_mcp.adapters.ssh_cli import SshCliRunner


GOOD_PARAM = r"^[A-Za-z0-9][A-Za-z0-9/._:-]{0,63}$"
CAVEAT = "Experimental read, not verified on this device; treat as a hint."
REAL_GETTER_PATH = server.getter_path

FAKE_SSH = r'''#!/usr/bin/env python3
import json
import os
import sys

record = {
    "argv": sys.argv,
    "env": {
        key: value
        for key, value in os.environ.items()
        if key.startswith("NEWTON_")
    },
}
with open(os.environ["NEWTON_FAKE_RECORD"], "a", encoding="utf-8") as stream:
    stream.write(json.dumps(record) + "\n")

mode = os.environ["NEWTON_FAKE_MODE"]
if mode == "version":
    sys.stdout.write("Junos: 23.4R1\nModel: vjunos\n")
elif mode == "vyos_version":
    sys.stdout.write(
        "set system login user lab authentication plaintext-password "
        "VyosSynthetic77\n"
        "community labro {\n"
    )
elif mode == "routeros_running_config":
    sys.stdout.write(
        "add name=p1 wpa2-pre-shared-key="
        "\\\n    RosSynthetic88\n"
    )
elif mode == "junos_secrets":
    sys.stdout.write(
        "lab-mx-r1 # show configuration | no-more\n"
        "version 23.4R1.9;\n"
        'authentication-key "$9$JxSynth41"; ## SECRET-DATA\n'
        "    community JxComm42;\n"
    )
elif mode == "eos_secrets":
    sys.stdout.write(
        "lab-eos-r1#show version\n"
        "Arista DCS-7280SR-48C6\n"
        "snmp-server community EosComm43 ro\n"
        "username a secret 7 070C285F4D06EE\n"
        "tacacs-server key 7 0822455D0A16EE\n"
    )
elif mode == "iosxe_secrets":
    sys.stdout.write(
        "lab-ios-r1#show version\n"
        "Cisco IOS XE Software, Version 17.12.04\n"
        "enable secret 9 $9$IosGs41synth\n"
        "snmp-server community IosGs42 RO\n"
        "username u password 7 0822455D0A16CD\n"
        "crypto isakmp key 0 IosGs43 address 192.0.2.1\n"
    )
elif mode == "polluted":
    sys.stdout.write(
        "\x1b[32mfriendly device line\x1b[0m\n"
        "status: ok\n"
        "enable secret 5 $1$abcd$SyntheticHash\n"
        "password = PWsynthetic9f3c\n"
    )
elif mode == "interfaces":
    sys.stdout.write(
        "Interface Admin Link\nge-0/0/0 up up\nlo0.0 up up\n"
    )
elif mode == "many":
    for index in range(250):
        sys.stdout.write(f"line {index:04d} payload text\n")
    sys.stdout.flush()
elif mode == "syntax":
    sys.stdout.write("error: syntax error, expecting <command>\n")
elif mode == "empty":
    pass
elif mode == "controls":
    sys.stdout.write("\x1b[0m\n")
elif mode == "refused":
    sys.stderr.write("ssh: connect to host 192.0.2.20 port 22: Connection refused\n")
    sys.exit(255)
elif mode == "auth":
    sys.stderr.write("newton@192.0.2.20: Permission denied (publickey).\n")
    sys.exit(255)
else:
    raise SystemExit(f"unknown fake mode: {mode}")
'''


def write_getters(path: Path) -> Path:
    path.write_text(
        f'''
platform = "junos"

[[getter]]
id = "version"
command = "show version"
enabled = true
verified = "unverified"
why = "Synthetic test row."
expect = ["Junos: * || friendly device line"]
error_markers = ["expecting <command>"]

[[getter]]
id = "interfaces"
command = "show interfaces terse"
enabled = true
verified = "unverified"
why = "Synthetic test row."
expect = ["Synthetic"]
error_markers = ["expecting <command>"]

[[getter]]
id = "routes"
command = "show route interface {{iface}}"
params = {{iface = "{GOOD_PARAM}"}}
enabled = true
verified = "unverified"
why = "Synthetic test row."
expect = ["Synthetic"]
error_markers = ["expecting <command>"]

[[getter]]
id = "ntp"
command = "show ntp associations"
enabled = false
verified = "unverified"
why = "Synthetic test row."
expect = ["Synthetic"]
error_markers = ["expecting <command>"]

[[getter]]
id = "running_config"
command = "show configuration | no-more"
max_bytes = 1024
enabled = true
verified = "unverified"
why = "Synthetic test row."
expect = ["Synthetic"]
error_markers = ["expecting <command>"]
''',
        encoding="utf-8",
    )
    return path


@pytest.fixture
def lab(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Install a synthetic inventory, getter file, and fake SSH executable."""
    fake = tmp_path / "fake-ssh"
    fake.write_text(FAKE_SSH, encoding="utf-8")
    fake.chmod(0o755)
    record = tmp_path / "fake-record.jsonl"
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text(
        "192.0.2.20 ssh-ed25519 "
        "AAAAC3NzaC1lZDI1NTE5AAAAIFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE\n",
        encoding="utf-8",
    )
    devices = {
        "quasar": server.Device(
            name="quasar",
            platform="openwrt",
            host="192.0.2.1",
            user="root",
        ),
        "jx1": server.Device(
            name="jx1",
            platform="junos",
            host="192.0.2.20",
            user="newton",
            experimental_readonly=True,
            known_hosts=known_hosts,
        ),
        "jx2": server.Device(
            name="jx2",
            platform="junos",
            host="192.0.2.21",
            user="newton",
            experimental_readonly=True,
            known_hosts=known_hosts,
        ),
        "eos1": server.Device(
            name="eos1",
            platform="eos",
            host="192.0.2.22",
            user="newton",
            experimental_readonly=True,
            known_hosts=known_hosts,
        ),
        "vyos1": server.Device(
            name="vyos1",
            platform="vyos",
            host="192.0.2.23",
            user="newton",
            experimental_readonly=True,
            lab=True,
            known_hosts=known_hosts,
        ),
        "ros1": server.Device(
            name="ros1",
            platform="routeros",
            host="192.0.2.24",
            user="newton",
            experimental_readonly=True,
            lab=True,
            known_hosts=known_hosts,
        ),
        "ios1": server.Device(
            name="ios1",
            platform="iosxe",
            host="192.0.2.25",
            user="newton",
            experimental_readonly=True,
            known_hosts=known_hosts,
        ),
        "fg1": server.Device(
            name="fg1",
            platform="fortios",
            host="192.0.2.26",
            user="newton",
            experimental_readonly=True,
            known_hosts=known_hosts,
        ),
    }
    state = tmp_path / "state"
    monkeypatch.setenv("NEWTON_STATE_DIR", str(state))
    monkeypatch.setenv("NEWTON_FAKE_RECORD", str(record))
    monkeypatch.setenv("NEWTON_FAKE_MODE", "version")
    monkeypatch.setattr(server, "SSH_BINARY", str(fake))
    monkeypatch.setattr(server, "_RUNNERS", {})
    monkeypatch.setattr(server, "_SEEN_IFACES", {})
    monkeypatch.setattr(server, "load_inventory", lambda: devices)
    getters = write_getters(tmp_path / "junos-getters.toml")
    monkeypatch.setattr(
        server, "getter_path", lambda platform: getters if platform == "junos" else None
    )
    return {"fake": fake, "record": record, "state": state, "devices": devices}


def records(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def fake_clock_runner(lab: dict[str, Any]) -> tuple[SshCliRunner, list[float]]:
    """Build an injected runner whose clock the test advances by 10 seconds."""
    clock = [100.0]
    runner = SshCliRunner(
        lab["state"], ssh=str(lab["fake"]), clock=lambda: clock[0]
    )
    return runner, clock


def string_leaves(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [text for item in value.values() for text in string_leaves(item)]
    if isinstance(value, list):
        return [text for item in value for text in string_leaves(item)]
    return []


def test_mv1_6_01_tool_names_schemas_and_live_tool_list() -> None:
    """the server exposes sixteen tools and fixed schemas."""
    import asyncio
    from mcp.shared.memory import create_connected_server_and_client_session

    assert len(server.TOOL_NAMES) == 17
    assert {"newton_get_state", "newton_list_getters"} <= server.TOOL_NAMES

    async def listed():
        async with create_connected_server_and_client_session(
            server.mcp._mcp_server
        ) as session:
            await session.initialize()
            return await session.list_tools()

    response = asyncio.run(listed())
    assert {tool.name for tool in response.tools} == server.TOOL_NAMES
    get_state = next(tool for tool in response.tools if tool.name == "newton_get_state")
    list_getters = next(
        tool for tool in response.tools if tool.name == "newton_list_getters"
    )
    assert set(get_state.inputSchema["properties"]) == {"device", "getter", "params"}
    assert set(list_getters.inputSchema["properties"]) == {"device"}


def test_mv1_6_02_openwrt_refuses_both_tools_before_any_process(
    lab: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Capability gate and belt-and-braces both exclude OpenWrt."""
    read = server.newton_get_state(device="quasar", getter="version")
    listed = server.newton_list_getters(device="quasar")
    assert read == {"error": "newton_get_state is not available for platform openwrt"}
    assert listed == {
        "error": "newton_list_getters is not available for platform openwrt"
    }
    assert not lab["record"].exists()

    openwrt_tools = registry.capabilities("openwrt").tools | {
        "newton_get_state", "newton_list_getters"
    }
    monkeypatch.setattr(
        server.registry,
        "capabilities",
        lambda platform: registry.Capabilities(
            tier="T1",
            writes=True,
            native_revert="newton-guard",
            tools=openwrt_tools,
        ),
    )
    bypass_attempt = server.newton_get_state(device="quasar", getter="version")
    assert bypass_attempt == {
        "error": "newton_get_state is not available for platform openwrt"
    }
    assert not lab["record"].exists()


def test_mv1_6_03_refusals_do_not_process_echo_or_touch_rate_limit(
    lab: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """All pre-flight refusals use fixed diagnostics."""
    invalid = server.newton_get_state(
        device="jx1", getter="show version; request system reboot"
    )
    absent = server.newton_get_state(device="jx1", getter="vpn")
    disabled = server.newton_get_state(device="jx1", getter="ntp")
    bad_params = server.newton_get_state(device="jx1", getter="version", params="x")
    bad_value = server.newton_get_state(
        device="jx1", getter="version", params={"iface": 5}
    )
    non_string = server.newton_get_state(device="jx1", getter=7)

    assert invalid == {"error": "unknown getter id"}
    assert "reboot" not in json.dumps(invalid)
    assert absent == {"error": "getter vpn is not available for platform junos"}
    assert disabled == {
        "error": "getter ntp is disabled for platform junos until a lab proves it"
    }
    assert bad_params == {"error": "params must be an object of string values"}
    assert bad_value == {"error": "params must be an object of string values"}
    assert non_string == {"error": "unknown getter id"}
    assert not lab["record"].exists()

    valid = server.newton_get_state(device="jx1", getter="version")
    assert valid["status"] == "ok"
    assert len(records(lab["record"])) == 1


def test_mv1_6_04_happy_path_result_and_ssh_argv(lab: dict[str, Any]) -> None:
    """A successful getter returns the exact experimental result."""
    result = server.newton_get_state(device="jx1", getter="version")
    assert set(result) == {
        "getter", "tier", "status", "shape", "truncated", "caveat",
        "device_role_enforced", "data",
    }
    assert result["getter"] == "version"
    assert result["tier"] == "T1"
    assert result["status"] == "ok"
    assert result["truncated"] is False
    assert result["caveat"] == CAVEAT
    assert result["device_role_enforced"] is False
    assert result["tier"] == "T1"
    assert result["data"] == {
        "kind": "untrusted-device-data",
        "source": "jx1:version",
        "text": "Junos: 23.4R1\nModel: vjunos\n",
    }
    assert records(lab["record"])[0]["argv"][-2:] == ["--", "show version"]


def test_mv1_6_05_device_output_is_cleaned_and_stays_enveloped(
    lab: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Hostile stdout cannot leak into Newton result fields."""
    monkeypatch.setenv("NEWTON_FAKE_MODE", "polluted")
    result = server.newton_get_state(device="jx1", getter="version")
    encoded = json.dumps(result)
    assert "SyntheticHash" not in encoded
    assert "PWsynthetic9f3c" not in encoded
    assert "\x1b" not in encoded
    assert server._envelope.FLAG_PREFIX in result["data"]["text"]

    outside = {
        key: value for key, value in result.items() if key != "data"
    }
    outside_data = {
        key: value for key, value in result["data"].items() if key != "text"
    }
    assert outside == {
        "getter": "version",
        "tier": "T1",
        "status": "ok",
        "shape": "matched",
        "truncated": False,
        "caveat": CAVEAT,
        "device_role_enforced": False,
    }
    assert outside_data == {
        "kind": "untrusted-device-data",
        "source": "jx1:version",
    }
    fixed_leaves = string_leaves(outside) + string_leaves(outside_data)
    assert all(
        marker not in value
        for marker in (
            "friendly device line",
            "status: ok",
            "enable secret 5",
            "password =",
        )
        for value in fixed_leaves
    )


def test_mv1_6_06_runner_statuses_pass_through_and_auth_disables(
    lab: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Result status follows the runner and auth failure is sticky."""
    runner, clock = fake_clock_runner(lab)
    monkeypatch.setattr(server, "_ssh_runner", lambda: runner)

    def advance() -> None:
        clock[0] += 10.0

    monkeypatch.setenv("NEWTON_FAKE_MODE", "refused")
    refused = server.newton_get_state(device="jx1", getter="version")
    assert refused["status"] == "unreachable"
    assert set(refused) == {
        "getter", "tier", "status", "shape", "truncated", "caveat",
        "device_role_enforced", "data",
    }

    advance()
    monkeypatch.setenv("NEWTON_FAKE_MODE", "syntax")
    syntax = server.newton_get_state(device="jx1", getter="version")
    assert syntax["status"] == "device_error"

    advance()
    monkeypatch.setenv("NEWTON_FAKE_MODE", "empty")
    empty = server.newton_get_state(device="jx1", getter="version")
    assert empty["status"] == "empty"

    advance()
    monkeypatch.setenv("NEWTON_FAKE_MODE", "controls")
    controls = server.newton_get_state(device="jx1", getter="version")
    assert controls["status"] == "empty"

    advance()
    monkeypatch.setenv("NEWTON_FAKE_MODE", "auth")
    auth = server.newton_get_state(device="jx1", getter="version")
    assert auth["status"] == "auth_failed"
    count_before_disable = len(records(lab["record"]))

    advance()
    disabled = server.newton_get_state(device="jx1", getter="version")
    assert "disabled after an auth failure" in disabled["error"]
    assert len(records(lab["record"])) == count_before_disable


def test_mv1_6_07_runner_is_process_global_and_rate_limited_per_device(
    lab: dict[str, Any],
) -> None:
    """One runner survives per-process service construction."""
    first = server.newton_get_state(device="jx1", getter="version")
    second = server.newton_get_state(device="jx1", getter="version")
    peer = server.newton_get_state(device="jx2", getter="version")
    assert first["status"] == "ok"
    assert "rate limited" in second["error"]
    assert peer["status"] == "ok"
    assert len(records(lab["record"])) == 2
    assert len(server._RUNNERS) == 1


def test_mv1_6_08_iface_parameter_must_come_from_interfaces_getter(
    lab: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Iface references are bounded by an earlier successful read."""
    runner, clock = fake_clock_runner(lab)
    monkeypatch.setattr(server, "_ssh_runner", lambda: runner)

    early = server.newton_get_state(
        device="jx1", getter="routes", params={"iface": "ge-0/0/0"}
    )
    assert early == {
        "error": (
            "getter routes: the iface value must be one the interfaces getter "
            "returned; run the interfaces getter first"
        )
    }
    assert "ge-0/0/0" not in early["error"]
    assert not lab["record"].exists()

    monkeypatch.setenv("NEWTON_FAKE_MODE", "interfaces")
    interfaces = server.newton_get_state(device="jx1", getter="interfaces")
    assert interfaces["status"] == "ok"

    clock[0] += 10.0
    monkeypatch.setenv("NEWTON_FAKE_MODE", "version")
    routes = server.newton_get_state(
        device="jx1", getter="routes", params={"iface": "ge-0/0/0"}
    )
    assert routes["status"] == "ok"
    assert records(lab["record"])[-1]["argv"][-1] == "show route interface ge-0/0/0"

    clock[0] += 10.0
    rejected = server.newton_get_state(
        device="jx1", getter="routes", params={"iface": "ge-0/0/9"}
    )
    assert rejected["error"] == (
        "getter routes: the iface value must be one the interfaces getter "
        "returned; run the interfaces getter first"
    )

    clock[0] += 10.0
    monkeypatch.setenv("NEWTON_FAKE_MODE", "refused")
    failed = server.newton_get_state(device="jx2", getter="interfaces")
    assert failed["status"] == "unreachable"
    clock[0] += 10.0
    unseeded = server.newton_get_state(
        device="jx2", getter="routes", params={"iface": "ge-0/0/0"}
    )
    assert "run the interfaces getter first" in unseeded["error"]


def test_mv1_6_09_list_getters_exposes_metadata_without_commands(
    lab: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The model sees getter ids and contracts, never commands."""
    result = server.newton_list_getters(device="jx1")
    assert result["result"] == "ok"
    assert result["device"] == "jx1"
    assert result["platform"] == "junos"
    assert result["tier"] == "T1"
    assert result["caveat"] == CAVEAT
    assert [row["id"] for row in result["getters"]] == [
        "version", "interfaces", "routes", "ntp", "running_config"
    ]
    running_config_row = next(row for row in result["getters"] if row["id"] == "running_config")
    assert running_config_row["enabled"] is True
    assert running_config_row["params"] == {}
    assert result["getters"][3]["enabled"] is False
    assert result["getters"][2]["params"] == {"iface": GOOD_PARAM}
    assert "command" not in json.dumps(result)
    assert "show route" not in json.dumps(result)

    monkeypatch.setattr(
        server,
        "getter_path",
        REAL_GETTER_PATH,
    )
    original_getters_file = server._getters.__file__
    empty_dir = lab["state"].parent / "empty-getters"
    empty_dir.mkdir()
    monkeypatch.setattr(server._getters, "__file__", str(empty_dir / "getters.py"))
    no_shipment = server.newton_list_getters(device="ios1")
    assert no_shipment["getters"] == []
    assert no_shipment["note"] == "no getters ship for platform iosxe yet"
    assert not lab["record"].exists()
    monkeypatch.setattr(server._getters, "__file__", original_getters_file)

    eos_listed = server.newton_list_getters(device="eos1")
    assert [row["id"] for row in eos_listed["getters"]] == [
        "version",
        "interfaces",
        "routes",
        "running_config",
    ]
    running_config_row = next(
        row for row in eos_listed["getters"] if row["id"] == "running_config"
    )
    assert running_config_row["enabled"] is False
    eos_encoded = json.dumps(eos_listed)
    assert "show ip route" not in eos_encoded
    assert "show running-config" not in eos_encoded


def test_mv1_6_10_list_devices_adds_capabilities_without_changing_fields(
    lab: dict[str, Any],
) -> None:
    """Inventory entries preserve fields and expose capabilities."""
    entries = {
        row["name"]: row for row in server.newton_list_devices()["devices"]
    }
    assert entries["quasar"] == {
        "name": "quasar",
        "platform": "openwrt",
        "host": "192.0.2.1",
        "user": "root",
        "auth": "key",
        "profile": "prod",
        "tier": "T1",
        "capabilities": {
            "writes": True,
            "native_revert": "newton-guard",
            "tools": sorted(registry.OPENWRT_TOOLS),
        },
        "easy_grant": None,
    }
    # the Junos platform writes: the platform may write, the
    # read-only device may not (the entry says so in its own "writes").
    assert entries["jx1"]["tier"] == "T1"
    assert entries["jx1"]["capabilities"] == {
        "writes": True,
        "native_revert": "commit confirmed",
        "tools": sorted(registry.VENDOR_WRITE_TOOLS),
    }


def test_mv1_6_11_new_methods_gate_the_device_first() -> None:
    """AST-check both new service paths begin at the capability gate."""
    tree = ast.parse(Path(server.__file__).read_text(encoding="utf-8"))
    service = next(
        node for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "NewtonService"
    )
    methods = {
        member.name: member
        for member in service.body
        if isinstance(member, ast.FunctionDef)
    }

    for method_name, tool_name in (
        ("get_state", "newton_get_state"),
        ("list_getters", "newton_list_getters"),
    ):
        method = methods[method_name]
        first = method.body[0]
        if (
            isinstance(first, ast.Expr)
            and isinstance(first.value, ast.Constant)
            and isinstance(first.value.value, str)
        ):
            first = method.body[1]
        assert isinstance(first, ast.Assign)
        assert isinstance(first.value, ast.Call)
        assert isinstance(first.value.func, ast.Attribute)
        assert first.value.func.attr == "device_for"
        assert first.value.args[0].value == tool_name  # type: ignore[attr-defined]


def test_mv1_6_12_service_result_is_redacted_before_call_tool(
    lab: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Get_state itself redacts (pipeline step 3), not only call_tool."""
    monkeypatch.setenv("NEWTON_FAKE_MODE", "polluted")
    encoded = json.dumps(server.NewtonService().get_state("jx1", "version", None))
    assert "SyntheticHash" not in encoded
    assert "PWsynthetic9f3c" not in encoded


def test_mv1_6_13_runner_truncation_survives_envelope_pass(
    lab: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """When the runner caps stdout the result marks truncated=True."""
    monkeypatch.setenv("NEWTON_FAKE_MODE", "many")
    result = server.newton_get_state(device="jx1", getter="running_config")
    assert result["status"] == "ok"
    assert result["truncated"] is True
    assert len(result["data"]["text"].encode("utf-8")) <= 1024


def test_mv1_6_14_iface_set_seeds_only_on_ok_interfaces_read(
    lab: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A non-ok interfaces read never seeds the iface set."""
    runner, clock = fake_clock_runner(lab)
    monkeypatch.setattr(server, "_ssh_runner", lambda: runner)
    monkeypatch.setenv("NEWTON_FAKE_MODE", "syntax")

    first = server.newton_get_state(device="jx1", getter="interfaces")
    assert first["status"] == "device_error"
    records_after_first = records(lab["record"])

    clock[0] += 10.0
    rejected = server.newton_get_state(
        device="jx1", getter="routes", params={"iface": "syntax"}
    )
    assert rejected == {
        "error": (
            "getter routes: the iface value must be one the interfaces getter "
            "returned; run the interfaces getter first"
        )
    }
    assert "syntax" not in rejected["error"]
    assert len(records(lab["record"])) == len(records_after_first)


def test_mv1_6_15_unknown_param_slots_never_reach_runner(
    lab: dict[str, Any],
) -> None:
    """Wrong param keys refuse before the runner starts."""
    bad = server.newton_get_state(
        device="jx1", getter="version", params={"x": "y"}
    )
    assert bad == {
        "error": (
            "getter version: params must name exactly the getter's slots"
        )
    }
    encoded = json.dumps(bad)
    assert "sneaky" not in encoded
    assert "secret" not in encoded
    assert not lab["record"].exists()
    valid = server.newton_get_state(device="jx1", getter="version")
    assert valid["status"] == "ok"
    assert len(records(lab["record"])) == 1


def test_mv1_6_16_get_state_redacts_vyos_space_separated_secrets(
    lab: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """VyOS config/op-mode secrets and communities are platform-redacted."""
    monkeypatch.setenv("NEWTON_FAKE_MODE", "vyos_version")
    result = server.newton_get_state(device="vyos1", getter="version")
    encoded = json.dumps(result)
    assert result["status"] == "ok"
    assert "VyosSynthetic77" not in encoded
    assert "labro" not in encoded


def test_mv1_6_17_get_state_joins_routeros_export_continuations(
    lab: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """RouterOS /export line wraps are joined before shared redaction.

    ``running_config`` is disabled, so this test exercises the
    line-join wiring through an enabled RouterOS getter (``version``); the
    fake SSH mode is the one that emits a RouterOS-style continuation so the
    join step still has work to do.
    """
    monkeypatch.setenv("NEWTON_FAKE_MODE", "routeros_running_config")
    result = server.newton_get_state(device="ros1", getter="version")
    assert result["status"] == "ok"
    assert "RosSynthetic88" not in json.dumps(result)


def test_mv1_6_18_get_state_refuses_disabled_routeros_running_config(
    lab: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A disabled RouterOS running_config getter is refused without a process."""
    refused = server.newton_get_state(device="ros1", getter="running_config")
    assert refused == {
        "error": (
            "getter running_config is disabled for platform routeros until "
            "a lab proves it"
        )
    }
    assert not lab["record"].exists()


def test_mv1_8_12_junos_get_state_runs_show_version(
    lab: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Junos enabled getter dispatches with the pinned command."""
    monkeypatch.setattr(
        server,
        "getter_path",
        REAL_GETTER_PATH,
    )
    monkeypatch.setenv("NEWTON_FAKE_MODE", "version")
    if lab["record"].exists():
        lab["record"].unlink()
    result = server.newton_get_state(device="jx1", getter="version")
    assert result["status"] == "ok"
    last_record = records(lab["record"])[-1]
    argv = last_record["argv"]
    assert argv[-2:] == ["--", "show version"], argv


def test_mv1_8_13_disabled_running_config_refused_without_process(
    lab: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Disabled running_config is refused on eos and junos, no ssh runs."""
    monkeypatch.setattr(
        server,
        "getter_path",
        REAL_GETTER_PATH,
    )
    if lab["record"].exists():
        lab["record"].unlink()

    eos_refused = server.newton_get_state(device="eos1", getter="running_config")
    junos_refused = server.newton_get_state(device="jx1", getter="running_config")
    assert (
        "getter running_config is disabled for platform eos" in eos_refused["error"]
    ), eos_refused
    assert (
        "getter running_config is disabled for platform junos"
        in junos_refused["error"]
    ), junos_refused
    assert not lab["record"].exists()


def test_mv1_8_21_eos_show_version_argv_pin(
    lab: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Eos version getter records ``["--", "show version"]`` as the trailing argv.

    Extends the Junos version test with an eos1 ``version`` call asserting the
    recorded argv ends ``["--", "show version"]``.
    """
    monkeypatch.setattr(
        server,
        "getter_path",
        REAL_GETTER_PATH,
    )
    monkeypatch.setenv("NEWTON_FAKE_MODE", "version")
    if lab["record"].exists():
        lab["record"].unlink()

    eos_result = server.newton_get_state(device="eos1", getter="version")
    assert eos_result["status"] == "ok"
    last_record = records(lab["record"])[-1]
    assert last_record["argv"][-2:] == ["--", "show version"], last_record["argv"]


FORTIOS_IDS = (
    "version",
    "interfaces",
    "routes",
    "firewall_policy",
    "nat",
    "ntp",
    "logging",
    "vpn",
    "running_config",
)


def test_mv1_9_12_iosxe_and_fortios_list_getters(
    lab: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Iosxe lists four ids with running_config disabled; fortios lists nine disabled ids; no command text leaks."""
    monkeypatch.setattr(
        server,
        "getter_path",
        REAL_GETTER_PATH,
    )

    ios_listed = server.newton_list_getters(device="ios1")
    assert [row["id"] for row in ios_listed["getters"]] == [
        "version",
        "interfaces",
        "routes",
        "running_config",
    ]
    running_config_row = next(
        row for row in ios_listed["getters"] if row["id"] == "running_config"
    )
    assert running_config_row["enabled"] is False
    ios_encoded = json.dumps(ios_listed)
    assert "show ip route" not in ios_encoded
    assert "show running-config" not in ios_encoded

    fortios_listed = server.newton_list_getters(device="fg1")
    assert [row["id"] for row in fortios_listed["getters"]] == list(FORTIOS_IDS)
    for row in fortios_listed["getters"]:
        assert row["enabled"] is False, ("fortios", row["id"])
    fortios_encoded = json.dumps(fortios_listed)
    assert "get system status" not in fortios_encoded
    assert "show full-configuration" not in fortios_encoded


def test_mv1_9_13_iosxe_version_records_show_version_argv(
    lab: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Iosxe version getter records argv trailing ``["--", "show version"]``."""
    monkeypatch.setattr(
        server,
        "getter_path",
        REAL_GETTER_PATH,
    )
    monkeypatch.setenv("NEWTON_FAKE_MODE", "version")
    if lab["record"].exists():
        lab["record"].unlink()

    ios_result = server.newton_get_state(device="ios1", getter="version")
    assert ios_result["status"] == "ok"
    last_record = records(lab["record"])[-1]
    assert last_record["argv"][-2:] == ["--", "show version"], last_record["argv"]


def test_mv1_9_14_disabled_getters_refused_without_process(
    lab: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Disabled iosxe/fortios getters refuse without running any ssh process."""
    monkeypatch.setattr(
        server,
        "getter_path",
        REAL_GETTER_PATH,
    )
    if lab["record"].exists():
        lab["record"].unlink()

    ios_refused = server.newton_get_state(device="ios1", getter="running_config")
    assert (
        "getter running_config is disabled for platform iosxe" in ios_refused["error"]
    ), ios_refused

    for getter_id in FORTIOS_IDS:
        fortios_refused = server.newton_get_state(device="fg1", getter=getter_id)
        assert (
            f"getter {getter_id} is disabled for platform fortios"
            in fortios_refused["error"]
        ), (getter_id, fortios_refused)

    assert not lab["record"].exists()


def test_mv1_8_19_junos_get_state_redacts_junos_secrets(
    lab: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Junos ``$9$`` and ``community`` strings are platform-redacted before model-bound output.

    red before the platform_redact edit; the fake ``junos_secrets``
    mode prints ``$9$JxSynth41`` and ``community JxComm42;`` and neither may
    survive ``newton_get_state``.
    """
    monkeypatch.setattr(
        server,
        "getter_path",
        REAL_GETTER_PATH,
    )
    runner, clock = fake_clock_runner(lab)
    monkeypatch.setattr(server, "_ssh_runner", lambda: runner)
    monkeypatch.setenv("NEWTON_FAKE_MODE", "junos_secrets")
    if lab["record"].exists():
        lab["record"].unlink()

    result = server.newton_get_state(device="jx1", getter="version")
    encoded = json.dumps(result)
    assert result["status"] == "ok"
    for fragment in ("JxSynth41", "JxComm42"):
        assert fragment not in encoded, f"leaked: {fragment}"


def test_mv1_8_20_eos_get_state_redacts_eos_secrets(
    lab: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """EOS snmp / type-7 / tacacs-style secrets are platform-redacted before model-bound output.

    red before the platform_redact edit; the fake ``eos_secrets``
    mode prints the four sentinel strings and none may survive ``newton_get_state``.
    """
    monkeypatch.setattr(
        server,
        "getter_path",
        REAL_GETTER_PATH,
    )
    runner, clock = fake_clock_runner(lab)
    monkeypatch.setattr(server, "_ssh_runner", lambda: runner)
    monkeypatch.setenv("NEWTON_FAKE_MODE", "eos_secrets")
    if lab["record"].exists():
        lab["record"].unlink()

    result = server.newton_get_state(device="eos1", getter="version")
    encoded = json.dumps(result)
    assert result["status"] == "ok"
    for fragment in ("EosComm43", "070C285F4D06EE", "0822455D0A16EE"):
        assert fragment not in encoded, f"leaked: {fragment}"


def test_mv1_9_22_iosxe_get_state_redacts_iosxe_secrets(
    lab: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """IOS XE enable-secret / snmp community / type-7 password /
    crypto isakmp key secrets are platform-redacted before model-bound output.

    red before the platform_redact edit; the fake
    ``iosxe_secrets`` mode prints the four sentinel strings and none may
    survive ``newton_get_state``.  Mind the rate limit as the neighbouring tests do.
    """
    monkeypatch.setattr(
        server,
        "getter_path",
        REAL_GETTER_PATH,
    )
    runner, clock = fake_clock_runner(lab)
    monkeypatch.setattr(server, "_ssh_runner", lambda: runner)
    monkeypatch.setenv("NEWTON_FAKE_MODE", "iosxe_secrets")
    if lab["record"].exists():
        lab["record"].unlink()

    result = server.newton_get_state(device="ios1", getter="version")
    encoded = json.dumps(result)
    assert result["status"] == "ok"
    for fragment in (
        "IosGs41synth",
        "IosGs42",
        "0822455D0A16CD",
        "IosGs43",
    ):
        assert fragment not in encoded, f"leaked: {fragment}"
