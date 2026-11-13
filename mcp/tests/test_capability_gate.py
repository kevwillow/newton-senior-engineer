"""Platform capability gating for every device-reaching MCP tool."""

from __future__ import annotations

import ast
import dataclasses
import inspect
from pathlib import Path
from typing import Any

import pytest

import newton_mcp.server as server
from newton_mcp.adapters import base, registry
from newton_mcp.server import NewtonError


DEVICE_TOOLS = {
    "newton_read",
    "newton_backup",
    "newton_plan_change",
    "newton_plan_undo",
    "newton_apply_change",
    "newton_change_status",
    "newton_abort_change",
    "newton_grant_off",
    "newton_plan_tier",
    "newton_guided_audit",
    "newton_plan_scan",
    "newton_run_scan",
    "newton_get_state",
    "newton_list_getters",
    "newton_ad_audit",
    "newton_ad_plan_change",
    "newton_ad_apply_change",
    "newton_ad_change_status",
    "newton_ad_abort_change",
}

NO_DEVICE_TOOLS = {
    "newton_list_devices",
    "newton_list_tiers",
    "newton_guided_recommend",
    "newton_ad_list_checks",
}

TOOL_KWARGS: dict[str, dict[str, Any]] = {
    "newton_read": {"device": "vy1", "command": "uname -a"},
    "newton_backup": {"device": "vy1"},
    "newton_plan_change": {
        "device": "vy1",
        "uci_batch": "set network.lan.ipaddr='192.0.2.1'",
    },
    "newton_plan_undo": {
        "device": "vy1",
        "change_id": "0" * 32,
        "explanation": {"intent": "Undo it", "risk": "It may fail"},
        "owner_confirmed_in_chat": True,
    },
    "newton_apply_change": {"device": "vy1", "session_id": "0" * 32},
    "newton_change_status": {"device": "vy1", "session_id": "0" * 32},
    "newton_abort_change": {"device": "vy1", "session_id": "0" * 32},
    "newton_grant_off": {"device": "vy1"},
    "newton_plan_tier": {"device": "vy1", "tier": "standard"},
    "newton_guided_audit": {"device": "vy1"},
    "newton_plan_scan": {"device": "vy1", "kind": "inside", "profile": "quick", "interface": "lan"},
    "newton_run_scan": {"device": "vy1", "request_id": "0" * 32},
    "newton_get_state": {"device": "vy1", "getter": "version"},
    "newton_list_getters": {"device": "vy1"},
    "newton_ad_audit": {"device": "vy1"},
    "newton_ad_plan_change": {"device": "vy1", "verb": "uac-clear"},
    "newton_ad_apply_change": {"device": "vy1", "plan_id": "0" * 32},
    "newton_ad_change_status": {"device": "vy1", "plan_id": "0" * 32},
    "newton_ad_abort_change": {"device": "vy1", "plan_id": "0" * 32},
}

DEVICE_METHOD_TOOLS = {
    "read": "newton_read",
    "guided_audit": "newton_guided_audit",
    "plan_scan": "newton_plan_scan",
    "run_scan": "newton_run_scan",
    "backup": "newton_backup",
    "plan": "newton_plan_change",
    "plan_undo": "newton_plan_undo",
    "plan_tier": "newton_plan_tier",
    "apply": "newton_apply_change",
    "status": "newton_change_status",
    "abort": "newton_abort_change",
    "get_state": "newton_get_state",
    "list_getters": "newton_list_getters",
    "ad_audit": "newton_ad_audit",
}


@dataclasses.dataclass
class _GateLab:
    """Synthetic two-platform inventory plus a subprocess-call recorder."""

    devices: dict[str, server.Device]
    calls: list[tuple[str, tuple[Any, ...], dict[str, Any]]]


def _fail_loud_subprocesses(
    monkeypatch: pytest.MonkeyPatch,
    calls: list[tuple[str, tuple[Any, ...], dict[str, Any]]],
) -> None:
    """Make every process launch fail loudly while recording the attempt."""
    def recorder(kind: str):
        def fail_loudly(
            *args: Any, **kwargs: Any
        ) -> None:
            calls.append((kind, args, kwargs))
            raise AssertionError(f"unexpected subprocess.{kind} call")

        return fail_loudly

    monkeypatch.setattr(server.subprocess, "run", recorder("run"))
    monkeypatch.setattr(server.subprocess, "Popen", recorder("Popen"))


@pytest.fixture
def capability_lab(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> _GateLab:
    """Install a read-only VyOS peer and make every process launch fail loudly."""
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
            known_hosts=tmp_path / "kh",
        ),
    }
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setattr(server, "load_inventory", lambda: devices)

    calls: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []
    _fail_loud_subprocesses(monkeypatch, calls)
    monkeypatch.setattr(
        server, "script_path", lambda: tmp_path / "missing" / "newton-change"
    )
    return _GateLab(devices=devices, calls=calls)


@pytest.fixture
def real_capability_lab(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> _GateLab:
    """Load a real two-platform inventory without replacing load_inventory."""
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text(
        "192.0.2.9 ssh-ed25519 "
        "AAAAC3NzaC1lZDI1NTE5AAAAIFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE\n"
    )
    inventory = tmp_path / "devices.toml"
    inventory.write_text(
        '[devices.quasar]\n'
        'platform = "openwrt"\n'
        'host = "192.0.2.1"\n'
        'user = "root"\n'
        '\n'
        '[devices.vy1]\n'
        'platform = "vyos"\n'
        'host = "192.0.2.9"\n'
        'user = "newton"\n'
        'experimental_readonly = true\n'
        'lab = true\n'
        f'known_hosts = "{known_hosts}"\n'
    )
    monkeypatch.setenv("NEWTON_INVENTORY", str(inventory))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))
    calls: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []
    _fail_loud_subprocesses(monkeypatch, calls)
    monkeypatch.setattr(
        server, "script_path", lambda: tmp_path / "missing" / "newton-change"
    )
    return _GateLab(devices=server.load_inventory(), calls=calls)


def _self_attr_calls(node: ast.AST, attribute: str) -> list[ast.Call]:
    """Return every direct ``self.<attribute>(...)`` call in an AST node."""
    found: list[ast.Call] = []
    for candidate in ast.walk(node):
        if not isinstance(candidate, ast.Call):
            continue
        function = candidate.func
        if (
            isinstance(function, ast.Attribute)
            and function.attr == attribute
            and isinstance(function.value, ast.Name)
            and function.value.id == "self"
        ):
            found.append(candidate)
    return found


def _newton_service_method(node: ast.Module, name: str) -> ast.FunctionDef:
    """Find a method directly on the NewtonService class."""
    for statement in node.body:
        if not isinstance(statement, ast.ClassDef) or statement.name != "NewtonService":
            continue
        for member in statement.body:
            if isinstance(member, ast.FunctionDef) and member.name == name:
                return member
    raise AssertionError(f"NewtonService.{name} not found")


def test_mv1_3_01_tool_names_partition_into_device_and_no_device_tools() -> None:
    """A future device tool must be added to one explicit gate set."""
    signature_device_tools = {
        name
        for name in server.TOOL_NAMES
        if "device" in inspect.signature(getattr(server, name)).parameters
    }
    assert signature_device_tools == DEVICE_TOOLS
    assert not (DEVICE_TOOLS & NO_DEVICE_TOOLS)
    assert server.TOOL_NAMES == DEVICE_TOOLS | NO_DEVICE_TOOLS


@pytest.mark.parametrize(
    "tool",
    sorted(DEVICE_TOOLS - registry.capabilities("vyos").tools),
)
def test_mv1_3_01_device_tool_refuses_vyos_before_any_process(
    capability_lab: _GateLab, tool: str
) -> None:
    """Tools outside the platform capability set fail closed."""
    result = getattr(server, tool)(**TOOL_KWARGS[tool])

    assert result == {"error": f"{tool} is not available for platform vyos"}
    assert capability_lab.calls == []

    # The capability lookup is deliberately before tier parsing: a caller cannot
    # learn anything about the OpenWrt tier parser by sending a bogus VyOS tier.
    if tool == "newton_plan_tier":
        bad_tier = server.newton_plan_tier(device="vy1", tier="bogus")
        assert bad_tier == {
            "error": "newton_plan_tier is not available for platform vyos"
        }
        assert capability_lab.calls == []


def test_mv1_3_02_guided_audit_refuses_vyos_before_openwrt_reads(
    capability_lab: _GateLab,
) -> None:
    """No OpenWrt audit getter may run on another platform."""
    result = server.newton_guided_audit(device="vy1")

    assert result == {
        "error": (
            "newton_guided_audit on platform vyos needs audit getters, "
            "which are not built yet"
        )
    }
    assert capability_lab.calls == []


def test_mv1_3_03_openwrt_capabilities_and_device_lookup_are_unchanged(
    capability_lab: _GateLab,
) -> None:
    """OpenWrt still exposes every current tool and resolves quasar."""
    assert registry.capabilities("openwrt").tools == server.TOOL_NAMES - {
        "newton_get_state",
        "newton_list_getters",
        "newton_ad_audit",
        "newton_ad_list_checks",
        "newton_ad_plan_change",
        "newton_ad_apply_change",
        "newton_ad_change_status",
        "newton_ad_abort_change",
    }

    service = server.NewtonService()
    openwrt_tools = DEVICE_TOOLS & registry.capabilities("openwrt").tools
    for tool in openwrt_tools:
        assert service.device_for(tool, "quasar") is capability_lab.devices["quasar"]
    for tool in (
        "newton_get_state",
        "newton_list_getters",
        "newton_ad_audit",
    ):
        with pytest.raises(NewtonError):
            service.device_for(tool, "quasar")


def test_mv1_3_04_device_for_preserves_lookup_and_unknown_platform_errors(
    capability_lab: _GateLab,
) -> None:
    """Lookup errors stay exact and unregistered platforms fail closed."""
    service = server.NewtonService()
    with pytest.raises(NewtonError) as unknown:
        service.device_for("newton_read", "nope")
    assert str(unknown.value) == "unknown device: nope"

    capability_lab.devices["acme"] = server.Device(
        name="acme",
        platform="acme",
        host="192.0.2.10",
        user="newton",
    )
    for tool in server.TOOL_NAMES:
        with pytest.raises(NewtonError, match="unsupported platform 'acme'"):
            service.device_for(tool, "acme")


def test_mv1_3_05_service_methods_cannot_bypass_device_for() -> None:
    """AST-check that every device path goes through the gate."""
    tree = ast.parse(Path(server.__file__).read_text(encoding="utf-8"))

    class SelfDeviceVisitor(ast.NodeVisitor):
        def __init__(self) -> None:
            self.stack: list[str] = []
            self.calls: list[tuple[tuple[str, ...], int]] = []

        def visit_Call(self, node: ast.Call) -> None:
            function = node.func
            if (
                isinstance(function, ast.Attribute)
                and function.attr == "device"
                and isinstance(function.value, ast.Name)
                and function.value.id == "self"
            ):
                self.calls.append((tuple(self.stack), node.lineno))
            self.generic_visit(node)

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self.stack.append(node.name)
            self.generic_visit(node)
            self.stack.pop()

    visitor = SelfDeviceVisitor()
    visitor.visit(tree)
    device_calls = [
        (stack, line)
        for stack, line in visitor.calls
    ]
    assert device_calls
    assert all("device_for" in stack for stack, _ in device_calls)

    for method_name, expected_tool in DEVICE_METHOD_TOOLS.items():
        method = _newton_service_method(tree, method_name)
        gated = _self_attr_calls(method, "device_for")
        assert len(gated) == 1, f"NewtonService.{method_name}"

        first_argument = gated[0].args[0]
        if method_name == "plan":
            assert isinstance(first_argument, ast.Name)
            assert first_argument.id == "_tool"
            parameter = inspect.signature(
                server.NewtonService.plan
            ).parameters["_tool"]
            assert parameter.kind is inspect.Parameter.KEYWORD_ONLY
            assert parameter.default == expected_tool
        else:
            assert isinstance(first_argument, ast.Constant)
            assert first_argument.value == expected_tool

        if method_name == "plan_tier":
            first_statement = method.body[0]
            if (
                isinstance(first_statement, ast.Expr)
                and isinstance(first_statement.value, ast.Constant)
                and isinstance(first_statement.value.value, str)
            ):
                first_statement = method.body[1]
            assert _self_attr_calls(first_statement, "device_for")
            plan_calls = _self_attr_calls(method, "plan")
            assert len(plan_calls) == 1
            keywords = {keyword.arg: keyword.value for keyword in plan_calls[0].keywords}
            assert isinstance(keywords["_tool"], ast.Constant)
            assert keywords["_tool"].value == "newton_plan_tier"


def test_mv1_3_06_registry_declares_experimental_read_only_platforms() -> None:
    """The registry reserves supported vendors as T0 read-only only.

    VyOS is the exception: it is a vendor write platform
    with its own device-side revert (commit-confirm).  RouterOS is the
    second exception: it writes too, but its revert is a
    reboot into the backup, so it is a T2.  Junos is the third:
    it writes and its revert is its own commit confirmed, so it is
    a T1.  The other vendors stay T0 read-only until their own write path
    ships.
    """
    expected_platforms = {
        "openwrt", "routeros", "vyos", "junos", "eos", "iosxe", "fortios",
        "ad-windows", "ad-samba", "ad-windows-write", "ad-samba-write",
    }
    assert registry.PLATFORMS == expected_platforms
    with pytest.raises(registry.UnknownPlatform):
        registry.capabilities("bad")
    assert issubclass(registry.UnknownPlatform, ValueError)

    for platform in expected_platforms - {
        "openwrt", "vyos", "routeros", "junos", "ad-windows", "ad-samba",
        "ad-windows-write", "ad-samba-write",
    }:
        caps = registry.capabilities(platform)
        assert caps.tier == "T0-exp"
        assert caps.writes is False
        assert caps.native_revert is None
        assert caps.tools == base.READ_ONLY_TOOLS

    vyos = registry.capabilities("vyos")
    assert vyos.tier == "T1"
    assert vyos.writes is True
    assert vyos.native_revert == "commit-confirm"
    assert vyos.tools == base.READ_ONLY_TOOLS | frozenset(
        {
            "newton_backup",
            "newton_plan_change",
            "newton_apply_change",
            "newton_change_status",
            "newton_abort_change",
        }
    )

    for platform in ("ad-windows-write", "ad-samba-write"):
        caps = registry.capabilities(platform)
        assert caps.tier == "T1"
        assert caps.writes is True
        assert caps.native_revert == "undo timer on the DC"
        assert caps.tools == frozenset({"newton_list_devices"}) | base.AD_WRITE_TOOLS

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

    assert base.READ_ONLY_TOOLS == {
        "newton_list_devices",
        "newton_list_getters",
        "newton_get_state",
        "newton_guided_recommend",
        "newton_guided_audit",
    }
    openwrt = registry.capabilities("openwrt")
    assert openwrt.writes is True
    assert openwrt.tier == "T1"


def test_mv1_3_13_the_ad_platforms_are_read_only_with_the_ad_tools() -> None:
    """The AD platforms serve the AD tools and nothing else.

    Their collector runs as a forced command over ssh and the audit is
    read-only, so there is no write and no device-side revert.  The
    tool set is the device listing and the two AD tools: no getters,
    no router tools, no writes.
    """
    expected = frozenset(
        {"newton_list_devices", "newton_ad_audit", "newton_ad_list_checks"}
    )
    assert registry.AD_PLATFORMS == frozenset({"ad-windows", "ad-samba"})
    for platform in sorted(registry.AD_PLATFORMS):
        caps = registry.capabilities(platform)
        assert caps.tier == "T0-exp"
        assert caps.writes is False
        assert caps.native_revert is None
        assert caps.tools == expected
        assert platform not in registry.VENDOR_WRITE_PLATFORMS
        assert caps.tools & base.READ_ONLY_TOOLS == frozenset(
            {"newton_list_devices"}
        )


def test_mv1_3_14_the_ad_tools_are_read_only_tools() -> None:
    """The AD tools may sit in a read-only capability, and only there."""
    assert base.AD_READ_ONLY_TOOLS == frozenset(
        {"newton_ad_audit", "newton_ad_list_checks"}
    )
    for platform in ("eos", "iosxe", "fortios"):
        assert base.AD_READ_ONLY_TOOLS & registry.capabilities(platform).tools == (
            frozenset()
        )
    with pytest.raises(ValueError):
        base.Capabilities(
            tier="T0-exp",
            writes=False,
            native_revert=None,
            tools=frozenset({"newton_apply_change"}),
        )


def test_mv1_3_07_capabilities_invariant_and_immutability() -> None:
    """Design 8.2: experimental capabilities cannot advertise writes."""
    read_only = base.Capabilities(
        tier="T0-exp",
        writes=False,
        native_revert=None,
        tools=frozenset({"newton_list_devices"}),
    )
    assert read_only.tools == frozenset({"newton_list_devices"})

    invalid_factories = [
        lambda: base.Capabilities(
            tier="T0-exp",
            writes=False,
            native_revert=None,
            tools=frozenset({"newton_apply_change"}),
        ),
        lambda: base.Capabilities(
            tier="T1",
            writes=False,
            native_revert=None,
            tools=frozenset({"newton_plan_change"}),
        ),
        lambda: base.Capabilities(
            tier="T0-exp",
            writes=True,
            native_revert=None,
            tools=frozenset({"newton_list_devices"}),
        ),
    ]
    for make_capabilities in invalid_factories:
        with pytest.raises(ValueError):
            make_capabilities()

    valid = base.Capabilities(
        tier="T0-exp",
        writes=False,
        native_revert=None,
        tools=frozenset({"newton_list_devices"}),
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        valid.tier = "T1"  # type: ignore[misc]


def test_mv1_3_08_real_inventory_reaches_the_capability_gate(
    real_capability_lab: _GateLab,
) -> None:
    """The real loader relaxes only inside the capability gate."""
    for tool in sorted(DEVICE_TOOLS - registry.capabilities("vyos").tools):
        result = getattr(server, tool)(**TOOL_KWARGS[tool])

        assert result == {"error": f"{tool} is not available for platform vyos"}
        assert real_capability_lab.calls == []

    audit = server.newton_guided_audit(device="vy1")
    assert audit == {
        "error": (
            "newton_guided_audit on platform vyos needs audit getters, "
            "which are not built yet"
        )
    }
    assert real_capability_lab.calls == []

    listed = server.newton_list_devices()
    entries = {device["name"]: device for device in listed["devices"]}
    assert entries["vy1"]["platform"] == "vyos"
    # A non-OpenWrt entry says whether that device may write.
    assert entries["vy1"]["writes"] is False
    assert set(entries["vy1"]) == {
        "name", "platform", "host", "user", "auth", "profile",
        "tier", "capabilities", "writes", "easy_grant",
    }
