"""The gate.  The owner flow opens no new door.

The owner flow adds no MCP tool, changes no choke point and reaches no router by
any other way than the read-back's own session.  This file proves it:

  * every device tool but the read and the plan still
    refuses a no-install device; the device list works on one too;
  * no owner module reaches for ssh, for a subprocess or for the
    installed-mode apply;
  * the only rpcd write of the whole owner flow is the one ``uci
    confirm`` of the read-back;
  * no file of the package mentions ``luci-uploads``.
"""

from __future__ import annotations

import ast
import subprocess
from pathlib import Path

import pytest

import newton_mcp.server as server
from newton_mcp import noinstall_read
from newton_mcp import owner_verify

from noinstall_answers import data
from noinstall_fakes import FakeRouter
from test_inventory_noinstall import (
    DEVICE_FREE_TOOLS,
    NO_INSTALL_ALLOWED,
    NO_INSTALL_MESSAGE,
    TOOL_CALLS,
    _no_install_body,
    _write_inventory,
)
from test_owner_verify import (
    AFTER,
    TOKEN,
    FakeRouter as VerifyRouter,
    _backup,
    _finish,
)

PACKAGE = Path(__file__).resolve().parents[1] / "newton_mcp"

#: The modules of the owner flow.
OWNER_MODULES = (
    "owner_ops.py",
    "owner_script.py",
    "owner_backup.py",
    "owner_records.py",
    "owner_flow.py",
    "owner_verify.py",
)

#: The rpcd methods that change the router.
WRITE_VERBS = frozenset(
    {
        "set",
        "add",
        "delete",
        "commit",
        "apply",
        "revert",
        "rollback",
        "rename",
        "move",
        "order",
        "import",
        "export",
        "confirm",
        "destroy",
        "create",
        "grant",
    }
)


# ---- the MCP surface -------------------------------------------------------


def test_every_other_device_tool_still_refuses_a_no_install_device(
    tmp_path, monkeypatch
) -> None:
    """A2's sweep, extended: A3 opens no tool and A4 opens the plan."""
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


def test_the_read_the_plan_and_the_list_work_on_a_no_install_device(
    tmp_path, monkeypatch
) -> None:
    """The read and the plan work; the device is listed."""
    _write_inventory(tmp_path, monkeypatch, _no_install_body(tmp_path))
    router = FakeRouter({("system", "board"): data("system.board")})
    monkeypatch.setattr(
        noinstall_read, "default_client_factory", lambda _device: router
    )

    read = server.newton_read("lab-r1", "ubus call system board")
    assert read.get("exit_code") == 0, read
    listed = server.newton_list_devices()
    rows = {row["name"]: row for row in listed["devices"]}
    assert rows["lab-r1"]["access"] == "no-install"
    # the tools that take no device are not a way in either
    for tool in DEVICE_FREE_TOOLS:
        assert getattr(server, tool)() is not None


# ---- the owner code path ---------------------------------------------------


def _tree(name: str) -> ast.Module:
    return ast.parse((PACKAGE / name).read_text(encoding="utf-8"))


def _identifiers(tree: ast.Module):
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            yield node.id
        elif isinstance(node, ast.Attribute):
            yield node.attr


@pytest.mark.parametrize("name", OWNER_MODULES)
def test_no_owner_module_reaches_for_ssh_or_a_subprocess(name: str) -> None:
    """No owner module runs anything on the host."""
    tree = _tree(name)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] != "subprocess", name
        if isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] != "subprocess", name
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            owner = node.func.value
            if isinstance(owner, ast.Name) and owner.id == "os":
                assert node.func.attr not in {
                    "system",
                    "popen",
                    "execv",
                    "execve",
                    "execvp",
                    "spawnl",
                    "spawnv",
                    "fork",
                }, (name, node.func.attr)
    for identifier in _identifiers(tree):
        assert "ssh" not in identifier.lower(), (name, identifier)


@pytest.mark.parametrize("name", OWNER_MODULES)
def test_no_owner_module_calls_the_installed_apply(name: str) -> None:
    """The installed-mode apply is not a path an owner script may take."""
    for node in ast.walk(_tree(name)):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            assert node.func.attr not in {
                "apply",
                "apply_batch",
                "commit",
                "confirm",
            }, (name, node.func.attr)


@pytest.mark.parametrize("name", OWNER_MODULES)
def test_the_only_rpcd_write_of_the_owner_flow_is_the_confirm(name: str) -> None:
    """One write verb, in one module: the confirm of the read-back.

    The call may name its arguments in any shape, so the check reads
    the words of the call and not the position of one of them.
    """
    found = []
    for node in ast.walk(_tree(name)):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr != "call":
            continue
        words = [
            arg.value
            for arg in node.args
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str)
        ]
        for verb in words:
            if verb in WRITE_VERBS:
                found.append((verb, tuple(words)))
    if found:
        assert len(found) == 1, (name, found)
        verb, words = found[0]
        assert verb == "confirm", (name, found)
        assert "uci" in words, (name, found)
        assert name == "owner_verify.py", name


def test_the_confirm_goes_out_with_the_script_session(tmp_path) -> None:
    """The confirm is sent with the session the script opened.

    A fresh limited session cannot confirm a root script's apply: the
    router answers [6] (measured).  The session the script opened is
    the one that carries the right, and it is the one the confirm goes
    out with.
    """
    router = VerifyRouter(AFTER)
    verdict = _finish(tmp_path, router)
    assert verdict.state == "CONFIRMED", verdict.notes
    assert router.confirm_sessions == [TOKEN], router.confirm_sessions
    # and it is not the session of the fresh limited login
    assert all(session.id != TOKEN for session in router.sessions)


def test_the_confirm_is_the_only_write_a_real_read_back_makes(tmp_path) -> None:
    """The read-back of a passing change writes once, and only once."""
    router = VerifyRouter(AFTER)
    verdict = _finish(tmp_path, router)
    assert verdict.state == "CONFIRMED", verdict.notes
    writes = [
        (obj, fn)
        for obj, fn, _args in router.calls
        if fn in WRITE_VERBS
    ]
    assert writes == [("uci", "confirm")], writes
    assert router.confirms == 1


def test_a_failing_read_back_never_writes(tmp_path) -> None:
    """A change that cannot be read back is never confirmed."""
    router = VerifyRouter(AFTER)
    router.configs = dict(AFTER)
    router.configs["dhcp"] = {
        "cfg01411c": dict(AFTER["dhcp"]["cfg01411c"]),
        "lan": dict(AFTER["dhcp"]["lan"], limit="999"),
    }
    verdict = _finish(tmp_path, router)
    assert verdict.state != "CONFIRMED", verdict.notes
    assert router.confirms == 0


def test_the_package_never_mentions_luci_uploads() -> None:
    """Nothing in the package writes to the router's upload directory."""
    for path in sorted(PACKAGE.glob("*.py")):
        text = path.read_text(encoding="utf-8")
        assert "luci-uploads" not in text, path.name
        assert "cgi-io" not in text, path.name
