"""SF1: the router setup loader applies the same inventory-file checks and the
same proxy_command allowlist as mcp/newton_mcp/inventory_file.py and
scripts/newton-vantage-setup, with the same messages.

Every case here ends inside load_inventory, so no fake router and no ssh are
needed: the tool either refuses with exit 2 before its first external call, or
load_inventory is sourced and run on its own.
"""

import ast
import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "scripts" / "newton-router-setup"

BASE_BODY = (
    'host = "192.0.2.1"\n'
    'user = "root"\n'
    'auth = "password"\n'
    'profile = "lab"\n'
)

# source the tool (its main is guarded), run its own loader and nothing else,
# then show the value it kept: load_inventory fills DEV_* instead of printing
SOURCE_RUN = r'''
source "$1"
INVENTORY="$2"
load_inventory "$3"
printf 'proxy=%s\n' "$DEV_PROXY"
'''


def _toml_basic(value):
    """Escape a string for a TOML basic string."""
    return value.replace("\\", "\\\\").replace('"', '\\"')


def write_inventory(tmp_path, *, body=BASE_BODY, proxy=None, device="r1",
                    mode=0o644):
    """The devices.toml a case runs against; `proxy` adds proxy_command."""
    if proxy is not None:
        body += 'proxy_command = "%s"\n' % _toml_basic(proxy)
    inventory = tmp_path / "devices.toml"
    inventory.write_text("[devices.%s]\n%s" % (device, body))
    # write_text creates 0666 & ~umask, i.e. 0664 under umask 0002, which the
    # inventory-file check refuses; pin the fixture mode.
    inventory.chmod(mode)
    return inventory


def base_env(tmp_path, inventory):
    env = {k: v for k, v in os.environ.items() if not k.startswith("NEWTON_")}
    env["NEWTON_INVENTORY"] = str(inventory)
    env["NEWTON_STATE_DIR"] = str(tmp_path / "state")
    env["HOME"] = str(tmp_path / "home")
    env["TMPDIR"] = str(tmp_path)
    return env


def run_tool(tmp_path, inventory, *args):
    """The whole tool, up to its first refusal at load_inventory."""
    return subprocess.run(
        [str(TOOL), *args], env=base_env(tmp_path, inventory),
        capture_output=True, text=True, timeout=60,
        stdin=subprocess.DEVNULL)


def load_inventory_only(tmp_path, inventory, device="r1"):
    """The tool's own load_inventory, run without any action or ssh."""
    return subprocess.run(
        ["bash", "-c", SOURCE_RUN, "bash", str(TOOL), str(inventory), device],
        capture_output=True, text=True, timeout=30,
        stdin=subprocess.DEVNULL, env={"PATH": "/usr/bin:/bin"})


# ---- the refusal messages must be the MCP server's, verbatim --------------


def _inventory_file_refusal_messages():
    """The static refusal messages mcp/newton_mcp/inventory_file.py returns,
    read from its source so this drift test cannot drift from it."""
    tree = ast.parse((ROOT / "mcp" / "newton_mcp" / "inventory_file.py").read_text())
    messages = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Return) or node.value is None:
            continue
        value = node.value
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            prefix = value.value
        elif isinstance(value, ast.JoinedStr):
            first = value.values[0]
            if not (isinstance(first, ast.Constant) and isinstance(first.value, str)):
                continue
            prefix = first.value
        else:
            continue
        # The lstat OSError branch interpolates a strerror, so its text is a
        # template rather than a fixed string; it is covered by its own
        # refusal tests, not by this verbatim comparison.
        if prefix.startswith("inventory file cannot be inspected"):
            continue
        messages.append(prefix)
    return tuple(messages)


INVENTORY_REFUSAL_MESSAGES = _inventory_file_refusal_messages()


def test_inventory_file_messages_match_router_setup():
    """The three static refusal messages must appear verbatim in the script's
    embedded loader, so an operator sees the same wording on every path."""
    assert len(INVENTORY_REFUSAL_MESSAGES) == 3, INVENTORY_REFUSAL_MESSAGES
    text = TOOL.read_text()
    for message in INVENTORY_REFUSAL_MESSAGES:
        assert message in text, message


def test_inventory_symlink_is_refused(tmp_path):
    """A symlinked inventory is refused without ever being opened: lstat sees a
    link, and the loader says so instead of following it."""
    inventory = write_inventory(tmp_path)
    real = tmp_path / "devices-real.toml"
    inventory.rename(real)
    inventory.symlink_to(real)

    result = run_tool(tmp_path, inventory, "r1", "check")

    assert result.returncode == 2, result.stdout + result.stderr
    assert "inventory file must be a regular file, not a symlink" in result.stderr


def test_inventory_group_or_world_writable_is_refused(tmp_path):
    """A 0664 inventory can be rewritten by another local user between the
    check and the read, so the loader refuses and names the fix."""
    inventory = write_inventory(tmp_path, mode=0o664)

    result = run_tool(tmp_path, inventory, "r1", "check")

    assert result.returncode == 2, result.stdout + result.stderr
    assert "inventory file must not be group- or world-writable" in result.stderr
    assert "chmod go-w {}".format(inventory) in result.stderr


def test_inventory_owned_by_another_user_is_refused(tmp_path):
    """An inventory owned by a different uid than the one running the tool is
    refused.  Needs root to chown, so it is skipped otherwise."""
    if os.geteuid() != 0:
        pytest.skip("chown to a foreign uid needs root")
    inventory = write_inventory(tmp_path)
    foreign_uid = 65534 if os.geteuid() != 65534 else 65533
    os.chown(inventory, foreign_uid, -1)

    result = run_tool(tmp_path, inventory, "r1", "check")

    assert result.returncode == 2, result.stdout + result.stderr
    assert "inventory file must be owned by the user running the MCP server" in result.stderr

def _pretend_other_euid(monkeypatch, tmp_path):
    """Make the script's python think it runs as another user (no root needed)."""
    hook = tmp_path / "euidhook"
    hook.mkdir()
    (hook / "sitecustomize.py").write_text("import os\nos.geteuid = lambda: os.stat(os.environ['NEWTON_INVENTORY']).st_uid + 1\n")
    monkeypatch.setenv("PYTHONPATH", str(hook))


def test_inventory_owner_mismatch_is_refused_without_root(tmp_path, monkeypatch):
    inventory = write_inventory(tmp_path)
    _pretend_other_euid(monkeypatch, tmp_path)

    result = run_tool(tmp_path, inventory, "r1", "check")

    assert result.returncode == 2, result.stdout + result.stderr
    assert "inventory file must be owned by the user running the MCP server" in result.stderr


def test_missing_inventory_keeps_its_current_message(tmp_path):
    """A missing inventory is not one of the refusals above: the read error the
    operator already knows stays as it was."""
    absent = tmp_path / "absent.toml"

    result = run_tool(tmp_path, absent, "r1", "check")

    assert result.returncode == 2, result.stdout + result.stderr
    assert "cannot read inventory" in result.stderr
    assert "regular file" not in result.stderr


@pytest.mark.parametrize(
    "char", [";", "|", "&", "$", "`", "(", ")", "<", ">", "'", '"', "\\"]
)
def test_proxy_command_with_shell_metacharacter_is_refused(tmp_path, char):
    """proxy_command reaches ssh -o ProxyCommand=<value>; any shell
    metacharacter in it is refused, exactly as the MCP server refuses it."""
    inventory = write_inventory(tmp_path, proxy="ssh -W %h:%p root@jump{}id".format(char))

    result = run_tool(tmp_path, inventory, "r1", "check")

    assert result.returncode == 2, result.stdout + result.stderr
    assert "bad proxy_command for r1" in result.stderr


def test_proxy_command_without_metacharacter_is_accepted(tmp_path):
    """The real-world ProxyCommand form stays accepted and reaches the loader's
    output, so the run continues past load_inventory."""
    proxy = "ssh -i /home/u/.ssh/key -o BatchMode=yes -W %h:%p root@jump"
    inventory = write_inventory(tmp_path, proxy=proxy)

    result = load_inventory_only(tmp_path, inventory)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "proxy=" + proxy in result.stdout.splitlines()
