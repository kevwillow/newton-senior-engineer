#!/usr/bin/env python3
"""The lab driver for vendor VMs (VyOS first).

The driver runs the vendor write shapes against a lab VM.  For every
(shape, vendor) pair it resets the VM to its Proxmox snapshot, plans the
change through the real NewtonService, writes the approval record the way
newton-approve writes it, applies the change, reads the status back and
compares the outcome with the shape's expectation.  One line per shape is
printed; the exit code is 0 only when every shape passed.

The shapes live in ``lab/vendor-shapes.toml``: one table per shape and one
lines table per vendor, so a new vendor adds a table and nothing else.
The driver never speaks to a device itself: it drives NewtonService in
process and every session goes through the same SshSessionRunner the MCP
server uses.

Tunnel: the lab VMs are reachable only through apollo, but the MCP ssh
transport is a direct ssh to the device's host and port.  So the driver
opens one ssh tunnel per run (an argv list, never a shell string), points
the inventory it writes at the tunnel's local endpoint and pins the host
key with a known_hosts file it rewrites for that endpoint.  The tunnel
dies with the run, in a finally.

Review fixes: a post may only run on the device under test or on a device
the shapes file allows in its [helpers] table, and the loader refuses
any other name.  ``--no-reset`` still reads the configuration hash and
stops the run when the device is not at the recorded baseline.  The
tunnel proves that the listener on its port is its own ssh.  A
passphrase that is not UTF-8 fails the shape instead of ending the run
with a traceback, and ``--state`` says that the records stay in the
state directory.

RouterOS CHR: the CHR is the second vendor.  The driver reads the
configuration with the vendor's own operations, so the hash of the
running configuration is the one the vendor defines (the export of a CHR
hashes as the CHR hashes it, not as the sha256 of the text).  The
listing loads the shapes the way a run loads them, a post may only name
the device under test or a helper (a shape-level device key does not
widen that list), and ``--no-reset`` is only allowed with exactly one
``--shape``: the baseline gate cannot protect a second shape.

Exit codes: 0 when every shape passed, 1 when a shape failed, 2 when the
run stopped before the shapes (a configuration error, or a device that is
not at its recorded baseline).
"""

from __future__ import annotations

import argparse
import contextlib
import importlib.util
import io
import json
import os
import re
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

if sys.version_info < (3, 11):
    sys.exit(f"{__file__}: requires Python 3.11+")

HERE = Path(__file__).resolve().parent
DEFAULT_LAB = HERE / "lab.toml"
DEFAULT_SHAPES = HERE / "vendor-shapes.toml"
MCP_DIR = HERE.parent / "mcp"
if str(MCP_DIR) not in sys.path:
    sys.path.insert(0, str(MCP_DIR))

from newton_mcp import approve, server, vendor_flow  # noqa: E402
from newton_mcp.adapters import vendor_write  # noqa: E402
from newton_mcp.adapters.vendor_ssh import SshSessionRunner  # noqa: E402
from newton_mcp.vendor_change import VendorRefusal  # noqa: E402


def _load_lab_module() -> Any:
    """The lab runner (lab/newton-lab-test.py) as a module.

    The file name has hyphens, so it cannot be imported by name.  The
    lab tests load it as ``newton_lab_test`` already; when they did, that
    module is reused so the driver and the tests share one Lab class.
    """
    existing = sys.modules.get("newton_lab_test")
    if existing is not None:
        return existing
    spec = importlib.util.spec_from_file_location(
        "newton_lab_test", HERE / "newton-lab-test.py"
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("the lab runner could not be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules["newton_lab_test"] = module
    spec.loader.exec_module(module)
    return module


nl = _load_lab_module()


EXPECT_WORDS = ("confirmed", "rolled_back", "refused_at_plan", "refused_at_apply")
DEVICE_NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
PLACEHOLDER_RE = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}")
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
# The tunnel's local endpoint.  The MCP transport talks to this address and
# the tunnel carries the traffic to the VM through apollo.
TUNNEL_HOST = "127.0.0.1"
# How long the driver waits for the tunnel's port to accept a connection.
TUNNEL_TIMEOUT_S = 15
TUNNEL_POLL_S = 0.2
# How long the driver waits before it proves that the listener on the
# port is its own ssh and not something else that took the port.
TUNNEL_SETTLE_S = 0.25
# The grammar of the two values the driver takes from the lab's [ssh]
# proxy string: the user and the host it reaches.
TUNNEL_USER_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}$")
TUNNEL_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$")
# The key types a known_hosts line may carry.  A line whose second field is
# none of these is not a known_hosts line the driver can rewrite.
KEYTYPE_RE = re.compile(r"^(?:ssh|ecdsa|sk)-[A-Za-z0-9@._-]+$")

# How long the driver waits for the Proxmox rollback task and for the
# device to answer ssh again after it.
RESET_TASK_TIMEOUT_S = 300
RESET_SSH_TIMEOUT_S = 300
# How many times a rollback that lost the lock of the config of the VM is
# sent again, and how long the driver waits between two attempts.
RESET_MAX_ATTEMPTS = 4
RESET_RETRY_SLEEP_S = 20
# The message of the Proxmox task that lost the lock of the config of the
# VM: the previous rollback is still finishing and it holds that lock, so
# the task cannot take it and says so.
LOCK_TIMEOUT_TEXT = "can't lock file"
LOCK_TIMEOUT_END = "got timeout"
POST_TIMEOUT_S = 60
POLL_S = 5
# The extra time the driver waits for a device that must come back by
# itself (the commit-confirm timer fires, the device reloads).
RETURN_GRACE_S = 90


class ShapeError(ValueError):
    """The shapes file is not usable; the message names the table."""


class DriverError(ValueError):
    """The run cannot start; the message names what the operator must fix."""


@dataclass(frozen=True)
class Post:
    """One check that runs after the apply, over ssh."""

    device: str
    cmd: str
    expect_rc: int = 0
    expect_stdout: str | None = None
    expect_not_stdout: str | None = None
    timeout: int = POST_TIMEOUT_S


@dataclass(frozen=True)
class Shape:
    """One shape: what it changes and what it must end up as."""

    id: str
    description: str
    expect: str
    explanation: dict[str, Any]
    lines: tuple[str, ...]
    claims: tuple[dict[str, Any], ...]
    posts: tuple[Post, ...]
    approval: bool = True
    sessions: int | None = None
    timeout_s: int = 90
    helpers: tuple[str, ...] = ()


@dataclass(frozen=True)
class ShapeResult:
    """What one shape ended up as."""

    id: str
    expected: str
    got: str
    passed: bool
    seconds: float
    detail: str = ""
    fatal: bool = False


@dataclass
class VendorContext:
    """Everything one run needs: the lab, the shapes and the service."""

    lab: Any
    shapes: dict[str, Shape]
    baseline_hash: str
    device: Any
    device_name: str
    vendor: str
    state: Path
    service: Any
    factory: Callable[[Any], Any]
    target: Any = None
    tunnel: Any = None
    counter: list[int] = field(default_factory=lambda: [0])
    wait_budget_s: float | None = None
    owns_state: bool = False
    previous_env: dict[str, str | None] = field(default_factory=dict)
    helpers: tuple[str, ...] = ()
    # Does this device ask for the fast reset?  A device that does may
    # skip the Proxmox rollback when it is already at the baseline.
    fast_reset: bool = False

    def close(self) -> None:
        """Kill the tunnel, put the environment back, drop the state dir."""
        if self.tunnel is not None:
            self.tunnel.stop()
        for name, value in self.previous_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        if self.owns_state:
            shutil.rmtree(self.state, ignore_errors=True)


# ---------- the tunnel to the lab VM ----------
#
# The MCP ssh transport (adapters/vendor_ssh.py, ssh_cli.base_argv) is a
# direct ssh to the device's host and port.  The lab VMs are reachable
# only through apollo, so the driver opens one ssh tunnel per run and
# points the inventory it writes at the tunnel's local endpoint.  The
# inventory format carries a port (server.load_inventory reads "port"), and
# ssh_cli's host grammar accepts 127.0.0.1, so no change in mcp/ is
# needed.

@dataclass
class Tunnel:
    """An open ssh tunnel: the local port and the process that holds it."""

    port: int
    argv: list[str] = field(default_factory=list)
    process: Any = None
    stopped: bool = False

    def stop(self) -> None:
        """Kill the tunnel's process group; safe to call more than once."""
        if self.stopped:
            return
        self.stopped = True
        if self.process is not None:
            _kill_tunnel(self.process)


def _free_port() -> int:
    """A free local port for the tunnel's forward."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((TUNNEL_HOST, 0))
        return int(sock.getsockname()[1])


def _port_accepts(port: int, timeout: float = 0.5) -> bool:
    """Is the tunnel's local port accepting connections?"""
    try:
        with socket.create_connection((TUNNEL_HOST, port), timeout=timeout):
            return True
    except OSError:
        return False


def _proxy_destination(lab: Any) -> tuple[str, str]:
    """The user and the host the lab's [ssh] proxy reaches.

    The proxy string ends with the destination ("root@192.0.2.11"); the
    last user@host token in it is that destination.  A proxy without one
    leaves the Proxmox host as the destination.
    """
    for token in reversed(str(lab.ssh_proxy).split()):
        if "@" not in token or token.startswith("-"):
            continue
        user, _, host = token.partition("@")
        if TUNNEL_USER_RE.fullmatch(user) and TUNNEL_HOSTNAME_RE.fullmatch(host):
            return user, host
    return "root", str(lab.pve_host)


def tunnel_argv(lab: Any, device: Any, port: int) -> list[str]:
    """The argv of the tunnel: a list, never a shell string.

    The tunnel forwards the local port to the device's ssh port through
    apollo: the lab's own ssh key, batch mode, no prompts and no forward
    that may fail silently.
    """
    user, host = _proxy_destination(lab)
    return [
        "ssh",
        "-i", str(lab.ssh_key),
        "-o", "IdentitiesOnly=yes",
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=8",
        "-o", "ExitOnForwardFailure=yes",
        "-N",
        "-L", f"{TUNNEL_HOST}:{port}:{device.host}:22",
        f"{user}@{host}",
    ]


def _kill_tunnel(process: Any) -> None:
    """Kill the tunnel's process group."""
    pid = getattr(process, "pid", None)
    if not isinstance(pid, int):
        return
    try:
        os.killpg(pid, signal.SIGTERM)
    except (OSError, ValueError):
        return
    try:
        process.wait(timeout=2)
    except (subprocess.TimeoutExpired, OSError):
        try:
            os.killpg(pid, signal.SIGKILL)
        except (OSError, ValueError):
            return


def _prove_tunnel(process: Any, port: int, device: Any) -> None:
    """Prove that the listener on the port is the ssh we started.

    The port is free when it is chosen, but something else may take it
    before the ssh binds it.  The tunnel would then look open while our
    own ssh is gone, and the driver would talk to whatever else is
    listening on that port.  The proof is that the ssh child is still
    running and that the port answers again after a short settle.
    """
    time.sleep(TUNNEL_SETTLE_S)
    if process.poll() is not None:
        _kill_tunnel(process)
        raise DriverError(
            f"the tunnel to {device.name} exited before its port accepted "
            "a connection"
        )
    if not _port_accepts(port):
        _kill_tunnel(process)
        raise DriverError(
            f"the tunnel to {device.name} lost its port {port}"
        )


def open_tunnel(lab: Any, device: Any, *, popen: Any = None,
                timeout_s: float = TUNNEL_TIMEOUT_S) -> Tunnel:
    """Open the tunnel to the device and wait until its port accepts.

    The tunnel is one ssh process in its own session, so the whole process
    group can be killed when the run ends.  A tunnel that dies before its
    port answers is a refusal, not a silent hang.  A port that answers
    while our ssh is gone is a refusal as well: the listener may belong
    to something else.
    """
    if popen is None:
        popen = subprocess.Popen
    port = _free_port()
    argv = tunnel_argv(lab, device, port)
    try:
        process = popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError as exc:
        raise DriverError(
            f"the tunnel to {device.name} could not be started: {exc}"
        ) from None
    deadline = time.monotonic() + timeout_s
    while True:
        if process.poll() is not None:
            _kill_tunnel(process)
            raise DriverError(
                f"the tunnel to {device.name} exited before its port accepted "
                "a connection"
            )
        if _port_accepts(port):
            _prove_tunnel(process, port, device)
            return Tunnel(port=port, argv=list(argv), process=process)
        if time.monotonic() >= deadline:
            _kill_tunnel(process)
            raise DriverError(
                f"the tunnel to {device.name} did not open port {port} within "
                f"{timeout_s:g} s"
            )
        time.sleep(TUNNEL_POLL_S)


def rewrite_known_hosts(text: str, host: str, port: int) -> tuple[str, list[str]]:
    """Rewrite the device's known_hosts for the tunnel's endpoint.

    The device's own entry becomes ``[127.0.0.1]:<port>``, so the host
    key the tunnel carries is still pinned and StrictHostKeyChecking=yes
    still means what it says.  A line that names another host is skipped
    with a message; a line the driver cannot read (a hashed host, a line
    that is not a known_hosts line) is refused, because the run would then
    pin nothing at all.
    """
    lines: list[str] = []
    notes: list[str] = []
    matched = False
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) < 3:
            raise DriverError(
                f"the known_hosts line {number} is not a known_hosts line: "
                f"{line!r}"
            )
        hosts, keytype = fields[0], fields[1]
        if hosts.startswith("|"):
            raise DriverError(
                f"the known_hosts line {number} is hashed; the driver cannot "
                f"rewrite it: {line!r}"
            )
        if hosts.startswith("@"):
            raise DriverError(
                f"the known_hosts line {number} is a marker line ({hosts}); "
                f"the driver cannot rewrite it: {line!r}"
            )
        if not KEYTYPE_RE.fullmatch(keytype):
            raise DriverError(
                f"the known_hosts line {number} is not a known_hosts line: "
                f"{line!r}"
            )
        names = hosts.split(",")
        if host not in names:
            notes.append(
                f"the known_hosts line {number} names another host ({hosts}); "
                "it was skipped"
            )
            continue
        matched = True
        endpoint = f"[{TUNNEL_HOST}]:{port}"
        names = [endpoint if name == host else name for name in names]
        lines.append(",".join(names) + " " + " ".join(fields[1:]))
    if not matched:
        raise DriverError(
            f"the known_hosts file has no entry for {host}; the tunnel's host "
            "key could not be pinned"
        )
    rewritten = "".join(line + "\n" for line in lines)
    return rewritten, notes


# ---------- the shapes file ----------

def _vars(data: dict[str, Any]) -> dict[str, str]:
    raw = data.get("vars", {})
    if not isinstance(raw, dict):
        raise ShapeError("vars must be a table")
    values: dict[str, str] = {}
    for name, value in raw.items():
        if not isinstance(name, str) or not isinstance(value, str):
            raise ShapeError("vars entries must be strings")
        values[name] = value
    return values


def _substitute(text: str, values: dict[str, str], where: str) -> str:
    """Replace the {name} placeholders with the file's variables."""
    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in values:
            raise ShapeError(f"{where}: unknown variable {name!r}")
        return values[name]

    return PLACEHOLDER_RE.sub(replace, text)


def _helpers(data: dict[str, Any]) -> tuple[str, ...]:
    """The devices a post may run on besides the device under test.

    The table is optional and empty by default: a shapes file that names
    no helper allows no helper at all.  Every name here is one the
    operator has allowed for this shapes file.
    """
    raw = data.get("helpers", {})
    if not isinstance(raw, dict):
        raise ShapeError("[helpers] must be a table")
    devices = raw.get("devices", [])
    if not isinstance(devices, list):
        raise ShapeError("[helpers].devices must be a list of device names")
    names: list[str] = []
    for index, name in enumerate(devices):
        if not isinstance(name, str) or not name:
            raise ShapeError(
                f"[helpers].devices[{index}] must be a device name"
            )
        if name not in names:
            names.append(name)
    return tuple(names)


def _posts(raw: Any, where: str, default_device: str,
           allowed: frozenset[str]) -> tuple[Post, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise ShapeError(f"{where} must be a list of post tables")
    posts: list[Post] = []
    for index, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise ShapeError(f"{where}[{index}] must be a table")
        cmd = entry.get("cmd")
        if not isinstance(cmd, str) or not cmd:
            raise ShapeError(f"{where}[{index}].cmd must be a non-empty string")
        device = entry.get("device", default_device)
        if not isinstance(device, str):
            raise ShapeError(f"{where}[{index}].device must be a device name")
        if device not in allowed:
            raise ShapeError(
                f"{where}[{index}].device names a device the driver may not "
                f"use: {device!r}; a post may only run on the device under "
                "test or on a device of the [helpers] table"
            )
        expect_rc = entry.get("expect_rc", 0)
        if isinstance(expect_rc, bool) or not isinstance(expect_rc, int):
            raise ShapeError(f"{where}[{index}].expect_rc must be an integer")
        posts.append(
            Post(
                device=device,
                cmd=cmd,
                expect_rc=expect_rc,
                expect_stdout=_optional_text(entry, "expect_stdout", where, index),
                expect_not_stdout=_optional_text(
                    entry, "expect_not_stdout", where, index
                ),
                timeout=int(entry.get("timeout", POST_TIMEOUT_S)),
            )
        )
    return tuple(posts)


def _optional_text(entry: dict[str, Any], key: str, where: str,
                   index: int) -> str | None:
    value = entry.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise ShapeError(f"{where}[{index}].{key} must be a non-empty string")
    return value


def _claims(raw: Any, where: str) -> tuple[dict[str, Any], ...]:
    if not isinstance(raw, list) or not raw:
        raise ShapeError(f"{where} must be a non-empty list of claim tables")
    claims: list[dict[str, Any]] = []
    for index, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise ShapeError(f"{where}[{index}] must be a table")
        kind = entry.get("kind")
        if kind not in ("config_has", "ping"):
            raise ShapeError(
                f"{where}[{index}].kind must be config_has or ping, got {kind!r}"
            )
        claims.append(dict(entry))
    return tuple(claims)


def _shape(shape_id: str, raw: Any, vendor: str,
           vendor_raw: Any, values: dict[str, str],
           helpers: tuple[str, ...], device: str) -> Shape:
    where = f"[shapes.{shape_id}]"
    if not isinstance(raw, dict):
        raise ShapeError(f"{where} must be a table")
    if raw.get("id", shape_id) != shape_id:
        raise ShapeError(f"{where}: id must be {shape_id!r}")
    if vendor_raw is None:
        raise ShapeError(
            f"[{vendor}.{shape_id}] is missing: the shape has no lines for "
            f"{vendor}"
        )
    if not isinstance(vendor_raw, dict):
        raise ShapeError(f"[{vendor}.{shape_id}] must be a table")

    # The vendor table may override the facts that are vendor-specific: the
    # outcome of the shape, the number of sessions it may open, the window
    # of the plan and the text of the explanation.  A shape that behaves the
    # same on every vendor does not repeat them.
    expect = vendor_raw.get("expect", raw.get("expect"))
    if expect not in EXPECT_WORDS:
        raise ShapeError(
            f"{where}.expect must be one of {', '.join(EXPECT_WORDS)}, "
            f"got {expect!r}"
        )
    description = raw.get("description", "")
    if not isinstance(description, str):
        raise ShapeError(f"{where}.description must be a string")
    approval = vendor_raw.get("approval", raw.get("approval", True))
    if not isinstance(approval, bool):
        raise ShapeError(f"{where}.approval must be true or false")
    sessions = vendor_raw.get("sessions", raw.get("sessions"))
    if sessions is not None and (
        isinstance(sessions, bool) or not isinstance(sessions, int)
        or sessions < 0
    ):
        raise ShapeError(f"{where}.sessions must be a count of ssh sessions")
    timeout_s = vendor_raw.get("timeout_s", raw.get("timeout_s", 90))
    if isinstance(timeout_s, bool) or not isinstance(timeout_s, int):
        raise ShapeError(f"{where}.timeout_s must be an integer")
    if not 60 <= timeout_s <= 600:
        raise ShapeError(f"{where}.timeout_s must be 60..600")

    lines_raw = vendor_raw.get("lines")
    if (not isinstance(lines_raw, list) or not lines_raw
            or not all(isinstance(line, str) and line for line in lines_raw)):
        raise ShapeError(
            f"[{vendor}.{shape_id}].lines must be a non-empty list of strings"
        )
    lines = tuple(
        _substitute(line, values, f"[{vendor}.{shape_id}].lines")
        for line in lines_raw
    )

    explanation_raw = raw.get("explanation")
    if not isinstance(explanation_raw, dict):
        raise ShapeError(f"{where}.explanation must be a table")
    intent = vendor_raw.get("intent", explanation_raw.get("intent"))
    risk = vendor_raw.get("risk", explanation_raw.get("risk"))
    if not isinstance(intent, str) or not intent:
        raise ShapeError(f"{where}.explanation.intent must be a non-empty string")
    if not isinstance(risk, str) or not risk:
        raise ShapeError(f"{where}.explanation.risk must be a non-empty string")
    steps = vendor_raw.get("steps", explanation_raw.get("steps"))
    if (not isinstance(steps, list)
            or not all(isinstance(step, str) and step for step in steps)):
        raise ShapeError(f"{where}.explanation.steps must be a list of strings")
    if len(steps) != len(lines):
        raise ShapeError(
            f"{where}.explanation.steps has {len(steps)} entries but the "
            f"{vendor} table has {len(lines)} lines; give one short reason "
            f"per change line"
        )
    claims_raw = vendor_raw.get("claims", explanation_raw.get("expect"))
    claims = _claims(claims_raw, f"[{vendor}.{shape_id}].claims")
    claims = tuple(
        {k: (_substitute(v, values, f"[{vendor}.{shape_id}].claims")
             if isinstance(v, str) else v) for k, v in claim.items()}
        for claim in claims
    )
    explanation = {
        "intent": intent,
        "steps": list(steps),
        "expect": [dict(claim) for claim in claims],
        "risk": risk,
    }
    posts = _posts(
        vendor_raw.get("posts", raw.get("posts")),
        f"[{vendor}.{shape_id}].posts",
        _default_post_device(raw, device),
        _allowed_devices(helpers, device),
    )
    return Shape(
        id=shape_id,
        description=description,
        expect=expect,
        explanation=explanation,
        lines=lines,
        claims=claims,
        posts=posts,
        approval=approval,
        sessions=sessions,
        timeout_s=timeout_s,
        helpers=helpers,
    )


def _default_post_device(raw: dict[str, Any], device: str) -> str:
    """The device a post of this shape runs on when it names none.

    The device under test is the default.  A shape may name another device
    with its own ``device`` key, and then that name has to be one the
    driver may use: the key does not widen the allowlist.
    """
    shape_device = raw.get("device", "")
    if not isinstance(shape_device, str) or not shape_device:
        return device
    return shape_device


def _allowed_devices(helpers: tuple[str, ...], device: str) -> frozenset[str]:
    """The devices a post of this shape may name.

    The device under test and the helpers of the [helpers] table, and
    nothing else.  A shape-level ``device`` key does not widen this list:
    the shapes file is data, and the data may not point the driver at a
    device of the lab.
    """
    allowed = {device}
    allowed.update(helpers)
    return frozenset(allowed)


def load_shapes(path: Path, vendor: str, *,
                 device: str = "") -> dict[str, Shape]:
    """Read the shapes file and expand it for one vendor.

    A vendor with no tables in the file, a shape with no lines for the
    vendor and a shape whose explanation does not have one step per change
    line are all refused: the file is the contract the driver runs.

    ``device`` is the name of the device the driver runs against.  A post
    may name that device or a device of the [helpers] table, and nothing
    else.
    """
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ShapeError(f"the shapes file cannot be read: {exc}") from None
    except tomllib.TOMLDecodeError as exc:
        raise ShapeError(f"the shapes file is not valid TOML: {exc}") from None
    if not isinstance(vendor, str) or not vendor:
        raise ShapeError("a vendor name is required")
    values = _vars(data)
    helpers = _helpers(data)
    shapes_raw = data.get("shapes")
    if not isinstance(shapes_raw, dict) or not shapes_raw:
        raise ShapeError("the shapes file has no [shapes] tables")
    vendor_raw = data.get(vendor)
    if vendor_raw is None:
        raise ShapeError(f"the shapes file has no tables for vendor {vendor!r}")
    if not isinstance(vendor_raw, dict):
        raise ShapeError(f"[{vendor}] must be a table")
    for shape_id in vendor_raw:
        if shape_id not in shapes_raw:
            raise ShapeError(
                f"[{vendor}.{shape_id}] has no [shapes.{shape_id}] definition"
            )
    shapes: dict[str, Shape] = {}
    for shape_id, raw in shapes_raw.items():
        if not isinstance(shape_id, str):
            raise ShapeError("a shape id must be a string")
        shapes[shape_id] = _shape(
            shape_id, raw, vendor, vendor_raw.get(shape_id), values,
            helpers, device,
        )
    return shapes


def load_baseline_hash(path: Path, vendor: str) -> str:
    """The recorded hash of the baseline running configuration."""
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ShapeError(f"the shapes file cannot be read: {exc}") from None
    except tomllib.TOMLDecodeError as exc:
        raise ShapeError(f"the shapes file is not valid TOML: {exc}") from None
    baseline = data.get("baseline")
    if not isinstance(baseline, dict):
        raise ShapeError("the shapes file has no [baseline] tables")
    entry = baseline.get(vendor)
    if not isinstance(entry, dict):
        raise ShapeError(
            f"the shapes file has no [baseline.{vendor}] table: the driver "
            f"cannot tell the baseline configuration from a changed one"
        )
    value = entry.get("config_hash")
    if not isinstance(value, str) or not HASH_RE.fullmatch(value):
        raise ShapeError(
            f"[baseline.{vendor}].config_hash must be 64 lowercase hex characters"
        )
    return value


# ---------- the run ----------

class _CountingRunner:
    """A runner that counts the sessions it opens."""

    def __init__(self, runner: Any, counter: list[int]) -> None:
        self._runner = runner
        self._counter = counter

    def __call__(self, spec: Any) -> Any:
        self._counter[0] += 1
        out = self._runner(spec)
        if os.environ.get("NEWTON_VENDOR_LAB_DEBUG"):
            print(f"debug session {self._counter[0]}: remote={spec.remote!r} "
                  f"stdin={spec.stdin!r:.600} -> {out!r:.1500}", file=sys.stderr)
        return out


class _CountingFactory:
    """The factory the vendor flow uses to build a session runner."""

    def __init__(self, inner: Callable[[Any], Any], counter: list[int]) -> None:
        self._inner = inner
        self._counter = counter

    def __call__(self, target: Any) -> Any:
        return _CountingRunner(self._inner(target), self._counter)


@contextlib.contextmanager
def use_runner(ctx: VendorContext) -> Iterable[None]:
    """Let the vendor flow build its sessions through the context's factory.

    The vendor flow builds its session runner in one place, so the driver
    counts the sessions there and the tests can put a fake device in.
    """
    original = vendor_flow.SshSessionRunner
    vendor_flow.SshSessionRunner = _CountingFactory(ctx.factory, ctx.counter)
    try:
        yield
    finally:
        vendor_flow.SshSessionRunner = original


def _inventory_text(device: Any, *, host: str, port: int, key_file: str,
                    known_hosts: str) -> str:
    """The inventory the MCP server reads: one device, the lab VM.

    The host is the tunnel's local endpoint and the port is the tunnel's
    port, so the MCP transport reaches the VM through apollo.  The key is
    the device's own key and the known_hosts file is the one the driver
    rewrote for that endpoint.
    """
    lines = [
        "[devices." + device.name + "]",
        f"platform = {json.dumps(device.platform)}",
        f"host = {json.dumps(host)}",
        f"port = {int(port)}",
        f"user = {json.dumps(device.user)}",
        'auth = "key"',
        'profile = "lab"',
        "vendor_write = true",
        "lab = true",
        f"key_file = {json.dumps(key_file)}",
        f"known_hosts = {json.dumps(known_hosts)}",
        "",
    ]
    return "\n".join(lines)


def _require_file(raw: str, what: str) -> Path:
    """The path of a file the run needs, or a refusal that names it."""
    path = Path(os.path.expanduser(raw))
    try:
        info = path.lstat()
    except OSError:
        raise DriverError(f"{what} is missing: {path}") from None
    if not stat.S_ISREG(info.st_mode):
        raise DriverError(f"{what} is not a regular file: {path}")
    return path


def _device_paths(lab: Any, device: Any) -> tuple[Path, Path]:
    """The device's own known_hosts and key, or the lab's when it has none.

    The VyOS write key is not the lab's OpenWrt runner key, so a device
    that names its own files uses them.  A device that names none falls
    back to the lab's.
    """
    known_hosts = str(getattr(device, "known_hosts", "") or lab.known_hosts or "")
    key = str(getattr(device, "admin_key", "") or lab.router_key or "")
    if not known_hosts:
        raise DriverError(
            f"the device {device.name} has no known_hosts file and the lab "
            "has none either"
        )
    if not key:
        raise DriverError(
            f"the device {device.name} has no key file and the lab has none "
            "either"
        )
    known_hosts_path = _require_file(
        known_hosts, f"the known_hosts file of {device.name}"
    )
    key_path = _require_file(key, f"the key file of {device.name}")
    mode = stat.S_IMODE(key_path.stat().st_mode)
    if mode != 0o600:
        raise DriverError(
            f"the key file of {device.name} must have mode 0600 (it has "
            f"{mode:04o}): {key_path}"
        )
    return known_hosts_path, key_path


def _restore_env(previous: dict[str, str | None]) -> None:
    for name, value in previous.items():
        if value is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = value


def _vendor_device(lab: Any, vendor: str) -> Any:
    """The device of the lab that speaks this vendor."""
    for candidate in lab.devices.values():
        if getattr(candidate, "platform", "") == vendor:
            return candidate
    raise ShapeError(
        f"the lab has no device for vendor {vendor!r}; add one with a "
        f"platform and vendor_write to [devices]"
    )


def _fast_reset_flag(lab_path: Path, device_name: str) -> bool:
    """Does this device ask for the fast reset?

    The flag is a field of the device table of the lab file: a device
    that asks for it may skip the Proxmox rollback when it is already at
    the baseline.  The field is optional and false by default, so the
    devices that do not name it keep the behaviour they had.

    The lab runner does not read the field (it has no use for it), so
    the driver reads it here, from the file the operator wrote.
    """
    try:
        data = tomllib.loads(Path(lab_path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise DriverError(f"the lab file cannot be read: {exc}") from None
    except tomllib.TOMLDecodeError as exc:
        raise DriverError(f"the lab file is not valid TOML: {exc}") from None
    devices = data.get("devices")
    if not isinstance(devices, dict):
        return False
    entry = devices.get(device_name)
    if not isinstance(entry, dict):
        return False
    value = entry.get("fast_reset", False)
    if not isinstance(value, bool):
        raise DriverError(
            f"devices.{device_name}.fast_reset: must be true or false"
        )
    return value


def build_context(lab: Any, shapes_path: Path, vendor: str, *,
                  factory: Callable[[Any], Any] | None = None,
                  state_dir: Path | None = None,
                  tunnel_opener: Callable[[Any, Any], Any] | None = None,
                  fast_reset: bool = False
                  ) -> VendorContext:
    """Build the context of one run: the shapes, the device and the service.

    The run opens the tunnel to the device first: the inventory the MCP
    server reads points at the tunnel's local endpoint, and the host key
    the tunnel carries is pinned by the known_hosts file the driver writes
    for it.  The tunnel is killed when the context is closed, and also
    when anything below fails.

    ``fast_reset`` says that the device may skip the Proxmox rollback
    when it is already at the baseline.  It is false by default, so the
    devices that do not ask for it keep the behaviour they had.
    """
    device = _vendor_device(lab, vendor)
    shapes = load_shapes(shapes_path, vendor, device=device.name)
    baseline_hash = load_baseline_hash(shapes_path, vendor)
    if getattr(device, "vendor_write", False) is not True:
        raise ShapeError(
            f"the lab device {device.name!r} does not have vendor_write = true"
        )
    if not DEVICE_NAME_RE.fullmatch(device.name):
        raise ShapeError(f"the lab device name {device.name!r} is not usable")

    owns_state = state_dir is None
    if state_dir is None:
        state = Path(tempfile.mkdtemp(prefix="newton-vendor-lab-"))
        os.chmod(state, 0o700)
    else:
        state = Path(state_dir)
        state.mkdir(mode=0o700, parents=True, exist_ok=True)

    opener = tunnel_opener if tunnel_opener is not None else open_tunnel
    previous_env = {
        "NEWTON_INVENTORY": os.environ.get("NEWTON_INVENTORY"),
        "NEWTON_STATE_DIR": os.environ.get("NEWTON_STATE_DIR"),
    }
    tunnel = None
    try:
        known_hosts_path, key_path = _device_paths(lab, device)
        tunnel = opener(lab, device)
        rewritten, notes = rewrite_known_hosts(
            known_hosts_path.read_text(encoding="utf-8"),
            device.host,
            tunnel.port,
        )
        for note in notes:
            print(f"newton-vendor-lab: {note}", file=sys.stderr)
        known_hosts = state / "known_hosts"
        known_hosts.write_text(rewritten, encoding="utf-8")
        os.chmod(known_hosts, 0o600)
        inventory = state / "devices.toml"
        inventory.write_text(
            _inventory_text(
                device,
                host=TUNNEL_HOST,
                port=tunnel.port,
                key_file=str(key_path),
                known_hosts=str(known_hosts),
            ),
            encoding="utf-8",
        )
        os.chmod(inventory, 0o600)
        os.environ["NEWTON_INVENTORY"] = str(inventory)
        os.environ["NEWTON_STATE_DIR"] = str(state)
        service = server.NewtonService()
        target = service.devices.get(device.name)
        if target is None:
            raise DriverError(
                f"the inventory the driver wrote has no device {device.name!r}"
            )
    except BaseException:
        _restore_env(previous_env)
        if tunnel is not None:
            tunnel.stop()
        raise
    return VendorContext(
        lab=lab,
        shapes=shapes,
        baseline_hash=baseline_hash,
        device=device,
        device_name=device.name,
        vendor=vendor,
        state=state,
        service=service,
        factory=factory if factory is not None else SshSessionRunner,
        target=target,
        tunnel=tunnel,
        owns_state=owns_state,
        previous_env=previous_env,
        helpers=shapes[next(iter(shapes))].helpers if shapes else (),
        fast_reset=fast_reset,
    )


def _log_text(log: Any) -> str:
    if isinstance(log, dict):
        text = log.get("text")
        if isinstance(text, str):
            return text.strip()
    if isinstance(log, str):
        return log.strip()
    return ""


def _session_runner(ctx: VendorContext) -> Any:
    """A session runner that counts the sessions it opens.

    The target is the device the MCP server reads from the inventory the
    driver wrote: the tunnel's endpoint, with the tunnel's port and the
    pinned host key.
    """
    return _CountingRunner(ctx.factory(ctx.target), ctx.counter)


def _ops_for(vendor: str) -> Any:
    """The operations of one vendor: the driver's own definition of the device.

    The same operations the MCP server uses for that platform, so the
    driver reads the configuration the way Newton reads it.
    """
    factory = vendor_flow.OPS_BY_PLATFORM.get(vendor)
    if factory is None:
        raise DriverError(f"the driver has no operations for vendor {vendor!r}")
    return factory()


def _read_snapshot(ctx: VendorContext) -> tuple[bool, Any]:
    """Read the device's configuration with the vendor's own operations.

    The hash of the configuration is the one the vendor's operations
    define: a VyOS configuration hashes as its own text, and the export
    of a CHR hashes as the CHR operations hash it (the export normalises
    its lines).  The driver never hashes a configuration itself.
    """
    ops = _ops_for(ctx.vendor)
    runner = _session_runner(ctx)
    try:
        snapshot = ops.snapshot(runner)
    except Exception:
        return False, None
    if not isinstance(getattr(snapshot, "text", None), str):
        return False, None
    if not snapshot.text:
        return False, None
    return True, snapshot


def _wait_for_device(ctx: VendorContext, timeout_s: float) -> tuple[bool, Any]:
    """Wait until the device answers again, then return its snapshot."""
    deadline = time.monotonic() + max(0.0, timeout_s)
    while True:
        ok, snapshot = _read_snapshot(ctx)
        if ok:
            return True, snapshot
        if time.monotonic() >= deadline:
            return False, None
        time.sleep(POLL_S)


def _baseline_check(ctx: VendorContext, snapshot: Any) -> tuple[bool, str]:
    """Is the configuration the baseline records?

    The hash is the one the vendor's operations define, so the check is
    the vendor's own comparison and not the driver's.
    """
    digest = snapshot.base_hash
    if digest == ctx.baseline_hash:
        return True, ""
    return False, (
        f"the configuration hash {digest} is not the recorded baseline "
        f"{ctx.baseline_hash}: the device is not at the snapshot baseline"
    )


def _at_recorded_baseline(ctx: VendorContext) -> tuple[bool, str]:
    """Read the configuration and check it against the recorded baseline.

    The reset proves the device is at the baseline by reading the
    configuration back.  When the reset is skipped the driver cannot do
    that, so it reads the hash itself and stops the run when the device
    is not at the baseline.
    """
    ok, snapshot = _read_snapshot(ctx)
    if not ok:
        return False, "the device did not answer"
    return _baseline_check(ctx, snapshot)


def _is_lock_timeout(exitstatus: Any) -> bool:
    """True when the rollback task lost the lock of the config of the VM.

    The previous rollback of the same VM is still finishing and it holds
    the lock of the config, so the task cannot take it and says so: the
    message of Proxmox is "can't lock file
    '/var/lock/qemu-server/lock-703.conf' - got timeout".  Any other
    failure of the task is a failure of the rollback itself.
    """
    text = str(exitstatus or "")
    return LOCK_TIMEOUT_TEXT in text and LOCK_TIMEOUT_END in text


def _reset(
    ctx: VendorContext,
    sleep: Callable[[float], None] = time.sleep,
) -> tuple[bool, str]:
    """Roll the VM back to its snapshot and prove it is at the baseline.

    The rollback task can lose the lock of the config of the VM: the
    previous rollback is still finishing and it holds that lock, so the
    task says "can't lock file ... - got timeout" and does nothing at
    all.  That one failure is retried (four attempts at the most, twenty
    seconds apart, and the wait is injected so a test does not sleep);
    every other failure of the task stops the run at once, because it is
    a failure of the rollback itself and not a busy lock.
    """
    detail = "the rollback task did not finish cleanly"
    rolled_back = False
    for attempt in range(1, RESET_MAX_ATTEMPTS + 1):
        upid = nl.pve_rollback(ctx.lab, ctx.device)
        status = nl.pve_wait_task(
            ctx.lab, upid, timeout_s=RESET_TASK_TIMEOUT_S
        )
        if not isinstance(status, dict):
            return False, "the rollback task did not report a status"
        exitstatus = status.get("exitstatus")
        if status.get("status") == "stopped" and exitstatus == "OK":
            rolled_back = True
            break
        detail = f"the rollback task did not finish cleanly: {exitstatus!r}"
        if not _is_lock_timeout(exitstatus):
            return False, detail
        if attempt < RESET_MAX_ATTEMPTS:
            sleep(RESET_RETRY_SLEEP_S)
    if not rolled_back:
        return False, detail
    ok, snapshot = _wait_for_device(ctx, RESET_SSH_TIMEOUT_S)
    if not ok:
        return False, "the device did not answer after the rollback"
    return _baseline_check(ctx, snapshot)


def _at_baseline(ctx: VendorContext, base_hash: str,
                 budget_s: float) -> tuple[bool, str]:
    """Is the device back at the configuration the plan was staged on?"""
    ok, snapshot = _wait_for_device(ctx, budget_s)
    if not ok:
        return False, "the device did not come back"
    digest = snapshot.base_hash
    if digest == base_hash:
        return True, ""
    return False, f"the configuration hash is {digest}"


def _prepare(ctx: VendorContext) -> tuple[bool, str]:
    """Put the device back at the baseline before the shape.

    A device that asks for the fast reset may skip the Proxmox rollback:
    a Junos takes six to eight minutes to boot from a cold rollback, so
    a device that is already at the baseline is left alone.  The driver
    reads the hash of the running configuration and the pending state of
    the device, and it skips the rollback only when the hash is the
    recorded baseline and nothing is pending on the device.  Every other
    device is rolled back and checked, as it always was.
    """
    if ctx.fast_reset:
        ok, snapshot = _read_snapshot(ctx)
        if not ok:
            return False, "the device did not answer"
        if snapshot.base_hash == ctx.baseline_hash and snapshot.pending == "idle":
            # the device is at the baseline and nothing is pending: the
            # rollback would put it where it already is.
            return True, ""
    return _reset(ctx)


class _ApproveInput:
    """The terminal newton-approve reads: the confirmation and the tty."""

    def __init__(self, session_id: str) -> None:
        self._answer = f"approve {session_id[:8]}\n"

    def isatty(self) -> bool:
        return True

    def readline(self) -> str:
        return self._answer

    def __getattr__(self, name: str) -> Any:
        raise AttributeError(name)


def write_approval(ctx: VendorContext, session_id: str) -> tuple[bool, str]:
    """Write the approval record the way newton-approve writes it.

    The crypto is newton-approve's: the passphrase is read with its own
    reader, the key is derived with its own KDF and the token is minted
    with its own HMAC over the plan's digest and the approval window.  The
    record itself is written by newton-approve itself, so the file the MCP
    server reads is the file the operator's tool would have written.
    """
    try:
        passphrase = approve.read_passphrase_file(ctx.lab.approve_passphrase_file)
    except OSError as exc:
        return False, f"the lab approval passphrase cannot be read: {exc}"
    try:
        k_hex = approve.derive_k(passphrase, ctx.device_name)
    except ValueError as exc:
        return False, str(exc)
    try:
        secret = passphrase.decode("utf-8")
    except UnicodeDecodeError:
        # the passphrase file is not text: the shape fails on its own and
        # the run goes on to the next shape
        return False, "the lab approval passphrase is not valid UTF-8"
    fingerprint_dir = ctx.state / "approval-fp"
    fingerprint_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(fingerprint_dir, 0o700)
    fingerprint = fingerprint_dir / ctx.device_name
    fingerprint.write_text(
        f"v1 {approve.approval_fingerprint(k_hex)}\n", encoding="utf-8"
    )
    os.chmod(fingerprint, 0o600)

    output = io.StringIO()
    original_stdin = sys.stdin
    original_getpass = approve._getpass
    sys.stdin = _ApproveInput(session_id)  # type: ignore[assignment]
    approve._getpass = lambda _prompt: secret
    try:
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            code = approve.main([session_id])
    finally:
        sys.stdin = original_stdin
        approve._getpass = original_getpass
    if code != 0:
        detail = output.getvalue().strip().splitlines()
        reason = detail[-1] if detail else "no reason given"
        return False, f"newton-approve refused the plan: {reason}"
    return True, ""


def _run_post(ctx: VendorContext, post: Post) -> tuple[bool, str]:
    """Run one post check and compare what it said with what it must say.

    A post runs on the device under test or on a helper of the
    [helpers] table.  The loader refuses any other name, and the check
    is made again here: the driver never runs a command on a device it
    was not told about.
    """
    if not post.device or post.device == ctx.device_name:
        runner = _session_runner(ctx)
        output = runner(vendor_write.SessionSpec(remote=post.cmd, stdin=""))
        if getattr(output, "status", "") != "ok":
            return False, f"the session did not run ({output.status})"
        code = output.exit_code if output.exit_code is not None else 0
        text = output.stdout
    elif post.device in ctx.helpers:
        device = ctx.lab.devices.get(post.device)
        if device is None:
            return False, f"the helper {post.device!r} is not a lab device"
        proc = nl._run(nl.ssh_cmd(ctx.lab, device, post.cmd), timeout=post.timeout)
        code = proc.returncode
        text = proc.stdout
    else:
        return False, (
            f"the post device {post.device!r} is not the device under test "
            "and not a helper of the [helpers] table"
        )
    if code != post.expect_rc:
        return False, f"it returned {code}, expected {post.expect_rc}"
    if post.expect_stdout is not None and post.expect_stdout not in text:
        return False, "its output does not carry the expected text"
    if post.expect_not_stdout is not None and post.expect_not_stdout in text:
        return False, "its output carries text it must not carry"
    return True, ""


def run_shape(ctx: VendorContext, shape: Shape, *,
              reset: bool = True) -> ShapeResult:
    """Run one shape against the device and compare the outcome."""
    started = time.monotonic()
    if reset:
        ok, detail = _prepare(ctx)
        if not ok:
            return ShapeResult(
                id=shape.id,
                expected=shape.expect,
                got="reset_failed",
                passed=False,
                seconds=time.monotonic() - started,
                detail=detail,
                fatal=True,
            )

    ctx.counter[0] = 0
    detail = ""
    got = "not_run"
    planned = None
    posts_ok = True

    with use_runner(ctx):
        try:
            planned = ctx.service.plan(
                ctx.device_name,
                "\n".join(shape.lines),
                shape.timeout_s,
                explanation=shape.explanation,
                owner_confirmed_in_chat=True,
            )
        except server.NewtonError as exc:
            got = "refused_at_plan"
            detail = str(exc)
        else:
            session_id = planned["session_id"]
            if shape.approval:
                approved, approval_detail = write_approval(ctx, session_id)
                if not approved:
                    got = "approval_failed"
                    detail = approval_detail
            if got != "approval_failed":
                try:
                    applied = ctx.service.apply(ctx.device_name, session_id)
                except (server.NewtonError, VendorRefusal) as exc:
                    got = "refused_at_apply"
                    detail = str(exc)
                else:
                    got = applied.get("result", "unknown")
                    if os.environ.get("NEWTON_VENDOR_LAB_DEBUG"):
                        print(f"debug {shape.id}: {applied!r}", file=sys.stderr)
                    detail = _log_text(applied.get("log"))
                    if got == "unknown":
                        budget = (
                            ctx.wait_budget_s
                            if ctx.wait_budget_s is not None
                            else shape.timeout_s + RETURN_GRACE_S
                        )
                        back, note = _at_baseline(
                            ctx, planned["base_hash"], budget
                        )
                        if back:
                            got = "rolled_back"
                            detail = (
                                f"{detail}; the device is back at the baseline "
                                f"configuration"
                            )
                        else:
                            detail = f"{detail}; {note}"
                    status = ctx.service.status(ctx.device_name, session_id)
                    detail = (
                        f"{detail}; the device status exit code is "
                        f"{status.get('exit_code')}"
                    )

        if planned is not None:
            for post in shape.posts:
                ok, note = _run_post(ctx, post)
                if not ok:
                    posts_ok = False
                    detail = f"{detail}; the post failed: {note}"

    sessions_ok = shape.sessions is None or ctx.counter[0] == shape.sessions
    if not sessions_ok:
        detail = (
            f"{detail}; the shape opened {ctx.counter[0]} ssh sessions, "
            f"expected {shape.sessions}"
        )
    passed = got == shape.expect and posts_ok and sessions_ok
    return ShapeResult(
        id=shape.id,
        expected=shape.expect,
        got=got,
        passed=passed,
        seconds=time.monotonic() - started,
        detail=detail,
    )


# ---------- the command line ----------

def _print_line(result: ShapeResult) -> None:
    print(
        f"{result.id}  expected={result.expected}  got={result.got}  "
        f"{'PASS' if result.passed else 'FAIL'}  {result.seconds:.1f}s"
    )
    if not result.passed and result.detail:
        print(f"newton-vendor-lab: {result.id}: {result.detail}", file=sys.stderr)


def main(argv: list[str] | None = None, *,
         factory: Callable[[Any], Any] | None = None) -> int:
    args = _parse_args(argv)
    shapes_path = Path(args.shapes)
    try:
        lab = nl.load_lab(Path(args.lab))
        device = _vendor_device(lab, args.vendor)
        # The shapes are loaded with the device under test, so a post may
        # name it: the listing and the run see the same file.
        shapes = load_shapes(shapes_path, args.vendor, device=device.name)
        if args.shape is not None and args.shape not in shapes:
            print(
                f"newton-vendor-lab: no shape {args.shape!r}; the file has "
                f"{', '.join(sorted(shapes))}",
                file=sys.stderr,
            )
            return 2
        if args.no_reset and args.shape is None:
            # The baseline gate runs before the first shape and cannot tell
            # the second shape from a device the first one changed.
            print(
                "newton-vendor-lab: --no-reset needs exactly one --shape: the "
                "baseline gate cannot protect a second shape",
                file=sys.stderr,
            )
            return 2
    except (ShapeError, DriverError, nl.LabConfigError) as exc:
        print(f"newton-vendor-lab: {exc}", file=sys.stderr)
        return 2
    except server.NewtonError as exc:
        print(f"newton-vendor-lab: {exc}", file=sys.stderr)
        return 2

    if args.list:
        for shape in shapes.values():
            print(f"{shape.id}  {shape.expect}  {shape.description}")
        return 0

    try:
        context = build_context(
            lab,
            shapes_path,
            args.vendor,
            factory=factory,
            state_dir=Path(args.state) if args.state else None,
            # the fast reset is a field of the device table of the lab
            # file: a device that asks for it may skip the rollback when
            # it is already at the baseline.
            fast_reset=_fast_reset_flag(Path(args.lab), device.name),
        )
    except (ShapeError, DriverError, nl.LabConfigError) as exc:
        print(f"newton-vendor-lab: {exc}", file=sys.stderr)
        return 2
    except server.NewtonError as exc:
        print(f"newton-vendor-lab: {exc}", file=sys.stderr)
        return 2

    if args.state:
        print(
            f"newton-vendor-lab: the state directory {args.state} is kept; "
            "its plan and approval records stay there",
            file=sys.stderr,
        )

    selected = (
        [shapes[args.shape]] if args.shape is not None
        else [shapes[name] for name in sorted(shapes)]
    )
    results: list[ShapeResult] = []
    try:
        if args.no_reset:
            # Without the reset the driver cannot put the device back at
            # the snapshot, so it reads the configuration hash itself and
            # stops the run when the device is not at the baseline.
            ok, detail = _at_recorded_baseline(context)
            if not ok:
                print(f"newton-vendor-lab: {detail}", file=sys.stderr)
                return 2
        for shape in selected:
            result = run_shape(context, shape, reset=not args.no_reset)
            _print_line(result)
            results.append(result)
            if result.fatal:
                return 2
    finally:
        context.close()
    return 0 if all(result.passed for result in results) else 1


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the vendor write shapes against the lab."
    )
    parser.add_argument("--vendor", default="vyos",
                        help="the vendor whose lines table is used")
    parser.add_argument("--shape", default=None,
                        help="run only this shape")
    parser.add_argument("--no-reset", action="store_true",
                        help="do not roll the VM back before the shape")
    parser.add_argument("--list", action="store_true",
                        help="list the shapes and stop")
    parser.add_argument("--lab", default=str(DEFAULT_LAB),
                        help="the lab file with the devices")
    parser.add_argument("--shapes", default=str(DEFAULT_SHAPES),
                        help="the shapes file")
    parser.add_argument("--state", default=None,
                        help="the state directory (a temporary one by default)")
    return parser.parse_args(argv)


if __name__ == "__main__":
    sys.exit(main())
