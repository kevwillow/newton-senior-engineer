"""The owner's local build config (PLAN-1.5 task 8; DESIGN-1.5, open point
6 of task 7): where each server's helper login is, and the targets of the
checkpoint adapters.

The file is ``ad-build.toml`` in Newton's config directory (beside the
inventory, ``~/.config/newton``; ``NEWTON_AD_BUILD_CONFIG`` names another
path).  It holds no secret: the ssh keys, the pinned host keys, the
Proxmox token secret and its CA are files it names, and the token secret
is read from its file at each request.  Its schema is exact: an unknown
key, a value of the wrong type, a relative path or a file another user may
write is refused, so a secret cannot be written into it by mistake.

Example::

    version = 1

    [servers.build1]
    host = "192.0.2.11"
    port = 22
    key_file = "/home/owner/.ssh/newton-build"
    known_hosts = "/home/owner/.config/newton/ad-build.known_hosts"

    [servers.build1.proxmox]
    api = "https://pve.example.test:8006/api2/json"
    node = "pve"
    vmid = "8301"
    token_id = "newton@pve!build"
    token_file = "/home/owner/.config/newton/pve-build.token"
    ca_file = "/home/owner/.config/newton/pve-ca.pem"

    # the read-only newton-audit login of DC1 (the 1.3 collector) that stage
    # 10 reads through; without it stage 10 stops acceptance_unavailable
    [audit]
    host = "192.0.2.11"
    port = 22
    key_file = "/home/owner/.ssh/newton-audit"
    known_hosts = "/home/owner/.config/newton/ad-build.known_hosts"

    [servers.build2.hyperv]
    host = "hvhost.example.test"
    port = 22
    user = "hv-checkpoint"
    key_file = "/home/owner/.ssh/hv-checkpoint"
    known_hosts = "/home/owner/.config/newton/hv.known_hosts"
    vm = "BUILD2"
"""

from __future__ import annotations

import os
import re
import stat
import subprocess
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ...adapters.ssh_cli import HOST_RE
from . import acceptance as _acceptance
from . import checkpoint as _checkpoint
from .transport import HelperDcReads, HelperTarget, HelperTransport, SshHelperTransport

#: The version of the schema.
CONFIG_VERSION = 1

#: The default path: beside the inventory.
DEFAULT_PATH = "~/.config/newton/ad-build.toml"

_DEVICE_RE = re.compile(r"[a-z][a-z0-9-]{0,31}")
_HV_USER_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}")

_SERVER_KEYS = frozenset({"host", "port", "key_file", "known_hosts", "proxmox", "hyperv"})
_SERVER_REQUIRED = ("host", "port", "key_file", "known_hosts")
_PROXMOX_KEYS = frozenset({"api", "node", "vmid", "token_id", "token_file", "ca_file"})
_HYPERV_KEYS = frozenset({"host", "port", "user", "key_file", "known_hosts", "vm"})
_AUDIT_KEYS = frozenset({"host", "port", "key_file", "known_hosts"})

#: The timeout of one call of the Hyper-V host's forced command.
HYPERV_TIMEOUT_S = 300


class BuildConfigError(Exception):
    """The build config is missing or does not fit its schema.  The message
    names the key, never a value."""


@dataclass(frozen=True)
class BuildConfig:
    """The checked config."""

    helpers: dict[str, HelperTarget]
    proxmox: dict[str, _checkpoint.ProxmoxTarget]
    hyperv: dict[str, tuple[_checkpoint.HyperVTarget, Path, Path]]
    audit: _acceptance.AuditTarget | None = None


def config_path() -> Path:
    """The path of the build config."""
    return Path(os.environ.get("NEWTON_AD_BUILD_CONFIG", DEFAULT_PATH)).expanduser()


def _exact(table: Any, keys: frozenset[str], required: tuple[str, ...], where: str) -> Mapping[str, Any]:
    if not isinstance(table, dict):
        raise BuildConfigError(f"{where} is not a table")
    for key in table:
        if key not in keys:
            raise BuildConfigError(f"{where} holds a key the schema does not have")
    for key in required:
        if key not in table:
            raise BuildConfigError(f"{where} holds no {key}")
    return table


def _text(value: Any, pattern: re.Pattern[str], where: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise BuildConfigError(f"{where} is outside its grammar")
    return value


def _port(value: Any, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise BuildConfigError(f"{where} is not a port")
    return value


def _path(value: Any, where: str) -> Path:
    if not isinstance(value, str) or not value or "\0" in value or "\n" in value:
        raise BuildConfigError(f"{where} is not a path")
    path = Path(value)
    if not path.is_absolute():
        raise BuildConfigError(f"{where} is not an absolute path")
    return path


def _check_file_mode(path: Path) -> None:
    """The config is the owner's: a regular file no other user may write."""
    try:
        info = path.lstat()
    except OSError:
        raise BuildConfigError("there is no build config") from None
    if not stat.S_ISREG(info.st_mode):
        raise BuildConfigError("the build config is not a regular file")
    if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise BuildConfigError("the build config may be written by another user")
    if hasattr(os, "getuid") and info.st_uid != os.getuid():
        raise BuildConfigError("the build config is not the owner's")


def parse_config(raw: Mapping[str, Any]) -> BuildConfig:
    """The checked config of a parsed TOML document."""
    _exact(raw, frozenset({"version", "servers", "audit"}), ("version", "servers"), "the build config")
    if raw["version"] != CONFIG_VERSION or isinstance(raw["version"], bool):
        raise BuildConfigError("the build config is not of version 1")
    servers = raw["servers"]
    if not isinstance(servers, dict) or not servers:
        raise BuildConfigError("the build config names no server")
    helpers: dict[str, HelperTarget] = {}
    proxmox: dict[str, _checkpoint.ProxmoxTarget] = {}
    hyperv: dict[str, tuple[_checkpoint.HyperVTarget, Path, Path]] = {}
    for device, table in servers.items():
        _text(device, _DEVICE_RE, "a server name")
        where = f"server {device}"
        table = _exact(table, _SERVER_KEYS, _SERVER_REQUIRED, where)
        helpers[device] = HelperTarget(
            name=device,
            host=_text(table["host"], HOST_RE, f"{where} host"),
            port=_port(table["port"], f"{where} port"),
            key_file=_path(table["key_file"], f"{where} key_file"),
            known_hosts=_path(table["known_hosts"], f"{where} known_hosts"),
        )
        if "proxmox" in table and "hyperv" in table:
            raise BuildConfigError(f"{where} names two hypervisors")
        if "proxmox" in table:
            pve = _exact(table["proxmox"], _PROXMOX_KEYS, tuple(sorted(_PROXMOX_KEYS)), f"{where} proxmox")
            for key in ("api", "node", "vmid", "token_id"):
                if not isinstance(pve[key], str):
                    raise BuildConfigError(f"{where} proxmox {key} is not text")
            try:
                proxmox[device] = _checkpoint.ProxmoxTarget(
                    api=pve["api"],
                    node=pve["node"],
                    vmid=pve["vmid"],
                    token_id=pve["token_id"],
                    token_file=_path(pve["token_file"], f"{where} proxmox token_file"),
                    ca_file=_path(pve["ca_file"], f"{where} proxmox ca_file"),
                )
            except ValueError:
                raise BuildConfigError(f"{where} proxmox is outside its grammar") from None
        if "hyperv" in table:
            hv = _exact(table["hyperv"], _HYPERV_KEYS, tuple(sorted(_HYPERV_KEYS)), f"{where} hyperv")
            host = _text(hv["host"], HOST_RE, f"{where} hyperv host")
            user = _text(hv["user"], _HV_USER_RE, f"{where} hyperv user")
            port = _port(hv["port"], f"{where} hyperv port")
            key_file = _path(hv["key_file"], f"{where} hyperv key_file")
            known_hosts = _path(hv["known_hosts"], f"{where} hyperv known_hosts")
            argv = (
                "ssh", "-F", "/dev/null", "-T",
                "-o", "BatchMode=yes",
                "-o", "StrictHostKeyChecking=yes",
                "-o", f"UserKnownHostsFile={known_hosts}",
                "-o", "UpdateHostKeys=no",
                "-o", "ForwardAgent=no",
                "-o", "ForwardX11=no",
                "-o", "ClearAllForwardings=yes",
                "-o", "RequestTTY=no",
                "-o", "ControlMaster=no",
                "-o", "ControlPath=none",
                "-o", "ConnectTimeout=8",
                "-o", "LogLevel=ERROR",
                "-p", str(port),
                "-i", str(key_file), "-o", "IdentitiesOnly=yes",
                f"{user}@{host}",
            )
            if not isinstance(hv["vm"], str):
                raise BuildConfigError(f"{where} hyperv vm is not text")
            try:
                hyperv[device] = (_checkpoint.HyperVTarget(ssh=argv, vm=hv["vm"]), key_file, known_hosts)
            except ValueError:
                raise BuildConfigError(f"{where} hyperv is outside its grammar") from None
    audit: _acceptance.AuditTarget | None = None
    if "audit" in raw:
        # The user is not a key: it is the 1.3 collector's account of the
        # plan's domain (``acceptance.AuditTarget.with_domain``).
        table = _exact(raw["audit"], _AUDIT_KEYS, tuple(sorted(_AUDIT_KEYS)), "the audit login")
        audit = _acceptance.AuditTarget(
            host=_text(table["host"], HOST_RE, "the audit login host"),
            port=_port(table["port"], "the audit login port"),
            key_file=_path(table["key_file"], "the audit login key_file"),
            known_hosts=_path(table["known_hosts"], "the audit login known_hosts"),
        )
    return BuildConfig(helpers=helpers, proxmox=proxmox, hyperv=hyperv, audit=audit)


def load_config(path: Path | None = None) -> BuildConfig:
    """Read and check the owner's build config."""
    path = config_path() if path is None else path
    _check_file_mode(path)
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
        raise BuildConfigError("the build config is not TOML") from None
    return parse_config(raw)


def _run_argv(argv: list[str]) -> tuple[int, str]:
    """One call of the Hyper-V host's forced command (argv list, no shell)."""
    env = os.environ.copy()
    env.pop("SSH_AUTH_SOCK", None)
    try:
        done = subprocess.run(
            argv, capture_output=True, text=True, timeout=HYPERV_TIMEOUT_S, env=env, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return 255, ""
    return done.returncode, done.stdout


def _dc_read_not_built(server_cfg: Mapping[str, Any]) -> Any:
    """The reads of a DC without the helper transport: a DC checkpoint
    does not verify through adapters built without one."""
    raise _checkpoint.CheckpointUnverified("the DC read has no helper transport")


def _wbadmin_take_not_built(server_cfg: Mapping[str, Any], backup: str) -> str:
    raise _checkpoint.CheckpointUnverified("the wbadmin backup through the helper is not built")


def build_adapters(config: BuildConfig, *, transport: HelperTransport | None = None) -> _checkpoint.CheckpointAdapters:
    """The checkpoint adapters of the config's targets.

    With the helper transport, the DC reads (``msDS-GenerationId``,
    ``repadmin /showbackup``, ``wbadmin get versions``) go through each
    server's helper (``transport.HelperDcReads``; PLAN-1.5 task 8 part
    B0), once the caller opens the server's read context; without it they
    fail closed.  The wbadmin backup itself is not built either way: the
    plan holds no backup target volume (DESIGN-1.5, open point 2 of task
    7).
    """
    reads = HelperDcReads(transport) if transport is not None else None
    read_genid: Any = reads.read_genid if reads is not None else _dc_read_not_built
    read_showbackup: Any = reads.read_showbackup if reads is not None else _dc_read_not_built
    read_versions: Any = reads.read_versions if reads is not None else _dc_read_not_built
    by_method: dict[str, Any] = {
        "proxmox": _checkpoint.ProxmoxAdapter(dict(config.proxmox), read_genid=read_genid),
        "hyperv": _checkpoint.HyperVAdapter(
            {device: target for device, (target, _k, _h) in config.hyperv.items()},
            run=_run_argv,
            read_genid=read_genid,
            read_showbackup=read_showbackup,
        ),
        "wbadmin": _checkpoint.WbadminAdapter(
            read_versions=read_versions,
            read_genid=read_genid,
            take=_wbadmin_take_not_built,
        ),
    }
    return _checkpoint.CheckpointAdapters(by_method, reads=reads)


def build_acceptance(config: BuildConfig) -> Any:
    """Stage 10's acceptance through the config's newton-audit login (the maintainer's
    decision R2), or None when the config names none."""
    if config.audit is None:
        return None
    return _acceptance.audit_acceptance(config.audit)


def build_transport(config: BuildConfig) -> SshHelperTransport:
    """The helper transport of the config's logins."""
    return SshHelperTransport(dict(config.helpers))
