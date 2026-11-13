"""MCP tools for the OpenWrt change protocol.

The module deliberately exposes only a small, validated read surface and the
tested plan/apply protocol.  All subprocess failures become tool results.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import hmac
import os
import re
import shlex
import stat
import subprocess
import tempfile
import threading
import time
import traceback
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, Mapping

from mcp.server.fastmcp import Context, FastMCP

from . import change_receipt as _change_receipt
from . import client_checks as _client_checks
from . import approval_gate as _gate
from . import change_classes as _change_classes
from . import consequences as _consequences
from . import credential_file as _credential_file
from . import elicit_approval
from . import envelope as _envelope
from . import explanation as _explanation
from . import grants as _grants
from . import inventory_file as _inventory_file
from . import probes as _probes
from . import redact as _redact
from . import scans as _scans
from . import ssh_path as _ssh_path
from . import tiers as _tiers
from . import touched as _touched
from . import undo_plan as _undo_plan
from . import wifiscan as _wifiscan
from . import vendor_flow
from .ad import tools as _ad_tools
from .ad.setupgen import DOMAIN_RE as AD_DNS_DOMAIN_RE
from .ad.write import apply as _ad_apply
from .ad.write import plan as _ad_write
from .ad.write import render as _ad_render
from .ad.write.errors import WriteError as _AdWriteError
from .adapters import registry
from .adapters import getters as _getters
from .adapters import platform_redact as _platform_redact
from .adapters.openwrt_rpcd import is_valid_pin as _is_valid_pin
from . import receipts as _receipts
from .adapters.ssh_cli import (
    HOST_RE,
    MISMATCH_CAVEAT,
    PROXY_COMMAND_RE,
    RunnerRefused,
    SshCliRunner,
    USER_RE,
    shape_of,
    user_grammar,
)
from .plan import compute_plan_hash
from .policy import classify, parse_section_fact_line
from .probes import validate_probes, write_probe_file


TOOL_NAMES = {
    "newton_list_devices",
    "newton_read",
    "newton_backup",
    "newton_plan_change",
    "newton_plan_undo",
    "newton_apply_change",
    "newton_change_status",
    "newton_abort_change",
    "newton_grant_off",
    "newton_list_tiers",
    "newton_plan_tier",
    "newton_guided_recommend",
    "newton_guided_audit",
    "newton_plan_scan",
    "newton_run_scan",
    "newton_get_state",
    "newton_list_getters",
    "newton_ad_audit",
    "newton_ad_list_checks",
    "newton_ad_plan_change",
    "newton_ad_apply_change",
    "newton_ad_change_status",
    "newton_ad_abort_change",
}

# The tools that answer for a no-install device (ADR-021 point 1).  The read
# asks the router's own web API, so it needs nothing installed.
# the plan goes there too (it decides between an auto plan and an
# owner script), and the apply, the status and the abort answer for a
# plan of that device.  The listing of the devices answers too.  Every
# other tool is refused at the choke point.
#
# This is the ONE set: the refusal at the choke point and the tool list
# a no-install device advertises are both taken from it, so the listing
# can never promise a tool the refusal would stop.
NO_INSTALL_TOOLS = frozenset(
    {
        "newton_list_devices",
        "newton_read",
        "newton_plan_change",
        "newton_apply_change",
        "newton_change_status",
        "newton_abort_change",
    }
)

# The way back for a no-install device, in plain words: OpenWrt's own
# undo timer (the rpcd one), not Newton's guard.  It lives in the
# router's RAM, so a reboot inside the window keeps the change.
NO_INSTALL_REVERT = "openwrt-rpcd-timer"

EXPERIMENTAL_CAVEAT = (
    "Experimental read, not verified on this device; treat as a hint."
)
SSH_BINARY: str | None = None  # tests monkeypatch it with a fake ssh path; None means resolve from the fixed list
_RUNNERS: dict[str, SshCliRunner] = {}
_RUNNERS_LOCK = threading.Lock()
_SEEN_IFACES: dict[tuple[str, str], frozenset[str]] = {}
_SEEN_IFACES_LOCK = threading.Lock()
# OS version last read from each device's `version` getter in this
# process, keyed (state dir, device name, host, platform) and valid for
# LEARNED_VERSION_TTL seconds. It costs no device call: receipts use it only
# when the owner's own `version` read already ran. Memory only.
_LEARNED_VERSIONS: dict[tuple[str, str, str, str], tuple[str, float]] = {}
LEARNED_VERSION_TTL = 15 * 60.0
_LEARNED_VERSIONS_LOCK = threading.Lock()
RECEIPT_NOTE = "field receipt not recorded"
FIELD_EVIDENCE_NOTE = (
    "Counts of past results by OS version, from local use of this Newton. "
    "Field evidence only, not verification; a getter is verified only by a "
    "recorded lab or an owner-approved capture."
)


def _learned_now() -> float:
    return time.monotonic()


def getter_path(platform: str) -> Path | None:
    """Return a getter-file override for tests; None loads the packaged adapters/<platform>/getters.toml."""
    return None


def _ssh_runner() -> SshCliRunner:
    """Return the one process-global runner for this state directory."""
    key = str(state_dir())
    with _RUNNERS_LOCK:
        runner = _RUNNERS.get(key)
        if runner is None:
            runner = SshCliRunner(state_dir(), ssh=SSH_BINARY)
            _RUNNERS[key] = runner
        return runner

SESSION_RE = re.compile(r"^[0-9a-f]{32}$")
_CONFIGHASH_RE = re.compile(
    r"^CONFIGHASH ([0-9a-f]{32}) ([A-Za-z0-9_-]{1,64})$"
)
NAME_RE = re.compile(r"^[A-Za-z0-9_.@-]+$")
IFACE_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
TARGET_RE = re.compile(r"^[A-Za-z0-9_.:-]+$")
CONFIG_RE = re.compile(r"^[a-z0-9_-]+$")
FORBIDDEN_READ = set(";&|`$<>(){}\\\n\r")

# The remote router program (design 3.8/7.2): every read the MCP sends is
# `/usr/libexec/newton/newton-router read <tokens>`.
PROG = "/usr/libexec/newton/newton-router"
# triage #3/#26: the only device names that may be looked up or logged.
DEVICE_NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
# The objectGUID of the domain head, as the inventory of a write entry
# holds it (SPEC-1.4, the maq plan).
AD_GUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
# A token the router's request filter (design 3.2) accepts unquoted.
READ_TOKEN_RE = re.compile(r"^[A-Za-z0-9._:/@+[\]-]+$")
# setup's inventory rules (scripts/newton-router-setup load_inventory).
INVENTORY_PATH_RE = re.compile(r"[A-Za-z0-9_./-]+")
INVENTORY_ZONE_RE = re.compile(r"[A-Za-z0-9_-]{1,32}")
IP_OPTIONS = {"-4", "-6", "-s", "-d"}
IP_OBJECTS = {"addr", "address", "route", "link", "neigh", "rule"}
IP_ACTIONS = {"show", "list"}
IP_DEV_OBJECTS = {"addr", "address", "route", "link", "neigh"}
IP_TABLE_OBJECTS = {"route", "rule"}
IP_READ_ERROR = ("read command is not allowed: ip (use full words: ip [-4|-6] [-s] [-d] "
                 "addr|route|link|neigh|rule [show|list] [dev X] [table T], or ip route get X)")
UBUS_CALLS = {
    ("system", "board"), ("system", "info"),
    ("network.interface", "dump"), ("network.device", "status"),
    ("network.wireless", "status"),
}
KNOWN_UCI_CONFIGS = frozenset({
    "network", "wireless", "dhcp", "firewall", "system", "dropbear",
    "uhttpd", "rpcd", "ubootenv", "ucitrack", "luci", "fstab", "qos",
    "sqm", "ddns", "acme", "adblock", "banip", "mwan3", "openvpn",
    "upnpd", "samba4", "nlbwmon", "statistics", "vnstat2",
    "https-dns-proxy", "travelmate", "unbound", "snmpd", "mosquitto",
    "tor", "dockerd", "attendedsysupgrade", "watchcat", "usteer",
    "newton_wanhealth",
})


class NewtonError(Exception):
    """A client-safe operational or validation error."""


class DeviceTextError(NewtonError):
    """A NewtonError whose message embeds router output.

    Raised by ``backup()`` and ``plan()`` only when the underlying subprocess
    produced text we could not parse — the message comes from the device and
    must reach the model inside an ``untrusted-device-data`` envelope.  Plain
    NewtonErrors stay bare strings because they are server-side messages
    (validation, "unknown device", "timeout_s must be an integer...").
    """


# SW2 (design Item 2): a record without the integer window fields the v2
# token binds, or with fields that disagree with its own created_at /
# expires_at, is an old newton-approve record or an edited one.  One
# message for both, raised before the expiry test so the operator is told
# to approve again rather than that the approval expired.
OLD_APPROVAL_MSG = "approval was made by an older newton-approve or edited; approve the plan again"


@dataclass(frozen=True)
class ApprovalGrant:
    """What consume_approval hands back: the token and the window it was
    minted over (UNIX seconds), both passed to the wrapper for ``apply``."""

    token: str
    not_before: int
    not_after: int


@dataclass(frozen=True)
class Device:
    name: str
    platform: str
    host: str
    user: str
    auth: str = "key"
    port: int = 22
    password_file: Path | None = None
    proxy_command: str | None = None          # e.g. "ssh -i ~/.ssh/key -o BatchMode=yes -W %h:%p root@jump"
    profile: str = "prod"                     # "lab" | "prod"; missing in the inventory means "prod" (fail safe)
    mgmt_interface: str = "lan"               # leash: changes to network.<mgmt_interface> are CRITICAL
    mgmt_zone: str = "lan"                    # leash: changes to the firewall zone named <mgmt_zone> are CRITICAL
    key_file: Path | None = None              # key-mode ssh identity (0600, owned by the server user)
    known_hosts: Path | None = None           # key-mode ssh known-hosts file (syntax-checked only)
    wan_zones: tuple[str, ...] = ("wan",)     # the device's WAN zones (policy/leash facts)
    experimental_readonly: bool = False
    vendor_write: bool = False                # a non-OpenWrt device may write
    lab: bool = False
    # An AD write entry (SPEC-1.4) names its domain with ``ad_domain``:
    # the device that stands for the domain.  ``ad_domain_guid`` is the
    # objectGUID of the domain head, which the maq plan needs, and
    # ``ad_dns_domain`` is the DNS name of the domain, which the setup
    # prints in the entry.
    ad_domain: str | None = None
    ad_domain_guid: str | None = None
    ad_dns_domain: str | None = None
    # (ADR-021 point 1) the access mode of an OpenWrt device.
    # "installed" is today's mode (Newton's program on the router) and
    # the default, so an inventory without the field keeps working
    # unchanged.  "no-install" is the router's own web API; Newton
    # cannot manage such a device yet in this version, so every tool
    # refuses it at the one choke point (NewtonService.device).
    access: str = "installed"
    rpcd_password_file: Path | None = None    # no-install: the rpcd user's password file
    https_spki: str | None = None             # no-install: the pinned SPKI (base64 sha256)
    https_host: str | None = None             # no-install: the host of the web API (default: host)
    https_port: int = 443                     # no-install: the HTTPS port of the web API
    # (ADR-021 point 1) the answer of the installed-mode offer.  It
    # is set only on a no-install device and holds one value, "declined"
    # (the owner said no).  None means the owner was never asked.
    installed_offer: str | None = None

    @property
    def destination(self) -> str:
        return f"{self.user}@{self.host}"


def state_dir() -> Path:
    return Path(os.environ.get("NEWTON_STATE_DIR", "~/.local/state/newton")).expanduser()


ONELINE_LIMIT = 240


def oneline(value: str, limit: int = ONELINE_LIMIT) -> str:
    """Make any text safe as one audit/log field (triage #3/#26).

    Every control character (C0, DEL, U+0085, U+2028, U+2029) becomes a
    space, so caller or device text can never start a new log line, and
    the field is capped at `limit` characters.
    """
    if not isinstance(value, str):
        value = str(value)
    cleaned = "".join(
        " " if (ord(ch) < 0x20 or ord(ch) == 0x7F or ch in "\u0085\u2028\u2029") else ch
        for ch in value
    )
    return cleaned[:limit]


def write_audit(tool: str, device: str, result: str) -> None:
    """Best-effort audit that also works when inventory loading fails.

    The state directory (when this code creates it) and the audit log file
    are opened with mode 0o700 and 0o600 respectively so the audit log
    cannot leak across users on a shared host.
    """
    try:
        root = state_dir()
        if _receipts.check_state_write_path(root, root) is not None:
            return
        created = not root.exists()
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if created:
            os.chmod(root, 0o700)
        line = (
            f"{datetime.now(timezone.utc).isoformat()} "
            f"tool={oneline(tool)} device={oneline(device)} result={oneline(result)}\n"
        )
        fd = os.open(
            str(root / "mcp-audit.log"),
            os.O_WRONLY | os.O_APPEND | os.O_CREAT,
            0o600,
        )
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            f.write(line)
    except OSError:
        pass


def _log_unexpected_error(tool: str, device: str) -> None:
    """Best-effort on-disk traceback for the generic ``except Exception`` branch.

    The model still sees only ``{"error": "internal server error"}``; this
    helper exists so an operator can recover the real cause from a hidden
    crash (e.g. a missing manifest).  Any failure here must be silent:
    call_tool returns the standard error regardless.
    """
    try:
        root = state_dir()
        if _receipts.check_state_write_path(root, root) is not None:
            return
        created = not root.exists()
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if created:
            os.chmod(root, 0o700)
        entry = (
            f"{datetime.now(timezone.utc).isoformat()} "
            f"tool={oneline(tool)} device={oneline(device)}\n"
            f"{_redact.redact_text(traceback.format_exc())}\n\n"
        )
        fd = os.open(
            str(root / "mcp-errors.log"),
            os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW,
            0o600,
        )
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            f.write(entry)
    except Exception:
        pass


def script_path() -> Path:
    root = os.environ.get("NEWTON_HOME")
    path = Path(root).expanduser() / "scripts/owrt-change.sh" if root else Path(__file__).resolve().parents[2] / "scripts/owrt-change.sh"
    if not path.is_file():
        raise NewtonError(f"OpenWrt change script not found: {path}")
    return path


def load_inventory() -> dict[str, Device]:
    path = Path(os.environ.get("NEWTON_INVENTORY", "~/.config/newton/devices.toml")).expanduser()
    try:
        path.lstat()
    except OSError:
        raise NewtonError(f"inventory file not found: {path}")
    message = _inventory_file.check(path)
    if message is not None:
        raise NewtonError(message)
    try:
        import tomllib
        data = tomllib.loads(path.read_text())
        entries = data.get("devices", {})
        if not isinstance(entries, dict):
            raise ValueError("[devices] must be a table")
    except (OSError, ValueError, tomllib.TOMLDecodeError) as exc:
        raise NewtonError(f"invalid inventory: {exc}") from exc
    devices: dict[str, Device] = {}
    for name, raw in entries.items():
        if not isinstance(name, str) or not DEVICE_NAME_RE.fullmatch(name):
            raise NewtonError(f"invalid device name in inventory: {oneline(str(name))}")
        if not isinstance(raw, dict):
            raise NewtonError(f"invalid device entry: {oneline(name)}")
        platform = raw.get("platform")
        if not isinstance(platform, str) or platform not in registry.PLATFORMS:
            raise NewtonError(
                f"device {name}: unsupported platform {oneline(str(platform))!r}; "
                f"supported: {', '.join(sorted(registry.PLATFORMS))}"
            )
        host, user = raw.get("host"), raw.get("user")
        if not isinstance(host, str) or not host or not isinstance(user, str) or not user:
            raise NewtonError(f"device {name}: host and user are required")
        # INJ-1: the host and the user are pasted into the ssh argv as
        # ``<user>@<host>``, so they must match the same grammar the getter
        # lane uses; a user of ``-oProxyCommand=...`` would otherwise make
        # ssh read the destination as an option.
        if HOST_RE.fullmatch(host) is None:
            raise NewtonError(f"device {name}: host fails the hostname grammar")
        if user_grammar(platform).fullmatch(user) is None:
            raise NewtonError(f"device {name}: user fails the username grammar")
        auth = raw.get("auth", "key")
        if auth not in {"key", "password"}:
            raise NewtonError(f"device {name}: auth must be 'key' or 'password'")
        port = raw.get("port", 22)
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise NewtonError(f"device {name}: port must be 1..65535")
        password_file: Path | None = None
        if auth == "password":
            password = raw.get("password_file")
            if not isinstance(password, str) or not password:
                raise NewtonError(f"device {name}: password_file is required for password auth")
            password_file = Path(password).expanduser()
            # the password file is a credential.  The rule is the
            # key_file rule: lstat (a symlink is not followed), a regular
            # file, mode 0600 and owned by the user running the MCP server.
            problem = _credential_file.check(password_file)
            if problem is not None:
                raise NewtonError(f"device {name}: {problem}")
        proxy = raw.get("proxy_command")
        if proxy is not None:
            if not isinstance(proxy, str) or "%h" not in proxy or "\n" in proxy:
                raise NewtonError(f"device {name}: proxy_command must be a single-line string containing %h")
            if PROXY_COMMAND_RE.fullmatch(proxy) is None:
                raise NewtonError(f"device {name}: proxy_command contains characters outside [A-Za-z0-9 _./:@%~=,+-]")
        profile = raw.get("profile", "prod")
        if not isinstance(profile, str) or profile not in {"lab", "prod"}:
            raise NewtonError(f"device {name}: profile must be 'lab' or 'prod'")
        mgmt_interface = raw.get("mgmt_interface", "lan")
        mgmt_zone = raw.get("mgmt_zone", "lan")
        for label, value in (("mgmt_interface", mgmt_interface), ("mgmt_zone", mgmt_zone)):
            if not isinstance(value, str) or not INVENTORY_ZONE_RE.fullmatch(value):
                raise NewtonError(f"device {name}: {label} must be 1 to 32 characters of [A-Za-z0-9_-]")
        wan_raw = raw.get("wan_zones", ["wan"])
        if not isinstance(wan_raw, list) or not 1 <= len(wan_raw) <= 4:
            raise NewtonError(f"device {name}: wan_zones must be a list of 1 to 4 zone names")
        for zone in wan_raw:
            if not isinstance(zone, str) or not INVENTORY_ZONE_RE.fullmatch(zone):
                raise NewtonError(f"device {name}: each wan zone must be 1 to 32 characters of [A-Za-z0-9_-]")
        wan_zones = tuple(wan_raw)

        def inventory_path(field: str) -> Path | None:
            """setup's rule: an optional path string of [A-Za-z0-9_./-] (or empty = absent)."""
            value = raw.get(field, "")
            if value is None or value == "":
                return None
            if not isinstance(value, str) or not INVENTORY_PATH_RE.fullmatch(value):
                raise NewtonError(f"device {name}: {field} must be a path of [A-Za-z0-9_./-] or empty")
            return Path(value)

        key_file = inventory_path("key_file")
        if key_file is not None:
            try:
                key_stat = key_file.lstat()
            except OSError:
                raise NewtonError(
                    f"device {name}: key_file must be an existing regular file (not a symlink) "
                    "owned by the server user with mode 0600"
                ) from None
            if stat.S_ISLNK(key_stat.st_mode) or not stat.S_ISREG(key_stat.st_mode):
                raise NewtonError(f"device {name}: key_file must be a regular file, not a symlink")
            if stat.S_IMODE(key_stat.st_mode) != 0o600:
                raise NewtonError(f"device {name}: key_file must have mode 0600")
            if key_stat.st_uid != os.geteuid():
                raise NewtonError(f"device {name}: key_file must be owned by the user running the MCP server")
        known_hosts = inventory_path("known_hosts")
        experimental_readonly = False
        vendor_write = False
        # an OpenWrt device may say ``lab = true``; that is one of the two
        # conditions of the approval carve-out (approval_gate).  The shared
        # inventory contract still lets OpenWrt ignore a malformed ``lab``
        # (inventory_cases.json), so anything but the boolean true reads as
        # False, which is the fail-safe side (the device then needs approval).
        lab = raw.get("lab") is True if platform == "openwrt" else False
        if platform != "openwrt":
            # A non-OpenWrt device is either read-only (experimental_readonly)
            # or a vendor write device (vendor_write).  The two flags are
            # mutually exclusive: one says the device may only be read, the
            # other says it may be changed.
            vendor_write_raw = raw.get("vendor_write", False)
            if not isinstance(vendor_write_raw, bool):
                raise NewtonError(f"device {name}: vendor_write must be true or false")
            wants_write = vendor_write_raw is True
            wants_readonly = raw.get("experimental_readonly") is True
            if wants_write and wants_readonly:
                raise NewtonError(
                    f"device {name}: vendor_write and experimental_readonly are "
                    "mutually exclusive"
                )
            if wants_write and platform not in registry.VENDOR_WRITE_PLATFORMS:
                raise NewtonError(
                    f"device {name}: vendor_write is not available yet for "
                    f"platform {platform}"
                )
            if (
                not wants_write
                and not wants_readonly
                and platform not in registry.AD_PLATFORMS
                and platform not in registry.AD_WRITE_PLATFORMS
            ):
                raise NewtonError(
                    f"device {name}: platform {platform} is experimental and "
                    "read-only; set experimental_readonly = true, or set "
                    "vendor_write = true for vendor writes (VyOS, RouterOS "
                    "and Junos only in this release)"
                )
            if known_hosts is None:
                raise NewtonError(
                    f"device {name}: known_hosts is required for platform "
                    f"{platform} and must be an existing regular file"
                )
            try:
                known_hosts_stat = known_hosts.lstat()
            except OSError:
                raise NewtonError(
                    f"device {name}: known_hosts is required for platform "
                    f"{platform} and must be an existing regular file"
                ) from None
            if stat.S_ISLNK(known_hosts_stat.st_mode) or not stat.S_ISREG(known_hosts_stat.st_mode):
                raise NewtonError(
                    f"device {name}: known_hosts is required for platform "
                    f"{platform} and must be an existing regular file"
                )
            lab = raw.get("lab", False)
            if not isinstance(lab, bool):
                raise NewtonError(f"device {name}: lab must be true or false")
            if platform == "vyos" and not lab:
                raise NewtonError(
                    f"device {name}: vyos devices are lab-only in this release; "
                    "set lab = true"
                )
            if wants_write and not lab:
                # A write on a platform whose revert is disruptive stays in
                # the lab until the operator says otherwise.
                raise NewtonError(
                    f"device {name}: {platform} devices are lab-only in this "
                    "release; set lab = true"
                )
            if wants_write:
                # A vendor write runs as a non-interactive session with the
                # inventory key: no password prompt may reach the device.
                if auth != "key":
                    raise NewtonError(
                        f"device {name}: vendor_write requires auth = 'key'"
                    )
                if key_file is None:
                    raise NewtonError(
                        f"device {name}: vendor_write requires key_file"
                    )
            experimental_readonly = (
                wants_readonly or platform in registry.AD_PLATFORMS
            )
            vendor_write = wants_write
            if platform in registry.AD_WRITE_PLATFORMS:
                # An AD write entry writes by its platform: the helper runs
                # as a forced command and the undo is armed on the DC.
                # It is never a read-only device and it never carries the
                # vendor write flag.
                if wants_write or wants_readonly:
                    raise NewtonError(
                        f"device {name}: an AD write device writes by its "
                        "platform; do not set vendor_write or "
                        "experimental_readonly"
                    )
                if auth != "key":
                    raise NewtonError(
                        f"device {name}: an AD write device requires auth = 'key'"
                    )
                if key_file is None:
                    raise NewtonError(
                        f"device {name}: an AD write device requires key_file"
                    )
        # (SPEC-1.4 section 7) the write entries name their domain.
        ad_domain: str | None = None
        ad_domain_guid: str | None = None
        ad_dns_domain: str | None = None
        if platform in registry.AD_WRITE_PLATFORMS:
            raw_domain = raw.get("ad_domain")
            if not isinstance(raw_domain, str) or not DEVICE_NAME_RE.fullmatch(raw_domain):
                raise NewtonError(
                    f"device {name}: ad_domain is required for an AD write device"
                )
            ad_domain = raw_domain
            raw_guid = raw.get("ad_domain_guid")
            if raw_guid is not None:
                if not isinstance(raw_guid, str) or AD_GUID_RE.fullmatch(raw_guid) is None:
                    raise NewtonError(
                        f"device {name}: ad_domain_guid must be a guid"
                    )
                ad_domain_guid = raw_guid
            raw_dns = raw.get("domain")
            if raw_dns is None:
                # The DNS name of the domain is what tells the entries of
                # two domains apart, and the setup prints it: an entry
                # without it is refused.
                raise NewtonError(
                    f"device {name}: domain (the DNS name of the AD domain, "
                    "which the setup prints) is required for an AD write device"
                )
            if (
                not isinstance(raw_dns, str)
                or AD_DNS_DOMAIN_RE.fullmatch(raw_dns) is None
            ):
                raise NewtonError(
                    f"device {name}: domain must be the DNS name of the "
                    "AD domain"
                )
            ad_dns_domain = raw_dns
        elif "ad_domain" in raw or "ad_domain_guid" in raw:
            raise NewtonError(
                f"device {name}: ad_domain is only for AD write devices"
            )
        # (ADR-021 point 1) the access mode.  Only an OpenWrt
        # device has one, and only a no-install device needs the rpcd
        # credentials and the pinned certificate.
        if "access" in raw and platform != "openwrt":
            raise NewtonError(
                f"device {name}: access is only for OpenWrt devices"
            )
        access = raw.get("access", "installed")
        if access not in ("installed", "no-install"):
            raise NewtonError(
                f"device {name}: access must be 'installed' or 'no-install'"
            )
        # (ADR-021 point 1) the answer of the installed-mode offer.
        # The field belongs to a no-install device and holds one value,
        # "declined".  Anything else is refused the way a bad access is
        # refused: it is the owner's own answer and nothing else may
        # stand in its place.
        installed_offer = raw.get("installed_offer")
        if installed_offer is not None:
            if not isinstance(installed_offer, str) or installed_offer != "declined":
                raise NewtonError("device %s: installed_offer must be 'declined'" % name)
            if access != "no-install":
                raise NewtonError(
                    "device %s: installed_offer is only for a no-install device" % name
                )
        rpcd_password_file: Path | None = None
        https_spki: str | None = None
        https_host: str | None = None
        https_port = 443
        if access == "no-install":
            rpcd_password = raw.get("rpcd_password_file")
            if not isinstance(rpcd_password, str) or not rpcd_password:
                raise NewtonError(
                    f"device {name}: rpcd_password_file is required for "
                    "no-install access"
                )
            rpcd_password_file = Path(rpcd_password).expanduser()
            problem = _credential_file.check(
                rpcd_password_file, what="rpcd_password_file"
            )
            if problem is not None:
                raise NewtonError(f"device {name}: {problem}")
            pin = raw.get("https_spki")
            if not _is_valid_pin(pin):
                raise NewtonError(
                    f"device {name}: https_spki is required for no-install "
                    "access and must be the base64 sha256 of the "
                    "certificate's SPKI (44 characters)"
                )
            https_spki = pin
            https_host = raw.get("https_host", host)
            if not isinstance(https_host, str) or HOST_RE.fullmatch(https_host) is None:
                raise NewtonError(f"device {name}: https_host fails the hostname grammar")
            https_port = raw.get("https_port", 443)
            if (
                isinstance(https_port, bool)
                or not isinstance(https_port, int)
                or not 1 <= https_port <= 65535
            ):
                raise NewtonError(f"device {name}: https_port must be 1..65535")
        devices[name] = Device(
            name, platform, host, user, auth, port, password_file,
            os.path.expanduser(proxy) if proxy else None,
            profile, mgmt_interface, mgmt_zone,
            key_file=key_file, known_hosts=known_hosts, wan_zones=wan_zones,
            experimental_readonly=experimental_readonly,
            vendor_write=vendor_write, lab=lab,
            ad_domain=ad_domain, ad_domain_guid=ad_domain_guid,
            ad_dns_domain=ad_dns_domain,
            access=access, rpcd_password_file=rpcd_password_file,
            https_spki=https_spki, https_host=https_host,
            https_port=https_port,
            installed_offer=installed_offer,
        )
    # (SPEC-1.4 section 7) the write entries of one domain name the
    # device that stands for it, and that device names itself.
    for name, device in devices.items():
        if device.platform not in registry.AD_WRITE_PLATFORMS:
            continue
        domain = devices.get(device.ad_domain or "")
        if domain is None or domain.platform not in registry.AD_WRITE_PLATFORMS:
            raise NewtonError(
                f"device {name}: ad_domain must name an AD write device"
            )
        if domain.ad_domain != domain.name:
            raise NewtonError(
                f"device {name}: ad_domain must name the device of the domain"
            )
        # The DNS name of the entry is the DNS name of the domain it
        # belongs to: an entry that carries the name of another domain
        # may not join this one, or a controller of that other domain
        # would answer for it.
        if (
            device.ad_dns_domain
            and domain.ad_dns_domain
            and device.ad_dns_domain.lower() != domain.ad_dns_domain.lower()
        ):
            raise NewtonError(
                f"device {name}: domain {device.ad_dns_domain} is not the "
                f"domain of {domain.name} ({domain.ad_dns_domain})"
            )
        # The guid of the entry is the guid of the head of the domain it
        # names: every DC of a domain prints the objectGUID of that
        # head, and it is the same on every DC of the domain.  An entry
        # that carries the guid of another domain would answer for a
        # domain it does not belong to.
        if (
            device.ad_domain_guid
            and domain.ad_domain_guid
            and device.ad_domain_guid != domain.ad_domain_guid
        ):
            raise NewtonError(
                f"device {name}: ad_domain_guid {device.ad_domain_guid} is "
                f"not the guid of the domain of {domain.name} "
                f"({domain.ad_domain_guid})"
            )
    # (SPEC-1.4 section 1) ``device`` names the domain and every DC of
    # the domain holds the same approval key, so one domain has ONE
    # device that stands for it.  The setup of every other DC names the
    # domain device with --domain-device; a second DC that names itself
    # is a second device standing for the same domain, and every write
    # of that domain would depend on which one answered.  The DNS name
    # of the domain is what tells the two entries apart from two honest
    # one-DC domains.  A DNS name is not case sensitive, so the name is
    # folded before it is looked up.
    standing: dict[str, list[str]] = {}
    for name, device in devices.items():
        if device.platform not in registry.AD_WRITE_PLATFORMS:
            continue
        if device.ad_domain != name or not device.ad_dns_domain:
            continue
        key = device.ad_dns_domain.lower()
        others = standing.setdefault(key, [])
        for other in others:
            # Two one-DC domains of different forests may answer to the
            # same DNS name.  Every DC of a domain prints the
            # objectGUID of the head of that domain, so two entries
            # with different guids are two domains and the inventory
            # loads; two entries with the same guid are two devices of
            # one domain, and the second one is refused.
            other_device = devices[other]
            if (
                other_device.ad_domain_guid
                and device.ad_domain_guid
                and other_device.ad_domain_guid != device.ad_domain_guid
            ):
                continue
            message = (
                f"devices {other} and {name}: two AD write devices stand "
                f"for the domain {device.ad_dns_domain}; run the setup of "
                f"{name} with --domain-device naming {other}"
            )
            if not (other_device.ad_domain_guid and device.ad_domain_guid):
                # Without the guid of the head of the domain the two
                # entries may be two honest one-DC domains of two
                # forests: the owner tells them apart with the guid
                # their setups printed.
                message += (
                    "; if they are two domains, give both entries the "
                    "ad_domain_guid their setups printed"
                )
            raise NewtonError(message)
        others.append(name)
    return devices


# ---- the read grammar (design 3.8 and 3.3, mirrored table-driven) ----
# grammar.tsv holds only the 24 subcommand rows, so the per-verb read forms
# and the argument classes live here as data and are pinned to the router
# program by the shared vectors in device/openwrt/newton-router/tests/read_cases.json.

# 3.3 argument classes (whole token), plus the small composed classes the
# 3.8 rows need (a flag bundle, a fixed word set, or CFG.SECTION[.OPTION]).
_ARG_CLASS_PATTERN = {
    "CFG": r"[a-z0-9_-]{1,32}",
    "SECTION": r"(?:[A-Za-z0-9_]{1,64}|@[A-Za-z0-9_-]{1,32}\[-?[0-9]{1,3}\])",
    "OPTION": r"[A-Za-z0-9_]{1,64}",
    "IFACE": r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}",
    "HOST": r"[A-Za-z0-9][A-Za-z0-9._:-]{0,252}",
    "OBJ": r"[a-z][a-z0-9_.-]{0,63}",
    "NFTFAM": r"(?:inet|ip|ip6|arp|bridge|netdev)",
    "NFTNAME": r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}",
    "APKNAME": r"[a-z0-9][a-z0-9_.+-]{0,63}",
    "LOGPAT": r"[A-Za-z0-9_.:][A-Za-z0-9_.:-]{0,63}",
    "LINES": r"[1-9][0-9]{0,4}",
    "COUNT": r"[1-5]",
    "TABLE": r"(?:main|local|default|all|[0-9]{1,10}|[A-Za-z0-9_.@][A-Za-z0-9_.@-]{0,63})",
    # The Wi-Fi survey verb takes the radio's name, radio0..radio99.
    "RADIO": r"radio[0-9]{1,2}",
}
ARG_CLASSES = {
    name: re.compile(pattern) for name, pattern in {
        **_ARG_CLASS_PATTERN,
        "UCIPATH": r"{CFG}\.{SECTION}(?:\.{OPTION})?".format(**_ARG_CLASS_PATTERN),
        "CFG_OR_PATH": r"(?:{CFG}\.{SECTION}(?:\.{OPTION})?|{CFG})".format(**_ARG_CLASS_PATTERN),
        "UBUSIFC": r"network\.interface\.{IFACE}".format(**_ARG_CLASS_PATTERN),
        # read_cat refuses a config name that starts with '-' (3.8 preamble)
        "CAT_CONFIG": r"/etc/config/[a-z0-9_][a-z0-9_-]{0,31}",
        "NETSTAT_OPTS": r"-[alnptuwxr]{1,8}",
        "DF_OPTS": r"-[hkPT]{1,4}",
        "FREE_OPTS": r"-(?:b|k|m|g|h)",
        "UNAME_OPTS": r"-[asnrvmpio]{1,9}",
        "APK_LIST_FLAG": r"-(?:I|u|a)",
        "APK_INFO_FLAG": r"-(?:L|d|s|R|r)",
        "IWINFO_WORD": r"(?:info|assoclist|txpowerlist|freqlist|countrylist|htmodelist)",
        "NFT_KIND": r"(?:chain|set|map|counter|quota|limit|flowtable)",
    }.items()
}

CAT_FIXED_PATHS = (
    "/etc/openwrt_release", "/tmp/dhcp.leases", "/proc/uptime",
    "/proc/loadavg", "/proc/meminfo",
)

# 3.8 read verbs: each row lists the accepted forms exactly; a form is a
# tuple of slots, a slot is a class name (in ARG_CLASSES) or a literal word.
# `ip` has the fix-read-ip grammar (options/selectors with cross-slot rules)
# and gets its own small matcher below.
READ_FORMS: dict[str, tuple[tuple[str, ...], ...]] = {
    "uci": (
        ("show",), ("show", "CFG_OR_PATH"),
        ("export",), ("export", "CFG"),
        ("changes",), ("changes", "CFG"),
        ("get", "UCIPATH"),
    ),
    "ubus": (
        ("list",), ("list", "OBJ"),
        *[("call", obj, method) for obj, method in sorted(UBUS_CALLS)],
        ("call", "UBUSIFC", "status"),
    ),
    "ifstatus": (("IFACE",),),
    "fw4": (("check",), ("print",)),
    "nft": (
        ("list", "ruleset"), ("list", "tables"),
        ("list", "table", "NFTFAM", "NFTNAME"),
        ("list", "NFT_KIND", "NFTFAM", "NFTNAME", "NFTNAME"),
    ),
    "cat": tuple((path,) for path in CAT_FIXED_PATHS) + (("CAT_CONFIG",),),
    "iwinfo": ((), ("IFACE",), ("IFACE", "IWINFO_WORD")),
    "netstat": ((), ("NETSTAT_OPTS",)),
    "df": ((), ("DF_OPTS",)),
    "free": ((), ("FREE_OPTS",)),
    "uptime": ((),),
    "uname": ((), ("UNAME_OPTS",)),
    "wifi": (("status",),),
    "logread": (
        (), ("-e", "LOGPAT"), ("-l", "LINES"),
        ("-e", "LOGPAT", "-l", "LINES"), ("-l", "LINES", "-e", "LOGPAT"),
    ),
    "apk": (
        ("list",), ("list", "APK_LIST_FLAG"), ("list", "APKNAME"),
        ("list", "APK_LIST_FLAG", "APKNAME"),
        ("info", "APKNAME"), ("info", "APK_INFO_FLAG", "APKNAME"),
        ("search", "APKNAME"),
    ),
    "ping": (("-c", "COUNT", "HOST"),),
    "traceroute": (("HOST",),),
    "nslookup": (("HOST",), ("HOST", "HOST")),
    # One Wi-Fi scan with the router's own radio.
    "wifiscan": (("RADIO",),),
}


# slots whose value is allowed to start with '-' (the 3.8 flags); every
# other argument must not start with '-' even when its class charset would
# allow it (CFG contains '-')
READ_FLAG_SLOTS = frozenset({
    "NETSTAT_OPTS", "DF_OPTS", "FREE_OPTS", "UNAME_OPTS",
    "APK_LIST_FLAG", "APK_INFO_FLAG",
})


def _form_matches(args: list[str], form: tuple[str, ...]) -> bool:
    if len(args) != len(form):
        return False
    for value, slot in zip(args, form):
        matcher = ARG_CLASSES.get(slot)
        if matcher is not None:
            if not matcher.fullmatch(value):
                return False
            if value.startswith("-") and slot not in READ_FLAG_SLOTS:
                return False
        elif value != slot:
            return False
    return True


def _validate_ip(args: list[str]) -> None:
    """The fix-read-ip grammar (design 3.8 row ip): full words only, all
    options before the OBJECT, each option and selector at most once, dev
    only for addr/address/link/neigh/route, table only for route and rule;
    or `[-4|-6] route get HOST` (no -s/-d with get)."""
    position = 0
    options: set[str] = set()
    family: str | None = None
    while position < len(args) and args[position] in IP_OPTIONS:
        option = args[position]
        if option in options or (option in {"-4", "-6"} and family is not None):
            raise NewtonError(IP_READ_ERROR)
        options.add(option)
        if option in {"-4", "-6"}:
            family = option
        position += 1
    if position >= len(args):
        raise NewtonError(IP_READ_ERROR)
    ip_object = args[position]
    position += 1
    if ip_object not in IP_OBJECTS:
        raise NewtonError(IP_READ_ERROR)
    if position < len(args) and args[position] == "get":
        rest = args[position + 1:]
        if (ip_object != "route" or options & {"-s", "-d"} or len(rest) != 1
                or not ARG_CLASSES["HOST"].fullmatch(rest[0])):
            raise NewtonError(IP_READ_ERROR)
        return
    if position < len(args) and args[position] in IP_ACTIONS:
        position += 1
    selectors: set[str] = set()
    while position < len(args):
        selector = args[position]
        if selector not in {"dev", "table"} or selector in selectors or position + 1 >= len(args):
            raise NewtonError(IP_READ_ERROR)
        value = args[position + 1]
        value_class = "IFACE" if selector == "dev" else "TABLE"
        if not ARG_CLASSES[value_class].fullmatch(value):
            raise NewtonError(IP_READ_ERROR)
        if selector == "dev" and ip_object not in IP_DEV_OBJECTS:
            raise NewtonError(IP_READ_ERROR)
        if selector == "table" and ip_object not in IP_TABLE_OBJECTS:
            raise NewtonError(IP_READ_ERROR)
        selectors.add(selector)
        position += 2


def validate_read(command: str) -> list[str]:
    if not isinstance(command, str) or not command.strip():
        raise NewtonError("command must be a non-empty string")
    if any(c in command for c in FORBIDDEN_READ):
        raise NewtonError("read command contains forbidden shell syntax")
    try:
        tokens = shlex.split(command)
    except ValueError as exc:
        raise NewtonError(f"invalid command quoting: {exc}") from exc
    if not tokens:
        raise NewtonError("command must be a non-empty string")
    cmd, args = tokens[0], tokens[1:]
    if cmd == "ip":
        _validate_ip(args)
    else:
        forms = READ_FORMS.get(cmd)
        if forms is None or not any(_form_matches(args, form) for form in forms):
            raise NewtonError(f"read command is not allowed: {tokens[0]}")
    # last line of defence: every token must be safe to send unquoted in
    # key mode (the router's request charset, design 3.2)
    if not all(READ_TOKEN_RE.fullmatch(token) for token in tokens):
        raise NewtonError("read command contains a token the router would refuse")
    return tokens


def truncate(value: str | None, limit: int = 64 * 1024) -> tuple[str, bool]:
    value = value or ""
    return (value[:limit], len(value) > limit)


def scrub_read_text(
    tokens: list[str],
    out_raw: str,
    err_raw: str,
) -> tuple[str, str, bool]:
    """Apply bare-value protection and redaction before either truncation.

    Every read's output goes through here, the one over ssh and the one
    over the router's own web API alike: a value of a secret-looking
    option is replaced by its fingerprint, and both fields are
    sanitised and capped.
    """
    if out_raw and tokens[0] == "uci" and len(tokens) >= 3 and tokens[1] == "get":
        get_path = tokens[2]
        last = get_path.rsplit(".", 1)[-1] if "." in get_path else get_path
        if _redact._looks_like_secret_option(last):
            has_nl = out_raw.endswith("\n")
            get_value = out_raw[:-1] if has_nl else out_raw
            fp = _redact.fingerprint(get_path, get_value)
            out_raw = f"<redacted:{fp}>\n" if has_nl else f"<redacted:{fp}>"
    out_san = _envelope.sanitise_text(out_raw, redact=_redact.redact_text, line_cap=_envelope.FIELD_CAP)
    err_san = _envelope.sanitise_text(err_raw, redact=_redact.redact_text, line_cap=_envelope.FIELD_CAP)
    return out_san.text, err_san.text, out_san.truncated or err_san.truncated


def returned_approval_reasons(reasons: list[str], uci_batch: str, diff: str) -> list[str]:
    """Approval reasons safe to return to the model, deduped, order kept.

    The plan record keeps the full reasons; this value must carry no device
    text outside the envelope.  A reason that ends with ``": "`` followed by
    a quoted staged-diff or batch line (cut to 120 characters, with or
    without its leading ``-+@^`` op character, the way ``classify`` quotes
    it) is cut to the text before that line.  Every other reason — the prod
    profile reason, the non-trivial-check reason — keeps its ``": "`` and
    stays whole.
    """
    candidates: list[str] = []
    for source in (diff, uci_batch):
        for raw_line in source.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            candidates.append(": " + line[:120])
            if line[0] in "-+@^":
                candidates.append(": " + line[1:][:120])
    candidates = sorted(dict.fromkeys(candidates), key=len, reverse=True)
    stripped: list[str] = []
    for reason in reasons:
        kept = reason
        for candidate in candidates:
            if reason.endswith(candidate):
                kept = reason[: -len(candidate)]
                break
        stripped.append(kept)
    return list(dict.fromkeys(stripped))


class NewtonService:
    def __init__(self) -> None:
        self.devices = load_inventory()
        self.state = state_dir()

    def scan_vantages(self) -> dict[str, _scans.Vantage]:
        """Load scan-only inventory lazily so unrelated tools keep their seams."""
        try:
            return _scans.load_vantages()
        except _scans.ScanError as exc:
            raise NewtonError(str(exc)) from exc

    def device(self, name: str, allow_noinstall: bool = False) -> Device:
        """Resolve a device, refusing a no-install one unless asked.

        (ADR-021 point 1) a no-install device is refused here, at
        the one place every tool goes through.  Only the read may pass
        it, and only because the no-install read asks the router's own
        web API instead of ssh.
        """
        if name not in self.devices:
            raise NewtonError(f"unknown device: {name}")
        device = self.devices[name]
        if device.access == "no-install" and not allow_noinstall:
            raise NewtonError(
                f"device {oneline(name)} uses no-install access; Newton cannot "
                "manage it yet in this version"
            )
        return device

    def device_for(self, tool: str, name: str) -> Device:
        """Resolve a device only when the tool is in its platform capabilities.

        A no-install device is refused for every tool but the ones the
        no-install set names (NO_INSTALL_TOOLS): the same set the
        listing advertises, so the two can never disagree.
        """
        device = self.device(name, allow_noinstall=(tool in NO_INSTALL_TOOLS))
        try:
            caps = registry.capabilities(device.platform)
        except registry.UnknownPlatform as exc:
            raise NewtonError(
                f"device {oneline(name)}: unsupported platform {oneline(device.platform)!r}"
            ) from exc
        if tool not in caps.tools:
            raise NewtonError(
                f"{tool} is not available for platform {device.platform}"
            )
        if (
            device.platform != "openwrt"
            and tool in registry.VENDOR_WRITE_TOOL_NAMES
            and not device.vendor_write
        ):
            # The platform may write, this device may not: only a device
            # with vendor_write = true in the inventory may be changed.
            raise NewtonError(
                f"device {oneline(name)} is read-only; vendor_write is not enabled"
            )
        return device

    def audit(self, tool: str, device: str, result: str) -> None:
        write_audit(tool, device, result)

    def script_env(self, device: Device) -> dict[str, str]:
        env = os.environ.copy()
        env["OWRT_OPERATOR"] = "mcp"
        if device.auth == "password" and device.password_file:
            env["OWRT_SSH_PASSWORD_FILE"] = str(device.password_file)
        env["OWRT_SSH_PORT"] = str(device.port)
        if device.proxy_command:
            env["OWRT_SSH_PROXY"] = device.proxy_command
        env["OWRT_EXPECT_DEVICE"] = device.name
        env["OWRT_EXPECT_PROFILE"] = device.profile
        if device.key_file:
            env["OWRT_SSH_KEY"] = str(device.key_file)
        if device.known_hosts:
            env["OWRT_KNOWN_HOSTS"] = str(device.known_hosts)
        return env

    def run_script(
        self,
        device: Device,
        *args: str,
        timeout: int | None = None,
        extra_env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        if device.platform != "openwrt":
            raise NewtonError(
                f"OpenWrt change script is not available for platform {device.platform}"
            )
        env = self.script_env(device)
        if extra_env:
            env.update(extra_env)
        return subprocess.run([str(script_path()), *args], text=True, capture_output=True, stdin=subprocess.DEVNULL, timeout=timeout, env=env, check=False)

    def device_capabilities(self, device: Device) -> registry.Capabilities:
        """The capabilities of one device, by its access mode.

        A no-install device has nothing of Newton on the router: no
        guard, no installed-only tool.  Its way back is OpenWrt's own
        undo timer (NO_INSTALL_REVERT), and its tools are the ones the
        no-install set names (NO_INSTALL_TOOLS).  An installed device
        keeps the platform's capabilities exactly as they were.
        """
        caps = registry.capabilities(device.platform)
        if device.access != "no-install":
            return caps
        return registry.Capabilities(
            caps.tier, caps.writes, NO_INSTALL_REVERT, NO_INSTALL_TOOLS
        )

    def list_devices(self) -> dict[str, Any]:
        from . import grants

        devices: list[dict[str, Any]] = []
        for device in self.devices.values():
            caps = self.device_capabilities(device)
            devices.append(
                {
                    "name": device.name,
                    "platform": device.platform,
                    "host": device.host,
                    "user": device.user,
                    # A no-install router logs in over its web API with the
                    # rpcd password; device.auth is only its unused ssh setting.
                    "auth": (
                        "web-password" if device.access == "no-install" else device.auth
                    ),
                    "profile": device.profile,
                    "tier": caps.tier,
                    "capabilities": {
                        "writes": caps.writes,
                        "native_revert": caps.native_revert,
                        "tools": sorted(caps.tools),
                    },
                    # A non-OpenWrt device says whether IT may write; the
                    # OpenWrt entry keeps exactly the keys it had.  An AD
                    # write entry writes by its platform.
                    **(
                        {
                            "writes": device.vendor_write
                            or device.platform in registry.AD_WRITE_PLATFORMS
                        }
                        if device.platform != "openwrt"
                        else {}
                    ),
                    # A no-install device says so; an installed one keeps
                    # exactly the keys it had (installed is the default).
                    **(
                        {"access": device.access}
                        if device.access != "installed"
                        else {}
                    ),
                    # the answer of the installed-mode offer.  A
                    # no-install device that was asked carries it; one
                    # that was never asked does not (the agent may then
                    # ask the owner once).
                    **(
                        {"installed_offer": device.installed_offer}
                        if device.access == "no-install" and device.installed_offer
                        else {}
                    ),
                    "easy_grant": grants.grant_summary(device.name),
                }
            )
        return {"devices": devices}

    def get_state(
        self,
        device_name: str,
        getter_id: Any,
        params: Any,
    ) -> dict[str, Any]:
        device = self.device_for("newton_get_state", device_name)
        if device.platform == "openwrt":
            raise NewtonError(
                "newton_get_state is not available for platform openwrt"
            )
        if (
            type(getter_id) is not str
            or getter_id not in _getters.GETTER_IDS
        ):
            raise NewtonError("unknown getter id")
        try:
            getters = _getters.load_getters(
                device.platform, getter_path(device.platform)
            )
        except _getters.GetterError as exc:
            raise NewtonError(str(exc)) from exc
        getter = getters.get(getter_id)
        if getter is None:
            raise NewtonError(
                f"getter {getter_id} is not available for platform "
                f"{device.platform}"
            )
        if not getter.enabled:
            raise NewtonError(
                f"getter {getter_id} is disabled for platform "
                f"{device.platform} until a lab proves it"
            )
        if params is None:
            supplied: dict[str, str] = {}
        elif (
            type(params) is not dict
            or any(type(key) is not str for key in params)
            or any(type(value) is not str for value in params.values())
        ):
            raise NewtonError("params must be an object of string values")
        else:
            supplied = params
        if set(supplied) != set(getter.params):
            raise NewtonError(
                f"getter {getter_id}: params must name exactly the getter's slots"
            )

        seen_key = (str(state_dir()), device.name)
        with _SEEN_IFACES_LOCK:
            seen_ifaces = _SEEN_IFACES.get(seen_key, frozenset())
        if "iface" in getter.params and supplied.get("iface") not in seen_ifaces:
            raise NewtonError(
                "getter "
                f"{getter_id}: the iface value must be one the interfaces "
                "getter returned; run the interfaces getter first"
            )

        try:
            result = _ssh_runner().run(device, getter, supplied)
        except (RunnerRefused, _getters.GetterError) as exc:
            raise NewtonError(str(exc)) from exc

        if getter.id == "interfaces" and result.status == "ok":
            tokens = result.stdout.split()[:4096]
            values = frozenset(
                token.rstrip(",;:")
                for token in tokens
                if token.rstrip(",;:") and len(token.rstrip(",;:")) <= 64
            )
            with _SEEN_IFACES_LOCK:
                _SEEN_IFACES[seen_key] = values

        san = _envelope.sanitise(
            f"{device_name}:{getter_id}",
            result.stdout,
            redact=lambda text: _redact.redact_text(
                _platform_redact.redact(device.platform, text)
            ),
            max_bytes=getter.max_bytes,
        )
        status = result.status
        if status == "ok":
            status = san.status
        shape = shape_of(getter, status, result.stdout)
        caveat = EXPERIMENTAL_CAVEAT
        if shape == "mismatch":
            caveat = f"{caveat} {MISMATCH_CAVEAT}"
        response: dict[str, Any] = {
            "getter": getter_id,
            "tier": registry.capabilities(device.platform).tier,
            "status": status,
            "shape": shape,
            "truncated": result.truncated or san.truncated,
            "caveat": caveat,
            "device_role_enforced": False,
            "data": san.envelope,
        }
        if not self._field_receipt(device, getter_id, status, shape, result.stdout):
            response["receipt_note"] = RECEIPT_NOTE
        return response

    def _field_receipt(
        self, device: Device, getter_id: str, status: str, shape: str, stdout: str
    ) -> bool:
        """Record one field receipt; True when nothing needs a note (also when off).

        Never raises: a receipt problem must not fail the read.
        """
        try:
            key = (str(state_dir()), device.name, device.host, device.platform)
            now = _learned_now()
            if getter_id == "version":
                learned = _receipts.UNKNOWN
                if status == "ok" and shape == "matched":
                    learned = _receipts.extract_version(device.platform, stdout)
                with _LEARNED_VERSIONS_LOCK:
                    if learned == _receipts.UNKNOWN:
                        _LEARNED_VERSIONS.pop(key, None)
                    else:
                        _LEARNED_VERSIONS[key] = (learned, now)
            # Learning runs even when receipts are off, so re-enabling never
            # brings back a version a later failed `version` run should have cleared.
            if not _receipts.enabled():
                return True
            os_version = _receipts.UNKNOWN
            with _LEARNED_VERSIONS_LOCK:
                held = _LEARNED_VERSIONS.get(key)
                if held is not None:
                    if now - held[1] < LEARNED_VERSION_TTL:
                        os_version = held[0]
                    else:
                        del _LEARNED_VERSIONS[key]
            return _receipts.record(
                state_dir(), device.platform, getter_id, status, shape, os_version
            )
        except Exception:
            return False

    def ad_audit(
        self,
        device_name: str,
        checks: list[str] | None = None,
    ) -> dict[str, Any]:
        device = self.device_for("newton_ad_audit", device_name)
        return _ad_tools.audit(device, checks)

    def ad_list_checks(self) -> dict[str, Any]:
        return _ad_tools.list_checks()

    def ad_plan_change(
        self,
        device: str,
        verb: str,
        sam_names: list[str] | None = None,
        value: int | str | None = None,
    ) -> dict[str, Any]:
        """Plan one change in one domain (SPEC-1.4)."""
        self.device_for("newton_ad_plan_change", device)
        try:
            planned = _ad_write.plan_change(
                device,
                verb,
                sam_names,
                value,
                devices=self.devices,
            )
        except _AdWriteError as exc:
            raise NewtonError(str(exc)) from None
        return _ad_render.plan(planned)

    def ad_apply_change(self, device: str, plan_id: str) -> dict[str, Any]:
        """Apply one approved change and verify it on every DC with a write entry."""
        self.device_for("newton_ad_apply_change", device)
        try:
            result = _ad_apply.apply_change(
                plan_id, domain=device, devices=self.devices
            )
        except _AdWriteError as exc:
            raise NewtonError(str(exc)) from None
        return _ad_render.applied(result)

    def ad_change_status(self, device: str, plan_id: str) -> dict[str, Any]:
        """The state of one change, as the domain controller holds it."""
        self.device_for("newton_ad_change_status", device)
        try:
            result = _ad_apply.change_status(
                plan_id, domain=device, devices=self.devices
            )
        except _AdWriteError as exc:
            raise NewtonError(str(exc)) from None
        return _ad_render.applied(result)

    def ad_abort_change(self, device: str, plan_id: str) -> dict[str, Any]:
        """Abort one change: the domain controller puts the before-image back."""
        self.device_for("newton_ad_abort_change", device)
        try:
            result = _ad_apply.abort_change(
                plan_id, domain=device, devices=self.devices
            )
        except _AdWriteError as exc:
            raise NewtonError(str(exc)) from None
        return _ad_render.applied(result)

    def list_getters(self, device_name: str) -> dict[str, Any]:
        device = self.device_for("newton_list_getters", device_name)
        caps = registry.capabilities(device.platform)
        try:
            getters = _getters.load_getters(
                device.platform, getter_path(device.platform)
            )
        except _getters.GetterError as exc:
            raise NewtonError(str(exc)) from exc
        result: dict[str, Any] = {
            "result": "ok",
            "device": device.name,
            "platform": device.platform,
            "tier": caps.tier,
            "caveat": EXPERIMENTAL_CAVEAT,
            "getters": [
                {
                    "id": getter.id,
                    "enabled": getter.enabled,
                    "params": dict(getter.params),
                    "secret_bearing": getter.secret_bearing,
                    "verified": getter.verified,
                    "os_range": getter.os_range,
                }
                for getter in getters.values()
            ],
        }
        if _receipts.enabled():
            try:
                summary = _receipts.summarise(state_dir(), device.platform)
                result["field_evidence"] = {"enabled": True, "note": FIELD_EVIDENCE_NOTE}
            except Exception:
                summary = {}
                result["field_evidence"] = {
                    "enabled": True,
                    "note": "Field evidence could not be read (error); the getter list is unaffected.",
                }
            for entry in result["getters"]:
                found = summary.get(entry["id"], {"by_os": {}, "omitted": 0})
                entry["field_evidence"] = found["by_os"]
                if found["omitted"]:
                    entry["field_evidence_omitted_os"] = found["omitted"]
        else:
            result["field_evidence"] = {
                "enabled": False,
                "note": "Field receipts are turned off (NEWTON_FIELD_RECEIPTS).",
            }
        if not result["getters"]:
            result["note"] = (
                f"no getters ship for platform {device.platform} yet"
            )
        return result

    def list_tiers(self) -> dict[str, Any]:
        note = (
            "A tier is a hardening level, not a device profile; a tier is "
            "applied batch by batch in order. Each batch is its own plan / "
            "approval / apply / confirm cycle, so a failed batch rolls back "
            "only itself while earlier batches stay applied. Controls listed "
            "in `skipped` are lab-bound (name a lab-only interface, zone or "
            "address) or conditional (need a package the router does not "
            "have) and are never planned. A tier is written for a router "
            "that has not had a lower tier applied: stepping up (for example "
            "standard to lockdown) does not delete options the lower tier "
            "set, such as dropbear Interface; delete those first. "
            "Resolve the placeholder values "
            "with the existing read tool (e.g. `uci get`) before calling "
            "`newton_plan_tier`."
        )
        return {
            "result": "ok",
            "tiers": _tiers.list_tiers(),
            "note": note,
        }

    def _scrub_read(
        self, tokens: list[str], out_raw: str, err_raw: str
    ) -> tuple[str, str, bool]:
        """Apply bare-value protection and redaction before either truncation."""
        return scrub_read_text(tokens, out_raw, err_raw)

    def read(self, device_name: str, command: str) -> dict[str, Any]:
        device = self.device_for("newton_read", device_name)
        tokens = validate_read(command)
        if device.access == "no-install":
            # a no-install router is read over its own web API, and
            # only over it: nothing on this path reaches ssh.
            from . import noinstall_read as _noinstall_read

            return _noinstall_read.read_noinstall(
                device, command, _noinstall_read.default_client_factory
            )
        return self._ssh_read(
            device, ["read", *tokens], f"{device_name}:{command}", tokens
        )

    def read_hello(self, device_name: str) -> dict[str, Any]:
        """The router program's hello line (its version among other facts).

        The hello verb is not one of the read verbs the model may call.
        The Wi-Fi scan needs the program version before it spends the
        owner's consent, so the hello line has its own path.
        """
        device = self.device_for("newton_read", device_name)
        nonce = os.urandom(8).hex()
        argv = ["hello", nonce]
        return self._ssh_read(device, argv, f"{device_name}:hello", argv)

    def _ssh_read(
        self,
        device: Device,
        remote_argv: list[str],
        source: str,
        scrub_tokens: list[str],
    ) -> dict[str, Any]:
        """Run one router-program command over SSH; the output is enveloped."""
        try:
            ssh_binary = _ssh_path.resolve_ssh()
        except _ssh_path.SshNotFound as exc:
            raise NewtonError(str(exc)) from exc
        args = [ssh_binary, "-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "ConnectTimeout=8", "-p", str(device.port)]
        if device.proxy_command:
            args += ["-o", f"ProxyCommand={device.proxy_command}"]
        env = os.environ.copy()
        askpass: str | None = None
        if device.auth == "password":
            with tempfile.NamedTemporaryFile("w", prefix="newton-askpass-", delete=False) as f:
                askpass = f.name
                f.write("#!/bin/sh\ncat -- " + shlex.quote(str(device.password_file)) + "\n")
            os.chmod(askpass, 0o700)
            env.update({"SSH_ASKPASS": askpass, "SSH_ASKPASS_REQUIRE": "force", "DISPLAY": "x"})
            args += ["-o", "BatchMode=no", "-o", "PreferredAuthentications=password,keyboard-interactive", "-o", "NumberOfPasswordPrompts=1"]
        else:
            args += ["-o", "BatchMode=yes"]
            if device.key_file:
                args += ["-i", str(device.key_file), "-o", "IdentitiesOnly=yes"]
            if device.known_hosts:
                args += ["-o", "StrictHostKeyChecking=yes",
                         "-o", f"UserKnownHostsFile={device.known_hosts}"]
        # design 7.2: key mode sends the tokens unquoted (the router refuses
        # quotes and every token is inside its request charset); password
        # mode goes through root's shell, which must not glob `[0]`.
        if device.auth == "password":
            remote = shlex.join([PROG, *remote_argv])
        else:
            remote = " ".join([PROG, *remote_argv])
        try:
            # INJ-1: the ``--`` ends ssh's option list, so the destination
            # can never be read as an option.
            cp = subprocess.run(args + ["--", device.destination, remote], text=True, capture_output=True, stdin=subprocess.DEVNULL, timeout=30, env=env, check=False)
        except subprocess.TimeoutExpired as exc:
            out_raw = exc.stdout if isinstance(exc.stdout, str) else ""
            err_raw = exc.stderr if isinstance(exc.stderr, str) else ""
            out_text, err_text, truncated = self._scrub_read(scrub_tokens, out_raw, err_raw)
            err_msg = err_text or "read command timed out"
            return {
                "exit_code": 124,
                "stdout": _envelope.envelope(source, out_text),
                "stderr": _envelope.envelope(source, err_msg),
                "truncated": truncated,
            }
        finally:
            if askpass:
                try:
                    Path(askpass).unlink()
                except OSError:
                    pass
        out, err, truncated = self._scrub_read(scrub_tokens, cp.stdout or "", cp.stderr or "")
        return {
            "exit_code": cp.returncode,
            "stdout": _envelope.envelope(source, out),
            "stderr": _envelope.envelope(source, err),
            "truncated": truncated,
        }

    def guided_audit(self, device_name: str) -> dict[str, Any]:
        """Run the fixed guided audit through the existing read path."""
        from . import guided as _guided

        # Resolve the device before attempting any item.  In particular, an
        # unknown device stays the ordinary call_tool NewtonError and cannot
        # be mistaken for fourteen independent read failures.
        device = self.device_for("newton_guided_audit", device_name)
        if device.platform != "openwrt":
            raise NewtonError(
                f"newton_guided_audit on platform {device.platform} "
                "needs audit getters, which are not built yet"
            )

        items: list[dict[str, Any]] = []
        package_command = "apk list -I miniupnpd-nftables"
        package_name = "miniupnpd-nftables"

        for audit_item in _guided.AUDIT_ITEMS:
            item: dict[str, Any] = {
                "id": audit_item["id"],
                "title": audit_item["title"],
                "reads": [],
            }
            if audit_item["id"] == "services":
                item["gap"] = "no closed running/enabled-service read"

            for command in audit_item["commands"]:
                source = f"{device_name}:{command}"
                try:
                    read_result = self.read(device_name, command)
                    exit_code = read_result["exit_code"]
                    output = read_result["stdout"]
                    stderr: Any = read_result["stderr"]
                    output_text = output["text"]
                    if exit_code != 0:
                        state = "failed"
                    elif output_text:
                        state = "ok"
                    else:
                        state = "empty"
                except DeviceTextError as exc:
                    exit_code = 1
                    state = "failed"
                    output = _envelope.envelope(source, "")
                    stderr = _envelope.envelope(source, str(exc))
                    output_text = ""
                except NewtonError as exc:
                    exit_code = 1
                    state = "failed"
                    output = _envelope.envelope(source, "")
                    stderr = str(exc)
                    output_text = ""

                item["reads"].append({
                    "command": command,
                    "state": state,
                    "exit_code": exit_code,
                    "output": output,
                    "stderr": stderr,
                })

                if command == package_command and state != "failed":
                    installed = any(
                        line.startswith(package_name)
                        for line in output_text.splitlines()
                    )
                    item["package_state"] = (
                        "installed" if installed else "not-installed"
                    )

            items.append(item)

        return {
            "result": "ok",
            "device": device_name,
            "items": items,
            "not_checked": [],
        }

    def plan_scan(
        self,
        device_name: str,
        kind: Any,
        profile: Any,
        interface: Any,
    ) -> dict[str, Any]:
        """Derive and persist one scan request; never start a scan."""
        device = self.device_for("newton_plan_scan", device_name)
        if device.platform != "openwrt":
            raise NewtonError("scans are available only for OpenWrt devices")
        try:
            kind, profile, supplied_interface = _scans.validate_plan_inputs(
                kind, profile, interface
            )
            if kind == _scans.WIFI_KIND:
                # The Wi-Fi survey runs on the router's own radio over
                # the normal read lane.  There is no vantage and no IP
                # target; the radio has to exist in the router's own
                # wireless configuration.
                assert supplied_interface is not None
                radio = supplied_interface
                wireless = _scans.router_text(
                    self.read(device_name, "uci show wireless"),
                    "wireless configuration",
                )
                if not _wifiscan.has_radio(wireless, radio):
                    raise _scans.ScanError(
                        f"the router has no radio named {radio}"
                    )
                record = _scans.make_request(
                    device=device_name,
                    kind=kind,
                    profile=profile,
                    interface=radio,
                    target=_scans.WIFI_TARGET,
                    vantage=_scans.WIFI_VANTAGE,
                )
            else:
                vantage = _scans.choose_vantage(self.scan_vantages(), device_name, kind)
                dump = _scans.read_json(
                    self.read(device_name, "ubus call network.interface dump"),
                    "interface dump",
                )
                if kind == "inside":
                    assert supplied_interface is not None
                    if supplied_interface not in _scans.interface_names(dump):
                        raise _scans.ScanError("inside interface does not exist on the router")
                    firewall = _scans.read_text(
                        self.read(device_name, "uci show firewall"), "firewall zones"
                    )
                    if supplied_interface in _scans.wan_networks(
                        firewall, device.wan_zones
                    ):
                        raise _scans.ScanError("inside interface belongs to a WAN zone")
                    scan_interface = supplied_interface
                else:
                    scan_interface = _scans.default_route_interface(dump)
                status = _scans.read_json(
                    self.read(
                        device_name,
                        f"ubus call network.interface.{scan_interface} status",
                    ),
                    "interface status",
                )
                address, network = _scans.address_and_network(status)
                if kind == "inside" and network.prefixlen < 24:
                    raise _scans.ScanError("inside subnet is wider than /24")
                target = (
                    str(network)
                    if kind == "inside" and profile == "quick"
                    else str(address)
                )
                # SC-1: the target came from the router's interface report; a
                # compromised router can steer the scan at any address or /24
                # it likes, so re-check the kind-specific policy here too.
                # ``scans._validate_target`` raises ``ScanError`` for any
                # target that is not allowed; this is the plan-time half of
                # the same check ``scans._validate_request_fields`` runs on
                # load.
                parsed_target = (
                    _scans.ipaddress.ip_network(target, strict=False)
                    if "/" in target
                    else _scans.ipaddress.ip_address(target)
                )
                _scans._validate_target(kind, parsed_target)
                record = _scans.make_request(
                    device=device_name,
                    kind=kind,
                    profile=profile,
                    interface=scan_interface,
                    target=target,
                    vantage=vantage.name,
                )
            _scans.save_request(self.state, record)
        except _scans.ScanError as exc:
            raise NewtonError(str(exc)) from exc
        return {
            "result": "planned",
            "id": record["id"],
            "device": record["device"],
            "kind": record["kind"],
            "profile": record["profile"],
            "interface": record["interface"],
            "target": record["target"],
            "vantage": record["vantage"],
            "duration_cap_s": record["duration_cap_s"],
            "kept": record["kept"],
        }

    def run_scan(self, device_name: str, request_id: Any) -> dict[str, Any]:
        """Consume consent before executing one registered-vantage scan."""
        device = self.device_for("newton_run_scan", device_name)
        if device.platform != "openwrt":
            raise NewtonError("scans are available only for OpenWrt devices")
        if not isinstance(request_id, str):
            raise NewtonError("scan request id must be 32 lowercase hexadecimal characters")
        try:
            request = _scans.load_request(self.state, request_id)
            if request["device"] != device_name:
                raise _scans.ScanError("scan request is for a different device")
            if request["kind"] == _scans.WIFI_KIND:
                # The Wi-Fi survey has no vantage; it runs on the
                # router's own radio over the normal read lane.
                vantage = None
            else:
                vantage = self.scan_vantages().get(str(request["vantage"]))
                if (
                    vantage is None
                    or vantage.role != request["kind"]
                    or device_name not in vantage.devices
                ):
                    raise _scans.ScanError(
                        "scan request vantage no longer matches the inventory; plan it again"
                    )
            if request["kind"] == _scans.WIFI_KIND:
                # The version preflight runs BEFORE the consent is
                # consumed, so an unupgraded router costs the owner no
                # approval.
                self._wifi_version_preflight(device_name)
            consent = _scans.consume_consent(self.state, request, device_name)
        except _scans.ScanError as exc:
            raise NewtonError(str(exc)) from exc

        if request["kind"] == _scans.WIFI_KIND:
            return self._run_wifi_scan(device_name, request, consent)

        command = [
            "scan",
            str(request["profile"]),
            str(request["kind"]),
            str(request["target"]),
        ]
        started = datetime.now(timezone.utc)
        completed: subprocess.CompletedProcess[str] | None = None
        stdout_text = ""
        try:
            completed = _scans.run_vantage(vantage, command)
            stdout_text = completed.stdout or ""
        except subprocess.TimeoutExpired as exc:
            stdout_text = exc.stdout if isinstance(exc.stdout, str) else ""
        except OSError:
            stopped = datetime.now(timezone.utc)
            self._scan_audit(request, consent, started, stopped, 0, 0, "runner-error")
            raise NewtonError("scan vantage could not be started") from None
        stopped = datetime.now(timezone.utc)
        timed_out_addresses = _scans.parse_timed_out(stdout_text)
        hosts = _scans.parse_grepable(stdout_text)
        findings = _scans.findings_for(str(request["kind"]), hosts)
        port_count = sum(len(host["ports"]) for host in hosts)
        rc = completed.returncode if completed is not None else -1
        incomplete = (
            completed is None
            or rc != 0
            or timed_out_addresses
            or not _scans.scan_complete(stdout_text)
        )
        scan_name = f"nmap_{request['kind']}"
        if incomplete:
            note = "scan did not finish; results are partial"
            self._scan_audit(
                request,
                consent,
                started,
                stopped,
                len(hosts),
                port_count,
                "incomplete",
                timed_out=len(timed_out_addresses),
            )
            from . import guided as _guided

            skeleton = _guided._empty_v1_report_skeleton("standard")
            return {
                "result": "incomplete",
                "request_id": request_id,
                "note": note,
                "timed_out": timed_out_addresses,
                "findings": findings,
                "host_count": len(hosts),
                "port_count": port_count,
                "report_update": {
                    "scans_run": skeleton["scans_run"],
                    "scans_not_run": skeleton["scans_not_run"],
                    "scans_incomplete": [scan_name],
                    "findings": skeleton["findings"],
                },
            }
        self._scan_audit(
            request,
            consent,
            started,
            stopped,
            len(hosts),
            port_count,
            "ok",
            timed_out=0,
        )
        from . import guided as _guided

        report_update = _guided.with_scan_result(
            _guided._empty_v1_report_skeleton("standard"),
            str(request["kind"]),
            findings,
        )
        summary = json.dumps({"hosts": hosts}, ensure_ascii=False, sort_keys=True)
        return {
            "result": "ok",
            "request_id": request_id,
            "scan": _envelope.envelope(f"{device_name}:scan:{request_id}", summary),
            "findings": findings,
            "host_count": len(hosts),
            "port_count": port_count,
            "report_update": {
                "scans_run": report_update["scans_run"],
                "scans_not_run": report_update["scans_not_run"],
                "scans_incomplete": [],
                "findings": report_update["findings"],
            },
        }

    def _router_program_version(
        self, device_name: str
    ) -> tuple[int, int, int] | None:
        """The router program's version, from its hello line, or None.

        None means the version could not be read or understood.  The Wi-Fi
        preflight then fails closed before consent is consumed.
        """
        try:
            result = self.read_hello(device_name)
        except NewtonError:
            return None
        try:
            text = _scans.router_text(result, "hello line")
        except _scans.ScanError:
            return None
        return _scans.parse_program_version(text)

    def _wifi_version_preflight(self, device_name: str) -> None:
        """Refuse the Wi-Fi scan unless the router program is new enough.

        The check runs before the owner's consent is consumed: an
        unreadable or unupgraded router must not burn the single-use
        approval.
        """
        version = self._router_program_version(device_name)
        if version is None:
            raise _scans.ScanError(_scans.WIFI_ERROR_VERSION_UNREADABLE)
        if version < _scans.WIFI_SCAN_MIN_VERSION:
            raise _scans.ScanError(
                _scans.WIFI_ERROR_TOO_OLD.format(device=device_name)
            )

    def _run_wifi_scan(
        self,
        device_name: str,
        request: dict[str, Any],
        consent: dict[str, Any],
    ) -> dict[str, Any]:
        """One Wi-Fi survey with the router's own radio.

        The router's own SSIDs, channel and BSSID are read again here, at
        run time: a request planned minutes ago may sit behind a changed
        configuration.  The scan output is parsed in memory and dropped
        again; what leaves is counts, and the look-alike names inside the
        untrusted envelope.
        """
        radio = str(request["interface"])
        started = datetime.now(timezone.utc)
        try:
            wireless = _scans.router_text(
                self.read(device_name, "uci show wireless"),
                "wireless configuration",
            )
            own_ssids = _wifiscan.own_ssids(wireless, radio)
            own_channel = _wifiscan.own_channel(wireless, radio)
            own_bssids = _wifiscan.own_bssids_from_uci(wireless, radio)
            for ifname in _wifiscan.up_ap_ifnames(wireless, radio):
                if not _scans.INTERFACE_RE.fullmatch(ifname):
                    continue
                info = self.read(device_name, f"iwinfo {ifname} info")
                if info.get("exit_code") != 0:
                    continue
                own_bssids |= _wifiscan.bssids_from_iwinfo(
                    _scans.router_text(info, "wireless interface information")
                )
            scan_result = self.read(device_name, f"wifiscan {radio}")
            if scan_result.get("exit_code") != 0:
                raise _scans.ScanError(
                    _scans.wifi_scan_error(scan_result, device=device_name)
                )
            results = _scans.parse_wifi_results(
                _scans.router_text(scan_result, "Wi-Fi scan output")
            )
        except _scans.ScanError as exc:
            raise NewtonError(str(exc)) from exc
        stopped = datetime.now(timezone.utc)
        source = f"{device_name}:wifi-scan:{request['id']}"
        summary = _wifiscan.summarise(
            radio=radio,
            results=results,
            own_ssids=own_ssids,
            own_channel=own_channel,
            own_bssids=own_bssids,
            source=source,
        )
        findings = summary["findings"]
        self._scan_audit(
            request,
            consent,
            started,
            stopped,
            0,
            0,
            "ok",
            timed_out=0,
            networks=summary["networks"],
            channels=summary["channels"],
            findings=len(findings),
        )
        from . import guided as _guided

        report_update = _guided.with_scan_result(
            _guided._empty_v1_report_skeleton("standard"),
            _scans.WIFI_KIND,
            findings,
        )
        payload = {
            key: value for key, value in summary.items() if key != "findings"
        }
        return {
            "result": "ok",
            "request_id": request["id"],
            "scan": _envelope.envelope(
                source, json.dumps(payload, ensure_ascii=False, sort_keys=True)
            ),
            "findings": findings,
            "network_count": summary["networks"],
            "channel_count": summary["channels"],
            "finding_count": len(findings),
            "report_update": {
                "scans_run": report_update["scans_run"],
                "scans_not_run": report_update["scans_not_run"],
                "scans_incomplete": [],
                "findings": report_update["findings"],
            },
        }

    def _scan_audit(
        self,
        request: dict[str, Any],
        consent: dict[str, Any],
        started: datetime,
        stopped: datetime,
        hosts: int,
        ports: int,
        result: str,
        timed_out: int = 0,
        *,
        networks: int | None = None,
        channels: int | None = None,
        findings: int | None = None,
    ) -> None:
        detail = (
            f"request_hash={request['request_hash']} start={started.isoformat()} "
            f"stop={stopped.isoformat()} hosts={hosts} ports={ports} "
            f"approver={oneline(str(consent.get('approved_by', '')))} "
            f"timed_out={timed_out} outcome={result}"
        )
        if networks is not None:
            # The Wi-Fi survey has no hosts and no ports: it records the
            # counts it has instead.  The nmap line above is unchanged.
            # The approver goes last, so a long one is cut rather than the
            # counts.
            detail = (
                f"request_hash={request['request_hash']} start={started.isoformat()} "
                f"stop={stopped.isoformat()} networks={networks} "
                f"channels={channels} findings={findings} outcome={result} "
                f"approver={oneline(str(consent.get('approved_by', '')))}"
            )
        write_audit("newton_run_scan", str(request["device"]), detail)

    def backup(self, device_name: str) -> dict[str, Any]:
        device = self.device_for("newton_backup", device_name)
        if device.platform != "openwrt":
            return vendor_flow.backup(self, device, device_name)
        cp = self.run_script(device, "backup", device.destination)
        parsed = parse_backup(cp.stdout + cp.stderr)
        if cp.returncode or not parsed:
            log = script_log(cp)
            if log:
                raise DeviceTextError(log)
            raise NewtonError("backup failed")
        return {
            "backup_path": _envelope.envelope(f"{device_name}:backup", parsed["backup_path"]),
            "config_files": parsed["config_files"],
        }

    def plan(
        self,
        device_name: str,
        uci_batch: str,
        timeout_s: int | None = None,
        probes: list[list[str]] | None = None,
        manifest_checks: list[str] | None = None,
        *,
        explanation: Any = None,
        owner_confirmed_in_chat: Any = None,
        _tool: str = "newton_plan_change",
        _deleted_values: Mapping[tuple[str, str, str], str | tuple[str, ...]] | None = None,
    ) -> dict[str, Any]:
        # (ADR-021 point 4) a no-install device is planned by the
        # no-install flow, which decides between an auto plan and an
        # owner script.  It branches here, before any ssh: the
        # installed flow stages the change on the router, and a
        # no-install router has no program of Newton on it.
        device = self.device_for(_tool, device_name)
        if device.access == "no-install":
            from . import noinstall_flow

            return noinstall_flow.plan(
                self,
                device_name,
                uci_batch,
                180 if timeout_s is None else timeout_s,
                explanation=explanation,
                owner_confirmed_in_chat=owner_confirmed_in_chat,
            )
        if timeout_s is None:
            timeout_s = 90
        if device.platform != "openwrt":
            return vendor_flow.plan(
                self,
                device,
                device_name,
                uci_batch,
                timeout_s,
                explanation,
                owner_confirmed_in_chat,
            )
        if not isinstance(uci_batch, str):
            raise NewtonError("uci_batch must be a string")
        uci_batch = self._resolve_placeholders(device_name, uci_batch)
        if isinstance(timeout_s, bool) or not isinstance(timeout_s, int) or not 60 <= timeout_s <= 600:
            raise NewtonError("timeout_s must be an integer 60..600")
        caller_probes = probes if probes is not None else []
        if not isinstance(caller_probes, list):
            validate_probes(caller_probes)  # raises the clear type error
        # the owner's yes in the conversation and the
        # agent's explanation come before any device contact.  The steps count
        # is taken on the resolved batch, the same text apply and newton-approve
        # count later (a dropped placeholder line still counts).
        #
        # A change a live grant covers is consented by the grant, so
        # it needs no second yes in the chat.  The waiver is decided here,
        # before any device contact, from the staged batch and the grant on
        # disk -- never from what the agent says about the change.
        waived = _grant_waives_chat(device_name, uci_batch, owner_confirmed_in_chat)
        stored_explanation = check_explanation_inputs(
            explanation,
            owner_confirmed_in_chat,
            _explanation.change_lines(uci_batch),
            waived=waived,
        )
        client_rows = _client_checks.client_claims(stored_explanation["expect"])
        if client_rows:
            if timeout_s < _client_checks.MIN_TIMEOUT_S:
                raise NewtonError(
                    f"timeout_s must be at least {_client_checks.MIN_TIMEOUT_S} "
                    "seconds for a client check"
                )
            try:
                vantages = self.scan_vantages()
                for _, claim in client_rows:
                    _client_checks.vantage_for_zone(
                        vantages, device_name, claim["zone"]
                    )
            except (_client_checks.ClientCheckError, _scans.ScanError) as exc:
                raise NewtonError(str(exc)) from exc

        # Refuse up front when the router's firewall already fails
        # `fw4 check` before any change: planning on a broken firewall
        # can only produce a plan we cannot safely apply.  Only fw4's
        # own verdict (exit_code == 1) refuses; any other result
        # (clean, ssh timeout, ssh failure, no fw4 binary, read lane
        # refusal) lets the existing apply-time gate catch it.
        self._refuse_failing_fw4(device_name)

        # ADR-010: every apply runs the live checks of the manifest controls
        # it touches.  ``auto_entries`` are derived from the staged batch
        # alone (no router round-trip yet); they are entry INDEXES, not ids,
        # so a duplicate-id sibling (e.g. OW-FW-06 '0' and '1') is distinct.
        # ``caller_ids`` are the ``manifest_checks`` the MCP caller named;
        # they go through the by-id lookup (an id naming more than one entry
        # is REFUSED).  ``caller_probes`` count into the same sealed-probe
        # cap in seal_manifest_ids, so a refusal names the control ids being
        # added (never a bare ``too-many`` from later validate_probes).
        caller_ids = list(manifest_checks) if manifest_checks is not None else []
        auto_entries = _touched.derive_touched_entries(uci_batch)
        # the agent's expect claims are sealed as probes AFTER Newton's
        # own and the caller's, into the same list the router verifies from a
        # fresh session.  They count toward the same cap; a plan that would not
        # fit is refused, never trimmed (a claim cannot displace a Newton probe).
        claim_probes = _explanation.claim_probes(stored_explanation)
        extra_probes = caller_probes + claim_probes
        try:
            sealed_entries, manifest_probes = _touched.seal_manifest_ids(
                caller_ids, auto_entries, extra_probes=extra_probes,
            )
        except ValueError as exc:
            raise NewtonError(
                f"{exc} (the {len(claim_probes)} expect claims are sealed as probes too and count toward the same cap)"
            ) from exc
        controls = _probes._load_controls(_probes.manifest_path())
        sealed_ids = _touched.entry_ids(controls, sealed_entries)

        if client_rows:
            def _load_interface_dump() -> dict[str, Any]:
                return _scans.read_json(
                    self.read(device_name, "ubus call network.interface dump"),
                    "interface dump",
                )

            try:
                filled_expect = _client_checks.fill_targets(
                    stored_explanation["expect"], _load_interface_dump
                )
            except (_client_checks.ClientCheckError, _scans.ScanError) as exc:
                raise NewtonError(str(exc)) from exc
            filled_explanation = {
                **stored_explanation,
                "expect": filled_expect,
            }
            try:
                stored_explanation = _explanation.parse_explanation(
                    filled_explanation,
                    change_lines=_explanation.change_lines(uci_batch),
                    allow_targets=True,
                )
            except _explanation.ExplanationError as exc:
                raise NewtonError("internal: client claims did not re-parse") from exc
            if stored_explanation["expect"] != filled_expect:
                raise NewtonError("internal: client claims did not re-parse")

        def _stage_plan(sealed_probes: list[list[str]]) -> dict[str, Any]:
            try:
                cp_norm = validate_probes(list(sealed_probes) + caller_probes + claim_probes)
            except NewtonError as exc:
                if not str(exc).endswith(("too-many", "too-long")):
                    raise
                raise NewtonError(
                    f"{exc} (the {len(claim_probes)} expect claims are sealed as probes too and count toward the same cap)"
                ) from exc
            cp_fd, cp_filename = tempfile.mkstemp(prefix="newton-uci-", suffix=".uci")
            cp_probe_filename: str | None = None
            # APR-08: stamp the stage time BEFORE the plan
            # script starts so the host's stage expiry is never later
            # than the router's -- the router counts from stage-up at
            # stage time, while the previous code stamped staged_at
            # AFTER the whole plan script returned (stage, seal, diff,
            # masking), so the host could show and cap an approval a
            # few seconds to tens of seconds too late.  An approval at
            # the edge would then fail with stale-stage and be burned
            # (APR-05).  Stamped before, the host's window is the
            # strict subset of the router's; an approval that the
            # router would reject is also rejected by the host.
            staged_at = datetime.now(timezone.utc).isoformat()
            try:
                os.fchmod(cp_fd, 0o600)
                with os.fdopen(cp_fd, "w", encoding="utf-8") as f:
                    f.write(uci_batch)
                cp_probe_filename = write_probe_file(cp_norm)
                cp_cp = self.run_script(
                    device, "plan", device.destination, cp_filename, str(timeout_s), cp_probe_filename
                )
            finally:
                for path in (cp_filename, cp_probe_filename):
                    if path is not None:
                        try:
                            Path(path).unlink()
                        except OSError:
                            pass
            cp_parsed = parse_plan(cp_cp.stdout + cp_cp.stderr)
            if cp_cp.returncode or not cp_parsed:
                log = script_log(cp_cp)
                if log:
                    raise DeviceTextError(log)
                raise NewtonError("planning failed")
            return {"parsed": cp_parsed, "normalized": cp_norm, "staged_at": staged_at}

        staged = _stage_plan(manifest_probes)
        parsed = staged["parsed"]
        normalized = staged["normalized"]
        # APR-08: _stage_plan now stamps staged_at BEFORE
        # the plan script runs, so the host's stage expiry can never
        # run later than the router's.  The restage branch below
        # overwrites this when the diff surfaces a manifest entry the
        # batch alone did not, so the persisted record always names
        # the freshest live stage on the device.
        staged_at = staged["staged_at"]

        # ADR-010: re-check using the router's diff + section facts.  A diff
        # that pulls in a manifest entry the batch alone did not surface
        # -> abort the staged session and re-plan ONCE with the union.  The
        # shared ``needs_restage`` decision lives in ``touched.py`` and
        # compares entry INDEXES; the lab runner applies the same rule when
        # it cannot reach the MCP.
        diff_entries = _touched.derive_touched_entries(
            uci_batch, parsed["diff"], parsed["sections"]
        )
        needs, missing = _touched.needs_restage(sealed_entries, diff_entries)
        if needs:
            self.abort(device_name, parsed["session_id"])
            union_entries = list(sealed_entries) + list(missing)
            try:
                sealed_entries, manifest_probes = _touched.seal_manifest_ids(
                    [], union_entries, extra_probes=extra_probes,
                )
            except ValueError as exc:
                raise NewtonError(
                    f"{exc} (the {len(claim_probes)} expect claims are sealed as probes too and count toward the same cap)"
                ) from exc
            sealed_ids = _touched.entry_ids(controls, sealed_entries)
            staged = _stage_plan(manifest_probes)
            parsed = staged["parsed"]
            normalized = staged["normalized"]
            staged_at = staged["staged_at"]
            diff_entries = _touched.derive_touched_entries(
                uci_batch, parsed["diff"], parsed["sections"]
            )
            needs2, missing2 = _touched.needs_restage(sealed_entries, diff_entries)
            if needs2:
                self.abort(device_name, parsed["session_id"])
                missing_ids = _touched.entry_ids(controls, missing2)
                raise NewtonError(
                    "manifest checks keep needing more after the union; "
                    f"aborting: control ids missing: {missing_ids!r}"
                )
        # The persisted ``manifest_checks_auto`` records every id the
        # auto-derivation surfaced (batch-side + diff-restage-added).
        # It can overlap with ``manifest_checks`` when the caller and the
        # derivation both named the same id; that overlap is informational
        # and does NOT mean a duplicate probe was sealed (the seal dedupes
        # caller + auto before expansion).
        caller_set = set(caller_ids)
        batch_auto_ids = _touched.entry_ids(controls, auto_entries)
        diff_added: list[str] = []
        for cid in sealed_ids:
            if cid in caller_set or cid in batch_auto_ids:
                continue
            diff_added.append(cid)
        final_auto_ids = batch_auto_ids + diff_added
        try:
            section_facts = {}
            for section_line in parsed["sections"]:
                parsed_fact = parse_section_fact(section_line)
                if parsed_fact is not None:
                    section_facts[parsed_fact[0]] = parsed_fact[1]
            if _deleted_values is None:
                decision = classify(device, uci_batch, parsed["diff"], section_facts)
            else:
                decision = classify(
                    device,
                    uci_batch,
                    parsed["diff"],
                    section_facts,
                    deleted_values=_deleted_values,
                )
        except ValueError as exc:
            raise NewtonError(str(exc)) from exc
        # A grant covers the KIND of change, but the policy's own
        # verdict on this plan still stands.  A plan the policy calls
        # critical is never waived by a grant: it goes back to the owner
        # in the chat, with the usual words.
        if waived and decision["risk"] == "critical":
            raise NewtonError(OWNER_CONFIRMATION_HELP)
        router_requires = parsed["approval_required"]
        approval = _gate.plan_requires_approval(
            device,
            router_requires=bool(router_requires),
            policy_requires=bool(decision["requires_approval"]),
        )
        reasons = list(decision["reasons"])
        record = {
            "device": device_name,
            "host": device.host,
            "session_id": parsed["session_id"],
            "uci_batch": uci_batch,
            "diff": parsed["diff"],
            "probes": normalized,
            "timeout_s": timeout_s,
            "base_hash": parsed["base_hash"],
            "requires_approval": approval,
            "router_digest": parsed["digest"],
            "explanation": stored_explanation,
            # A waived plan was consented by a live grant, so the
            # owner's chat yes is false and the consent basis says so.  A
            # plan the owner confirmed in chat carries no basis key at all.
            "owner_confirmed_in_chat": not waived,
            "reasons": reasons,
            "risk": decision["risk"],
            "created_at": datetime.now(timezone.utc).isoformat(),
            "staged_at": staged_at,
            "manifest_checks": caller_ids,
            "router_leash": parsed["leash"],
            "router_profile": parsed["profile"],
            "router_requires_approval": router_requires,
            "router_sections": parsed["sections"],
            "staged_check": parsed["staged_check"],
            # Not hash-bound: where the pre-change backup is, for the change receipt.
            "backup_path": parsed["backup_path"],
        }
        if waived:
            record["consent_basis"] = "grant"
        if final_auto_ids:
            record["manifest_checks_auto"] = final_auto_ids
        record["plan_hash"] = compute_plan_hash(record)
        plans = self.state / "plans"
        refusal = _receipts.check_state_write_path(plans, self.state)
        if refusal is not None:
            return {"error": refusal}
        plans.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(plans, 0o700)
        target = plans / f"{parsed['session_id']}.json"
        # APR-04: the record holds the raw uci_batch, so it is written the
        # way approve.py writes a record: a fresh mkstemp file (mode 0600
        # from the start, never a fixed name an attacker can plant), an
        # fsync, and an atomic replace into place.  A failure removes the
        # temporary file.
        descriptor, temporary = tempfile.mkstemp(prefix=f".{target.name}.", dir=plans)
        try:
            # the stream owns the descriptor from here on, so every later
            # failure closes it (mkstemp already made the file 0600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(json.dumps(record, sort_keys=True))
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
        except BaseException:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise
        # Free-form explanation text can carry a secret that redaction cannot see
        # (it only catches ``name=value`` forms), so the audit line carries no
        # text at all: just the intent length and a short hash for cross-record
        # correlation.
        intent_text = stored_explanation["intent"]
        audit_line = (
            f"session={parsed['session_id']} "
            f"intent_len={len(intent_text)} "
            f"intent_sha256={hashlib.sha256(intent_text.encode('utf-8')).hexdigest()[:12]}"
        )
        write_audit("newton_explanation", device_name, audit_line)
        return {
            "session_id": parsed["session_id"],
            "plan_hash": record["plan_hash"],
            "base_hash": parsed["base_hash"],
            "touched_configs": parsed["touched_configs"],
            "requires_approval": approval,
            "approval_required": approval,
            "staged_check": record["staged_check"],
            "router_requires_approval": router_requires,
            "approval_reasons": returned_approval_reasons(reasons, uci_batch, parsed["diff"]),
            "risk": decision["risk"],
            # Where the consent came from, so the agent can tell
            # the owner "your grant covered this; nothing to confirm".
            "consent_basis": "grant" if waived else "chat",
            "what_this_does": _consequences.describe(uci_batch),
            "smaller_alternatives": _consequences.alternatives(uci_batch),
            "diff": _envelope.envelope(f"{device_name}:plan", parsed["diff"]),
            "backup_path": _envelope.envelope(f"{device_name}:plan", parsed["backup_path"]),
        }

    def plan_undo(
        self,
        device_name: str,
        change_id: str,
        explanation: Any = None,
        owner_confirmed_in_chat: Any = None,
    ) -> dict[str, Any]:
        device = self.device_for("newton_plan_undo", device_name)
        require_session(change_id)
        # the owner's yes comes before any device contact, also the backup below.
        if owner_confirmed_in_chat is not True:
            raise NewtonError(OWNER_CONFIRMATION_HELP)
        cp = self.run_script(device, "backup", device.destination)
        parsed = parse_backup(cp.stdout + cp.stderr)
        if cp.returncode or not parsed:
            log = script_log(cp)
            if log:
                raise DeviceTextError(log)
            raise NewtonError("backup failed")
        try:
            draft = _undo_plan.draft_undo(
                self.state,
                device_name,
                device.host,
                change_id,
                Path(parsed["backup_path"]),
                explanation,
            )
        except _undo_plan.UndoRefused as exc:
            raise NewtonError(str(exc)) from exc
        result = self.plan(
            device_name,
            draft.batch,
            explanation=draft.explanation,
            owner_confirmed_in_chat=owner_confirmed_in_chat,
            _tool="newton_plan_undo",
            _deleted_values=draft.deleted_values,
        )
        if "error" in result:
            return result
        session_id = result["session_id"]
        record_path = self.state / "plans" / f"{session_id}.json"
        try:
            record = json.loads(record_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise NewtonError(
                "the undo plan record cannot be read; plan the undo again"
            ) from exc
        if not isinstance(record, dict):
            raise NewtonError("the undo plan record cannot be read; plan the undo again")
        backup_path = record.get("backup_path")
        if not isinstance(backup_path, str) or not backup_path:
            raise NewtonError(
                "the undo plan record has no backup path; plan the undo again"
            )
        try:
            _undo_plan.verify_plan_base(draft, Path(backup_path))
        except _undo_plan.UndoRefused as exc:
            self.abort(device_name, session_id)
            raise NewtonError(str(exc)) from exc
        try:
            marked = _undo_plan.mark_undo(self.state, session_id, change_id)
        except _undo_plan.UndoRefused as exc:
            self.abort(device_name, session_id)
            raise NewtonError(str(exc)) from exc
        if not marked:
            self.abort(device_name, session_id)
            raise NewtonError(
                "the undo plan record could not be marked; plan the undo again"
            )
        return {
            **result,
            "undo_of": change_id,
            "packages": list(draft.packages),
            "not_undone": list(draft.not_undone),
        }

    def plan_tier(
        self,
        device_name: str,
        tier: str,
        batch_index: int = 0,
        values: dict[str, str] | None = None,
        timeout_s: int = 90,
        *,
        explanation: Any = None,
        owner_confirmed_in_chat: Any = None,
    ) -> dict[str, Any]:
        """Plan ONE batch of a hardening tier (R2).

        The full tier exceeds the router's sealed-probe cap, so ``tiers``
        (R1) splits it into ordered batches that each fit.  This method
        picks ``batch_index`` of those batches, resolves the
        ``{name}`` placeholders against ``values``, and calls the same
        ``plan()`` the existing tool uses -- so the seal, ADR-010 touched
        checks on the RESOLVED lines, the approval gate, the leash and
        the prod-profile decisions all apply unchanged.

        No automatic router lookups: ``values`` is the operator's
        payload, gathered with the existing read tool.  Fail closed: a
        missing / unknown / bad value name is refused BEFORE any device
        call (and the error message never echoes a rejected value).
        """
        device = self.device_for("newton_plan_tier", device_name)
        if tier not in _tiers.TIER_NAMES:
            raise NewtonError("tier must be one of: standard, hardened, lockdown")
        if isinstance(batch_index, bool) or not isinstance(batch_index, int):
            raise NewtonError("batch_index must be an integer")
        try:
            info = _tiers.split_tier(tier)
        except _tiers.TierError as exc:
            raise NewtonError(str(exc)) from exc
        batches_total = len(info["batches"])
        if not 0 <= batch_index < batches_total:
            raise NewtonError(
                f"batch_index out of range; this tier has batches_total={batches_total}"
            )
        try:
            _tiers.validate_values(values)
            batch = info["batches"][batch_index]
            tier_names = sorted({
                name
                for b in info["batches"]
                for name in _tiers.tier_placeholders(b["text"])
            })
            text = _tiers.resolve_batch(
                batch["text"], values, tier_names=tier_names
            )
        except _tiers.TierError as exc:
            raise NewtonError(str(exc)) from exc
        planned = self.plan(
            device_name, text, timeout_s, _tool="newton_plan_tier",
            explanation=explanation, owner_confirmed_in_chat=owner_confirmed_in_chat,
        )
        return {
            **planned,
            "tier": tier,
            "batch_index": batch_index,
            "batches_total": batches_total,
            "control_ids": batch["control_ids"],
            "skipped": info["skipped"],
        }

    def _refuse_failing_fw4(self, device_name: str) -> None:
        """Refuse plan() up front when `fw4 check` on the router already fails.

        A router whose firewall is already broken before any change is a
        bad place to plan a new write: the resulting plan can only be
        re-applied to a config that is itself invalid, and the apply-time
        health-snapshot catches this so late that the plan/approval steps
        are wasted.  This precheck runs `fw4 check` via the read lane and
        refuses with a clear message when fw4's own verdict (exit_code
        == 1) says the ruleset is bad.  Every other read-lane result
        (clean = 0, ssh timeout = 124, ssh failure = 125, no fw4 = 127,
        or the read lane's own refusal codes) lets plan() continue; the
        apply-time gate still owns those cases.

        The message names the first 3 non-empty lines of stdout+stderr
        so the operator sees fw4's own diagnostic.  Every line is run
        through the redactor before it reaches the message so a secret
        embedded in the fw4 output (e.g. a Password option) is masked
        rather than echoed back.
        """
        result = self.read(device_name, "fw4 check")
        if not isinstance(result, dict) or result.get("exit_code") != 1:
            return
        sources: list[str] = []
        for key in ("stdout", "stderr"):
            field = result.get(key)
            if isinstance(field, dict) and _envelope.is_envelope(field):
                sources.append(field.get("text") or "")
            elif isinstance(field, str):
                sources.append(field)
        lines: list[str] = []
        for text in sources:
            for raw in text.splitlines():
                line = raw.strip()
                if line:
                    lines.append(_redact.redact_text(line[:200]))
                if len(lines) >= 3:
                    break
            if len(lines) >= 3:
                break
        detail = " / ".join(lines[:3])
        # DeviceTextError, not plain NewtonError: the message embeds
        # router text (fw4's own diagnostic).  call_tool wraps
        # DeviceTextError in the untrusted-device-data envelope so the
        # model never reads device-originated text as instructions.
        raise DeviceTextError(
            "fw4 check already fails on the router before any change: "
            "fix the firewall first"
            + (f": {detail}" if detail else "")
        )

    def _resolve_placeholders(self, device_name: str, uci_batch: str) -> str:
        """Drop `set <path>=<redacted:fp>` lines whose fp matches the current value at <path>;
        refuse any other use of a placeholder token.
        """
        out_lines: list[str] = []
        placeholder_re = _redact.PLACEHOLDER_RE
        for raw_line in uci_batch.splitlines():
            if raw_line.strip().startswith(_explanation.DROPPED_PLACEHOLDER_PREFIX):
                # Only Newton writes this marker (below); it counts as a change
                # line, so an agent-written one would hide an undescribed change.
                raise NewtonError(
                    f"uci_batch lines may not start with {_explanation.DROPPED_PLACEHOLDER_PREFIX!r}: "
                    "that marker is written by Newton only"
                )
            flattened = raw_line.translate(str.maketrans("", "", "'\"\\"))
            if "<redacted:" not in flattened:
                out_lines.append(raw_line)
                continue
            stripped = raw_line.strip()
            if not stripped or stripped.startswith("#"):
                out_lines.append(raw_line)
                continue
            try:
                parts = shlex.split(stripped, posix=True)
            except ValueError as exc:
                raise NewtonError(
                    f"placeholder in {stripped[:120]!r}: invalid quoting ({exc})"
                ) from exc
            if len(parts) != 2 or parts[0] != "set" or "=" not in parts[1]:
                raise NewtonError(
                    f"placeholder in {stripped[:120]!r}: "
                    "placeholders may only be used as the value in `set <path>=<redacted:fp>` "
                    "(no surrounding text, no space form, no other verbs)"
                )
            path, _, value = parts[1].partition("=")
            ph_match = placeholder_re.fullmatch(value)
            any_fp = (placeholder_re.search(value) or placeholder_re.search(stripped))
            fp_msg = any_fp.group(1) if any_fp else "?"
            if ph_match is None:
                raise NewtonError(
                    f"placeholder <redacted:{fp_msg}> in {stripped[:120]!r}: "
                    "the value must be exactly one `<redacted:8hex>` placeholder "
                    "(no surrounding text, no embedded characters)"
                )
            placeholder_fp = ph_match.group(1)
            try:
                result = self.read(device_name, f"uci get {path}")
            except NewtonError:
                raise NewtonError(
                    f"placeholder <redacted:{placeholder_fp}> in {stripped[:120]!r}: "
                    f"current value at {path} could not be read"
                )
            if result.get("exit_code") != 0:
                raise NewtonError(
                    f"placeholder <redacted:{placeholder_fp}> in {stripped[:120]!r}: "
                    f"current value at {path} could not be read (exit={result.get('exit_code')})"
                )
            stdout_field = result.get("stdout") or ""
            # `read()` wraps stdout in an untrusted-device-data envelope; pull the
            # underlying text so the fingerprint check sees the value itself.
            if _envelope.is_envelope(stdout_field):
                stdout = stdout_field.get("text") or ""
            else:
                stdout = stdout_field
            if stdout.endswith("\n"):
                stdout = stdout[:-1]
            current_m = placeholder_re.fullmatch(stdout)
            if current_m:
                current_fp = current_m.group(1)
            else:
                current_fp = _redact.fingerprint(path, stdout)
            if current_fp != placeholder_fp:
                raise NewtonError(
                    f"placeholder <redacted:{placeholder_fp}> does not match the current value at {path}"
                    f" (line {stripped[:120]!r})"
                )
            out_lines.append(f"# dropped placeholder: {stripped}")
        suffix = "\n" if uci_batch.endswith("\n") else ""
        return "\n".join(out_lines) + suffix

    def apply(self, device_name: str, session_id: str) -> dict[str, Any]:
        device = self.device_for("newton_apply_change", device_name)
        if device.platform != "openwrt":
            return vendor_flow.apply(self, device, device_name, session_id)
        require_session(session_id)
        if device.access == "no-install":
            # (ADR-021 point 4) a no-install router is changed by
            # Newton itself over the router's own web API.  The
            # installed path stages the change on the router, and a
            # no-install router has no program of Newton on it.
            from . import noinstall_flow

            return noinstall_flow.apply(self, device_name, session_id)
        record_path = self.state / "plans" / f"{session_id}.json"
        try:
            record = json.loads(record_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise NewtonError("no plan record for this device and session") from exc
        if record.get("device") != device_name:
            raise NewtonError("no plan record for this device and session")
        if record.get("host") != device.host or record.get("session_id") != session_id:
            raise NewtonError("plan device or host changed since planning; plan again")
        try:
            actual_plan_hash = compute_plan_hash(record)
        except (TypeError, ValueError) as exc:
            raise NewtonError("plan record was modified or is invalid; plan again") from exc
        stored_plan_hash = record.get("plan_hash")
        if not isinstance(stored_plan_hash, str) or not hmac.compare_digest(stored_plan_hash, actual_plan_hash):
            raise NewtonError("plan record was modified or is invalid; plan again")
        timeout_s = record.get("timeout_s")
        probes_record = record.get("probes")
        base_hash = record.get("base_hash")
        router_digest = record.get("router_digest")
        if (
            isinstance(timeout_s, bool)
            or not isinstance(timeout_s, int)
            or not 60 <= timeout_s <= 600
            or not isinstance(probes_record, list)
            or not all(
                isinstance(probe, list) and all(isinstance(f, str) for f in probe)
                for probe in probes_record
            )
            or not isinstance(base_hash, str)
            or not re.fullmatch(r"[0-9a-f]{64}", base_hash)
            or not isinstance(router_digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", router_digest)
            or not isinstance(record.get("requires_approval"), bool)
        ):
            raise NewtonError("plan record was modified or is invalid; plan again")
        # a stored plan must still carry a valid explanation and the owner's
        # chat yes, and a device outside the lab carve-out must not run a plan
        # that says no approval is needed.  (The hash above already makes the
        # stored values tamper-evident; this catches a self-consistent record.)
        # A plan consented by a live grant carries no chat yes but
        # names its consent basis instead.
        if (
            record.get("owner_confirmed_in_chat") is not True
            and record.get("consent_basis") != "grant"
        ):
            raise NewtonError(
                "plan record has no owner_confirmed_in_chat; plan again after explaining to the owner and asking them"
            )
        try:
            checked_explanation = _explanation.parse_explanation(
                record.get("explanation"),
                change_lines=_explanation.change_lines(str(record.get("uci_batch", ""))),
                allow_targets=True,
            )
        except _explanation.ExplanationError as exc:
            raise NewtonError(f"plan record has an invalid explanation ({exc}); plan again") from exc
        # the claims must be the last sealed probes, or they would not be
        # checked after apply.
        if not _explanation.claims_match_probes(probes_record, checked_explanation):
            raise NewtonError(
                "plan record does not carry the explanation's expect claims as its last probes; plan again"
            )
        if record["requires_approval"] is not True and not _gate.lab_carve_out_applies(device):
            raise NewtonError(
                "this device requires approval for every change but the plan record says none is needed; plan again"
            )
        client_rows = _client_checks.client_claims(checked_explanation["expect"])
        spec_path: Path | None = None
        spec: dict[str, Any] | None = None
        spec_directory = self.state / "vantage-runs"
        if client_rows:
            try:
                vantages = self.scan_vantages()
                for _, claim in client_rows:
                    _client_checks.vantage_for_zone(
                        vantages, device_name, claim["zone"]
                    )
            except (
                NewtonError,
                _scans.ScanError,
                _client_checks.ClientCheckError,
            ) as exc:
                raise NewtonError(
                    "client check vantage no longer registered; plan again"
                ) from exc
            run_path = script_path().parent / "newton-vantage-run"
            if not run_path.is_file() or not os.access(run_path, os.X_OK):
                raise NewtonError("the vantage runner is missing")
            try:
                spec = _client_checks.build_spec(
                    session_id, checked_explanation["expect"], vantages, device_name
                )
            except _client_checks.ClientCheckError as exc:
                raise NewtonError(str(exc)) from exc
        token = "none"
        approval_window: tuple[int, int] | None = None
        reached_router = False
        cp: subprocess.CompletedProcess[str] | None = None
        timed_out_log: str | None = None
        try:
            if client_rows:
                try:
                    assert spec is not None
                    spec_path = spec_directory / f"{session_id}.json"
                    written_spec_path = _client_checks.write_spec(spec_directory, spec)
                    spec_path = written_spec_path
                except _client_checks.ClientCheckError as exc:
                    raise NewtonError(str(exc)) from exc
            if record.get("requires_approval") is True:
                # APR-05: consume_approval now CLAIMS the record
                # by renaming <sid>.json to <sid>.claimed; settle happens
                # in the finally block below once we know whether the
                # script reached the router.
                grant = self.consume_approval(device_name, session_id, record)
                token = grant.token
                approval_window = (grant.not_before, grant.not_after)
            try:
                # SW2 (design Item 2): the window goes with the token; the
                # router recomputes the HMAC over NBF/EXP, so an edited
                # expires_at cannot extend the approval.  With no approval
                # required (token none) nothing is passed: the wrapper
                # defaults NBF/EXP to 0 0.
                extra_env = {
                    "OWRT_EXPECT_BASE": base_hash,
                    "OWRT_APPROVAL_TOKEN": token,
                }
                if approval_window is not None:
                    extra_env["OWRT_APPROVAL_NBF"] = str(approval_window[0])
                    extra_env["OWRT_APPROVAL_EXP"] = str(approval_window[1])
                if client_rows:
                    try:
                        extra_env["OWRT_LOCAL_CHECK"] = _client_checks.local_check_string(run_path, session_id)
                    except _client_checks.ClientCheckError as exc:
                        raise NewtonError(str(exc)) from exc
                    extra_env["NEWTON_VANTAGE_SPEC_DIR"] = str(spec_directory)
                cp = self.run_script(
                    device,
                    "apply",
                    device.destination,
                    session_id,
                    str(timeout_s),
                    timeout=timeout_s + 300,
                    extra_env=extra_env,
                )
            except subprocess.TimeoutExpired as exc:
                # outcome unknown -- the run may have reached the
                # router; treat it as reached so the approval is
                # burned and the next apply cannot replay it.
                reached_router = True
                log = ((exc.stdout or "") if isinstance(exc.stdout, str) else "") + ((exc.stderr or "") if isinstance(exc.stderr, str) else "")
                timed_out_log = log
            else:
                # split on "\n" only -- device text is untrusted and
                # could carry U+2028/U+2029 separators (U-4).  A line
                # that is exactly ``APPLYING session=<sid>`` is the
                # signal owrt-change.sh prints right before it invokes
                # the helper over ssh; if the script got that far, the
                # token reached the router.  Mid-line occurrences do
                # NOT count.
                apply_token_line = f"APPLYING session={session_id}"
                reached_router = any(
                    line == apply_token_line
                    for line in (cp.stdout or "").split("\n")
                )
            finally:
                if record.get("requires_approval") is True:
                    self.settle_approval(session_id, reached_router=reached_router)
            if timed_out_log is not None:
                self._write_change_receipt(device_name, record, "unknown", timed_out_log)
                if timed_out_log:
                    return {"result": "unknown", "log": _envelope.envelope(f"{device_name}:apply", timed_out_log)}
                return {"result": "unknown", "log": "apply subprocess timed out"}
            assert cp is not None  # only reached on the non-timeout path
            stdout, confighash_text = _remove_config_hashes(cp.stdout or "")
            log = stdout + (cp.stderr or "")
            outcome: dict[str, Any] = {
                "result": classify_apply(cp.returncode, stdout, session_id),
                "log": _envelope.envelope(f"{device_name}:apply", log),
            }
            # A receipt for every change that ended CONFIRMED, ROLLED BACK or UNKNOWN.  An
            # error after the APPLYING line means the request reached the router, so it is UNKNOWN.
            receipt_outcome = outcome["result"] if outcome["result"] in _change_receipt.OUTCOME_WORDS else None
            if receipt_outcome is None and reached_router:
                receipt_outcome = "unknown"
            if receipt_outcome is not None:
                self._write_change_receipt(device_name, record, receipt_outcome, log)
            if outcome["result"] == "confirmed":
                try:
                    _undo_plan.record_after_hash(
                        self.state, session_id, confighash_text
                    )
                except Exception:
                    pass
            # Say which expect claim failed verify (the result is rolled_back;
            # the armed rollback restores the router).  Built from the stored claim,
            # not device text; the device supplies only a probe number, a probe name
            # and a reason word that must fit the strict shape.  A client claim
            # is named by the vantage runner's own line instead.
            if outcome["result"] != "confirmed":
                failed = _explanation.failed_claim(
                    stdout, session_id, probes_record, checked_explanation["expect"]
                )
                if failed is not None:
                    outcome["failed_claim"] = failed
            return outcome
        finally:
            if spec_path is not None:
                try:
                    spec_path.unlink()
                except Exception:
                    pass

    def _write_change_receipt(
        self, device_name: str, record: dict[str, Any], outcome: str, apply_output: str
    ) -> None:
        """Best effort: a receipt problem never changes the apply result."""
        try:
            path = _change_receipt.write_receipt(self.state, record, outcome, apply_output)
            if path is not None:
                write_audit(
                    "newton_receipt", device_name,
                    f"session={record.get('session_id')} outcome={outcome} file={path.name}",
                )
        except Exception:
            return

    def consume_approval(
        self, device_name: str, session_id: str, record: dict[str, Any]
    ) -> ApprovalGrant:
        """Validate the out-of-band approval record and CLAIM it.

        The checks are the earlier rounds'; the approval's ``token``
        (written by newton-approve, ^[0-9a-f]{64}$) is also returned now.
        A missing or malformed token is a refusal with a clear message,
        never a silent ``none``.

        A record that is not valid UTF-8, not valid JSON, has a non-dict
        body, an unparseable ``expires_at``, a missing token, or a token
        that is not 64 lowercase hex characters (notably 63 or 65) is
        refused with the same client-safe message; the bad file is left
        in place so the user can inspect it.

        SW2 (design Item 2): the approval window is bound into the token
        by newton-approve, so the record must carry it.  A record whose
        ``not_before``/``not_after`` are missing, not integers (a bool is
        not one here), not ordered, or not equal to the UNIX-second floors
        of its own ``created_at``/``expires_at`` is refused with
        OLD_APPROVAL_MSG -- it was written by an older newton-approve or
        edited after the fact.  That refusal runs BEFORE the expiry test.
        The grant returned carries the token and the window so apply()
        can hand both to the wrapper (``OWRT_APPROVAL_TOKEN``,
        ``OWRT_APPROVAL_NBF``, ``OWRT_APPROVAL_EXP``); the router
        recomputes the token over those numbers, so a window edited in the
        file fails there as ``bad-approval``.

        APR-05: the record is now CLAIMED here, not consumed.
        The file is renamed from <sid>.json to <sid>.claimed so a
        concurrent second apply (or a pre-router failure) cannot double-
        spend it.  apply() calls settle_approval() after run_script
        returns: if the script reached the router (stdout has the exact
        ``APPLYING session=<sid>`` line, or the run timed out so the
        outcome is unknown) the claim is converted to <sid>.used;
        otherwise it is restored to <sid>.json so the human approval
        can be reused on the next apply call.
        """
        approvals = self.state / "approvals"
        refusal = _receipts.check_state_write_path(approvals, self.state)
        if refusal is not None:
            raise NewtonError(refusal)
        approvals.mkdir(mode=0o700, parents=True, exist_ok=True)
        approval_path = approvals / f"{session_id}.json"
        claimed_path = approvals / f"{session_id}.claimed"
        used_path = approvals / f"{session_id}.used"
        invalid_msg = "approval record is invalid; ask the user to approve the plan again"
        try:
            raw = approval_path.read_bytes()
        except FileNotFoundError as exc:
            if used_path.exists():
                raise NewtonError("approval already used; ask the user to approve the plan again") from exc
            if claimed_path.exists():
                # a concurrent apply is in progress (or the previous one
                # crashed after claim and before settle); the human
                # approval is single-use under concurrency.
                raise NewtonError(
                    "approval is in use by an apply in progress; ask the user to approve the plan again if the in-flight apply did not succeed"
                ) from exc
            command = f"sudo -u newton /usr/local/bin/newton-approve {session_id}"
            raise NewtonError(
                f"approval required; ask the user to run `{command}` in their own terminal, then call apply again"
            ) from exc
        except OSError as exc:
            raise NewtonError(invalid_msg) from exc
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise NewtonError(invalid_msg) from exc
        try:
            approval = json.loads(text)
        except json.JSONDecodeError as exc:
            raise NewtonError(invalid_msg) from exc
        if not isinstance(approval, dict):
            raise NewtonError(invalid_msg)
        if approval.get("plan_id") != session_id:
            raise NewtonError("approval plan id mismatch")
        if approval.get("plan_hash") != record["plan_hash"]:
            raise NewtonError("approval plan hash mismatch; approve the current plan again")
        if approval.get("device") != device_name:
            raise NewtonError("approval device mismatch")
        if approval.get("base_hash") != record["base_hash"]:
            raise NewtonError("approval base hash mismatch; approve the current plan again")
        try:
            expires_at = datetime.fromisoformat(approval["expires_at"])
        except (KeyError, TypeError, ValueError) as exc:
            raise NewtonError(invalid_msg) from exc
        # SW2 (design Item 2): the approval window travels inside the v2
        # token as two integers.  A record that does not carry them, or
        # carries values that do not equal the floors of its own
        # created_at/expires_at, is either one an older newton-approve
        # wrote or one an agent edited after the fact -- both are refused
        # here, BEFORE the expiry test, so the operator is told to
        # approve again instead of being told the approval expired.
        not_before = approval.get("not_before")
        not_after = approval.get("not_after")
        if (
            isinstance(not_before, bool)
            or isinstance(not_after, bool)
            or not isinstance(not_before, int)
            or not isinstance(not_after, int)
            or not_after <= not_before
        ):
            raise NewtonError(OLD_APPROVAL_MSG)
        try:
            created_at = datetime.fromisoformat(approval["created_at"])
        except (KeyError, TypeError, ValueError) as exc:
            raise NewtonError(OLD_APPROVAL_MSG) from exc
        if (
            not_before != int(created_at.timestamp())
            or not_after != int(expires_at.timestamp())
        ):
            raise NewtonError(OLD_APPROVAL_MSG)
        if expires_at.tzinfo is None or expires_at <= datetime.now(timezone.utc):
            raise NewtonError("approval expired; ask the user to approve the plan again")
        token = approval.get("token")
        if not isinstance(token, str) or not re.fullmatch(r"[0-9a-f]{64}", token):
            raise NewtonError(invalid_msg)
        try:
            approval_path.replace(claimed_path)
        except FileNotFoundError as exc:
            # lost a race to another claim/settle; refuse like the
            # single-use case so the human is asked to approve again.
            if used_path.exists():
                raise NewtonError("approval already used; ask the user to approve the plan again") from exc
            if claimed_path.exists():
                raise NewtonError(
                    "approval is in use by an apply in progress; ask the user to approve the plan again if the in-flight apply did not succeed"
                ) from exc
            raise NewtonError(invalid_msg) from exc
        return ApprovalGrant(token, not_before, not_after)

    def settle_approval(
        self, session_id: str, *, reached_router: bool
    ) -> None:
        """Settle a previously CLAIMED approval.

        reached_router=True: rename <sid>.claimed to <sid>.used (the
        token reached the router and must not be reused).

        reached_router=False: rename <sid>.claimed back to <sid>.json
        so the human approval can be reused on the next apply call.

        The methods tolerate a missing <sid>.claimed -- apply() may call
        us after a validation failure inside consume_approval() already
        raised, and a crash between claim and settle is harmless to the
        next apply (consume_approval surfaces the in-use refusal above).
        The <sid>.json restore is also tolerant: a <sid>.json left
        behind by a previous settle of a different apply must not be
        overwritten.
        """
        approvals = self.state / "approvals"
        claimed_path = approvals / f"{session_id}.claimed"
        if not claimed_path.exists():
            return
        if reached_router:
            used_path = approvals / f"{session_id}.used"
            try:
                claimed_path.replace(used_path)
            except FileNotFoundError:
                pass
            return
        approval_path = approvals / f"{session_id}.json"
        if approval_path.exists():
            # a second approval file is already in place; drop the
            # stale claim so the in-use refusal above does not stick
            try:
                claimed_path.unlink()
            except FileNotFoundError:
                pass
            return
        try:
            claimed_path.replace(approval_path)
        except FileNotFoundError:
            pass

    def status(self, device_name: str, session_id: str) -> dict[str, Any]:
        device = self.device_for("newton_change_status", device_name)
        if device.platform != "openwrt":
            return vendor_flow.status(self, device, device_name, session_id)
        require_session(session_id)
        if device.access == "no-install":
            from . import noinstall_flow

            return noinstall_flow.status(self, device_name, session_id)
        cp = self.run_script(device, "status", device.destination, session_id)
        return {"exit_code": cp.returncode, "log": _envelope.envelope(f"{device_name}:status", script_log(cp))}

    def abort(self, device_name: str, session_id: str) -> dict[str, Any]:
        device = self.device_for("newton_abort_change", device_name)
        if device.platform != "openwrt":
            return vendor_flow.abort(self, device, device_name, session_id)
        require_session(session_id)
        if device.access == "no-install":
            from . import noinstall_flow

            return noinstall_flow.abort(self, device_name, session_id)
        cp = self.run_script(device, "abort", device.destination, session_id)
        return {"exit_code": cp.returncode, "log": _envelope.envelope(f"{device_name}:abort", script_log(cp))}


def parse_section_fact(section_line: str) -> tuple[tuple[str, str], tuple[str | None, str | None]] | None:
    """Parse one router SECTION line (without its ``SECTION `` prefix) into
    the policy's ``section_facts`` entry: ``((config, section), (type, name))``
    with ``-`` mapped to None (round m2 exposes the raw lines; this is the
    minimum the host policy needs of them)."""
    return parse_section_fact_line(section_line)


def require_session(session_id: str) -> None:
    if not isinstance(session_id, str) or not SESSION_RE.fullmatch(session_id):
        raise NewtonError("session_id must be 32 lowercase hexadecimal characters")


def script_log(cp: subprocess.CompletedProcess[str]) -> str:
    return (cp.stdout or "") + (cp.stderr or "")


def _remove_config_hashes(stdout: str) -> tuple[str, str]:
    """Return stdout without CONFIGHASH lines and their normalized text."""
    kept: list[str] = []
    hashes: list[str] = []
    for line in stdout.split("\n"):
        match = _CONFIGHASH_RE.fullmatch(line)
        if match is None:
            kept.append(line)
            continue
        hashes.append(f"{match.group(1)} {match.group(2)}\n")
    return "\n".join(kept), "".join(hashes)


def classify_apply(returncode: int, stdout: str, session_id: str) -> str:
    """Classify only unambiguous outcome lines emitted for this apply session."""
    sid = re.escape(session_id)
    # Device text is untrusted.  Python's universal line splitting also treats
    # U+2028/U+2029, NEL and several C0 controls as line boundaries; only the
    # protocol's LF (with an optional CRLF suffix) may create a classifier line.
    lines = [line.removesuffix("\r") for line in stdout.split("\n")]
    final = next((line for line in reversed(lines) if line.strip()), "")
    if returncode == 0 and re.match(rf"^CONFIRMED session={sid}(\s|$)", final):
        return "confirmed"
    if returncode == 1 and re.match(rf"^ROLLBACK WINDOW PASSED session={sid}(\s|$)", final):
        return "rolled_back"
    if (re.match(rf"^ALERT session={sid}(\s|$)", final)
            or "OUTCOME UNKNOWN" in final
            or any(re.match(rf"^APPLIED session={sid}(\s|$)", line) for line in lines)):
        return "unknown"
    return "error"


def parse_backup(output: str) -> dict[str, Any] | None:
    match = re.search(r"^BACKUP\s+(\S+)\s+\((\d+) config files\)", output, re.MULTILINE)
    return {"backup_path": match.group(1), "config_files": int(match.group(2))} if match else None


STAGEDCHECK_LINE_RE = re.compile(
    r"^STAGEDCHECK fw4 (?:(pass|skipped-untouched)|(not-checked) ([a-z0-9-]{1,40}))[ \t]*$", re.MULTILINE
)
PROBES_LINE_RE = re.compile(r"^PROBES ([0-9]{1,3}) ([0-9a-f]{64})\s*$", re.MULTILINE)
PROFILE_LINE_RE = re.compile(r"^PROFILE (lab|prod)\s*$", re.MULTILINE)
APPROVAL_LINE_RE = re.compile(r"^APPROVAL (required|not-required)\s*$", re.MULTILINE)
PLANDIGEST_LINE_RE = re.compile(r"^PLANDIGEST ([0-9a-f]{64})\s*$", re.MULTILINE)
SECTION_LINE_RE = re.compile(r"^SECTION (.+)$", re.MULTILINE)
LEASH_LINE_RE = re.compile(r"^LEASH (.+)$", re.MULTILINE)


def parse_plan(output: str) -> dict[str, Any] | None:
    """Parse the plan-branch owrt-change.sh output (design 3.5b/7.1).

    After STAGED the script echoes BASEHASH, PROBES <n> <sha>, PROFILE,
    SECTION lines, LEASH lines, APPROVAL required|not-required and
    PLANDIGEST <64hex>, then the masked diff.  A missing or malformed line
    (a digest that is not 64 hex, an APPROVAL that is neither word) is an
    error, not a guess: None comes back and plan() refuses.
    """
    backup = parse_backup(output)
    staged = re.search(r"^STAGED\s+session=([0-9a-f]{32})\b", output, re.MULTILINE)
    base_hash = re.search(r"^BASEHASH\s+([0-9a-f]{64})\s*$", output, re.MULTILINE)
    block = re.search(r"^----- diff -----\n(.*?)^----------------\s*$", output, re.MULTILINE | re.DOTALL)
    if not backup or not staged or not base_hash or not block:
        return None
    # the router-fact lines live before the diff block; diff text must not
    # be able to forge them
    head = output[: block.start()]
    probes_line = PROBES_LINE_RE.search(head)
    profile = PROFILE_LINE_RE.search(head)
    approval = APPROVAL_LINE_RE.search(head)
    digest = PLANDIGEST_LINE_RE.search(head)
    if not probes_line or not profile or not approval or not digest:
        return None
    diff = block.group(1).rstrip("\n")
    configs = sorted({_safe_config_name(m.group(1)) for line in diff.splitlines() if (m := re.match(r"^[-@^+]?([a-z0-9_-]+)\.", line.strip()))})
    # The staged-config check.  Exactly one well-formed line before the diff, else
    # the result is "not-checked": a missing or odd report is never read as a pass.
    reports = list(STAGEDCHECK_LINE_RE.finditer(head))
    if len(reports) == 1 and len(re.findall(r"^STAGEDCHECK\b", head, re.MULTILINE)) == 1:
        hit = reports[0]
        fw4, reason = (hit.group(1), "") if hit.group(1) else (hit.group(2), hit.group(3))
    else:
        fw4, reason = "not-checked", "no-report"
    staged_check = {
        "fw4": fw4,
        "reason": reason,
        # fw4's check covers the firewall config only; every other touched package has no
        # check before the apply (dnsmasq and the rest have no dry run), and a firewall
        # change that was not checked is listed too.
        "not_checked": [c for c in configs if not (c == "firewall" and fw4 == "pass")],
    }
    return {
        "staged_check": staged_check,
        "session_id": staged.group(1),
        "base_hash": base_hash.group(1),
        "diff": diff,
        "backup_path": backup["backup_path"],
        "touched_configs": configs,
        "probes_count": int(probes_line.group(1)),
        "probes_sha": probes_line.group(2),
        "profile": profile.group(1),
        "sections": [m.group(1) for m in SECTION_LINE_RE.finditer(head)],
        "leash": [m.group(1) for m in LEASH_LINE_RE.finditer(head)],
        "approval_required": approval.group(1) == "required",
        "digest": digest.group(1),
    }


def _safe_config_name(name: str) -> str:
    return name if name in KNOWN_UCI_CONFIGS else "other"


OWNER_CONFIRMATION_HELP = (
    "owner_confirmed_in_chat must be true. Next step: explain the change to the owner in plain "
    "words in the conversation (intent, one step per change line, what you expect to be true "
    "afterwards, and what could go wrong), ask them to confirm, and only after their yes call "
    "this tool again with owner_confirmed_in_chat=true and an explanation."
)
EXPLANATION_HELP = (
    "explanation is required: an object with intent (one line), steps (one short reason per "
    "change line), expect (1-8 claims, each {\"kind\": \"uci_equals\", \"path\": "
    "\"config.section.option\", \"equals\": \"text\"} or {\"kind\": \"probe\", \"probe\": "
    "[name, fields...]}) and risk (one or two lines)"
)


def _grant_waives_chat(
    device_name: str,
    uci_batch: str,
    owner_confirmed: Any,
    types: Mapping[tuple[str, str], str] | None = None,
) -> bool:
    """Does a live grant cover this change, so the owner's chat yes is not needed?

    A grant is the owner saying in advance: changes of this kind, on this
    device, are fine until <time>.  A change the grant covers needs no
    second yes in the chat, so the agent is not sent back to the owner
    for every change of an allowed kind.

    The answer is decided HERE, before any device contact, from the
    staged batch and the grant on disk: Newton decides what the change
    IS (:mod:`newton_mcp.change_classes`) and the grant says which
    classes it covers (:mod:`newton_mcp.grants`).  Nothing the agent
    says about the change can move the answer.

    A change that is HIGH, is not fully explained by the granted classes,
    or has no live grant is not waived.  Neither is a plan the owner
    already confirmed in chat: that plan is consented by the chat yes.
    """
    if owner_confirmed is True:
        return False
    if os.environ.get("NEWTON_GRANT_SKIPS_CHAT") == "0":
        # The kill switch: a grant never waives the chat yes.
        return False
    try:
        classification = _change_classes.classify(uci_batch, types=types)
        return _grants.covers(device_name, classification) is not None
    except (OSError, RuntimeError, ValueError):
        # A grant that cannot be read covers nothing.
        return False


def _grant_on_disk(device_name: str) -> bool:
    """Is there a live grant for this device?

    A grant may cover a change whose class needs the types the router
    holds, so the router is read before such a grant is answered.  A
    device without a grant never gets that read.
    """
    try:
        return _grants.load_live_grant(device_name) is not None
    except (OSError, RuntimeError, ValueError):
        return False


def _grant_can_waive_chat(device_name: str) -> bool:
    """May a live grant waive the owner's chat yes at all?

    The kill switch says no: with it, a grant never waives the chat
    yes, so the router may not be read before the owner's yes.  A
    device without a live grant may not be read before the owner's
    yes either.
    """
    if os.environ.get("NEWTON_GRANT_SKIPS_CHAT") == "0":
        return False
    return _grant_on_disk(device_name)


def check_explanation_inputs(
    explanation: Any,
    owner_confirmed: Any,
    change_lines: int,
    waived: bool = False,
    *,
    platform: str = "openwrt",
) -> dict[str, Any]:
    """Refuse a plan request without the owner's chat yes or a valid explanation.

    Returns the masked, plain-JSON explanation to store.  The owner flag is
    checked first so the agent is told to talk to the owner before it spends
    effort on the object.

    ``waived`` is True when a live grant covers the change: the
    grant IS the owner's consent, so the missing chat yes is not an error.
    The explanation is required either way.
    """
    if owner_confirmed is not True and not waived:
        raise NewtonError(OWNER_CONFIRMATION_HELP)
    if explanation is None:
        raise NewtonError(EXPLANATION_HELP)
    try:
        return _explanation.parse_explanation(
            explanation,
            change_lines=change_lines,
            platform=platform,
        )
    except _explanation.ExplanationError as exc:
        raise NewtonError(f"{exc}. {EXPLANATION_HELP}") from exc


def call_tool(tool: str, device: str, fn: Any) -> dict[str, Any]:
    # triage #3: the device name is checked before anything is logged or
    # looked up; the audit line for a bad name never carries the caller's text.
    if device != "-" and not (isinstance(device, str) and DEVICE_NAME_RE.fullmatch(device)):
        write_audit(tool, "-", "error invalid device name")
        return {"error": "invalid device name"}
    try:
        service = NewtonService()
        result = fn(service)
        write_audit(tool, device, str(result.get("result", "ok")))
        return _redact.redact_value(result)
    except DeviceTextError as exc:
        write_audit(tool, device, "error")
        return _redact.redact_value({"error": _envelope.envelope(f"{device}:{tool}", str(exc))})
    except NewtonError as exc:
        write_audit(tool, device, "error")
        return {"error": _redact.redact_text(str(exc))}
    except Exception:
        _log_unexpected_error(tool, device)
        write_audit(tool, device, "error")
        return {"error": "internal server error"}


mcp = FastMCP("Newton OpenWrt", instructions=_envelope.UNTRUSTED_DEVICE_DATA_NOTE)


def _envelope_docstring(prefix: str) -> str:
    """Build a tool description that embeds the UNTRUSTED_DEVICE_DATA_NOTE."""
    return f"{prefix}\n\n{_envelope.UNTRUSTED_DEVICE_DATA_NOTE}\n"


@mcp.tool()
def newton_list_devices() -> dict[str, Any]:
    """List devices from the local inventory."""
    return call_tool("newton_list_devices", "-", lambda s: s.list_devices())


@mcp.tool(description=_envelope_docstring(
    "Read one read-only command from a device. The command must be one verb\n"
    "with plain arguments (no shell operators, no quotes); the accepted forms\n"
    "are exactly:\n"
    "  uci show [CFG[.SECTION[.OPTION]]] | uci export [CFG] | uci changes [CFG] | uci get CFG.SECTION[.OPTION]\n"
    "  ubus list [OBJ] | ubus call system board|info, network.interface dump,\n"
    "    network.device status, network.wireless status, network.interface.NAME status\n"
    "  ifstatus IFACE | fw4 check|print | wifi status | uptime\n"
    "  nft list ruleset|tables | nft list table FAM TABLE | nft list chain|set|map|counter|quota|limit|flowtable FAM TABLE NAME\n"
    "  cat /etc/openwrt_release, /tmp/dhcp.leases, /proc/uptime, /proc/loadavg,\n"
    "    /proc/meminfo, /etc/config/NAME\n"
    "  iwinfo [IFACE [info|assoclist|txpowerlist|freqlist|countrylist|htmodelist]]\n"
    "  netstat|df|free|uname [FLAGS] | logread [-e PAT] [-l N]\n"
    "  apk list [-I|-u|-a] [PKG] | apk info [-L|-d|-s|-R|-r] PKG | apk search PKG\n"
    "  ping -c N HOST | traceroute HOST | nslookup HOST [SERVER]\n"
    "  ip [-4|-6] [-s] [-d] addr|address|route|link|neigh|rule [show|list] [dev IFACE] [table T] | ip [-4|-6] route get HOST\n"
    "On a no-install router only the reads its web API allows are available\n"
    "(config, status, logs, leases, ping, traceroute, nslookup); the others are\n"
    "refused by name and say what installed access would be needed.\n"
    "Returns the result inside an untrusted-device-data envelope (see server\n"
    "description)."
))
def newton_read(device: str, command: str) -> dict[str, Any]:
    return call_tool("newton_read", device, lambda s: _model_read(s, device, command))


def _model_read(service: NewtonService, device: str, command: str) -> dict[str, Any]:
    """newton_read's path: every read verb except the Wi-Fi scan.

    The scan transmits and returns neighbours' names and addresses, so it
    runs only through newton_plan_scan / newton_run_scan (owner consent,
    summaries only); _run_wifi_scan calls service.read directly.
    """
    if validate_read(command)[0] == "wifiscan":
        raise NewtonError(
            "wifiscan is not a read: plan it with newton_plan_scan(kind='wifi'), "
            "the owner approves it, then newton_run_scan returns a summary"
        )
    return service.read(device, command)


@mcp.tool(description=_envelope_docstring(
    "Snapshot a device's /etc/config to the local backup dir. The returned "
    "backup_path comes from the device and is returned inside an "
    "untrusted-device-data envelope."
))
def newton_backup(device: str) -> dict[str, Any]:
    return call_tool("newton_backup", device, lambda s: s.backup(device))


_PROBE_TABLE_DOC = """\
Stage a plan with structured verification probes and a rollback timeout.
There is no shell check any more (the old `check` parameter is gone);
verification is a fixed set of router probes.

`probes` is a list of probe lines; each line is a list of fields, the first
being the probe name. Fields are joined with TABs on the wire; every field
is 1-128 printable bytes (no backslash), a line is at most 512 bytes, and at
most 32 lines / 4096 bytes fit in one plan. The 19 probes (fields after the
name; brackets = optional with the shown default):
  fail
  ping HOST [COUNT 1-3, default 1]
  resolve HOST [SERVER, default 127.0.0.1]
  service-running SERVICE INSTANCE('any' or IFACE) [present|absent, default present]
  uci-equals CFG.SECTION.OPTION TEXT          (refused on secret-looking options)
  uci-unset CFG.SECTION[.OPTION]              (refused on secret-looking options)
  listen tcp|udp ADDR(any|wildcard|address) PORT PROG(any|name) EXPECT
  nft-rule FAM TABLE CHAIN|ruleset EXPECT TEXT [TEXT x3]
  nft-rule-order FAM TABLE CHAIN TEXT-A TEXT-B
  nft-rule-near FAM TABLE CHAIN|ruleset TEXT-A NEAR(1-10) TEXT-B
  nft-set-has FAM TABLE SET ELEMENT present|absent|only
  conf-has dnsmasq line|prefix|substr EXPECT TEXT  (also counts /tmp/hosts/dhcp.<SUF> for each conf file)
  proc-args PROC SPEC [SPEC x7]               (SPEC: '~TEXT', '!SPEC' or 1-4 elements)
  iface-field IFACE FIELD(up|available|pending|autostart|dynamic|proto|device|l3_device) TEXT
  iface-absent IFACE
  sysctl-equals KEY TEXT                      (KEY: family/part[...], no '.' or '..' part)
  ra-absent IFACE
  log-has EXPECT TEXT [TEXT x2]               (EXPECT: present|absent|eq:N|min:N)
  root-password-class EMPTY|LOCKED|HASH|NOROOT|MULTIROOT
TEXT fields may start with '!' for a negative match. An empty probe list
means only the built-in steps (ping, DNS, DHCP test, health) run.

`manifest_checks` is a list of control ids (^[A-Za-z0-9_.-]{1,64}$, each at
most once) expanded to extra probe lists from the manifest BEFORE the
caller's probes; a control whose check has no probe form yet is refused.

Before planning, explain the change to the owner in plain words (intent, one
step per change line, what you expect afterwards, what could go wrong), ask
them to confirm, and only after their yes pass ``owner_confirmed_in_chat=true``
together with ``explanation``: an object with
  intent   one line: what the owner asked for (max 160 chars)
  steps    one short reason per change line, in order (batch lines that are
           not blank or `#` comments; each max 160 chars; the count must match)
  expect   1-8 claims about the state after apply, each
           {"kind": "uci_equals", "path": "config.section.option", "equals": "text"}
           or {"kind": "probe", "probe": ["<probe name>", fields...]} (any probe above)
  risk     what could break and how the owner would notice (max 300 chars, 1-2 lines)
Text must be printable (control characters are refused) and secrets are
masked. The explanation is YOUR claim: the owner sees it under "Agent's
explanation (unchecked claims)" next to Newton's own facts, and it is inside
the plan hash, so changing it needs a new plan and a new approval.

Every change needs the owner's approval (the lab carve-out below aside): the
plan needs approval unless the device is flagged ``lab = true`` with
``profile = "lab"`` and neither the router's leash/profile nor the host policy
says so. When the result has
``requires_approval`` true, tell the user to run
``sudo -u newton /usr/local/bin/newton-approve <session_id>`` (the
session_id this plan returned) in their own terminal, then call
``newton_apply_change``. The diff and backup_path fields come from the
device and are returned inside untrusted-device-data envelopes."""


@mcp.tool(description=_envelope_docstring(_PROBE_TABLE_DOC))
def newton_plan_change(
    device: str,
    uci_batch: str,
    timeout_s: int | None = None,
    probes: list[list[str]] | None = None,
    manifest_checks: list[str] | None = None,
    explanation: dict[str, Any] | None = None,
    owner_confirmed_in_chat: bool | None = None,
) -> dict[str, Any]:
    return call_tool(
        "newton_plan_change",
        device,
        lambda s: s.plan(
            device, uci_batch, timeout_s, probes, manifest_checks,
            explanation=explanation, owner_confirmed_in_chat=owner_confirmed_in_chat,
        ),
    )


@mcp.tool(description=_envelope_docstring(
    "Undo a CONFIRMED change by id. Newton builds the changes; give only "
    "intent and risk in explanation; conflicts with later changes REFUSE "
    "the whole undo and are listed; packages, passwords, reboots and client "
    "leases are not undone; needs the owner's yes in chat and newton-approve "
    "like any change."
))
def newton_plan_undo(
    device: str,
    change_id: str,
    explanation: dict[str, Any] | None = None,
    owner_confirmed_in_chat: bool | None = None,
) -> dict[str, Any]:
    return call_tool(
        "newton_plan_undo",
        device,
        lambda s: s.plan_undo(
            device,
            change_id,
            explanation,
            owner_confirmed_in_chat,
        ),
    )


_APPLY_CHANGE_DESCRIPTION = _envelope_docstring(
    "Apply a saved plan. If approval is needed the owner is shown a dialog in their client and answers it; "
    "if the client cannot show one, tell the owner to run the newton-approve command in the error. "
    "The session_id comes from newton_plan_change. The log field comes from the device and is returned "
    "inside an untrusted-device-data envelope (server-side messages stay bare)."
)


def newton_apply_change(device: str, session_id: str) -> dict[str, Any]:
    """Apply a saved plan without opening the owner's approval dialog."""
    return call_tool(
        "newton_apply_change", device, lambda s: s.apply(device, session_id)
    )


@mcp.tool(name="newton_apply_change", description=_APPLY_CHANGE_DESCRIPTION)
async def _apply_change_tool(
    device: str,
    session_id: str,
    ctx: Context,
) -> dict[str, Any]:
    from . import approve
    from . import grants
    from . import notice

    valid_device = isinstance(device, str) and DEVICE_NAME_RE.fullmatch(device)
    valid_session = isinstance(session_id, str) and SESSION_RE.fullmatch(session_id)

    def _summary() -> str:
        if not valid_session:
            return "(plan not available)"
        try:
            record = approve._load_plan(session_id)
            batch = record.get("uci_batch")
            if not isinstance(batch, str):
                return "(plan not available)"
            lines = _consequences.describe(batch)
        except (OSError, ValueError, TypeError):
            return "(plan not available)"
        return lines[0] if lines else "(plan not available)"

    summary = _summary()
    shown_device = device if valid_device else "-"
    shown_session = session_id if valid_session else ""

    def _finish(
        result: dict[str, Any], outcome: elicit_approval.Outcome
    ) -> dict[str, Any]:
        result["newton_result"] = notice.result_line(
            result,
            shown_device,
            shown_session,
            summary,
            outcome.grant_note,
        )
        # Any attempt that reached the router and did not confirm ends the
        # grant, whichever way the approval was reached (a dialog, the
        # grant itself or an approval that was already on disk).
        grant_ended = (
            outcome.grant_used
            or outcome.grant_note.startswith(elicit_approval.GRANT_OPENED_PREFIX + ":")
            or outcome.status in ("approved", "skip")
        )
        if grant_ended and result.get("result") != "confirmed":
            # The line says a grant ended, so a grant must have been open.
            # A record that is expired or malformed was never a live grant
            # (load_live_grant deletes it) and a device that never had one
            # has nothing to end: the result line must not claim it.
            ended = False
            try:
                if grants.load_live_grant(device) is not None:
                    ended = grants.revoke_grant(device)
            except (OSError, ValueError):
                ended = False
            if ended:
                result["newton_result"] += "  EASY GRANT ENDED."
        if outcome.grant_note:
            result["grant_notice"] = outcome.grant_note
        return result

    if not valid_device:
        write_audit("newton_apply_change", "-", "error invalid device name")
        return _finish(
            {"error": "invalid device name"},
            elicit_approval.Outcome("fallback", "invalid device name"),
        )
    try:
        outcome = await elicit_approval.collect_approval(ctx, device, session_id)
    except Exception:
        # the same shape as call_tool's generic branch: the model sees
        # only a short error, the real cause goes to the on-disk log
        _log_unexpected_error("newton_apply_change", device)
        write_audit("newton_apply_change", device, "error")
        return _finish(
            {"error": "internal server error"},
            elicit_approval.Outcome("fallback", "internal server error"),
        )
    if outcome.status in {"fallback", "declined", "wrong", "locked"}:
        write_audit(
            "newton_apply_change",
            device,
            "error approval " + outcome.status,
        )
        return _finish(
            {"error": _redact.redact_text(outcome.message)}, outcome
        )
    result = await asyncio.to_thread(newton_apply_change, device, session_id)
    if not isinstance(result, dict):
        result = {"error": "internal server error"}
    result = _finish(result, outcome)
    if outcome.notice:
        # the owner has to be told once: the passphrase was on the
        # screen they typed it on, and it may still be there
        result["approval_notice"] = outcome.notice
    return result


@mcp.tool(description=_envelope_docstring(
    "Query the live status of an applied session. The log field comes from "
    "the device and is returned inside an untrusted-device-data envelope."
))
def newton_change_status(device: str, session_id: str) -> dict[str, Any]:
    return call_tool("newton_change_status", device, lambda s: s.status(device, session_id))


@mcp.tool(description=_envelope_docstring(
    "Abort an in-flight session. The log field comes from the device and is "
    "returned inside an untrusted-device-data envelope."
))
def newton_abort_change(device: str, session_id: str) -> dict[str, Any]:
    return call_tool("newton_abort_change", device, lambda s: s.abort(device, session_id))


@mcp.tool(description=_envelope_docstring(
    "End the easy grant on a device. It can only end or narrow a grant, never "
    "open or widen one."
))
def newton_grant_off(device: str) -> dict[str, Any]:
    from . import grants

    def end_grant(service: NewtonService) -> dict[str, Any]:
        known = service.device_for("newton_grant_off", device)
        return {
            "result": "ok",
            "revoked": grants.revoke_grant(known.name),
        }

    return call_tool("newton_grant_off", device, end_grant)


@mcp.tool(description=_envelope_docstring(
    "Plan a consent-gated scan without running it. kind is inside, outside or "
    "wifi; profile is quick, full-tcp or survey. For inside, interface is "
    "required and must name a non-WAN router interface. For wifi, profile is "
    "survey and interface names the router's own radio (radio0, radio1); the "
    "survey runs with that radio, sends probe requests on every channel and "
    "keeps channel counts and look-alike network names only. Newton derives "
    "the exact IPv4 target of an nmap scan from router reads and selects the "
    "inventory's single matching vantage; callers cannot supply a target, "
    "host, port, flag, or vantage. The returned request must be approved out "
    "of band with newton-approve."
))
def newton_plan_scan(
    device: str,
    kind: Literal["inside", "outside", "wifi"],
    profile: Literal["quick", "full-tcp", "survey"],
    interface: str | None = None,
) -> dict[str, Any]:
    return call_tool(
        "newton_plan_scan",
        device,
        lambda s: s.plan_scan(device, kind, profile, interface),
    )


@mcp.tool(description=_envelope_docstring(
    "Run one stored scan request after the owner approved that exact request "
    "with newton-approve. Consent is single-use, expires after at most 30 "
    "minutes, and is consumed before the registered vantage starts. For an "
    "nmap scan only validated IPv4 addresses and open TCP ports are "
    "retained; raw nmap output, hostnames, MACs, vendors, and OS data are "
    "discarded. For a wifi survey the router scans with its own radio and "
    "only channel counts and look-alike network names are kept; every name "
    "comes back inside an untrusted-device-data envelope and no BSSID is "
    "kept at all."
))
def newton_run_scan(device: str, request_id: str) -> dict[str, Any]:
    return call_tool(
        "newton_run_scan", device, lambda s: s.run_scan(device, request_id)
    )


@mcp.tool(description=_envelope_docstring(
    "List the three hardening tiers with their batch count, probe lines, "
    "placeholder names, and the controls the planner will NEVER carry. A "
    "tier is a hardening level, not a device profile; it is applied batch "
    "by batch in order, each batch is its own plan / approval / apply / "
    "confirm cycle, so a failed batch rolls back only itself while "
    "earlier batches stay applied. Controls in `skipped` are lab-bound "
    "(name a lab-only interface, zone or address) or conditional (need a "
    "package the router does not have) and are never planned. Resolve the "
    "placeholder values for the chosen batch with the existing read tool "
    "(e.g. `uci get`) before calling `newton_plan_tier`. A placeholder like "
    "`{fw_wan_zone}` wants the UCI section id (e.g. `@zone[1]` or a named "
    "section id), NOT the zone's name option (`wan`)."
))
def newton_list_tiers() -> dict[str, Any]:
    return call_tool("newton_list_tiers", "-", lambda s: s.list_tiers())


@mcp.tool(description=_envelope_docstring(
    "Plan ONE batch of a hardening tier. The full tier exceeds the "
    "router's sealed-probe cap, so it is split into ordered batches that "
    "each fit; pick the batch with `batch_index` (0-based). A placeholder "
    "like `{fw_wan_zone}` wants the UCI section id (e.g. `@zone[1]` or a "
    "named section id), NOT the zone's name option (`wan`). `values` "
    "resolves the {name} placeholders of the chosen batch (use the "
    "existing read tool to look them up first). Fail closed: a missing / "
    "unknown / malformed value name is refused BEFORE any device call, "
    "and the error message never echoes a rejected value. The router's "
    "diff + section facts go through the same plan path `newton_plan_"
    "change` uses, so the seal, ADR-010 touched checks on the RESOLVED "
    "lines, approval gate, leash and prod-profile decisions all apply. "
    "When `requires_approval` is true, the user runs `sudo -u newton "
    "/usr/local/bin/newton-approve <session_id>` and then calls "
    "`newton_apply_change` -- there is no tier-apply tool. `timeout_s` "
    "is 60..600 (default 90). The returned `batches_total` tells the "
    "agent how many more batches the tier has; `skipped` lists every "
    "control the planner never carries for this tier. Like `newton_plan_change`, "
    "it requires `owner_confirmed_in_chat=true` (explain the batch to the owner "
    "and get their yes first) and an `explanation` object (intent, steps with "
    "exactly one short reason per change line of the batch, expect with 1-8 "
    "claims, risk); a wrong steps count is refused and the error says how many "
    "change lines the batch has. Every change needs the owner's approval."
))
def newton_plan_tier(
    device: str,
    tier: Literal["standard", "hardened", "lockdown"],
    batch_index: int = 0,
    values: dict[str, str] | None = None,
    timeout_s: int = 90,
    explanation: dict[str, Any] | None = None,
    owner_confirmed_in_chat: bool | None = None,
) -> dict[str, Any]:
    return call_tool(
        "newton_plan_tier",
        device,
        lambda s: s.plan_tier(
            device, tier, batch_index, values, timeout_s,
            explanation=explanation, owner_confirmed_in_chat=owner_confirmed_in_chat,
        ),
    )


@mcp.tool(description=_envelope_docstring(
    "Run the fixed six-item guided read-only audit for one device: listeners, "
    "services, port forwards, UPnP, Wi-Fi settings, and DHCP devices. Every "
    "router access delegates to the same validated newton_read path; one "
    "failed read is recorded and does not stop the remaining reads. Device "
    "stdout and stderr stay inside untrusted-device-data envelopes, and the "
    "result distinguishes successful non-empty, successful empty, and failed "
    "reads. This tool performs no scans and makes no changes."
))
def newton_guided_audit(device: str) -> dict[str, Any]:
    return call_tool(
        "newton_guided_audit", device, lambda s: s.guided_audit(device)
    )


@mcp.tool(description=_envelope_docstring(
    "List the experimental read-only getters (T0-exp) for one non-OpenWrt "
    "device: getter id, enabled, parameter slots and patterns, verification "
    "state. No device contact. OpenWrt devices use newton_read."
))
def newton_list_getters(device: str) -> dict[str, Any]:
    return call_tool(
        "newton_list_getters", device, lambda s: s.list_getters(device)
    )


@mcp.tool(description=_envelope_docstring(
    "Run the read-only Active Directory audit on one AD device (platform "
    "ad-windows or ad-samba). The collector document is fetched over ssh "
    "with the forced command of the platform and is validated against the "
    "collector contract before a single check runs; the collector reads "
    "the directory first, and a privileged key is then refused before any "
    "check runs. `checks` is an optional list of check "
    "ids (newton_ad_list_checks lists them); without it every check of the "
    "catalogue runs. The report holds the counts and the result of every "
    "check; every directory string in it is inside an untrusted-device-data "
    "envelope (see server description). This tool changes nothing."
))
def newton_ad_audit(
    device: str,
    checks: list[str] | None = None,
) -> dict[str, Any]:
    return call_tool(
        "newton_ad_audit", device, lambda s: s.ad_audit(device, checks)
    )


@mcp.tool(description=_envelope_docstring(
    "List the checks of the read-only Active Directory audit: id, title, "
    "severity and the platforms each check runs on, plus the checks the "
    "spec defers to the change release. No device contact."
))
def newton_ad_list_checks() -> dict[str, Any]:
    return call_tool(
        "newton_ad_list_checks", "-", lambda s: s.ad_list_checks()
    )


@mcp.tool(description=_envelope_docstring(
    "Plan one Active Directory change in one domain (SPEC-1.4). The device "
    "is the write entry that stands for the domain: the DCs of that domain "
    "name it in their `ad_domain`. `verb` is one of "
    "uac-clear, disable, enable, enc-types, unlock, member-add, "
    "member-remove, maq, user-create or move. `sam_names` holds the "
    "sAMAccountNames of the target: one for an account, two for a "
    "membership (the group first), none for maq. `value` holds the int or "
    "the guid the verb needs: the bit of a uac-clear (4194304, 32, 128 "
    "or 65536; 524288 is refused, as it needs SeEnableDelegationPrivilege), "
    "the encryption types of enc-types, the quota of "
    "maq, the new parent of a move and the parent of a user-create. "
    "The undo window of a plan is 600 s; an unlock arms no undo and is "
    "confirmed once written (its window field is fixed at 120). "
    "The plan lists in `dcs` the DCs the apply will read back: only the "
    "DCs of the domain with a write entry in the inventory. A DC without "
    "a write entry is never read, and `warning` says so. "
    "Nothing else is accepted: a filter, a DN and free text are refused "
    "before anything is read. The plan is written under the state "
    "directory with mode 0600 and the owner approves it out of band with "
    "`sudo -u newton /usr/local/bin/newton-approve ad-change <plan_id>`; "
    "this tool never approves "
    "anything. Every string the directory gave is inside an "
    "untrusted-device-data envelope."
))
def newton_ad_plan_change(
    device: str,
    verb: str,
    sam_names: list[str] | None = None,
    value: int | str | None = None,
) -> dict[str, Any]:
    return call_tool(
        "newton_ad_plan_change",
        device,
        lambda s: s.ad_plan_change(device, verb, sam_names, value),
    )


@mcp.tool(description=_envelope_docstring(
    "Apply one approved Active Directory change and verify it on every DC "
    "of its domain with a write entry in the inventory (SPEC-1.4). A DC of "
    "the domain without a write entry is never read. The device is the "
    "write entry that stands "
    "for the domain. The plan must be approved already: the "
    "approval comes from "
    "`sudo -u newton /usr/local/bin/newton-approve ad-change <plan_id>`, "
    "never from "
    "this server. The change is applied on the domain controller, the "
    "target is read back from each of those DCs over a fresh session, and "
    "the confirm is sent only when each of them shows the after-image. A DC that "
    "does not catch up in time is NOT TESTED and the change is aborted "
    "instead (an unlock is not aborted: it has no undo and stays "
    "written); the result then carries restored and the conflicts of the "
    "undo, or the state abort_failed when the undo did not run (the DC "
    "refused the abort or it did not arrive). The undo is armed on the "
    "domain controller until Newton "
    "confirms, and the apply confirms or aborts before it returns. If the "
    "connection to a domain controller fails mid-apply, the receipt is "
    "still written and the state names the step that was lost: "
    "apply_unknown (Newton does not know whether the change was written), "
    "confirm_unknown (every DC showed it, and the confirm may not have "
    "arrived) or abort_failed. Then run newton_ad_change_status to read the "
    "change from the DC: a change that is not confirmed is put back by the "
    "DC itself at its undo_at, except an unlock, which has no undo and "
    "stays written. A connection lost while a DC is read back counts as "
    "that DC not showing the change, so the change is aborted, except an "
    "unlock. A request Newton refuses before it is sent is refused: "
    "nothing was sent. Once "
    "confirmed, Newton does not undo a change: the owner plans the reverse "
    "change. An unlock has no undo and is written at once. The receipt is written under the state directory and never "
    "holds the password of a user-create. Every string the directory gave "
    "is inside an untrusted-device-data envelope."
))
def newton_ad_apply_change(device: str, plan_id: str) -> dict[str, Any]:
    return call_tool(
        "newton_ad_apply_change",
        device,
        lambda s: s.ad_apply_change(device, plan_id),
    )


@mcp.tool(description=_envelope_docstring(
    "The state of one Active Directory change, as the domain controller "
    "holds it: armed, confirmed, undone, undo_failed or refused, with the "
    "undo deadline and the conflicts of the undo. Every string the "
    "directory gave is inside an untrusted-device-data envelope."
))
def newton_ad_change_status(device: str, plan_id: str) -> dict[str, Any]:
    return call_tool(
        "newton_ad_change_status",
        device,
        lambda s: s.ad_change_status(device, plan_id),
    )


@mcp.tool(description=_envelope_docstring(
    "Abort one Active Directory change. This works only on a change still "
    "armed: written and not yet confirmed, which covers the window while "
    "Newton is still verifying it and an apply cut off before its confirm. "
    "The apply confirms or aborts before it returns, so after a normal apply "
    "the abort is refused with conflict; when the domain controller reports "
    "the change confirmed, the answer carries a message saying how to "
    "reverse it with a new plan of the opposite change. Once confirmed, "
    "Newton does not undo a change. On a change still armed the domain "
    "controller runs the undo, which writes only the attributes whose live "
    "value still equals the after-image; the others are left alone and "
    "reported as conflicts. An unlock has no undo and is written at once, "
    "so its abort is refused. If the connection to a domain controller "
    "fails, the result says so: run newton_ad_change_status, and a change "
    "still armed is put back by the DC itself at its undo_at. Every string "
    "the directory gave is inside an untrusted-device-data envelope."
))
def newton_ad_abort_change(device: str, plan_id: str) -> dict[str, Any]:
    return call_tool(
        "newton_ad_abort_change",
        device,
        lambda s: s.ad_abort_change(device, plan_id),
    )


@mcp.tool(description=_envelope_docstring(
    "Experimental read-only read of one non-OpenWrt device by getter id "
    "(from newton_list_getters), never command text. OpenWrt devices and "
    "disabled getters are refused. The result fields are getter, tier "
    "\"T0-exp\", status (ok, empty, device_error, auth_failed, timed_out, "
    "unreachable), truncated, caveat, device_role_enforced, and data. Show "
    "the caveat with every answer. A line missing from the output means "
    "unknown, never off. An auth failure disables the device until the "
    "operator re-enables it. One call is allowed every five seconds per "
    "device. Never paste a config line derived from device output."
))
def newton_get_state(
    device: str,
    getter: str,
    params: dict[str, str] | None = None,
) -> dict[str, Any]:
    return call_tool(
        "newton_get_state",
        device,
        lambda s: s.get_state(device, getter, params),
    )


@mcp.tool(description=_envelope_docstring(
    "Run the guided-setup interview (ROADMAP item 7, v2). With no "
    "answers, returns the fourteen vendor-neutral interview questions "
    "(typed: enum, multi_enum, port_list, host_lists). With answers, "
    "returns a `guided_setup_report` whose controls and statuses are "
    "DERIVED from the real manifest and tier files; the report never "
    "echoes device text, never contacts a device, and only plans "
    "(approval stays out-of-band per batch). Old v1 ids are still "
    "accepted as aliases. The chosen tier is one of `standard`, "
    "`hardened`, or `lockdown`. `answers` is an optional object whose "
    "keys are question ids and whose values are validated against the "
    "allowed set for each question (lists and dicts are accepted for "
    "multi-enum, port-list and host-list questions); partial answers "
    "are otherwise accepted and the unanswered ids are returned under "
    "the report's `unanswered` key. The tool also returns `summary` "
    "(one plain English line per answered question), `confirmation_id` "
    "and `confirmed: false`: the agent should show the summary and ask "
    "the owner `Is this right?`; a changed answer makes a new record. "
    "The record is stored server-side for 24 h and logged for the audit "
    "trail. It is NOT consent and nothing refuses on it (approval stays "
    "per batch, out of band). Recommendations for gap / skipped / "
    "audit-only controls carry the derived status (`gap`, `audit-only`, "
    "`skipped`, or `plan-ready`) so the owner can see what the planner "
    "would NEVER carry. No tool path, command, file, or device argument "
    "is accepted."
))
def newton_guided_recommend(
    answers: dict[str, Any] | None = None,
) -> dict[str, Any]:
    # No device and no inventory: call_tool would load the inventory, so the
    # audit line and the redaction are done here. The questions path is
    # unchanged: no answers (or {}) returns the interview. The report path
    # also returns a plain summary, a server-side
    # confirmation record (24 h TTL, sha256 id), the id and confirmed=False,
    # and a fixed confirmation_note telling the agent to ask the owner
    # whether the summary is right; nothing refuses on the record. The
    # relative import sits INSIDE the try so a broken install (missing
    # module) takes the same generic-error path as any other unexpected
    # exception: one mcp-errors.log entry and ``{"error": "internal server error"}``.
    confirmation_note = (
        "Newton stored this interview summary server-side for 24 h and is "
        "logging the confirmation_id for the audit trail. Ask the owner "
        "\"Is this right?\"; a changed answer makes a new record. This "
        "is NOT consent and nothing refuses on the record: approval for "
        "writes still happens per batch, out of band."
    )
    # A store that raised OSError saved nothing, so the note must not claim
    # the record exists: confirmation_id and confirmation_expires_at are None
    # and the audit line already says confirmation=none.
    confirmation_not_stored_note = (
        "Newton could not store this interview summary: the confirmation "
        "record was NOT stored and nothing was saved, so there is no "
        "confirmation_id and nothing to log for the audit trail (the "
        "audit line records confirmation=none). Show the summary to the "
        "owner and ask \"Is this right?\" anyway; a later run with a "
        "writable state directory stores the record. This is NOT consent "
        "and nothing refuses on it: approval for writes still happens per "
        "batch, out of band."
    )
    try:
        from . import guided as _guided
        if not answers:
            out: dict[str, Any] = {"result": "ok", "questions": _guided.questions()}
        else:
            report = _guided.recommend(answers)
            text = _guided.summary(answers)
            record = _guided.confirmation_record(
                answers, text, device="-", platform="openwrt",
            )
            try:
                _guided.store_confirmation(record, state_dir())
                conf_id = record["id"]
                conf_expires = record["expires_at"]
                audit_suffix = f"confirmation={conf_id}"
                note = confirmation_note
            except OSError:
                conf_id = None
                conf_expires = None
                audit_suffix = "confirmation=none"
                note = confirmation_not_stored_note
            out = {
                "result": "ok",
                "report": report,
                "summary": text,
                "confirmation_id": conf_id,
                "confirmed": False,
                "confirmation_expires_at": conf_expires,
                "confirmation_note": note,
            }
    except NewtonError as exc:
        write_audit("newton_guided_recommend", "-", "error")
        return {"error": _redact.redact_text(str(exc))}
    except Exception:
        _log_unexpected_error("newton_guided_recommend", "-")
        write_audit("newton_guided_recommend", "-", "error")
        return {"error": "internal server error"}
    if answers:
        write_audit("newton_guided_recommend", "-", f"ok {audit_suffix}")
    else:
        write_audit("newton_guided_recommend", "-", "ok")
    return _redact.redact_value(out)


def main() -> None:
    mcp.run(transport="stdio")
