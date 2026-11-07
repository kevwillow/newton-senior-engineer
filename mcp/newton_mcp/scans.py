"""Consent-gated host-side nmap scan support (ROADMAP item 7, I7b R1).

The model chooses only a scan kind and profile.  Targets come from validated
router reads, and execution is possible only through a registered vantage and
an out-of-band consent record.  Raw grepable nmap output is parsed in memory
and is never returned or persisted.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import stat
import subprocess
import tempfile
import tomllib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from . import envelope as envelope_module
from . import inventory_file as inventory_file_module
from . import receipts as _receipts
from . import ssh_path as ssh_path_module
from .adapters.ssh_cli import HOST_RE, PROXY_COMMAND_RE, USER_RE


REQUEST_ID_RE = re.compile(r"^[0-9a-f]{32}$")
NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
INTERFACE_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}$")
# A zone is named like a device, and a network namespace like a name
# with an underscore or a dash in it.
ZONE_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
NETNS_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
# The ranges the forced command may probe when the inventory does not say
# otherwise: the private IPv4 space (RFC1918 and the CGNAT range), and
# nothing else.  A router address may live in any of them.
DEFAULT_CHECK_TARGETS = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",
)
MAX_ZONES = 16
MAX_CHECK_TARGETS = 32
ZONE_KEYS = frozenset({"name", "src", "canary", "iface", "netns"})
PATH_RE = re.compile(r"^[A-Za-z0-9_./-]+$")
SERVICE_RE = re.compile(r"^[a-z0-9-]{1,32}$")
HOST_LINE_RE = re.compile(
    r"^Host: ([0-9]{1,3}(?:\.[0-9]{1,3}){3}) "
    r"\([^\t\r\n]*\)\tPorts: ([^\t]*)(?:\t.*)?$"
)
TIMEOUT_LINE_RE = re.compile(
    r"^Host: ([0-9]{1,3}(?:\.[0-9]{1,3}){3}) "
    r"\([^\t\r\n]*\)\tStatus: Timeout$"
)
DONE_LINE_RE = re.compile(r"^# Nmap done at .+$")
PORT_RE = re.compile(r"^([0-9]{1,5})/open/tcp//([^/]*)///$")
KINDS = frozenset({"inside", "outside"})
PROFILES = frozenset({"quick", "full-tcp"})
# The Wi-Fi survey (kind "wifi") rides on the same two tools.  The
# nmap kinds and profiles above are unchanged: an nmap request planned
# before this change must still load, with the same hash.
WIFI_KIND = "wifi"
WIFI_PROFILE = "survey"
SCAN_KINDS = frozenset({*KINDS, WIFI_KIND})
# The wifi request has no IP target and no vantage: the scan runs on the
# router's own radio over the normal read lane.
WIFI_TARGET = "-"
WIFI_VANTAGE = "router-radio"
WIFI_INTERFACE_RE = re.compile(r"^radio[0-9]{1,2}$")
# What a live measurement showed about the client disruption of a scan.
WIFI_DISRUPTION_NOTE = (
    "measured on the lab router (one 5 GHz AP, one client): the scan took 4 s "
    "and the client lost its link for about 10 s (65 of 100 test pings failed); "
    "run it when nobody needs the Wi-Fi"
)
DURATION_CAP_S = 300
KEPT = "addresses and open TCP ports only"
WIFI_KEPT = "channel counts and look-alike network names only"
# The router's scan reply is capped by the router program itself; the host
# caps the number of networks it reads as well.
MAX_WIFI_RESULTS = 400
# The fixed texts a refused Wi-Fi scan becomes.  The router's own words
# never reach the model: the refusal line is matched exactly, and the
# router's error word is named only when it is in the fixed allowlist.
WIFI_ERROR_TIMEOUT = "the Wi-Fi scan timed out"
WIFI_ERROR_NO_UBUS = "the router cannot run a Wi-Fi scan; its iwinfo service is missing"
WIFI_ERROR_TOO_OLD = (
    "router program too old for Wi-Fi scan; run "
    "sudo -u newton /usr/local/bin/newton-router-setup {device} upgrade"
)
WIFI_ERROR_NOT_UNDERSTOOD = "scan output not understood"
WIFI_ERROR_VERSION_UNREADABLE = "the router program version could not be read"
WIFI_ERROR_REFUSED = "the router refused the Wi-Fi scan"
WIFI_ERROR_REFUSED_NAMED = "the router refused the Wi-Fi scan ({word})"
# The refusal of a router whose program does not know the verb: the
# shape is `error bad-arg 2 1`, the word at position 1 being the verb.
# A bad-arg about any other word is not that.
WIFI_REFUSAL_VERB_UNKNOWN = "error bad-arg 2 1"
# The router's error words the host names.  Every other word (a
# bad-character, an arg-count) becomes the generic text.
WIFI_REFUSAL_WORDS = (
    "no-radio",
    "scan-rate-limited",
    "scan-too-large",
    "lock-timeout",
    "internal",
)
# The router program version the Wi-Fi scan needs.
WIFI_SCAN_MIN_VERSION = (1, 2, 0)
WIFI_CHANNEL_MIN = 1
WIFI_CHANNEL_MAX = 233
WIFI_SIGNAL_MIN = -128
WIFI_SIGNAL_MAX = 0
# The version field of a hello line: digits and dots only.
VERSION_FIELD_RE = re.compile(r"^version=([0-9]{1,4})\.([0-9]{1,4})\.([0-9]{1,4})$")
MAX_GREPABLE_LINES = 10_000
MAX_GREPABLE_LINE = 4096
MAX_HOSTS = 256
# SC-2: a planned scan request without consent is unusable forever
# without a bound; the 30-minute window matches the consent window the
# operator already accepts.  Enforced in ``load_request`` so the run
# path (after consent is consumed) and ``newton-approve`` (before
# consent is written) both reach it.  A ``created_at`` more than 5
# minutes in the future is rejected as "modified or invalid"; the
# hash check above is the primary defence, the clamp here keeps the
# reason identical for a clock-skewed operator.
SCAN_REQUEST_MAX_AGE = timedelta(minutes=30)
SCAN_REQUEST_FUTURE_TOLERANCE = timedelta(minutes=5)


def _now() -> datetime:
    """Wall clock for expiry checks; tests monkeypatch this so they
    can stage ``created_at`` offsets without sleeping."""
    return datetime.now(timezone.utc)

REQUEST_FIELDS = (
    "id",
    "device",
    "kind",
    "profile",
    "interface",
    "target",
    "vantage",
    "duration_cap_s",
    "kept",
    "created_at",
)
REQUEST_KEYS = frozenset((*REQUEST_FIELDS, "request_hash"))
CONSENT_KEYS = frozenset(
    {
        "request_id",
        "request_hash",
        "device",
        "approved_by",
        "created_at",
        "expires_at",
    }
)


class ScanError(ValueError):
    """Client-safe scan validation or state error."""


@dataclass(frozen=True)
class VantageZone:
    """One zone an inside vantage can check from.

    ``src`` is the address the vantage must have in the zone: a check only
    runs where that address is configured, so a vantage that is not really
    in the zone answers "wrong-zone" instead of pretending.  ``canary`` is
    the zone router's address (an IPv4 address and a port).  ``iface`` is the
    interface a DHCP probe needs and ``netns`` the network namespace the
    checks run in; both are empty when the zone does not use them.
    """

    name: str
    src: str
    canary_ip: str
    canary_port: int
    iface: str = ""
    netns: str = ""


@dataclass(frozen=True)
class Vantage:
    name: str
    host: str
    user: str
    key_file: Path
    known_hosts: Path
    proxy_command: str | None
    role: str
    devices: tuple[str, ...]
    # The zones this vantage can check from, and the ranges the forced
    # command may probe.  A vantage with no zones is a scan vantage only.
    # The loader fills ``check_targets`` with the private ranges when the
    # inventory does not say which ranges may be probed.
    zones: tuple[VantageZone, ...] = ()
    check_targets: tuple[str, ...] = ()

    @property
    def destination(self) -> str:
        return f"{self.user}@{self.host}"

    @property
    def check_key_file(self) -> Path:
        """The second key: the client checks run through their own key.

        The scan key is unchanged; the forced command gets a key of its own,
        so a compromised scan key cannot run the checks.
        """
        return Path(str(self.key_file) + "-check")


def _inventory_path() -> Path:
    return Path(
        os.environ.get("NEWTON_INVENTORY", "~/.config/newton/devices.toml")
    ).expanduser()


def _inventory_file(raw: Any, name: str, field: str, *, private: bool) -> Path:
    if not isinstance(raw, str) or not raw or not PATH_RE.fullmatch(raw):
        raise ScanError(
            f"vantage {name}: {field} must be a path of [A-Za-z0-9_./-]"
        )
    path = Path(raw).expanduser()
    try:
        info = path.lstat()
    except OSError:
        raise ScanError(
            f"vantage {name}: {field} must be an existing regular file (not a symlink)"
        ) from None
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ScanError(f"vantage {name}: {field} must be a regular file, not a symlink")
    if private and stat.S_IMODE(info.st_mode) != 0o600:
        raise ScanError(f"vantage {name}: {field} must have mode 0600")
    if info.st_uid != os.geteuid():
        raise ScanError(f"vantage {name}: {field} must be owned by the server user")
    return path


def _is_ipv4(text: str) -> bool:
    try:
        ipaddress.IPv4Address(text)
    except ValueError:
        return False
    return True


def _valid_check_cidr(value: str) -> bool:
    address, separator, prefix = value.partition("/")
    if not separator or "/" in prefix:
        return False
    if re.fullmatch(r"(?:[89]|[1-9][0-9])", prefix) is None:
        return False
    if not 8 <= int(prefix) <= 32:
        return False
    return _is_ipv4(address)


def _zone_rows(name: str, raw: Any) -> tuple[VantageZone, ...]:
    """The zones of a vantage: every field validated, no other keys."""
    if not isinstance(raw, list):
        raise ScanError(f"vantage {name}: zones must be a list of zone tables")
    if len(raw) > MAX_ZONES:
        raise ScanError(f"vantage {name}: zones must have at most {MAX_ZONES} entries")
    rows: list[VantageZone] = []
    seen: set[str] = set()
    for entry in raw:
        if not isinstance(entry, dict):
            raise ScanError(f"vantage {name}: each zone must be a table")
        unknown = sorted(set(entry) - ZONE_KEYS)
        if unknown:
            raise ScanError(f"vantage {name}: zone has unknown keys: {', '.join(unknown)}")
        zone = entry.get("name")
        if not isinstance(zone, str) or not ZONE_RE.fullmatch(zone):
            raise ScanError(
                f"vantage {name}: zone name must match ^[a-z][a-z0-9-]{{0,31}}$"
            )
        if zone in seen:
            raise ScanError(f"vantage {name}: zone names must be unique")
        seen.add(zone)
        src = entry.get("src")
        if not isinstance(src, str) or not _is_ipv4(src):
            raise ScanError(f"vantage {name}: zone {zone}: src must be an IPv4 address")
        canary = entry.get("canary")
        if not isinstance(canary, str) or ":" not in canary:
            raise ScanError(
                f"vantage {name}: zone {zone}: canary must be an IPv4 address and a port"
            )
        canary_ip, _, canary_port = canary.rpartition(":")
        if not _is_ipv4(canary_ip):
            raise ScanError(
                f"vantage {name}: zone {zone}: canary must be an IPv4 address and a port"
            )
        if not re.fullmatch(r"[1-9][0-9]{0,4}", canary_port) or int(canary_port) > 65535:
            raise ScanError(f"vantage {name}: zone {zone}: canary port must be 1-65535")
        iface = entry.get("iface", "")
        if iface is None:
            iface = ""
        if not isinstance(iface, str) or (iface and not INTERFACE_RE.fullmatch(iface)):
            raise ScanError(
                f"vantage {name}: zone {zone}: iface must match "
                "^[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}$"
            )
        netns = entry.get("netns", "")
        if netns is None:
            netns = ""
        if not isinstance(netns, str) or (netns and not NETNS_RE.fullmatch(netns)):
            raise ScanError(
                f"vantage {name}: zone {zone}: netns must match ^[a-z][a-z0-9_-]{{0,31}}$"
            )
        rows.append(
            VantageZone(
                name=zone,
                src=src,
                canary_ip=canary_ip,
                canary_port=int(canary_port),
                iface=iface,
                netns=netns,
            )
        )
    return tuple(rows)


def _check_target_rows(name: str, raw: Any) -> tuple[str, ...]:
    """The ranges the forced command may probe (the private space by default)."""
    if raw is None:
        return DEFAULT_CHECK_TARGETS
    if not isinstance(raw, list) or len(raw) > MAX_CHECK_TARGETS:
        raise ScanError(
            f"vantage {name}: check_targets must be a list of at most "
            f"{MAX_CHECK_TARGETS} CIDRs"
        )
    rows: list[str] = []
    seen: set[str] = set()
    for entry in raw:
        if not isinstance(entry, str):
            raise ScanError(f"vantage {name}: check_targets must be a list of IPv4 CIDRs")
        if not _valid_check_cidr(entry):
            raise ScanError(
                f"vantage {name}: check_targets must be IPv4 CIDRs"
            ) from None
        if entry in seen:
            raise ScanError(
                f"vantage {name}: check_targets must not contain duplicate CIDRs"
            )
        seen.add(entry)
        rows.append(entry)
    return tuple(rows)


def load_vantages(path: Path | None = None) -> dict[str, Vantage]:
    """Load and strictly validate ``[vantages.<name>]`` inventory entries."""
    inventory = path or _inventory_path()
    try:
        inventory.lstat()
    except OSError:
        raise ScanError(f"inventory file not found: {inventory}")
    message = inventory_file_module.check(inventory)
    if message is not None:
        raise ScanError(message)
    try:
        data = tomllib.loads(inventory.read_text(encoding="utf-8"))
    except (OSError, ValueError, tomllib.TOMLDecodeError) as exc:
        raise ScanError(f"invalid inventory: {exc}") from exc
    raw_vantages = data.get("vantages", {})
    if not isinstance(raw_vantages, dict):
        raise ScanError("[vantages] must be a table")
    raw_devices = data.get("devices", {})
    if not isinstance(raw_devices, dict):
        raise ScanError("[devices] must be a table")
    known_devices = set(raw_devices)
    allowed = {
        "host",
        "user",
        "key_file",
        "known_hosts",
        "proxy_command",
        "role",
        "devices",
        "admin_key",
        "admin_password_file",
        "zones",
        "check_targets",
    }
    result: dict[str, Vantage] = {}
    for name, raw in raw_vantages.items():
        if not isinstance(name, str) or not NAME_RE.fullmatch(name):
            raise ScanError("invalid vantage name in inventory")
        if not isinstance(raw, dict):
            raise ScanError(f"invalid vantage entry: {name}")
        unknown = sorted(set(raw) - allowed)
        if unknown:
            raise ScanError(f"vantage {name}: unknown keys: {', '.join(unknown)}")
        missing = sorted({"host", "user", "key_file", "known_hosts", "role", "devices"} - set(raw))
        if missing:
            raise ScanError(f"vantage {name}: missing required keys: {', '.join(missing)}")
        host = raw["host"]
        user = raw["user"]
        if not isinstance(host, str) or not HOST_RE.fullmatch(host):
            raise ScanError(f"vantage {name}: host has an invalid shape")
        if not isinstance(user, str) or not USER_RE.fullmatch(user):
            raise ScanError(f"vantage {name}: user has an invalid shape")
        role = raw["role"]
        if role not in KINDS:
            raise ScanError(f"vantage {name}: role must be 'inside' or 'outside'")
        devices = raw["devices"]
        if (
            not isinstance(devices, list)
            or not devices
            or len(devices) > 64
            or any(not isinstance(device, str) or not NAME_RE.fullmatch(device) for device in devices)
            or len(set(devices)) != len(devices)
        ):
            raise ScanError(
                f"vantage {name}: devices must be a non-empty list of unique device names"
            )
        if not set(devices) <= known_devices:
            raise ScanError(f"vantage {name}: devices contains an unknown device name")
        for admin_field in ("admin_key", "admin_password_file"):
            admin_value = raw.get(admin_field)
            if admin_value is not None and (
                not isinstance(admin_value, str) or not PATH_RE.fullmatch(admin_value)
            ):
                raise ScanError(f"vantage {name}: {admin_field} has an invalid shape")
        proxy = raw.get("proxy_command")
        if proxy is not None:
            if (
                not isinstance(proxy, str) or "%h" not in proxy or "\n" in proxy or "\r" in proxy
            ):
                raise ScanError(
                    f"vantage {name}: proxy_command must be a single-line string containing %h"
                )
            if PROXY_COMMAND_RE.fullmatch(proxy) is None:
                raise ScanError(
                    f"vantage {name}: proxy_command contains characters outside [A-Za-z0-9 _./:@%~=,+-]"
                )
        result[name] = Vantage(
            name=name,
            host=host,
            user=user,
            key_file=_inventory_file(raw["key_file"], name, "key_file", private=True),
            known_hosts=_inventory_file(
                raw["known_hosts"], name, "known_hosts", private=False
            ),
            proxy_command=os.path.expanduser(proxy) if proxy else None,
            role=role,
            devices=tuple(devices),
            zones=_zone_rows(name, raw["zones"]) if "zones" in raw else (),
            check_targets=_check_target_rows(name, raw.get("check_targets")),
        )
    return result


def compute_request_hash(record: dict[str, Any]) -> str:
    missing = [field for field in REQUEST_FIELDS if field not in record]
    if missing:
        raise ScanError(f"scan request is missing: {', '.join(missing)}")
    payload = {field: record[field] for field in REQUEST_FIELDS}
    canonical = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    # every caller passes state/<subdir>/<file>.json, so the state root is two
    # levels up; refuse before the mkdir below when either level is unsafe
    refusal = _receipts.check_state_write_path(path, path.parent.parent)
    if refusal is not None:
        raise ScanError(refusal)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def request_path(state: Path, request_id: str) -> Path:
    return state / "scan-requests" / f"{request_id}.json"


def consent_path(state: Path, request_id: str) -> Path:
    return state / "scan-consents" / f"{request_id}.json"


def save_request(state: Path, record: dict[str, Any]) -> None:
    _atomic_json(request_path(state, str(record["id"])), record)


def save_consent(state: Path, record: dict[str, Any]) -> None:
    _atomic_json(consent_path(state, str(record["request_id"])), record)


def load_request(state: Path, request_id: str) -> dict[str, Any]:
    if not isinstance(request_id, str) or not REQUEST_ID_RE.fullmatch(request_id):
        raise ScanError("scan request id must be 32 lowercase hexadecimal characters")
    try:
        value = json.loads(request_path(state, request_id).read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise ScanError("scan request not found or invalid") from exc
    if not isinstance(value, dict) or set(value) != REQUEST_KEYS:
        raise ScanError("scan request was modified or is invalid; plan it again")
    actual = compute_request_hash(value)
    stored = value.get("request_hash")
    if (
        not isinstance(stored, str)
        or not re.fullmatch(r"[0-9a-f]{64}", stored)
        or not hmac.compare_digest(stored, actual)
        or value.get("id") != request_id
    ):
        raise ScanError("scan request was modified or is invalid; plan it again")
    _validate_request_fields(value)
    _check_request_age(value)
    return value


def _check_request_age(value: dict[str, Any]) -> None:
    """SC-2: a planned scan request is only good for SCAN_REQUEST_MAX_AGE
    after ``created_at``; older requests are expired, requests with a
    ``created_at`` more than SCAN_REQUEST_FUTURE_TOLERANCE in the future
    are refused as "modified or invalid" (the hash check above is the
    primary defence; this keeps the message identical for an operator
    whose clock is ahead).  Both callers of ``load_request``
    (newton-approve and the run tool, which loads before consuming
    consent) hit this branch.
    """
    created = datetime.fromisoformat(str(value["created_at"]))
    now = _now()
    if created > now + SCAN_REQUEST_FUTURE_TOLERANCE:
        raise ScanError("scan request was modified or is invalid; plan it again")
    if now - created > SCAN_REQUEST_MAX_AGE:
        raise ScanError("scan request expired; plan a new scan request")


def _validate_request_fields(value: dict[str, Any]) -> None:
    # The wifi branch runs BEFORE the IP parse.  A wifi request has no
    # IP target at all (its target is "-"), so the ipaddress parse would
    # refuse it; the wifi fields are checked on their own instead.
    if value.get("kind") == WIFI_KIND:
        _validate_wifi_request_fields(value)
        return
    if (
        not isinstance(value.get("device"), str)
        or not NAME_RE.fullmatch(value["device"])
        or value.get("kind") not in KINDS
        or value.get("profile") not in PROFILES
        or not isinstance(value.get("interface"), str)
        or not INTERFACE_RE.fullmatch(value["interface"])
        or not isinstance(value.get("vantage"), str)
        or not NAME_RE.fullmatch(value["vantage"])
        or value.get("duration_cap_s") != DURATION_CAP_S
        or value.get("kept") != KEPT
        or not isinstance(value.get("created_at"), str)
    ):
        raise ScanError("scan request was modified or is invalid; plan it again")
    try:
        created = datetime.fromisoformat(value["created_at"])
    except ValueError:
        raise ScanError("scan request was modified or is invalid; plan it again") from None
    if created.tzinfo is None:
        raise ScanError("scan request was modified or is invalid; plan it again")
    try:
        target = str(value["target"])
        parsed = ipaddress.ip_network(target, strict=False) if "/" in target else ipaddress.ip_address(target)
    except (KeyError, ValueError):
        raise ScanError("scan request was modified or is invalid; plan it again") from None
    if not isinstance(parsed, (ipaddress.IPv4Address, ipaddress.IPv4Network)):
        raise ScanError("scan request was modified or is invalid; plan it again")
    if str(parsed) != target:
        raise ScanError("scan request was modified or is invalid; plan it again")
    if isinstance(parsed, ipaddress.IPv4Network) and parsed.prefixlen < 24:
        raise ScanError("scan request was modified or is invalid; plan it again")
    if value["kind"] == "outside" and isinstance(parsed, ipaddress.IPv4Network):
        raise ScanError("scan request was modified or is invalid; plan it again")
    if value["kind"] == "inside" and value["profile"] == "quick" and not isinstance(parsed, ipaddress.IPv4Network):
        raise ScanError("scan request was modified or is invalid; plan it again")
    if value["profile"] == "full-tcp" and isinstance(parsed, ipaddress.IPv4Network):
        raise ScanError("scan request was modified or is invalid; plan it again")
    _validate_target(value["kind"], parsed)


def _validate_wifi_request_fields(value: dict[str, Any]) -> None:
    """The wifi request fields: the radio, the fixed target and vantage.

    Every field is fixed by the host, so a request that carries anything
    else was changed on disk and is refused like any other tampered
    request.
    """
    if (
        not isinstance(value.get("device"), str)
        or not NAME_RE.fullmatch(value["device"])
        or value.get("kind") != WIFI_KIND
        or value.get("profile") != WIFI_PROFILE
        or not isinstance(value.get("interface"), str)
        or not WIFI_INTERFACE_RE.fullmatch(value["interface"])
        or value.get("target") != WIFI_TARGET
        or value.get("vantage") != WIFI_VANTAGE
        or value.get("duration_cap_s") != DURATION_CAP_S
        or value.get("kept") != WIFI_KEPT
        or not isinstance(value.get("created_at"), str)
    ):
        raise ScanError("scan request was modified or is invalid; plan it again")
    try:
        created = datetime.fromisoformat(value["created_at"])
    except ValueError:
        raise ScanError("scan request was modified or is invalid; plan it again") from None
    if created.tzinfo is None:
        raise ScanError("scan request was modified or is invalid; plan it again")


def kept_for(kind: str) -> str:
    """The retention statement the owner approves for a scan kind.

    The nmap statement is unchanged: an nmap request planned before the
    wifi scan landed keeps its hash.
    """
    return WIFI_KEPT if kind == WIFI_KIND else KEPT


def validate_plan_inputs(kind: Any, profile: Any, interface: Any) -> tuple[str, str, str | None]:
    if not isinstance(kind, str) or kind not in SCAN_KINDS:
        raise ScanError("kind must be 'inside', 'outside' or 'wifi'")
    if kind == WIFI_KIND:
        if profile != WIFI_PROFILE:
            raise ScanError("profile must be 'survey' for a wifi scan")
        if not isinstance(interface, str) or not WIFI_INTERFACE_RE.fullmatch(interface):
            raise ScanError("interface must name a radio, for example radio0")
        return kind, profile, interface
    if not isinstance(profile, str) or profile not in PROFILES:
        raise ScanError("profile must be 'quick' or 'full-tcp'")
    if kind == "inside":
        if interface is None:
            raise ScanError("interface is required for an inside scan")
        if not isinstance(interface, str) or not INTERFACE_RE.fullmatch(interface):
            raise ScanError("interface must match ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}$")
        return kind, profile, interface
    if interface is not None:
        raise ScanError("interface must not be supplied for an outside scan")
    return kind, profile, None


def choose_vantage(vantages: dict[str, Vantage], device: str, role: str) -> Vantage:
    matches = [v for v in vantages.values() if v.role == role and device in v.devices]
    if len(matches) != 1:
        raise ScanError(f"device {device} must have exactly one {role} vantage; found {len(matches)}")
    return matches[0]


def read_text(result: dict[str, Any], what: str) -> str:
    if result.get("exit_code") != 0 or result.get("truncated") is True:
        raise ScanError(f"could not derive scan target from router {what}")
    stdout = result.get("stdout")
    if (
        not isinstance(stdout, dict)
        or stdout.get("kind") != "untrusted-device-data"
        or not isinstance(stdout.get("text"), str)
    ):
        raise ScanError(f"could not derive scan target from router {what}")
    return stdout["text"]


def _strip_flag_prefix_at_line_start(text: str, prefix: str) -> str:
    """Remove FLAG_PREFIX only where it appears at the START of a line.

    Real router ``ubus call network.interface dump`` output has indented
    lines like ``\\t\\t\\t"data": {`` and ``\\t\\t\\t\\t\\t"source": "x"``,
    and the envelope's output pipeline prepends FLAG_PREFIX to every line
    that imitates a Newton field.  Stripping only at line start restores
    the JSON shape without weakening the safety property: the prefix is
    still part of the envelope text shown to the model, and the text
    itself is not used as instructions anywhere except as data the JSON
    path needs to parse.  Every other path (the model-visible stdout, the
    audit log) keeps FLAG_PREFIX verbatim.
    """
    if not text:
        return text
    n = len(prefix)
    if n == 0:
        return text
    parts: list[str] = []
    i = 0
    while i < len(text):
        nl = text.find("\n", i)
        line_end = nl if nl >= 0 else len(text)
        line = text[i:line_end]
        if line.startswith(prefix):
            line = line[n:]
        parts.append(line)
        if nl < 0:
            break
        parts.append("\n")
        i = nl + 1
    return "".join(parts)


def read_json(result: dict[str, Any], what: str) -> dict[str, Any]:
    raw = read_text(result, what)
    body = _strip_flag_prefix_at_line_start(raw, envelope_module.FLAG_PREFIX)
    try:
        value = json.loads(body)
    except (ValueError, json.JSONDecodeError) as exc:
        raise ScanError(f"could not derive scan target from router {what}") from exc
    if not isinstance(value, dict):
        raise ScanError(f"could not derive scan target from router {what}")
    return value


def router_text(result: dict[str, Any], what: str) -> str:
    """The router's own text, ready to be parsed.

    The output pipeline prepends the flag prefix to every line that
    imitates a Newton field; the JSON path already strips it before it
    parses (``read_json``).  The wifi path parses the router's uci dump
    and its scan JSON the same way, so it uses the same rule: the prefix
    goes, the line stays.

    ``what`` is a fixed host string: nothing the router said is part of
    the message.
    """
    if result.get("exit_code") != 0 or result.get("truncated") is True:
        raise ScanError(f"could not read the router's {what}")
    stdout = result.get("stdout")
    if (
        not isinstance(stdout, dict)
        or stdout.get("kind") != "untrusted-device-data"
        or not isinstance(stdout.get("text"), str)
    ):
        raise ScanError(f"could not read the router's {what}")
    return _strip_flag_prefix_at_line_start(
        stdout["text"], envelope_module.FLAG_PREFIX
    )


def _stderr_text(result: dict[str, Any]) -> str:
    """The router's stderr text, or "" when there is none."""
    stderr = result.get("stderr")
    if isinstance(stderr, dict) and isinstance(stderr.get("text"), str):
        return stderr["text"]
    return ""


def _refusal_line(result: dict[str, Any]) -> str:
    """The router's refusal line: the first line that starts with "error "."""
    for line in _stderr_text(result).splitlines():
        stripped = line.strip()
        if stripped.startswith("error "):
            return stripped
    return ""


def wifi_scan_error(result: dict[str, Any], *, device: str) -> str:
    """The fixed message for a router that refused the Wi-Fi scan.

    The router's own words are matched, never echoed: the refusal line is
    matched EXACTLY, so a refusal the host does not know becomes the
    generic text.  The router's error word is named only when it is in
    the fixed allowlist.
    """
    exit_code = result.get("exit_code")
    if exit_code == 124:
        return WIFI_ERROR_TIMEOUT
    if exit_code == 127:
        return WIFI_ERROR_NO_UBUS
    line = _refusal_line(result)
    if line == WIFI_REFUSAL_VERB_UNKNOWN:
        # The router's program does not know the verb: it is older than
        # the release that carries it.  The host validated the radio name
        # itself, so the refusal is about the verb.
        return WIFI_ERROR_TOO_OLD.format(device=device)
    word = line[len("error "):].split(" ", 1)[0] if line else ""
    if word in WIFI_REFUSAL_WORDS:
        return WIFI_ERROR_REFUSED_NAMED.format(word=word)
    return WIFI_ERROR_REFUSED


def parse_program_version(text: str) -> tuple[int, int, int] | None:
    """The version field of a hello line, as (major, minor, patch).

    Only digits and dots are accepted: the hello line is device text, and
    a version that does not parse is no version at all.
    """
    for token in text.split():
        match = VERSION_FIELD_RE.match(token)
        if match is not None:
            return (
                int(match.group(1)),
                int(match.group(2)),
                int(match.group(3)),
            )
    return None


def parse_wifi_results(text: str) -> list[dict[str, Any]]:
    """Parse the router's scan JSON in memory.

    The reply must carry a ``results`` list; every network must carry an
    SSID (text), a BSSID (text), a channel (a number) and a signal (a
    number).  Channels outside 1..233 and signals outside -128..0 are
    dropped.  Anything the host does not understand is refused with a
    fixed message: the raw text never reaches an error, a log or the audit.
    """
    try:
        value = json.loads(text)
    except (ValueError, json.JSONDecodeError) as exc:
        raise ScanError(WIFI_ERROR_NOT_UNDERSTOOD) from exc
    if not isinstance(value, dict):
        raise ScanError(WIFI_ERROR_NOT_UNDERSTOOD)
    results = value.get("results")
    if not isinstance(results, list):
        raise ScanError(WIFI_ERROR_NOT_UNDERSTOOD)
    if len(results) > MAX_WIFI_RESULTS:
        raise ScanError(WIFI_ERROR_NOT_UNDERSTOOD)
    parsed: list[dict[str, Any]] = []
    for entry in results:
        if not isinstance(entry, dict):
            raise ScanError(WIFI_ERROR_NOT_UNDERSTOOD)
        ssid = entry.get("ssid", "")  # ubus leaves the key out for a hidden network
        bssid = entry.get("bssid")
        channel = entry.get("channel")
        signal = entry.get("signal")
        if (
            not isinstance(ssid, str)
            or not isinstance(bssid, str)
            or isinstance(channel, bool)
            or not isinstance(channel, int)
            or isinstance(signal, bool)
            or not isinstance(signal, int)
        ):
            raise ScanError(WIFI_ERROR_NOT_UNDERSTOOD)
        if not WIFI_CHANNEL_MIN <= channel <= WIFI_CHANNEL_MAX:
            continue
        if not WIFI_SIGNAL_MIN <= signal <= WIFI_SIGNAL_MAX:
            continue
        parsed.append(
            {
                "ssid": ssid,
                "bssid": bssid,
                "channel": channel,
                "signal": signal,
            }
        )
    if results and not parsed:
        raise ScanError(WIFI_ERROR_NOT_UNDERSTOOD)
    return parsed


def interface_names(dump: dict[str, Any]) -> set[str]:
    entries = dump.get("interface")
    if not isinstance(entries, list):
        raise ScanError("could not derive scan target from router interface dump")
    return {
        entry["interface"]
        for entry in entries
        if isinstance(entry, dict)
        and isinstance(entry.get("interface"), str)
        and INTERFACE_RE.fullmatch(entry["interface"])
    }


def default_route_interface(dump: dict[str, Any]) -> str:
    entries = dump.get("interface")
    found: dict[str, int] = {}
    if isinstance(entries, list):
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            name = entry.get("interface")
            routes = entry.get("route")
            if not isinstance(name, str) or not INTERFACE_RE.fullmatch(name) or not isinstance(routes, list):
                continue
            for route in routes:
                if not isinstance(route, dict):
                    continue
                target = route.get("target")
                mask = route.get("mask")
                if (target == "0.0.0.0" and mask == 0) or target == "0.0.0.0/0":
                    # ubus reports the metric on the interface, not the route.
                    metric = route.get("metric", entry.get("metric", 0))
                    if isinstance(metric, bool) or not isinstance(metric, int) or metric < 0:
                        continue
                    found[name] = min(found.get(name, metric), metric)
    if not found:
        raise ScanError("router must have an IPv4 default-route interface; found 0")
    best_metric = min(found.values())
    best = sorted(name for name, metric in found.items() if metric == best_metric)
    if len(best) != 1:
        raise ScanError(
            f"router must have exactly one preferred IPv4 default-route interface; found {len(best)}"
        )
    return best[0]


_ZONE_VALUE_RE = re.compile(
    r"^firewall\.([A-Za-z0-9_@\[\]-]{1,80})\.(name|network)=(.*)$"
)


def wan_networks(firewall: str, wan_zones: tuple[str, ...]) -> set[str]:
    sections: dict[str, dict[str, list[str]]] = {}
    for line in firewall.splitlines():
        match = _ZONE_VALUE_RE.fullmatch(line)
        if not match:
            continue
        section, option, raw = match.groups()
        try:
            # UCI's show form is a sequence of single-quoted data words.  This
            # parser only interprets data; it never executes the result.
            import shlex

            values = shlex.split(raw, posix=True)
        except ValueError:
            continue
        if option == "network":
            values = [part for value in values for part in value.split()]
        if values and all(INTERFACE_RE.fullmatch(value) for value in values):
            sections.setdefault(section, {})[option] = values
    networks: set[str] = set()
    for values in sections.values():
        names = values.get("name", [])
        if len(names) == 1 and names[0] in wan_zones:
            networks.update(values.get("network", []))
    if not networks:
        raise ScanError("could not determine WAN-zone interfaces from router firewall data")
    return networks


def address_and_network(status: dict[str, Any]) -> tuple[ipaddress.IPv4Address, ipaddress.IPv4Network]:
    raw = status.get("ipv4-address")
    candidates: list[tuple[ipaddress.IPv4Address, ipaddress.IPv4Network]] = []
    if isinstance(raw, list):
        for entry in raw:
            if not isinstance(entry, dict):
                continue
            address = entry.get("address")
            mask = entry.get("mask")
            if not isinstance(address, str) or isinstance(mask, bool) or not isinstance(mask, int):
                continue
            try:
                ip = ipaddress.IPv4Address(address)
                network = ipaddress.IPv4Network(f"{address}/{mask}", strict=False)
            except ValueError:
                continue
            candidates.append((ip, network))
    if len(candidates) != 1:
        raise ScanError(f"scan interface must have exactly one IPv4 address; found {len(candidates)}")
    return candidates[0]


def make_request(
    *,
    device: str,
    kind: str,
    profile: str,
    interface: str,
    target: str,
    vantage: str,
) -> dict[str, Any]:
    request_id = secrets.token_hex(16)
    record: dict[str, Any] = {
        "id": request_id,
        "device": device,
        "kind": kind,
        "profile": profile,
        "interface": interface,
        "target": target,
        "vantage": vantage,
        "duration_cap_s": DURATION_CAP_S,
        "kept": kept_for(kind),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    record["request_hash"] = compute_request_hash(record)
    return record


def consume_consent(state: Path, request: dict[str, Any], device: str) -> dict[str, Any]:
    request_id = str(request["id"])
    path = consent_path(state, request_id)
    used = path.with_suffix(".used")
    if used.exists():
        raise ScanError("scan consent was already used")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ScanError("scan consent is required; run newton-approve with the request id") from None
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise ScanError("scan consent record is invalid") from exc
    if not isinstance(value, dict) or set(value) != CONSENT_KEYS:
        raise ScanError("scan consent record is invalid")
    if value.get("request_id") != request_id:
        raise ScanError("scan consent does not match this request")
    if value.get("device") != device or request.get("device") != device:
        raise ScanError("scan consent is for a different device")
    stored_hash = value.get("request_hash")
    request_hash = request.get("request_hash")
    if (
        not isinstance(stored_hash, str)
        or not isinstance(request_hash, str)
        or not hmac.compare_digest(stored_hash, request_hash)
    ):
        raise ScanError("scan consent does not match this request")
    if not isinstance(value.get("approved_by"), str):
        raise ScanError("scan consent record is invalid")
    try:
        created = datetime.fromisoformat(str(value["created_at"]))
        expiry = datetime.fromisoformat(str(value["expires_at"]))
    except (KeyError, ValueError):
        raise ScanError("scan consent record is invalid") from None
    if (
        created.tzinfo is None
        or expiry.tzinfo is None
        or expiry <= created
        or (expiry - created).total_seconds() > 30 * 60
    ):
        raise ScanError("scan consent record is invalid")
    if expiry <= datetime.now(timezone.utc):
        raise ScanError("scan consent expired; approve the request again")
    try:
        os.replace(path, used)
    except FileNotFoundError:
        if used.exists():
            raise ScanError("scan consent was already used") from None
        raise ScanError("scan consent is required; run newton-approve with the request id") from None
    return value


def run_vantage(
    vantage: Vantage,
    command: list[str],
    *,
    run: Callable[..., subprocess.CompletedProcess[str]] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Send one validated forced-command grammar line over pinned SSH."""
    if (
        len(command) != 4
        or command[0] != "scan"
        or command[1] not in PROFILES
        or command[2] not in KINDS
    ):
        raise ScanError("invalid internal scan command")
    try:
        target = ipaddress.ip_network(command[3], strict=False) if "/" in command[3] else ipaddress.ip_address(command[3])
    except ValueError:
        raise ScanError("invalid internal scan target") from None
    if not isinstance(target, (ipaddress.IPv4Address, ipaddress.IPv4Network)):
        raise ScanError("invalid internal scan target")
    if isinstance(target, ipaddress.IPv4Network) and target.prefixlen < 24:
        raise ScanError("invalid internal scan target")
    try:
        ssh_binary = ssh_path_module.resolve_ssh()
    except ssh_path_module.SshNotFound as exc:
        raise ScanError(str(exc)) from exc
    argv = [
        ssh_binary,
        "-o",
        "ControlMaster=no",
        "-o",
        "ControlPath=none",
        "-o",
        "ConnectTimeout=8",
        "-o",
        "BatchMode=yes",
    ]
    if vantage.proxy_command:
        argv += ["-o", f"ProxyCommand={vantage.proxy_command}"]
    argv += [
        "-i",
        str(vantage.key_file),
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"UserKnownHostsFile={vantage.known_hosts}",
        # the ``--`` ends ssh's option list: the destination can never be
        # read as an option
        "--",
        vantage.destination,
        *command,
    ]
    runner = subprocess.run if run is None else run
    return runner(
        argv,
        text=True,
        capture_output=True,
        stdin=subprocess.DEVNULL,
        timeout=DURATION_CAP_S,
        check=False,
    )


def parse_grepable(raw: str) -> list[dict[str, Any]]:
    """Parse bounded nmap ``-oG`` text, retaining no raw strings."""
    by_address: dict[str, dict[int, str]] = {}
    for index, line in enumerate(raw.splitlines()):
        if index >= MAX_GREPABLE_LINES:
            break
        if len(line) > MAX_GREPABLE_LINE:
            continue
        match = HOST_LINE_RE.fullmatch(line)
        if not match:
            continue
        try:
            address = str(ipaddress.IPv4Address(match.group(1)))
        except ValueError:
            continue
        if address not in by_address and len(by_address) >= MAX_HOSTS:
            continue
        ports: dict[int, str] = by_address.setdefault(address, {})
        for raw_port in match.group(2).split(", "):
            port_match = PORT_RE.fullmatch(raw_port)
            if not port_match:
                continue
            port = int(port_match.group(1))
            if not 1 <= port <= 65535:
                continue
            service_raw = port_match.group(2)
            service = service_raw if SERVICE_RE.fullmatch(service_raw) else "unknown"
            ports[port] = service
        if not ports:
            by_address.pop(address, None)
    return [
        {
            "address": address,
            "ports": [
                {"port": port, "service": service}
                for port, service in sorted(ports.items())
            ],
        }
        for address, ports in sorted(
            by_address.items(), key=lambda item: int(ipaddress.IPv4Address(item[0]))
        )
    ]


def parse_timed_out(raw: str) -> list[str]:
    """Collect timed-out IPv4 addresses from bounded nmap ``-oG`` text.

    nmap emits ``Host: <addr> (<name>)\\tStatus: Timeout`` when ``--host-timeout``
    is reached.  Only the address is validated and kept; the parenthesised
    text is bounded to ``[^\\t\\r\\n]`` so it cannot smuggle bytes past the
    line scan, and nothing else from those lines is ever returned.
    """
    seen: set[str] = set()
    timed_out: list[str] = []
    for index, line in enumerate(raw.splitlines()):
        if index >= MAX_GREPABLE_LINES:
            break
        if len(line) > MAX_GREPABLE_LINE:
            continue
        match = TIMEOUT_LINE_RE.fullmatch(line)
        if not match:
            continue
        try:
            address = str(ipaddress.IPv4Address(match.group(1)))
        except ValueError:
            continue
        if address in seen:
            continue
        if len(timed_out) >= MAX_HOSTS:
            continue
        seen.add(address)
        timed_out.append(address)
    return timed_out


def scan_complete(raw: str) -> bool:
    """True iff the nmap output carries the ``# Nmap done at`` trailer."""
    for index, line in enumerate(raw.splitlines()):
        if index >= MAX_GREPABLE_LINES:
            break
        if len(line) > MAX_GREPABLE_LINE:
            continue
        if DONE_LINE_RE.fullmatch(line):
            return True
    return False


WAN_CONTROL_IDS = {22: "OW-MGMT-01", 53: "OW-DNS-02", 80: "OW-MGMT-02", 443: "OW-MGMT-02"}


# SC-1: scan target sanity.  The target string comes from the router's
# own interface report (server.py: ``plan_scan`` -> ``address_and_network``
# for an inside scan, or the default-route interface's address for an
# outside scan), so a compromised router can steer an approved scan at
# any host or /24 it likes unless the host re-validates the shape after
# parsing.  ``_validate_target`` is the single check: every code path
# (``scans._validate_request_fields`` on load, ``newton_plan_scan`` after
# deriving the target) reaches it.
_ALLOWED_INSIDE_NETWORKS: tuple[ipaddress.IPv4Network, ...] = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
)
_BROADCAST_ADDRESS = ipaddress.IPv4Address("255.255.255.255")


def _validate_target(
    kind: str,
    parsed: ipaddress.IPv4Address | ipaddress.IPv4Network,
) -> None:
    """Reject a parsed scan target that does not fit the kind's policy.

    For ``inside`` the target must lie wholly inside one of
    ``_ALLOWED_INSIDE_NETWORKS`` (RFC 1918 plus the CGNAT block
    100.64.0.0/10): a public address, loopback, link-local, multicast,
    the unspecified / this-network block (0.0.0.0/8), the broadcast
    address or a network that only partly overlaps an allowed space is
    refused.  ``subnet_of`` enforces the "wholly inside" property, so
    172.0.0.0/8 (172.0.0.0 - 172.255.255.255) and 10.0.0.0/7 (10.0.0.0 -
    11.255.255.255) are not subnets of 172.16.0.0/12 or 10.0.0.0/8 and
    are rejected; the same goes for 192.168.0.0/15 (192.168.0.0 -
    192.169.255.255).

    For ``outside`` the target must be a single unicast address that is
    not loopback, link-local, multicast, unspecified, or broadcast.
    Private and CGNAT addresses stay allowed because real WANs sit
    behind CGNAT and the lab WAN is private; the only thing the router
    can corrupt is the *address* in the interface report, so the rule
    is on the address itself, not its allocation status.
    """
    if kind == "inside":
        network = (
            parsed
            if isinstance(parsed, ipaddress.IPv4Network)
            else ipaddress.ip_network(f"{parsed}/32", strict=False)
        )
        for allowed in _ALLOWED_INSIDE_NETWORKS:
            if network.subnet_of(allowed):
                return
        raise ScanError(
            "scan target must lie wholly inside RFC 1918 (10/8, 172.16/12, "
            "192.168/16) or 100.64.0.0/10"
        )
    if kind == "outside":
        if isinstance(parsed, ipaddress.IPv4Network):
            raise ScanError("scan target must be a single address, not a network")
        if parsed.is_loopback:
            raise ScanError("scan target must not be a loopback address")
        if parsed.is_link_local:
            raise ScanError("scan target must not be a link-local address")
        if parsed.is_multicast:
            raise ScanError("scan target must not be a multicast address")
        if parsed.is_unspecified:
            raise ScanError("scan target must not be the unspecified address")
        if parsed == _BROADCAST_ADDRESS or parsed.is_reserved:
            raise ScanError("scan target must not be the broadcast or a reserved address")
        return
    raise ScanError("scan kind must be 'inside' or 'outside'")


def findings_for(kind: str, hosts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for host in hosts:
        for port in host["ports"]:
            finding: dict[str, Any] = {
                "finding": f"tcp/{port['port']} open on {kind}",
                "address": host["address"],
                "port": port["port"],
                "service": port["service"],
                "control_id": (
                    WAN_CONTROL_IDS.get(port["port"])
                    if kind == "outside"
                    else None
                ),
            }
            findings.append(finding)
    return findings

