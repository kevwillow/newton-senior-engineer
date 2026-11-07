"""Client-vantage outcome checks: what a client inside a zone sees.

Router-side verify can only see what the router reports.  A plan may also
claim something about a CLIENT: that a client in the guest zone resolves a
name through the zone router, that it gets a DHCP offer, that it reaches the
internet, or that it cannot reach a set of addresses.

Those claims are not sealed as router probes.  Instead Newton asks a
registered inside vantage (a client machine) to run fixed checks through a
second, forced-command key, and a FAIL or a NOT-TESTED of any claimed check
stops the confirm: the router rolls back by itself.

This module is the host side of that arrangement and holds only pure
functions: no ssh, no device, no vantage.  It derives the addresses a blocked
claim is checked against, it finds the vantage that serves a zone, it fills
the targets Newton owns (the agent may not supply them), it builds the spec
the vantage runner reads, and it builds the one string the router-side script
runs the vantage runner with.

The addresses used here are the router's own, read from
``ubus call network.interface dump``; only private ones (RFC1918 and the
CGNAT range) are used, and the list is capped, so the check cannot be turned
into a port scan of the outside world.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import stat
import tempfile
from pathlib import Path
from typing import Any, Callable

from .scans import Vantage

# A client claim never carries free text: it names a kind and a zone, and the
# words Newton shows are built from these values.
CLIENT_KINDS = ("client_dns", "client_dhcp", "client_internet", "client_blocked")

# The ports a blocked-router claim is checked against.
ROUTER_PORTS = (22, 80, 443)

# The two public resolvers an internet claim is checked against.
INTERNET_TARGETS = ("1.1.1.1:443", "9.9.9.9:443")

# How many addresses a single blocked claim may carry.
MAX_TARGETS = 24

# The verify budget a plan needs when it claims a client check: the vantage
# round is slower than a router probe, so the plan's timeout must allow it.
MIN_TIMEOUT_S = 150

# The one shape the router-side script accepts for OWRT_LOCAL_CHECK: the
# quoted path of the vantage runner and the session id.
LOCAL_CHECK_RE = re.compile(r"^'/[A-Za-z0-9_./-]+/newton-vantage-run' [0-9a-f]{32}$")

# The version of the spec file the vantage runner reads.
SPEC_VERSION = 1

_RUN_PATH_RE = re.compile(r"^/[A-Za-z0-9_./-]+$")
_SID_RE = re.compile(r"^[0-9a-f]{32}$")

# The private IPv4 space a router address may live in: RFC1918 and the
# CGNAT range.  ``ipaddress``'s own ``is_private`` also covers the
# documentation and test ranges, which are not the router's addresses.
_PRIVATE_V4 = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
)
_CGNAT_V4 = ipaddress.IPv4Network("100.64.0.0/10")


class ClientCheckError(ValueError):
    """A client check could not be prepared.  The message is safe to show the agent."""


def is_client_claim(claim: Any) -> bool:
    """True when the claim is one of the client kinds."""
    kind = claim.get("kind") if isinstance(claim, dict) else getattr(claim, "kind", None)
    return isinstance(kind, str) and kind in CLIENT_KINDS


def client_claims(expect: Any) -> list[tuple[int, dict[str, Any]]]:
    """The client claims of an ``expect`` list, with their claim numbers.

    The number is the 1-based index into ``expect`` (the same number the
    verify lines, the receipts and ``failed_claim`` use), so a client claim
    and a router claim share one numbering.
    """
    rows: list[tuple[int, dict[str, Any]]] = []
    for number, claim in enumerate(expect if isinstance(expect, list) else [], start=1):
        if is_client_claim(claim):
            rows.append((number, claim))
    return rows


def _private_v4(text: str) -> ipaddress.IPv4Address | None:
    try:
        address = ipaddress.IPv4Address(text)
    except ValueError:
        return None
    if any(address in network for network in _PRIVATE_V4) or address in _CGNAT_V4:
        return address
    return None


def derive_router_targets(dump: dict[str, Any]) -> list[str]:
    """The addresses a blocked-router claim is checked against.

    ``dump`` is the parsed ``ubus call network.interface dump``: every
    interface with its IPv4 addresses.  Every private address (RFC1918 or
    the CGNAT range) is crossed with the ports in ``ROUTER_PORTS``, and the
    result is de-duplicated and sorted as text, so the same dump always
    gives the same list.  The list is capped at ``MAX_TARGETS``.  A router
    with too many (or with none) is refused: the claim could not be checked,
    and Newton does not guess.
    """
    interfaces = dump.get("interface") if isinstance(dump, dict) else None
    addresses: set[ipaddress.IPv4Address] = set()
    for entry in interfaces if isinstance(interfaces, list) else []:
        if not isinstance(entry, dict):
            continue
        rows = entry.get("ipv4-address")
        for row in rows if isinstance(rows, list) else []:
            raw = row.get("address") if isinstance(row, dict) else None
            if not isinstance(raw, str):
                continue
            address = _private_v4(raw)
            if address is not None:
                addresses.add(address)
    targets = sorted(
        {f"{address}:{port}" for address in addresses for port in ROUTER_PORTS}
    )
    if not targets:
        raise ClientCheckError("the router has no private address to check")
    if len(targets) > MAX_TARGETS:
        raise ClientCheckError(
            f"too many router addresses to check ({len(targets)}); the cap is {MAX_TARGETS}"
        )
    return targets


def vantage_for_zone(vantages: dict[str, Vantage], device: str, zone: str) -> Vantage:
    """The one inside vantage that serves ``zone`` for ``device``.

    Only a vantage with role ``inside`` can serve a client claim, and it must
    list the device and carry the zone.  Zero or more than one match is a
    refusal: Newton does not pick one and does not guess.
    """
    matches = [
        vantage
        for vantage in vantages.values()
        if vantage.role == "inside"
        and device in vantage.devices
        and zone in {row.name for row in vantage.zones}
    ]
    if not matches:
        raise ClientCheckError(f"no inside vantage serves zone {zone} for this device")
    if len(matches) > 1:
        raise ClientCheckError(
            f"more than one inside vantage serves zone {zone} for this device"
        )
    return matches[0]


def fill_targets(
    expect: list[dict[str, Any]], dump_loader: Callable[[], dict[str, Any]]
) -> list[dict[str, Any]]:
    """The claim list with the targets Newton derives filled in.

    ``dump_loader`` reads the router's interface dump and is called at most
    once, and only when a claim needs it (a blocked claim against the
    router's own addresses).  The list that came in is not changed.
    """
    filled: list[dict[str, Any]] = []
    dump: dict[str, Any] | None = None
    for claim in expect if isinstance(expect, list) else []:
        if not isinstance(claim, dict):
            filled.append(claim)
            continue
        kind = claim.get("kind")
        if kind != "client_blocked":
            filled.append(dict(claim))
            continue
        destination = claim.get("to")
        if destination == "internet":
            filled.append({**claim, "targets": list(INTERNET_TARGETS)})
            continue
        if destination == "router":
            if dump is None:
                dump = dump_loader()
            filled.append({**claim, "targets": derive_router_targets(dump)})
            continue
        raise ClientCheckError(f"a {kind} claim has no known destination")
    return filled


def local_check_string(run_path: Path, sid: str) -> str:
    """The value of ``OWRT_LOCAL_CHECK``.

    This is the only place that value is built.  The path must be an
    absolute path of ``[A-Za-z0-9_./-]`` that ends in the vantage runner,
    and the session id must be 32 lowercase hex characters; anything else is
    refused rather than quoted.  The result is one word plus the id, and it
    always satisfies ``LOCAL_CHECK_RE``.
    """
    text = str(run_path)
    if not _RUN_PATH_RE.fullmatch(text):
        raise ClientCheckError("the vantage runner path has an unusable shape")
    if not isinstance(sid, str) or not _SID_RE.fullmatch(sid):
        raise ClientCheckError("the session id has an unusable shape")
    value = f"'{text}' {sid}"
    if not LOCAL_CHECK_RE.fullmatch(value):
        raise ClientCheckError("the vantage runner path must end in newton-vantage-run")
    return value


def build_spec(
    sid: str, expect: list[dict[str, Any]], vantages: dict[str, Vantage], device: str
) -> dict[str, Any]:
    """The spec the vantage runner reads for one apply.

    One group per (vantage, zone), the checks of a group in claim order, and
    every check names the claim number it stands for.  The vantage's check
    key (not its scan key) is the one the forced command uses.
    """
    if not isinstance(sid, str) or not _SID_RE.fullmatch(sid):
        raise ClientCheckError("the session id has an unusable shape")
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    order: list[tuple[str, str]] = []
    for number, claim in client_claims(expect):
        zone = claim.get("zone")
        if not isinstance(zone, str) or not zone:
            raise ClientCheckError(f"expect claim {number} has no zone")
        vantage = vantage_for_zone(vantages, device, zone)
        key = (vantage.name, zone)
        if key not in groups:
            groups[key] = {
                "zone": zone,
                "vantage": {
                    "name": vantage.name,
                    "destination": vantage.destination,
                    "key_file": str(vantage.check_key_file),
                    "known_hosts": str(vantage.known_hosts),
                    "proxy_command": vantage.proxy_command,
                },
                "checks": [],
            }
            order.append(key)
        kind = claim.get("kind")
        check: dict[str, Any] = {"claim": number, "kind": kind}
        if kind == "client_blocked":
            check["to"] = claim.get("to")
            targets = claim.get("targets")
            if not isinstance(targets, list) or not targets:
                raise ClientCheckError(f"expect claim {number} has no targets")
            check["targets"] = list(targets)
        groups[key]["checks"].append(check)
    return {"version": SPEC_VERSION, "sid": sid, "groups": [groups[key] for key in order]}


def write_spec(directory: Path, spec: dict[str, Any]) -> Path:
    """Write the spec as ``<directory>/<sid>.json`` and return the path.

    The directory is 0700, the file 0600, the write is atomic (a temporary
    file in the same directory, then a rename) and no symlink is followed.

    Every OSError of the write is a ``ClientCheckError``: the server
    catches that one and refuses the apply cleanly, so a directory that
    cannot be written must not reach it as an OSError.
    """
    directory = Path(directory)
    sid = spec.get("sid") if isinstance(spec, dict) else None
    if not isinstance(sid, str) or not _SID_RE.fullmatch(sid):
        raise ClientCheckError("the vantage run spec has no usable session id")
    try:
        info = directory.lstat()
    except FileNotFoundError:
        try:
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        except OSError:
            raise ClientCheckError(
                "the vantage run spec could not be written"
            ) from None
    except OSError as exc:
        raise ClientCheckError(
            f"the vantage run directory cannot be inspected: {exc.strerror}"
        ) from None
    else:
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise ClientCheckError(
                "the vantage run directory must be a real directory, not a symlink"
            )
    try:
        os.chmod(directory, 0o700)
    except OSError:
        raise ClientCheckError("the vantage run spec could not be written") from None
    path = directory / f"{sid}.json"
    try:
        existing = path.lstat()
    except OSError:
        existing = None
    if existing is not None and stat.S_ISLNK(existing.st_mode):
        raise ClientCheckError("the vantage run spec must not be a symlink")
    try:
        fd, temporary = tempfile.mkstemp(prefix=f".{sid}.", dir=directory)
    except OSError:
        raise ClientCheckError("the vantage run spec could not be written") from None
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(spec, stream, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except OSError:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise ClientCheckError("the vantage run spec could not be written") from None
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    try:
        os.chmod(path, 0o600)
    except OSError:
        raise ClientCheckError("the vantage run spec could not be written") from None
    return path
