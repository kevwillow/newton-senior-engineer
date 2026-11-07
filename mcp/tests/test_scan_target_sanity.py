"""SC-1: scan target sanity.

The scan target is taken from the router's own interface report, so a
compromised router can steer an approved scan at any host or /24 it likes
unless the host re-validates the shape after parsing.  The check happens
in ``scans`` because that is the one module every code path reaches:

- ``scans._validate_request_fields`` re-parses and re-validates a stored
  request on load (``newton_run_scan`` and ``_approve_scan``), so a
  request that was edited on disk or written by a future planner is
  refused before any nmap command is built.
- ``newton_plan_scan`` calls the same check after deriving the target
  from the interface status, so a hostile router cannot make a request
  land on disk in the first place.

This file exercises both paths.  Each refused class gets its own test so a
regression names the case; the allowed-class tests are the positive
counterweight so a too-strict check fails fast too.
"""

from __future__ import annotations

import io
import json
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import newton_mcp.approve as approve
import newton_mcp.envelope as envelope
import newton_mcp.redact as redact
import newton_mcp.scans as scans
import newton_mcp.server as server


REQUEST_ID = "0123456789abcdef0123456789abcdef"


# ---------------------------------------------------------------------------
# Test helpers (copy/adapted from test_scans.py so this file stays
# self-contained; the existing helpers live behind fixtures that
# _isolate_state_dir already provides).
# ---------------------------------------------------------------------------


class TerminalInput(io.StringIO):
    def isatty(self):
        return True


def _envelope(source: str, text: str) -> dict[str, str]:
    return {"kind": "untrusted-device-data", "source": source, "text": text}


def _read_result(command: str, value: object, exit_code: int = 0) -> dict[str, object]:
    text = value if isinstance(value, str) else json.dumps(value)
    return {
        "exit_code": exit_code,
        "stdout": _envelope(f"router:{command}", text),
        "stderr": _envelope(f"router:{command}", ""),
        "truncated": False,
    }


def _write_inventory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    vantages: tuple[tuple[str, str], ...] = (("inside-a", "inside"),),
) -> Path:
    key = tmp_path / "scan.key"
    known_hosts = tmp_path / "known_hosts"
    key.write_text("synthetic-key")
    known_hosts.write_text("synthetic host key\n")
    key.chmod(0o600)
    known_hosts.chmod(0o600)
    chunks = [
        "[devices.router]\n",
        'platform = "openwrt"\n',
        'host = "192.0.2.1"\n',
        'user = "root"\n',
        'wan_zones = ["wan"]\n',
    ]
    for name, role in vantages:
        chunks.extend(
            [
                f"\n[vantages.{name}]\n",
                'host = "scan.example.invalid"\n',
                'user = "newton"\n',
                f'key_file = "{key}"\n',
                f'known_hosts = "{known_hosts}"\n',
                f'role = "{role}"\n',
                'devices = ["router"]\n',
            ]
        )
    inventory = tmp_path / "devices.toml"
    inventory.write_text("".join(chunks))
    monkeypatch.setenv("NEWTON_INVENTORY", str(inventory))
    return inventory


def _fake_reads(
    monkeypatch: pytest.MonkeyPatch,
    *,
    lan_address: str = "192.168.1.1",
    lan_mask: int = 24,
    wan_address: str = "198.51.100.9",
) -> list[str]:
    """Router read fakes whose LAN status lives at a private RFC 1918
    address so the derived inside target passes the new sanity check."""
    calls: list[str] = []
    dump = {
        "interface": [
            {"interface": "lan", "up": True},
            {
                "interface": "wan",
                "up": True,
                "route": [{"target": "0.0.0.0", "mask": 0}],
            },
        ]
    }
    firewall = "\n".join(
        [
            "firewall.@zone[0]=zone",
            "firewall.@zone[0].name='lan'",
            "firewall.@zone[0].network='lan'",
            "firewall.@zone[1]=zone",
            "firewall.@zone[1].name='wan'",
            "firewall.@zone[1].network='wan wan6'",
        ]
    )
    statuses = {
        "lan": {"up": True, "ipv4-address": [{"address": lan_address, "mask": lan_mask}]},
        "wan": {"up": True, "ipv4-address": [{"address": wan_address, "mask": 24}]},
    }

    def fake_read(self, device: str, command: str):
        calls.append(command)
        if command == "ubus call network.interface dump":
            return _read_result(command, dump)
        if command == "uci show firewall":
            return _read_result(command, firewall)
        prefix = "ubus call network.interface."
        if command.startswith(prefix) and command.endswith(" status"):
            iface = command[len(prefix) : -len(" status")]
            if iface in statuses:
                return _read_result(command, statuses[iface])
        return _read_result(command, "not found", exit_code=1)

    monkeypatch.setattr(server.NewtonService, "read", fake_read)
    return calls


def _outside_request(
    *,
    target: str,
    device: str = "router",
    vantage: str = "outside-a",
) -> dict[str, object]:
    # SC-2: a planned scan request expires 30 minutes after planning;
    # stamp it at the current wall clock so the request stays inside
    # the expiry window of ``load_request``.  Tests that need a
    # specific offset overwrite ``created_at`` (and ``request_hash``)
    # themselves.
    record: dict[str, object] = {
        "id": REQUEST_ID,
        "device": device,
        "kind": "outside",
        "profile": "quick",
        "interface": "wan",
        "target": target,
        "vantage": vantage,
        "duration_cap_s": 300,
        "kept": "addresses and open TCP ports only",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    record["request_hash"] = scans.compute_request_hash(record)
    return record


def _inside_request(
    *,
    target: str,
    profile: str = "quick",
    interface: str = "lan",
    device: str = "router",
    vantage: str = "inside-a",
) -> dict[str, object]:
    record: dict[str, object] = {
        "id": REQUEST_ID,
        "device": device,
        "kind": "inside",
        "profile": profile,
        "interface": interface,
        "target": target,
        "vantage": vantage,
        "duration_cap_s": 300,
        "kept": "addresses and open TCP ports only",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    record["request_hash"] = scans.compute_request_hash(record)
    return record


def _write_request(tmp_path: Path, record: dict[str, object]) -> Path:
    path = tmp_path / "state" / "scan-requests" / f"{REQUEST_ID}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record))
    path.chmod(0o600)
    return path


def _write_consent(tmp_path: Path, record: dict[str, object]) -> Path:
    now = datetime.now(timezone.utc)
    consent = {
        "request_id": REQUEST_ID,
        "request_hash": record["request_hash"],
        "device": record["device"],
        "approved_by": "operator",
        "created_at": (now - timedelta(minutes=1)).isoformat(),
        "expires_at": (now + timedelta(minutes=30)).isoformat(),
    }
    path = tmp_path / "state" / "scan-consents" / f"{REQUEST_ID}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(consent))
    path.chmod(0o600)
    return path


# ---------------------------------------------------------------------------
# Direct unit tests of the validator (scans._validate_target).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "target",
    [
        "8.8.8.8",         # public, single address
        "8.8.8.0/24",      # public network
        "127.0.0.1",       # loopback
        "127.0.0.0/8",     # loopback network
        "169.254.1.1",     # link-local
        "169.254.0.0/16",  # link-local network
        "224.0.0.1",       # multicast
        "224.0.0.0/4",     # multicast network
        "0.0.0.0",         # unspecified
        "0.0.0.0/8",       # "this network" (RFC 1122)
        "255.255.255.255", # broadcast
        "172.0.0.0/8",     # partial overlap of 172.16.0.0/12
        "10.0.0.0/7",      # partial overlap of 10.0.0.0/8 (10.0.0.0/8 + 11.0.0.0/8)
        "192.168.0.0/15",  # partial overlap of 192.168.0.0/16
    ],
)
def test_inside_target_refused(target):
    """SC-1: every target class the design lists must be refused by
    ``scans._validate_target`` so a hand-edited request cannot slip a
    public, loopback, link-local, multicast, unspecified, broadcast or
    partly-overlapping network onto the nmap command line."""
    parsed = (
        scans.ipaddress.ip_network(target, strict=False)
        if "/" in target
        else scans.ipaddress.ip_address(target)
    )
    with pytest.raises(scans.ScanError):
        scans._validate_target("inside", parsed)


@pytest.mark.parametrize(
    "target",
    [
        "127.0.0.1",       # loopback
        "169.254.1.1",     # link-local
        "224.0.0.1",       # multicast
        "0.0.0.0",         # unspecified
        "255.255.255.255", # broadcast (reserved)
        "8.8.8.0/24",      # network instead of single address
    ],
)
def test_outside_target_refused(target):
    parsed = (
        scans.ipaddress.ip_network(target, strict=False)
        if "/" in target
        else scans.ipaddress.ip_address(target)
    )
    with pytest.raises(scans.ScanError):
        scans._validate_target("outside", parsed)


@pytest.mark.parametrize(
    "target",
    [
        # RFC 1918: 10.0.0.0/8
        "10.0.0.0/24",
        "10.5.6.0/25",
        "10.255.255.0/24",
        # RFC 1918: 172.16.0.0/12
        "172.16.0.0/24",
        "172.20.0.0/16",
        "172.31.255.0/24",
        # RFC 1918: 192.168.0.0/16
        "192.168.0.0/24",
        "192.168.255.0/24",
        # CGNAT: 100.64.0.0/10
        "100.64.0.0/24",
        "100.127.255.0/24",
    ],
)
def test_inside_network_target_allowed(target):
    parsed = scans.ipaddress.ip_network(target, strict=False)
    scans._validate_target("inside", parsed)


@pytest.mark.parametrize(
    "target",
    [
        # RFC 1918 single addresses (full-tcp inside)
        "10.0.0.5",
        "172.16.1.5",
        "172.31.255.5",
        "192.168.1.5",
        # CGNAT single address
        "100.64.0.5",
    ],
)
def test_inside_single_address_allowed(target):
    parsed = scans.ipaddress.ip_address(target)
    scans._validate_target("inside", parsed)


@pytest.mark.parametrize(
    "target",
    [
        # public addresses (outside)
        "8.8.8.8",
        "198.51.100.9",
        # private addresses (outside still allowed; real WANs sit
        # behind CGNAT and the lab WAN is private)
        "10.0.0.5",
        "192.168.1.5",
        # CGNAT single address
        "100.64.0.5",
    ],
)
def test_outside_single_address_allowed(target):
    parsed = scans.ipaddress.ip_address(target)
    scans._validate_target("outside", parsed)


# ---------------------------------------------------------------------------
# Request-load path: ``scans._validate_request_fields`` is the single
# place that re-parses a stored request before any nmap command is built,
# so a hand-edited request that lands a forbidden target on disk is
# refused at load time (by ``newton_run_scan`` and by ``_approve_scan``).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "target",
    [
        "8.8.8.8",
        "127.0.0.1",
        "169.254.1.1",
        "224.0.0.1",
        "0.0.0.0",
        "255.255.255.255",
        "172.0.0.0/8",
        "10.0.0.0/7",
    ],
)
def test_load_request_refuses_inside_target_outside_allowed_spaces(
    tmp_path, target
):
    """A stored inside request whose target is outside the allowed
    private spaces is refused on load -- before ``newton_run_scan``
    reaches the vantage runner."""
    record = _inside_request(target=target)
    _write_request(tmp_path, record)
    with pytest.raises(scans.ScanError):
        scans.load_request(tmp_path / "state", REQUEST_ID)


@pytest.mark.parametrize(
    "target",
    [
        "127.0.0.1",
        "169.254.1.1",
        "224.0.0.1",
        "0.0.0.0",
        "255.255.255.255",
        "8.8.8.0/24",
    ],
)
def test_load_request_refuses_outside_target_that_is_loopback_or_worse(
    tmp_path, target
):
    record = _outside_request(target=target)
    _write_request(tmp_path, record)
    with pytest.raises(scans.ScanError):
        scans.load_request(tmp_path / "state", REQUEST_ID)


# ---------------------------------------------------------------------------
# Plan-time path: ``newton_plan_scan`` derives the target from the
# router's interface status and must refuse before saving the request.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("lan_address", "lan_mask"),
    [
        ("8.8.8.1", 24),         # public
        ("127.0.0.1", 24),       # loopback
        ("169.254.1.1", 24),     # link-local
        ("224.0.0.1", 24),       # multicast
        ("0.0.0.1", 8),          # unspecified / this network
        ("255.255.255.255", 32), # broadcast
    ],
)
def test_plan_inside_refuses_when_interface_address_is_not_private(
    tmp_path, monkeypatch, lan_address, lan_mask
):
    """A compromised router can rewrite ``network.interface.<ifname>``
    status and steer the inside scan at any address it likes; the host
    must refuse before saving the request."""
    _write_inventory(tmp_path, monkeypatch)
    _fake_reads(monkeypatch, lan_address=lan_address, lan_mask=lan_mask)
    result = server.newton_plan_scan("router", "inside", "quick", "lan")
    assert "error" in result
    assert not (tmp_path / "state" / "scan-requests").exists() or not any(
        (tmp_path / "state" / "scan-requests").iterdir()
    )


def test_plan_inside_accepts_rfc1918_interface_address(tmp_path, monkeypatch):
    _write_inventory(tmp_path, monkeypatch)
    _fake_reads(monkeypatch, lan_address="192.168.1.1", lan_mask=24)
    result = server.newton_plan_scan("router", "inside", "quick", "lan")
    assert result["target"] == "192.168.1.0/24"


def test_plan_inside_accepts_cgnat_interface_address(tmp_path, monkeypatch):
    _write_inventory(tmp_path, monkeypatch)
    _fake_reads(monkeypatch, lan_address="100.64.0.1", lan_mask=24)
    result = server.newton_plan_scan("router", "inside", "quick", "lan")
    assert result["target"] == "100.64.0.0/24"


def test_plan_inside_accepts_each_rfc1918_band(tmp_path, monkeypatch):
    _write_inventory(tmp_path, monkeypatch)
    _fake_reads(monkeypatch, lan_address="172.20.0.1", lan_mask=24)
    result = server.newton_plan_scan("router", "inside", "quick", "lan")
    assert result["target"] == "172.20.0.0/24"


def test_plan_inside_full_tcp_accepts_each_rfc1918_band(tmp_path, monkeypatch):
    _write_inventory(tmp_path, monkeypatch)
    _fake_reads(monkeypatch, lan_address="10.0.0.5", lan_mask=24)
    result = server.newton_plan_scan("router", "inside", "full-tcp", "lan")
    assert result["target"] == "10.0.0.5"


@pytest.mark.parametrize(
    "wan_address",
    [
        "127.0.0.1",       # loopback
        "169.254.1.1",     # link-local
        "224.0.0.1",       # multicast
        "0.0.0.0",         # unspecified
        "255.255.255.255", # broadcast
    ],
)
def test_plan_outside_refuses_when_default_route_address_is_loopback_or_worse(
    tmp_path, monkeypatch, wan_address
):
    """A compromised router can rewrite the default-route interface's
    status to point the outside scan at a loopback, link-local,
    multicast, unspecified or broadcast address; the host must refuse
    before saving the request."""
    inventory = _write_inventory(
        tmp_path, monkeypatch, vantages=(("outside-a", "outside"),)
    )
    _fake_reads(monkeypatch, wan_address=wan_address)
    result = server.newton_plan_scan("router", "outside", "quick")
    assert "error" in result
    requests_dir = tmp_path / "state" / "scan-requests"
    if requests_dir.exists():
        assert not any(requests_dir.iterdir())


@pytest.mark.parametrize(
    "wan_address",
    [
        "8.8.8.8",        # public
        "198.51.100.9",   # public (TEST-NET-2)
        "192.168.1.1",    # private
        "10.0.0.1",       # private
        "100.64.0.1",     # CGNAT
    ],
)
def test_plan_outside_accepts_public_private_and_cgnat_default_route(
    tmp_path, monkeypatch, wan_address
):
    inventory = _write_inventory(
        tmp_path, monkeypatch, vantages=(("outside-a", "outside"),)
    )
    _fake_reads(monkeypatch, wan_address=wan_address)
    result = server.newton_plan_scan("router", "outside", "quick")
    assert result["target"] == wan_address


# ---------------------------------------------------------------------------
# Approve screen: SC-1 also requires the human approver to see that the
# target came from the router's own interface report, not from the agent.
# ---------------------------------------------------------------------------


def test_approve_scan_screen_prints_target_source_line(tmp_path, monkeypatch, capsys):
    """SC-1: the approve screen prints one fixed line directly after
    the ``Target:`` row, naming the source of the target string.  A
    compromised router can change its interface report, so the approver
    has to know the string did not come from the agent or from the
    inventory."""
    _write_inventory(tmp_path, monkeypatch, vantages=(("outside-a", "outside"),))
    record = _outside_request(target="198.51.100.9")
    _write_request(tmp_path, record)
    monkeypatch.setattr(approve, "_getpass", lambda prompt: pytest.fail("getpass must not be called"))
    monkeypatch.setattr(approve.sys, "stdin", TerminalInput("no\n"))
    assert approve.main([REQUEST_ID]) == 1
    out = capsys.readouterr().out
    lines = out.splitlines()
    target_index = lines.index(f"Target: {record['target']}")
    assert lines[target_index + 1] == (
        "Target source: the router's own interface report "
        "(a compromised router could change it)."
    )