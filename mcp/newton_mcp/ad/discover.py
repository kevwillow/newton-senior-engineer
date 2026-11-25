"""Find the domain controllers of a domain from DNS and print the setup commands.

``newton-ad-discover --domain DNS --platform windows|samba --pubkey FILE``
asks DNS for the SRV records of the domain controllers and of the PDC
emulator, looks up the addresses of the hosts it finds and prints the
``newton-ad-setup`` commands the owner would run, one per controller.  It
prints and never sets anything up, holds no credential and writes nothing.

With ``--fetch-host-keys`` it also asks ``ssh-keyscan`` for the host keys
of every controller it found, and prints, for every key, its SHA256
fingerprint (the way ``ssh-keygen -lf`` prints it) and the ready
``known_hosts`` line.  A scan travels over the network, so it can be
spoofed: the fingerprint is only worth something when the owner compares
it with the one the controller shows at its console, and the tool says so.
A controller whose scan fails, or that has no key, gets a plain line and
keeps the placeholder.

With ``--preflight`` it also checks every controller it found, from the
host the tool runs on: the ports 22, 389 and 88 are connected (nothing is
sent), and the clock of the controller is read with one time query.  A
controller whose LDAP port 389 or Kerberos port 88 is not open is a FAIL,
and so is one whose clock is more than 300 s off; port 22 is only
reported, because the setup script installs SSH later.  The checks are
read-only, but they do contact the addresses DNS gave in the same run,
before the owner has read the list: so the owner runs the tool without
``--preflight`` first, checks the list against their own controllers, and
only then runs it again with the flag.  That second run reads DNS again:
the first list does not limit what the second run probes, and the
addresses it probes are the ones that run prints.  Nothing is pinned: the
second run trusts DNS as much as the first one did.

The time query is one SNTP request on UDP 123, over IPv6 for an IPv6
address.  Its transmit timestamp holds the local time and a random
fraction, and the reply is used only when it is exactly 48 bytes long
(up to 512 bytes are read, and any length other than 48 is refused),
comes from a time server whose clock is synchronized, carries a transmit
timestamp that is not all zero, and carries the transmit timestamp of the
request (bytes 40..47) in its originate timestamp (bytes 24..31): a reply
to another query, or a datagram of another length, is never read as the
clock of the controller.

DNS answers are untrusted (SECURITY: anyone who can spoof DNS can name
any host), so every name goes through one strict check before it can
appear in a printed command:

- letters, digits and hyphens only (LDH), labels of 1 to 63 characters
  that do not start or end with a hyphen, at most 253 characters in all;
- the name must end in ``.<domain>``;
- at most ``MAX_DCS`` controllers are used;
- an address with a scope id (a ``%`` and the name of an interface of
  the host the tool runs on) is dropped with a printed reason: the tool
  cannot know which interface it names, so it never connects to it;
- everything else is skipped, and the reason is printed (the name is
  shown escaped and cut short, so it can never move a terminal);
- every value of a printed command goes through ``shlex.quote``.

The work one host can cost is bounded too: at most
``MAX_ADDRESS_RECORDS`` A and AAAA records are read for it, and at most
``MAX_REFUSALS`` scope-id refusals are printed for it.  What was cut is
said out loud, in a note.

What the scan answers is untrusted too: only the key types of
``hostkeys.KEY_TYPES`` are kept, the blob must be valid base64 and must
carry the type its line names, and the host name that is printed is the
one that was asked for.  The caps of ``hostkeys`` (``MAX_KEYS`` and
``MAX_BLOB``) limit what is kept and printed; they do not limit what the
program reads: there is no size cap on what is read, and a timeout
bounds time, not bytes.  When more valid keys are found than the cap
allows, the tool says the list was cut, so the owner knows the
fingerprints shown are not all of them and that the ready
``known_hosts`` lines are not all of the keys either.

The owner is told to check the list against their own controllers.  The
pinning of the SSH host key in the setup still protects the logins: this
tool adds no trust.

The DNS part is the small ``DnsLookup`` class over dnspython.  The tests
give ``main`` a fake with the same two methods, a fake runner for
``ssh-keyscan``, fake sockets and a fixed clock, so no test touches a
network.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
import secrets
import shlex
import socket
import struct
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Protocol

from . import hostkeys
from .hostkeys import HostKey, Runner
from .setupgen import DEVICE_RE, DOMAIN_RE, SetupError, _read_public_key
from .setupgen_write import validate_ous

# The most controllers one run uses, and the most records it looks at.
MAX_DCS = 32
MAX_RECORDS = 512

# The longest DNS name, without the final dot, and the longest label.
MAX_NAME = 253
MAX_LABEL = 63

# The most addresses printed for one host.
MAX_ADDRESSES = 4

# The most A and AAAA records read for one host, and the most scope-id
# refusals printed for one host.  DNS answers are untrusted, so the work
# one host can cost is bounded; what was cut is said out loud.
MAX_ADDRESS_RECORDS = 64
MAX_REFUSALS = 8

# How long one DNS question may take, in seconds, and how long one
# attempt waits.
LOOKUP_LIFETIME = 5.0
LOOKUP_TIMEOUT = 2.0

# The longest piece of a hostile name that is shown.
SHOWN_LENGTH = 60

# The longest short host name: the write device adds "-ops", and the
# device grammar of the setup allows 32 characters.
MAX_SHORT = 28

# The ports the preflight connects to on every controller, in the order
# they are checked.
PREFLIGHT_PORTS = ((22, "SSH"), (389, "LDAP"), (88, "Kerberos"))

# The ports a controller must have open: LDAP and Kerberos.  SSH is not
# one of them (the setup script installs SSH later), so port 22 is
# reported only.
REQUIRED_PORTS = (389, 88)

# How long one TCP connect and one time query may take, in seconds.
PREFLIGHT_TIMEOUT = 3.0

# The clock skew the preflight allows, in seconds: the Kerberos default
# (five minutes).
SKEW_LIMIT = 300.0

# The NTP port, and the seconds between the NTP epoch (1900-01-01) and
# the Unix epoch (1970-01-01).
NTP_PORT = 123
NTP_EPOCH_OFFSET = 2208988800

# The size of an SNTP packet: the request is 48 bytes, and a reply is
# only accepted when it is exactly that long.
NTP_PACKET_SIZE = 48

# The byte offsets of an SNTP packet (RFC 4330, figure 1).  The first
# byte holds the leap indicator, the version and the mode, the second
# the stratum; then the poll, the precision, the root delay, the root
# dispersion and the reference identifier; then the four timestamps:
# the reference (16..23), the originate (24..31), the receive (32..39)
# and the transmit (40..47).
NTP_OFF_LEAP_MODE = 0
NTP_OFF_STRATUM = 1
NTP_OFF_REFERENCE = 16
NTP_OFF_ORIGINATE = 24
NTP_OFF_RECEIVE = 32
NTP_OFF_TRANSMIT = 40

# The size of one NTP timestamp: two big-endian uint32, the seconds and
# the fraction.
NTP_TIMESTAMP_SIZE = 8

# How much one time query reads: up to 512 bytes.  A datagram socket
# hands over the whole datagram, but cuts it short when the buffer is
# smaller, so a datagram longer than 512 bytes is cut short by the read:
# any length other than 48 is refused, not trimmed to a length that looks
# right.
NTP_RECV_SIZE = 512

# The first byte of the request: LI 0, version 4, mode 3 (client).
NTP_CLIENT_BYTE = 0x23

# The mode of a time server's reply, and the strata that mean the server
# has a time source of its own.
NTP_SERVER_MODE = 4
NTP_MIN_STRATUM = 1
NTP_MAX_STRATUM = 15

# The leap indicator of a reply: 3 means the clock of the time server
# is not synchronized, so its time cannot be used.
NTP_LEAP_NOT_SYNCED = 3

# The exit codes (the header of scripts/newton-ad-discover lists them).
EXIT_OK = 0
EXIT_PREFLIGHT = 1
EXIT_ARGUMENTS = 2
EXIT_NO_RECORDS = 3
EXIT_TIMEOUT = 4
EXIT_NO_USABLE_DC = 5
EXIT_NO_PDC = 6

_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


class DiscoverError(Exception):
    """A lookup or a refusal that stops the run.  ``code`` is the exit code."""

    code = EXIT_ARGUMENTS


class NoSuchName(DiscoverError):
    """The name does not exist (NXDOMAIN)."""

    code = EXIT_NO_RECORDS


class NoAnswer(DiscoverError):
    """The name exists and has no record of the asked type."""

    code = EXIT_NO_RECORDS


class DnsTimeout(DiscoverError):
    """No resolver answered in time."""

    code = EXIT_TIMEOUT


class Lookup(Protocol):
    """What the tool needs of a resolver."""

    def srv_targets(self, name: str) -> list[str]: ...

    def addresses(self, name: str, kind: str) -> list[str]: ...


class DnsLookup:
    """The real resolver, over dnspython.

    ``resolver_ip`` is the server to ask; ``None`` uses the system's.
    Every dnspython error is mapped to one of the three errors above.
    """

    def __init__(self, resolver_ip: str | None) -> None:
        import dns.resolver

        self._dns_resolver = dns.resolver
        try:
            self._resolver = dns.resolver.Resolver(configure=resolver_ip is None)
        except dns.resolver.NoResolverConfiguration as exc:
            raise DnsTimeout("no resolver is configured") from exc
        if resolver_ip is not None:
            self._resolver.nameservers = [resolver_ip]
        self._resolver.timeout = LOOKUP_TIMEOUT
        self._resolver.lifetime = LOOKUP_LIFETIME

    def _ask(self, name: str, rdtype: str):
        import dns.exception

        resolver = self._dns_resolver
        try:
            return self._resolver.resolve(name, rdtype)
        except resolver.NXDOMAIN as exc:
            raise NoSuchName(name) from exc
        except resolver.NoAnswer as exc:
            raise NoAnswer(name) from exc
        except (resolver.NoNameservers, dns.exception.Timeout) as exc:
            raise DnsTimeout(name) from exc
        except dns.exception.DNSException as exc:
            raise DnsTimeout(name) from exc

    def srv_targets(self, name: str) -> list[str]:
        return [str(record.target) for record in self._ask(name, "SRV")]

    def addresses(self, name: str, kind: str) -> list[str]:
        return [str(record.address) for record in self._ask(name, kind)]


@dataclass
class Dc:
    """One domain controller that passed the checks."""

    host: str
    device: str
    addresses: list[str] = field(default_factory=list)
    is_pdc: bool = False
    keys: list[HostKey] = field(default_factory=list)
    key_note: str = ""
    keys_cut: bool = False

    @property
    def write_device(self) -> str:
        return f"{self.device}-ops"


@dataclass
class Discovery:
    """What the lookups found."""

    domain: str
    dcs: list[Dc] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    pdc: Dc | None = None
    pdc_problem: str | None = None
    fetched_keys: bool = False


def _shown(text: str) -> str:
    """A name from DNS as it is printed: escaped, cut short, one line."""
    shown = ascii(text)[: SHOWN_LENGTH + 2]
    return shown if len(ascii(text)) <= SHOWN_LENGTH + 2 else shown + "..."


def _clean_host(raw: str, domain: str) -> tuple[str | None, str]:
    """The lower-case host name of an SRV target, or None and the reason."""
    name = raw[:-1] if raw.endswith(".") else raw
    if len(name) > MAX_NAME:
        return None, f"longer than {MAX_NAME} characters"
    if not name:
        return None, "not a valid host name (empty: the service is not offered here)"
    lowered = name.lower()
    labels = lowered.split(".")
    for label in labels:
        if not _LABEL_RE.match(label):
            return None, "not a valid host name (letters, digits and hyphens only)"
    if not lowered.endswith("." + domain):
        return None, f"outside the domain {domain}"
    return lowered, ""


def _short_name(host: str, domain: str) -> str:
    return host[: -(len(domain) + 1)].split(".")[0]


def _clean_hosts(records: list[str], domain: str, result: Discovery) -> list[str]:
    """The valid hosts of a list of SRV targets, in answer order, no repeats."""
    hosts: list[str] = []
    for raw in records[:MAX_RECORDS]:
        host, reason = _clean_host(raw, domain)
        if host is None:
            result.skipped.append(f"skipped: {_shown(raw)}: {reason}")
        elif host not in hosts:
            hosts.append(host)
    if len(records) > MAX_RECORDS:
        result.skipped.append(
            f"skipped: {len(records) - MAX_RECORDS} records past the first {MAX_RECORDS}"
        )
    return hosts


def _addresses(lookup: Lookup, host: str) -> tuple[list[str], list[str], list[str]]:
    """The addresses of a host (A, then AAAA), the notes and the refusals.

    An address with a scope id is refused with a reason, and the reason
    shows the address escaped: the scope names an interface of the host
    the tool runs on, and the tool cannot know which one, so it never
    connects to such an address.

    DNS is untrusted, so the work for one host is bounded: at most
    ``MAX_ADDRESS_RECORDS`` records are read for it (A and AAAA
    together) and at most ``MAX_REFUSALS`` scope-id refusals are
    printed for it.  What was cut is said out loud, in a note.
    """
    found: list[str] = []
    notes: list[str] = []
    refused: list[str] = []
    budget = MAX_ADDRESS_RECORDS
    cut_records = 0
    cut_refusals = 0
    for kind in ("A", "AAAA"):
        try:
            raw = lookup.addresses(host, kind)
        except (NoSuchName, NoAnswer):
            continue
        except DnsTimeout:
            notes.append("an address lookup did not answer in time")
            continue
        if budget <= 0:
            cut_records += len(raw)
            continue
        if len(raw) > budget:
            cut_records += len(raw) - budget
            raw = raw[:budget]
        for text in raw:
            budget -= 1
            if "%" in text:
                if len(refused) < MAX_REFUSALS:
                    refused.append(
                        f"skipped: {host}: {_shown(text)}: an address with a scope id is not used"
                    )
                else:
                    cut_refusals += 1
                continue
            try:
                address = str(ipaddress.ip_address(text))
            except ValueError:
                continue
            if address not in found:
                found.append(address)
    if cut_records:
        notes.append(
            f"{cut_records} address records past the first {MAX_ADDRESS_RECORDS} were not read"
        )
    if cut_refusals:
        notes.append(
            f"{cut_refusals} scope-id refusals past the first {MAX_REFUSALS} were not printed"
        )
    return found[:MAX_ADDRESSES], notes, refused


def discover(domain: str, lookup: Lookup) -> Discovery:
    """Look the domain up and return what passed the checks.

    Raises ``DiscoverError`` when the controller records cannot be had
    (exit 3 or 4) or none of them is usable (exit 5).
    """
    result = Discovery(domain=domain)
    records = lookup.srv_targets(f"_ldap._tcp.dc._msdcs.{domain}")
    hosts = _clean_hosts(records, domain, result)
    if len(hosts) > MAX_DCS:
        result.skipped.append(
            f"skipped: {len(records)} records, using the first {MAX_DCS}"
        )
        hosts = hosts[:MAX_DCS]
    seen_devices: dict[str, str] = {}
    for host in hosts:
        short = _short_name(host, domain)
        if len(short) > MAX_SHORT or DEVICE_RE.fullmatch(short) is None:
            result.skipped.append(
                f"skipped: {host}: no device name can be made from its short name"
            )
            continue
        if short in seen_devices:
            result.skipped.append(
                f"skipped: {host}: the same device name as {seen_devices[short]}"
            )
            continue
        seen_devices[short] = host
        addresses, notes, refused = _addresses(lookup, host)
        result.skipped.extend(refused)
        dc = Dc(host=host, device=short, addresses=addresses)
        if not addresses:
            result.notes.append(
                f"{host}: no address found{('; ' + '; '.join(notes)) if notes else ''}"
            )
        elif notes:
            result.notes.append(f"{host}: {'; '.join(notes)}")
        result.dcs.append(dc)
    if not result.dcs:
        raise _NoUsableDc("no usable domain controller was found")
    _find_pdc(domain, lookup, result)
    result.dcs.sort(key=lambda dc: (not dc.is_pdc, dc.host))
    return result


class _NoUsableDc(DiscoverError):
    code = EXIT_NO_USABLE_DC


def _find_pdc(domain: str, lookup: Lookup, result: Discovery) -> None:
    """Mark the PDC emulator, or say why it cannot be named."""
    try:
        records = lookup.srv_targets(f"_ldap._tcp.pdc._msdcs.{domain}")
    except (NoSuchName, NoAnswer):
        result.pdc_problem = "no PDC emulator record was found in DNS"
        return
    except DnsTimeout:
        result.pdc_problem = "the PDC emulator lookup did not answer in time"
        return
    scratch = Discovery(domain=domain)
    hosts = _clean_hosts(records, domain, scratch)
    result.skipped.extend(scratch.skipped)
    if not hosts:
        result.pdc_problem = "no PDC emulator record was found in DNS"
        return
    by_host = {dc.host: dc for dc in result.dcs}
    pdc = by_host.get(hosts[0])
    if pdc is None:
        result.pdc_problem = (
            "the PDC emulator record names a host that is not in the DC list"
        )
        return
    pdc.is_pdc = True
    result.pdc = pdc


# ---- the preflight ------------------------------------------------------------


class Sockets(Protocol):
    """The socket calls the preflight makes.

    The real ``socket`` module satisfies it; the tests give it a fake.
    """

    def create_connection(self, address: tuple[str, int], timeout: float) -> Any: ...

    def socket(self, family: int, socktype: int) -> Any: ...


@dataclass
class PortState:
    """One port of one controller: open, closed or timeout."""

    port: int
    service: str
    state: str


@dataclass
class ClockState:
    """The clock of one controller: the skew, or why it is unknown."""

    seconds: float | None
    reason: str


@dataclass
class PreflightDc:
    """What the preflight found on one controller."""

    host: str
    address: str
    ports: list[PortState] = field(default_factory=list)
    clock: ClockState = field(default_factory=lambda: ClockState(None, "not checked"))

    @property
    def clock_over_limit(self) -> bool:
        """True when the clock is known and more than the limit off."""
        return self.clock.seconds is not None and abs(self.clock.seconds) > SKEW_LIMIT

    @property
    def required_port_not_open(self) -> bool:
        """True when a required port (LDAP or Kerberos) is not open.

        Only a probed port counts: a controller with no address has no
        port to be open or not.
        """
        return any(
            port.port in REQUIRED_PORTS and port.state != "open" for port in self.ports
        )

    @property
    def verdict(self) -> str:
        """PASS, FAIL (the clock or a required port) or UNKNOWN.

        FAIL wins over UNKNOWN: a controller whose LDAP or Kerberos
        port is not open is a FAIL, even when its clock cannot be read.
        """
        if self.clock_over_limit or self.required_port_not_open:
            return "FAIL"
        if self.clock.seconds is None:
            return "UNKNOWN"
        return "PASS"


@dataclass
class Preflight:
    """The preflight of every controller that was found."""

    dcs: list[PreflightDc] = field(default_factory=list)

    @property
    def passed(self) -> int:
        return sum(1 for dc in self.dcs if dc.verdict == "PASS")

    @property
    def failed(self) -> int:
        return sum(1 for dc in self.dcs if dc.verdict == "FAIL")

    @property
    def unknown(self) -> int:
        return sum(1 for dc in self.dcs if dc.verdict == "UNKNOWN")

    @property
    def ok(self) -> bool:
        """True when every controller passed."""
        return self.failed == 0 and self.unknown == 0


def _tcp_state(address: str, port: int, timeout: float, sockets: Sockets) -> str:
    """'open', 'closed' or 'timeout' for one port: connect, then close.

    Nothing is ever sent: the connection is closed as soon as it is made.
    """
    try:
        conn = sockets.create_connection((address, port), timeout=timeout)
    except socket.timeout:
        return "timeout"
    except OSError:
        return "closed"
    try:
        conn.close()
    except OSError:
        pass
    return "open"


def _socket_family(address: str) -> int:
    """The address family of a time query: IPv6 for an IPv6 literal."""
    try:
        if ipaddress.ip_address(address).version == 6:
            return socket.AF_INET6
    except ValueError:
        pass
    return socket.AF_INET


def _ntp_seconds(when: float) -> int:
    """A Unix time as the seconds field of an NTP timestamp."""
    return (int(when) + NTP_EPOCH_OFFSET) & 0xFFFFFFFF


def _random_fraction() -> int:
    """The random 32 bit fraction of the transmit timestamp of a request.

    It is random, so that a reply can be tied to the request it belongs
    to: a time server copies the transmit timestamp of the request
    (bytes 40..47) into the originate timestamp of its reply (bytes
    24..31).
    """
    return secrets.randbits(32)


def _ntp_request(sent: float, fraction: int) -> bytes:
    """The 48 byte SNTP client packet of a time query.

    The transmit timestamp (bytes 40..47) holds the local time; its
    fraction is random, so the reply can be bound to this request.
    """
    request = bytearray(NTP_PACKET_SIZE)
    request[NTP_OFF_LEAP_MODE] = NTP_CLIENT_BYTE
    request[NTP_OFF_TRANSMIT : NTP_OFF_TRANSMIT + NTP_TIMESTAMP_SIZE] = struct.pack(
        ">II", _ntp_seconds(sent), fraction
    )
    return bytes(request)


def _read_reply(reply: bytes, sent: float, received: float, originate: bytes) -> ClockState:
    """The skew from a time server's reply, or why the reply is not one.

    The reply is only used when it belongs to the request: its
    originate timestamp (bytes 24..31) must be the transmit timestamp
    of the request (bytes 40..47), byte for byte.  (RFC 4330, figure 1:
    a time server copies the transmit timestamp of the request into the
    originate timestamp of its reply.)  The skew itself comes from the
    local times of the query, not from the request.

    A reply whose transmit timestamp (bytes 40..47) is all zero carries
    no time at all, so it is discarded (RFC 4330, section 5, check 4):
    the clock of the controller is unknown, never a skew.
    """
    if len(reply) != NTP_PACKET_SIZE:
        return ClockState(None, f"the reply was {len(reply)} bytes, not {NTP_PACKET_SIZE}")
    leap = reply[NTP_OFF_LEAP_MODE] >> 6
    if leap == NTP_LEAP_NOT_SYNCED:
        return ClockState(None, "the clock of the time server is not synchronized")
    mode = reply[NTP_OFF_LEAP_MODE] & 0x07
    if mode != NTP_SERVER_MODE:
        return ClockState(None, f"the reply was not from a time server (mode {mode})")
    stratum = reply[NTP_OFF_STRATUM]
    if not NTP_MIN_STRATUM <= stratum <= NTP_MAX_STRATUM:
        return ClockState(None, f"the time server has no time source (stratum {stratum})")
    if reply[NTP_OFF_ORIGINATE : NTP_OFF_ORIGINATE + NTP_TIMESTAMP_SIZE] != originate:
        return ClockState(None, "the reply does not belong to this time query")
    transmit = reply[NTP_OFF_TRANSMIT : NTP_OFF_TRANSMIT + NTP_TIMESTAMP_SIZE]
    if transmit == bytes(NTP_TIMESTAMP_SIZE):
        return ClockState(None, "the transmit timestamp of the reply is all zero")
    seconds, fraction = struct.unpack(">II", transmit)
    if seconds < NTP_EPOCH_OFFSET:
        seconds += 1 << 32
    server = seconds - NTP_EPOCH_OFFSET + fraction / 2**32
    return ClockState(server - (sent + received) / 2, "")


def _clock_state(
    address: str,
    timeout: float,
    sockets: Sockets,
    now: Callable[[], float],
    fraction: Callable[[], int],
) -> ClockState:
    """One time query to the controller: the clock skew, or why it is unknown.

    The request is the 48 byte SNTP client packet with the local time in
    its transmit timestamp; the reply is read with the same timeout.
    """
    sent = now()
    request = _ntp_request(sent, fraction())
    originate = request[NTP_OFF_TRANSMIT : NTP_OFF_TRANSMIT + NTP_TIMESTAMP_SIZE]
    try:
        sock = sockets.socket(_socket_family(address), socket.SOCK_DGRAM)
    except OSError as exc:
        return ClockState(None, f"the time query could not be started: {exc}")
    try:
        sock.settimeout(timeout)
        # connect() on the datagram socket names the one peer the reply
        # may come from.
        sock.connect((address, NTP_PORT))
        sock.send(request)
        reply = sock.recv(NTP_RECV_SIZE)
    except socket.timeout:
        return ClockState(None, "the controller did not answer the time query in time")
    except OSError as exc:
        return ClockState(None, f"the time query failed: {exc}")
    finally:
        try:
            sock.close()
        except OSError:
            pass
    received = now()
    return _read_reply(reply, sent, received, originate)


def preflight(
    dcs: list[Dc],
    *,
    sockets: Sockets | None = None,
    now: Callable[[], float] | None = None,
    fraction: Callable[[], int] | None = None,
) -> Preflight:
    """Check every controller: the ports, and the clock.

    Read-only, from the host the tool runs on.  The controllers are
    reached at the addresses DNS gave them.  A controller whose LDAP or
    Kerberos port is not open is a FAIL, like one whose clock is too far
    off.
    """
    net = socket if sockets is None else sockets
    clock = time.time if now is None else now
    rand = _random_fraction if fraction is None else fraction
    result = Preflight()
    for dc in dcs:
        if not dc.addresses:
            result.dcs.append(
                PreflightDc(dc.host, "", [], ClockState(None, "the controller has no address"))
            )
            continue
        address = dc.addresses[0]
        ports = [
            PortState(port, service, _tcp_state(address, port, PREFLIGHT_TIMEOUT, net))
            for port, service in PREFLIGHT_PORTS
        ]
        result.dcs.append(
            PreflightDc(
                dc.host,
                address,
                ports,
                _clock_state(address, PREFLIGHT_TIMEOUT, net, clock, rand),
            )
        )
    return result


# ---- what is printed ---------------------------------------------------------

_PDC_NEXT_STEP = (
    "Next step: find the PDC emulator yourself (on Windows: Get-ADDomain | "
    "Select-Object PDCEmulator; on Samba: samba-tool fsmo show), then set "
    "up the write host of the PDC first, and every other DC with the write "
    "command's --domain-device option naming the PDC's device."
)

# One fixed text: no value of the run goes into it, because the values
# of a run come from untrusted DNS.
_PORT_NEXT_STEP = (
    "Next step: LDAP 389 and Kerberos 88 must be reachable from this host: check "
    "the firewall between this host and the DC, and that the AD services run on "
    "that DC."
)


def _command(setup: str, *parts: str) -> str:
    return " ".join([shlex.quote(setup), *(shlex.quote(part) for part in parts)])


def _preflight_lines(found: Preflight) -> list[str]:
    """The lines the preflight prints: one block per controller, then the sum."""
    lines = [
        "",
        "Preflight (read-only, from this host; it probes the addresses DNS gave in "
        "this same run, before you have read the list: run the tool without "
        "--preflight first and check the list against your own DCs. DNS is read "
        "again in this second run: the first list does not limit what the second "
        "run probes, and the addresses it probes are the ones printed here. "
        "Nothing is pinned):",
        "",
    ]
    for dc in found.dcs:
        where = f" ({dc.address})" if dc.address else ""
        lines.append(f"  {dc.host}{where}")
        for port in dc.ports:
            lines.append(f"    {port.port} {port.service}: {port.state}")
        clock = dc.clock
        if clock.seconds is None:
            lines.append(f"    clock skew: unknown ({clock.reason})")
        else:
            side = "over" if abs(clock.seconds) > SKEW_LIMIT else "within"
            lines.append(
                f"    clock skew: {clock.seconds:+.1f} s "
                f"({side} the {SKEW_LIMIT:.0f} s limit)"
            )
        lines.append(f"    {dc.verdict}")
        lines.append("")
    lines.append(
        f"Preflight: {len(found.dcs)} DCs checked, {found.passed} passed, "
        f"{found.failed} failed, {found.unknown} unknown."
    )
    if any(dc.clock_over_limit for dc in found.dcs):
        lines.append(
            "Next step: sync the clocks: the DC with the PDC role is the domain's "
            "time source."
        )
    if any(dc.required_port_not_open for dc in found.dcs):
        lines.append(_PORT_NEXT_STEP)
    if any(dc.clock.seconds is None for dc in found.dcs):
        lines.append(
            "note: the clock of one or more DCs could not be checked (the reason is "
            "above each DC); check that the DC answers NTP on UDP 123."
        )
    return lines


def _host_key_lines(found: Discovery) -> list[str]:
    """The host keys of every controller, and what to do with them."""
    lines = [
        "Host keys, fetched with ssh-keyscan (they come over the network, so they "
        "can be spoofed):",
        "",
    ]
    for dc in found.dcs:
        lines.append(f"  {dc.host}")
        if dc.keys:
            for key in dc.keys:
                lines.append(f"    {key.keytype} {key.fingerprint}")
            if dc.keys_cut:
                lines.append(
                    f"    the list of host keys was cut: more than "
                    f"{hostkeys.MAX_KEYS} keys were found, so the fingerprints "
                    "above are not all of them and the ready known_hosts lines "
                    "below are not all of the keys either"
                )
            lines.append("    ready known_hosts lines:")
            for key in dc.keys:
                lines.append(f"      {dc.host} {key.keytype} {key.blob}")
        else:
            lines.append(
                f"    no host key was scanned ({dc.key_note}): the known_hosts line "
                "stays a placeholder the owner fills in."
            )
    lines += [
        "",
        "Compare every fingerprint above with the one the controller shows at its "
        "console (on the controller: ssh-keygen -lf on its host key) before you "
        "trust it: a keyscan travels over the network, so it can be spoofed. Put "
        "the ready known_hosts lines above in the known_hosts file of the newton "
        "account and fill the inventory entry's known_hosts line with the path of "
        "that file.",
        "",
        "A scan resolves the host name with the system resolver, not with "
        "--resolver (that one is for the lookups of the discovery): the scan can "
        "land on another address than the one DNS gave, which is one more reason "
        "to compare every fingerprint at the controller.",
    ]
    return lines


def render(
    found: Discovery,
    *,
    platform: str,
    pubkey: str,
    write: bool,
    ous: list[str],
    setup: str,
    ops_pubkey: str | None = None,
    checked: Preflight | None = None,
) -> str:
    """The text the tool prints."""
    domain = found.domain
    lines = [f"Domain controllers of {domain}, from DNS (untrusted):", ""]
    for dc in found.dcs:
        mark = "  (PDC emulator)" if dc.is_pdc else ""
        where = "  " + ", ".join(dc.addresses) if dc.addresses else ""
        lines.append(f"  {dc.host}{mark}{where}")
    lines.append("")
    for item in found.skipped:
        lines.append(item)
    for item in found.notes:
        lines.append(f"note: {item}")
    if found.pdc_problem:
        lines.append(f"{found.pdc_problem}.")
    if found.fetched_keys:
        lines += _host_key_lines(found)
    lines += [
        "",
        "DNS can be spoofed. Before you run anything, check this list against your "
        "domain controllers: a host that is not yours must not be set up. The SSH "
        "host key you pin during setup still protects the logins.",
    ]
    if checked is not None:
        lines += _preflight_lines(checked)
    lines += [
        "",
    ]
    if found.fetched_keys:
        lines += [
            "Nothing was set up on any controller and nothing was changed: only the "
            "host keys above were scanned. Inventory entries (the setup script "
            "prints the full one, with the key_file and known_hosts lines to fill "
            "in):",
            "",
        ]
    else:
        lines += [
            "Nothing was run. Inventory entries (the setup script prints the full one, "
            "with the key_file and known_hosts lines to fill in):",
            "",
        ]
    platform_name = "ad-windows" if platform == "windows" else "ad-samba"
    user = f"newton-audit@{domain}" if platform == "windows" else "newton-ssh"
    for dc in found.dcs:
        lines += [
            f"[devices.{dc.device}]",
            f'platform = "{platform_name}"',
            f'host = "{dc.host}"',
            f'user = "{user}"',
            f'domain = "{domain}"',
            "",
        ]
    lines.append("Audit setup, one command per controller:")
    lines.append("")
    for dc in found.dcs:
        lines.append(
            _command(
                setup, platform, "--domain", domain, "--pubkey", pubkey,
                "--device", dc.device, "--host", dc.host,
            )
        )
    if write:
        lines += ["", "Change setup, the PDC emulator first:", ""]
        if found.pdc is None:
            lines.append("Not printed: " + (found.pdc_problem or "no PDC emulator") + ".")
            lines.append(_PDC_NEXT_STEP)
        else:
            for dc in found.dcs:
                parts = [
                    "write", platform, "--domain", domain, "--pubkey", ops_pubkey,
                    "--device", dc.write_device, "--host", dc.host,
                ]
                if not dc.is_pdc:
                    parts += ["--domain-device", found.pdc.write_device]
                for ou in ous:
                    parts += ["--ou", ou]
                lines.append(_command(setup, *parts))
    elif found.pdc_problem:
        lines += ["", _PDC_NEXT_STEP]
    return "\n".join(lines) + "\n"


# ---- the command line --------------------------------------------------------


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="newton-ad-discover",
        description=(
            "Find the domain controllers of a domain from DNS and print the "
            "newton-ad-setup commands for them. Nothing is set up and nothing "
            "is written."
        ),
    )
    parser.add_argument("--domain", required=True, help="the DNS name of the domain")
    parser.add_argument("--platform", required=True, choices=("windows", "samba"))
    parser.add_argument("--pubkey", required=True, help="the public key of the audit key")
    parser.add_argument("--write", action="store_true", help="also print the write setup commands")
    parser.add_argument(
        "--ops-pubkey",
        help="the public key of the operations key (with --write); never the audit key",
    )
    parser.add_argument(
        "--ou", action="append", dest="ous", metavar="DN", default=[],
        help="a delegated location (with --write); give it once per location",
    )
    parser.add_argument(
        "--resolver",
        default=None,
        metavar="IP",
        help=(
            "the DNS server to ask for the lookups of the discovery; ssh-keyscan "
            "resolves the host name of a scan with the system resolver"
        ),
    )
    parser.add_argument(
        "--preflight",
        action="store_true",
        help=(
            "also check every controller: the ports 22, 389 and 88, and the clock "
            "skew (read-only, from this host); a controller whose LDAP 389 or "
            "Kerberos 88 is not open is a FAIL, like a clock more than 300 s off"
        ),
    )
    parser.add_argument(
        "--fetch-host-keys",
        action="store_true",
        help=(
            "also fetch the host keys of every controller with ssh-keyscan and print "
            "their fingerprints and their known_hosts lines"
        ),
    )
    return parser


def main(
    argv: list[str] | None = None,
    lookup: Lookup | None = None,
    sockets: Sockets | None = None,
    now: Callable[[], float] | None = None,
    fraction: Callable[[], int] | None = None,
    keyscan: Runner | None = None,
) -> int:
    """Print the setup commands of a domain."""
    args = _parser().parse_args(argv)
    domain = args.domain
    try:
        if DOMAIN_RE.fullmatch(domain) is None or len(domain) > MAX_NAME:
            raise SetupError("the domain must be a DNS name")
        domain = domain.lower()
        audit_key = _read_public_key(Path(args.pubkey))
        if args.write:
            if not args.ous:
                raise SetupError("--write needs at least one --ou")
            validate_ous(args.ous, domain)
            if args.ops_pubkey is None:
                raise SetupError(
                    "--write needs --ops-pubkey: the write setup authorises its key for "
                    "newton-ops, so it takes the operations key, not the audit key"
                )
            ops_key = _read_public_key(Path(args.ops_pubkey))
            if ops_key.split()[:2] == audit_key.split()[:2]:
                raise SetupError(
                    "--ops-pubkey holds the audit key: give the public key of the "
                    "operations key (dc1-ops.pub), a different key"
                )
        elif args.ous:
            raise SetupError("--ou is only used with --write")
        elif args.ops_pubkey is not None:
            raise SetupError("--ops-pubkey is only used with --write")
        if args.resolver is not None:
            try:
                ipaddress.ip_address(args.resolver)
            except ValueError as exc:
                raise SetupError("--resolver must be an IP address") from exc
    except SetupError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ARGUMENTS
    except OSError as exc:
        print(f"error: the public key cannot be read: {exc}", file=sys.stderr)
        return EXIT_ARGUMENTS

    try:
        resolver = lookup if lookup is not None else DnsLookup(args.resolver)
        found = discover(domain, resolver)
    except (NoSuchName, NoAnswer):
        print(f"error: DNS has no domain controller records for {domain}", file=sys.stderr)
        return EXIT_NO_RECORDS
    except DnsTimeout:
        print(
            f"error: DNS did not answer in time for {domain}; check --resolver or the "
            "network, then run it again",
            file=sys.stderr,
        )
        return EXIT_TIMEOUT
    except DiscoverError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return exc.code
    checked = (
        preflight(found.dcs, sockets=sockets, now=now, fraction=fraction)
        if args.preflight
        else None
    )
    if args.fetch_host_keys:
        found.fetched_keys = True
        runner = keyscan if keyscan is not None else hostkeys.run_program
        for dc in found.dcs:
            scan = hostkeys.scan_host(dc.host, runner)
            dc.keys = scan.keys
            dc.key_note = scan.note
            dc.keys_cut = scan.cut
    setup = os.environ.get("NEWTON_AD_SETUP") or "newton-ad-setup"
    sys.stdout.write(
        render(
            found,
            platform=args.platform,
            pubkey=args.pubkey,
            ops_pubkey=args.ops_pubkey,
            write=args.write,
            ous=args.ous,
            setup=setup,
            checked=checked,
        )
    )
    if checked is not None and not checked.ok:
        return EXIT_PREFLIGHT
    if args.write and found.pdc is None:
        return EXIT_NO_PDC
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
