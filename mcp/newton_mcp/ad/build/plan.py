"""The build plan of Newton 1.5 (DESIGN-1.5 "The plan", PLAN-1.5 task 1).

The plan is one document: the owner approves its bytes once, the
helpers receive those bytes with every request, and every parameter a
stage template uses is read out of them.  Nothing outside the bytes
reaches a template, so this module is the whole of what a build is.

THE CANONICAL BYTES

The document is ASCII, one ``key=value`` pair per line, LF only, and
its first line is the header ``newton-ad-build-v1``.  The pairs are
sorted ordinally, by byte value, as SPEC-1.4-REQUEST section 4 sorts
them.  The rules of the 1.4 request format that fit are the ones
reused here: the header line, the ``key=value`` line, the ASCII bytes,
the LF, the decimal int without a sign or a leading zero, and the
comma-joined list of the values of one pair.

The rules of 1.4 that do not fit are the fixed order of its lines and
its one-level objects: a plan holds lists (the servers, the groups,
the findings) and sections (the domain, the baseline, the stages), so
the keys of the plan are dotted and indexed -- ``domain.dns_name``,
``servers.0.ip``, ``accepted_findings.0.id``, ``stages.graph.dc1``.
Every value of the plan is in the bytes, and every byte of the plan is
in a value, so the digest of the bytes is the digest of the plan.

THE PLAN IS THE PLAN OF ``plan_build``

A plan can be changed on the way from the inputs to the bytes: a
value with a newline in it would inject a line into the bytes, a
field the plan does not have would be dropped without a word, and a
stage kind or a stage graph could be changed and signed as it is.
So the canonical bytes and the stage graph rebuild the plan out of
its own fields first and refuse it unless it is the plan
``plan_build`` makes of them.


THE GRAMMAR OF THE PLAN

Every value of the plan comes out of a grammar, and the grammar of a
value is the one of its field: the functional level is one of the
levels of the design, a name is a name, an address is an IPv4
address, a prefix is a number in its range.  A name, a path, a
forwarder or a finding id is not in the plan twice (two names that
differ in their case are one name), a server holds at
least one forwarder, the gateway of a server is inside the network of
its address and its prefix, and the GUID of a Proxmox VM is held in
lower case, so one VM is one plan.

THE REFUSAL CODES

The codes are the nine of the plan, and no others.  ``bad_dns_name``
and ``bad_netbios`` are the domain's two names; ``bad_ip`` is every
address of the plan (the servers, their gateways, their forwarders);
``duplicate_ip`` is two servers with one address;
``two_servers_same_name`` is two servers with one name (the device
name, the hostname or the vmgenid of a Proxmox VM);
``unknown_baseline_option`` is a baseline
setting or a value of it that is not in the allowlist;
``proxmox_without_vmgenid`` and ``proxmox_without_agent`` are the two
things a Proxmox VM must have; ``free_text`` is every other value that
is not from the grammar it must belong to -- an enum outside its set,
a name with a character outside its pattern, a field the plan does not
have, a field the plan needs and does not get, a value of the wrong
kind, or a plan that is not the plan of ``plan_build``.  The message
of a refusal is for the log and never carries the value that was
refused.

THE REUSE

The key of a server and the token of a plan are the ones of
``newton_mcp.approve``: ``derive_k`` and ``approval_token`` are called
here and never reimplemented.

THE DERIVED SECRETS

A derivation takes the info string of the secret it derives: the two of
the design and no others.  The DSRM secret and the owner's first admin
password are the only two, and each of them has its own info string, so
one key material gives two different secrets.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import ipaddress
import re
from collections.abc import Mapping, Sequence
from typing import Any

from ..write import request as _write_request
from . import baseline as _baseline


#: The header line of the canonical plan document.
PLAN_HEADER = "newton-ad-build-v1"

#: The header line of the message the stage digest is the hash of.
STAGE_HEADER = "newton-ad-build-stage-v1"

#: The info string of the DSRM secret.
DSRM_INFO = "newton-ad-build-dsrm-v1"

#: The info string of the owner's first admin password.
ADMIN_INFO = "newton-ad-build-admin-v1"

#: The info strings of the derived secrets: the two of the design and
#: no others.
INFO_STRINGS: tuple[str, ...] = (
    "newton-ad-build-dsrm-v1",
    "newton-ad-build-admin-v1",
)

#: The stage ids of the design table.
STAGE_IDS: tuple[str, ...] = ("0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10")

#: The kind of every stage (DESIGN-1.5, the stage table).
STAGE_KINDS: dict[str, str] = {
    "0": "read",
    "1": "reversible",
    "2": "irreversible",
    "3": "irreversible",
    "4": "irreversible",
    "5": "reversible",
    "6": "irreversible",
    "7": "irreversible",
    "8": "reversible",
    "9": "final",
    "10": "read",
}

#: The stage graph of DC1 when the plan holds a DC2 as well.
DC1_GRAPH: tuple[str, ...] = ("0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10")

#: The stage graph of DC2.
DC2_GRAPH: tuple[str, ...] = ("0", "1", "7", "9")

#: The stage graph of DC1 when the plan holds no DC2: stage 7 does not
#: exist, because there is no second DC to join.
DC1_GRAPH_ALONE: tuple[str, ...] = tuple(
    stage for stage in DC1_GRAPH if stage != "7"
)

#: The roles of the servers.
ROLES: tuple[str, ...] = ("dc1", "dc2")

#: The checkpoint methods of the design.
CHECKPOINT_METHODS: tuple[str, ...] = ("hyperv", "proxmox", "wbadmin")

#: The codes the plan refuses with.  There are no others.
REFUSAL_CODES: tuple[str, ...] = (
    "bad_dns_name",
    "bad_netbios",
    "bad_ip",
    "duplicate_ip",
    "unknown_baseline_option",
    "free_text",
    "two_servers_same_name",
    "proxmox_without_vmgenid",
    "proxmox_without_agent",
)

#: The baseline settings that have options, and the options each one
#: may take: the ones of the baseline file of task 6
#: (``baseline-2026.11.toml``, read by ``baseline.load_baseline``).
BASELINE_OPTIONS: dict[str, tuple[str, ...]] = _baseline.load_baseline(
    _baseline.VERSIONS[-1]
).options()

#: The length of a derived secret.
SECRET_LENGTH = 24

#: The alphabets of a derived secret.  The ambiguous characters (0, O,
#: 1, l and I) are left out: the owner reads the secret once, in a
#: terminal, and types it.
_UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ"
_LOWER = "abcdefghijkmnopqrstuvwxyz"
_DIGIT = "23456789"
_SYMBOL = "!@#$%^&*-+=_"

#: A DNS name of the domain: two labels or more, each of them a label.
DNS_NAME_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
)

#: The longest a DNS name of the domain may be: 253 characters, the
#: length of a name in the wire format.
DNS_NAME_MAX = 253

#: A NetBIOS name: 15 characters at most, no dot, no space.
NETBIOS_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,14}$")

#: The hostname of a server: the shape of a computer name, so it starts
#: and ends with a letter or a digit and holds no underscore.
HOSTNAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,13}[A-Za-z0-9])?$")

#: A name of the domain: an OU, a group, the owner's admin account or
#: the site.  No comma (the separator of the canonical form), no quote,
#: no backslash, nothing that a shell or a template could read as
#: something else.
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}$")

#: The owner's admin account: the shape of an sAMAccountName, so it is
#: 8 to 20 characters.  A shorter name is a name the derived admin
#: secret could hold (one name of three letters in about 1600).
OWNER_ADMIN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{7,19}$")

#: The names the owner's admin account may not be: the build account of
#: the design (the account the helper logs in with) and every account a
#: fresh forest already holds: the built-in Administrator (the build
#: disables it or resets its password), Guest, krbtgt and DefaultAccount,
#: and WDAGUtilityAccount, the account Windows makes for Application
#: Guard.  Stage 5 adds the owner's admin account to Domain Admins and
#: Protected Users, so it must be an account the build makes (IC4 of the
#: task 6 triage; the helper also refuses an account Newton did not
#: make).  Compared case-folded, as sAMAccountName is.
RESERVED_OWNER_ADMINS: frozenset[str] = frozenset(
    {"newton-build", "administrator", "guest", "krbtgt", "defaultaccount", "wdagutilityaccount"}
)

#: The functional level of the forest: the level the design builds the
#: forest at, and no other.
FUNCTIONAL_LEVELS: tuple[str, ...] = ("Win2025",)

#: The domain functional levels of Windows Server and their
#: msDS-Behavior-Version numbers (the numbers the directory holds, as
#: the read of stage 2 shows them).  The design builds the forest at
#: 2025 only (``FUNCTIONAL_LEVELS``); this table is here for the one
#: refusal that names a level: the Windows LAPS policy of the baseline
#: (``ADPasswordEncryptionEnabled``) needs the domain functional level
#: 2016 or later, so a plan that asks for an older level is refused with
#: that reason.
DOMAIN_LEVELS: dict[str, int] = {
    "Win2000": 0,
    "WinXP": 1,
    "Win2003": 2,
    "Win2008": 3,
    "Win2008R2": 4,
    "Win2012": 5,
    "Win2012R2": 6,
    "Win2016": 7,
    "Win2019": 8,
    "Win2022": 9,
    "Win2025": 10,
}

#: The domain functional level the Windows LAPS policy of the baseline
#: needs: the encryption of the password in the directory is off below
#: it.
LAPS_MINIMUM_DOMAIN_LEVEL: int = 7

#: The id of a 1.3 finding: ``AD-``, a letter, a hyphen, two digits and
#: at most one lower case letter after them (the lettered checks of the
#: catalogue carry one).
FINDING_ID_RE = re.compile(r"^AD-[A-Z]-[0-9]{2}[a-z]?$")

#: The reason code of an accepted finding: a code, never a sentence.
REASON_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")

#: The version of the baseline.
VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")

#: The name of a baseline setting.
OPTION_KEY_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")

#: The value of a baseline option.
OPTION_VALUE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

#: A digest: 64 lowercase hexadecimal characters.
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")

#: The key K of a server: 64 lowercase hexadecimal characters.
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")

#: The id of a checkpoint: printable ASCII, no space, no newline.
CHECKPOINT_ID_RE = re.compile(r"^[!-~]{1,128}$")

#: The newton-ops public key of stage 8 (the maintainer's decision R1, 2026-11-15): the
#: type ``ssh-ed25519``, one space and the base64 body of one ed25519 key
#: (51 bytes: the type field and the 32-byte key), no comment, no options.
OPS_PUBLIC_KEY_RE = re.compile(r"^ssh-ed25519 [A-Za-z0-9+/]{68}$")

#: The blob of an ed25519 public key: the length-prefixed type, then the
#: length-prefixed 32 bytes of the key.
_ED25519_HEAD = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20"

#: The fields of the domain.
_DOMAIN_FIELDS = frozenset(
    {
        "dns_name",
        "netbios",
        "functional_level",
        "site",
        "ou_tree",
        "groups",
        "owner_admin",
    }
)

#: The fields of a server, without the two of a Proxmox VM.
_SERVER_FIELDS = frozenset(
    {
        "device",
        "role",
        "hostname",
        "ip",
        "prefix",
        "gateway",
        "forwarders",
        "checkpoint",
    }
)

#: The two fields a Proxmox VM holds and no other server does.
_PROXMOX_FIELDS = frozenset({"vmgenid", "agent"})

#: The fields of the baseline.
_BASELINE_FIELDS = frozenset({"version", "options"})

#: The fields of an accepted finding.
_FINDING_FIELDS = frozenset({"id", "reason"})

#: The fields of the ops section: stage 8's newton-ops public key and the
#: sha256 of the 1.4 write helper (``write.ps1``) the stage installs (the maintainer's
#: decision R1, 2026-11-15), and the public key of the read-only newton-audit
#: login of the 1.3 collector, which stage 8 installs too and stage 10
#: reads through (the maintainer's decision on open point 34, 2026-11-16).
_OPS_FIELDS = frozenset({"audit_public_key", "public_key", "write_helper_sha256"})

#: The fields the inputs may hold.
_INPUT_FIELDS = frozenset(
    {
        "domain",
        "servers",
        "baseline",
        "accepted_findings",
        "ops",
        "resume_from",
        "start_stage",
        "secrets_from",
    }
)

#: The fields the inputs must hold.
_REQUIRED_INPUT_FIELDS = ("domain", "servers", "baseline", "accepted_findings", "ops")


class BuildPlanRefused(Exception):
    """The plan is refused with one of the codes of the plan.

    The code is the word the caller answers with; the message is for
    the log and never carries the value that was refused.
    """

    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(message or code)
        self.code = code
        self.message = message or code


def _refuse(code: str, message: str) -> BuildPlanRefused:
    return BuildPlanRefused(code, message)


# --------------------------------------------------------------------------
# The grammar of the inputs
# --------------------------------------------------------------------------


def _text(value: Any, where: str) -> str:
    """A value that must be text."""
    if not isinstance(value, str):
        raise _refuse("free_text", f"{where} is not text")
    return value


def _mapping(value: Any, where: str) -> Mapping[str, Any]:
    """A value that must be an object."""
    if not isinstance(value, Mapping):
        raise _refuse("free_text", f"{where} is not an object")
    return value


def _sequence(value: Any, where: str) -> list[Any]:
    """A value that must be a list."""
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise _refuse("free_text", f"{where} is not a list")
    return list(value)


def _exact_fields(value: Mapping[str, Any], fields: frozenset[str], where: str) -> None:
    """An object that must hold exactly the fields it may hold."""
    if set(value) != set(fields):
        raise _refuse("free_text", f"{where} does not hold exactly its own fields")


def _ipv4(value: Any, where: str) -> str:
    """An address that must be an IPv4 address."""
    if not isinstance(value, str):
        raise _refuse("bad_ip", f"{where} is not an IPv4 address")
    try:
        address = ipaddress.IPv4Address(value)
    except ValueError:
        raise _refuse("bad_ip", f"{where} is not an IPv4 address") from None
    return str(address)


def _int(value: Any, where: str) -> int:
    """A value that must be an int, and not a bool."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise _refuse("free_text", f"{where} is not an integer")
    return value


def _names(values: Any, where: str) -> list[str]:
    """A list of names of the domain, and no name twice.

    Two names that differ in their case are one name: the names of a
    domain are the names of its accounts and of its containers, and
    those do not have two spellings.  The plan holds the spelling the
    names were given in.
    """
    names: list[str] = []
    for value in _sequence(values, where):
        name = _text(value, where)
        if NAME_RE.fullmatch(name) is None:
            raise _refuse("free_text", f"{where} holds a name outside its grammar")
        names.append(name)
    if len({name.casefold() for name in names}) != len(names):
        raise _refuse("free_text", f"{where} holds a name twice")
    return names


def _domain(inputs: Mapping[str, Any]) -> dict[str, Any]:
    """The domain of the plan."""
    domain = _mapping(inputs.get("domain"), "the domain")
    _exact_fields(domain, _DOMAIN_FIELDS, "the domain")

    dns_name = _text(domain.get("dns_name"), "the DNS name")
    if DNS_NAME_RE.fullmatch(dns_name) is None:
        raise _refuse("bad_dns_name", "the DNS name is outside its grammar")
    if len(dns_name) > DNS_NAME_MAX:
        raise _refuse("bad_dns_name", "the DNS name is longer than 253 characters")
    if dns_name.rsplit(".", 1)[-1].isdigit():
        raise _refuse("bad_dns_name", "the last label of the DNS name is a number")

    netbios = _text(domain.get("netbios"), "the NetBIOS name")
    if NETBIOS_RE.fullmatch(netbios) is None:
        raise _refuse("bad_netbios", "the NetBIOS name is outside its grammar")
    if netbios.isdigit():
        raise _refuse("bad_netbios", "the NetBIOS name is a number")

    functional_level = _text(domain.get("functional_level"), "the functional level")
    if functional_level not in FUNCTIONAL_LEVELS:
        number = DOMAIN_LEVELS.get(functional_level)
        if number is not None and number < LAPS_MINIMUM_DOMAIN_LEVEL:
            raise _refuse(
                "free_text",
                "the Windows LAPS policy of the domain controllers needs the domain "
                f"functional level 2016 or later; the plan asks for {functional_level} "
                f"(level {number})",
            )
        raise _refuse("free_text", "the functional level is not one of the design")

    site = _text(domain.get("site"), "the site")
    if NAME_RE.fullmatch(site) is None:
        raise _refuse("free_text", "the site is outside its grammar")

    owner_admin = _text(domain.get("owner_admin"), "the owner's admin account")
    if OWNER_ADMIN_RE.fullmatch(owner_admin) is None:
        raise _refuse("free_text", "the owner's admin account is outside its grammar")
    folded_admin = owner_admin.casefold()
    if folded_admin in RESERVED_OWNER_ADMINS:
        raise _refuse("free_text", "the owner's admin account is a reserved name")

    groups = _names(domain.get("groups"), "the groups")
    if any(folded_admin == group.casefold() for group in groups):
        raise _refuse(
            "free_text", "the owner's admin account is the name of a group"
        )

    ou_tree: list[str] = []
    for path in _sequence(domain.get("ou_tree"), "the OU tree"):
        text = _text(path, "the OU tree")
        names = text.split("/")
        for name in names:
            if NAME_RE.fullmatch(name) is None:
                raise _refuse(
                    "free_text", "the OU tree holds a name outside its grammar"
                )
        ou_tree.append("/".join(names))
    if len({path.casefold() for path in ou_tree}) != len(ou_tree):
        raise _refuse("free_text", "the OU tree holds a path twice")

    return {
        "dns_name": dns_name,
        "netbios": netbios,
        "functional_level": functional_level,
        "site": site,
        "ou_tree": ou_tree,
        "groups": groups,
        "owner_admin": owner_admin,
    }


def _server(raw: Any, index: int) -> dict[str, Any]:
    """One server of the plan."""
    server = _mapping(raw, f"server {index}")

    checkpoint = _text(server.get("checkpoint"), "the checkpoint method")
    if checkpoint not in CHECKPOINT_METHODS:
        raise _refuse("free_text", "the checkpoint method is not one of the three")

    # The two Proxmox fields are checked before the shape of the server,
    # so that a Proxmox VM without them is refused with the code of its
    # own defect and not with the code of a missing field.
    vmgenid: str | None = None
    agent: int | None = None
    if checkpoint == "proxmox":
        raw_vmgenid = server.get("vmgenid")
        if isinstance(raw_vmgenid, str):
            # The GUID of a VM is one value: the plan holds it in lower
            # case, so the plan of an upper case vmgenid is the plan of
            # the lower case one.
            raw_vmgenid = raw_vmgenid.lower()
        if (
            not isinstance(raw_vmgenid, str)
            or _write_request.GUID_RE.fullmatch(raw_vmgenid) is None
        ):
            raise _refuse("proxmox_without_vmgenid", "the Proxmox VM has no vmgenid")
        raw_agent = server.get("agent")
        if (
            isinstance(raw_agent, bool)
            or not isinstance(raw_agent, int)
            or raw_agent != 1
        ):
            raise _refuse(
                "proxmox_without_agent", "the Proxmox VM has no guest agent"
            )
        vmgenid = raw_vmgenid
        agent = raw_agent
        fields = _SERVER_FIELDS | _PROXMOX_FIELDS
    else:
        fields = _SERVER_FIELDS
    _exact_fields(server, fields, f"server {index}")

    device = _text(server.get("device"), "the device name")
    if _write_request.DEVICE_RE.fullmatch(device) is None:
        raise _refuse("free_text", "the device name is outside its grammar")

    role = _text(server.get("role"), "the role")
    if role not in ROLES:
        raise _refuse("free_text", "the role is not dc1 or dc2")

    hostname = _text(server.get("hostname"), "the hostname")
    if HOSTNAME_RE.fullmatch(hostname) is None or hostname.isdigit():
        raise _refuse("free_text", "the hostname is outside its grammar")

    prefix = _int(server.get("prefix"), "the prefix")
    if not 1 <= prefix <= 30:
        raise _refuse("free_text", "the prefix is outside its range")

    address = _ipv4(server.get("ip"), "the IP address")
    gateway = _ipv4(server.get("gateway"), "the gateway")
    ip_address = ipaddress.IPv4Address(address)
    gateway_address = ipaddress.IPv4Address(gateway)

    # The address of the server and the address of its gateway are
    # addresses the build can be reached at: an unspecified, a
    # loopback, a multicast, a link-local or a reserved address is not
    # one of them.
    for value, where in (
        (ip_address, "the IP address"),
        (gateway_address, "the gateway"),
    ):
        if (
            value.is_unspecified
            or value.is_loopback
            or value.is_multicast
            or value.is_link_local
            or value.is_reserved
        ):
            raise _refuse("bad_ip", f"{where} is an address that cannot be used")

    network = ipaddress.ip_network(f"{address}/{prefix}", strict=False)
    if ip_address in (network.network_address, network.broadcast_address):
        raise _refuse("bad_ip", "the IP address is an address of the network")
    if gateway_address in (network.network_address, network.broadcast_address):
        raise _refuse("bad_ip", "the gateway is an address of the network")
    if gateway_address == ip_address:
        raise _refuse("bad_ip", "the gateway is the address of the server")
    if gateway_address not in network:
        raise _refuse("bad_ip", "the gateway is outside the network of the server")

    forwarders = [
        _ipv4(value, "a DNS forwarder")
        for value in _sequence(server.get("forwarders"), "the DNS forwarders")
    ]
    if not forwarders:
        raise _refuse("free_text", "the server holds no DNS forwarder")
    if len(set(forwarders)) != len(forwarders):
        raise _refuse("free_text", "the server holds a DNS forwarder twice")
    for value in forwarders:
        forwarder = ipaddress.IPv4Address(value)
        if (
            forwarder.is_unspecified
            or forwarder.is_loopback
            or forwarder.is_multicast
            or forwarder.is_link_local
            or forwarder.is_reserved
        ):
            raise _refuse("bad_ip", "a DNS forwarder cannot be used")
        if forwarder == ip_address:
            raise _refuse("bad_ip", "a DNS forwarder is the address of the server")

    built: dict[str, Any] = {
        "device": device,
        "role": role,
        "hostname": hostname,
        "ip": address,
        "prefix": prefix,
        "gateway": gateway,
        "forwarders": forwarders,
        "checkpoint": checkpoint,
    }
    if vmgenid is not None:
        built["vmgenid"] = vmgenid
    if agent is not None:
        built["agent"] = agent
    return built


def _servers(inputs: Mapping[str, Any]) -> list[dict[str, Any]]:
    """The servers of the plan."""
    raw = _sequence(inputs.get("servers"), "the servers")
    if not 1 <= len(raw) <= 2:
        raise _refuse("free_text", "the plan holds one server or two")

    servers = [_server(one, index) for index, one in enumerate(raw)]

    roles = [server["role"] for server in servers]
    if len(set(roles)) != len(roles):
        raise _refuse("free_text", "two servers hold the same role")

    # The forest root is DC1, so a plan without a DC1 is not a plan of
    # a build: the graph of the design has no other root.
    if "dc1" not in roles:
        raise _refuse("free_text", "the plan has no dc1")

    addresses = [server["ip"] for server in servers]
    if len(set(addresses)) != len(addresses):
        raise _refuse("duplicate_ip", "two servers hold the same address")

    devices = [server["device"].casefold() for server in servers]
    if len(set(devices)) != len(devices):
        raise _refuse("two_servers_same_name", "two servers hold the same device name")

    hostnames = [server["hostname"].casefold() for server in servers]
    if len(set(hostnames)) != len(hostnames):
        raise _refuse("two_servers_same_name", "two servers hold the same hostname")

    # The GUID of a Proxmox VM is one value, so the plan holds it in
    # lower case: two servers with one GUID are one VM.
    vmgenids = [server["vmgenid"] for server in servers if "vmgenid" in server]
    if len(set(vmgenids)) != len(vmgenids):
        raise _refuse("two_servers_same_name", "two servers hold the same vmgenid")

    # The order of the servers is the order of the plan, not the order
    # the caller happened to list them in: DC1 first, then DC2.
    servers.sort(key=lambda server: server["role"])
    return servers


def _baseline(inputs: Mapping[str, Any]) -> dict[str, Any]:
    """The baseline of the plan."""
    baseline = _mapping(inputs.get("baseline"), "the baseline")
    _exact_fields(baseline, _BASELINE_FIELDS, "the baseline")

    version = _text(baseline.get("version"), "the baseline version")
    if VERSION_RE.fullmatch(version) is None:
        raise _refuse("free_text", "the baseline version is outside its grammar")

    options: dict[str, str] = {}
    for key, value in _mapping(
        baseline.get("options"), "the baseline options"
    ).items():
        if not isinstance(key, str) or OPTION_KEY_RE.fullmatch(key) is None:
            raise _refuse(
                "unknown_baseline_option", "a baseline setting is outside its grammar"
            )
        allowed = BASELINE_OPTIONS.get(key)
        if allowed is None:
            raise _refuse(
                "unknown_baseline_option",
                "a baseline setting is not one of the known ones",
            )
        if not isinstance(value, str) or OPTION_VALUE_RE.fullmatch(value) is None:
            raise _refuse(
                "unknown_baseline_option", "a baseline option is outside its grammar"
            )
        if value not in allowed:
            raise _refuse(
                "unknown_baseline_option",
                "a baseline option is not one of the options of its setting",
            )
        options[key] = value

    # Every setting that has options has one of them chosen: a
    # baseline that says nothing about the built-in Administrator
    # leaves the choice to whoever runs the build.
    if set(options) != set(BASELINE_OPTIONS):
        raise _refuse(
            "free_text", "a setting that has options has no option chosen"
        )

    return {"version": version, "options": dict(sorted(options.items()))}


def _findings(inputs: Mapping[str, Any]) -> list[dict[str, str]]:
    """The accepted 1.3 findings of the plan."""
    findings: list[dict[str, str]] = []
    for raw in _sequence(inputs.get("accepted_findings"), "the accepted findings"):
        finding = _mapping(raw, "an accepted finding")
        _exact_fields(finding, _FINDING_FIELDS, "an accepted finding")
        identifier = _text(finding.get("id"), "the id of an accepted finding")
        if FINDING_ID_RE.fullmatch(identifier) is None:
            raise _refuse(
                "free_text", "the id of an accepted finding is outside its grammar"
            )
        reason = _text(finding.get("reason"), "the reason of an accepted finding")
        if REASON_RE.fullmatch(reason) is None:
            raise _refuse(
                "free_text", "the reason of an accepted finding is outside its grammar"
            )
        findings.append({"id": identifier, "reason": reason})
    identifiers = [finding["id"] for finding in findings]
    if len(set(identifiers)) != len(identifiers):
        raise _refuse("free_text", "two accepted findings hold the same id")
    return findings


def _ed25519_key(value: Any, what: str) -> str:
    """One public key of stage 8, checked whole: the line's grammar, then
    the base64 body decodes to exactly one ed25519 key blob."""
    key = _text(value, what)
    if OPS_PUBLIC_KEY_RE.fullmatch(key) is None:
        raise _refuse("free_text", f"{what} is outside its grammar")
    try:
        blob = base64.b64decode(key.split(" ", 1)[1], validate=True)
    except (binascii.Error, ValueError):
        raise _refuse("free_text", f"{what} is not base64") from None
    if len(blob) != len(_ED25519_HEAD) + 32 or not blob.startswith(_ED25519_HEAD):
        raise _refuse("free_text", f"{what} is not one ed25519 key")
    return key


def _ops(inputs: Mapping[str, Any]) -> dict[str, str]:
    """The ops section of the plan: what stage 8 installs (the maintainer's decision R1,
    2026-11-15, and his ruling on open point 34, 2026-11-16).  Both keys
    are in the same grammar, and they are two keys: one key for both
    logins would give the holder of the read-only login the write one."""
    ops = _mapping(inputs.get("ops"), "the ops section")
    _exact_fields(ops, _OPS_FIELDS, "the ops section")
    key = _ed25519_key(ops.get("public_key"), "the newton-ops public key")
    audit = _ed25519_key(ops.get("audit_public_key"), "the newton-audit public key")
    if audit == key:
        raise _refuse("free_text", "the newton-audit public key is the newton-ops public key")
    sha = _text(ops.get("write_helper_sha256"), "the sha256 of the write helper")
    if DIGEST_RE.fullmatch(sha) is None:
        raise _refuse("free_text", "the sha256 of the write helper is not a digest")
    return {"audit_public_key": audit, "public_key": key, "write_helper_sha256": sha}


def _graphs(servers: Sequence[Mapping[str, Any]]) -> dict[str, list[str]]:
    """The stage graph of every server of the plan.

    Stage 7 is the replica DC, so it exists only when the plan holds a
    second server.

    The graphs are lists and not tuples: the plan is carried as JSON,
    so a plan that went through JSON holds its graphs as lists, and a
    plan that is refused after the round trip is a plan that cannot be
    resumed.
    """
    roles = {server["role"] for server in servers}
    graph: dict[str, list[str]] = {}
    if "dc1" in roles:
        graph["dc1"] = list(DC1_GRAPH if "dc2" in roles else DC1_GRAPH_ALONE)
    if "dc2" in roles:
        graph["dc2"] = list(DC2_GRAPH)
    return graph


def _resume(
    inputs: Mapping[str, Any], graph: Mapping[str, Sequence[str]]
) -> dict[str, Any]:
    """The resume of the plan: the digest it continues, the stage it
    starts at, and the digest its derived secrets are salted with.

    ``secrets_from`` is the digest of the build's first plan (DESIGN-1.5
    open point 71): the DCs keep the DSRM and the admin password a first
    plan installed, so a resume plan's approval and its helper derive them
    from that digest and never from the resume plan's own.  It is in the
    signed bytes; the tools fill it from the plans on record.
    """
    resume_from = inputs.get("resume_from")
    start_stage = inputs.get("start_stage")
    secrets_from = inputs.get("secrets_from")
    if (resume_from is None) != (start_stage is None):
        raise _refuse(
            "free_text", "a resumed plan carries resume_from and start_stage together"
        )
    if (resume_from is None) != (secrets_from is None):
        raise _refuse(
            "free_text", "a resumed plan carries secrets_from, and only a resumed plan"
        )
    if resume_from is None:
        return {}
    if not isinstance(resume_from, str) or DIGEST_RE.fullmatch(resume_from) is None:
        raise _refuse("free_text", "resume_from is not a digest")
    if not isinstance(secrets_from, str) or DIGEST_RE.fullmatch(secrets_from) is None:
        raise _refuse("free_text", "secrets_from is not a digest")
    if not isinstance(start_stage, str) or start_stage not in STAGE_IDS:
        raise _refuse("free_text", "start_stage is not a stage of the design")
    stages = {stage for graph_of_server in graph.values() for stage in graph_of_server}
    if start_stage not in stages:
        raise _refuse("free_text", "start_stage is not a stage of this plan")
    return {"resume_from": resume_from, "start_stage": start_stage, "secrets_from": secrets_from}


def plan_build(inputs: Mapping[str, Any]) -> dict[str, Any]:
    """Build the plan of one build.

    The inputs are the fields of DESIGN-1.5 "The plan": the domain, the
    servers, the baseline and the accepted 1.3 findings, and, for a
    resumed plan, the digest it continues and the stage it starts at.

    Every value comes from a grammar: a name, a DNS label, an IPv4
    address, an int or one of the words of an enum.  There is no free
    text anywhere in the plan.

    Raises ``BuildPlanRefused`` with one of the codes of the plan when
    the inputs do not fit.
    """
    if not isinstance(inputs, Mapping):
        raise _refuse("free_text", "the inputs are not an object")
    for key in inputs:
        if key not in _INPUT_FIELDS:
            raise _refuse("free_text", "the inputs hold a field the plan does not have")
    for key in _REQUIRED_INPUT_FIELDS:
        if key not in inputs:
            raise _refuse("free_text", f"the inputs do not hold {key}")

    domain = _domain(inputs)
    servers = _servers(inputs)

    # The name of the domain and the name of a server are two different
    # names: a server that holds the name of the domain is a computer
    # account that collides with the domain itself.
    netbios = domain["netbios"].casefold()
    for server in servers:
        if server["hostname"].casefold() == netbios:
            raise _refuse("free_text", "a server holds the name of the domain")

    graph = _graphs(servers)
    built: dict[str, Any] = {
        "domain": domain,
        "servers": servers,
        "baseline": _baseline(inputs),
        "accepted_findings": _findings(inputs),
        "ops": _ops(inputs),
        "stages": {"graph": graph, "kind": dict(STAGE_KINDS)},
    }
    built.update(_resume(inputs, graph))
    return built


# --------------------------------------------------------------------------
# The canonical bytes
# --------------------------------------------------------------------------


def _joined(values: Any, where: str) -> str:
    """The value of a list: the items joined with a comma, as the 1.4
    request format joins the pairs of an object."""
    items = _sequence(values, where)
    parts: list[str] = []
    for value in items:
        text = _text(value, where)
        if "," in text:
            raise _refuse("free_text", f"{where} holds a value with a comma in it")
        parts.append(text)
    return ",".join(parts)


def _pairs(values: Mapping[str, Any], where: str) -> str:
    """The value of an object: the pairs joined with a comma, sorted by
    key, as the 1.4 request format does."""
    parts: list[str] = []
    for key in sorted(values):
        text = _text(values[key], where)
        if "," in text or "=" in text:
            raise _refuse(
                "free_text", f"{where} holds a value with a comma or an equal in it"
            )
        parts.append(f"{key}={text}")
    return ",".join(parts)


def _plan_lines(plan: Mapping[str, Any]) -> dict[str, str]:
    """Every pair of the plan, as the map of its key and its value."""
    if not isinstance(plan, Mapping):
        raise _refuse("free_text", "the plan is not an object")

    lines: dict[str, str] = {}

    domain = _mapping(plan.get("domain"), "the domain of the plan")
    for field in ("dns_name", "netbios", "functional_level", "site", "owner_admin"):
        lines[f"domain.{field}"] = _text(domain.get(field), f"domain.{field}")
    lines["domain.ou_tree"] = _joined(domain.get("ou_tree"), "domain.ou_tree")
    lines["domain.groups"] = _joined(domain.get("groups"), "domain.groups")

    for index, raw in enumerate(
        _sequence(plan.get("servers"), "the servers of the plan")
    ):
        server = _mapping(raw, f"server {index} of the plan")
        for field in ("device", "role", "hostname", "ip", "gateway", "checkpoint"):
            lines[f"servers.{index}.{field}"] = _text(
                server.get(field), f"servers.{index}.{field}"
            )
        lines[f"servers.{index}.prefix"] = str(
            _int(server.get("prefix"), f"servers.{index}.prefix")
        )
        lines[f"servers.{index}.forwarders"] = _joined(
            server.get("forwarders"), f"servers.{index}.forwarders"
        )
        if "vmgenid" in server:
            lines[f"servers.{index}.vmgenid"] = _text(
                server.get("vmgenid"), f"servers.{index}.vmgenid"
            )
        if "agent" in server:
            lines[f"servers.{index}.agent"] = str(
                _int(server.get("agent"), f"servers.{index}.agent")
            )

    baseline = _mapping(plan.get("baseline"), "the baseline of the plan")
    lines["baseline.version"] = _text(baseline.get("version"), "baseline.version")
    lines["baseline.options"] = _pairs(
        _mapping(baseline.get("options"), "the baseline options of the plan"),
        "baseline.options",
    )

    for index, raw in enumerate(
        _sequence(plan.get("accepted_findings"), "the accepted findings of the plan")
    ):
        finding = _mapping(raw, f"accepted finding {index} of the plan")
        lines[f"accepted_findings.{index}.id"] = _text(
            finding.get("id"), f"accepted_findings.{index}.id"
        )
        lines[f"accepted_findings.{index}.reason"] = _text(
            finding.get("reason"), f"accepted_findings.{index}.reason"
        )

    ops = _mapping(plan.get("ops"), "the ops section of the plan")
    for field in ("audit_public_key", "public_key", "write_helper_sha256"):
        lines[f"ops.{field}"] = _text(ops.get(field), f"ops.{field}")

    stages = _mapping(plan.get("stages"), "the stages of the plan")
    graph = _mapping(stages.get("graph"), "the stage graph of the plan")
    for role in graph:
        lines[f"stages.graph.{role}"] = _joined(
            graph[role], f"stages.graph.{role}"
        )
    kinds = _mapping(stages.get("kind"), "the stage kinds of the plan")
    for stage in kinds:
        lines[f"stages.kind.{stage}"] = _text(kinds[stage], f"stages.kind.{stage}")

    if "resume_from" in plan:
        lines["resume_from"] = _text(plan["resume_from"], "resume_from")
    if "start_stage" in plan:
        lines["start_stage"] = _text(plan["start_stage"], "start_stage")
    if "secrets_from" in plan:
        lines["secrets_from"] = _text(plan["secrets_from"], "secrets_from")

    return lines


def _inputs_of(plan: Mapping[str, Any]) -> dict[str, Any]:
    """The inputs of a plan: the fields the plan is built from.

    The stages are not among them: they are read out of the servers,
    so a plan that holds other stages is not the plan of
    ``plan_build``.
    """
    domain = _mapping(plan.get("domain"), "the domain of the plan")
    servers = _sequence(plan.get("servers"), "the servers of the plan")
    baseline = _mapping(plan.get("baseline"), "the baseline of the plan")
    findings = _sequence(
        plan.get("accepted_findings"), "the accepted findings of the plan"
    )
    inputs: dict[str, Any] = {
        "domain": dict(domain),
        "servers": [dict(_mapping(one, "a server of the plan")) for one in servers],
        "baseline": dict(baseline),
        "accepted_findings": [
            dict(_mapping(one, "an accepted finding of the plan")) for one in findings
        ],
        "ops": dict(_mapping(plan.get("ops"), "the ops section of the plan")),
    }
    for key in ("resume_from", "start_stage", "secrets_from"):
        if key in plan:
            inputs[key] = plan[key]
    return inputs


def _checked_plan(plan: Mapping[str, Any]) -> Mapping[str, Any]:
    """The plan, checked: it must be the plan of ``plan_build``.

    The canonical bytes and the stage graph are read out of the plan
    the owner approved, so the plan is rebuilt out of its own fields
    and refused unless the two are the same.  A value with a newline in
    it, a field the plan does not have, a stage kind or a stage graph
    that was changed on the way are refused here and never reach the
    bytes.
    """
    if not isinstance(plan, Mapping):
        raise _refuse("free_text", "the plan is not an object")
    rebuilt = plan_build(_inputs_of(plan))
    if rebuilt["stages"] != plan.get("stages") or rebuilt != plan:
        raise _refuse("free_text", "the plan is not a plan of plan_build")
    return rebuilt


def canonical_bytes(plan: Mapping[str, Any]) -> bytes:
    """The canonical bytes of one plan.

    The bytes are ASCII, one ``key=value`` pair per line, LF only, and
    the first line is the header of the plan.  The pairs are sorted
    ordinally, by byte value.

    The plan is rebuilt out of its own fields first and refused unless
    it is the plan of ``plan_build``: the bytes are then the bytes of
    a plan and of nothing else.
    """
    lines = _plan_lines(_checked_plan(plan))
    text = "\n".join(
        [PLAN_HEADER] + [f"{key}={lines[key]}" for key in sorted(lines)]
    ) + "\n"
    try:
        return text.encode("ascii")
    except UnicodeEncodeError:
        raise _refuse("free_text", "the plan holds a value that is not ASCII") from None


def digest(plan: Mapping[str, Any]) -> str:
    """The digest of one plan: the sha256 of its canonical bytes."""
    return hashlib.sha256(canonical_bytes(plan)).hexdigest()


def stage_digest(plan_digest: str, stage: str, checkpoint_id: str) -> str:
    """The digest of one stage: the sha256 of the message of the design.

    The message is the header of the stage, then the digest of the plan,
    the stage and the id of the checkpoint, each on a line of its own.
    The checkpoint is in the signed bytes, so a token of a stage does
    not open another checkpoint.
    """
    if not isinstance(plan_digest, str) or DIGEST_RE.fullmatch(plan_digest) is None:
        raise _refuse("free_text", "the plan digest is not a digest")
    if not isinstance(stage, str) or stage not in STAGE_IDS:
        raise _refuse("free_text", "the stage is not one of the stages of the design")
    if (
        not isinstance(checkpoint_id, str)
        or CHECKPOINT_ID_RE.fullmatch(checkpoint_id) is None
    ):
        raise _refuse("free_text", "the checkpoint id is outside its grammar")
    message = (
        f"{STAGE_HEADER}\n"
        f"plan={plan_digest}\n"
        f"stage={stage}\n"
        f"checkpoint={checkpoint_id}\n"
    )
    return hashlib.sha256(message.encode("ascii")).hexdigest()


# --------------------------------------------------------------------------
# The stage graphs
# --------------------------------------------------------------------------


def _role_of(server: Any) -> str:
    """The role of the server the graph is asked for."""
    if isinstance(server, Mapping):
        server = server.get("role")
    if not isinstance(server, str) or server not in ROLES:
        raise _refuse("free_text", "the server is not one of the servers of the plan")
    return server


def stage_graph(plan: Mapping[str, Any], server: Any) -> tuple[str, ...]:
    """The stage graph of one server of the plan.

    The server is the role (``dc1`` or ``dc2``) or the server itself.

    The plan is rebuilt out of its own fields first and refused unless
    it is the plan of ``plan_build``, so a graph that was changed on
    the way is never handed out.
    """
    role = _role_of(server)
    checked = _checked_plan(plan)
    stages = _mapping(checked.get("stages"), "the stages of the plan")
    graph = _mapping(stages.get("graph"), "the stage graph of the plan")
    stages_of_role = graph.get(role)
    if not isinstance(stages_of_role, (list, tuple)):
        raise _refuse("free_text", "the plan has no stage graph for that server")
    return tuple(str(stage) for stage in stages_of_role)


# --------------------------------------------------------------------------
# The derived secrets
# --------------------------------------------------------------------------


def _hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """HKDF-SHA256 (RFC 5869) out of the standard library only.

    The extract step is the HMAC of the salt over the key material, the
    expand step is a chain of HMACs over the info and a counter.
    """
    if length < 0 or length > 255 * 32:
        raise ValueError("the length of the derived key is out of range")
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = b""
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


def _encode_secret(okm: bytes) -> str:
    """The secret of the derived bytes.

    The first four characters are one upper case, one lower case, one
    digit and one symbol, so the secret always holds the four classes
    the Windows complexity rules ask for; the rest are drawn from the
    four classes together.  The secret is 24 characters long, so it is
    longer than the 14 the rules ask for as well.
    """
    if len(okm) < SECRET_LENGTH:
        raise ValueError("the derived key is too short for the secret")
    characters = [
        _UPPER[okm[0] % len(_UPPER)],
        _LOWER[okm[1] % len(_LOWER)],
        _DIGIT[okm[2] % len(_DIGIT)],
        _SYMBOL[okm[3] % len(_SYMBOL)],
    ]
    alphabet = _UPPER + _LOWER + _DIGIT + _SYMBOL
    for octet in okm[4:SECRET_LENGTH]:
        characters.append(alphabet[octet % len(alphabet)])
    return "".join(characters)


def secrets_digest(plan: Mapping[str, Any]) -> str:
    """The salt of the derived secrets of one plan (DESIGN-1.5 "Secrets",
    open point 71): the plan's own digest for a first plan, its signed
    ``secrets_from`` (the build's first plan's digest) for a resume plan.
    The approval and the helper both derive from this one value."""
    own = digest(plan)
    if "secrets_from" in plan:
        return str(plan["secrets_from"])
    return own


def derive_secret(k_hex: str, plan_digest: str, info: str) -> str:
    """The secret of one derivation.

    The key material is the K of the server, the salt is the digest of
    the plan and the info is the name of the secret: the DSRM password
    or the owner's first admin password.  The two secrets of one plan
    are therefore different, and the same secret of two plans is
    different too.
    """
    if not isinstance(k_hex, str) or HEX64_RE.fullmatch(k_hex) is None:
        raise _refuse("free_text", "the key is not 64 lowercase hexadecimal characters")
    if not isinstance(plan_digest, str) or DIGEST_RE.fullmatch(plan_digest) is None:
        raise _refuse("free_text", "the plan digest is not a digest")
    if not isinstance(info, str) or info not in INFO_STRINGS:
        raise _refuse("free_text", "the info string is not one of the two of the design")
    okm = _hkdf_sha256(
        bytes.fromhex(k_hex),
        plan_digest.encode("ascii"),
        info.encode("ascii"),
        SECRET_LENGTH,
    )
    return _encode_secret(okm)


# --------------------------------------------------------------------------
# The reuse of the approve module
# --------------------------------------------------------------------------


def server_key(passphrase: bytes, device: str) -> str:
    """The key K of one server: the approve module's key, never a second
    one."""
    from ...approve import derive_k

    return derive_k(passphrase, device)


def plan_token(k_hex: str, plan_digest: str, nbf: int, exp: int) -> str:
    """The token of one plan: the approve module's token, never a second
    one."""
    from ...approve import approval_token

    return approval_token(k_hex, plan_digest, nbf, exp)
