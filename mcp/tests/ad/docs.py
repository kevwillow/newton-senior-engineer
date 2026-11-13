"""Test helpers: the collector documents the tests build.

SPEC-1.3 section 10 says a fixture is a document *measured* from a lab
collector, and that variants are made by editing a measured document in a
test helper.  This helper builds its documents from the shipped query set:
the shape comes from the contract, not from a frozen copy of somebody's
run.  The measured documents of the lab ship in ``fixtures`` and are
loaded and edited in ``measured.py``.

``minimal_document`` returns a document that satisfies the contract of
section 5: every query id is present, every status is ``ok`` and every row
list is empty.  The overrides are the way a test changes one thing.

``measured_document`` is the one measured document this helper loads
(``FIXTURE_PATH``: the lab Windows Server 2025 DC read as the
Administrator), with the patches the collector bugs of that run need (an
empty ``domain_sid`` and the domain head in every base-scope query).
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

from newton_mcp.ad import queryset, values, wire


DOMAIN_SID = "S-1-5-21-1004336348-1177238915-682003330"
DOMAIN_DN = "DC=win,DC=newton,DC=test"
CONFIG_DN = "CN=Configuration,DC=win,DC=newton,DC=test"
SCHEMA_DN = "CN=Schema,CN=Configuration,DC=win,DC=newton,DC=test"
AUDIT_SID = f"{DOMAIN_SID}-1105"
ADMIN_SID = f"{DOMAIN_SID}-500"
KRBTGT_SID = f"{DOMAIN_SID}-502"
DOMAIN_ADMINS_SID = f"{DOMAIN_SID}-512"
DOMAIN_USERS_SID = f"{DOMAIN_SID}-513"
DOMAIN_COMPUTERS_SID = f"{DOMAIN_SID}-516"


def sid_blob(sid: str) -> str:
    """The base64 of the binary SID, the way a collector reports it."""
    parts = sid.split("-")
    revision = int(parts[1])
    authority = int(parts[2])
    subs = [int(part) for part in parts[3:]]
    raw = bytearray([revision, len(subs)])
    raw += authority.to_bytes(6, "big")
    for sub in subs:
        raw += sub.to_bytes(4, "little")
    return base64.b64encode(bytes(raw)).decode("ascii")


def guid_blob(guid: str) -> str:
    """The base64 of the binary GUID, the way a collector reports it."""
    text = guid.replace("-", "")
    first = bytes.fromhex(text[0:8])[::-1]
    second = bytes.fromhex(text[8:12])[::-1]
    third = bytes.fromhex(text[12:16])[::-1]
    rest = bytes.fromhex(text[16:32])
    return base64.b64encode(first + second + third + rest).decode("ascii")


def row(dn: str, **attrs: Any) -> dict[str, Any]:
    """One row: a distinguished name and the attributes that came back."""
    values: dict[str, list[str]] = {}
    for name, value in attrs.items():
        if isinstance(value, list):
            values[name] = [str(item) for item in value]
        else:
            values[name] = [str(value)]
    return {"dn": dn, "a": values}


def query_block(
    rows: list[dict[str, Any]] | None = None,
    *,
    status: str = "ok",
    error_code: str = "",
) -> dict[str, Any]:
    """One query result: a status, an error code and the rows."""
    return {
        "status": status,
        "error_code": error_code,
        "rows": rows if rows is not None else [],
    }


def minimal_query_set() -> dict[str, Any]:
    """A query set with one query, valid apart from what a test changes."""
    return {
        "v": 1,
        "queries": [
            {
                "id": "users",
                "base": "{domain}",
                "scope": "sub",
                "filter": "(&(objectCategory=person)(objectClass=user))",
                "attrs": ["objectSid", "distinguishedName"],
                "binary": ["objectSid"],
                "ranged": [],
                "sd": False,
                "limit": 50000,
                "presence_only": False,
            }
        ],
    }


# The fixed settings list of each collector (SPEC-1.3 section 7), written
# out here and not taken from wire.py, so a test that compares the two
# compares two copies.
WINDOWS_SETTINGS = tuple(
    "HKLM\\SYSTEM\\CurrentControlSet\\" + tail
    for tail in (
        "Services\\NTDS\\Parameters\\LDAPServerIntegrity",
        "Services\\NTDS\\Parameters\\LdapEnforceChannelBinding",
        "Control\\Lsa\\LmCompatibilityLevel",
        "Control\\Lsa\\NoLMHash",
        "Control\\Lsa\\RestrictAnonymous",
        "Control\\Lsa\\MSV1_0\\RestrictSendingNTLMTraffic",
        "Control\\Lsa\\MSV1_0\\RestrictReceivingNTLMTraffic",
        "Services\\Netlogon\\Parameters\\RestrictNTLMInDomain",
        "Services\\Netlogon\\Parameters\\FullSecureChannelProtection",
        "Services\\Netlogon\\Parameters\\VulnerableChannelAllowList",
    )
)
SAMBA_SETTINGS = (
    "ldap server require strong auth",
    "ntlm auth",
    "server signing",
    "server min protocol",
    "kerberos encryption types",
    "allow nt4 crypto",
    "reject md5 clients",
    "server schannel",
    "tls enabled",
)


def settings_items(collector: str = "windows") -> list[dict[str, str]]:
    """The fixed settings list of the collector, every item unread."""
    if collector == "samba":
        source, keys = "loadparm", SAMBA_SETTINGS
    else:
        source, keys = "registry", WINDOWS_SETTINGS
    return [
        {"source": source, "key": key, "status": "unavailable", "value": ""}
        for key in keys
    ]


def minimal_document(**overrides: Any) -> dict[str, Any]:
    """A document that satisfies the contract of section 5.

    Every query of the shipped query set is present with the status
    ``ok`` and no rows, and the settings carry the fixed list of the
    collector with every item ``unavailable``.  An override replaces a
    top-level key; a nested change is made by the test itself.
    """
    queries = {
        query.id: query_block() for query in queryset.load().queries
    }
    document: dict[str, Any] = {
        "v": 1,
        "collector": "windows",
        "collector_version": "1.3.0",
        "querysetsha": queryset.load().sha256,
        "is_dc": True,
        "domain": {
            "dns": "win.newton.test",
            "domain_dn": DOMAIN_DN,
            "config_dn": CONFIG_DN,
            "schema_dn": SCHEMA_DN,
            "domain_sid": DOMAIN_SID,
        },
        "identity": {
            "user": "newton-audit",
            "sid": AUDIT_SID,
            "token_group_sids": [DOMAIN_USERS_SID, "S-1-5-11"],
        },
        "started": "20261108T120000Z",
        "elapsed_ms": 812,
        "queries": queries,
        "files": {
            "gpp": {"status": "ok", "error_code": "", "items": []},
            "gpttmpl": {"status": "ok", "error_code": "", "items": []},
        },
        "settings": {"status": "ok", "error_code": "", "items": []},
    }
    document.update(overrides)
    if "settings" not in overrides:
        document["settings"]["items"] = settings_items(document["collector"])
    return document


def document(**query_rows: list[dict[str, Any]]) -> dict[str, Any]:
    """A document whose named queries carry the given rows."""
    built = minimal_document()
    for query_id, rows in query_rows.items():
        built["queries"][query_id] = query_block(rows)
    return built


def parsed(**query_rows: list[dict[str, Any]]) -> wire.Document:
    """The validated document of the given rows."""
    raw = json.dumps(document(**query_rows)).encode("utf-8")
    return wire.parse(raw, queryset.load())


# The measured collector document of the lab DC (Windows Server 2025).
FIXTURE_PATH = (
    Path(__file__).with_name("fixtures") / "win-dc-admin-2026-11-08.json"
)

# The rows of the base-scope queries.  The collector built its searcher
# with the base as the filter, so every search ran against the default
# naming context and every base-scope query came back with the domain
# head.  These are the names the queries asked for: the fixed collector
# reads the row where the base is.
BUGGED_BASE_ROWS: dict[str, str] = {
    "dir_service": (
        "CN=Directory Service,CN=Windows NT,CN=Services,"
        "CN=Configuration,DC=win,DC=newton,DC=test"
    ),
    "partitions": "CN=Partitions,CN=Configuration,DC=win,DC=newton,DC=test",
    "schema_head": "CN=Schema,CN=Configuration,DC=win,DC=newton,DC=test",
    "adminsdholder": "CN=AdminSDHolder,CN=System,DC=win,DC=newton,DC=test",
    "dc_ou": "OU=Domain Controllers,DC=win,DC=newton,DC=test",
}


def measured_document(*, bug_rows: bool = False) -> dict[str, Any]:
    """The measured collector document of the lab DC.

    The collector has two bugs that are being fixed separately: it writes
    an empty ``domain_sid``, and it built every searcher with the base as
    the filter, so every base-scope query came back with the domain head.
    This helper sets the domain sid to the SID decoded from the objectSid
    of the domain head, which is the SID of the domain the document is
    about, and puts the row of every base-scope query where the query
    asked for it, and says so here.  Every other field of the document is
    the measured one.

    With ``bug_rows`` the rows of the base-scope queries are left the way
    they were measured: that is the shape the core must refuse.
    """
    document = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    domain_head = document["queries"]["domain_head"]["rows"][0]
    domain_sid = values.sid_from_base64(domain_head["a"]["objectSid"][0])
    document["domain"]["domain_sid"] = domain_sid
    if not bug_rows:
        for query_id, dn in BUGGED_BASE_ROWS.items():
            for row in document["queries"][query_id]["rows"]:
                row["dn"] = dn
    return document


def measured_parsed() -> wire.Document:
    """The measured document, validated against the shipped query set."""
    raw = json.dumps(measured_document()).encode("utf-8")
    return wire.parse(raw, queryset.load())
