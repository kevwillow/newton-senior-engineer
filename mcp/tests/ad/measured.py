"""The measured documents of the lab, and the helpers that edit them.

The documents of this module are the ones the lab collectors measured:

- ``win-dc-audit-r3.json``: the seeded Windows domain read as the
  ordinary audit account ``newton-audit``;
- ``win-dc-admin-r3.json``: the same domain read as the Administrator;
- ``win-dc-audit-r4-acl.json``: the same domain read as the ordinary
  audit account after the ACL seeds of the lab were planted (S13-S16 of
  the lab seeds): the replication rights of a plain account on the
  domain head, two write rights on the AdminSDHolder and the edit
  right of the domain users on the seeded GPO;
- ``samba-dc-audit-r1.json``: the Samba domain of the lab read as the
  ordinary audit account ``newton-audit`` (the first measured document
  of the Samba collector).

They are loaded with ``wire.parse`` and the shipped query set, exactly
as the collector's output is.  A variant of a measured document is made
by editing that document here: every helper names the file it starts
from, so a test always says which measurement it builds on.

The ACE helpers build the bytes of an access allowed ACE and add it to
the DACL of a measured descriptor.  The DACL of every measured
descriptor is the last structure of the buffer, so an ACE is added at
the end of it and the size and the count of the DACL are corrected.
"""

from __future__ import annotations

import base64
import json
import uuid
from pathlib import Path
from typing import Any

from newton_mcp.ad import queryset, secdesc, wire


FIXTURES = Path(__file__).with_name("fixtures")

# The measured document of the seeded domain read as the ordinary audit
# account.  The account cannot read the fine-grained password policies,
# the backup keys or the dSHeuristics of the directory service.
AUDIT_FIXTURE = FIXTURES / "win-dc-audit-r3.json"

# The measured document of the same domain read as the Administrator.
# The Administrator may read everything the audit account may not.
ADMIN_FIXTURE = FIXTURES / "win-dc-admin-r3.json"

# The measured document of the seeded domain read as the ordinary audit
# account, with the ACL seeds of the lab planted on it.
R4_FIXTURE = FIXTURES / "win-dc-audit-r4-acl.json"

# The measured document of the Samba domain of the lab read as the
# ordinary audit account.
SAMBA_FIXTURE = FIXTURES / "samba-dc-audit-r1.json"

# The template of the Default Domain Policy of a stock Samba domain
# controller: the provision template of Samba, measured on the lab DC
# (Samba 4.22.11).  It holds ten keys of the [System Access] section
# and one of the [Kerberos Policy] section that no check of Newton
# reads, and the four keys of the Kerberos policy that the checks do
# read.
STOCK_GPTTMPL = (
    "[Unicode]\n"
    "Unicode=yes\n"
    "[System Access]\n"
    "MinimumPasswordAge = 1\n"
    "MaximumPasswordAge = 42\n"
    "MinimumPasswordLength = 7\n"
    "PasswordComplexity = 1\n"
    "PasswordHistorySize = 24\n"
    "LockoutBadCount = 0\n"
    "RequireLogonToChangePassword = 0\n"
    "ForceLogoffWhenHourExpire = 0\n"
    "ClearTextPassword = 0\n"
    "LSAAnonymousNameLookup = 0\n"
    "[Kerberos Policy]\n"
    "MaxTicketAge = 10\n"
    "MaxRenewAge = 7\n"
    "MaxServiceAge = 600\n"
    "MaxClockSkew = 5\n"
    "TicketValidateClient = 1\n"
    "[Version]\n"
    'signature="$CHICAGO$"\n'
    "Revision=1\n"
)

# The SID of the ordinary audit account of the measured domain.
AUDIT_SID = "S-1-5-21-2694141092-4246003333-2665853310-2719"


def audit_json() -> dict[str, Any]:
    """The measured document of the audit account, as it was measured."""
    return json.loads(AUDIT_FIXTURE.read_text(encoding="utf-8"))


def admin_json() -> dict[str, Any]:
    """The measured document of the Administrator, as it was measured."""
    return json.loads(ADMIN_FIXTURE.read_text(encoding="utf-8"))


def r4_json() -> dict[str, Any]:
    """The measured document of the audit account with the ACL seeds."""
    return json.loads(R4_FIXTURE.read_text(encoding="utf-8"))


def samba_json() -> dict[str, Any]:
    """The measured document of the Samba DC, as it was measured."""
    return json.loads(SAMBA_FIXTURE.read_text(encoding="utf-8"))


def parse(document: dict[str, Any]) -> wire.Document:
    """The validated document of an edited measured document."""
    raw = json.dumps(document).encode("utf-8")
    return wire.parse(raw, queryset.load())


def audit_document() -> wire.Document:
    """The validated measured document of the audit account."""
    return parse(audit_json())


def admin_document() -> wire.Document:
    """The validated measured document of the Administrator."""
    return parse(admin_json())


def r4_document() -> wire.Document:
    """The validated measured document of the audit account with the seeds."""
    return parse(r4_json())


def sid_bytes(sid: str) -> bytes:
    """The binary SID of a SID in text."""
    parts = sid.split("-")
    revision = int(parts[1])
    authority = int(parts[2])
    subs = [int(part) for part in parts[3:]]
    raw = bytearray([revision, len(subs)])
    raw += authority.to_bytes(6, "big")
    for sub in subs:
        raw += sub.to_bytes(4, "little")
    return bytes(raw)


def guid_bytes(guid: str) -> bytes:
    """The binary GUID of a GUID in text, the way Windows stores it."""
    return uuid.UUID(guid).bytes_le


def guid_blob(guid: str) -> str:
    """The base64 of a binary GUID, the way a collector reports it."""
    return base64.b64encode(guid_bytes(guid)).decode("ascii")


def sid_blob(sid: str) -> str:
    """The base64 of a binary SID, the way a collector reports it."""
    return base64.b64encode(sid_bytes(sid)).decode("ascii")


def build_ace(
    mask: int,
    trustee: str,
    object_type: str | None = None,
    flags: int = 0,
) -> bytes:
    """The bytes of one access allowed ACE.

    An ACE that names an object is an object ACE: it carries the flags
    of the object type and the GUID of the object it names.
    """
    body = bytearray()
    body += mask.to_bytes(4, "little")
    if object_type is not None:
        body += secdesc.ACE_OBJECT_TYPE_PRESENT.to_bytes(4, "little")
        body += guid_bytes(object_type)
    body += sid_bytes(trustee)
    header = bytearray()
    header.append(secdesc.ACCESS_ALLOWED_OBJECT_ACE if object_type else secdesc.ACCESS_ALLOWED_ACE)
    header.append(flags)
    header += (4 + len(body)).to_bytes(2, "little")
    return bytes(header) + bytes(body)


def add_ace(descriptor: str, ace: bytes) -> str:
    """The measured descriptor with one more ACE in its DACL.

    The ACE goes at the end of the DACL.  The structures that sit
    after the DACL in the buffer (the owner of a measured descriptor
    sits after it) move back by the size of the ACE, and the header
    that points at them is corrected.
    """
    raw = bytearray(base64.b64decode(descriptor))
    control = int.from_bytes(raw[2:4], "little")
    if not control & secdesc.SE_DACL_PRESENT:
        raise ValueError("the descriptor carries no DACL")
    offsets = {
        "owner": int.from_bytes(raw[4:8], "little"),
        "group": int.from_bytes(raw[8:12], "little"),
        "sacl": int.from_bytes(raw[12:16], "little"),
        "dacl": int.from_bytes(raw[16:20], "little"),
    }
    if not offsets["dacl"]:
        raise ValueError("the DACL of the descriptor is null")
    start = offsets["dacl"]
    size = int.from_bytes(raw[start + 2 : start + 4], "little")
    count = int.from_bytes(raw[start + 4 : start + 6], "little")
    end = start + size
    for name, field in (("owner", 4), ("group", 8), ("sacl", 12)):
        offset = offsets[name]
        if offset and offset >= end:
            raw[field : field + 4] = (offset + len(ace)).to_bytes(4, "little")
    raw[start + 2 : start + 4] = (size + len(ace)).to_bytes(2, "little")
    raw[start + 4 : start + 6] = (count + 1).to_bytes(2, "little")
    raw[end:end] = ace
    return base64.b64encode(bytes(raw)).decode("ascii")


def build_descriptor(owner: str, aces: list[bytes]) -> str:
    """A self-relative descriptor with the given ACEs in its DACL.

    The descriptor holds an owner and a DACL, and nothing else: the
    collectors ask for the owner and the DACL only.
    """
    owner_bytes = sid_bytes(owner)
    dacl = bytearray()
    dacl.append(secdesc.ACL_REVISION)
    dacl.append(0)
    dacl += (8 + sum(len(ace) for ace in aces)).to_bytes(2, "little")
    dacl += len(aces).to_bytes(2, "little")
    dacl += (0).to_bytes(2, "little")
    for ace in aces:
        dacl += ace
    header = bytearray()
    header.append(1)
    header.append(0)
    header += (secdesc.SE_DACL_PRESENT | secdesc.SE_SELF_RELATIVE).to_bytes(2, "little")
    header += (20).to_bytes(4, "little")
    header += (0).to_bytes(4, "little")
    header += (0).to_bytes(4, "little")
    header += (20 + len(owner_bytes)).to_bytes(4, "little")
    raw = bytes(header) + owner_bytes + bytes(dacl)
    return base64.b64encode(raw).decode("ascii")


def null_dacl(descriptor: str) -> str:
    """The measured descriptor with a null DACL.

    A null DACL grants everything to everyone: the control says there
    is a DACL and the offset says there is none.
    """
    raw = bytearray(base64.b64decode(descriptor))
    raw[16:20] = (0).to_bytes(4, "little")
    return base64.b64encode(bytes(raw)).decode("ascii")


def no_dacl(descriptor: str) -> str:
    """The measured descriptor with no DACL at all.

    The control says there is no DACL: the bit that says there is one
    is clear.  This is not a null DACL, and a check may not read it as
    one.
    """
    raw = bytearray(base64.b64decode(descriptor))
    control = int.from_bytes(raw[2:4], "little")
    raw[2:4] = (control & ~secdesc.SE_DACL_PRESENT).to_bytes(2, "little")
    return base64.b64encode(bytes(raw)).decode("ascii")


def set_setting(
    document: dict[str, Any],
    name: str,
    value: str,
    status: str = "ok",
) -> None:
    """The value of one setting of the collector host."""
    for item in document["settings"]["items"]:
        if item["key"].lower().endswith(name.lower()):
            item["status"] = status
            item["value"] = value
            return
    raise KeyError("the document does not carry the setting")


def set_query_status(
    document: dict[str, Any],
    query_id: str,
    status: str,
    error_code: str = "other",
) -> None:
    """The status of one query of the document."""
    block = document["queries"][query_id]
    block["status"] = status
    block["error_code"] = "" if status == "ok" else error_code


def set_file_status(
    document: dict[str, Any],
    section_id: str,
    status: str,
    error_code: str = "other",
) -> None:
    """The status of one file section of the document."""
    block = document["files"][section_id]
    block["status"] = status
    block["error_code"] = "" if status == "ok" else error_code


def drop_attribute(row: dict[str, Any], name: str) -> None:
    """The row without one attribute."""
    row["a"].pop(name, None)
