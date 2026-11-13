"""The fake Samba bindings the write helper of the DC runs against.

The samba python bindings are not installed on this machine, so the tests
build these fakes and put them into ``sys.modules``.  The fakes
reproduce the shapes the lab DC was measured with (Samba 4.22.11, the
measurements of SPEC-1.4-REQUEST section 9):

* ``SamDB(url=..., credentials=..., lp=...)`` binds, and the fake records
  the url and the credentials it was given;
* the atomic modify is one message with two elements under the keys "0"
  and "1": the first deletes the old value and the second adds the new
  one.  A stale old value raises ``LdbError`` 16 (NO_SUCH_ATTRIBUTE);
* a write outside the delegation raises ``LdbError`` 50;
* ``modify`` takes the message and not a name beside it: the name is in
  the message itself, and a call shaped like ``modify(dn, message)`` or
  a message without a name raises ``TypeError("controls is not a
  list")``, the way the real binding was measured to raise;
* ``add`` takes one dict with the name and the class in it: a call
  shaped like ``add(dn, attrs)`` raises ``TypeError("controls is not a
  list")`` and a dict without an ``objectClass`` raises an
  ``LdbError``;
* ``rename(old, new)`` moves the object and ``delete(dn)`` takes it
  out; both keep the shape they were measured with;
* the ``tokenGroups`` of an object are only given by a base search: any
  other scope raises ``LdbError`` 1 ("Cannot provide tokenGroups
  attribute, this is not a BASE search");
* a modify of ``distinguishedName`` raises ``LdbError`` 53
  (UNWILLING_TO_PERFORM), and the move of an object is done with
  ``rename(old, new)``, which raises ``LdbError`` 32 when the old name is
  not there (measured on Samba 4.22.11, 2026-11-09);
* ``add`` with ``unicodePwd`` works, and ``delete`` works;
* ``msDS-ReplAttributeMetaData`` is in no object, so it reads nothing;
* ``ldb.binary_encode`` returns text, not bytes;
* ``LoadParm.get(name)`` raises a ``KeyError`` for a name it does not
  hold;
* every value of an attribute of a result is bytes, and a result holds
  the attributes the search named and nothing else.

The fake holds one domain, with the shapes the lab DC was measured with
on 2026-11-09:

* the rootDSE (the empty base) answers ``dsServiceName`` and
  ``serverName``;
* the domain head names the NTDS Settings object of the PDC in its
  ``fSMORoleOwner``;
* the NTDS Settings object lives under the configuration container, not
  under the computer account of the DC;
* the computer account of the DC lives in ``OU=Domain Controllers``, and
  that OU is an organizational unit with an ``ou`` value and no ``cn``;
* the computer account of the DC carries a ``serverReferenceBL``.

The fake holds the accounts, the groups (including a group nested three
deep in Domain Admins and a pair of groups whose ``memberOf`` values point
at each other) and the organizational units of the domain.  The writes of
the delegated OU succeed, the writes of any other object raise 50.

Every call the fake makes is recorded, and every call is also appended to
the log file of the test when one is named: the log of the fake and the
log of the faked ``systemd-run`` and ``systemctl`` are one file, so a
test can hold the order of the steps of an apply.
"""

from __future__ import annotations

import stat
import sys
import types
import uuid
from pathlib import Path
from typing import Any


# ---- the domain the fake holds ---------------------------------------------

DOMAIN_DN = "DC=lab,DC=newton,DC=test"
DOMAIN_SID = "S-1-5-21-2694141092-4246003333-2665853310"
DOMAIN_DNS = "lab.newton.test"
DOMAIN_GUID = "1a2b3c4d-5e6f-4a8b-9c0d-1e2f3a4b5c6d"
NETBIOS = "DC1"
REALM = "LAB.NEWTON.TEST"

#: The NetBIOS name of the domain, the workgroup of the loadparm.
WORKGROUP = "LAB"

USERS_DN = "CN=Users," + DOMAIN_DN
SERVERS_OU_DN = "OU=Servers," + DOMAIN_DN
OTHER_OU_DN = "OU=Other," + DOMAIN_DN
RESTRICTED_OU_DN = "OU=Restricted," + DOMAIN_DN

#: The container of the domain controllers, as it was measured: an
#: organizational unit with an ``ou`` value and no ``cn``.
DC_OU_DN = "OU=Domain Controllers," + DOMAIN_DN
DC_OU_NAME = "Domain Controllers"

#: The computer account of the DC, in the container of the controllers.
DC_DN = "CN=" + NETBIOS + "," + DC_OU_DN

#: The configuration container of the sites and the servers.
CONFIGURATION_DN = "CN=Configuration," + DOMAIN_DN
SITES_DN = "CN=Sites," + CONFIGURATION_DN
DEFAULT_SITE_DN = "CN=Default-First-Site-Name," + SITES_DN
SERVERS_CONTAINER_DN = "CN=Servers," + DEFAULT_SITE_DN

#: The NTDS Settings object of the DC, as it was measured: it lives under
#: the object of this DC in the container of the servers, and not under
#: the computer account.
SERVER_DN = "CN=" + NETBIOS + "," + SERVERS_CONTAINER_DN
NTDS_SETTINGS_DN = "CN=NTDS Settings," + SERVER_DN

#: The name of the server object of the DC, in the rootDSE.
SERVER_NAME_DN = SERVER_DN

DOMAIN_ADMINS_DN = "CN=Domain Admins," + USERS_DN
DOMAIN_ADMINS_SID = DOMAIN_SID + "-512"
DOMAIN_ADMINS_GUID = "2a2b3c4d-5e6f-4a8b-9c0d-1e2f3a4b5c6d"
DOMAIN_USERS_DN = "CN=Domain Users," + USERS_DN
DOMAIN_USERS_SID = DOMAIN_SID + "-513"
DOMAIN_USERS_GUID = "3a2b3c4d-5e6f-4a8b-9c0d-1e2f3a4b5c6d"

NESTED1_DN = "CN=Nested1," + USERS_DN
NESTED1_SID = DOMAIN_SID + "-1101"
NESTED1_GUID = "4a2b3c4d-5e6f-4a8b-9c0d-1e2f3a4b5c6d"
NESTED2_DN = "CN=Nested2," + USERS_DN
NESTED2_SID = DOMAIN_SID + "-1102"
NESTED2_GUID = "5a2b3c4d-5e6f-4a8b-9c0d-1e2f3a4b5c6d"
NESTED3_DN = "CN=Nested3," + USERS_DN
NESTED3_SID = DOMAIN_SID + "-1103"
NESTED3_GUID = "6a2b3c4d-5e6f-4a8b-9c0d-1e2f3a4b5c6d"

CYCLE_A_DN = "CN=CycleA," + USERS_DN
CYCLE_A_SID = DOMAIN_SID + "-1110"
CYCLE_A_GUID = "7a2b3c4d-5e6f-4a8b-9c0d-1e2f3a4b5c6d"
CYCLE_B_DN = "CN=CycleB," + USERS_DN
CYCLE_B_SID = DOMAIN_SID + "-1111"
CYCLE_B_GUID = "8a2b3c4d-5e6f-4a8b-9c0d-1e2f3a4b5c6d"

GROUP_DN = "CN=Group 1106," + USERS_DN
GROUP_SID = DOMAIN_SID + "-1106"
GROUP_GUID = "9a2b3c4d-5e6f-4a8b-9c0d-1e2f3a4b5c6d"

ALICE_DN = "CN=alice," + SERVERS_OU_DN
ALICE_SID = DOMAIN_SID + "-1105"
ALICE_GUID = "aa2b3c4d-5e6f-4a8b-9c0d-1e2f3a4b5c6d"
BOB_DN = "CN=bob," + SERVERS_OU_DN
BOB_SID = DOMAIN_SID + "-1112"
BOB_GUID = "ba2b3c4d-5e6f-4a8b-9c0d-1e2f3a4b5c6d"
CAROL_DN = "CN=carol," + SERVERS_OU_DN
CAROL_SID = DOMAIN_SID + "-1116"
CAROL_GUID = "bb2b3c4d-5e6f-4a8b-9c0d-1e2f3a4b5c6d"
MALLORY_DN = "CN=mallory," + RESTRICTED_OU_DN
MALLORY_SID = DOMAIN_SID + "-1113"
MALLORY_GUID = "ca2b3c4d-5e6f-4a8b-9c0d-1e2f3a4b5c6d"
ADMIN_DN = "CN=admin2," + SERVERS_OU_DN
ADMIN_SID = DOMAIN_SID + "-1114"
ADMIN_GUID = "da2b3c4d-5e6f-4a8b-9c0d-1e2f3a4b5c6d"
OPS_DN = "CN=newton-ops," + USERS_DN
OPS_SID = DOMAIN_SID + "-1115"
OPS_GUID = "ea2b3c4d-5e6f-4a8b-9c0d-1e2f3a4b5c6d"

SERVERS_OU_GUID = "fa2b3c4d-5e6f-4a8b-9c0d-1e2f3a4b5c6d"
OTHER_OU_GUID = "0b2b3c4d-5e6f-4a8b-9c0d-1e2f3a4b5c6d"

#: The places ``newton-ops`` may write.
DELEGATED_ROOTS = (SERVERS_OU_DN, OTHER_OU_DN, USERS_DN)

#: The objects ``newton-ops`` may write outside the delegated places.
DELEGATED_OBJECTS = (DOMAIN_DN,)

#: The loadparm of the fake DC.
PARM: dict[str, Any] = {
    "server role": "active directory domain controller",
    "netbios name": NETBIOS,
    "realm": REALM,
    "workgroup": WORKGROUP,
    "path": "/var/lib/samba",
}

#: The states of the kerberos of the credentials (samba.credentials).
#: The fake only needs them to be the integers the binding carries.
MUST_USE_KERBEROS = 2
SPECIFIED = 1

#: The attributes the directory only gives in a base search.
BASE_ONLY_ATTRS = ("tokengroups",)


def sid_bytes(text: str) -> bytes:
    """The binary form of a SID."""
    parts = text.split("-")
    revision = int(parts[1])
    authority = int(parts[2])
    sub_authorities = [int(part) for part in parts[3:]]
    out = bytearray([revision, len(sub_authorities)])
    out += authority.to_bytes(6, "big")
    for number in sub_authorities:
        out += number.to_bytes(4, "little")
    return bytes(out)


def sid_text(raw: bytes) -> str:
    """The text form of a binary SID.

    A buffer that is not a SID raises, the way the binding raises when
    the bytes it is given are not one.
    """
    if len(raw) < 8:
        raise ValueError("the sid is too short")
    revision = raw[0]
    count = raw[1]
    if revision != 1 or count > 15 or len(raw) != 8 + 4 * count:
        raise ValueError("the sid is malformed")
    authority = int.from_bytes(raw[2:8], "big")
    parts = [f"S-{revision}", str(authority)]
    for index in range(count):
        start = 8 + 4 * index
        parts.append(str(int.from_bytes(raw[start : start + 4], "little")))
    return "-".join(parts)


def guid_bytes(text: str) -> bytes:
    """The binary form of an objectGUID."""
    return uuid.UUID(text).bytes_le


def guid_text(raw: bytes) -> str:
    """The text form of an objectGUID."""
    return str(uuid.UUID(bytes_le=raw))


def created_guid(dn: str) -> str:
    """The guid the fake gives an object it creates."""
    return guid_text(_created_guid_bytes(dn))


def _created_guid_bytes(dn: str) -> bytes:
    """The bytes of the guid the fake gives an object it creates."""
    import hashlib

    return hashlib.sha256(dn.encode("utf-8")).digest()[:16]


# ---- the errors and the constants of the ldb -------------------------------

SCOPE_BASE = 0
SCOPE_ONELEVEL = 1
SCOPE_SUBTREE = 2

FLAG_MOD_ADD = 0x00000080
FLAG_MOD_DELETE = 0x00000010
FLAG_MOD_REPLACE = 0x000000ff

ERR_TIME_LIMIT_EXCEEDED = 3
ERR_SIZE_LIMIT_EXCEEDED = 4
ERR_NO_SUCH_ATTRIBUTE = 16
ERR_NO_SUCH_OBJECT = 32
ERR_INVALID_CREDENTIALS = 49
ERR_INSUFFICIENT_ACCESS_RIGHTS = 50
ERR_BUSY = 51
ERR_UNAVAILABLE = 52
ERR_UNWILLING_TO_PERFORM = 53
ERR_OTHER = 80


class LdbError(Exception):
    """The error of the fake ldb: the code first, the message second."""

    def __init__(self, code: int, message: str = "") -> None:
        super().__init__(message)
        self.args = (code, message)


def binary_encode(value: Any) -> str:
    """The escaped form of a value, as ldb.binary_encode gives it.

    The real one returns text (measured on Samba 4.22.11:
    ``ldb.binary_encode("a*b(")`` is the str ``"a\\2Ab\\28"``), so the
    fake returns text as well.
    """
    if isinstance(value, str):
        raw = value.encode("utf-8", "surrogateescape")
    else:
        raw = bytes(value)
    out = []
    for byte in raw:
        char = chr(byte)
        if 0x20 <= byte <= 0x7E and char not in "()*\\":
            out.append(char)
        else:
            out.append("\\%02x" % byte)
    return "".join(out)


class MessageElement:
    """One element of a message of the fake ldb."""

    def __init__(self, value: Any, flags: int, name: str) -> None:
        self.value = value
        self.flags = flags
        self.name = name


class Message(dict):
    """One message of the fake ldb: the elements under their keys."""


class Dn:
    """The name of an object, as the bindings hold it.

    The real one is built with ``ldb.Dn(ldb_object, dn)`` and it is put
    in the message of a modify, the way the binding expects it.
    """

    def __init__(self, db: Any = None, dn: Any = "") -> None:
        self.db = db
        self.dn = str(dn)

    def __str__(self) -> str:
        return self.dn

    def __repr__(self) -> str:
        return "Dn(%r)" % self.dn


# ---- the objects of the fake directory --------------------------------------


class FakeElement:
    """The values of one attribute of a result."""

    def __init__(self, values: list[bytes]) -> None:
        self._values = list(values)

    def __iter__(self):
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)

    @property
    def values(self) -> list[bytes]:
        return list(self._values)


class FakeMessage:
    """One result of a search.

    A result holds the attributes the search named and nothing else, the
    way ldb holds them, and the name of an attribute is matched without
    its case.
    """

    def __init__(self, dn: str, attributes: dict[str, list[bytes]], attrs: list[str]) -> None:
        self.dn = dn
        self._attributes: dict[str, list[bytes]] = {}
        for name in attrs:
            canonical = _canonical_name(attributes, name)
            if canonical is None:
                continue
            self._attributes[canonical] = list(attributes[canonical])

    def keys(self) -> list[str]:
        return list(self._attributes) + ["dn"]

    def __contains__(self, name: str) -> bool:
        return self._lookup(name) is not None

    def __getitem__(self, name: str) -> FakeElement:
        found = self._lookup(name)
        if found is None:
            raise KeyError(name)
        return FakeElement(found)

    def _lookup(self, name: str) -> list[bytes] | None:
        for key, values in self._attributes.items():
            if key.lower() == name.lower():
                return values
        return None


def _canonical_name(
    attributes: dict[str, list[bytes]],
    name: str,
) -> str | None:
    """The name of an attribute as the object spells it."""
    for key in attributes:
        if key.lower() == name.lower():
            return key
    return None


# ---- the filter of the fake -------------------------------------------------


def _unescape(text: str) -> bytes | None:
    """The bytes of a filter value, or None when it is not escaped."""
    out = bytearray()
    index = 0
    while index < len(text):
        char = text[index]
        if char != "\\":
            out.extend(char.encode("utf-8"))
            index += 1
            continue
        if index + 2 >= len(text):
            return None
        try:
            out.append(int(text[index + 1 : index + 3], 16))
        except ValueError:
            return None
        index += 3
    return bytes(out)


def _parse_group(text: str, index: int):
    """One group of a filter and the index behind it."""
    index += 1
    operator = None
    terms = []
    while True:
        while index < len(text) and text[index] in " \t":
            index += 1
        if index < len(text) and text[index] in "&|":
            operator = text[index]
            index += 1
        if index < len(text) and text[index] == "(":
            node, index = _parse_group(text, index)
        else:
            start = index
            while index < len(text) and text[index] not in "()&|":
                index += 1
            term = text[start:index].strip()
            name, _, value = term.partition("=")
            node = ("term", name.strip().lower(), value.strip())
        terms.append(node)
        while index < len(text) and text[index] in " \t":
            index += 1
        if index < len(text) and text[index] == ")":
            index += 1
            break
        if index >= len(text):
            break
    if not terms:
        raise ValueError("the filter holds no term")
    if operator is None:
        return terms[0], index
    return (operator, terms), index


def _parse_filter(text: str):
    """The tree of one filter."""
    node, _ = _parse_group(text, 0)
    return node


def _match_term(name: str, value: str, attributes: dict[str, list[bytes]]) -> bool:
    """True when the object matches one comparison term."""
    values: list[bytes] | None = None
    for key, held in attributes.items():
        if key.lower() == name:
            values = held
            break
    if values is None:
        return False
    if value == "*":
        return bool(values)
    raw = _unescape(value)
    if raw is not None and "\\" in value:
        return any(one == raw for one in values)
    wanted = value.lower()
    for one in values:
        if one.decode("utf-8", "replace").lower() == wanted:
            return True
    return False


def _evaluate(node, attributes: dict[str, list[bytes]]) -> bool:
    """True when the object matches the filter tree."""
    kind = node[0]
    if kind in ("&", "and"):
        return all(_evaluate(part, attributes) for part in node[1])
    if kind in ("|", "or"):
        return any(_evaluate(part, attributes) for part in node[1])
    if kind == "not":
        return not _evaluate(node[1], attributes)
    return _match_term(node[1], node[2], attributes)


def _in_scope(dn: str, base: str, scope: int) -> bool:
    """True when the object sits in the scope of the search."""
    if scope == SCOPE_BASE:
        return dn.lower() == base.lower()
    if scope == SCOPE_ONELEVEL:
        return dn.lower().endswith("," + base.lower()) and "," not in dn.lower()[
            : -len(base) - 1
        ]
    return dn.lower() == base.lower() or dn.lower().endswith("," + base.lower())


# ---- the loadparm and the credentials ---------------------------------------


class FakeLoadParm:
    """The loadparm of the fake DC.

    An option the loadparm does not hold raises a ``KeyError``, the way
    the real binding does (measured on the lab DC).
    """

    def __init__(self) -> None:
        self.loaded = False

    def load_default(self) -> None:
        self.loaded = True

    def get(self, name: str, default: Any = None) -> Any:
        if name not in PARM:
            raise KeyError(name)
        return PARM[name]


class FakeCredentials:
    """The credentials of the fake bind.

    The helper binds with the measured code of section 9: it sets the
    realm, the workgroup, the kerberos state and the named cache.  It
    never guesses them, and the fake records the guess so a test can
    prove it never happened.
    """

    def __init__(self) -> None:
        self.username = ""
        self.password = ""
        self.domain = ""
        self.realm = ""
        self.kerberos_state: int | None = None
        self.ccache = ""
        self.ccache_type: int | None = None
        self.guessed = False

    def guess(self, lp: Any) -> None:
        self.guessed = True
        active = _ACTIVE
        if active is not None:
            active.record("credentials", "guessed")
        try:
            self.domain = str(lp.get("realm"))
        except KeyError:
            self.domain = ""

    def set_username(self, name: str) -> None:
        self.username = name

    def set_password(self, password: str) -> None:
        self.password = password

    def set_domain(self, name: str) -> None:
        self.domain = name

    def set_realm(self, realm: str) -> None:
        self.realm = realm

    def set_kerberos_state(self, state: int) -> None:
        self.kerberos_state = state

    def set_named_ccache(self, name: str, ccache_type: int, lp: Any = None) -> None:
        self.ccache = name
        self.ccache_type = ccache_type


# ---- the directory ----------------------------------------------------------


class FakeSamDB:
    """The directory of the fake DC."""

    def __init__(
        self,
        url: str | None = None,
        credentials: Any = None,
        lp: Any = None,
        session_info: Any = None,
    ) -> None:
        self.url = url
        self.credentials = credentials
        self.lp = lp

    # -- the domain -------------------------------------------------------

    def domain_dn(self) -> str:
        return DOMAIN_DN

    def domain_dns_name(self) -> str:
        return DOMAIN_DNS

    def get_domain_sid(self) -> str:
        return DOMAIN_SID

    # -- the searches -----------------------------------------------------

    def search(
        self,
        base: str | None = None,
        scope: int | None = None,
        expression: str | None = None,
        attrs: list[str] | None = None,
        controls: list[str] | None = None,
    ) -> list[FakeMessage]:
        wanted = [str(name) for name in (attrs or [])]
        if int(scope or 0) != SCOPE_BASE:
            for name in wanted:
                if name.lower() in BASE_ONLY_ATTRS:
                    raise LdbError(
                        1,
                        "Cannot provide %s attribute, this is not a BASE search"
                        % name,
                    )
        active = _ACTIVE
        active.record(
            "search",
            "base=%s scope=%s expression=%s attrs=%s"
            % (base, scope, expression, ",".join(wanted)),
        )
        tree = _parse_filter(str(expression))
        found = []
        for dn, attributes in active.objects.items():
            if not _in_scope(dn, str(base), int(scope or 0)):
                continue
            if not _evaluate(tree, attributes):
                continue
            found.append(FakeMessage(dn, attributes, wanted))
        return found

    # -- the writes -------------------------------------------------------

    def modify(self, message: Any, controls: Any = None) -> None:
        """One modify: the message holds the name and the elements."""
        active = _ACTIVE
        dn = _message_dn(message)
        if controls is not None and not isinstance(controls, list):
            raise TypeError("controls is not a list")
        elements = [message[key] for key in sorted(message)]
        active.record(
            "modify",
            "dn=%s elements=%s"
            % (
                dn,
                ",".join(
                    "%s:%s:%s"
                    % (
                        element.name,
                        _flag_name(element.flags),
                        element.value,
                    )
                    for element in elements
                ),
            ),
        )
        attributes = active.objects.get(dn)
        if attributes is None:
            raise LdbError(ERR_NO_SUCH_OBJECT, "no such object")
        if not active.delegated(dn):
            raise LdbError(ERR_INSUFFICIENT_ACCESS_RIGHTS, "access denied")
        if active.modify_error is not None:
            raise active.modify_error
        if active.modify_code is not None:
            raise LdbError(active.modify_code, "the modify was refused")
        if dn in active.stale:
            raise LdbError(ERR_NO_SUCH_ATTRIBUTE, "no such attribute")
        if len(elements) not in (1, 2):
            raise LdbError(ERR_OTHER, "the modify is not the measured shape")
        if len(elements) == 1:
            only = elements[0]
            if only.flags == FLAG_MOD_DELETE:
                delete, add = only, None
            elif only.flags == FLAG_MOD_ADD:
                delete, add = None, only
            else:
                raise LdbError(ERR_OTHER, "the modify is not the measured shape")
        else:
            delete, add = elements[0], elements[1]
            if delete.flags != FLAG_MOD_DELETE or add.flags != FLAG_MOD_ADD:
                raise LdbError(ERR_OTHER, "the modify is not the measured shape")
            if delete.name.lower() != add.name.lower():
                raise LdbError(ERR_OTHER, "the modify names two attributes")
        name = (delete or add).name
        if name.lower() == "distinguishedname":
            # Measured on Samba 4.22.11 (2026-11-09): a modify of the
            # distinguished name answers 53, and the object is moved
            # with rename().
            raise LdbError(
                ERR_UNWILLING_TO_PERFORM, "the name is not written with a modify"
            )
        values = active.values_of(dn, name)
        if delete is not None:
            if delete.value not in values:
                raise LdbError(ERR_NO_SUCH_ATTRIBUTE, "no such attribute")
            values.remove(delete.value)
        if add is not None:
            values.append(add.value)
        active.set_values(dn, name, values)

    def rename(self, olddn: str, newdn: str, controls: Any = None) -> None:
        """Move one object to another name, as the bindings do."""
        active = _ACTIVE
        active.record("rename", "old=%s new=%s" % (olddn, newdn))
        code = active.rename_errors.get(olddn)
        if code is not None:
            raise LdbError(code, "the rename was refused")
        found = None
        for dn in active.objects:
            if dn.lower() == str(olddn).lower():
                found = dn
                break
        if found is None:
            raise LdbError(ERR_NO_SUCH_OBJECT, "no such object")
        if not active.delegated(str(newdn)):
            raise LdbError(ERR_INSUFFICIENT_ACCESS_RIGHTS, "access denied")
        attributes = active.objects.pop(found)
        active.objects[str(newdn)] = attributes

    def add(self, message: Any, controls: Any = None) -> None:
        """One object: one dict with the name and the class in it."""
        active = _ACTIVE
        if not isinstance(message, dict) or "dn" not in message:
            raise TypeError("controls is not a list")
        if controls is not None and not isinstance(controls, list):
            raise TypeError("controls is not a list")
        dn = str(message["dn"])
        attrs = {name: value for name, value in message.items() if name != "dn"}
        if not any(str(name).lower() == "objectclass" for name in attrs):
            raise LdbError(ERR_OTHER, "the object holds no objectClass")
        active.record("add", "dn=%s attrs=%s" % (dn, ",".join(sorted(attrs))))
        if not active.delegated(dn):
            raise LdbError(ERR_INSUFFICIENT_ACCESS_RIGHTS, "access denied")
        if active.add_error is not None:
            raise active.add_error
        if active.add_code is not None:
            raise LdbError(active.add_code, "the add was refused")
        if dn in active.objects:
            raise LdbError(ERR_OTHER, "the object is already there")
        held: dict[str, list[bytes]] = {}
        for name, value in attrs.items():
            held[name.lower()] = [_as_bytes(value)]
        held.setdefault("objectsid", [sid_bytes(_new_sid(active))])
        held.setdefault("objectguid", [_created_guid_bytes(dn)])
        held.setdefault("usnchanged", [str(active.next_usn()).encode("utf-8")])
        active.objects[dn] = held

    def delete(self, dn: str, controls: Any = None) -> None:
        active = _ACTIVE
        active.record("delete", "dn=%s" % dn)
        if dn not in active.objects:
            raise LdbError(ERR_NO_SUCH_OBJECT, "no such object")
        if not active.delegated(dn):
            raise LdbError(ERR_INSUFFICIENT_ACCESS_RIGHTS, "access denied")
        if active.delete_error is not None:
            raise active.delete_error
        if active.delete_code is not None:
            raise LdbError(active.delete_code, "the delete was refused")
        del active.objects[dn]


def _message_dn(message: Any) -> str:
    """The name of the object of a message.

    The real binding takes the name in the message: a call shaped like
    ``modify(dn, message)`` hands it a name where the message belongs,
    and it answers ``TypeError("controls is not a list")``, the way it
    was measured to answer.
    """
    name = getattr(message, "dn", None)
    if name is None:
        raise TypeError("controls is not a list")
    return str(name)


def _flag_name(flags: int) -> str:
    """The name of a flag of a message."""
    if flags == FLAG_MOD_DELETE:
        return "delete"
    if flags == FLAG_MOD_ADD:
        return "add"
    if flags == FLAG_MOD_REPLACE:
        return "replace"
    return str(flags)


def _as_bytes(value: Any) -> bytes:
    """The bytes of one value of an add."""
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    return str(value).encode("utf-8")


def _new_sid(active: "Fake") -> str:
    """The SID of an object the fake creates."""
    active._sid_counter += 1
    return DOMAIN_SID + "-1" + str(1000 + active._sid_counter)


# ---- the fake ---------------------------------------------------------------


class Fake:
    """The fake DC: its objects, its calls and its log."""

    def __init__(self, log_path: Path | None = None) -> None:
        self.log_path = log_path
        self.calls: list[tuple[str, str]] = []
        self.objects: dict[str, dict[str, list[bytes]]] = {}
        self.credentials: FakeCredentials | None = None
        self.url: str | None = None
        self.stale: set[str] = set()
        self.modify_code: int | None = None
        self.modify_error: Exception | None = None
        self.add_code: int | None = None
        self.add_error: Exception | None = None
        self.delete_code: int | None = None
        self.delete_error: Exception | None = None
        self.rename_errors: dict[str, int] = {}
        self._usn = 1000
        self._sid_counter = 0
        self.reset()

    # -- the state --------------------------------------------------------

    def reset(self) -> None:
        """Put the fake back to the state of a fresh DC."""
        self.objects = {}
        self.calls = []
        self.stale = set()
        self.modify_code = None
        self.modify_error = None
        self.add_code = None
        self.add_error = None
        self.delete_code = None
        self.delete_error = None
        self.rename_errors = {}
        self._usn = 1000
        self._sid_counter = 0
        for dn, attributes in _initial_objects().items():
            self.objects[dn] = {
                name.lower(): list(values) for name, values in attributes.items()
            }

    def next_usn(self) -> int:
        """The next value of the uSNChanged of the fake."""
        self._usn += 1
        return self._usn

    # -- the calls --------------------------------------------------------

    def record(self, kind: str, text: str) -> None:
        """Record one call of the fake."""
        self.calls.append((kind, text))
        if self.log_path is None:
            return
        with open(self.log_path, "a", encoding="utf-8") as handle:
            handle.write(f"{kind}: {text}\n")

    # -- the objects ------------------------------------------------------

    def has_object(self, dn: str) -> bool:
        """True when the fake holds that object."""
        return dn in self.objects

    def values_of(self, dn: str, name: str) -> list[bytes]:
        """The values of one attribute of one object."""
        attributes = self.objects.get(dn, {})
        for key, values in attributes.items():
            if key.lower() == name.lower():
                return values
        return []

    def set_values(self, dn: str, name: str, values: list[bytes]) -> None:
        """Set the values of one attribute of one object."""
        attributes = self.objects.setdefault(dn, {})
        for key in list(attributes):
            if key.lower() == name.lower():
                attributes[key] = list(values)
                return
        attributes[name.lower()] = list(values)

    def set_attribute(self, dn: str, name: str, value: Any) -> None:
        """Set one attribute of one object to one value."""
        self.set_values(dn, name, [_as_bytes(value)])

    def get_attribute(self, dn: str, name: str) -> str | None:
        """The text of one value of one attribute."""
        values = self.values_of(dn, name)
        if not values:
            return None
        return values[0].decode("utf-8", "replace")

    def add_member(self, group_dn: str, member_dn: str) -> None:
        """Add a member to a group."""
        values = self.values_of(group_dn, "member")
        values.append(member_dn.encode("utf-8"))
        self.set_values(group_dn, "member", values)

    def set_stale_value(self, dn: str) -> None:
        """The object moves on between the read and the write.

        Every modify of that object then answers 16, the way the server
        answers a stale old value.
        """
        self.stale.add(dn)

    def set_token_groups(self, dn: str, sids: list[str]) -> None:
        """Set the tokenGroups of one object."""
        self.set_values(dn, "tokenGroups", [sid_bytes(one) for one in sids])

    def remove_object(self, dn: str) -> None:
        """Take one object out of the directory."""
        self.objects.pop(dn, None)

    def add_object(self, dn: str, attributes: dict[str, list[bytes]]) -> None:
        """Put one object into the directory."""
        self.objects[dn] = {
            name.lower(): list(values) for name, values in attributes.items()
        }

    def move_object(self, dn: str, new_dn: str) -> None:
        """Move one object to another name, as somebody else would."""
        attributes = self.objects.pop(dn)
        self.objects[new_dn] = attributes

    def set_rename_error(self, dn: str, code: int) -> None:
        """The rename of that object answers that code."""
        self.rename_errors[dn] = code

    def delegated(self, dn: str) -> bool:
        """True when the fake lets the write account write that object."""
        if dn in DELEGATED_OBJECTS:
            return True
        for root in DELEGATED_ROOTS:
            if dn.lower().endswith("," + root.lower()):
                return True
        return False

    # -- the modules ------------------------------------------------------

    def modules(self) -> dict[str, types.ModuleType]:
        """The modules the helper imports, the fake of each one."""
        global _ACTIVE
        _ACTIVE = self

        ldb_module = types.ModuleType("ldb")
        ldb_module.LdbError = LdbError
        ldb_module.Message = Message
        ldb_module.MessageElement = MessageElement
        ldb_module.Dn = Dn
        ldb_module.SCOPE_BASE = SCOPE_BASE
        ldb_module.SCOPE_ONELEVEL = SCOPE_ONELEVEL
        ldb_module.SCOPE_SUBTREE = SCOPE_SUBTREE
        ldb_module.FLAG_MOD_ADD = FLAG_MOD_ADD
        ldb_module.FLAG_MOD_DELETE = FLAG_MOD_DELETE
        ldb_module.FLAG_MOD_REPLACE = FLAG_MOD_REPLACE
        ldb_module.ERR_TIME_LIMIT_EXCEEDED = ERR_TIME_LIMIT_EXCEEDED
        ldb_module.ERR_SIZE_LIMIT_EXCEEDED = ERR_SIZE_LIMIT_EXCEEDED
        ldb_module.ERR_NO_SUCH_ATTRIBUTE = ERR_NO_SUCH_ATTRIBUTE
        ldb_module.ERR_NO_SUCH_OBJECT = ERR_NO_SUCH_OBJECT
        ldb_module.ERR_INVALID_CREDENTIALS = ERR_INVALID_CREDENTIALS
        ldb_module.ERR_INSUFFICIENT_ACCESS_RIGHTS = ERR_INSUFFICIENT_ACCESS_RIGHTS
        ldb_module.ERR_BUSY = ERR_BUSY
        ldb_module.ERR_UNAVAILABLE = ERR_UNAVAILABLE
        ldb_module.ERR_UNWILLING_TO_PERFORM = ERR_UNWILLING_TO_PERFORM
        ldb_module.ERR_OTHER = ERR_OTHER
        ldb_module.binary_encode = binary_encode

        samba_module = types.ModuleType("samba")
        samba_module.__path__ = []  # type: ignore[attr-defined]

        samdb_module = types.ModuleType("samba.samdb")
        samdb_module.SamDB = _BoundSamDB

        param_module = types.ModuleType("samba.param")
        param_module.LoadParm = FakeLoadParm

        credentials_module = types.ModuleType("samba.credentials")
        credentials_module.Credentials = _BoundCredentials
        credentials_module.MUST_USE_KERBEROS = MUST_USE_KERBEROS
        credentials_module.SPECIFIED = SPECIFIED

        dcerpc_module = types.ModuleType("samba.dcerpc")
        dcerpc_module.__path__ = []  # type: ignore[attr-defined]
        security_module = types.ModuleType("samba.dcerpc.security")
        security_module.dom_sid = FakeDomSid

        ndr_module = types.ModuleType("samba.ndr")
        ndr_module.ndr_unpack = lambda _cls, raw: sid_text(raw)

        samba_module.samdb = samdb_module
        samba_module.param = param_module
        samba_module.credentials = credentials_module
        samba_module.dcerpc = dcerpc_module
        samba_module.ndr = ndr_module
        dcerpc_module.security = security_module

        return {
            "ldb": ldb_module,
            "samba": samba_module,
            "samba.samdb": samdb_module,
            "samba.param": param_module,
            "samba.credentials": credentials_module,
            "samba.dcerpc": dcerpc_module,
            "samba.dcerpc.security": security_module,
            "samba.ndr": ndr_module,
        }


class _BoundSamDB(FakeSamDB):
    """The SamDB of the fake: it records the bind it was given."""

    def __init__(self, url: str | None = None, credentials: Any = None, lp: Any = None) -> None:
        super().__init__(url=url, credentials=credentials, lp=lp)
        active = _ACTIVE
        if active is not None:
            active.url = url
            active.credentials = credentials
            active.record("bind", "url=%s" % url)


class _BoundCredentials(FakeCredentials):
    """The credentials of the fake: they are recorded by the bind."""

    def set_named_ccache(self, name: str, ccache_type: int, lp: Any = None) -> None:
        super().set_named_ccache(name, ccache_type, lp)
        active = _ACTIVE
        if active is not None:
            active.record("credentials", "ccache=%s" % name)


class FakeDomSid:
    """The dom_sid of the fake."""

    def __init__(self, raw: bytes | None = None) -> None:
        self.raw = raw or b""

    def __str__(self) -> str:
        return sid_text(self.raw)


#: The fake the modules of the helper belong to.
_ACTIVE: Fake | None = None


def _initial_objects() -> dict[str, dict[str, list[bytes]]]:
    """The objects of the fake domain."""
    objects: dict[str, dict[str, list[bytes]]] = {
        # the rootDSE: the empty base, with the names the measured DC
        # answers (MEASURED-2026-11-09)
        "": {
            "objectClass": [b"top"],
            "defaultNamingContext": [DOMAIN_DN.encode("utf-8")],
            "dsServiceName": [NTDS_SETTINGS_DN.encode("utf-8")],
            "serverName": [SERVER_NAME_DN.encode("utf-8")],
        },
        DOMAIN_DN: {
            "objectClass": [b"domain", b"domainDNS"],
            "objectSid": [sid_bytes(DOMAIN_SID)],
            "objectGUID": [guid_bytes(DOMAIN_GUID)],
            "fSMORoleOwner": [NTDS_SETTINGS_DN.encode("utf-8")],
            "ms-DS-MachineAccountQuota": [b"10"],
            "adminCount": [b"0"],
            "uSNChanged": [b"1000"],
        },
        DC_OU_DN: {
            "objectClass": [b"organizationalUnit"],
            "ou": [DC_OU_NAME.encode("utf-8")],
            "objectGUID": [guid_bytes("1c2b3c4d-5e6f-4a8b-9c0d-1e2f3a4b5c6d")],
            "uSNChanged": [b"1019"],
        },
        DC_DN: {
            "objectClass": [b"computer"],
            "sAMAccountName": [b"DC1$"],
            "objectSid": [sid_bytes(DOMAIN_SID + "-1107")],
            "objectGUID": [guid_bytes("0c2b3c4d-5e6f-4a8b-9c0d-1e2f3a4b5c6d")],
            "userAccountControl": [b"4096"],
            "primaryGroupID": [b"516"],
            "serverReferenceBL": [SERVER_NAME_DN.encode("utf-8")],
            "uSNChanged": [b"1001"],
        },
        SERVERS_CONTAINER_DN: {
            "objectClass": [b"container"],
            "objectGUID": [guid_bytes("2c2b3c4d-5e6f-4a8b-9c0d-1e2f3a4b5c6d")],
            "uSNChanged": [b"1020"],
        },
        SERVER_DN: {
            "objectClass": [b"server"],
            "objectGUID": [guid_bytes("3c2b3c4d-5e6f-4a8b-9c0d-1e2f3a4b5c6d")],
            "uSNChanged": [b"1021"],
        },
        NTDS_SETTINGS_DN: {
            "objectClass": [b"nTDSDSA"],
            "uSNChanged": [b"1002"],
        },
        DOMAIN_ADMINS_DN: {
            "objectClass": [b"group"],
            # the sam of a group follows the pattern of the contract:
            # a name with a space in it cannot be named in a request
            "sAMAccountName": [b"domainadmins"],
            "objectSid": [sid_bytes(DOMAIN_ADMINS_SID)],
            "objectGUID": [guid_bytes(DOMAIN_ADMINS_GUID)],
            "adminCount": [b"1"],
            "member": [],
            "uSNChanged": [b"1003"],
        },
        DOMAIN_USERS_DN: {
            "objectClass": [b"group"],
            "sAMAccountName": [b"domainusers"],
            "objectSid": [sid_bytes(DOMAIN_USERS_SID)],
            "objectGUID": [guid_bytes(DOMAIN_USERS_GUID)],
            "member": [],
            "uSNChanged": [b"1004"],
        },
        NESTED1_DN: {
            "objectClass": [b"group"],
            "sAMAccountName": [b"nested1"],
            "objectSid": [sid_bytes(NESTED1_SID)],
            "objectGUID": [guid_bytes(NESTED1_GUID)],
            "memberOf": [DOMAIN_ADMINS_DN.encode("utf-8")],
            "member": [],
            "uSNChanged": [b"1005"],
        },
        NESTED2_DN: {
            "objectClass": [b"group"],
            "sAMAccountName": [b"nested2"],
            "objectSid": [sid_bytes(NESTED2_SID)],
            "objectGUID": [guid_bytes(NESTED2_GUID)],
            "memberOf": [NESTED1_DN.encode("utf-8")],
            "member": [],
            "uSNChanged": [b"1006"],
        },
        NESTED3_DN: {
            "objectClass": [b"group"],
            "sAMAccountName": [b"nested3"],
            "objectSid": [sid_bytes(NESTED3_SID)],
            "objectGUID": [guid_bytes(NESTED3_GUID)],
            "memberOf": [NESTED2_DN.encode("utf-8")],
            "member": [],
            "uSNChanged": [b"1007"],
        },
        CYCLE_A_DN: {
            "objectClass": [b"group"],
            "sAMAccountName": [b"cyclea"],
            "objectSid": [sid_bytes(CYCLE_A_SID)],
            "objectGUID": [guid_bytes(CYCLE_A_GUID)],
            "memberOf": [CYCLE_B_DN.encode("utf-8")],
            "member": [],
            "uSNChanged": [b"1008"],
        },
        CYCLE_B_DN: {
            "objectClass": [b"group"],
            "sAMAccountName": [b"cycleb"],
            "objectSid": [sid_bytes(CYCLE_B_SID)],
            "objectGUID": [guid_bytes(CYCLE_B_GUID)],
            "memberOf": [CYCLE_A_DN.encode("utf-8")],
            "member": [],
            "uSNChanged": [b"1009"],
        },
        GROUP_DN: {
            "objectClass": [b"group"],
            "sAMAccountName": [b"group1106"],
            "objectSid": [sid_bytes(GROUP_SID)],
            "objectGUID": [guid_bytes(GROUP_GUID)],
            "member": [],
            "uSNChanged": [b"1010"],
        },
        SERVERS_OU_DN: {
            "objectClass": [b"organizationalUnit"],
            "objectGUID": [guid_bytes(SERVERS_OU_GUID)],
            "uSNChanged": [b"1011"],
        },
        OTHER_OU_DN: {
            "objectClass": [b"organizationalUnit"],
            "objectGUID": [guid_bytes(OTHER_OU_GUID)],
            "uSNChanged": [b"1012"],
        },
        ALICE_DN: {
            "objectClass": [b"user", b"person"],
            "sAMAccountName": [b"alice"],
            "objectSid": [sid_bytes(ALICE_SID)],
            "objectGUID": [guid_bytes(ALICE_GUID)],
            # a normal account that carries DONT_REQ_PREAUTH
            "userAccountControl": [b"4194816"],
            "msDS-SupportedEncryptionTypes": [b"0"],
            "lockoutTime": [b"1000"],
            "adminCount": [b"0"],
            "primaryGroupID": [b"513"],
            "memberOf": [DOMAIN_USERS_DN.encode("utf-8")],
            "uSNChanged": [b"1013"],
        },
        BOB_DN: {
            "objectClass": [b"user", b"person"],
            "sAMAccountName": [b"bob"],
            "objectSid": [sid_bytes(BOB_SID)],
            "objectGUID": [guid_bytes(BOB_GUID)],
            "userAccountControl": [b"512"],
            "adminCount": [b"0"],
            "primaryGroupID": [b"513"],
            "memberOf": [DOMAIN_USERS_DN.encode("utf-8")],
            "uSNChanged": [b"1014"],
        },
        CAROL_DN: {
            "objectClass": [b"user", b"person"],
            "sAMAccountName": [b"carol"],
            "objectSid": [sid_bytes(CAROL_SID)],
            "objectGUID": [guid_bytes(CAROL_GUID)],
            "userAccountControl": [b"514"],
            "adminCount": [b"0"],
            "primaryGroupID": [b"513"],
            "memberOf": [DOMAIN_USERS_DN.encode("utf-8")],
            "uSNChanged": [b"1018"],
        },
        MALLORY_DN: {
            "objectClass": [b"user", b"person"],
            "sAMAccountName": [b"mallory"],
            "objectSid": [sid_bytes(MALLORY_SID)],
            "objectGUID": [guid_bytes(MALLORY_GUID)],
            "userAccountControl": [b"4194304"],
            "adminCount": [b"0"],
            "primaryGroupID": [b"513"],
            "uSNChanged": [b"1015"],
        },
        ADMIN_DN: {
            "objectClass": [b"user", b"person"],
            "sAMAccountName": [b"admin2"],
            "objectSid": [sid_bytes(ADMIN_SID)],
            "objectGUID": [guid_bytes(ADMIN_GUID)],
            "userAccountControl": [b"4194304"],
            "adminCount": [b"1"],
            "primaryGroupID": [b"513"],
            "memberOf": [DOMAIN_ADMINS_DN.encode("utf-8")],
            "uSNChanged": [b"1016"],
        },
        OPS_DN: {
            "objectClass": [b"user", b"person"],
            "sAMAccountName": [b"newton-ops"],
            "objectSid": [sid_bytes(OPS_SID)],
            "objectGUID": [guid_bytes(OPS_GUID)],
            "userAccountControl": [b"512"],
            "adminCount": [b"0"],
            "primaryGroupID": [b"513"],
            "tokenGroups": [sid_bytes(DOMAIN_USERS_SID), sid_bytes("S-1-1-0")],
            "uSNChanged": [b"1017"],
        },
    }
    return objects


# ---- the faked commands -----------------------------------------------------

#: The commands the helper runs.
COMMANDS = ("systemd-run", "systemctl", "kinit")


def _command_script(name: str) -> str:
    """The script of one faked command.

    The script records its arguments in the log file the test names and
    never does anything else: the helper runs it with an argv list, and
    the shell that runs it sees one argument per word.

    Two environment variables let a test make the command fail or take
    its time: ``NEWTON_FAKE_FAIL_<NAME>`` is the exit code it answers
    and ``NEWTON_FAKE_SLEEP_<NAME>`` is the number of seconds it waits
    before it answers.
    """
    upper = name.replace("-", "_").upper()
    return (
        "#!/bin/sh\n"
        'name=`basename "$0"`\n'
        'printf "command: %s" "$name" >> "$NEWTON_FAKE_LOG"\n'
        'for argument in "$@"; do printf " %s" "$argument" >> "$NEWTON_FAKE_LOG"; done\n'
        'printf "\\n" >> "$NEWTON_FAKE_LOG"\n'
        'if [ -n "$NEWTON_FAKE_SLEEP_UPPER" ]; then sleep "$NEWTON_FAKE_SLEEP_UPPER"; fi\n'
        'if [ -n "$NEWTON_FAKE_FAIL_UPPER" ]; then exit "$NEWTON_FAKE_FAIL_UPPER"; fi\n'
        "exit 0\n"
    ).replace("UPPER", upper)


def install_commands(bin_dir: Path) -> None:
    """Write the fakes of the commands the helper runs."""
    bin_dir.mkdir(parents=True, exist_ok=True)
    for name in COMMANDS:
        path = bin_dir / name
        path.write_text(_command_script(name), encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
