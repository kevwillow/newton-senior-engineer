"""The fake Samba bindings the Samba collector runs against in the tests.

The samba python bindings are not installed on this machine, so the
collector tests build these fakes and inject them into ``sys.modules``.
The fakes reproduce the shapes the lab DC was measured with:

* ``db.domain_dn()`` returns a str, ``db.get_config_basedn()`` and
  ``db.get_schema_basedn()`` return an object whose ``str()`` is the DN;
* every value of an attribute of a result is bytes;
* the keys of a result hold ``"dn"``;
* an ``LdbError`` carries ``(32, "...")``: the code first, the message
  second;
* the session comes from ``samba.auth.system_session`` and there is no
  ``samba.auth.system`` module (measured on Samba 4.22.11);
* the unpack of an NDR object comes from ``samba.ndr.ndr_unpack`` and
  ``samba.dcerpc.misc`` has no ``ndr_unpack`` in it (measured on Samba
  4.22.11);
* ``ldb.binary_encode`` returns text, not bytes (measured on Samba
  4.22.11: ``ldb.binary_encode("a*b(")`` is the str ``"a\\2Ab\\28"``);
* the error codes of the ldb are the measured ones:
  ``ERR_TIME_LIMIT_EXCEEDED=3``, ``ERR_SIZE_LIMIT_EXCEEDED=4``,
  ``ERR_NO_SUCH_OBJECT=32``, ``ERR_INVALID_CREDENTIALS=49``,
  ``ERR_INSUFFICIENT_ACCESS_RIGHTS=50``, ``ERR_BUSY=51``,
  ``ERR_UNAVAILABLE=52``, ``ERR_UNWILLING_TO_PERFORM=53`` and
  ``ERR_OTHER=80``.  There is no ``ERR_ACCESS_DENIED``, no
  ``ERR_INSUFFICIENT_ACCESS`` and no ``ERR_AUTH_ERROR``;
* the second argument of ``LoadParm.get`` is the name of a share and
  not a default value (measured on Samba 4.22.11: ``lp.get("realm")``
  is the realm, ``lp.get("realm", "")`` is None and
  ``lp.get("path", "sysvol")`` is the path of the sysvol share), and an
  option the loadparm does not hold raises a ``KeyError``, the way the
  real binding does;
* a result holds the attributes the search named and nothing else, and
  the names are matched without their case, the way ldb matches them.

The fake directory holds the objects the query set of section 4 reads,
so a full run over it produces a document that satisfies the contract
of ``wire.parse``.  The values of the fake are the measured ones of the
lab DC (Samba 4.22.11) and of the spec; nothing here is invented.
"""

from __future__ import annotations

import sys
import types
from typing import Any


# ---- the domain the fake holds ---------------------------------------------

DOMAIN_DN = "DC=lab,DC=newton,DC=test"
CONFIG_DN = "CN=Configuration," + DOMAIN_DN
SCHEMA_DN = "CN=Schema," + CONFIG_DN
DOMAIN_DNS = "lab.newton.test"
DOMAIN_SID = "S-1-5-21-2694141092-4246003333-2665853310"
DOMAIN_USERS_SID = DOMAIN_SID + "-513"
DOMAIN_ADMINS_SID = DOMAIN_SID + "-512"
ADMINISTRATOR_SID = DOMAIN_SID + "-500"
AUDIT_NAME = "newton-audit"
AUDIT_SID = DOMAIN_SID + "-1105"
COMPUTER_SID = DOMAIN_SID + "-1107"
GROUP_SID = DOMAIN_SID + "-1108"
FSP_SID = DOMAIN_SID + "-1109"
GPO_GUID = "{31B2F340-016D-11D2-945F-00C04FB984F9}"


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
    """The text form of a binary SID."""
    revision = raw[0]
    count = raw[1]
    authority = int.from_bytes(raw[2:8], "big")
    parts = [f"S-{revision}", str(authority)]
    for index in range(count):
        start = 8 + 4 * index
        parts.append(str(int.from_bytes(raw[start : start + 4], "little")))
    return "-".join(parts)


def descriptor_bytes(owner: str, trustees: list[str]) -> bytes:
    """The bytes of a self-relative security descriptor.

    The layout is the one of MS-DTYP 2.4.6: the header, the owner and
    a DACL with one access allowed ACE per trustee.  The collectors ask
    for the owner and the DACL only, so the descriptor holds nothing
    else.
    """
    owner_raw = sid_bytes(owner)
    aces = b""
    for trustee in trustees:
        trustee_raw = sid_bytes(trustee)
        ace = bytearray()
        ace.append(0x00)  # ACCESS_ALLOWED_ACE
        ace.append(0x00)  # no flags
        ace += (8 + len(trustee_raw)).to_bytes(2, "little")
        ace += (0x000F01FF).to_bytes(4, "little")  # ADS_RIGHT_DS_ALL
        ace += trustee_raw
        aces += bytes(ace)
    dacl = bytearray()
    dacl.append(0x02)  # ACL_REVISION
    dacl.append(0x00)
    dacl += (8 + len(aces)).to_bytes(2, "little")
    dacl += len(trustees).to_bytes(2, "little")
    dacl += (0).to_bytes(2, "little")
    dacl += aces
    header = bytearray()
    header.append(0x01)  # a self-relative descriptor
    header.append(0x00)
    header += (0x8004).to_bytes(2, "little")  # SE_SELF_RELATIVE, SE_DACL_PRESENT
    header += (20).to_bytes(4, "little")  # the owner
    header += (0).to_bytes(4, "little")  # no group
    header += (0).to_bytes(4, "little")  # no SACL
    header += (20 + len(owner_raw)).to_bytes(4, "little")  # the DACL
    return bytes(header) + owner_raw + bytes(dacl)


# The security descriptors of the fake objects, the way the DC returns
# them: the raw bytes of a self-relative descriptor.  The domain head
# and the AdminSDHolder are the two the collector reads by name, and
# the others are the ones the protected-descriptor query reads.
DOMAIN_DESCRIPTOR = descriptor_bytes(DOMAIN_ADMINS_SID, [DOMAIN_ADMINS_SID])
ADMINSDHOLDER_DESCRIPTOR = descriptor_bytes(
    DOMAIN_ADMINS_SID, [DOMAIN_ADMINS_SID, AUDIT_SID]
)
PROTECTED_DESCRIPTOR = descriptor_bytes(DOMAIN_ADMINS_SID, [DOMAIN_ADMINS_SID])


# ---- the loadparm -----------------------------------------------------------

# The measured values of the loadparm of the lab DC.  The tests change
# them one at a time and restore them afterwards.
PARM: dict[str, Any] = {
    "server role": "active directory domain controller",
    "path": "/var/lib/samba",
    "realm": "LAB.NEWTON.TEST",
    "ldap server require strong auth": "Yes",
    "ntlm auth": "ntlmv2-only",
    "server signing": "default",
    "server min protocol": "SMB2_02",
    "kerberos encryption types": "all",
    "allow nt4 crypto": False,
    "reject md5 clients": True,
    "server schannel": "Yes",
    "tls enabled": True,
}


class FakeLoadParm:
    """The loadparm of the fake DC.

    The second argument of ``get`` is the name of a share and not a
    default value.  Measured on the lab DC (Samba 4.22.11):
    ``lp.get("realm")`` is the realm, ``lp.get("realm", "")`` is None
    and ``lp.get("path", "sysvol")`` is the path of the sysvol share.

    An option the loadparm does not hold raises a ``KeyError``, the
    way the real binding does (measured on the lab DC: ``lp.get("no
    such option")`` raises ``KeyError: 'no such option'``).
    """

    def __init__(self) -> None:
        self.loaded = False

    def load_default(self) -> None:
        self.loaded = True

    def get(self, name: str, default: Any = None) -> Any:
        if default is not None:
            return self.share_path(str(default))
        if name not in PARM:
            raise KeyError(name)
        return PARM[name]

    def share_path(self, share: str) -> Any:
        """The path of a share, or None when there is no such share.

        The sysvol share sits in the private directory of the samba
        installation, so its path follows the "path" parameter.
        """
        if share != "sysvol":
            return None
        base = str(PARM.get("path", "/var/lib/samba"))
        return base.rstrip("/") + "/sysvol"

    def private_path(self, name: str) -> str:
        return "/var/lib/samba/private/" + name


# ---- the directory ----------------------------------------------------------


class FakeDn:
    """The distinguished name of a result."""

    def __init__(self, text: str) -> None:
        self.text = text

    def __str__(self) -> str:
        return self.text

    def __repr__(self) -> str:
        return f"FakeDn({self.text!r})"


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


class FakeObject:
    """One object of the fake directory."""

    def __init__(
        self,
        dn: str,
        attributes: dict[str, list[bytes]],
        classes: tuple[str, ...] = (),
        categories: tuple[str, ...] = (),
    ) -> None:
        self.dn = dn
        self.attributes = dict(attributes)
        self.classes = {name.lower() for name in classes}
        self.categories = {name.lower() for name in categories}

    def matches(self, name: str, value: str) -> bool:
        """True when the object matches one comparison term."""
        if value == "*":
            if name == "objectclass":
                return bool(self.classes)
            if name == "objectcategory":
                return bool(self.categories)
            return self._attribute(name) is not None
        if name == "objectclass":
            return value.lower() in self.classes
        if name == "objectcategory":
            return value.lower() in self.categories
        wanted = value.lower()
        values = self._attribute(name)
        if values is None:
            return False
        for one in values:
            text = one.decode("utf-8", "replace").lower()
            if wanted.endswith("*"):
                if text.startswith(wanted[:-1]):
                    return True
            elif text == wanted:
                return True
        return False

    def _attribute(self, name: str) -> list[bytes] | None:
        """The values of one attribute, whatever its case is."""
        for key, values in self.attributes.items():
            if key.lower() == name.lower():
                return values
        return None

    def canonical_name(self, name: str) -> str | None:
        """The name of an attribute as the object spells it.

        The name of an attribute of a directory does not carry its case
        in the comparison, so a search that asks for "objectSid" gets
        the attribute of the object, whatever the object spells it.
        """
        for key in self.attributes:
            if key.lower() == name.lower():
                return key
        return None


class FakeMessage:
    """One result of a search.

    A result holds the attributes the search asked for and nothing else,
    the way ldb holds them, and the name of an attribute is matched
    without its case.  The name of the object is not an attribute of it:
    it is the ``dn`` of the result, and the keys of a result hold it.
    """

    def __init__(self, obj: FakeObject, attrs: list[str]) -> None:
        self.dn = FakeDn(obj.dn)
        self._attributes: dict[str, list[bytes]] = {}
        for name in attrs:
            canonical = obj.canonical_name(name)
            if canonical is None:
                continue
            self._attributes[canonical] = list(obj.attributes[canonical])

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
        """The values of one attribute, whatever its case is."""
        for key, values in self._attributes.items():
            if key.lower() == name.lower():
                return values
        return None


class SearchCall:
    """One search the collector made."""

    def __init__(
        self,
        base: str,
        scope: int,
        expression: str,
        attrs: list[str],
        controls: list[str],
    ) -> None:
        self.base = base
        self.scope = scope
        self.expression = expression
        self.attrs = attrs
        self.controls = controls


# ---- the filter of the fake -------------------------------------------------


def parse_filter(text: str):
    """A tree of one filter of the query set.

    The parser knows the shapes the query set uses: a group of terms
    joined by ``&`` or by ``|``, and a term that is a comparison.
    """
    node, _ = _parse_group(text, 0)
    return node


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


def evaluate(node, obj: FakeObject) -> bool:
    """True when the object matches the filter tree."""
    kind = node[0]
    if kind in ("&", "and"):
        return all(evaluate(part, obj) for part in node[1])
    if kind in ("|", "or"):
        return any(evaluate(part, obj) for part in node[1])
    if kind == "not":
        return not evaluate(node[1], obj)
    return obj.matches(node[1], node[2])


def _in_scope(dn: str, base: str, scope: int) -> bool:
    """True when the object sits in the scope of the search."""
    if scope == SCOPE_BASE:
        return dn.lower() == base.lower()
    return dn.lower() == base.lower() or dn.lower().endswith("," + base.lower())


# ---- the fake database ------------------------------------------------------

SCOPE_BASE = 0
SCOPE_ONELEVEL = 1
SCOPE_SUBTREE = 2


class FakeSamDB:
    """The directory of the fake DC."""

    def __init__(self, url: str | None = None, session_info: Any = None, lp: Any = None) -> None:
        self.url = url
        self.session_info = session_info
        self.lp = lp

    def domain_dn(self) -> str:
        return DOMAIN_DN

    def get_config_basedn(self) -> FakeDn:
        return FakeDn(CONFIG_DN)

    def get_schema_basedn(self) -> FakeDn:
        return FakeDn(SCHEMA_DN)

    def get_domain_sid(self) -> str:
        return DOMAIN_SID

    def domain_dns_name(self) -> str:
        return DOMAIN_DNS

    def search(
        self,
        base: str | None = None,
        scope: int | None = None,
        expression: str | None = None,
        attrs: list[str] | None = None,
        controls: list[str] | None = None,
    ) -> list[FakeMessage]:
        CALLS.append(
            SearchCall(
                str(base),
                int(scope or 0),
                str(expression),
                list(attrs or []),
                list(controls or []),
            )
        )
        failure = FAILURES.get(str(expression))
        if failure is not None:
            raise LdbError(failure[0], failure[1])
        tree = parse_filter(str(expression))
        found = []
        for obj in OBJECTS:
            if not _in_scope(obj.dn, str(base), int(scope or 0)):
                continue
            if not evaluate(tree, obj):
                continue
            found.append(FakeMessage(obj, list(attrs or [])))
        return found


# ---- the state of the fake --------------------------------------------------

OBJECTS: list[FakeObject] = []
FAILURES: dict[str, tuple[int, str]] = {}
CALLS: list[SearchCall] = []


class LdbError(Exception):
    """The error of the fake ldb: the code first, the message second."""


def build_objects() -> list[FakeObject]:
    """The objects of the fake domain."""
    users_dn = "CN=Users," + DOMAIN_DN
    computers_dn = "CN=Computers," + DOMAIN_DN
    system_dn = "CN=System," + DOMAIN_DN
    policies_dn = "CN=Policies," + system_dn
    windows_nt_dn = "CN=Windows NT,CN=Services," + CONFIG_DN
    directory_service_dn = "CN=Directory Service," + windows_nt_dn
    objects = [
        FakeObject(
            DOMAIN_DN,
            {
                "objectSid": [sid_bytes(DOMAIN_SID)],
                "ms-DS-MachineAccountQuota": [b"10"],
                "msDS-Behavior-Version": [b"7"],
                "minPwdLength": [b"7"],
                "pwdHistoryLength": [b"24"],
                "maxPwdAge": [b"0"],
                "minPwdAge": [b"1"],
                "pwdProperties": [b"0"],
                "lockoutThreshold": [b"0"],
                "lockoutDuration": [b"30"],
                "lockOutObservationWindow": [b"0"],
                "gPLink": [
                    (
                        "[LDAP://CN="
                        + GPO_GUID
                        + ",CN=Policies,CN=System,"
                        + DOMAIN_DN
                        + ";0]"
                    ).encode()
                ],
                "fSMORoleOwner": [b"CN=Administrator," + users_dn.encode()],
                "objectClass": [b"domain", b"domainDNS"],
                # The descriptor of the object: the queries that ask
                # for one get it from the object itself.
                "nTSecurityDescriptor": [DOMAIN_DESCRIPTOR],
            },
            classes=("domain", "domainDNS"),
            categories=("domain",),
        ),
        FakeObject(
            "CN=" + AUDIT_NAME + "," + users_dn,
            {
                "sAMAccountName": [AUDIT_NAME.encode()],
                "objectSid": [sid_bytes(AUDIT_SID)],
                "userAccountControl": [b"512"],
                "pwdLastSet": [b"134385793441023177"],
                "lastLogonTimestamp": [b"134385793441023178"],
                "adminCount": [b"0"],
                "primaryGroupID": [b"513"],
                "whenCreated": [b"20261108024224.0Z"],
                "tokenGroups": [
                    sid_bytes(DOMAIN_USERS_SID),
                    sid_bytes("S-1-1-0"),
                    sid_bytes("S-1-5-32-545"),
                    sid_bytes("S-1-5-11"),
                    sid_bytes("S-1-5-15"),
                ],
                # The account has a password attribute: the presence
                # query of the set must find it, and the collector must
                # never ask for it.
                "userPassword": [b"{REDACTED}"],
                "objectClass": [b"user", b"person"],
            },
            classes=("user", "person"),
            categories=("person",),
        ),
        FakeObject(
            "CN=Administrator," + users_dn,
            {
                "sAMAccountName": [b"Administrator"],
                "objectSid": [sid_bytes(ADMINISTRATOR_SID)],
                "userAccountControl": [b"512"],
                "adminCount": [b"1"],
                "primaryGroupID": [b"512"],
                "whenCreated": [b"20261107171335.0Z"],
                # The key credential attribute of the presence query.
                "msDS-KeyCredentialLink": [b"secret-blob"],
                "objectClass": [b"user", b"person"],
                "nTSecurityDescriptor": [PROTECTED_DESCRIPTOR],
            },
            classes=("user", "person"),
            categories=("person",),
        ),
        FakeObject(
            "CN=SAMBAD C1," + computers_dn,
            {
                "sAMAccountName": [b"SAMBAD C1$"],
                "objectSid": [sid_bytes(COMPUTER_SID)],
                "userAccountControl": [b"4096"],
                "primaryGroupID": [b"516"],
                "operatingSystem": [b"Samba"],
                "operatingSystemVersion": [b"4.22.11"],
                "objectClass": [b"computer"],
                "nTSecurityDescriptor": [PROTECTED_DESCRIPTOR],
            },
            classes=("computer",),
            categories=("computer",),
        ),
        FakeObject(
            "CN=Domain Admins," + users_dn,
            {
                "sAMAccountName": [b"Domain Admins"],
                "objectSid": [sid_bytes(DOMAIN_ADMINS_SID)],
                "member": [
                    ("CN=Administrator," + users_dn).encode(),
                    ("CN=" + AUDIT_NAME + "," + users_dn).encode(),
                ],
                "groupType": [b"-2147483646"],
                "adminCount": [b"1"],
                "objectClass": [b"group"],
                "nTSecurityDescriptor": [PROTECTED_DESCRIPTOR],
            },
            classes=("group",),
            categories=("group",),
        ),
        FakeObject(
            "CN=Domain Users," + users_dn,
            {
                "sAMAccountName": [b"Domain Users"],
                "objectSid": [sid_bytes(DOMAIN_USERS_SID)],
                "member": [("CN=" + AUDIT_NAME + "," + users_dn).encode()],
                "groupType": [b"-2147483644"],
                "objectClass": [b"group"],
            },
            classes=("group",),
            categories=("group",),
        ),
        FakeObject(
            "CN=Group " + str(GROUP_SID.rsplit("-", 1)[1]) + "," + users_dn,
            {
                "sAMAccountName": [b"Group 1108"],
                "objectSid": [sid_bytes(GROUP_SID)],
                "groupType": [b"-2147483646"],
                "objectClass": [b"group"],
            },
            classes=("group",),
            categories=("group",),
        ),
        FakeObject(
            "CN=S-1-5-21-2694141092-4246003333-2665853310-1109,"
            "CN=ForeignSecurityPrincipals," + DOMAIN_DN,
            {
                "objectSid": [sid_bytes(FSP_SID)],
                "objectClass": [b"foreignSecurityPrincipal"],
            },
            classes=("foreignsecurityprincipal",),
        ),
        FakeObject(
            "OU=Servers," + DOMAIN_DN,
            {
                "gPLink": [b""],
                "gPOptions": [b"1"],
                "objectClass": [b"organizationalUnit"],
            },
            classes=("organizationalunit",),
        ),
        FakeObject(
            "OU=Domain Controllers," + DOMAIN_DN,
            {
                "objectClass": [b"organizationalUnit"],
                "nTSecurityDescriptor": [PROTECTED_DESCRIPTOR],
            },
            classes=("organizationalunit",),
        ),
        FakeObject(
            "CN=" + GPO_GUID + "," + policies_dn,
            {
                "displayName": [b"Default Domain Policy"],
                "objectGUID": [bytes(range(16))],
                "gPCFileSysPath": [b"\\\\lab.newton.test\\sysvol\\lab.newton.test"],
                "versionNumber": [b"65536"],
                "flags": [b"0"],
                "objectClass": [b"groupPolicyContainer"],
                "nTSecurityDescriptor": [PROTECTED_DESCRIPTOR],
            },
            classes=("grouppolicycontainer",),
        ),
        FakeObject(
            "CN=AdminSDHolder," + system_dn,
            {
                "objectClass": [b"container"],
                "nTSecurityDescriptor": [ADMINSDHOLDER_DESCRIPTOR],
            },
            classes=("container",),
        ),
        FakeObject(
            "CN=BCKUPKEY-1," + system_dn,
            {
                "cn": [b"BCKUPKEY-1"],
                "objectClass": [b"secret"],
                "nTSecurityDescriptor": [PROTECTED_DESCRIPTOR],
            },
            classes=("secret",),
        ),
        FakeObject(
            directory_service_dn,
            {
                "dSHeuristics": [b"10"],
                "tombstoneLifetime": [b"180"],
                "objectClass": [b"container"],
            },
            classes=("container",),
        ),
        FakeObject(
            "CN=Partitions," + CONFIG_DN,
            {
                "msDS-Behavior-Version": [b"0"],
                "objectClass": [b"container"],
            },
            classes=("container",),
        ),
        FakeObject(
            SCHEMA_DN,
            {
                "objectVersion": [b"88"],
                "objectClass": [b"attributeSchema"],
            },
            classes=("attributeschema",),
        ),
        FakeObject(
            "CN=ms-Mcs-AdmPwd," + SCHEMA_DN,
            {
                "lDAPDisplayName": [b"ms-Mcs-AdmPwd"],
                "objectClass": [b"attributeSchema"],
            },
            classes=("attributeschema",),
        ),
    ]
    return objects


def reset() -> None:
    """Put the fake back to the state of a fresh DC."""
    global OBJECTS
    OBJECTS = build_objects()
    FAILURES.clear()
    CALLS.clear()
    PARM.update(
        {
            "server role": "active directory domain controller",
            "path": "/var/lib/samba",
            "realm": "LAB.NEWTON.TEST",
            "ldap server require strong auth": "Yes",
            "ntlm auth": "ntlmv2-only",
            "server signing": "default",
            "server min protocol": "SMB2_02",
            "kerberos encryption types": "all",
            "allow nt4 crypto": False,
            "reject md5 clients": True,
            "server schannel": "Yes",
            "tls enabled": True,
        }
    )


reset()


# ---- the modules the collector imports --------------------------------------


def binary_encode(value) -> str:
    """The escaped form of a value, as ldb.binary_encode gives it.

    The real one returns text (measured on Samba 4.22.11:
    ``ldb.binary_encode("a*b(")`` is the str ``"a\\2Ab\\28"``), so the
    fake returns text as well.  Every byte that is not printable
    ASCII is escaped as two hexadecimal digits in upper case (measured:
    ``ldb.binary_encode("a\\x01b")`` is the str ``"a\\01b"``), and so
    are the three characters that carry a meaning in a filter.
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
            out.append("\\%02X" % byte)
    return "".join(out)


class FakeDomSid:
    """The dom_sid of the fake.

    The real one is an NDR object: ``ndr_unpack(security.dom_sid, raw)``
    builds it from the raw bytes of a SID, and its text form is the
    text form of the SID.
    """

    def __init__(self, raw: bytes | None = None) -> None:
        self.raw = raw or b""

    def __str__(self) -> str:
        return sid_text(self.raw)


def install() -> None:
    """Put the fake ``ldb`` and ``samba`` modules into ``sys.modules``."""
    ldb_module = types.ModuleType("ldb")
    ldb_module.LdbError = LdbError
    ldb_module.SCOPE_BASE = SCOPE_BASE
    ldb_module.SCOPE_ONELEVEL = SCOPE_ONELEVEL
    ldb_module.SCOPE_SUBTREE = SCOPE_SUBTREE
    # The error codes of the lab DC (Samba 4.22.11).  There is no
    # ERR_ACCESS_DENIED, no ERR_INSUFFICIENT_ACCESS and no
    # ERR_AUTH_ERROR.
    ldb_module.ERR_TIME_LIMIT_EXCEEDED = 3
    ldb_module.ERR_SIZE_LIMIT_EXCEEDED = 4
    ldb_module.ERR_NO_SUCH_OBJECT = 32
    ldb_module.ERR_INVALID_CREDENTIALS = 49
    ldb_module.ERR_INSUFFICIENT_ACCESS_RIGHTS = 50
    ldb_module.ERR_BUSY = 51
    ldb_module.ERR_UNAVAILABLE = 52
    ldb_module.ERR_UNWILLING_TO_PERFORM = 53
    ldb_module.ERR_OTHER = 80
    ldb_module.binary_encode = binary_encode
    sys.modules["ldb"] = ldb_module

    samba_module = types.ModuleType("samba")
    samba_module.__path__ = []  # type: ignore[attr-defined]

    samdb_module = types.ModuleType("samba.samdb")
    samdb_module.SamDB = FakeSamDB

    # The session comes from this module (measured on Samba 4.22.11:
    # "from samba.auth import system_session"), and there is no
    # "samba.auth.system" module at all.
    auth_module = types.ModuleType("samba.auth")
    auth_module.__path__ = []  # type: ignore[attr-defined]
    auth_module.system_session = lambda: "system-session"

    param_module = types.ModuleType("samba.param")
    param_module.LoadParm = FakeLoadParm

    dcerpc_module = types.ModuleType("samba.dcerpc")
    dcerpc_module.__path__ = []  # type: ignore[attr-defined]
    security_module = types.ModuleType("samba.dcerpc.security")
    security_module.dom_sid = FakeDomSid
    # The unpack of an NDR object comes from "samba.ndr" (measured on
    # Samba 4.22.11: "cannot import name 'ndr_unpack' from
    # 'samba.dcerpc.misc'"), so this module has no unpack in it.
    misc_module = types.ModuleType("samba.dcerpc.misc")
    ndr_module = types.ModuleType("samba.ndr")
    ndr_module.ndr_unpack = lambda _cls, raw: sid_text(raw)

    samba_module.samdb = samdb_module
    samba_module.auth = auth_module
    samba_module.param = param_module
    samba_module.dcerpc = dcerpc_module
    samba_module.ndr = ndr_module
    dcerpc_module.security = security_module
    dcerpc_module.misc = misc_module

    sys.modules["samba"] = samba_module
    sys.modules["samba.samdb"] = samdb_module
    sys.modules["samba.auth"] = auth_module
    sys.modules["samba.param"] = param_module
    sys.modules["samba.dcerpc"] = dcerpc_module
    sys.modules["samba.dcerpc.security"] = security_module
    sys.modules["samba.dcerpc.misc"] = misc_module
    sys.modules["samba.ndr"] = ndr_module
