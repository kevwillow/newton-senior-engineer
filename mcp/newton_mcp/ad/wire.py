"""Validate one collector document (SPEC-1.3 section 5).

A collector prints one JSON document and Newton never trusts it.  This
module is the whole contract: the sizes, the statuses, the error codes,
the query ids, the identity, the descriptors and the GPO names.  A
document that breaks any rule is a hard error for the whole audit, never
a partial report.

Every error is ``collector document invalid: <reason>`` and the reason is
one of a fixed set: it never carries any text of the document, because the
document is untrusted and its text reaches a log.

The document is also checked against the directory it claims to be about:
the domain sid is the sid of the domain head, the audit account is an
account of that domain, the naming contexts of the document are the ones
of its domain, every row sits inside the base of the query that brought
it, every row carries only the attributes its query asked for, and no two
principals have the same sid or the same name.

The query set hash is checked here too: a collector that ran a different
file is refused with the message of section 2, ``collector out of date:
rerun the setup``.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from .forbidden import is_forbidden
from .queryset import Query, QuerySet
from .values import canonical_sid, dn_key, dn_rdns, sid_from_base64


# The largest document Newton reads (SPEC-1.3 section 5).
MAX_DOCUMENT_BYTES = 64 * 1024 * 1024

# The largest single value in a document.
MAX_VALUE_CHARS = 64 * 1024

# The largest number of values one attribute of a row may hold.  The
# member of a big group holds more, and nothing else does.
MAX_VALUES_PER_ATTRIBUTE = 5000
MAX_VALUES_PER_MEMBER = 100000

# The largest number of attributes one row may hold.
MAX_ATTRIBUTES_PER_ROW = 64

# The status values of a query, a file section and a settings item.
STATUSES = frozenset(
    {
        "ok",
        "truncated",
        "denied",
        "unsupported",
        "unavailable",
        "not_collected",
        "error",
    }
)

# The error codes of a query or a file section.  The code is empty when
# the status is "ok" and one of these otherwise.
ERROR_CODES = frozenset(
    {
        "access_denied",
        "no_such_object",
        "size_limit",
        "time_limit",
        "byte_limit",
        "unsupported",
        "server_down",
        "not_a_dc",
        "parse_refused",
        "other",
    }
)

# The collectors Newton knows.
COLLECTORS = frozenset({"windows", "samba"})

# The fixed settings list of each collector (SPEC-1.3 section 7): the
# source of its items and their keys, in the order the collector writes
# them.  A settings section that was read carries exactly these keys,
# each once; a section that was not read carries none.
SETTINGS_SOURCE = {"windows": "registry", "samba": "loadparm"}
SETTINGS_KEYS: dict[str, tuple[str, ...]] = {
    "windows": tuple(
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
    ),
    "samba": (
        "ldap server require strong auth",
        "ntlm auth",
        "server signing",
        "server min protocol",
        "kerberos encryption types",
        "allow nt4 crypto",
        "reject md5 clients",
        "server schannel",
        "tls enabled",
    ),
}

# The kinds a SYSVOL file item may have.
FILE_KINDS = frozenset({"cpassword", "autologon"})

# The name of a GPO folder (SPEC-1.3 section 5): a GUID in braces.  A
# folder that is not one is skipped by the collector and counted.  The
# name is matched whole: a name that ends in a newline is not a name.
GPO_NAME_RE = re.compile(
    r"\{[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\}"
)

# The queries whose rows are principals: every one of them carries a
# SID, and no two of them may carry the same one or the same name.
PRINCIPAL_QUERIES = ("users", "computers", "groups", "fsps")

# The queries whose rows must carry an objectSid.  The identity guard
# and the membership walk are computed from them.
SID_REQUIRED_QUERIES = ("users", "groups", "computers")

# The containers the configuration and the schema naming context sit in,
# under the domain of a single-domain forest.
CONFIGURATION_CONTAINER = "CN=Configuration"
SCHEMA_CONTAINER = "CN=Schema"

# The version of the document format.
FORMAT_VERSION = 1

# The message of a collector that ran a different query set.
OUT_OF_DATE_MESSAGE = "collector out of date: rerun the setup"


class WireError(Exception):
    """The document does not satisfy the contract.

    The message never carries any text of the document.
    """


def _invalid(reason: str) -> WireError:
    return WireError(f"collector document invalid: {reason}")


# ---- the document shape ---------------------------------------------------


@dataclass(frozen=True)
class Row:
    """One row of a query result."""

    dn: str
    a: dict[str, tuple[str, ...]]


@dataclass(frozen=True)
class QueryResult:
    """The result of one query of the set."""

    id: str
    status: str
    error_code: str
    rows: tuple[Row, ...]


@dataclass(frozen=True)
class GppItem:
    """One scrubbed SYSVOL file item."""

    gpo: str
    path: str
    kind: str
    count: int


@dataclass(frozen=True)
class GptTmplItem:
    """One setting of a GPO template."""

    gpo: str
    section: str
    key: str
    value: str


@dataclass(frozen=True)
class SettingsItem:
    """One configured setting of the collector host."""

    source: str
    key: str
    status: str
    value: str


@dataclass(frozen=True)
class FileSection:
    """One file section of the document (``gpp`` or ``gpttmpl``).

    ``parse_refused`` counts the files the collector read and could not
    use, and ``skipped_special`` counts the entries it never read (a
    symlink, a named pipe, an entry past a cap).  A section that
    refused or skipped files cannot prove that there is nothing in
    them, so a check that reads it may not answer PASS.
    """

    status: str
    error_code: str
    items: tuple[GppItem | GptTmplItem, ...]
    skipped_nonguid: int
    parse_refused: int = 0
    skipped_special: int = 0


@dataclass(frozen=True)
class SettingsSection:
    """The settings section of the document."""

    status: str
    error_code: str
    items: tuple[SettingsItem, ...]


@dataclass(frozen=True)
class Identity:
    """The account the collector ran as."""

    user: str
    sid: str
    token_group_sids: tuple[str, ...]


@dataclass(frozen=True)
class DomainInfo:
    """The directory the collector read."""

    dns: str
    domain_dn: str
    config_dn: str
    schema_dn: str
    domain_sid: str


@dataclass(frozen=True)
class Document:
    """One validated collector document."""

    v: int
    collector: str
    collector_version: str
    querysetsha: str
    is_dc: bool
    domain: DomainInfo
    identity: Identity
    started: str
    elapsed_ms: int
    queries: dict[str, QueryResult]
    files: dict[str, FileSection]
    settings: SettingsSection


# ---- small readers --------------------------------------------------------


def _text(value: object, reason: str) -> str:
    """A text field, with no NUL in it."""
    if not isinstance(value, str):
        raise _invalid(reason)
    if "\x00" in value:
        raise _invalid("a string holds a NUL")
    return value


def _no_nul(value: str) -> str:
    if "\x00" in value:
        raise _invalid("a string holds a NUL")
    return value


def _mapping(value: object, reason: str) -> dict:
    if not isinstance(value, dict):
        raise _invalid(reason)
    return value


def _sequence(value: object, reason: str) -> list:
    if not isinstance(value, list):
        raise _invalid(reason)
    return value


def _status_block(block: dict) -> tuple[str, str]:
    """The status and the error code of a query or a file section."""
    status = _text(block.get("status"), "a status is not text")
    if status not in STATUSES:
        raise _invalid("a status is not known")
    error_code = _text(block.get("error_code"), "an error code is not text")
    if status == "ok":
        if error_code:
            raise _invalid("an ok status carries an error code")
    else:
        if not error_code:
            raise _invalid("a status without ok carries no error code")
        if error_code not in ERROR_CODES:
            raise _invalid("an error code is not known")
    return status, error_code


def _canonical_attribute(name: str, query: Query) -> str:
    """The canonical spelling of an attribute name, or an error.

    A row may only carry the attributes its query asked for.  The
    comparison ignores the case and the name is stored the way the query
    set spells it, so one name is one name everywhere.  A ranged key is
    refused: the collector merges the ranges before it emits them.
    """
    if "range=" in name.lower():
        raise _invalid("a ranged attribute key is present")
    for allowed in query.allowed_attrs:
        if allowed.lower() == name.lower():
            return allowed
    raise _invalid("an attribute name is not requested by the query")


def _max_values(name: str) -> int:
    """The largest number of values one attribute may hold."""
    if name.lower() == "member":
        return MAX_VALUES_PER_MEMBER
    return MAX_VALUES_PER_ATTRIBUTE


def _parse_rows(raw: object, query: Query) -> tuple[Row, ...]:
    """The rows of a query result."""
    items = _sequence(raw, "the rows are not a list")
    if len(items) > query.limit:
        raise _invalid("a query holds more rows than its limit")
    rows: list[Row] = []
    for item in items:
        row = _mapping(item, "a row is not an object")
        dn = _text(row.get("dn"), "a row has no distinguished name")
        attributes = _mapping(row.get("a"), "the attributes of a row are not an object")
        if len(attributes) > MAX_ATTRIBUTES_PER_ROW:
            raise _invalid("a row holds too many attributes")
        values: dict[str, tuple[str, ...]] = {}
        for name, value in attributes.items():
            if not isinstance(name, str) or not name:
                raise _invalid("an attribute name is not text")
            _no_nul(name)
            if is_forbidden(name):
                raise _invalid("a forbidden attribute name is present")
            canonical = _canonical_attribute(name, query)
            listed = _sequence(value, "an attribute value is not a list")
            if len(listed) > _max_values(canonical):
                raise _invalid("an attribute holds too many values")
            texts: list[str] = []
            for one in listed:
                text = _text(one, "an attribute value is not text")
                if len(text) > MAX_VALUE_CHARS:
                    raise _invalid("an attribute value is too long")
                texts.append(text)
            values[canonical] = tuple(texts)
        if query.id in SID_REQUIRED_QUERIES and "objectSid" not in values:
            raise _invalid("a row of this query has no objectSid")
        rows.append(Row(dn=dn, a=values))
    return tuple(rows)


def _parse_gpp_items(raw: object) -> tuple[GppItem, ...]:
    items = _sequence(raw, "the file items are not a list")
    out: list[GppItem] = []
    for item in items:
        block = _mapping(item, "a file item is not an object")
        gpo = _text(block.get("gpo"), "a gpo name is not text")
        if not GPO_NAME_RE.fullmatch(gpo):
            raise _invalid("a gpo name is not a guid")
        path = _text(block.get("path"), "a file path is not text")
        kind = _text(block.get("kind"), "a file kind is not text")
        if kind not in FILE_KINDS:
            raise _invalid("a file kind is not known")
        count = block.get("count")
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            raise _invalid("a file count is not a number")
        out.append(GppItem(gpo=gpo, path=path, kind=kind, count=count))
    return tuple(out)


def _parse_gpttmpl_items(raw: object) -> tuple[GptTmplItem, ...]:
    items = _sequence(raw, "the file items are not a list")
    out: list[GptTmplItem] = []
    for item in items:
        block = _mapping(item, "a file item is not an object")
        gpo = _text(block.get("gpo"), "a gpo name is not text")
        if not GPO_NAME_RE.fullmatch(gpo):
            raise _invalid("a gpo name is not a guid")
        section = _text(block.get("section"), "a template section is not text")
        key = _text(block.get("key"), "a template key is not text")
        value = _text(block.get("value"), "a template value is not text")
        if len(value) > MAX_VALUE_CHARS:
            raise _invalid("an attribute value is too long")
        out.append(
            GptTmplItem(gpo=gpo, section=section, key=key, value=value)
        )
    return tuple(out)


def _parse_settings_items(raw: object) -> tuple[SettingsItem, ...]:
    items = _sequence(raw, "the settings items are not a list")
    out: list[SettingsItem] = []
    for item in items:
        block = _mapping(item, "a settings item is not an object")
        source = _text(block.get("source"), "a settings source is not text")
        key = _text(block.get("key"), "a settings key is not text")
        status = _text(block.get("status"), "a settings status is not text")
        if status not in STATUSES:
            raise _invalid("a status is not known")
        value = _text(block.get("value"), "a settings value is not text")
        if len(value) > MAX_VALUE_CHARS:
            raise _invalid("an attribute value is too long")
        out.append(
            SettingsItem(source=source, key=key, status=status, value=value)
        )
    return tuple(out)


def _check_settings_list(
    collector: str, status: str, items: tuple[SettingsItem, ...]
) -> None:
    """The items are the fixed list of the collector, or none at all.

    A section that was read (``ok``) carries every key of the list once,
    with the source of the collector; any other section carries no item.
    """
    if status != "ok":
        if items:
            raise _invalid("the settings items are not the fixed settings list")
        return
    source = SETTINGS_SOURCE[collector]
    keys = [item.key for item in items]
    if (
        any(item.source != source for item in items)
        or len(keys) != len(set(keys))
        or set(keys) != set(SETTINGS_KEYS[collector])
    ):
        raise _invalid("the settings items are not the fixed settings list")


def _parse_file_section(
    raw: object,
    *,
    kind: str,
) -> FileSection:
    block = _mapping(raw, "a file section is missing")
    status, error_code = _status_block(block)
    if kind == "gpp":
        items: tuple[GppItem | GptTmplItem, ...] = _parse_gpp_items(
            block.get("items", [])
        )
    else:
        items = _parse_gpttmpl_items(block.get("items", []))
    skipped = block.get("skipped_nonguid", 0)
    if not isinstance(skipped, int) or isinstance(skipped, bool) or skipped < 0:
        raise _invalid("a file count is not a number")
    refused = block.get("parse_refused", 0)
    if not isinstance(refused, int) or isinstance(refused, bool) or refused < 0:
        raise _invalid("a file count is not a number")
    special = block.get("skipped_special", 0)
    if not isinstance(special, int) or isinstance(special, bool) or special < 0:
        raise _invalid("a file count is not a number")
    return FileSection(
        status=status,
        error_code=error_code,
        items=items,
        skipped_nonguid=skipped,
        parse_refused=refused,
        skipped_special=special,
    )


def _canonical_sid(text: str, reason: str) -> str:
    """The canonical form of a SID, or an error.

    Every SID of the document is parsed and printed again, so two
    spellings of one SID are one SID everywhere it is compared.
    """
    try:
        return canonical_sid(text)
    except ValueError as exc:
        raise _invalid(reason) from exc


def _parse_identity(raw: object) -> Identity:
    block = _mapping(raw, "the identity block is missing")
    user = _text(block.get("user"), "the identity user is not text")
    sid = _text(block.get("sid"), "the identity sid is missing")
    sid = _canonical_sid(sid, "the identity sid is not a sid")
    raw_groups = _sequence(
        block.get("token_group_sids"), "the token group sids are missing"
    )
    if not raw_groups:
        raise _invalid("the token group sids are empty")
    groups: list[str] = []
    for one in raw_groups:
        text = _text(one, "a token group sid is not text")
        groups.append(_canonical_sid(text, "a token group sid is not a sid"))
    return Identity(user=user, sid=sid, token_group_sids=tuple(groups))


def _parse_domain(raw: object) -> DomainInfo:
    block = _mapping(raw, "the domain block is missing")
    dns = _text(block.get("dns"), "a domain field is missing")
    domain_dn = _text(block.get("domain_dn"), "a domain field is missing")
    config_dn = _text(block.get("config_dn"), "a domain field is missing")
    schema_dn = _text(block.get("schema_dn"), "a domain field is missing")
    domain_sid = _text(block.get("domain_sid"), "a domain field is missing")
    domain_sid = _canonical_sid(domain_sid, "the domain sid is not a sid")
    return DomainInfo(
        dns=dns,
        domain_dn=domain_dn,
        config_dn=config_dn,
        schema_dn=schema_dn,
        domain_sid=domain_sid,
    )


def _row_sid(row: Row) -> str | None:
    """The SID of a row, when it has one."""
    for value in row.a.get("objectSid", ()):
        try:
            return sid_from_base64(value)
        except ValueError:
            return None
    return None


def _domain_sid_of_head(result: QueryResult) -> str | None:
    """The SID of the domain head, when the query read one.

    The domain head is the root of the domain: its SID is the SID of
    the domain, and the document may not claim another one.
    """
    if result.status != "ok" or not result.rows:
        return None
    sid = _row_sid(result.rows[0])
    if sid is None:
        raise _invalid("the domain head has no usable sid")
    return sid


def _check_duplicates(queries: dict[str, QueryResult]) -> None:
    """No two principals may have the same SID or the same name.

    The check runs over the principal queries only: the same object
    legitimately appears in the protected sds query and in its own
    query.
    """
    sids: set[str] = set()
    names: set[str] = set()
    for query_id in PRINCIPAL_QUERIES:
        result = queries.get(query_id)
        if result is None:
            continue
        for row in result.rows:
            sid = _row_sid(row)
            if sid is not None:
                if sid in sids:
                    raise _invalid("two principals have the same sid")
                sids.add(sid)
            key = dn_key(row.dn)
            if key in names:
                raise _invalid("two principals have the same distinguished name")
            names.add(key)


def _expand_base(template: str, domain: DomainInfo) -> str:
    """The base of a query, with the naming contexts of the document in it.

    The substitution is the one the collectors do: the three
    placeholders of a base are the naming contexts the collector read,
    and the collector searched under the result.  The base of a query is
    therefore the place the rows of that query came from.
    """
    expanded = template
    for placeholder, naming_context in (
        ("{domain}", domain.domain_dn),
        ("{config}", domain.config_dn),
        ("{schema}", domain.schema_dn),
    ):
        expanded = expanded.replace(placeholder, naming_context)
    return expanded


def _inside_base(row_dn: str, base_dn: str, scope: str) -> bool:
    """True when the row sits inside the base of its query.

    A base-scope query reads one object: the row is the base itself.  A
    sub-scope query reads the base and everything under it, so the RDNs
    of the row end with the RDNs of the base.  The comparison is on the
    RDNs and never on the text of the name: a name whose text ends with
    the text of the base is not under the base when its RDNs are not
    (one RDN may hold an escaped comma, and a look-alike name may end
    with the same text).
    """
    base_key = dn_key(base_dn)
    row_key = dn_key(row_dn)
    if scope == "base":
        return row_key == base_key
    if row_key == base_key:
        return True
    row_rdns = dn_rdns(row_dn)
    base_rdns = dn_rdns(base_dn)
    if not base_rdns or len(row_rdns) < len(base_rdns):
        return False
    return row_rdns[len(row_rdns) - len(base_rdns) :] == base_rdns


def _check_rows_in_base(
    queries: dict[str, QueryResult],
    queryset: QuerySet,
    domain: DomainInfo,
) -> None:
    """Every row of every query sits inside the base of its query.

    A collector that reads somewhere else than the query asked for (a
    search root that was not the base, a search scope that was not the
    one of the query) fills the query with rows that belong to another
    place, and the audit of those rows is about another object than the
    one the query names.  The document is refused: one wrong row makes
    the whole document untrustworthy.
    """
    for query in queryset.queries:
        result = queries.get(query.id)
        if result is None:
            continue
        base = _expand_base(query.base, domain)
        for row in result.rows:
            if not _inside_base(row.dn, base, query.scope):
                raise _invalid("a row is outside its query base")


def _check_naming_contexts(
    domain: DomainInfo,
    queries: dict[str, QueryResult],
) -> None:
    """The naming contexts of the document are the ones of its domain.

    The domain name is the name of the domain head: the query that
    reads the head is a base-scope query under the domain, so the two
    are one name.

    The configuration and the schema naming context are the containers
    under the domain: ``CN=Configuration`` and ``CN=Schema``.

    The forest of 1.3 is a single-domain forest, so the configuration
    container of the domain is under the domain itself.  A forest whose
    root domain is above this one has its configuration container under
    that root domain, and this check refuses such a document; 1.3 has
    one domain per collector host and the naming contexts of the
    document are the ones of that domain.
    """
    head = queries.get("domain_head")
    if head is not None and head.status == "ok" and head.rows:
        if dn_key(head.rows[0].dn) != dn_key(domain.domain_dn):
            raise _invalid("the domain name is not the name of the domain head")
    if dn_key(domain.config_dn) != dn_key(
        f"{CONFIGURATION_CONTAINER},{domain.domain_dn}"
    ):
        raise _invalid("the configuration name is not the one of the domain")
    if dn_key(domain.schema_dn) != dn_key(f"{SCHEMA_CONTAINER},{domain.config_dn}"):
        raise _invalid("the schema name is not the one of the configuration")


def parse(raw: bytes, queryset: QuerySet) -> Document:
    """Validate one collector document and return it.

    The document is checked against the query set: the ids must be the
    ids of the set, exactly, and the hash must be the hash of the file
    Newton installed.

    Every failure of the document is a ``WireError``: a document that
    is malformed, too deep to parse or that carries a value Newton
    cannot read never reaches the audit as anything else.
    """
    try:
        return _parse(raw, queryset)
    except WireError:
        raise
    except (RecursionError, ValueError) as exc:
        # A document that is too deep to parse, or a value that is not
        # what it claims to be, is a document that is invalid.
        raise _invalid("the document is not valid") from exc


def _parse(raw: bytes, queryset: QuerySet) -> Document:
    """Validate one collector document and return it."""
    if not isinstance(raw, (bytes, bytearray)):
        raise _invalid("the document is not bytes")
    if len(raw) > MAX_DOCUMENT_BYTES:
        raise _invalid("the document is too large")
    try:
        payload = json.loads(bytes(raw).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _invalid("the document is not JSON") from exc
    except RecursionError as exc:
        raise _invalid("the document is too deep to parse") from exc
    document = _mapping(payload, "the document is not an object")

    version = document.get("v")
    if isinstance(version, bool) or version != FORMAT_VERSION:
        raise _invalid("the document version is not supported")
    collector = _text(document.get("collector"), "the collector name is not text")
    if collector not in COLLECTORS:
        raise _invalid("the collector name is not known")
    collector_version = _text(
        document.get("collector_version"), "the collector version is not text"
    )
    querysetsha = _text(document.get("querysetsha"), "the query set hash is not text")
    if querysetsha != queryset.sha256:
        raise WireError(OUT_OF_DATE_MESSAGE)
    is_dc = document.get("is_dc")
    if not isinstance(is_dc, bool):
        raise _invalid("is_dc is not a boolean")

    domain = _parse_domain(document.get("domain"))
    identity = _parse_identity(document.get("identity"))
    if not identity.sid.startswith(f"{domain.domain_sid}-"):
        raise _invalid("the identity sid is not in the domain")
    started = _text(document.get("started"), "started is not text")
    elapsed_ms = document.get("elapsed_ms")
    if not isinstance(elapsed_ms, int) or isinstance(elapsed_ms, bool):
        raise _invalid("elapsed_ms is not a number")

    raw_queries = _mapping(document.get("queries"), "the queries block is missing")
    if set(raw_queries) != set(queryset.ids):
        raise _invalid("the query ids do not match the query set")
    queries: dict[str, QueryResult] = {}
    for query_id in queryset.ids:
        block = _mapping(raw_queries[query_id], "a query block is not an object")
        status, error_code = _status_block(block)
        rows = _parse_rows(block.get("rows", []), queryset.by_id(query_id))
        queries[query_id] = QueryResult(
            id=query_id,
            status=status,
            error_code=error_code,
            rows=rows,
        )

    head_sid = _domain_sid_of_head(queries["domain_head"])
    if head_sid is not None and head_sid != domain.domain_sid:
        raise _invalid("the domain sid is not the sid of the domain head")
    _check_naming_contexts(domain, queries)
    _check_rows_in_base(queries, queryset, domain)
    _check_duplicates(queries)

    raw_files = _mapping(document.get("files"), "the files block is missing")
    files = {
        "gpp": _parse_file_section(raw_files.get("gpp"), kind="gpp"),
        "gpttmpl": _parse_file_section(raw_files.get("gpttmpl"), kind="gpttmpl"),
    }

    raw_settings = _mapping(document.get("settings"), "the settings block is missing")
    settings_status, settings_error = _status_block(raw_settings)
    settings = SettingsSection(
        status=settings_status,
        error_code=settings_error,
        items=_parse_settings_items(raw_settings.get("items", [])),
    )
    _check_settings_list(collector, settings.status, settings.items)

    return Document(
        v=FORMAT_VERSION,
        collector=collector,
        collector_version=collector_version,
        querysetsha=querysetsha,
        is_dc=is_dc,
        domain=domain,
        identity=identity,
        started=started,
        elapsed_ms=elapsed_ms,
        queries=queries,
        files=files,
        settings=settings,
    )
