"""Load and validate the pinned query set (SPEC-1.3 section 4).

The query set is the one file both collectors install and run, and its
bytes are hashed: a collector reports the hash of the file it ran and
Newton refuses a document whose hash is not its own.  The hash is over the
bytes of the file, so the file is written once and never rewritten by
hand.

The validator runs at build time and at load time, and each rule has a
test:

- the query ids are unique;
- every attribute matches ``^[A-Za-z][A-Za-z0-9-]*$`` and none is ``*``;
- no requested attribute is forbidden;
- outside a ``presence_only`` query, no attribute name on the left of a
  filter term is forbidden (a value such as ``lDAPDisplayName=ms-Mcs-AdmPwd``
  is fine);
- the filters are balanced and hold no ``:=``;
- the limit is at most 50000.

The filter tokenizer here is a small one, not an LDAP parser: it checks
the parentheses and finds the attribute name on the left of every
comparison term.  There is no ldap3 dependency (SPEC-1.3 section 3).

Portions adapted from ActiveDirectoryMCP, Copyright (c) 2024 Alperen Adalar,
MIT License.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

from .forbidden import is_forbidden


# The file the collectors install, next to this module.
QUERIES_PATH = Path(__file__).with_name("queries.json")

# The version of the file format this module understands.
FORMAT_VERSION = 1

# The naming contexts a base may be: the three placeholders, or a DN that
# ends in one of them.
NAMING_CONTEXTS = ("{domain}", "{config}", "{schema}")

# The scopes a query may have.
SCOPES = frozenset({"base", "sub"})

# The largest number of rows a query may ask for.
MAX_LIMIT = 50000

# An attribute name: a letter, then letters, digits and dashes.
ATTRIBUTE_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]*$")

# A query id: the same shape as an attribute name but with the
# underscore the table uses ("domain_head", "kds_root_keys").
QUERY_ID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*$")


class QuerySetError(Exception):
    """The query set does not satisfy the contract of section 4.

    The message is one of a fixed set: it never carries any text of the
    file, because the file may be a hostile one.
    """


def _invalid(reason: str) -> QuerySetError:
    return QuerySetError(f"query set invalid: {reason}")


def _balanced(text: str) -> bool:
    """True when the parentheses of a filter are balanced."""
    depth = 0
    index = 0
    length = len(text)
    while index < length:
        char = text[index]
        if char == "\\":
            # An escaped character: the next two bytes are one value.
            index += 2
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth < 0:
                return False
        index += 1
    return depth == 0


@dataclass(frozen=True)
class FilterTerm:
    """One comparison term of a filter.

    The name is the attribute without its options: ``unicodePwd;binary``
    is the attribute ``unicodePwd``, because the options never change
    which attribute the term is about.
    """

    name: str
    operator: str
    value: str


def filter_terms(text: str) -> tuple[FilterTerm, ...]:
    """The comparison terms of a filter.

    The terms are ``=``, ``>=``, ``<=`` and ``~=``.  An extensible match
    (``:=``) is refused: it is the shape that turns a filter into an
    oracle, and no query of the set uses one.

    Raises ``QuerySetError`` when the filter is not balanced, uses an
    extensible match or names an attribute that is not an attribute name.
    """
    if not _balanced(text):
        raise _invalid("a query filter is not balanced")
    terms: list[FilterTerm] = []
    index = 0
    length = len(text)
    while index < length:
        char = text[index]
        if char == "\\":
            index += 2
            continue
        if char == ":":
            if text.startswith(":=", index):
                raise _invalid("a query filter uses an extensible match")
            index += 1
            continue
        if char not in "=<>~":
            index += 1
            continue
        operator_at = index
        if text[index : index + 2] in (">=", "<=", "~="):
            operator = text[index : index + 2]
            index += 2
        elif char == "=":
            operator = "="
            index += 1
        else:
            # A ">" or a "<" that is not an operator: the name in front
            # of it cannot be an attribute name, and the name check below
            # says so.
            operator = char
            index += 1
        end = operator_at
        while end > 0 and text[end - 1].isspace():
            end -= 1
        start = end
        while start > 0 and (
            text[start - 1].isalnum() or text[start - 1] in "-_;"
        ):
            start -= 1
        raw_name = text[start:end]
        name, _, _options = raw_name.partition(";")
        if not name:
            raise _invalid("a query filter has a term without an attribute")
        if not ATTRIBUTE_NAME_RE.fullmatch(name):
            raise _invalid("a filter attribute name is not valid")
        value_end = index
        while value_end < length:
            value_char = text[value_end]
            if value_char == "\\":
                value_end += 2
                continue
            if value_char == ")":
                break
            value_end += 1
        terms.append(
            FilterTerm(
                name=name,
                operator=operator,
                value=text[index:value_end].strip(),
            )
        )
        index = value_end
    return tuple(terms)


def filter_attributes(text: str) -> set[str]:
    """The attribute names on the left of the comparison terms of a filter.

    The names are the ones of the terms, without their options.  Raises
    ``QuerySetError`` when the filter is not balanced, uses an extensible
    match or names an attribute that is not an attribute name.
    """
    return {term.name for term in filter_terms(text)}


@dataclass(frozen=True)
class Query:
    """One query of the set."""

    id: str
    base: str
    scope: str
    filter: str
    attrs: tuple[str, ...]
    binary: tuple[str, ...]
    ranged: tuple[str, ...]
    sd: bool
    limit: int
    presence_only: bool

    @property
    def allowed_attrs(self) -> frozenset[str]:
        """The attribute names the rows of this query may carry.

        The names are the ones of the file, spelled the way the file
        spells them.  The security descriptor is asked for by the ``sd``
        flag and not by name, so it is allowed for the queries that ask
        for it.
        """
        names = set(self.attrs) | set(self.binary)
        if self.sd:
            names.add("nTSecurityDescriptor")
        return frozenset(names)


@dataclass(frozen=True)
class QuerySet:
    """The query set, its bytes and its hash."""

    path: Path
    raw: bytes
    queries: tuple[Query, ...]
    sha256: str

    @property
    def ids(self) -> tuple[str, ...]:
        """The query ids, in the order of the file."""
        return tuple(query.id for query in self.queries)

    @property
    def allowed_attrs(self) -> frozenset[str]:
        """Every attribute name the set asks a collector for."""
        names: set[str] = set()
        for query in self.queries:
            names.update(query.attrs)
            names.update(query.binary)
        return frozenset(names)

    def by_id(self, query_id: str) -> Query:
        """The query with that id."""
        for query in self.queries:
            if query.id == query_id:
                return query
        raise KeyError(query_id)


def _read_field(query: dict[str, object], name: str, kind: type) -> object:
    if name not in query:
        raise _invalid("a query field is missing")
    value = query[name]
    if kind is bool:
        if not isinstance(value, bool):
            raise _invalid("a query field has the wrong type")
        return value
    if kind is int:
        if not isinstance(value, int) or isinstance(value, bool):
            raise _invalid("a query field has the wrong type")
        return value
    if kind is str:
        if not isinstance(value, str):
            raise _invalid("a query field has the wrong type")
        return value
    if not isinstance(value, list):
        raise _invalid("a query field has the wrong type")
    for item in value:
        if not isinstance(item, str):
            raise _invalid("a query field has the wrong type")
    return value


def _validate_base(base: str) -> None:
    if base in NAMING_CONTEXTS:
        return
    for context in NAMING_CONTEXTS:
        if base.endswith("," + context):
            return
    raise _invalid("a query base is not a naming context")


def _validate_attrs(names: tuple[str, ...]) -> None:
    for name in names:
        if name == "*" or not ATTRIBUTE_NAME_RE.match(name):
            raise _invalid("a requested attribute name is not valid")
        if is_forbidden(name):
            raise _invalid("a requested attribute is forbidden")


def _parse_query(raw: object) -> Query:
    if not isinstance(raw, dict):
        raise _invalid("a query is not an object")
    query_id = _read_field(raw, "id", str)
    if not isinstance(query_id, str) or not QUERY_ID_RE.match(query_id):
        raise _invalid("a query id is not a name")
    base = _read_field(raw, "base", str)
    scope = _read_field(raw, "scope", str)
    filter_text = _read_field(raw, "filter", str)
    attrs = tuple(_read_field(raw, "attrs", list))
    binary = tuple(_read_field(raw, "binary", list))
    ranged = tuple(_read_field(raw, "ranged", list))
    sd = _read_field(raw, "sd", bool)
    limit = _read_field(raw, "limit", int)
    presence_only = _read_field(raw, "presence_only", bool)

    assert isinstance(base, str)
    assert isinstance(scope, str)
    assert isinstance(filter_text, str)
    assert isinstance(sd, bool)
    assert isinstance(limit, int)
    assert isinstance(presence_only, bool)

    _validate_base(base)
    if scope not in SCOPES:
        raise _invalid("a query scope is not base or sub")
    if limit < 1 or limit > MAX_LIMIT:
        raise _invalid("a query limit is out of range")
    _validate_attrs(attrs)
    _validate_attrs(binary)
    _validate_attrs(ranged)
    for name in ranged:
        if name not in attrs:
            raise _invalid("a ranged attribute is not requested")

    terms = filter_terms(filter_text)
    if not presence_only:
        for term in terms:
            if is_forbidden(term.name):
                raise _invalid("a filter attribute is forbidden")
    else:
        # A presence-only query tests that a forbidden attribute is
        # there, and nothing else: the term is exactly ``(attr=*)``.
        for term in terms:
            if not is_forbidden(term.name):
                continue
            if term.operator != "=" or term.value != "*":
                raise _invalid(
                    "a presence-only query may only test the presence "
                    "of an attribute"
                )

    return Query(
        id=query_id,
        base=base,
        scope=scope,
        filter=filter_text,
        attrs=attrs,
        binary=binary,
        ranged=ranged,
        sd=sd,
        limit=limit,
        presence_only=presence_only,
    )


def load(path: Path | str | None = None) -> QuerySet:
    """Load and validate the query set.

    Without a path the shipped file is read.  The hash is over the bytes
    of the file, so it is the same on every host that installs it.
    """
    source = Path(path) if path is not None else QUERIES_PATH
    try:
        raw = source.read_bytes()
    except OSError as exc:
        raise _invalid("the query set cannot be read") from exc
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _invalid("the query set is not JSON") from exc
    if not isinstance(payload, dict):
        raise _invalid("the query set is not an object")
    version = payload.get("v")
    if isinstance(version, bool) or version != FORMAT_VERSION:
        raise _invalid("the query set version is not supported")
    raw_queries = payload.get("queries")
    if not isinstance(raw_queries, list) or not raw_queries:
        raise _invalid("the query set has no queries")

    queries = tuple(_parse_query(item) for item in raw_queries)
    ids = [query.id for query in queries]
    if len(set(ids)) != len(ids):
        raise _invalid("the query ids are not unique")

    return QuerySet(
        path=source,
        raw=raw,
        queries=queries,
        sha256=hashlib.sha256(raw).hexdigest(),
    )
