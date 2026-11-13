"""The pinned query set: its content, its hash and its validator."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from newton_mcp.ad import forbidden, queryset

import docs


# The query ids of SPEC-1.3 section 4, in the order of the table.
TABLE_IDS = (
    "domain_head",
    "users",
    "computers",
    "groups",
    "fsps",
    "gmsa",
    "kds_root_keys",
    "psos",
    "dir_service",
    "optional_features",
    "partitions",
    "schema_head",
    "schema_laps",
    "trusts",
    "adminsdholder",
    "protected_sds",
    "dc_ou",
    "gpos",
    "ous",
    "dpapi_backup",
    "pw_attr_presence",
    "keycred_presence",
)

# The measured documents of the lab, the ones the tests read.
FIXTURE_DIR = Path(__file__).with_name("fixtures")
MEASURED_DOCUMENTS = (
    "win-dc-audit-r3.json",
    "win-dc-audit-r4-acl.json",
    "win-dc-admin-r3.json",
    "win-dc-admin-2026-11-08.json",
)


def write_query_set(tmp_path: Path, payload: dict) -> Path:
    """Write a query set to a file and return its path."""
    target = tmp_path / "queries.json"
    target.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return target


def test_the_shipped_query_set_loads() -> None:
    """The file Newton ships passes its own validator."""
    loaded = queryset.load()

    assert loaded.queries
    assert loaded.sha256


def test_the_hash_is_over_the_bytes_of_the_file() -> None:
    """The hash a collector reports is the hash of the file it ran."""
    loaded = queryset.load()

    assert loaded.sha256 == hashlib.sha256(loaded.raw).hexdigest()
    assert loaded.raw == queryset.QUERIES_PATH.read_bytes()


def test_the_measured_documents_carry_the_hash_of_the_query_set() -> None:
    """The measured documents were measured with the current query set.

    A measured document holds the hash of the query set it was read
    with.  The reader refuses a document whose hash is not the one of the
    file Newton ships, so a change of the query set has to be written into
    the measured documents with it.
    """
    loaded = queryset.load()

    for name in MEASURED_DOCUMENTS:
        document = json.loads(
            (FIXTURE_DIR / name).read_text(encoding="utf-8")
        )
        assert document["querysetsha"] == loaded.sha256, name


def test_the_query_ids_are_the_ones_of_the_table() -> None:
    """Every row of section 4 is in the file, and no other one is."""
    loaded = queryset.load()

    assert loaded.ids == TABLE_IDS


def test_every_query_asks_for_the_distinguished_name() -> None:
    """The table says every query requests distinguishedName."""
    for query in queryset.load().queries:
        assert "distinguishedName" in query.attrs


def test_the_groups_query_pages_through_member() -> None:
    """Only the groups query ranges, and it ranges member."""
    ranged = {
        query.id: query.ranged for query in queryset.load().queries if query.ranged
    }

    assert ranged == {"groups": ("member",)}


def test_only_the_two_presence_queries_are_presence_only() -> None:
    """The two presence queries are the only ones that are."""
    presence = [
        query.id
        for query in queryset.load().queries
        if query.presence_only
    ]

    assert presence == ["pw_attr_presence", "keycred_presence"]


def test_the_presence_queries_ask_for_the_sid_and_the_name_only() -> None:
    """A presence query requests distinguishedName and objectSid only."""
    for query in queryset.load().queries:
        if query.presence_only:
            assert set(query.attrs) == {"objectSid", "distinguishedName"}


def test_the_allowed_attributes_are_the_ones_of_the_table() -> None:
    """The allowlist is every attribute the set asks for."""
    allowed = queryset.load().allowed_attrs

    for name in (
        "objectSid",
        "userAccountControl",
        "member",
        "servicePrincipalName",
    ):
        assert name in allowed
    # The descriptor is asked for by the sd flag, not by name.
    assert "nTSecurityDescriptor" not in allowed
    # A forbidden name is never requested, not even in a presence query.
    assert "msDS-KeyCredentialLink" not in allowed


def test_the_forbidden_names_are_not_requested_anywhere() -> None:
    """The shipped set never asks for a forbidden attribute."""
    allowed = {name.lower() for name in queryset.load().allowed_attrs}

    for name in forbidden.FORBIDDEN_ATTRIBUTES:
        assert name not in allowed


def test_the_filter_of_the_schema_query_names_a_laps_value() -> None:
    """A forbidden name on the right of a term is fine."""
    query = queryset.load().by_id("schema_laps")

    assert "ms-Mcs-AdmPwd" in query.filter
    assert "lDAPDisplayName" in queryset.filter_attributes(query.filter)


@pytest.mark.parametrize("name", sorted(forbidden.FORBIDDEN_ATTRIBUTES))
def test_a_forbidden_attribute_in_the_attrs_is_refused(
    tmp_path: Path,
    name: str,
) -> None:
    """A generated test per forbidden name: the attrs are refused."""
    payload = docs.minimal_query_set()
    payload["queries"][0]["attrs"].append(name)

    with pytest.raises(queryset.QuerySetError) as caught:
        queryset.load(write_query_set(tmp_path, payload))

    assert "forbidden" in str(caught.value)


@pytest.mark.parametrize("name", sorted(forbidden.FORBIDDEN_ATTRIBUTES))
def test_a_forbidden_attribute_in_a_filter_is_refused(
    tmp_path: Path,
    name: str,
) -> None:
    """A generated test per forbidden name: the filter is refused."""
    payload = docs.minimal_query_set()
    payload["queries"][0]["filter"] = f"({name}=*)"

    with pytest.raises(queryset.QuerySetError) as caught:
        queryset.load(write_query_set(tmp_path, payload))

    assert "forbidden" in str(caught.value)


@pytest.mark.parametrize("name", sorted(forbidden.FORBIDDEN_ATTRIBUTES))
def test_a_presence_query_may_name_a_forbidden_attribute(
    tmp_path: Path,
    name: str,
) -> None:
    """The presence-only exception: the attribute side may be forbidden."""
    payload = docs.minimal_query_set()
    payload["queries"][0]["filter"] = f"({name}=*)"
    payload["queries"][0]["presence_only"] = True

    loaded = queryset.load(write_query_set(tmp_path, payload))

    assert loaded.ids == ("users",)


def test_a_filter_that_is_not_balanced_is_refused(tmp_path: Path) -> None:
    """A filter with an open parenthesis is refused."""
    payload = docs.minimal_query_set()
    payload["queries"][0]["filter"] = "(&(objectClass=user)"

    with pytest.raises(queryset.QuerySetError) as caught:
        queryset.load(write_query_set(tmp_path, payload))

    assert "balanced" in str(caught.value)


def test_a_filter_that_uses_an_extensible_match_is_refused(
    tmp_path: Path,
) -> None:
    """The ":=" shape is refused: it is the oracle shape."""
    payload = docs.minimal_query_set()
    payload["queries"][0]["filter"] = "(memberOf:1.2.840.113556.1.4.1941:=x)"

    with pytest.raises(queryset.QuerySetError) as caught:
        queryset.load(write_query_set(tmp_path, payload))

    assert "extensible" in str(caught.value)


def test_a_limit_over_fifty_thousand_is_refused(tmp_path: Path) -> None:
    """The limit is a hard cap."""
    payload = docs.minimal_query_set()
    payload["queries"][0]["limit"] = 50001

    with pytest.raises(queryset.QuerySetError) as caught:
        queryset.load(write_query_set(tmp_path, payload))

    assert "limit" in str(caught.value)


def test_two_queries_with_the_same_id_are_refused(tmp_path: Path) -> None:
    """The ids are unique."""
    payload = docs.minimal_query_set()
    payload["queries"].append(dict(payload["queries"][0]))

    with pytest.raises(queryset.QuerySetError) as caught:
        queryset.load(write_query_set(tmp_path, payload))

    assert "unique" in str(caught.value)


def test_the_star_attribute_is_refused(tmp_path: Path) -> None:
    """No query may ask for every attribute."""
    payload = docs.minimal_query_set()
    payload["queries"][0]["attrs"].append("*")

    with pytest.raises(queryset.QuerySetError) as caught:
        queryset.load(write_query_set(tmp_path, payload))

    assert "attribute name" in str(caught.value)


def test_an_attribute_name_that_is_not_a_name_is_refused(tmp_path: Path) -> None:
    """An attribute name is a name and nothing else."""
    payload = docs.minimal_query_set()
    payload["queries"][0]["attrs"].append("object Sid")

    with pytest.raises(queryset.QuerySetError) as caught:
        queryset.load(write_query_set(tmp_path, payload))

    assert "attribute name" in str(caught.value)


def test_a_base_that_is_not_a_naming_context_is_refused(tmp_path: Path) -> None:
    """A base is a placeholder or a DN that ends in one."""
    payload = docs.minimal_query_set()
    payload["queries"][0]["base"] = "DC=elsewhere"

    with pytest.raises(queryset.QuerySetError) as caught:
        queryset.load(write_query_set(tmp_path, payload))

    assert "naming context" in str(caught.value)


def test_a_scope_that_is_not_base_or_sub_is_refused(tmp_path: Path) -> None:
    """The scope is base or sub."""
    payload = docs.minimal_query_set()
    payload["queries"][0]["scope"] = "one"

    with pytest.raises(queryset.QuerySetError) as caught:
        queryset.load(write_query_set(tmp_path, payload))

    assert "scope" in str(caught.value)


def test_a_query_set_that_is_not_json_is_refused(tmp_path: Path) -> None:
    """A file that is not JSON is refused."""
    target = tmp_path / "queries.json"
    target.write_text("not json", encoding="utf-8")

    with pytest.raises(queryset.QuerySetError) as caught:
        queryset.load(target)

    assert "not JSON" in str(caught.value)


def test_the_error_message_never_carries_the_text_of_the_file(
    tmp_path: Path,
) -> None:
    """A hostile file does not get its text into the message."""
    payload = docs.minimal_query_set()
    payload["queries"][0]["attrs"].append("secret value")

    with pytest.raises(queryset.QuerySetError) as caught:
        queryset.load(write_query_set(tmp_path, payload))

    assert "secret value" not in str(caught.value)


def test_the_filter_tokenizer_finds_every_attribute() -> None:
    """The tokenizer reads the left side of every comparison term."""
    names = queryset.filter_attributes(
        "(|(lDAPDisplayName=ms-Mcs-AdmPwd)(adminCount>=1)(member<=x))"
    )

    assert names == {"lDAPDisplayName", "adminCount", "member"}


def test_the_filter_tokenizer_refuses_an_extensible_match() -> None:
    """The ":=" shape never reaches the tokenizer's result."""
    with pytest.raises(queryset.QuerySetError):
        queryset.filter_attributes("(member:1.2.3:=x)")


def test_the_tokenizer_strips_the_options_of_an_attribute() -> None:
    """The options of a name never hide the name itself."""
    assert queryset.filter_attributes("(unicodePwd;binary=*)") == {"unicodePwd"}
    assert queryset.filter_attributes("(objectClass;lang-en=*)") == {
        "objectClass"
    }


def test_a_forbidden_attribute_with_options_is_refused(
    tmp_path: Path,
) -> None:
    """The options do not hide a forbidden name in a filter."""
    payload = docs.minimal_query_set()
    payload["queries"][0]["filter"] = "(unicodePwd;binary=*)"

    with pytest.raises(queryset.QuerySetError) as caught:
        queryset.load(write_query_set(tmp_path, payload))

    assert "forbidden" in str(caught.value)


def test_a_presence_only_query_may_only_test_the_presence(
    tmp_path: Path,
) -> None:
    """A presence-only query tests presence, never a value."""
    payload = docs.minimal_query_set()
    payload["queries"][0]["filter"] = "(userPassword=x)"
    payload["queries"][0]["presence_only"] = True

    with pytest.raises(queryset.QuerySetError) as caught:
        queryset.load(write_query_set(tmp_path, payload))

    assert "presence" in str(caught.value)


def test_a_presence_only_query_may_not_use_another_operator(
    tmp_path: Path,
) -> None:
    """A presence-only query may not compare a forbidden name either."""
    payload = docs.minimal_query_set()
    payload["queries"][0]["filter"] = "(userPassword>=1)"
    payload["queries"][0]["presence_only"] = True

    with pytest.raises(queryset.QuerySetError) as caught:
        queryset.load(write_query_set(tmp_path, payload))

    assert "presence" in str(caught.value)


def test_a_presence_only_query_may_test_the_presence(
    tmp_path: Path,
) -> None:
    """The presence term itself is still accepted."""
    payload = docs.minimal_query_set()
    payload["queries"][0]["filter"] = "(userPassword=*)"
    payload["queries"][0]["presence_only"] = True

    loaded = queryset.load(write_query_set(tmp_path, payload))

    assert loaded.ids == ("users",)
