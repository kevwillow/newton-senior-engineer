"""The collector document contract: one test per malformed shape."""

from __future__ import annotations

import json
from typing import Any

import pytest

from newton_mcp.ad import queryset, wire

import docs


def encode(document: dict[str, Any]) -> bytes:
    """The bytes a collector prints."""
    return json.dumps(document).encode("utf-8")


@pytest.fixture
def loaded() -> queryset.QuerySet:
    return queryset.load()


def parse(document: dict[str, Any], loaded: queryset.QuerySet) -> wire.Document:
    return wire.parse(encode(document), loaded)


def test_a_well_formed_document_parses(loaded: queryset.QuerySet) -> None:
    """The shape of section 5 is accepted."""
    document = parse(docs.minimal_document(), loaded)

    assert document.v == 1
    assert document.collector == "windows"
    assert document.identity.sid == docs.AUDIT_SID
    assert set(document.queries) == set(loaded.ids)


def test_the_samba_collector_is_known(loaded: queryset.QuerySet) -> None:
    """Both collectors are accepted."""
    document = parse(docs.minimal_document(collector="samba"), loaded)

    assert document.collector == "samba"


def test_a_document_that_is_not_json_is_refused(loaded: queryset.QuerySet) -> None:
    """Bytes that are not JSON never reach the audit."""
    with pytest.raises(wire.WireError) as caught:
        wire.parse(b"not json", loaded)

    assert "not JSON" in str(caught.value)


def test_a_document_that_is_not_an_object_is_refused(
    loaded: queryset.QuerySet,
) -> None:
    """A JSON array is not a document."""
    with pytest.raises(wire.WireError) as caught:
        wire.parse(b"[]", loaded)

    assert "not an object" in str(caught.value)


def test_a_document_over_the_cap_is_refused(
    loaded: queryset.QuerySet,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A document over 64 MiB is refused."""
    assert wire.MAX_DOCUMENT_BYTES == 64 * 1024 * 1024
    monkeypatch.setattr(wire, "MAX_DOCUMENT_BYTES", 16)

    with pytest.raises(wire.WireError) as caught:
        wire.parse(encode(docs.minimal_document()), loaded)

    assert "too large" in str(caught.value)


def test_a_document_with_the_wrong_version_is_refused(
    loaded: queryset.QuerySet,
) -> None:
    """Only version 1 is understood."""
    with pytest.raises(wire.WireError) as caught:
        parse(docs.minimal_document(v=2), loaded)

    assert "version" in str(caught.value)


def test_an_unknown_collector_is_refused(loaded: queryset.QuerySet) -> None:
    """Newton knows two collectors."""
    with pytest.raises(wire.WireError) as caught:
        parse(docs.minimal_document(collector="freebsd"), loaded)

    assert "collector name" in str(caught.value)


def test_a_collector_that_is_not_text_is_refused(
    loaded: queryset.QuerySet,
) -> None:
    """The collector name is text."""
    with pytest.raises(wire.WireError) as caught:
        parse(docs.minimal_document(collector=7), loaded)

    assert "not text" in str(caught.value)


def test_a_collector_version_that_is_not_text_is_refused(
    loaded: queryset.QuerySet,
) -> None:
    """The collector version is text."""
    with pytest.raises(wire.WireError) as caught:
        parse(docs.minimal_document(collector_version=None), loaded)

    assert "not text" in str(caught.value)


def test_a_query_set_hash_that_is_not_text_is_refused(
    loaded: queryset.QuerySet,
) -> None:
    """The hash is text."""
    with pytest.raises(wire.WireError) as caught:
        parse(docs.minimal_document(querysetsha=12), loaded)

    assert "not text" in str(caught.value)


def test_a_document_of_another_query_set_is_refused(
    loaded: queryset.QuerySet,
) -> None:
    """A collector that ran another file is out of date."""
    with pytest.raises(wire.WireError) as caught:
        parse(docs.minimal_document(querysetsha="0" * 64), loaded)

    assert str(caught.value) == "collector out of date: rerun the setup"


def test_is_dc_that_is_not_a_boolean_is_refused(
    loaded: queryset.QuerySet,
) -> None:
    """is_dc is a boolean."""
    with pytest.raises(wire.WireError) as caught:
        parse(docs.minimal_document(is_dc="yes"), loaded)

    assert "is_dc" in str(caught.value)


def test_a_missing_domain_block_is_refused(loaded: queryset.QuerySet) -> None:
    """The domain block is part of the contract."""
    document = docs.minimal_document()
    del document["domain"]

    with pytest.raises(wire.WireError) as caught:
        parse(document, loaded)

    assert "domain block" in str(caught.value)


def test_a_missing_domain_field_is_refused(loaded: queryset.QuerySet) -> None:
    """Every domain field is part of the contract."""
    document = docs.minimal_document()
    del document["domain"]["config_dn"]

    with pytest.raises(wire.WireError) as caught:
        parse(document, loaded)

    assert "domain field" in str(caught.value)


def test_a_domain_sid_that_is_not_a_sid_is_refused(
    loaded: queryset.QuerySet,
) -> None:
    """The domain sid is a SID."""
    document = docs.minimal_document()
    document["domain"]["domain_sid"] = "not-a-sid"

    with pytest.raises(wire.WireError) as caught:
        parse(document, loaded)

    assert "domain sid" in str(caught.value)


def test_a_missing_identity_block_is_refused(
    loaded: queryset.QuerySet,
) -> None:
    """The identity block is part of the contract."""
    document = docs.minimal_document()
    del document["identity"]

    with pytest.raises(wire.WireError) as caught:
        parse(document, loaded)

    assert "identity block" in str(caught.value)


def test_a_missing_identity_sid_is_refused(loaded: queryset.QuerySet) -> None:
    """The identity sid is part of the contract."""
    document = docs.minimal_document()
    del document["identity"]["sid"]

    with pytest.raises(wire.WireError) as caught:
        parse(document, loaded)

    assert "identity sid" in str(caught.value)


def test_an_identity_sid_that_is_not_a_sid_is_refused(
    loaded: queryset.QuerySet,
) -> None:
    """The identity sid is a SID."""
    document = docs.minimal_document()
    document["identity"]["sid"] = "S-1-5-21-not"

    with pytest.raises(wire.WireError) as caught:
        parse(document, loaded)

    assert "identity sid" in str(caught.value)


def test_empty_token_group_sids_are_refused(loaded: queryset.QuerySet) -> None:
    """The token groups are never empty."""
    document = docs.minimal_document()
    document["identity"]["token_group_sids"] = []

    with pytest.raises(wire.WireError) as caught:
        parse(document, loaded)

    assert "empty" in str(caught.value)


def test_a_token_group_sid_that_is_not_a_sid_is_refused(
    loaded: queryset.QuerySet,
) -> None:
    """Every token group is a SID."""
    document = docs.minimal_document()
    document["identity"]["token_group_sids"] = ["S-1-5-21-1", "nonsense"]

    with pytest.raises(wire.WireError) as caught:
        parse(document, loaded)

    assert "token group sid" in str(caught.value)


def test_a_started_that_is_not_text_is_refused(
    loaded: queryset.QuerySet,
) -> None:
    """The start time is text."""
    with pytest.raises(wire.WireError) as caught:
        parse(docs.minimal_document(started=42), loaded)

    assert "started" in str(caught.value)


def test_an_elapsed_time_that_is_not_a_number_is_refused(
    loaded: queryset.QuerySet,
) -> None:
    """The elapsed time is a number."""
    with pytest.raises(wire.WireError) as caught:
        parse(docs.minimal_document(elapsed_ms="812"), loaded)

    assert "elapsed_ms" in str(caught.value)


def test_a_missing_queries_block_is_refused(loaded: queryset.QuerySet) -> None:
    """The queries block is part of the contract."""
    document = docs.minimal_document()
    del document["queries"]

    with pytest.raises(wire.WireError) as caught:
        parse(document, loaded)

    assert "queries block" in str(caught.value)


def test_an_extra_query_id_is_refused(loaded: queryset.QuerySet) -> None:
    """The query ids are the ids of the set, exactly."""
    document = docs.minimal_document()
    document["queries"]["extra"] = docs.query_block()

    with pytest.raises(wire.WireError) as caught:
        parse(document, loaded)

    assert "query ids" in str(caught.value)


def test_a_missing_query_id_is_refused(loaded: queryset.QuerySet) -> None:
    """A query of the set that is not in the document is refused."""
    document = docs.minimal_document()
    del document["queries"]["users"]

    with pytest.raises(wire.WireError) as caught:
        parse(document, loaded)

    assert "query ids" in str(caught.value)


def test_an_unknown_status_is_refused(loaded: queryset.QuerySet) -> None:
    """Only the documented statuses are statuses."""
    document = docs.minimal_document()
    document["queries"]["users"]["status"] = "fine"

    with pytest.raises(wire.WireError) as caught:
        parse(document, loaded)

    assert "status is not known" in str(caught.value)


def test_an_unknown_error_code_is_refused(loaded: queryset.QuerySet) -> None:
    """Only the documented error codes are error codes."""
    document = docs.minimal_document()
    document["queries"]["users"]["status"] = "denied"
    document["queries"]["users"]["error_code"] = "who_knows"

    with pytest.raises(wire.WireError) as caught:
        parse(document, loaded)

    assert "error code is not known" in str(caught.value)


def test_an_error_code_on_an_ok_status_is_refused(
    loaded: queryset.QuerySet,
) -> None:
    """The error code is empty when the status is ok."""
    document = docs.minimal_document()
    document["queries"]["users"]["error_code"] = "other"

    with pytest.raises(wire.WireError) as caught:
        parse(document, loaded)

    assert "ok status" in str(caught.value)


def test_a_status_without_an_error_code_is_refused(
    loaded: queryset.QuerySet,
) -> None:
    """A status that is not ok carries an error code."""
    document = docs.minimal_document()
    document["queries"]["users"]["status"] = "truncated"

    with pytest.raises(wire.WireError) as caught:
        parse(document, loaded)

    assert "carries no error code" in str(caught.value)


def test_rows_that_are_not_a_list_are_refused(loaded: queryset.QuerySet) -> None:
    """The rows are a list."""
    document = docs.minimal_document()
    document["queries"]["users"]["rows"] = {}

    with pytest.raises(wire.WireError) as caught:
        parse(document, loaded)

    assert "rows are not a list" in str(caught.value)


def test_a_row_that_is_not_an_object_is_refused(
    loaded: queryset.QuerySet,
) -> None:
    """A row is an object."""
    document = docs.minimal_document()
    document["queries"]["users"]["rows"] = ["CN=User"]

    with pytest.raises(wire.WireError) as caught:
        parse(document, loaded)

    assert "row is not an object" in str(caught.value)


def test_a_row_without_a_distinguished_name_is_refused(
    loaded: queryset.QuerySet,
) -> None:
    """A row carries its distinguished name."""
    document = docs.minimal_document()
    document["queries"]["users"]["rows"] = [{"a": {}}]

    with pytest.raises(wire.WireError) as caught:
        parse(document, loaded)

    assert "distinguished name" in str(caught.value)


def test_attributes_that_are_not_an_object_are_refused(
    loaded: queryset.QuerySet,
) -> None:
    """The attributes of a row are an object."""
    document = docs.minimal_document()
    document["queries"]["users"]["rows"] = [{"dn": "CN=User", "a": []}]

    with pytest.raises(wire.WireError) as caught:
        parse(document, loaded)

    assert "attributes of a row" in str(caught.value)


def test_an_attribute_value_that_is_not_a_list_is_refused(
    loaded: queryset.QuerySet,
) -> None:
    """An attribute holds a list of values."""
    document = docs.minimal_document()
    document["queries"]["users"]["rows"] = [
        {"dn": "CN=User", "a": {"objectSid": "abc"}}
    ]

    with pytest.raises(wire.WireError) as caught:
        parse(document, loaded)

    assert "not a list" in str(caught.value)


def test_an_attribute_value_that_is_not_text_is_refused(
    loaded: queryset.QuerySet,
) -> None:
    """Every value is a string."""
    document = docs.minimal_document()
    document["queries"]["users"]["rows"] = [
        {"dn": "CN=User", "a": {"objectSid": [42]}}
    ]

    with pytest.raises(wire.WireError) as caught:
        parse(document, loaded)

    assert "not text" in str(caught.value)


def test_an_attribute_value_over_the_cap_is_refused(
    loaded: queryset.QuerySet,
) -> None:
    """A value is at most 64 KiB."""
    document = docs.minimal_document()
    document["queries"]["users"]["rows"] = [
        {"dn": "CN=User", "a": {"sAMAccountName": ["x" * (64 * 1024 + 1)]}}
    ]

    with pytest.raises(wire.WireError) as caught:
        parse(document, loaded)

    assert "too long" in str(caught.value)


def test_a_forbidden_attribute_name_is_refused(loaded: queryset.QuerySet) -> None:
    """No forbidden name may be anywhere in the attributes."""
    document = docs.minimal_document()
    document["queries"]["users"]["rows"] = [
        {"dn": "CN=User", "a": {"userPassword": ["hash"]}}
    ]

    with pytest.raises(wire.WireError) as caught:
        parse(document, loaded)

    assert "forbidden attribute name" in str(caught.value)


def test_a_forbidden_attribute_name_with_options_is_refused(
    loaded: queryset.QuerySet,
) -> None:
    """The options of a name do not hide it."""
    document = docs.minimal_document()
    document["queries"]["users"]["rows"] = [
        {"dn": "CN=User", "a": {"unicodePwd;binary": ["hash"]}}
    ]

    with pytest.raises(wire.WireError) as caught:
        parse(document, loaded)

    assert "forbidden attribute name" in str(caught.value)


def test_a_nul_in_a_string_is_refused(loaded: queryset.QuerySet) -> None:
    """No string of the document holds a NUL."""
    document = docs.minimal_document()
    document["queries"]["users"]["rows"] = [
        {"dn": "CN=User\x00name", "a": {}}
    ]

    with pytest.raises(wire.WireError) as caught:
        parse(document, loaded)

    assert "NUL" in str(caught.value)


def test_a_nul_in_an_attribute_value_is_refused(
    loaded: queryset.QuerySet,
) -> None:
    """No value of the document holds a NUL."""
    document = docs.minimal_document()
    document["queries"]["users"]["rows"] = [
        {"dn": "CN=User", "a": {"sAMAccountName": ["user\x00"]}}
    ]

    with pytest.raises(wire.WireError) as caught:
        parse(document, loaded)

    assert "NUL" in str(caught.value)


def test_a_missing_files_block_is_refused(loaded: queryset.QuerySet) -> None:
    """The files block is part of the contract."""
    document = docs.minimal_document()
    del document["files"]

    with pytest.raises(wire.WireError) as caught:
        parse(document, loaded)

    assert "files block" in str(caught.value)


def test_a_missing_file_section_is_refused(loaded: queryset.QuerySet) -> None:
    """Both file sections are part of the contract."""
    document = docs.minimal_document()
    del document["files"]["gpp"]

    with pytest.raises(wire.WireError) as caught:
        parse(document, loaded)

    assert "file section" in str(caught.value)


def test_a_gpo_name_that_is_not_a_guid_is_refused(
    loaded: queryset.QuerySet,
) -> None:
    """A GPO folder that is not a GUID is never in the document."""
    document = docs.minimal_document()
    document["files"]["gpp"]["items"] = [
        {
            "gpo": "{not-a-guid}",
            "path": "Machine/Preferences/Groups/Groups.xml",
            "kind": "cpassword",
            "count": 1,
        }
    ]

    with pytest.raises(wire.WireError) as caught:
        parse(document, loaded)

    assert "gpo name is not a guid" in str(caught.value)


def test_a_gpo_name_with_a_shell_word_is_refused(
    loaded: queryset.QuerySet,
) -> None:
    """A folder name that carries a metacharacter is not a GUID."""
    document = docs.minimal_document()
    document["files"]["gpp"]["items"] = [
        {
            "gpo": "{31B2F340-016D-11D2-945F-00C04FB984F9}; rm -rf /",
            "path": "Machine/Preferences/Groups/Groups.xml",
            "kind": "cpassword",
            "count": 1,
        }
    ]

    with pytest.raises(wire.WireError) as caught:
        parse(document, loaded)

    assert "gpo name is not a guid" in str(caught.value)


def test_a_file_kind_that_is_not_known_is_refused(
    loaded: queryset.QuerySet,
) -> None:
    """A file item is a cpassword or an autologon."""
    document = docs.minimal_document()
    document["files"]["gpp"]["items"] = [
        {
            "gpo": "{31B2F340-016D-11D2-945F-00C04FB984F9}",
            "path": "Machine/Preferences/Groups/Groups.xml",
            "kind": "script",
            "count": 1,
        }
    ]

    with pytest.raises(wire.WireError) as caught:
        parse(document, loaded)

    assert "file kind" in str(caught.value)


def test_a_file_count_that_is_not_a_number_is_refused(
    loaded: queryset.QuerySet,
) -> None:
    """The count of a file item is a number."""
    document = docs.minimal_document()
    document["files"]["gpp"]["items"] = [
        {
            "gpo": "{31B2F340-016D-11D2-945F-00C04FB984F9}",
            "path": "Machine/Preferences/Groups/Groups.xml",
            "kind": "cpassword",
            "count": "one",
        }
    ]

    with pytest.raises(wire.WireError) as caught:
        parse(document, loaded)

    assert "count" in str(caught.value)


def test_a_file_section_carries_the_counts_of_the_refused_files(
    loaded: queryset.QuerySet,
) -> None:
    """The counts of the files that were refused are part of the contract.

    A check that reads a file section has to know that the collector
    refused a file or skipped a special one: a section that refused
    files cannot prove that there is nothing in them.
    """
    document = docs.minimal_document()
    document["files"]["gpp"]["parse_refused"] = 2
    document["files"]["gpp"]["skipped_special"] = 3
    document["files"]["gpttmpl"]["parse_refused"] = 1

    parsed = parse(document, loaded)

    assert parsed.files["gpp"].parse_refused == 2
    assert parsed.files["gpp"].skipped_special == 3
    assert parsed.files["gpttmpl"].parse_refused == 1
    assert parsed.files["gpttmpl"].skipped_special == 0


def test_a_file_section_without_the_counts_is_accepted(
    loaded: queryset.QuerySet,
) -> None:
    """The Windows document carries no such count and still parses.

    The counts are optional and default to zero, so a document of the
    Windows collector keeps the meaning it had.
    """
    parsed = parse(docs.minimal_document(), loaded)

    assert parsed.files["gpp"].parse_refused == 0
    assert parsed.files["gpp"].skipped_special == 0
    assert parsed.files["gpttmpl"].parse_refused == 0
    assert parsed.files["gpttmpl"].skipped_special == 0


@pytest.mark.parametrize("count", (-1, "one", 1.5, True, None))
def test_a_count_of_refused_files_that_is_not_a_number_is_refused(
    loaded: queryset.QuerySet, count: object
) -> None:
    """A count of refused files is a number of files."""
    document = docs.minimal_document()
    document["files"]["gpp"]["parse_refused"] = count

    with pytest.raises(wire.WireError) as caught:
        parse(document, loaded)

    assert "count" in str(caught.value)


def test_a_missing_settings_block_is_refused(loaded: queryset.QuerySet) -> None:
    """The settings block is part of the contract."""
    document = docs.minimal_document()
    del document["settings"]

    with pytest.raises(wire.WireError) as caught:
        parse(document, loaded)

    assert "settings block" in str(caught.value)


def test_a_settings_item_that_is_not_an_object_is_refused(
    loaded: queryset.QuerySet,
) -> None:
    """A settings item is an object."""
    document = docs.minimal_document()
    document["settings"]["items"] = ["HKLM\\SYSTEM"]

    with pytest.raises(wire.WireError) as caught:
        parse(document, loaded)

    assert "settings item" in str(caught.value)


def test_a_settings_item_with_an_unknown_status_is_refused(
    loaded: queryset.QuerySet,
) -> None:
    """A settings item carries a status of the table."""
    document = docs.minimal_document()
    document["settings"]["items"] = [
        {
            "source": "registry",
            "key": "HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters",
            "status": "fine",
            "value": "1",
        }
    ]

    with pytest.raises(wire.WireError) as caught:
        parse(document, loaded)

    assert "status is not known" in str(caught.value)


def test_a_settings_item_with_a_status_is_accepted(
    loaded: queryset.QuerySet,
) -> None:
    """The item-level status replaces the in-band sentinel value."""
    document = docs.minimal_document()
    document["settings"]["items"][0]["status"] = "unavailable"
    document["settings"]["items"][1]["status"] = "ok"
    document["settings"]["items"][1]["value"] = "2"

    parsed = parse(document, loaded)

    assert parsed.settings.items[0].status == "unavailable"
    assert parsed.settings.items[1].status == "ok"


def test_the_error_message_never_carries_the_text_of_the_document(
    loaded: queryset.QuerySet,
) -> None:
    """A hostile document does not get its text into the message."""
    document = docs.minimal_document()
    document["queries"]["users"]["rows"] = [
        {"dn": "CN=secret value", "a": {"userPassword": ["hash"]}}
    ]

    with pytest.raises(wire.WireError) as caught:
        parse(document, loaded)

    assert "secret value" not in str(caught.value)


def principal(dn: str, sid: str, **attrs: object) -> dict[str, Any]:
    """One principal row, with its SID."""
    values: dict[str, object] = {"objectSid": docs.sid_blob(sid)}
    values.update(attrs)
    return docs.row(dn, **values)


def test_a_domain_sid_that_is_not_the_domain_heads_sid_is_refused(
    loaded: queryset.QuerySet,
) -> None:
    """The domain sid is the SID of the domain head."""
    document = docs.minimal_document()
    document["queries"]["domain_head"]["rows"] = [
        principal(docs.DOMAIN_DN, docs.DOMAIN_SID)
    ]
    document["domain"]["domain_sid"] = "S-1-5-21-1-2-3"
    # The identity is of the domain the document claims, so the only
    # thing that is wrong is the domain head.
    document["identity"]["sid"] = "S-1-5-21-1-2-3-1105"

    with pytest.raises(wire.WireError) as caught:
        parse(document, loaded)

    assert "domain sid" in str(caught.value)


def test_an_identity_of_another_domain_is_refused(
    loaded: queryset.QuerySet,
) -> None:
    """The audit account is an account of the domain it audited."""
    document = docs.minimal_document()
    document["queries"]["domain_head"]["rows"] = [
        principal(docs.DOMAIN_DN, docs.DOMAIN_SID)
    ]
    document["identity"]["sid"] = "S-1-5-21-9-9-9-9-1105"

    with pytest.raises(wire.WireError) as caught:
        parse(document, loaded)

    assert "identity sid" in str(caught.value)


def test_the_domain_sid_of_the_domain_head_is_accepted(
    loaded: queryset.QuerySet,
) -> None:
    """The domain sid that matches the domain head is accepted."""
    document = docs.minimal_document()
    document["queries"]["domain_head"]["rows"] = [
        principal(docs.DOMAIN_DN, docs.DOMAIN_SID)
    ]

    parsed = parse(document, loaded)

    assert parsed.domain.domain_sid == docs.DOMAIN_SID


def test_an_attribute_the_query_does_not_ask_for_is_refused(
    loaded: queryset.QuerySet,
) -> None:
    """A row may only carry the attributes of its query."""
    document = docs.minimal_document()
    document["queries"]["users"]["rows"] = [
        principal("CN=User", docs.AUDIT_SID, description="not asked for")
    ]

    with pytest.raises(wire.WireError) as caught:
        parse(document, loaded)

    assert "not requested" in str(caught.value)


def test_an_attribute_is_stored_under_the_canonical_spelling(
    loaded: queryset.QuerySet,
) -> None:
    """A name that differs only in case is the canonical name."""
    document = docs.minimal_document()
    document["queries"]["users"]["rows"] = [
        {
            "dn": f"CN=User,{docs.DOMAIN_DN}",
            "a": {"objectsid": [docs.sid_blob(docs.AUDIT_SID)]},
        }
    ]

    parsed = parse(document, loaded)

    row = parsed.queries["users"].rows[0]
    assert "objectSid" in row.a
    assert "objectsid" not in row.a


def test_a_ranged_attribute_key_is_refused(
    loaded: queryset.QuerySet,
) -> None:
    """The collector merges the ranges before it emits them."""
    document = docs.minimal_document()
    document["queries"]["groups"]["rows"] = [
        {
            "dn": "CN=Group",
            "a": {
                "objectSid": [docs.sid_blob(docs.DOMAIN_ADMINS_SID)],
                "member;range=0-1499": ["CN=User"],
            },
        }
    ]

    with pytest.raises(wire.WireError) as caught:
        parse(document, loaded)

    assert "range" in str(caught.value)


def test_a_user_row_without_an_object_sid_is_refused(
    loaded: queryset.QuerySet,
) -> None:
    """Every user carries its SID."""
    document = docs.minimal_document()
    document["queries"]["users"]["rows"] = [
        docs.row("CN=User", sAMAccountName="svc")
    ]

    with pytest.raises(wire.WireError) as caught:
        parse(document, loaded)

    assert "objectSid" in str(caught.value)


def test_a_group_row_without_an_object_sid_is_refused(
    loaded: queryset.QuerySet,
) -> None:
    """Every group carries its SID."""
    document = docs.minimal_document()
    document["queries"]["groups"]["rows"] = [docs.row("CN=Group")]

    with pytest.raises(wire.WireError) as caught:
        parse(document, loaded)

    assert "objectSid" in str(caught.value)


def test_two_principals_with_the_same_sid_are_refused(
    loaded: queryset.QuerySet,
) -> None:
    """Two principals may not have the same SID."""
    document = docs.minimal_document()
    document["queries"]["users"]["rows"] = [
        principal(f"CN=One,{docs.DOMAIN_DN}", docs.AUDIT_SID),
        principal(f"CN=Two,{docs.DOMAIN_DN}", docs.AUDIT_SID),
    ]

    with pytest.raises(wire.WireError) as caught:
        parse(document, loaded)

    assert "same sid" in str(caught.value)


def test_two_principals_with_the_same_name_are_refused(
    loaded: queryset.QuerySet,
) -> None:
    """Two principals may not have the same name."""
    document = docs.minimal_document()
    document["queries"]["users"]["rows"] = [
        principal(f"CN=User,{docs.DOMAIN_DN}", docs.AUDIT_SID),
        principal(f"cn=user,{docs.DOMAIN_DN}", f"{docs.DOMAIN_SID}-1106"),
    ]

    with pytest.raises(wire.WireError) as caught:
        parse(document, loaded)

    assert "same distinguished name" in str(caught.value)


def test_the_same_principal_in_two_queries_is_refused(
    loaded: queryset.QuerySet,
) -> None:
    """A principal that is in two queries is a duplicate."""
    document = docs.minimal_document()
    document["queries"]["users"]["rows"] = [
        principal(f"CN=User,{docs.DOMAIN_DN}", docs.AUDIT_SID)
    ]
    document["queries"]["groups"]["rows"] = [
        principal(f"CN=Group,{docs.DOMAIN_DN}", docs.AUDIT_SID)
    ]

    with pytest.raises(wire.WireError) as caught:
        parse(document, loaded)

    assert "same sid" in str(caught.value)


def test_the_same_object_in_protected_sds_is_not_a_duplicate(
    loaded: queryset.QuerySet,
) -> None:
    """The protected sds query holds objects the other queries hold too."""
    document = docs.minimal_document()
    document["queries"]["users"]["rows"] = [
        principal(f"CN=User,{docs.DOMAIN_DN}", docs.AUDIT_SID)
    ]
    document["queries"]["protected_sds"]["rows"] = [
        principal(f"CN=User,{docs.DOMAIN_DN}", docs.AUDIT_SID, objectClass=["user"])
    ]

    parsed = parse(document, loaded)

    assert len(parsed.queries["protected_sds"].rows) == 1


def test_a_document_that_is_too_deep_is_refused(
    loaded: queryset.QuerySet,
) -> None:
    """A document that cannot be parsed is refused, never a crash."""
    with pytest.raises(wire.WireError):
        wire.parse(b"[" * 100000, loaded)


def test_too_many_rows_are_refused(
    loaded: queryset.QuerySet,
) -> None:
    """A query may not hold more rows than its limit."""
    document = docs.minimal_document()
    document["queries"]["domain_head"]["rows"] = [
        principal("CN=One", docs.DOMAIN_SID),
        principal("CN=Two", f"{docs.DOMAIN_SID}-1106"),
    ]

    with pytest.raises(wire.WireError) as caught:
        parse(document, loaded)

    assert "rows" in str(caught.value)


def test_too_many_values_of_one_attribute_are_refused(
    loaded: queryset.QuerySet,
) -> None:
    """One attribute may not hold more than five thousand values."""
    document = docs.minimal_document()
    document["queries"]["users"]["rows"] = [
        principal(
            "CN=User",
            docs.AUDIT_SID,
            sAMAccountName=["svc"] * (wire.MAX_VALUES_PER_ATTRIBUTE + 1),
        )
    ]

    with pytest.raises(wire.WireError) as caught:
        parse(document, loaded)

    assert "values" in str(caught.value)


def test_the_member_attribute_holds_more_values(
    loaded: queryset.QuerySet,
) -> None:
    """The member of a big group holds more values than the rest."""
    assert wire.MAX_VALUES_PER_MEMBER > wire.MAX_VALUES_PER_ATTRIBUTE
    document = docs.minimal_document()
    document["queries"]["groups"]["rows"] = [
        principal(
            f"CN=Group,{docs.DOMAIN_DN}",
            docs.DOMAIN_ADMINS_SID,
            member=["CN=User"] * (wire.MAX_VALUES_PER_ATTRIBUTE + 1),
        )
    ]

    parsed = parse(document, loaded)

    assert len(parsed.queries["groups"].rows[0].a["member"]) == (
        wire.MAX_VALUES_PER_ATTRIBUTE + 1
    )


def test_too_many_attributes_in_one_row_are_refused(
    loaded: queryset.QuerySet,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One row may not hold more attributes than the cap."""
    monkeypatch.setattr(wire, "MAX_ATTRIBUTES_PER_ROW", 1)
    document = docs.minimal_document()
    document["queries"]["users"]["rows"] = [
        principal("CN=User", docs.AUDIT_SID, sAMAccountName="svc")
    ]

    with pytest.raises(wire.WireError) as caught:
        parse(document, loaded)

    assert "attributes" in str(caught.value)


def test_the_measured_document_of_the_lab_dc_parses(
    loaded: queryset.QuerySet,
) -> None:
    """The measured document satisfies the contract of section 5.

    It is the document of the lab Windows Server 2025 DC, with the one
    patch the collector bug needs: the domain sid is the SID of the
    domain head.
    """
    parsed = wire.parse(
        json.dumps(docs.measured_document()).encode("utf-8"), loaded
    )

    assert parsed.domain.domain_sid == (
        "S-1-5-21-2694141092-4246003333-2665853310"
    )
    assert parsed.collector == "windows"
    assert len(parsed.queries["users"].rows) == 1613
    assert len(parsed.queries["groups"].rows) == 55
    assert parsed.queries["domain_head"].rows[0].dn == (
        "DC=win,DC=newton,DC=test"
    )


def test_the_measured_document_holds_no_ranged_key() -> None:
    """The collector merged the ranges of the member attribute.

    A ranged key in a document is a hard error: the collector merges the
    ranges before it emits them.
    """
    document = docs.measured_document()

    keys = {
        name
        for query in document["queries"].values()
        for row in query["rows"]
        for name in row["a"]
    }

    assert [name for name in keys if "range=" in name.lower()] == []


def test_the_measured_document_holds_no_descriptor() -> None:
    """The measured document carries no security descriptor.

    The collector did not emit one: the queries that ask for it (``sd``)
    hold their rows and no ``nTSecurityDescriptor``.  The descriptor
    reader is therefore tested on descriptors built to the documented
    layout, and the collector has to emit the descriptor before the
    measured document can prove the descriptor reader.
    """
    document = docs.measured_document()

    for query in document["queries"].values():
        for row in query["rows"]:
            assert "nTSecurityDescriptor" not in row["a"]


# The base of the base-scope queries, with the naming contexts of the
# document in them.
DIR_SERVICE_DN = (
    "CN=Directory Service,CN=Windows NT,CN=Services,"
    "CN=Configuration,DC=win,DC=newton,DC=test"
)
DC_OU_DN = "OU=Domain Controllers,DC=win,DC=newton,DC=test"

# The message a row outside its base is refused with.  It is one fixed
# sentence: the document is untrusted and its text reaches a log.
OUTSIDE_BASE = "collector document invalid: a row is outside its query base"


def test_the_measured_wrong_shape_is_refused(
    loaded: queryset.QuerySet,
) -> None:
    """The shape the collector bug measured is refused.

    The collector ran every search against the default naming context,
    so every base-scope query came back with the domain head.  The core
    catches that class itself: the rows of a query have to sit inside the
    base of that query.
    """
    document = docs.measured_document(bug_rows=True)

    with pytest.raises(wire.WireError) as caught:
        wire.parse(json.dumps(document).encode("utf-8"), loaded)

    assert str(caught.value) == OUTSIDE_BASE


def test_a_base_query_that_returns_the_domain_head_is_refused(
    loaded: queryset.QuerySet,
) -> None:
    """A base-scope query that returns the domain head is refused."""
    document = docs.minimal_document()
    document["queries"]["dir_service"]["rows"] = [docs.row(docs.DOMAIN_DN)]

    with pytest.raises(wire.WireError) as caught:
        parse(document, loaded)

    assert str(caught.value) == OUTSIDE_BASE


def test_a_base_query_that_returns_its_own_base_is_accepted(
    loaded: queryset.QuerySet,
) -> None:
    """A base-scope query that returns its base is accepted."""
    document = docs.minimal_document()
    document["queries"]["dir_service"]["rows"] = [docs.row(DIR_SERVICE_DN)]

    parsed = parse(document, loaded)

    assert parsed.queries["dir_service"].rows[0].dn == DIR_SERVICE_DN


def test_a_sub_query_row_outside_its_base_is_refused(
    loaded: queryset.QuerySet,
) -> None:
    """A row of a sub-scope query that is under another base is refused."""
    document = docs.minimal_document()
    document["queries"]["users"]["rows"] = [
        principal("CN=User,OU=Other,DC=other,DC=test", docs.AUDIT_SID)
    ]

    with pytest.raises(wire.WireError) as caught:
        parse(document, loaded)

    assert str(caught.value) == OUTSIDE_BASE


def test_a_look_alike_suffix_is_refused(
    loaded: queryset.QuerySet,
) -> None:
    """A name that ends with the text of the base is not under the base.

    ``DC=evilwin,DC=newton,DC=test`` is not under
    ``DC=win,DC=newton,DC=test``: the text ends with the text of the
    base, but the RDNs are not the RDNs of the base.
    """
    for dn in (
        "DC=evilwin,DC=newton,DC=test",
        "CN=User,DC=evilwin,DC=newton,DC=test",
        "CN=User,OU=People,DC=evilwin,DC=newton,DC=test",
    ):
        document = docs.minimal_document()
        document["queries"]["users"]["rows"] = [principal(dn, docs.AUDIT_SID)]

        with pytest.raises(wire.WireError) as caught:
            parse(document, loaded)

        assert str(caught.value) == OUTSIDE_BASE


def test_a_row_under_the_base_is_accepted(
    loaded: queryset.QuerySet,
) -> None:
    """A row under the base of a sub-scope query is accepted."""
    document = docs.minimal_document()
    document["queries"]["users"]["rows"] = [
        principal(f"CN=User,OU=People,{docs.DOMAIN_DN}", docs.AUDIT_SID)
    ]

    parsed = parse(document, loaded)

    assert len(parsed.queries["users"].rows) == 1


def test_the_base_itself_is_accepted(
    loaded: queryset.QuerySet,
) -> None:
    """A sub-scope query may return the base itself."""
    document = docs.minimal_document()
    document["queries"]["users"]["rows"] = [
        principal(docs.DOMAIN_DN, docs.AUDIT_SID)
    ]

    parsed = parse(document, loaded)

    assert len(parsed.queries["users"].rows) == 1


def test_escapes_and_spacing_inside_the_base_are_accepted(
    loaded: queryset.QuerySet,
) -> None:
    """A row that is inside the base is accepted however it is written.

    The escapes are decoded and the spaces around the separators go
    before the names are compared, so a row that names the same object
    in another spelling is inside the base.
    """
    document = docs.minimal_document()
    document["queries"]["users"]["rows"] = [
        principal(
            "CN=Admin\\,istrator, OU=People , DC=win, DC=newton,DC=test",
            docs.AUDIT_SID,
        )
    ]
    document["queries"]["dc_ou"]["rows"] = [
        docs.row("ou=domain controllers , dc=win ,dc=newton, dc=test")
    ]

    parsed = parse(document, loaded)

    assert len(parsed.queries["users"].rows) == 1
    assert len(parsed.queries["dc_ou"].rows) == 1


def test_an_escaped_comma_is_not_the_base(
    loaded: queryset.QuerySet,
) -> None:
    """The comparison is on the RDNs and never on the text of the name.

    The row below ends with the text of the base, and it is not under
    the base: its second RDN holds the comma of ``DC=Win`` and the comma
    of ``DC=newton``, so it is one RDN and not two.
    """
    document = docs.minimal_document()
    document["queries"]["users"]["rows"] = [
        principal("CN=User,DC=Win\\,DC=newton,DC=test", docs.AUDIT_SID)
    ]

    with pytest.raises(wire.WireError) as caught:
        parse(document, loaded)

    assert str(caught.value) == OUTSIDE_BASE


def test_the_measured_document_still_parses(
    loaded: queryset.QuerySet,
) -> None:
    """The measured document, with the patches of the collector bugs.

    The collector bugs are fixed in the collector; the measured document
    is the run of the broken collector, so the helper patches it: the
    domain sid is the SID of the domain head and every base-scope query
    holds the row it asked for.
    """
    parsed = wire.parse(
        json.dumps(docs.measured_document()).encode("utf-8"), loaded
    )

    assert parsed.queries["dir_service"].rows[0].dn == DIR_SERVICE_DN
    assert parsed.queries["dc_ou"].rows[0].dn == DC_OU_DN
    assert len(parsed.queries["users"].rows) == 1613


def test_a_domain_name_that_is_not_the_domain_head_is_refused(
    loaded: queryset.QuerySet,
) -> None:
    """The domain name is the name of the domain head."""
    document = docs.minimal_document()
    document["queries"]["domain_head"]["rows"] = [
        principal("DC=other,DC=newton,DC=test", docs.DOMAIN_SID)
    ]

    with pytest.raises(wire.WireError) as caught:
        parse(document, loaded)

    assert "domain name" in str(caught.value)


def test_a_configuration_name_that_is_not_the_one_of_the_domain_is_refused(
    loaded: queryset.QuerySet,
) -> None:
    """The configuration naming context is under the domain."""
    document = docs.minimal_document()
    document["domain"]["config_dn"] = "CN=Configuration,DC=other,DC=newton,DC=test"

    with pytest.raises(wire.WireError) as caught:
        parse(document, loaded)

    assert "configuration name" in str(caught.value)


def test_a_schema_name_that_is_not_the_one_of_the_configuration_is_refused(
    loaded: queryset.QuerySet,
) -> None:
    """The schema naming context is under the configuration naming context."""
    document = docs.minimal_document()
    document["domain"]["schema_dn"] = "CN=Schema,DC=win,DC=newton,DC=test"

    with pytest.raises(wire.WireError) as caught:
        parse(document, loaded)

    assert "schema name" in str(caught.value)


def test_the_naming_contexts_may_be_written_differently(
    loaded: queryset.QuerySet,
) -> None:
    """The naming contexts are compared as names, not as text."""
    document = docs.minimal_document()
    document["domain"]["domain_dn"] = "dc=win, dc=newton ,DC=test"
    document["domain"]["config_dn"] = (
        "cn=configuration, dc=win, dc=newton, dc=test"
    )
    document["domain"]["schema_dn"] = (
        "CN=Schema,CN=Configuration, dc=win, dc=newton, dc=test"
    )

    parsed = parse(document, loaded)

    assert parsed.domain.domain_dn == "dc=win, dc=newton ,DC=test"
