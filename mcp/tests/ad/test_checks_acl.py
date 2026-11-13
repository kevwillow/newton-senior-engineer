"""The ACL checks over the measured documents.

The measured documents carry the real descriptors of the lab: the
domain head, the AdminSDHolder, the protected objects, the container
of the domain controllers and the GPO containers.  The lab has no
planted ACL abuse, so the measured documents give PASS; the FINDING
cases are built by adding one ACE to a measured descriptor in the
helper ``measured``, which says which measurement it builds on.

The fix of a finding is rendered with ``render.render`` and every
command is checked with ``render.assert_no_directory_text``: a
directory-originated string never ends up inside a command.
"""

from __future__ import annotations

from typing import Any

from newton_mcp.ad import catalogue, model, render, runner, values, wire
from newton_mcp.ad.checks import acl

import measured


# The extended rights that let a principal replicate the directory.
GET_CHANGES = values.EXTENDED_RIGHT_GET_CHANGES
GET_CHANGES_ALL = values.EXTENDED_RIGHT_GET_CHANGES_ALL
GET_CHANGES_IN_FILTERED_SET = values.EXTENDED_RIGHT_GET_CHANGES_IN_FILTERED_SET

# The bits of an access mask (MS-DTYP 2.4.6.2).
WRITE_PROPERTY = values.ACCESS_MASK_WRITE_PROP
READ_PROPERTY = values.ACCESS_MASK_READ_PROP
CONTROL_ACCESS = values.ACCESS_MASK_CONTROL_ACCESS
GENERIC_ALL = values.GENERIC_ALL_STORED
GENERIC_WRITE = values.GENERIC_WRITE_STORED
GENERIC_READ = values.GENERIC_READ_STORED


def property_guid(name: str) -> str:
    """The schema GUID of a property, from the table of the module."""
    for guid, property_name in values.PROPERTY_GUIDS.items():
        if property_name == name:
            return guid
    raise KeyError(f"the module holds no property named {name}")


# The schema GUID of the member attribute.
MEMBER = property_guid("member")

# The group of the measured domain that holds the ordinary accounts.
DOMAIN_USERS = "S-1-5-21-2694141092-4246003333-2665853310-513"

# The groups of the measured domain that hold the keys and the domain.
DOMAIN_ADMINS = "S-1-5-21-2694141092-4246003333-2665853310-512"
ENTERPRISE_ADMINS = "S-1-5-21-2694141092-4246003333-2665853310-519"
KEY_ADMINS = "S-1-5-21-2694141092-4246003333-2665853310-526"

# The seeded account of the lab that holds the replication rights on the
# domain head (seed S13 of the lab).
SEED_NEVERLOGON = "S-1-5-21-2694141092-4246003333-2665853310-1111"

# The GUID of the seeded GPO of the lab, the one the name of its container
# carries (seed S09).
SEED_GPO = "4a06e176-48dd-4b65-b2b0-214b24eb0f59"

# The objectGUID of the container of the seeded GPO of the lab.
SEED_GPO_OBJECT_GUID = "54813c7e-ad2a-4335-8b4d-b855a1973b1b"

# The administrators of the machine.
ADMINISTRATORS = "S-1-5-32-544"

# The name of a backup key object of a real domain.
BACKUP_KEY_GUID = "0f0e0d0c-0b0a-0908-0706-050403020100"

# The schema GUIDs of the GPO properties a write on them is a way into
# the domain (MS-GPOL 2.2.1.1.9 and 2.2.1.1.10).
GPC_FILE_SYS_PATH = "f30e3bc1-9ff0-11d1-b603-0000f80367c1"
GPC_MACHINE_EXTENSION_NAMES = "32ff8ecc-783f-11d2-9916-0000f87a57d4"
GPC_USER_EXTENSION_NAMES = "42a75fc6-783f-11d2-9916-0000f87a57d4"
VERSION_NUMBER = "bf967a76-0de6-11d0-a285-00aa003049e2"


def check_of(check_id: str) -> catalogue.Check:
    """The check of the catalogue with that id."""
    for check in catalogue.CHECKS:
        if check.id == check_id:
            return check
    raise KeyError("the catalogue does not hold the check")


def run_check(check_id: str, document: Any) -> model.CheckResult:
    """The result of one check over a document, through the runner."""
    report = runner.run(document, "ad-windows", checks=[check_of(check_id)])
    return report.results[0]


def directory_strings(report: runner.AuditReport) -> list[str]:
    """Every directory-originated string the report holds."""
    strings: list[str] = []
    for result in report.results:
        for finding in result.findings:
            for affected in finding.objects:
                for text in (affected.name, affected.dn, affected.evidence):
                    if text:
                        strings.append(text)
    return strings


def assert_the_fix_is_clean(check_id: str, document: Any) -> model.CheckResult:
    """The result of a check, with its fix rendered and proven clean."""
    report = runner.run(document, "ad-windows", checks=[check_of(check_id)])
    payload = render.render(report)
    strings = directory_strings(report)
    for result in payload["results"]:
        for finding in result["findings"]:
            if not finding["fix"]:
                continue
            for step in (finding["fix"]["windows"], finding["fix"]["samba"]):
                for command in step["commands"]:
                    render.assert_no_directory_text(command, strings)
    return report.results[0]


def add_ace_to_row(row: dict[str, Any], ace: bytes) -> None:
    """The row of the document with one more ACE in its DACL."""
    row["a"]["nTSecurityDescriptor"] = [
        measured.add_ace(row["a"]["nTSecurityDescriptor"][0], ace)
    ]


def domain_head(document: dict[str, Any]) -> dict[str, Any]:
    """The row of the domain head."""
    return document["queries"]["domain_head"]["rows"][0]


def adminsdholder(document: dict[str, Any]) -> dict[str, Any]:
    """The row of the AdminSDHolder."""
    return document["queries"]["adminsdholder"]["rows"][0]


def gpo_row(document: dict[str, Any]) -> dict[str, Any]:
    """The row of the GPO that is linked at the domain head."""
    for row in document["queries"]["gpos"]["rows"]:
        if "31B2F340" in row["dn"]:
            return row
    raise KeyError("the document does not hold the GPO of the domain head")


def drop_gpo_row(document: dict[str, Any], name: str) -> None:
    """The document without the row of the GPO of that display name.

    The GPO containers come from the measured document; the row is
    dropped the way a collector that could not read one GPO leaves it
    out.
    """
    rows = document["queries"]["gpos"]["rows"]
    kept = [
        row
        for row in rows
        if (row["a"].get("displayName") or [""])[0] != name
    ]
    if len(kept) == len(rows):
        raise KeyError(f"the document does not hold the GPO {name}")
    document["queries"]["gpos"]["rows"] = kept


# ---- the constants ----------------------------------------------------------


def test_constants() -> None:
    """The access mask, the property GUIDs and the rights are the documented ones."""
    assert values.ACCESS_MASK_CREATE_CHILD == 0x1
    assert values.ACCESS_MASK_DELETE_CHILD == 0x2
    assert values.ACCESS_MASK_LIST == 0x4
    assert values.ACCESS_MASK_SELF == 0x8
    assert values.ACCESS_MASK_READ_PROP == 0x10
    assert values.ACCESS_MASK_WRITE_PROP == 0x20
    assert values.ACCESS_MASK_DELETE_TREE == 0x40
    assert values.ACCESS_MASK_LIST_OBJECT == 0x80
    assert values.ACCESS_MASK_CONTROL_ACCESS == 0x100
    assert values.ACCESS_MASK_DELETE == 0x10000
    assert values.ACCESS_MASK_READ_CONTROL == 0x20000
    assert values.ACCESS_MASK_WRITE_DAC == 0x40000
    assert values.ACCESS_MASK_WRITE_OWNER == 0x80000
    assert values.ACCESS_MASK_GENERIC_ALL == 0x10000000
    assert values.ACCESS_MASK_GENERIC_WRITE == 0x40000000
    assert values.ACCESS_MASK_GENERIC_READ == 0x80000000
    assert values.GENERIC_ALL_STORED == 0xF01FF
    assert values.GENERIC_WRITE_STORED == 0x20028
    assert values.GENERIC_READ_STORED == 0x20094
    assert values.PROPERTY_GUIDS == {
        "bf9679c0-0de6-11d0-a285-00aa003049e2": "member",
        "f3a64788-5306-11d1-a9c5-0000f80367c1": "servicePrincipalName",
        "5b47d60f-6090-40b2-9f37-2a4de88f3063": "msDS-KeyCredentialLink",
        "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79": (
            "msDS-AllowedToActOnBehalfOfOtherIdentity"
        ),
        "bf9679a8-0de6-11d0-a285-00aa003049e2": "scriptPath",
    }
    assert values.EXTENDED_RIGHT_GET_CHANGES == "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
    assert values.EXTENDED_RIGHT_GET_CHANGES_ALL == "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
    assert (
        values.EXTENDED_RIGHT_GET_CHANGES_IN_FILTERED_SET
        == "89e95b76-444d-4c62-991a-0facbeda640c"
    )
    assert acl.GPO_PROPERTIES == {
        "f30e3bc1-9ff0-11d1-b603-0000f80367c1": "gPCFileSysPath",
        "32ff8ecc-783f-11d2-9916-0000f87a57d4": "gPCMachineExtensionNames",
        "42a75fc6-783f-11d2-9916-0000f87a57d4": "gPCUserExtensionNames",
        "bf967a76-0de6-11d0-a285-00aa003049e2": "versionNumber",
    }


# ---- AD-A-51: the replication rights ----------------------------------------


def test_ad_a_51_passes_on_the_measured_document() -> None:
    """No principal outside the allowed holders holds a replication right.

    The domain admins and the enterprise admins hold every extended
    right on the domain head, and both are allowed holders: Windows
    grants them that right by default.
    """
    result = run_check("AD-A-51", measured.audit_document())

    assert result.status == model.Status.PASS
    assert result.findings == ()


def test_ad_a_51_does_not_find_the_two_administrator_groups() -> None:
    """The two administrator groups of the domain are allowed holders.

    Their ACE on the domain head carries the control-access bit and
    names no object type, so it grants every extended right, the
    replication rights among them.  Windows grants that right by
    default, so it is not a finding.
    """
    result = run_check("AD-A-51", measured.audit_document())

    trustees = {
        affected.sid
        for finding in result.findings
        for affected in finding.objects
        if affected.sid
    }
    assert DOMAIN_ADMINS not in trustees
    assert ENTERPRISE_ADMINS not in trustees


def test_ad_a_51_finds_the_seeded_account_once_on_the_acl_document() -> None:
    """The seeded account holds two replication rights: one finding.

    The two rights are the ACEs of the seed S13 of the lab.  A
    principal is reported once, with every replication right it holds.
    """
    result = assert_the_fix_is_clean("AD-A-51", measured.r4_document())

    assert result.status == model.Status.FINDING
    assert len(result.findings) == 1
    finding = result.findings[0]
    sids = [affected.sid for affected in finding.objects if affected.sid]
    assert sids.count(SEED_NEVERLOGON) == 1
    evidence = " ".join(
        affected.evidence or "" for affected in finding.objects
    )
    assert GET_CHANGES in evidence
    assert GET_CHANGES_ALL in evidence


def test_ad_a_51_finds_a_principal_that_may_replicate_the_directory() -> None:
    """A replication right for an ordinary account is a finding."""
    raw = measured.audit_json()
    add_ace_to_row(
        domain_head(raw),
        measured.build_ace(CONTROL_ACCESS, measured.AUDIT_SID, GET_CHANGES_ALL),
    )

    result = assert_the_fix_is_clean("AD-A-51", measured.parse(raw))

    assert result.status == model.Status.FINDING
    holders = [
        affected.sid
        for finding in result.findings
        for affected in finding.objects
    ]
    assert measured.AUDIT_SID in holders


def test_ad_a_51_finds_the_members_of_a_group_that_may_replicate() -> None:
    """The members of the group inherit the replication right."""
    raw = measured.audit_json()
    add_ace_to_row(
        domain_head(raw),
        measured.build_ace(CONTROL_ACCESS, DOMAIN_USERS, GET_CHANGES),
    )

    result = assert_the_fix_is_clean("AD-A-51", measured.parse(raw))

    assert result.status == model.Status.FINDING
    holders = [
        affected.sid
        for finding in result.findings
        for affected in finding.objects
    ]
    assert DOMAIN_USERS in holders
    assert measured.AUDIT_SID in holders


def test_ad_a_51_finds_a_group_that_is_not_an_allowed_holder() -> None:
    """The key admins are not one of the allowed holders.

    The allowed holders are the domain controllers, the read-only
    domain controllers, the enterprise read-only domain controller, the
    administrators, the enterprise domain controllers and the system
    account.  A group that is privileged is not one of them.
    """
    raw = measured.audit_json()
    add_ace_to_row(
        domain_head(raw),
        measured.build_ace(CONTROL_ACCESS, KEY_ADMINS, GET_CHANGES),
    )

    result = assert_the_fix_is_clean("AD-A-51", measured.parse(raw))

    assert result.status == model.Status.FINDING
    trustees = [
        affected.sid
        for finding in result.findings
        for affected in finding.objects
    ]
    assert KEY_ADMINS in trustees


def test_ad_a_51_does_not_find_the_allowed_holders() -> None:
    """A replication right of an allowed holder is not a finding."""
    raw = measured.audit_json()
    add_ace_to_row(
        domain_head(raw),
        measured.build_ace(CONTROL_ACCESS, ADMINISTRATORS, GET_CHANGES),
    )
    add_ace_to_row(
        domain_head(raw),
        measured.build_ace(CONTROL_ACCESS, "S-1-5-9", GET_CHANGES_ALL),
    )
    add_ace_to_row(
        domain_head(raw),
        measured.build_ace(CONTROL_ACCESS, "S-1-5-18", GET_CHANGES_IN_FILTERED_SET),
    )

    result = run_check("AD-A-51", measured.parse(raw))

    assert result.status == model.Status.PASS
    holders = {
        affected.sid
        for finding in result.findings
        for affected in finding.objects
    }
    assert ADMINISTRATORS not in holders
    assert "S-1-5-9" not in holders
    assert "S-1-5-18" not in holders


def test_ad_a_51_does_not_find_an_extended_right_that_is_not_a_replication_one() -> None:
    """A control access on another extended right is not a replication right."""
    raw = measured.audit_json()
    add_ace_to_row(
        domain_head(raw),
        measured.build_ace(
            CONTROL_ACCESS,
            measured.AUDIT_SID,
            "e2a36dc9-ae17-47c3-b58b-be34c55ba633",
        ),
    )

    result = run_check("AD-A-51", measured.parse(raw))

    assert measured.AUDIT_SID not in {
        affected.sid
        for finding in result.findings
        for affected in finding.objects
    }


def test_ad_a_51_finds_a_domain_head_without_a_dacl() -> None:
    """A null DACL grants every right to every principal."""
    raw = measured.audit_json()
    head = domain_head(raw)
    head["a"]["nTSecurityDescriptor"] = [
        measured.null_dacl(head["a"]["nTSecurityDescriptor"][0])
    ]

    result = assert_the_fix_is_clean("AD-A-51", measured.parse(raw))

    assert result.status == model.Status.FINDING
    assert len(result.findings) == 1
    assert "DACL" in result.findings[0].title


def test_ad_a_51_is_unknown_when_the_domain_head_has_no_dacl() -> None:
    """A descriptor without a DACL proves nothing about the rights."""
    raw = measured.audit_json()
    head = domain_head(raw)
    head["a"]["nTSecurityDescriptor"] = [
        measured.no_dacl(head["a"]["nTSecurityDescriptor"][0])
    ]

    result = run_check("AD-A-51", measured.parse(raw))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ACCESS_DENIED


def test_ad_a_51_is_unknown_without_the_descriptor_of_the_domain_head() -> None:
    """A domain head without a descriptor proves nothing."""
    raw = measured.audit_json()
    measured.drop_attribute(domain_head(raw), "nTSecurityDescriptor")

    result = run_check("AD-A-51", measured.parse(raw))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ACCESS_DENIED


# ---- AD-A-52: the dangerous write rights -----------------------------------


def test_ad_a_52_passes_on_the_measured_document() -> None:
    """No object of the measured domain holds a dangerous write right."""
    result = run_check("AD-A-52", measured.audit_document())

    assert result.status == model.Status.PASS
    assert result.findings == ()


def test_ad_a_52_finds_a_write_on_the_member_attribute() -> None:
    """A write on the member attribute of the domain head is a finding."""
    raw = measured.audit_json()
    add_ace_to_row(
        domain_head(raw),
        measured.build_ace(WRITE_PROPERTY, measured.AUDIT_SID, MEMBER),
    )

    result = assert_the_fix_is_clean("AD-A-52", measured.parse(raw))

    assert result.status == model.Status.FINDING
    assert len(result.findings) == 1
    assert result.findings[0].objects[0].sid is not None
    assert "member" in (result.findings[0].objects[0].evidence or "")


def test_ad_a_52_finds_a_write_on_every_property() -> None:
    """An ACE that names no property grants a write on every property."""
    raw = measured.audit_json()
    add_ace_to_row(
        domain_head(raw),
        measured.build_ace(WRITE_PROPERTY, measured.AUDIT_SID),
    )

    result = assert_the_fix_is_clean("AD-A-52", measured.parse(raw))

    assert result.status == model.Status.FINDING
    assert len(result.findings) == 1
    assert "every property" in (result.findings[0].objects[0].evidence or "")


def test_ad_a_52_finds_a_generic_all() -> None:
    """The stored form of the generic all is full control on the object."""
    raw = measured.audit_json()
    add_ace_to_row(
        domain_head(raw),
        measured.build_ace(GENERIC_ALL, measured.AUDIT_SID),
    )

    result = assert_the_fix_is_clean("AD-A-52", measured.parse(raw))

    assert result.status == model.Status.FINDING
    assert len(result.findings) == 1
    assert "full control" in (result.findings[0].objects[0].evidence or "")


def test_ad_a_52_finds_an_object_without_a_dacl() -> None:
    """A null DACL grants everything to everyone."""
    raw = measured.audit_json()
    head = domain_head(raw)
    head["a"]["nTSecurityDescriptor"] = [
        measured.null_dacl(head["a"]["nTSecurityDescriptor"][0])
    ]

    result = assert_the_fix_is_clean("AD-A-52", measured.parse(raw))

    assert result.status == model.Status.FINDING
    assert len(result.findings) == 1
    assert "DACL" in result.findings[0].title


def test_ad_a_52_is_unknown_when_an_object_of_the_scope_has_no_dacl() -> None:
    """An object whose descriptor carries no DACL proves nothing."""
    raw = measured.audit_json()
    holder = adminsdholder(raw)
    holder["a"]["nTSecurityDescriptor"] = [
        measured.no_dacl(holder["a"]["nTSecurityDescriptor"][0])
    ]

    result = run_check("AD-A-52", measured.parse(raw))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ACCESS_DENIED


def test_ad_a_52_is_unknown_when_the_gpo_objects_are_not_readable() -> None:
    """The gPLink points at GPOs the collector did not read."""
    raw = measured.audit_json()
    raw["queries"]["gpos"]["rows"] = []

    result = run_check("AD-A-52", measured.parse(raw))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ACCESS_DENIED
    assert "GPO objects were not readable" in result.note


def test_ad_a_52_is_unknown_when_no_gpo_was_read_and_nothing_is_linked() -> None:
    """An empty GPO read is "could not read" even when no link points at one.

    The Default Domain Policy and the Default Domain Controllers Policy
    always exist, so a domain whose links were all removed still has
    GPO containers: an empty read of them proves nothing.
    """
    raw = measured.audit_json()
    raw["queries"]["gpos"]["rows"] = []
    for query_id in ("domain_head", "ous", "dc_ou"):
        for row in raw["queries"][query_id]["rows"]:
            row["a"].pop("gPLink", None)

    result = run_check("AD-A-52", measured.parse(raw))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ACCESS_DENIED
    assert "GPO objects were not readable" in result.note


def test_ad_a_52_is_unknown_when_a_linked_gpo_was_not_read() -> None:
    """One GPO of the links the collector did not read is enough.

    The domain head links the Default Domain Policy.  A collector that
    read no row of it read no descriptor of it, so the check cannot say
    anything about the DACL of that GPO.
    """
    raw = measured.r4_json()
    drop_gpo_row(raw, "Default Domain Policy")

    result = run_check("AD-A-52", measured.parse(raw))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ACCESS_DENIED
    assert "1 GPO(s)" in result.note


def test_ad_a_52_is_unknown_when_a_gpo_of_an_organizational_unit_was_not_read() -> None:
    """A link of any organizational unit counts as a link.

    The seeded GPO of the lab is linked at the unit of the seeds, not
    at the domain head, and its DACL is just as much a way into the
    domain.
    """
    raw = measured.r4_json()
    drop_gpo_row(raw, "seed-gpp")

    result = run_check("AD-A-52", measured.parse(raw))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ACCESS_DENIED
    assert "1 GPO(s)" in result.note


def test_the_note_of_a_missing_gpo_names_no_gpo() -> None:
    """The note counts the GPOs it could not read and names none of them."""
    raw = measured.r4_json()
    drop_gpo_row(raw, "Default Domain Policy")

    result = run_check("AD-A-52", measured.parse(raw))

    assert "31b2f340" not in result.note.lower()
    assert "Default Domain Policy" not in result.note


def test_ad_a_52_does_not_find_the_well_known_trustees() -> None:
    """The rights of the well-known trustees are not findings."""
    raw = measured.audit_json()
    head = domain_head(raw)
    add_ace_to_row(head, measured.build_ace(CONTROL_ACCESS, "S-1-5-10", GET_CHANGES_ALL))
    add_ace_to_row(head, measured.build_ace(CONTROL_ACCESS, "S-1-3-0", GET_CHANGES_ALL))
    add_ace_to_row(head, measured.build_ace(CONTROL_ACCESS, "S-1-5-9", GET_CHANGES_ALL))
    add_ace_to_row(head, measured.build_ace(CONTROL_ACCESS, "S-1-5-18", GET_CHANGES_ALL))
    add_ace_to_row(head, measured.build_ace(READ_PROPERTY, "S-1-5-11", MEMBER))

    result = run_check("AD-A-52", measured.parse(raw))

    assert result.status == model.Status.PASS
    assert result.findings == ()


def test_ad_a_52_is_unknown_without_a_descriptor_of_the_scope() -> None:
    """An object of the scope without a descriptor proves nothing."""
    raw = measured.audit_json()
    measured.drop_attribute(adminsdholder(raw), "nTSecurityDescriptor")

    result = run_check("AD-A-52", measured.parse(raw))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ACCESS_DENIED


# ---- AD-A-53: the AdminSDHolder ---------------------------------------------


def test_ad_a_53_passes_on_the_measured_document() -> None:
    """The measured AdminSDHolder holds no dangerous write right."""
    result = run_check("AD-A-53", measured.audit_document())

    assert result.status == model.Status.PASS
    assert result.findings == ()


def test_ad_a_53_finds_a_write_right_on_the_admin_sd_holder() -> None:
    """A write right on the template of the protected objects is a finding."""
    raw = measured.audit_json()
    add_ace_to_row(
        adminsdholder(raw),
        measured.build_ace(WRITE_PROPERTY, measured.AUDIT_SID, MEMBER),
    )

    result = assert_the_fix_is_clean("AD-A-53", measured.parse(raw))

    assert result.status == model.Status.FINDING
    assert len(result.findings) == 1
    assert result.findings[0].objects[0].dn is not None
    assert "AdminSDHolder" in result.findings[0].objects[0].dn


def test_the_admin_sd_holder_of_the_report_has_a_display_name() -> None:
    """The AdminSDHolder reads as its own name.

    The directory gives the template of the protected objects no name of
    its own: the name is derived from its distinguished name, so the
    report shows what the object is.
    """
    raw = measured.audit_json()
    add_ace_to_row(
        adminsdholder(raw),
        measured.build_ace(WRITE_PROPERTY, measured.AUDIT_SID, MEMBER),
    )
    report = runner.run(
        measured.parse(raw),
        "ad-windows",
        checks=[check_of("AD-A-53")],
    )
    payload = render.render(report)

    obj = payload["results"][0]["findings"][0]["objects"][0]
    assert obj["name"]["text"] == "AdminSDHolder"


def test_ad_a_53_is_unknown_when_an_object_of_the_scope_has_no_dacl() -> None:
    """An object without a DACL proves nothing about the rights."""
    raw = measured.audit_json()
    holder = adminsdholder(raw)
    holder["a"]["nTSecurityDescriptor"] = [
        measured.no_dacl(holder["a"]["nTSecurityDescriptor"][0])
    ]

    result = run_check("AD-A-53", measured.parse(raw))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ACCESS_DENIED


def test_ad_a_53_is_unknown_without_the_descriptor_of_the_holder() -> None:
    """An AdminSDHolder without a descriptor proves nothing."""
    raw = measured.audit_json()
    measured.drop_attribute(adminsdholder(raw), "nTSecurityDescriptor")

    result = run_check("AD-A-53", measured.parse(raw))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ACCESS_DENIED


# ---- AD-A-54: the GPO containers ---------------------------------------------


def test_ad_a_54_passes_on_the_measured_document() -> None:
    """The GPOs linked at the domain head hold no dangerous write right."""
    result = run_check("AD-A-54", measured.audit_document())

    assert result.status == model.Status.PASS
    assert result.findings == ()


def test_ad_a_54_finds_a_write_right_on_a_gpo() -> None:
    """A write right on a GPO of the domain is a finding."""
    raw = measured.audit_json()
    add_ace_to_row(
        gpo_row(raw),
        measured.build_ace(WRITE_PROPERTY, measured.AUDIT_SID, MEMBER),
    )

    result = assert_the_fix_is_clean("AD-A-54", measured.parse(raw))

    assert result.status == model.Status.FINDING
    assert len(result.findings) == 1
    assert result.findings[0].objects[0].guid is not None


def test_ad_a_54_is_unknown_when_the_gpo_objects_are_not_readable() -> None:
    """The gPLink points at GPOs the collector did not read."""
    raw = measured.audit_json()
    raw["queries"]["gpos"]["rows"] = []

    result = run_check("AD-A-54", measured.parse(raw))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ACCESS_DENIED
    assert "GPO objects were not readable" in result.note


def test_ad_a_54_is_unknown_when_no_gpo_was_read_and_nothing_is_linked() -> None:
    """An empty GPO read is "could not read" even when no link points at one.

    The Default Domain Policy and the Default Domain Controllers Policy
    always exist, so a domain whose links were all removed still has
    GPO containers: an empty read of them proves nothing.
    """
    raw = measured.audit_json()
    raw["queries"]["gpos"]["rows"] = []
    for query_id in ("domain_head", "ous", "dc_ou"):
        for row in raw["queries"][query_id]["rows"]:
            row["a"].pop("gPLink", None)

    result = run_check("AD-A-54", measured.parse(raw))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ACCESS_DENIED
    assert "GPO objects were not readable" in result.note


def test_ad_a_54_is_unknown_when_a_linked_gpo_was_not_read() -> None:
    """One GPO of the links the collector did not read is enough.

    The domain head links the Default Domain Policy.  A collector that
    read no row of it read no descriptor of it, so the check cannot say
    anything about the DACL of that GPO.
    """
    raw = measured.r4_json()
    drop_gpo_row(raw, "Default Domain Policy")

    result = run_check("AD-A-54", measured.parse(raw))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ACCESS_DENIED
    assert "1 GPO(s)" in result.note


def test_ad_a_54_is_unknown_when_a_gpo_of_an_organizational_unit_was_not_read() -> None:
    """A link of any organizational unit counts as a link."""
    raw = measured.r4_json()
    drop_gpo_row(raw, "seed-gpp")

    result = run_check("AD-A-54", measured.parse(raw))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ACCESS_DENIED
    assert "1 GPO(s)" in result.note


def test_ad_a_54_finds_a_write_on_the_sysvol_path_of_a_gpo() -> None:
    """A write on the path of the SYSVOL folder of a GPO is a finding.

    A principal that may write the path of the SYSVOL folder of a GPO
    decides where the files of that GPO come from: it decides what the
    computers of the domain run.
    """
    raw = measured.audit_json()
    add_ace_to_row(
        gpo_row(raw),
        measured.build_ace(WRITE_PROPERTY, DOMAIN_USERS, GPC_FILE_SYS_PATH),
    )

    result = assert_the_fix_is_clean("AD-A-54", measured.parse(raw))

    assert result.status == model.Status.FINDING
    assert len(result.findings) == 1
    evidence = " ".join(
        affected.evidence or "" for affected in result.findings[0].objects
    )
    assert "gPCFileSysPath" in evidence
    assert DOMAIN_USERS in evidence


def test_ad_a_54_finds_a_write_on_every_gpo_property_that_leads_in() -> None:
    """A write on the extensions a GPO applies, or on its version, is a finding."""
    raw = measured.audit_json()
    add_ace_to_row(
        gpo_row(raw),
        measured.build_ace(
            WRITE_PROPERTY,
            DOMAIN_USERS,
            GPC_MACHINE_EXTENSION_NAMES,
        ),
    )
    add_ace_to_row(
        gpo_row(raw),
        measured.build_ace(
            WRITE_PROPERTY,
            DOMAIN_USERS,
            GPC_USER_EXTENSION_NAMES,
        ),
    )
    add_ace_to_row(
        gpo_row(raw),
        measured.build_ace(WRITE_PROPERTY, DOMAIN_USERS, VERSION_NUMBER),
    )

    result = run_check("AD-A-54", measured.parse(raw))

    assert result.status == model.Status.FINDING
    assert len(result.findings) == 3


def test_ad_a_54_does_not_find_a_write_on_a_property_that_leads_nowhere() -> None:
    """A write on a property that leads nowhere is not a finding."""
    raw = measured.audit_json()
    add_ace_to_row(
        gpo_row(raw),
        measured.build_ace(
            WRITE_PROPERTY,
            DOMAIN_USERS,
            "00000000-0000-0000-0000-000000000001",
        ),
    )

    result = run_check("AD-A-54", measured.parse(raw))

    assert result.status == model.Status.PASS
    assert result.findings == ()


def test_ad_a_54_reads_every_gpo_of_the_query() -> None:
    """A GPO that is not linked at the domain head counts too.

    A GPO that is linked at an organizational unit of the domain, or
    that is linked nowhere, is a GPO of the domain: its DACL is read.
    """
    raw = measured.audit_json()
    for row in raw["queries"]["gpos"]["rows"]:
        if "4A06E176" in row["dn"]:
            add_ace_to_row(
                row,
                measured.build_ace(WRITE_PROPERTY, measured.AUDIT_SID, MEMBER),
            )

    result = run_check("AD-A-54", measured.parse(raw))

    assert result.status == model.Status.FINDING
    assert len(result.findings) == 1
    assert result.findings[0].objects[0].guid is not None


def test_ad_a_54_finds_the_seeded_gpo_on_the_acl_document() -> None:
    """The domain users may edit the seeded GPO: a finding.

    The seed S16 of the lab gives the edit right on the seeded GPO to
    the domain users, and the GPO is linked at an organizational unit,
    not at the domain head.
    """
    result = assert_the_fix_is_clean("AD-A-54", measured.r4_document())

    assert result.status == model.Status.FINDING
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.objects[0].guid == SEED_GPO_OBJECT_GUID
    evidence = " ".join(
        affected.evidence or "" for affected in finding.objects
    )
    assert SEED_GPO in evidence
    assert DOMAIN_USERS in evidence


def test_ad_a_54_names_the_generic_all_of_a_gpo() -> None:
    """A generic all on a GPO is full control on it."""
    raw = measured.audit_json()
    for row in raw["queries"]["gpos"]["rows"]:
        if "4A06E176" in row["dn"]:
            add_ace_to_row(
                row,
                measured.build_ace(GENERIC_ALL, measured.AUDIT_SID),
            )

    result = run_check("AD-A-54", measured.parse(raw))

    assert result.status == model.Status.FINDING
    assert len(result.findings) == 1
    assert "full control" in (result.findings[0].objects[0].evidence or "")


def test_ad_a_54_names_the_generic_write_of_a_gpo() -> None:
    """A generic write on a GPO is a write on it."""
    raw = measured.audit_json()
    for row in raw["queries"]["gpos"]["rows"]:
        if "4A06E176" in row["dn"]:
            add_ace_to_row(
                row,
                measured.build_ace(GENERIC_WRITE, measured.AUDIT_SID),
            )

    result = run_check("AD-A-54", measured.parse(raw))

    assert result.status == model.Status.FINDING
    assert len(result.findings) == 1
    assert "generic write" in (result.findings[0].objects[0].evidence or "")


def test_ad_a_54_is_unknown_without_the_descriptor_of_a_gpo() -> None:
    """A GPO of the scope without a descriptor proves nothing."""
    raw = measured.audit_json()
    measured.drop_attribute(gpo_row(raw), "nTSecurityDescriptor")

    result = run_check("AD-A-54", measured.parse(raw))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ACCESS_DENIED


# ---- AD-A-57: the domain backup keys -----------------------------------------


def backup_key_row(descriptor: str, name: str | None = None) -> dict[str, Any]:
    """A backup key object of the measured domain.

    The name of a backup key of a real domain is the GUID of the key and
    the word Secret, without braces.
    """
    if name is None:
        name = f"BCKUPKEY_{BACKUP_KEY_GUID} Secret"
    return {
        "dn": (
            f"CN={name},CN=System,DC=win,DC=newton,DC=test"
        ),
        "a": {
            "cn": [name],
            "nTSecurityDescriptor": [descriptor],
        },
    }


def key_descriptor(mask: int = READ_PROPERTY) -> str:
    """A descriptor whose DACL grants one right to the audit account."""
    return measured.build_descriptor(
        "S-1-5-21-2694141092-4246003333-2665853310-512",
        [measured.build_ace(mask, measured.AUDIT_SID)],
    )


def test_ad_a_57_is_unknown_when_the_backup_keys_are_not_visible() -> None:
    """The audit account does not see the backup keys."""
    result = run_check("AD-A-57", measured.audit_document())

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ACCESS_DENIED


def test_ad_a_57_is_unknown_when_the_backup_keys_were_not_read() -> None:
    """A query that did not complete proves nothing."""
    raw = measured.audit_json()
    measured.set_query_status(raw, "dpapi_backup", "denied", "access_denied")

    result = run_check("AD-A-57", measured.parse(raw))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ACCESS_DENIED


def test_ad_a_57_finds_a_principal_that_may_read_the_backup_key() -> None:
    """A read right on a backup key for an ordinary account is a finding."""
    raw = measured.audit_json()
    raw["queries"]["dpapi_backup"]["rows"] = [backup_key_row(key_descriptor())]

    result = assert_the_fix_is_clean("AD-A-57", measured.parse(raw))

    assert result.status == model.Status.FINDING
    assert len(result.findings) == 1
    assert result.findings[0].objects[0].dn is not None
    assert "BCKUPKEY" in result.findings[0].objects[0].dn


def test_ad_a_57_finds_a_principal_that_may_read_the_key_with_the_generic_read() -> None:
    """The stored form of the generic read is a read on the key."""
    raw = measured.audit_json()
    raw["queries"]["dpapi_backup"]["rows"] = [
        backup_key_row(key_descriptor(GENERIC_READ))
    ]

    result = assert_the_fix_is_clean("AD-A-57", measured.parse(raw))

    assert result.status == model.Status.FINDING
    assert len(result.findings) == 1


def test_ad_a_57_does_not_take_the_guid_of_the_key_from_its_name() -> None:
    """The name of an object is not the identifier of the object.

    The name of a backup key carries the GUID of the key, but a name is
    directory text: the identifier of the object is the objectGUID
    attribute and nothing else.
    """
    raw = measured.audit_json()
    raw["queries"]["dpapi_backup"]["rows"] = [
        backup_key_row(
            key_descriptor(),
            name=f"BCKUPKEY_{BACKUP_KEY_GUID}",
        )
    ]

    result = run_check("AD-A-57", measured.parse(raw))

    assert result.status == model.Status.FINDING
    assert result.findings[0].objects[0].guid is None


def test_the_guid_of_a_backup_key_is_the_object_guid() -> None:
    """The GUID of a backup key is the one of the objectGUID attribute."""
    row = wire.Row(
        dn=f"CN=BCKUPKEY_{BACKUP_KEY_GUID} Secret,CN=System",
        a={"objectGUID": [measured.guid_blob(BACKUP_KEY_GUID)]},
    )

    assert acl.backup_key_guid(row) == BACKUP_KEY_GUID


def test_ad_a_57_passes_when_only_the_privileged_set_may_read_the_key() -> None:
    """A backup key that only the privileged set may read passes."""
    raw = measured.audit_json()
    descriptor = measured.build_descriptor(
        "S-1-5-21-2694141092-4246003333-2665853310-512",
        [
            measured.build_ace(
                READ_PROPERTY,
                "S-1-5-21-2694141092-4246003333-2665853310-512",
            )
        ],
    )
    raw["queries"]["dpapi_backup"]["rows"] = [backup_key_row(descriptor)]

    result = run_check("AD-A-57", measured.parse(raw))

    assert result.status == model.Status.PASS
    assert result.findings == ()


def test_ad_a_57_is_unknown_when_a_backup_key_has_no_dacl() -> None:
    """A backup key without a DACL proves nothing about the rights."""
    raw = measured.audit_json()
    descriptor = measured.build_descriptor(
        "S-1-5-21-2694141092-4246003333-2665853310-512",
        [measured.build_ace(READ_PROPERTY, measured.AUDIT_SID)],
    )
    raw["queries"]["dpapi_backup"]["rows"] = [backup_key_row(descriptor)]
    raw["queries"]["dpapi_backup"]["rows"][0]["a"]["nTSecurityDescriptor"] = [
        measured.no_dacl(descriptor)
    ]

    result = run_check("AD-A-57", measured.parse(raw))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ACCESS_DENIED


# ---- the fixes ---------------------------------------------------------------


def test_the_fix_of_an_acl_finding_explains_the_change() -> None:
    """No documented cmdlet changes a DACL, so the fix explains it."""
    raw = measured.audit_json()
    add_ace_to_row(
        domain_head(raw),
        measured.build_ace(WRITE_PROPERTY, measured.AUDIT_SID, MEMBER),
    )

    report = runner.run(measured.parse(raw), "ad-windows", checks=[check_of("AD-A-52")])
    payload = render.render(report)
    fix = payload["results"][0]["findings"][0]["fix"]

    assert fix["windows"]["commands"] == ()
    assert fix["samba"]["commands"] == ()
    assert "DACL" in fix["windows"]["summary"]
    assert measured.AUDIT_SID in fix["windows"]["summary"]


def test_the_fix_of_a_backup_key_explains_the_change() -> None:
    """The fix of a backup key names the key and explains the change."""
    raw = measured.audit_json()
    descriptor = measured.build_descriptor(
        "S-1-5-21-2694141092-4246003333-2665853310-512",
        [measured.build_ace(READ_PROPERTY, measured.AUDIT_SID)],
    )
    raw["queries"]["dpapi_backup"]["rows"] = [backup_key_row(descriptor)]

    report = runner.run(measured.parse(raw), "ad-windows", checks=[check_of("AD-A-57")])
    payload = render.render(report)
    fix = payload["results"][0]["findings"][0]["fix"]

    assert fix["windows"]["commands"] == ()
    assert fix["samba"]["commands"] == ()
    assert measured.AUDIT_SID in fix["windows"]["summary"]
    assert "DACL" in fix["windows"]["summary"]


def test_the_whole_report_renders_the_findings_of_two_checks() -> None:
    """A report with a backup key finding and a trust finding is rendered."""
    raw = measured.audit_json()
    descriptor = measured.build_descriptor(
        "S-1-5-21-2694141092-4246003333-2665853310-512",
        [measured.build_ace(READ_PROPERTY, measured.AUDIT_SID)],
    )
    raw["queries"]["dpapi_backup"]["rows"] = [backup_key_row(descriptor)]
    raw["queries"]["trusts"]["rows"] = [
        {
            "dn": "CN=partner.test,CN=System,DC=win,DC=newton,DC=test",
            "a": {
                "trustPartner": ["partner.test"],
                "trustDirection": ["3"],
                "trustType": ["2"],
                "trustAttributes": ["8"],
                "securityIdentifier": [measured.sid_blob(measured.AUDIT_SID)],
            },
        }
    ]

    report = runner.run(measured.parse(raw), "ad-windows")
    payload = render.render(report)
    strings = directory_strings(report)

    found = {
        result["id"]
        for result in payload["results"]
        if result["findings"]
    }
    assert "AD-A-57" in found
    assert "AD-A-48" in found
    for result in payload["results"]:
        for finding in result["findings"]:
            if not finding["fix"]:
                continue
            for step in (finding["fix"]["windows"], finding["fix"]["samba"]):
                for command in step["commands"]:
                    render.assert_no_directory_text(command, strings)
