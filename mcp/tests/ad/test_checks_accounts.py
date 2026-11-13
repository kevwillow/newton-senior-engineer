"""The account checks, parts one and two.

Every test here reads the measured collector document of the lab domain
(``fixtures/win-dc-audit-r3.json``) and edits it when the test needs
another shape.  The helper that edits it names the file it starts from,
as SPEC-1.3 section 10 asks of every variant of a measured document.

The checks are run through the runner, because the runner is what proves
that the audit was allowed to see the data: a query that did not
complete, a sentinel that failed or a readable object without a required
attribute makes a check UNKNOWN, and the identity guard stops the audit
before any check runs.
"""

from __future__ import annotations

import base64
import functools
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import pytest

from newton_mcp.ad import catalogue, model, queryset, render, runner, secdesc, wire
from newton_mcp.ad.checks import accounts

import docs
from test_secdesc import ace, build


FIXTURE_DIR = Path(__file__).with_name("fixtures")

# The measured document every test of this file starts from.
AUDIT_SOURCE = "win-dc-audit-r3.json"

# The measured document of the same domain read again after the seeded
# security descriptors were written to it.
ACL_SOURCE = "win-dc-audit-r4-acl.json"

# The SID of the domain the measured document is about.
DOMAIN_SID = json.loads(
    (FIXTURE_DIR / AUDIT_SOURCE).read_text(encoding="utf-8")
)["domain"]["domain_sid"]

# The check ids of this part.
CHECK_IDS = (
    "AD-A-01",
    "AD-A-02",
    "AD-A-03",
    "AD-A-04",
    "AD-A-05",
    "AD-A-06",
    "AD-A-07",
    "AD-A-08",
    "AD-A-09",
    "AD-A-10",
    "AD-A-11",
    "AD-A-12",
    "AD-A-13",
    "AD-A-14",
    "AD-A-16",
    "AD-A-17",
    "AD-A-18",
    "AD-A-19",
    "AD-A-20",
    "AD-A-21",
    "AD-A-22",
    "AD-A-23",
    "AD-A-24",
    "AD-A-25",
    "AD-A-26",
    "AD-A-27",
    "AD-A-30",
    "AD-A-31",
    "AD-A-32",
)


# ---- the documents ---------------------------------------------------------


def source_document() -> dict[str, Any]:
    """The measured collector document, as the collector wrote it."""
    return json.loads((FIXTURE_DIR / AUDIT_SOURCE).read_text(encoding="utf-8"))


def parsed(document: dict[str, Any]) -> wire.Document:
    """The validated document of an edited measured document."""
    return wire.parse(json.dumps(document).encode("utf-8"), queryset.load())


@functools.lru_cache(maxsize=1)
def measured() -> wire.Document:
    """The measured audit document of the lab domain.

    The document is frozen and no test edits it, so it is read once.
    """
    return parsed(source_document())


@functools.lru_cache(maxsize=1)
def acl_measured() -> wire.Document:
    """The measured audit document of the lab domain with the ACL seeds.

    The document is the same domain read again after the seeded security
    descriptors were written to it.  It is frozen and no test edits it, so
    it is read once.
    """
    document = json.loads((FIXTURE_DIR / ACL_SOURCE).read_text(encoding="utf-8"))
    return parsed(document)


def variant(
    edit: Callable[[dict[str, Any]], None],
    source: str = AUDIT_SOURCE,
) -> wire.Document:
    """A variant of a measured document, edited by the test.

    The helper names the file it starts from: a variant of a measured
    document is never a document of its own.
    """
    document = json.loads((FIXTURE_DIR / source).read_text(encoding="utf-8"))
    edit(document)
    return parsed(document)


def rows_of(document: dict[str, Any], query_id: str) -> list[dict[str, Any]]:
    """The rows of one query of an edited document."""
    return document["queries"][query_id]["rows"]


def row_of(
    document: dict[str, Any], query_id: str, needle: str
) -> dict[str, Any]:
    """The row whose distinguished name holds the needle."""
    for row in rows_of(document, query_id):
        if needle.lower() in row["dn"].lower():
            return row
    raise AssertionError(f"the document holds no row with {needle}")


def set_attribute(
    document: dict[str, Any],
    query_id: str,
    needle: str,
    attribute: str,
    value: Any,
) -> None:
    """Set one attribute of one row of an edited document."""
    row_of(document, query_id, needle)["a"][attribute] = [str(value)]


def drop_attribute(
    document: dict[str, Any], query_id: str, needle: str, attribute: str
) -> None:
    """Take one attribute away from one row of an edited document."""
    row_of(document, query_id, needle)["a"].pop(attribute, None)


def drop_attribute_everywhere(
    document: dict[str, Any], query_id: str, attribute: str
) -> None:
    """Take one attribute away from every row of one query."""
    for row in rows_of(document, query_id):
        row["a"].pop(attribute, None)


def map_attribute(
    document: dict[str, Any],
    query_id: str,
    attribute: str,
    change: Callable[[int], int],
) -> None:
    """Change one attribute of every row that carries it."""
    for row in rows_of(document, query_id):
        if attribute in row["a"]:
            row["a"][attribute] = [
                str(change(int(value))) for value in row["a"][attribute]
            ]


def set_status(
    document: dict[str, Any],
    query_id: str,
    status: str,
    error_code: str = "access_denied",
) -> None:
    """Give one query of an edited document a status of its own."""
    block = document["queries"][query_id]
    block["status"] = status
    block["error_code"] = error_code


def drop_row(document: dict[str, Any], query_id: str, needle: str) -> None:
    """Take one row away from one query of an edited document."""
    rows = rows_of(document, query_id)
    for index, row in enumerate(rows):
        if needle.lower() in row["dn"].lower():
            del rows[index]
            return
    raise AssertionError(f"the document holds no row with {needle}")


def add_member(
    document: dict[str, Any], group_needle: str, member_dn: str
) -> None:
    """Add a member to a group of an edited document."""
    row = row_of(document, "groups", group_needle)
    row["a"].setdefault("member", []).append(member_dn)


def remove_member(
    document: dict[str, Any], group_needle: str, member_dn: str
) -> None:
    """Take a member out of a group of an edited document."""
    row = row_of(document, "groups", group_needle)
    members = row["a"].get("member", [])
    row["a"]["member"] = [
        value for value in members if value.lower() != member_dn.lower()
    ]


def sid_blob(sid: str) -> str:
    """The base64 of the binary SID, the way a collector reports it."""
    parts = sid.split("-")
    raw = bytearray([int(parts[1]), len(parts) - 3])
    raw += int(parts[2]).to_bytes(6, "big")
    for part in parts[3:]:
        raw += int(part).to_bytes(4, "little")
    return base64.b64encode(bytes(raw)).decode("ascii")


def filetime(moment: datetime) -> int:
    """The Windows FILETIME of a moment, the way a collector writes it.

    A FILETIME counts the hundred nanoseconds since the first of January
    of the year 1601, and the value of zero means "never".
    """
    epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
    return int((moment - epoch).total_seconds() * 10_000_000)


# A moment far enough in the past for every age the checks use, and the
# FILETIME of the moment the measured document was written: the day of
# the collection.
OLD = filetime(datetime(2020, 1, 1, tzinfo=timezone.utc))
RECENT = 134385437397003777

# The FILETIME of the first of January of the year 2000: a password that
# was set before that is older than any age the checks use.
YEAR_2000 = filetime(datetime(2000, 1, 1, tzinfo=timezone.utc))

# The account of the single sign-on of a hybrid tenant.  It is a computer
# object, so its name ends with the dollar sign of a computer account.
SINGLE_SIGN_ON_NAME = "AZUREADSSOACC$"

# The SID of the single sign-on computer the tests seed.
SINGLE_SIGN_ON_SID = f"{DOMAIN_SID}-1100"

# The SID of the synchronization account of the hybrid tenant the tests
# seed.  The lab domain has no free relative identifier below the bulk
# seeds, so the account takes one above them.
HYBRID_USER_SID = f"{DOMAIN_SID}-2720"

# The SID of a second synchronization account of the hybrid tenant.
HYBRID_USER_SID_TWO = f"{DOMAIN_SID}-2721"

# The SID of the account the measured audit ran as: the audit account of
# Newton's own setup.
AUDIT_ACCOUNT_SID = f"{DOMAIN_SID}-2719"

# The SID of an ordinary account of the measured domain, used by the
# tests that need an audit account that is not the audit account of
# Newton's setup.
ORDINARY_ACCOUNT_SID = f"{DOMAIN_SID}-1110"

# The line the result of AD-A-17 carries when the audit account of the
# run was skipped.
AUDIT_ACCOUNT_NOTE = (
    "the audit account of this run is not judged: Newton's setup gives it "
    "a random password nobody holds, and it signs in by key only"
)


def add_row(
    document: dict[str, Any], query_id: str, dn: str, **attrs: Any
) -> None:
    """Add a row to one query of an edited document."""
    values = {name: [str(value)] for name, value in attrs.items()}
    rows_of(document, query_id).append({"dn": dn, "a": values})


def add_managed_service_account(
    document: dict[str, Any],
    pwd_last_set: int = RECENT,
    readers: tuple[str, ...] = (f"{DOMAIN_SID}-1114",),
) -> None:
    """Add a group managed service account to an edited document.

    The membership of a managed service account is one security
    descriptor, so the readers are the trustees of its allowed ACEs.
    """
    aces = [
        ace(secdesc.ACCESS_ALLOWED_ACE, 0x00, 0x1, trustee)
        for trustee in readers
    ]
    add_row(
        document,
        "gmsa",
        "CN=seed-gmsa,OU=NewtonSeeds,DC=win,DC=newton,DC=test",
        **{
            "objectSid": sid_blob(f"{DOMAIN_SID}-1118"),
            "sAMAccountName": "seed-gmsa",
            "pwdLastSet": pwd_last_set,
            "servicePrincipalName": "HTTP/seed-gmsa.win.newton.test",
            "msDS-ManagedPasswordInterval": "30",
            "msDS-GroupMSAMembership": base64.b64encode(
                build(aces=aces)
            ).decode("ascii"),
        },
    )


def add_single_sign_on_computer(
    document: dict[str, Any], pwd_last_set: int = OLD
) -> None:
    """Add the single sign-on account of a hybrid tenant to a document.

    The account of the single sign-on of a tenant is a computer object.
    """
    add_row(
        document,
        "computers",
        "CN=AZUREADSSOACC,OU=NewtonSeeds,DC=win,DC=newton,DC=test",
        **{
            "objectSid": sid_blob(SINGLE_SIGN_ON_SID),
            "sAMAccountName": SINGLE_SIGN_ON_NAME,
            "userAccountControl": 4096,
            "pwdLastSet": pwd_last_set,
            "primaryGroupID": 515,
        },
    )


def add_hybrid_user(
    document: dict[str, Any],
    name: str,
    sid: str = HYBRID_USER_SID,
) -> None:
    """Add a synchronization account of a hybrid tenant to a document.

    The accounts of the cloud in the directory of the on-premises domain
    are users, and their name is the prefix the cloud gives them.
    """
    add_row(
        document,
        "users",
        f"CN={name},OU=NewtonSeeds,DC=win,DC=newton,DC=test",
        **{
            "objectSid": sid_blob(sid),
            "sAMAccountName": name,
            "userAccountControl": 512,
            "pwdLastSet": RECENT,
            "primaryGroupID": 513,
        },
    )


# ---- the checks ------------------------------------------------------------


def check_of(check_id: str) -> catalogue.Check:
    """The check of the catalogue with that id."""
    for check in accounts.CHECKS:
        if check.id == check_id:
            return check
    raise AssertionError(f"the catalogue holds no {check_id}")


def result_of(
    check: catalogue.Check,
    document: wire.Document,
    platform: str = "ad-windows",
) -> model.CheckResult:
    """The result of one check over one document, through the runner."""
    report = runner.run(document, platform, checks=[check])
    return report.results[0]


def finding_sids(result: model.CheckResult) -> list[str]:
    """The SIDs of every object of every finding of a result."""
    return [
        affected.sid
        for finding in result.findings
        for affected in finding.objects
        if affected.sid
    ]


def directory_strings(report: model.AuditReport) -> list[str]:
    """Every directory string the report holds."""
    strings: list[str] = []
    for result in report.results:
        for finding in result.findings:
            for affected in finding.objects:
                for text in (affected.name, affected.dn, affected.evidence):
                    if text:
                        strings.append(text)
    return strings


def assert_fix_holds_no_directory_text(
    check_id: str, document: wire.Document
) -> None:
    """The commands of the fix of a check hold no directory text.

    The renderer refuses a report that holds a directory string inside a
    command, so the rendering is the proof; the assertions below say what
    was looked for.
    """
    check = check_of(check_id)
    report = runner.run(document, "ad-windows", checks=[check])
    strings = directory_strings(report)
    rendered = render.render(report)
    for result in rendered["results"]:
        for finding in result["findings"]:
            for platform in ("windows", "samba"):
                step = finding["fix"][platform]
                for command in step["commands"]:
                    render.assert_no_directory_text(command, strings)
                    assert "{sid}" not in command
                    assert "{guid}" not in command


def fix_commands(
    check_id: str, document: wire.Document, platform: str = "windows"
) -> list[str]:
    """The command templates of the fix of a check, for one platform."""
    check = check_of(check_id)
    report = runner.run(document, "ad-windows", checks=[check])
    commands: list[str] = []
    for result in report.results:
        for finding in result.findings:
            if finding.fix is None:
                continue
            step = (
                finding.fix.windows
                if platform == "windows"
                else finding.fix.samba
            )
            commands.extend(step.commands)
    return commands


@functools.lru_cache(maxsize=1)
def command_documents() -> tuple[tuple[str, wire.Document], ...]:
    """The documents the fix commands of every check are read from.

    Every check needs a document that makes it find something, so that
    every fix of the module is read at least once.  The documents are
    frozen and no test edits them, so they are built once.
    """

    def enable_guest(document: dict[str, Any]) -> None:
        set_attribute(document, "users", "CN=Guest", "userAccountControl", 512)

    def primary_group(document: dict[str, Any]) -> None:
        set_attribute(
            document, "users", "CN=seed-nested", "primaryGroupID", 512
        )

    def key_credential(document: dict[str, Any]) -> None:
        admin = row_of(document, "users", "CN=Administrator")
        add_row(
            document,
            "keycred_presence",
            admin["dn"],
            objectSid=admin["a"]["objectSid"][0],
            distinguishedName=admin["dn"],
        )

    def descriptor(document: dict[str, Any]) -> None:
        blob = row_of(document, "protected_sds", "CN=Domain Admins")["a"][
            "nTSecurityDescriptor"
        ][0]
        set_attribute(
            document,
            "computers",
            "CN=seed-pc-kcd",
            "msDS-AllowedToActOnBehalfOfOtherIdentity",
            blob,
        )

    def sid_history(document: dict[str, Any]) -> None:
        set_attribute(
            document,
            "users",
            "CN=seed-nested",
            "sIDHistory",
            sid_blob("S-1-5-21-1-2-3-500"),
        )

    def password_attribute(document: dict[str, Any]) -> None:
        admin = row_of(document, "users", "CN=Administrator")
        add_row(
            document,
            "pw_attr_presence",
            admin["dn"],
            objectSid=admin["a"]["objectSid"][0],
        )

    def expired_account(document: dict[str, Any]) -> None:
        set_attribute(
            document, "users", "CN=seed-svc-spn", "accountExpires", OLD
        )

    def old_service_password(document: dict[str, Any]) -> None:
        set_attribute(document, "users", "CN=seed-svc-spn", "pwdLastSet", OLD)
        add_managed_service_account(document)

    def stale_user(document: dict[str, Any]) -> None:
        set_attribute(
            document,
            "users",
            "CN=seed-neverlogon",
            "whenCreated",
            "20200101000000.0Z",
        )

    def stale_computer(document: dict[str, Any]) -> None:
        set_attribute(document, "computers", "CN=WINMEMBER1", "pwdLastSet", OLD)

    def smart_card(document: dict[str, Any]) -> None:
        set_attribute(
            document,
            "users",
            "CN=seed-svc-spn",
            "userAccountControl",
            512 | 0x00040000,
        )
        set_attribute(document, "users", "CN=seed-svc-spn", "pwdLastSet", OLD)

    def old_krbtgt(document: dict[str, Any]) -> None:
        set_attribute(document, "users", "CN=krbtgt", "pwdLastSet", OLD)

    def everyone_in_the_group(document: dict[str, Any]) -> None:
        add_row(
            document,
            "fsps",
            "CN=S-1-1-0,CN=ForeignSecurityPrincipals,"
            "DC=win,DC=newton,DC=test",
            objectSid=sid_blob("S-1-1-0"),
        )
        add_member(
            document,
            "CN=Pre-Windows 2000 Compatible Access",
            "CN=S-1-1-0,CN=ForeignSecurityPrincipals,"
            "DC=win,DC=newton,DC=test",
        )

    def hybrid_account(document: dict[str, Any]) -> None:
        add_single_sign_on_computer(document, OLD)

    def read_only_controller(document: dict[str, Any]) -> None:
        set_attribute(document, "computers", "CN=WINMEMBER1", "primaryGroupID", 521)
        add_member(
            document,
            "CN=Allowed RODC Password Replication Group",
            "CN=Administrator,CN=Users,DC=win,DC=newton,DC=test",
        )

    return (
        ("AD-A-01", measured()),
        ("AD-A-02", variant(enable_guest)),
        ("AD-A-03", measured()),
        ("AD-A-04", variant(primary_group)),
        ("AD-A-05", measured()),
        ("AD-A-06", measured()),
        ("AD-A-07", measured()),
        ("AD-A-08", measured()),
        ("AD-A-09", measured()),
        ("AD-A-10", variant(key_credential)),
        ("AD-A-11", measured()),
        ("AD-A-12", measured()),
        ("AD-A-13", variant(descriptor)),
        ("AD-A-14", measured()),
        ("AD-A-16", measured()),
        ("AD-A-17", measured()),
        ("AD-A-18", measured()),
        ("AD-A-19", variant(sid_history)),
        ("AD-A-20", variant(password_attribute)),
        ("AD-A-21", measured()),
        ("AD-A-22", variant(expired_account)),
        ("AD-A-23", variant(old_service_password)),
        ("AD-A-24", variant(stale_user)),
        ("AD-A-25", variant(stale_computer)),
        ("AD-A-26", variant(smart_card)),
        ("AD-A-27", variant(old_krbtgt)),
        ("AD-A-30", variant(everyone_in_the_group)),
        ("AD-A-31", variant(hybrid_account)),
        ("AD-A-32", variant(read_only_controller)),
    )


# ---- AD-A-01: the built-in administrator -----------------------------------


def test_ad_a_01_finds_the_administrator_of_the_measured_document() -> None:
    """The built-in administrator of the lab domain is enabled."""
    result = result_of(check_of("AD-A-01"), measured())

    assert result.status == model.Status.FINDING
    assert f"{DOMAIN_SID}-500" in finding_sids(result)


def test_ad_a_01_passes_when_the_account_is_disabled() -> None:
    """A disabled built-in administrator is no finding."""

    def edit(document: dict[str, Any]) -> None:
        set_attribute(document, "users", "CN=Administrator", "userAccountControl", 514)

    result = result_of(check_of("AD-A-01"), variant(edit))

    assert result.status == model.Status.PASS
    assert result.findings == ()


def test_ad_a_01_is_unknown_when_a_required_attribute_is_missing() -> None:
    """An account without a readable userAccountControl proves nothing."""

    def edit(document: dict[str, Any]) -> None:
        drop_attribute(document, "users", "CN=Administrator", "userAccountControl")

    result = result_of(check_of("AD-A-01"), variant(edit))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ACCESS_DENIED


def test_ad_a_01_the_fix_holds_no_directory_text() -> None:
    """The fix of AD-A-01 names the account by its SID only."""
    assert_fix_holds_no_directory_text("AD-A-01", measured())


# ---- AD-A-02: the built-in guest -------------------------------------------


def test_ad_a_02_passes_on_the_measured_document() -> None:
    """The built-in guest of the lab domain is disabled."""
    result = result_of(check_of("AD-A-02"), measured())

    assert result.status == model.Status.PASS
    assert result.findings == ()


def test_ad_a_02_is_unknown_when_the_guest_row_is_missing() -> None:
    """A document without the guest account proves nothing about it."""

    def edit(document: dict[str, Any]) -> None:
        drop_row(document, "users", "CN=Guest")

    result = result_of(check_of("AD-A-02"), variant(edit))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ACCESS_DENIED


def test_ad_a_02_finds_an_enabled_guest() -> None:
    """An enabled guest account is a finding."""

    def edit(document: dict[str, Any]) -> None:
        set_attribute(document, "users", "CN=Guest", "userAccountControl", 512)

    result = result_of(check_of("AD-A-02"), variant(edit))

    assert result.status == model.Status.FINDING
    assert f"{DOMAIN_SID}-501" in finding_sids(result)


def test_ad_a_02_is_unknown_when_a_required_attribute_is_missing() -> None:
    """An account without a readable userAccountControl proves nothing."""

    def edit(document: dict[str, Any]) -> None:
        drop_attribute(document, "users", "CN=Guest", "userAccountControl")

    result = result_of(check_of("AD-A-02"), variant(edit))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ACCESS_DENIED


def test_ad_a_02_the_fix_holds_no_directory_text() -> None:
    """The fix of AD-A-02 names the account by its SID only."""

    def edit(document: dict[str, Any]) -> None:
        set_attribute(document, "users", "CN=Guest", "userAccountControl", 512)

    assert_fix_holds_no_directory_text("AD-A-02", variant(edit))


# ---- AD-A-03: the inventory of the privileged groups -----------------------


def test_ad_a_03_finds_the_seeded_nested_member() -> None:
    """The nested seed account sits in the privileged group of the lab."""
    result = result_of(check_of("AD-A-03"), measured())

    assert result.status == model.Status.FINDING
    assert f"{DOMAIN_SID}-1114" in finding_sids(result)


def test_ad_a_03_reports_the_inventory_of_the_privileged_groups() -> None:
    """The note of AD-A-03 holds the group and its member count."""
    result = result_of(check_of("AD-A-03"), measured())

    assert "Domain Admins" in result.note
    assert "recursive member counts" in result.note


def test_ad_a_03_is_unknown_when_a_member_resolves_to_no_object() -> None:
    """A privileged group that hides a member proves nothing.

    The seeded group of the chain is gone from the document, so the
    member value of the domain admins group names an object the audit
    cannot see.  The check counts those members and never names them.
    """

    def edit(document: dict[str, Any]) -> None:
        drop_row(document, "groups", "CN=seed-group-b")

    result = result_of(check_of("AD-A-03"), variant(edit))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ACCESS_DENIED
    assert "1 member value" in result.note
    assert "seed-group-b" not in result.note


def test_ad_a_03_passes_when_the_privileged_groups_hold_no_one_else() -> None:
    """A privileged group that holds only its default members is no finding."""

    def edit(document: dict[str, Any]) -> None:
        remove_member(
            document,
            "CN=Domain Admins",
            "CN=seed-group-b,OU=NewtonSeeds,DC=win,DC=newton,DC=test",
        )
        remove_member(
            document,
            "CN=seed-group-b",
            "CN=seed-group-a,OU=NewtonSeeds,DC=win,DC=newton,DC=test",
        )

    result = result_of(check_of("AD-A-03"), variant(edit))

    assert result.status == model.Status.PASS
    assert result.findings == ()


def test_ad_a_03_is_unknown_when_a_required_attribute_is_missing() -> None:
    """A readable object without a required attribute proves nothing."""

    def edit(document: dict[str, Any]) -> None:
        drop_attribute(document, "users", "CN=seed-nested", "sAMAccountName")

    result = result_of(check_of("AD-A-03"), variant(edit))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ACCESS_DENIED


def test_ad_a_03_the_fix_holds_no_directory_text() -> None:
    """The fix of AD-A-03 names the group by its SID only."""
    assert_fix_holds_no_directory_text("AD-A-03", measured())


def test_ad_a_03_the_fix_explains_the_change() -> None:
    """The fix of AD-A-03 explains and runs no command at all."""
    assert fix_commands("AD-A-03", measured(), "windows") == []
    assert fix_commands("AD-A-03", measured(), "samba") == []


# ---- AD-A-04: the privilege of a primary group ----------------------------


def test_ad_a_04_passes_on_the_measured_document() -> None:
    """No account of the lab domain has a privileged primary group."""

    def edit(document: dict[str, Any]) -> None:
        map_attribute(document, "users", "primaryGroupID", lambda value: 513)

    result = result_of(check_of("AD-A-04"), variant(edit))

    assert result.status == model.Status.PASS
    assert result.findings == ()


def test_ad_a_04_finds_an_account_with_a_privileged_primary_group() -> None:
    """An account whose primary group is a privileged group is a finding."""

    def edit(document: dict[str, Any]) -> None:
        set_attribute(document, "users", "CN=seed-nested", "primaryGroupID", 512)

    result = result_of(check_of("AD-A-04"), variant(edit))

    assert result.status == model.Status.FINDING
    assert f"{DOMAIN_SID}-1114" in finding_sids(result)


def test_ad_a_04_is_unknown_when_a_required_attribute_is_missing() -> None:
    """A readable object without a required attribute proves nothing."""

    def edit(document: dict[str, Any]) -> None:
        drop_attribute(document, "users", "CN=seed-nested", "primaryGroupID")

    result = result_of(check_of("AD-A-04"), variant(edit))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ACCESS_DENIED


def test_ad_a_04_the_fix_holds_no_directory_text() -> None:
    """The fix of AD-A-04 names the account by its SID only."""

    def edit(document: dict[str, Any]) -> None:
        set_attribute(document, "users", "CN=seed-nested", "primaryGroupID", 512)

    assert_fix_holds_no_directory_text("AD-A-04", variant(edit))


def test_ad_a_04_the_windows_fix_replaces_the_primary_group() -> None:
    """The primary group is written with the replace form of the module."""

    def edit(document: dict[str, Any]) -> None:
        set_attribute(document, "users", "CN=seed-nested", "primaryGroupID", 512)

    commands = fix_commands("AD-A-04", variant(edit), "windows")

    assert commands == [
        "Set-ADUser -Identity '{sid}' -Replace @{primaryGroupID=513}"
    ]


# ---- AD-A-05: the adminCount orphans ---------------------------------------


def test_ad_a_05_finds_the_seeded_admincount_account() -> None:
    """The seeded account holds adminCount without a protected membership."""
    result = result_of(check_of("AD-A-05"), measured())

    assert result.status == model.Status.FINDING
    assert f"{DOMAIN_SID}-1115" in finding_sids(result)


def test_ad_a_05_leaves_the_key_distribution_account_alone() -> None:
    """The key distribution account of the domain is a protected one."""
    result = result_of(check_of("AD-A-05"), measured())

    assert f"{DOMAIN_SID}-502" not in finding_sids(result)


def test_ad_a_05_leaves_a_protected_member_alone() -> None:
    """An account in a protected group is no orphan of the check."""

    def edit(document: dict[str, Any]) -> None:
        set_attribute(document, "users", "CN=seed-nested", "adminCount", 1)

    result = result_of(check_of("AD-A-05"), variant(edit))

    assert result.status == model.Status.FINDING
    assert f"{DOMAIN_SID}-1114" not in finding_sids(result)
    assert f"{DOMAIN_SID}-1115" in finding_sids(result)


def test_ad_a_05_passes_when_no_account_holds_admincount() -> None:
    """An account without adminCount is no finding."""

    def edit(document: dict[str, Any]) -> None:
        drop_attribute_everywhere(document, "users", "adminCount")

    result = result_of(check_of("AD-A-05"), variant(edit))

    assert result.status == model.Status.PASS
    assert result.findings == ()


def test_ad_a_05_is_unknown_when_a_required_attribute_is_missing() -> None:
    """A readable object without a required attribute proves nothing."""

    def edit(document: dict[str, Any]) -> None:
        drop_attribute(document, "users", "CN=seed-admincount", "sAMAccountName")

    result = result_of(check_of("AD-A-05"), variant(edit))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ACCESS_DENIED


def test_ad_a_05_the_fix_holds_no_directory_text() -> None:
    """The fix of AD-A-05 names the account by its SID only."""
    assert_fix_holds_no_directory_text("AD-A-05", measured())


def test_ad_a_05_the_windows_fix_names_the_account_with_set_aduser() -> None:
    """The adminCount is written with the cmdlet of a user."""

    def edit(document: dict[str, Any]) -> None:
        set_attribute(document, "users", "CN=seed-admincount", "adminCount", 1)

    commands = fix_commands("AD-A-05", variant(edit), "windows")

    assert commands == [
        "Set-ADUser -Identity '{sid}' -Replace @{adminCount=0}"
    ]


# ---- AD-A-06: the privileged accounts outside the protected users ----------


def test_ad_a_06_finds_the_privileged_accounts() -> None:
    """The privileged accounts of the lab domain are not protected users."""
    result = result_of(check_of("AD-A-06"), measured())

    assert result.status == model.Status.FINDING
    assert f"{DOMAIN_SID}-500" in finding_sids(result)
    assert f"{DOMAIN_SID}-1114" in finding_sids(result)


def test_ad_a_06_passes_when_every_privileged_account_is_protected() -> None:
    """A privileged account inside the protected users group is no finding."""

    def edit(document: dict[str, Any]) -> None:
        add_member(
            document,
            "CN=Protected Users",
            "CN=Administrator,CN=Users,DC=win,DC=newton,DC=test",
        )
        add_member(
            document,
            "CN=Protected Users",
            "CN=seed-nested,OU=NewtonSeeds,DC=win,DC=newton,DC=test",
        )

    result = result_of(check_of("AD-A-06"), variant(edit))

    assert result.status == model.Status.PASS
    assert result.findings == ()


def test_ad_a_06_is_unknown_when_a_required_attribute_is_missing() -> None:
    """A readable object without a required attribute proves nothing."""

    def edit(document: dict[str, Any]) -> None:
        drop_attribute(document, "users", "CN=seed-nested", "sAMAccountName")

    result = result_of(check_of("AD-A-06"), variant(edit))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ACCESS_DENIED


def test_ad_a_06_the_fix_holds_no_directory_text() -> None:
    """The fix of AD-A-06 names the account by its SID only."""
    assert_fix_holds_no_directory_text("AD-A-06", measured())


def test_ad_a_06_the_samba_fix_adds_the_member_with_ldbmodify() -> None:
    """The Samba step adds the account to the protected users group."""
    commands = fix_commands("AD-A-06", measured(), "samba")

    assert commands
    for command in commands:
        assert "ldbmodify" in command
        assert "add: member" in command
        assert "member: <SID={sid}>" in command


# ---- AD-A-07: the roastable service accounts -------------------------------


def test_ad_a_07_finds_the_seeded_service_account() -> None:
    """The seeded service account carries a service principal name."""
    result = result_of(check_of("AD-A-07"), measured())

    assert result.status == model.Status.FINDING
    assert f"{DOMAIN_SID}-1105" in finding_sids(result)


def test_ad_a_07_is_a_medium_finding_for_an_ordinary_service_account() -> None:
    """The ticket of an account that is not privileged is a medium finding."""
    result = result_of(check_of("AD-A-07"), measured())

    assert result.findings[0].severity == model.Severity.MEDIUM


def test_ad_a_07_is_a_high_finding_for_a_privileged_service_account() -> None:
    """The ticket of a privileged account is a high finding."""

    def edit(document: dict[str, Any]) -> None:
        add_member(
            document,
            "CN=Domain Admins",
            "CN=seed-svc-spn,OU=NewtonSeeds,DC=win,DC=newton,DC=test",
        )

    result = result_of(check_of("AD-A-07"), variant(edit))

    assert result.status == model.Status.FINDING
    assert result.findings[0].severity == model.Severity.HIGH


def test_ad_a_07_leaves_the_key_distribution_account_alone() -> None:
    """The key distribution account of the domain is not a finding."""

    def edit(document: dict[str, Any]) -> None:
        drop_attribute_everywhere(document, "users", "servicePrincipalName")

    result = result_of(check_of("AD-A-07"), variant(edit))

    assert result.status == model.Status.PASS
    assert result.findings == ()


def test_ad_a_07_is_unknown_when_a_required_attribute_is_missing() -> None:
    """A readable object without a required attribute proves nothing."""

    def edit(document: dict[str, Any]) -> None:
        drop_attribute(document, "users", "CN=seed-svc-spn", "sAMAccountName")

    result = result_of(check_of("AD-A-07"), variant(edit))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ACCESS_DENIED


def test_ad_a_07_the_fix_holds_no_directory_text() -> None:
    """The fix of AD-A-07 names the account by its SID only."""
    assert_fix_holds_no_directory_text("AD-A-07", measured())


# ---- AD-A-08: the accounts without pre-authentication ----------------------


def test_ad_a_08_finds_the_seeded_account() -> None:
    """The seeded account does without Kerberos pre-authentication."""
    result = result_of(check_of("AD-A-08"), measured())

    assert result.status == model.Status.FINDING
    assert f"{DOMAIN_SID}-1106" in finding_sids(result)


def test_ad_a_08_passes_when_every_account_requires_pre_authentication() -> None:
    """An account that requires pre-authentication is no finding."""

    def edit(document: dict[str, Any]) -> None:
        map_attribute(
            document,
            "users",
            "userAccountControl",
            lambda value: value & ~0x00400000,
        )

    result = result_of(check_of("AD-A-08"), variant(edit))

    assert result.status == model.Status.PASS
    assert result.findings == ()


def test_ad_a_08_is_unknown_when_a_required_attribute_is_missing() -> None:
    """A readable object without a required attribute proves nothing."""

    def edit(document: dict[str, Any]) -> None:
        drop_attribute(document, "users", "CN=seed-nopreauth", "userAccountControl")

    result = result_of(check_of("AD-A-08"), variant(edit))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ACCESS_DENIED


def test_ad_a_08_the_fix_holds_no_directory_text() -> None:
    """The fix of AD-A-08 names the account by its SID only."""
    assert_fix_holds_no_directory_text("AD-A-08", measured())


# ---- AD-A-09: the delegable privileged accounts ---------------------------


def test_ad_a_09_finds_the_privileged_accounts() -> None:
    """The privileged accounts of the lab domain may be delegated."""
    result = result_of(check_of("AD-A-09"), measured())

    assert result.status == model.Status.FINDING
    assert f"{DOMAIN_SID}-500" in finding_sids(result)
    assert f"{DOMAIN_SID}-1114" in finding_sids(result)


def test_ad_a_09_passes_when_no_privileged_account_may_be_delegated() -> None:
    """A privileged account with the delegation bit is no finding."""

    def edit(document: dict[str, Any]) -> None:
        map_attribute(
            document,
            "users",
            "userAccountControl",
            lambda value: value | 0x00100000,
        )

    result = result_of(check_of("AD-A-09"), variant(edit))

    assert result.status == model.Status.PASS
    assert result.findings == ()


def test_ad_a_09_leaves_a_protected_user_alone() -> None:
    """A member of the protected users group cannot be delegated."""

    def edit(document: dict[str, Any]) -> None:
        add_member(
            document,
            "CN=Protected Users",
            "CN=Administrator,CN=Users,DC=win,DC=newton,DC=test",
        )

    result = result_of(check_of("AD-A-09"), variant(edit))

    assert result.status == model.Status.FINDING
    assert f"{DOMAIN_SID}-500" not in finding_sids(result)
    assert f"{DOMAIN_SID}-1114" in finding_sids(result)


def test_ad_a_09_is_unknown_when_a_required_attribute_is_missing() -> None:
    """A readable object without a required attribute proves nothing."""

    def edit(document: dict[str, Any]) -> None:
        drop_attribute(document, "users", "CN=seed-nested", "sAMAccountName")

    result = result_of(check_of("AD-A-09"), variant(edit))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ACCESS_DENIED


def test_ad_a_09_the_fix_holds_no_directory_text() -> None:
    """The fix of AD-A-09 names the account by its SID only."""
    assert_fix_holds_no_directory_text("AD-A-09", measured())


def test_ad_a_09_the_windows_fix_sets_the_account_not_delegated() -> None:
    """The delegation bit is written with the parameter of the module."""
    commands = fix_commands("AD-A-09", measured(), "windows")

    assert commands
    for command in commands:
        assert command == (
            "Set-ADAccountControl -Identity '{sid}' -AccountNotDelegated $true"
        )


# ---- AD-A-10: the shadow credentials ---------------------------------------


def test_ad_a_10_is_unknown_when_no_key_credential_is_visible() -> None:
    """An empty presence query is "could not read", never PASS."""
    result = result_of(check_of("AD-A-10"), measured())

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ACCESS_DENIED


def test_ad_a_10_passes_when_the_collector_reads_everything() -> None:
    """A Samba collector reads as root: an empty result is a real empty."""

    def edit(document: dict[str, Any]) -> None:
        document["collector"] = "samba"
        document["settings"]["items"] = docs.settings_items("samba")

    result = result_of(check_of("AD-A-10"), variant(edit), "ad-samba")

    assert result.status == model.Status.PASS
    assert result.findings == ()


def test_ad_a_10_finds_an_object_with_a_key_credential() -> None:
    """An object that holds a key credential link is a finding."""

    def edit(document: dict[str, Any]) -> None:
        admin = row_of(document, "users", "CN=Administrator")
        add_row(
            document,
            "keycred_presence",
            admin["dn"],
            objectSid=admin["a"]["objectSid"][0],
            distinguishedName=admin["dn"],
        )

    result = result_of(check_of("AD-A-10"), variant(edit))

    assert result.status == model.Status.FINDING
    assert f"{DOMAIN_SID}-500" in finding_sids(result)


def test_ad_a_10_is_unknown_when_the_query_did_not_complete() -> None:
    """A presence query that did not complete proves nothing."""

    def edit(document: dict[str, Any]) -> None:
        set_status(document, "keycred_presence", "denied", "access_denied")

    result = result_of(check_of("AD-A-10"), variant(edit))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ACCESS_DENIED


def test_ad_a_10_the_fix_holds_no_directory_text() -> None:
    """The fix of AD-A-10 names the object by its SID only."""

    def edit(document: dict[str, Any]) -> None:
        admin = row_of(document, "users", "CN=Administrator")
        add_row(
            document,
            "keycred_presence",
            admin["dn"],
            objectSid=admin["a"]["objectSid"][0],
            distinguishedName=admin["dn"],
        )

    assert_fix_holds_no_directory_text("AD-A-10", variant(edit))


def test_ad_a_10_the_windows_fix_names_the_object_with_its_own_cmdlet() -> None:
    """The key credential link is taken off with the cmdlet of the object."""

    def edit(document: dict[str, Any]) -> None:
        admin = row_of(document, "users", "CN=Administrator")
        add_row(
            document,
            "keycred_presence",
            admin["dn"],
            objectSid=admin["a"]["objectSid"][0],
            distinguishedName=admin["dn"],
        )

    commands = fix_commands("AD-A-10", variant(edit), "windows")

    assert commands == [
        "Set-ADUser -Identity '{sid}' -Clear 'msDS-KeyCredentialLink'"
    ]


# ---- AD-A-11: the unconstrained delegation ---------------------------------


def test_ad_a_11_finds_the_seeded_computer() -> None:
    """The seeded computer is trusted for unconstrained delegation."""
    result = result_of(check_of("AD-A-11"), measured())

    assert result.status == model.Status.FINDING
    assert f"{DOMAIN_SID}-1116" in finding_sids(result)


def test_ad_a_11_leaves_the_domain_controller_alone() -> None:
    """A domain controller is trusted for delegation by the design.

    The seeded computer gives the delegation bit up and the domain
    controller of the lab keeps it: a domain controller is a server
    trust account, and the check never names it.
    """

    def edit(document: dict[str, Any]) -> None:
        set_attribute(
            document, "computers", "CN=seed-pc-unc", "userAccountControl", 4096
        )

    result = result_of(check_of("AD-A-11"), variant(edit))

    assert result.status == model.Status.PASS
    assert result.findings == ()
    assert f"{DOMAIN_SID}-1000" not in finding_sids(result)


def test_ad_a_11_is_unknown_when_the_query_did_not_complete() -> None:
    """A query that did not complete proves nothing."""

    def edit(document: dict[str, Any]) -> None:
        set_status(document, "computers", "denied", "access_denied")

    result = result_of(check_of("AD-A-11"), variant(edit))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ACCESS_DENIED


def test_ad_a_11_the_fix_holds_no_directory_text() -> None:
    """The fix of AD-A-11 names the computer by its SID only."""
    assert_fix_holds_no_directory_text("AD-A-11", measured())


# ---- AD-A-12: the constrained delegation -----------------------------------


def test_ad_a_12_finds_the_seeded_computer() -> None:
    """The seeded computer is configured for constrained delegation."""
    result = result_of(check_of("AD-A-12"), measured())

    assert result.status == model.Status.FINDING
    assert f"{DOMAIN_SID}-1117" in finding_sids(result)


def test_ad_a_12_is_a_lower_finding_without_the_protocol_transition() -> None:
    """A delegation target without the transition bit is a medium finding."""
    result = result_of(check_of("AD-A-12"), measured())

    assert result.findings[0].severity == model.Severity.MEDIUM


def test_ad_a_12_is_a_higher_finding_with_the_protocol_transition() -> None:
    """A delegation target with the transition bit is a high finding."""

    def edit(document: dict[str, Any]) -> None:
        set_attribute(
            document,
            "computers",
            "CN=seed-pc-kcd",
            "userAccountControl",
            4096 | 0x01000000,
        )

    result = result_of(check_of("AD-A-12"), variant(edit))

    assert result.status == model.Status.FINDING
    assert result.findings[0].severity == model.Severity.HIGH


def test_ad_a_12_passes_when_no_computer_holds_a_delegation_target() -> None:
    """A computer without a delegation target is no finding."""

    def edit(document: dict[str, Any]) -> None:
        drop_attribute_everywhere(
            document, "computers", "msDS-AllowedToDelegateTo"
        )

    result = result_of(check_of("AD-A-12"), variant(edit))

    assert result.status == model.Status.PASS
    assert result.findings == ()


def test_ad_a_12_is_unknown_when_the_query_did_not_complete() -> None:
    """A query that did not complete proves nothing."""

    def edit(document: dict[str, Any]) -> None:
        set_status(document, "computers", "denied", "access_denied")

    result = result_of(check_of("AD-A-12"), variant(edit))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ACCESS_DENIED


def test_ad_a_12_the_fix_holds_no_directory_text() -> None:
    """The fix of AD-A-12 names the computer by its SID only."""
    assert_fix_holds_no_directory_text("AD-A-12", measured())


# ---- AD-A-13: the resource-based constrained delegation --------------------


def test_ad_a_13_passes_on_the_measured_document() -> None:
    """No computer of the lab domain holds a delegation descriptor."""

    def edit(document: dict[str, Any]) -> None:
        drop_attribute_everywhere(
            document, "computers", "msDS-AllowedToActOnBehalfOfOtherIdentity"
        )

    result = result_of(check_of("AD-A-13"), variant(edit))

    assert result.status == model.Status.PASS
    assert result.findings == ()


def test_ad_a_13_finds_a_computer_with_a_descriptor() -> None:
    """A computer that holds a descriptor names the trustees inside it."""

    def edit(document: dict[str, Any]) -> None:
        blob = row_of(document, "protected_sds", "CN=Domain Admins")["a"][
            "nTSecurityDescriptor"
        ][0]
        set_attribute(
            document,
            "computers",
            "CN=seed-pc-kcd",
            "msDS-AllowedToActOnBehalfOfOtherIdentity",
            blob,
        )

    result = result_of(check_of("AD-A-13"), variant(edit))

    assert result.status == model.Status.FINDING
    assert f"{DOMAIN_SID}-1117" in finding_sids(result)
    assert "trustees" in (result.findings[0].objects[0].evidence or "")


def test_ad_a_13_is_unknown_when_the_query_did_not_complete() -> None:
    """A query that did not complete proves nothing."""

    def edit(document: dict[str, Any]) -> None:
        set_status(document, "computers", "denied", "access_denied")

    result = result_of(check_of("AD-A-13"), variant(edit))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ACCESS_DENIED


def test_ad_a_13_the_fix_holds_no_directory_text() -> None:
    """The fix of AD-A-13 names the computer by its SID only."""

    def edit(document: dict[str, Any]) -> None:
        blob = row_of(document, "protected_sds", "CN=Domain Admins")["a"][
            "nTSecurityDescriptor"
        ][0]
        set_attribute(
            document,
            "computers",
            "CN=seed-pc-kcd",
            "msDS-AllowedToActOnBehalfOfOtherIdentity",
            blob,
        )

    assert_fix_holds_no_directory_text("AD-A-13", variant(edit))


# ---- AD-A-14: the weak Kerberos encryption types ---------------------------


def test_ad_a_14_finds_the_seeded_account() -> None:
    """The seeded account offers RC4 only."""
    result = result_of(check_of("AD-A-14"), measured())

    assert result.status == model.Status.FINDING
    assert f"{DOMAIN_SID}-1110" in finding_sids(result)


def test_ad_a_14_finds_a_service_account_that_leaves_the_types_to_the_domain() -> None:
    """A service account without the attribute takes the default of the domain.

    The default of the domain is not in the query set of the audit, so a
    service account that sets no encryption type is a finding.
    """
    result = result_of(check_of("AD-A-14"), measured())

    assert result.status == model.Status.FINDING
    assert f"{DOMAIN_SID}-1105" in finding_sids(result)


def test_ad_a_14_leaves_the_key_distribution_account_alone() -> None:
    """The key distribution account of the domain is left alone."""
    result = result_of(check_of("AD-A-14"), measured())

    assert f"{DOMAIN_SID}-502" not in finding_sids(result)


def test_ad_a_14_leaves_a_disabled_account_alone() -> None:
    """A disabled account asks for no ticket."""

    def edit(document: dict[str, Any]) -> None:
        set_attribute(
            document, "users", "CN=seed-legacyenc", "userAccountControl", 514
        )

    result = result_of(check_of("AD-A-14"), variant(edit))

    assert result.status == model.Status.FINDING
    assert f"{DOMAIN_SID}-1110" not in finding_sids(result)


def test_ad_a_14_finds_the_seeded_user_accounts() -> None:
    """The service account and the legacy account of the lab are findings.

    The service account sets no encryption type at all and takes the
    default of the domain, and the legacy account offers RC4 only.
    """
    result = result_of(check_of("AD-A-14"), measured())

    assert result.status == model.Status.FINDING
    assert f"{DOMAIN_SID}-1105" in finding_sids(result)
    assert f"{DOMAIN_SID}-1110" in finding_sids(result)


def test_ad_a_14_leaves_a_computer_that_takes_the_domain_default_alone() -> None:
    """A computer that sets no encryption type is not judged by the default.

    The computer account of the lab gets a host service principal name and
    keeps no msDS-SupportedEncryptionTypes: it takes the default of the
    domain, and a computer account is judged by the value it sets only.
    """

    def edit(document: dict[str, Any]) -> None:
        set_attribute(
            document,
            "computers",
            "CN=seed-pc-unc",
            "servicePrincipalName",
            "HOST/seed-pc-unc.win.newton.test",
        )

    result = result_of(check_of("AD-A-14"), variant(edit))

    assert f"{DOMAIN_SID}-1116" not in finding_sids(result)


def test_ad_a_14_finds_a_computer_with_weak_encryption_types() -> None:
    """A computer that offers RC4 without AES is a finding."""

    def edit(document: dict[str, Any]) -> None:
        set_attribute(
            document,
            "computers",
            "CN=seed-pc-unc",
            "msDS-SupportedEncryptionTypes",
            4,
        )

    result = result_of(check_of("AD-A-14"), variant(edit))

    assert f"{DOMAIN_SID}-1116" in finding_sids(result)


def test_ad_a_14_leaves_a_computer_with_aes_alone() -> None:
    """A computer that offers AES is no finding."""

    def edit(document: dict[str, Any]) -> None:
        set_attribute(
            document,
            "computers",
            "CN=seed-pc-unc",
            "msDS-SupportedEncryptionTypes",
            24,
        )

    result = result_of(check_of("AD-A-14"), variant(edit))

    assert f"{DOMAIN_SID}-1116" not in finding_sids(result)


def test_ad_a_14_passes_when_every_account_offers_aes() -> None:
    """An account that offers AES only is no finding."""

    def edit(document: dict[str, Any]) -> None:
        for query_id in ("users", "computers"):
            for row in rows_of(document, query_id):
                attributes = row["a"]
                if (
                    "msDS-SupportedEncryptionTypes" in attributes
                    or attributes.get("servicePrincipalName")
                ):
                    attributes["msDS-SupportedEncryptionTypes"] = ["24"]

    result = result_of(check_of("AD-A-14"), variant(edit))

    assert result.status == model.Status.PASS
    assert result.findings == ()


def test_ad_a_14_is_unknown_when_the_query_did_not_complete() -> None:
    """A query that did not complete proves nothing."""

    def edit(document: dict[str, Any]) -> None:
        set_status(document, "computers", "denied", "access_denied")

    result = result_of(check_of("AD-A-14"), variant(edit))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ACCESS_DENIED


def test_ad_a_14_the_fix_holds_no_directory_text() -> None:
    """The fix of AD-A-14 names the account by its SID only."""
    assert_fix_holds_no_directory_text("AD-A-14", measured())


# ---- AD-A-16: the accounts that need no password ---------------------------


def test_ad_a_16_finds_the_seeded_account() -> None:
    """The seeded account does not require a password."""
    result = result_of(check_of("AD-A-16"), measured())

    assert result.status == model.Status.FINDING
    assert f"{DOMAIN_SID}-1107" in finding_sids(result)


def test_ad_a_16_leaves_the_guest_alone() -> None:
    """The built-in guest is the business of AD-A-02."""
    result = result_of(check_of("AD-A-16"), measured())

    assert f"{DOMAIN_SID}-501" not in finding_sids(result)


def test_ad_a_16_leaves_a_trust_account_alone() -> None:
    """The password of an interdomain trust account belongs to the trust."""

    def edit(document: dict[str, Any]) -> None:
        add_row(
            document,
            "users",
            "CN=seed-trust,OU=NewtonSeeds,DC=win,DC=newton,DC=test",
            objectSid=sid_blob(f"{DOMAIN_SID}-5900"),
            sAMAccountName="seed-trust",
            userAccountControl=0x800 | 0x20,
        )

    result = result_of(check_of("AD-A-16"), variant(edit))

    assert result.status == model.Status.FINDING
    assert f"{DOMAIN_SID}-5900" not in finding_sids(result)


def test_ad_a_16_is_a_low_finding_for_a_disabled_account() -> None:
    """A disabled account cannot be used with an empty password."""

    def edit(document: dict[str, Any]) -> None:
        set_attribute(
            document, "users", "CN=seed-pwnotreq", "userAccountControl", 546
        )

    result = result_of(check_of("AD-A-16"), variant(edit))

    assert result.status == model.Status.FINDING
    assert result.findings[0].severity == model.Severity.LOW
    assert "disabled" in result.note


def test_ad_a_16_passes_when_every_account_requires_a_password() -> None:
    """An account that requires a password is no finding."""

    def edit(document: dict[str, Any]) -> None:
        map_attribute(
            document,
            "users",
            "userAccountControl",
            lambda value: value & ~0x00000020,
        )

    result = result_of(check_of("AD-A-16"), variant(edit))

    assert result.status == model.Status.PASS
    assert result.findings == ()


def test_ad_a_16_is_unknown_when_a_required_attribute_is_missing() -> None:
    """A readable object without a required attribute proves nothing."""

    def edit(document: dict[str, Any]) -> None:
        drop_attribute(document, "users", "CN=seed-pwnotreq", "userAccountControl")

    result = result_of(check_of("AD-A-16"), variant(edit))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ACCESS_DENIED


def test_ad_a_16_the_fix_holds_no_directory_text() -> None:
    """The fix of AD-A-16 names the account by its SID only."""
    assert_fix_holds_no_directory_text("AD-A-16", measured())


# ---- AD-A-17: the passwords that never expire ------------------------------


def test_ad_a_17_finds_the_seeded_account() -> None:
    """The seeded account holds a password that never expires."""
    result = result_of(check_of("AD-A-17"), measured())

    assert result.status == model.Status.FINDING
    assert f"{DOMAIN_SID}-1108" in finding_sids(result)


def test_ad_a_17_leaves_the_built_in_accounts_alone() -> None:
    """The built-in accounts of the domain are not findings."""
    result = result_of(check_of("AD-A-17"), measured())

    assert f"{DOMAIN_SID}-500" not in finding_sids(result)
    assert f"{DOMAIN_SID}-501" not in finding_sids(result)
    assert f"{DOMAIN_SID}-502" not in finding_sids(result)


def test_ad_a_17_is_a_low_finding_for_a_service_account() -> None:
    """A service account whose password never expires is a low finding."""

    def edit(document: dict[str, Any]) -> None:
        set_attribute(
            document,
            "users",
            "CN=seed-noexpire",
            "servicePrincipalName",
            "HTTP/seed-app.win.newton.test",
        )

    result = result_of(check_of("AD-A-17"), variant(edit))

    assert result.findings[0].severity == model.Severity.LOW
    assert "service principal name" in result.note


def test_ad_a_17_passes_when_no_password_never_expires() -> None:
    """No account holds the bit."""

    def edit(document: dict[str, Any]) -> None:
        map_attribute(
            document,
            "users",
            "userAccountControl",
            lambda value: value & ~0x00010000,
        )

    result = result_of(check_of("AD-A-17"), variant(edit))

    assert result.status == model.Status.PASS
    assert result.findings == ()


def test_ad_a_17_is_unknown_when_a_required_attribute_is_missing() -> None:
    """A readable object without a required attribute proves nothing."""

    def edit(document: dict[str, Any]) -> None:
        drop_attribute(document, "users", "CN=seed-noexpire", "sAMAccountName")

    result = result_of(check_of("AD-A-17"), variant(edit))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ACCESS_DENIED


def test_ad_a_17_the_fix_holds_no_directory_text() -> None:
    """The fix of AD-A-17 names the account by its SID only."""
    assert_fix_holds_no_directory_text("AD-A-17", measured())


def test_ad_a_17_does_not_judge_the_audit_account_of_the_run() -> None:
    """The account the audit ran as is not judged by AD-A-17.

    Newton's setup gives the audit account a random password that
    nobody holds and it signs in by key only, so a password that never
    expires is not a finding of it.
    """

    def edit(document: dict[str, Any]) -> None:
        set_attribute(
            document,
            "users",
            "CN=newton-audit",
            "userAccountControl",
            66048,
        )

    result = result_of(check_of("AD-A-17"), variant(edit))

    assert AUDIT_ACCOUNT_SID not in finding_sids(result)


def test_ad_a_17_says_that_the_audit_account_is_not_judged() -> None:
    """The result says why the audit account of the run is not judged."""
    result = result_of(check_of("AD-A-17"), measured())

    assert AUDIT_ACCOUNT_NOTE in result.note


def test_ad_a_17_leaves_the_audit_account_of_the_run_alone() -> None:
    """The measured audit account is no finding and the seeded one is."""
    result = result_of(check_of("AD-A-17"), measured())

    assert AUDIT_ACCOUNT_SID not in finding_sids(result)
    assert f"{DOMAIN_SID}-1108" in finding_sids(result)


def test_ad_a_17_judges_an_account_that_is_not_the_audit_account() -> None:
    """An account that is not the audit account of the run is judged.

    The document is read as another ordinary account, so the audit
    account of Newton's setup is an ordinary account of the audit and
    its password that never expires is a finding.
    """

    def edit(document: dict[str, Any]) -> None:
        document["identity"]["sid"] = ORDINARY_ACCOUNT_SID
        document["identity"]["user"] = "seed-legacyenc"
        set_attribute(
            document,
            "users",
            "CN=newton-audit",
            "userAccountControl",
            66048,
        )

    result = result_of(check_of("AD-A-17"), variant(edit))

    assert AUDIT_ACCOUNT_SID in finding_sids(result)


# ---- AD-A-18: the reversible encryption -------------------------------------


def test_ad_a_18_finds_the_seeded_account() -> None:
    """The seeded account stores its password reversibly."""
    result = result_of(check_of("AD-A-18"), measured())

    assert result.status == model.Status.FINDING
    assert f"{DOMAIN_SID}-1109" in finding_sids(result)


def test_ad_a_18_finds_the_domain_that_stores_passwords_reversibly() -> None:
    """The domain policy is part of the check."""

    def edit(document: dict[str, Any]) -> None:
        set_attribute(document, "domain_head", "DC=win", "pwdProperties", 0x11)

    result = result_of(check_of("AD-A-18"), variant(edit))

    assert result.status == model.Status.FINDING
    assert DOMAIN_SID in finding_sids(result)


def test_ad_a_18_passes_when_nothing_is_stored_reversibly() -> None:
    """No account asks for reversible encryption."""

    def edit(document: dict[str, Any]) -> None:
        map_attribute(
            document,
            "users",
            "userAccountControl",
            lambda value: value & ~0x00000080,
        )

    result = result_of(check_of("AD-A-18"), variant(edit))

    assert result.status == model.Status.PASS
    assert result.findings == ()


def test_ad_a_18_is_unknown_when_the_domain_head_could_not_be_read() -> None:
    """A query that did not complete proves nothing."""

    def edit(document: dict[str, Any]) -> None:
        set_status(document, "domain_head", "denied", "access_denied")

    result = result_of(check_of("AD-A-18"), variant(edit))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ACCESS_DENIED


def test_ad_a_18_the_fix_holds_no_directory_text() -> None:
    """The fix of AD-A-18 names the account by its SID only."""
    assert_fix_holds_no_directory_text("AD-A-18", measured())


# ---- AD-A-19: the SID history ----------------------------------------------


def test_ad_a_19_passes_on_the_measured_document() -> None:
    """No account of the lab domain carries a SID history."""
    result = result_of(check_of("AD-A-19"), measured())

    assert result.status == model.Status.PASS
    assert result.findings == ()


def test_ad_a_19_finds_an_account_with_a_sid_history() -> None:
    """An account that was migrated keeps the SID of its old domain."""

    def edit(document: dict[str, Any]) -> None:
        set_attribute(
            document,
            "users",
            "CN=seed-nested",
            "sIDHistory",
            sid_blob("S-1-5-21-1-2-3-500"),
        )

    result = result_of(check_of("AD-A-19"), variant(edit))

    assert result.status == model.Status.FINDING
    assert f"{DOMAIN_SID}-1114" in finding_sids(result)


def test_ad_a_19_finds_a_group_with_a_sid_history() -> None:
    """A group that was migrated keeps the SID of its old domain."""

    def edit(document: dict[str, Any]) -> None:
        set_attribute(
            document,
            "groups",
            "CN=seed-group-a",
            "sIDHistory",
            sid_blob("S-1-5-21-1-2-3-500"),
        )

    result = result_of(check_of("AD-A-19"), variant(edit))

    assert result.status == model.Status.FINDING
    assert f"{DOMAIN_SID}-1112" in finding_sids(result)


def test_ad_a_19_finds_a_computer_with_a_sid_history() -> None:
    """A computer that was migrated keeps the SID of its old domain."""

    def edit(document: dict[str, Any]) -> None:
        set_attribute(
            document,
            "computers",
            "CN=WINMEMBER1",
            "sIDHistory",
            sid_blob("S-1-5-21-1-2-3-500"),
        )

    result = result_of(check_of("AD-A-19"), variant(edit))

    assert result.status == model.Status.FINDING
    assert f"{DOMAIN_SID}-1104" in finding_sids(result)


def test_ad_a_19_is_high_for_the_sid_of_this_domain() -> None:
    """The SID history of a privileged group of this domain is high."""

    def edit(document: dict[str, Any]) -> None:
        set_attribute(
            document,
            "users",
            "CN=seed-nested",
            "sIDHistory",
            sid_blob(f"{DOMAIN_SID}-512"),
        )

    result = result_of(check_of("AD-A-19"), variant(edit))

    assert result.status == model.Status.FINDING
    assert result.findings[0].severity == model.Severity.HIGH


def test_ad_a_19_names_the_privileged_group_in_the_evidence() -> None:
    """The evidence names the group of the domain the history holds."""

    def edit(document: dict[str, Any]) -> None:
        set_attribute(
            document,
            "users",
            "CN=seed-nested",
            "sIDHistory",
            sid_blob(f"{DOMAIN_SID}-512"),
        )

    result = result_of(check_of("AD-A-19"), variant(edit))

    evidence = result.findings[0].objects[0].evidence
    assert evidence is not None
    assert "512" in evidence
    assert "privileged group of this domain" in evidence


def test_ad_a_19_is_high_for_the_sid_of_the_builtin_administrators() -> None:
    """The SID history of the builtin administrators is high."""

    def edit(document: dict[str, Any]) -> None:
        set_attribute(
            document,
            "users",
            "CN=seed-nested",
            "sIDHistory",
            sid_blob("S-1-5-32-544"),
        )

    result = result_of(check_of("AD-A-19"), variant(edit))

    assert result.status == model.Status.FINDING
    assert result.findings[0].severity == model.Severity.HIGH


def test_ad_a_19_names_the_builtin_administrators_in_the_evidence() -> None:
    """The evidence names the builtin administrators the history holds."""

    def edit(document: dict[str, Any]) -> None:
        set_attribute(
            document,
            "users",
            "CN=seed-nested",
            "sIDHistory",
            sid_blob("S-1-5-32-544"),
        )

    result = result_of(check_of("AD-A-19"), variant(edit))

    evidence = result.findings[0].objects[0].evidence
    assert evidence is not None
    assert "544" in evidence
    assert "privileged group of this domain" in evidence


def test_ad_a_19_keeps_a_sid_of_another_domain_high() -> None:
    """The SID of another domain is a high finding and nothing more."""

    def edit(document: dict[str, Any]) -> None:
        set_attribute(
            document,
            "users",
            "CN=seed-nested",
            "sIDHistory",
            sid_blob("S-1-5-21-1-2-3-500"),
        )

    result = result_of(check_of("AD-A-19"), variant(edit))

    assert result.status == model.Status.FINDING
    assert result.findings[0].severity == model.Severity.HIGH


def test_ad_a_19_is_unknown_when_a_privileged_group_hides_a_member() -> None:
    """A privileged group that hides a member proves nothing."""

    def edit(document: dict[str, Any]) -> None:
        drop_row(document, "groups", "CN=seed-group-b")

    result = result_of(check_of("AD-A-19"), variant(edit))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ACCESS_DENIED
    assert "seed-group-b" not in result.note


def test_ad_a_19_the_fix_holds_no_directory_text() -> None:
    """The fix of AD-A-19 names the account by its SID only."""

    def edit(document: dict[str, Any]) -> None:
        set_attribute(
            document,
            "users",
            "CN=seed-nested",
            "sIDHistory",
            sid_blob("S-1-5-21-1-2-3-500"),
        )

    assert_fix_holds_no_directory_text("AD-A-19", variant(edit))


# ---- AD-A-20: the passwords in text attributes ------------------------------


def test_ad_a_20_is_unknown_when_no_password_attribute_is_visible() -> None:
    """An empty presence query is "could not read", never PASS."""
    result = result_of(check_of("AD-A-20"), measured())

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ACCESS_DENIED


def test_ad_a_20_passes_when_the_collector_reads_everything() -> None:
    """A Samba collector reads as root: an empty result is a real empty."""

    def edit(document: dict[str, Any]) -> None:
        document["collector"] = "samba"
        document["settings"]["items"] = docs.settings_items("samba")

    result = result_of(check_of("AD-A-20"), variant(edit), "ad-samba")

    assert result.status == model.Status.PASS
    assert result.findings == ()


def test_ad_a_20_finds_an_object_with_a_password_attribute() -> None:
    """An object that holds a password in a text attribute is a finding."""

    def edit(document: dict[str, Any]) -> None:
        admin = row_of(document, "users", "CN=Administrator")
        add_row(
            document,
            "pw_attr_presence",
            admin["dn"],
            objectSid=admin["a"]["objectSid"][0],
        )

    result = result_of(check_of("AD-A-20"), variant(edit))

    assert result.status == model.Status.FINDING
    assert f"{DOMAIN_SID}-500" in finding_sids(result)


def test_ad_a_20_the_fix_holds_no_directory_text() -> None:
    """The fix of AD-A-20 names the object by its SID only."""

    def edit(document: dict[str, Any]) -> None:
        admin = row_of(document, "users", "CN=Administrator")
        add_row(
            document,
            "pw_attr_presence",
            admin["dn"],
            objectSid=admin["a"]["objectSid"][0],
        )

    assert_fix_holds_no_directory_text("AD-A-20", variant(edit))


# ---- AD-A-21: the accounts without a password ------------------------------


def test_ad_a_21_finds_the_seeded_account() -> None:
    """The seeded account is enabled and holds no password."""
    result = result_of(check_of("AD-A-21"), measured())

    assert result.status == model.Status.FINDING
    assert f"{DOMAIN_SID}-1111" in finding_sids(result)


def test_ad_a_21_says_the_account_must_change_its_password() -> None:
    """A password last set time of 0 means a password change at next logon."""
    result = result_of(check_of("AD-A-21"), measured())

    finding = result.findings[0]
    assert "must change password at next logon" in finding.title
    evidence = finding.objects[0].evidence
    assert evidence is not None
    assert "must change password at next logon" in evidence


def test_ad_a_21_leaves_a_disabled_account_alone() -> None:
    """A disabled account cannot be used with an empty password."""

    def edit(document: dict[str, Any]) -> None:
        set_attribute(
            document, "users", "CN=seed-neverlogon", "userAccountControl", 514
        )

    result = result_of(check_of("AD-A-21"), variant(edit))

    assert result.status == model.Status.PASS
    assert result.findings == ()


def test_ad_a_21_passes_when_every_enabled_account_has_a_password() -> None:
    """An account with a password is no finding."""

    def edit(document: dict[str, Any]) -> None:
        map_attribute(document, "users", "pwdLastSet", lambda value: RECENT)

    result = result_of(check_of("AD-A-21"), variant(edit))

    assert result.status == model.Status.PASS
    assert result.findings == ()


def test_ad_a_21_is_unknown_when_a_required_attribute_is_missing() -> None:
    """A readable object without a required attribute proves nothing."""

    def edit(document: dict[str, Any]) -> None:
        drop_attribute(document, "users", "CN=seed-neverlogon", "pwdLastSet")

    result = result_of(check_of("AD-A-21"), variant(edit))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ACCESS_DENIED


def test_ad_a_21_the_fix_holds_no_directory_text() -> None:
    """The fix of AD-A-21 names the account by its SID only."""
    assert_fix_holds_no_directory_text("AD-A-21", measured())


# ---- AD-A-22: the accounts that expired ------------------------------------


def test_ad_a_22_passes_on_the_measured_document() -> None:
    """No account of the lab domain holds an expiry date that has passed."""
    result = result_of(check_of("AD-A-22"), measured())

    assert result.status == model.Status.PASS
    assert result.findings == ()


def test_ad_a_22_finds_an_enabled_account_that_expired() -> None:
    """An enabled account whose expiry date has passed is a finding."""

    def edit(document: dict[str, Any]) -> None:
        set_attribute(
            document, "users", "CN=seed-svc-spn", "accountExpires", OLD
        )

    result = result_of(check_of("AD-A-22"), variant(edit))

    assert result.status == model.Status.FINDING
    assert f"{DOMAIN_SID}-1105" in finding_sids(result)


def test_ad_a_22_leaves_a_disabled_account_alone() -> None:
    """A disabled account is not an enabled account."""

    def edit(document: dict[str, Any]) -> None:
        set_attribute(
            document, "users", "CN=seed-svc-spn", "accountExpires", OLD
        )
        set_attribute(
            document, "users", "CN=seed-svc-spn", "userAccountControl", 514
        )

    result = result_of(check_of("AD-A-22"), variant(edit))

    assert result.status == model.Status.PASS
    assert result.findings == ()


def test_ad_a_22_reports_the_accounts_that_never_expire() -> None:
    """The note holds the number of accounts that never expire."""
    result = result_of(check_of("AD-A-22"), measured())

    assert "never comes" in result.note


def test_ad_a_22_is_unknown_when_a_required_attribute_is_missing() -> None:
    """A readable object without a required attribute proves nothing."""

    def edit(document: dict[str, Any]) -> None:
        drop_attribute(document, "users", "CN=seed-svc-spn", "accountExpires")

    result = result_of(check_of("AD-A-22"), variant(edit))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ACCESS_DENIED


def test_ad_a_22_the_fix_holds_no_directory_text() -> None:
    """The fix of AD-A-22 names the account by its SID only."""

    def edit(document: dict[str, Any]) -> None:
        set_attribute(
            document, "users", "CN=seed-svc-spn", "accountExpires", OLD
        )

    assert_fix_holds_no_directory_text("AD-A-22", variant(edit))


# ---- AD-A-23: the service accounts ------------------------------------------


def test_ad_a_23_passes_when_the_collector_reads_everything() -> None:
    """A Samba collector reads as root: an empty result is a real empty."""

    def edit(document: dict[str, Any]) -> None:
        document["collector"] = "samba"
        document["settings"]["items"] = docs.settings_items("samba")

    document = variant(edit)
    assert not rows_of(source_document(), "gmsa")

    result = result_of(check_of("AD-A-23"), document, "ad-samba")

    assert result.status == model.Status.PASS
    assert result.findings == ()
    assert "the domain holds no group managed service account" in result.note


def test_ad_a_23_is_unknown_when_the_managed_accounts_are_not_visible() -> None:
    """An empty query on Windows is "could not read", never "nothing there".

    The audit account may not see the group managed service accounts at
    all, so an empty query says nothing about them: the check cannot
    prove that no service account holds an old password, and the reason
    says that the accounts were not visible to the audit account.
    """
    result = result_of(check_of("AD-A-23"), measured())

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ACCESS_DENIED
    assert result.note == "none visible to the audit account"
    assert result.findings == ()


def test_ad_a_23_finds_a_service_account_with_an_old_password() -> None:
    """A service account that is not managed holds a static password."""

    def edit(document: dict[str, Any]) -> None:
        document["collector"] = "samba"
        document["settings"]["items"] = docs.settings_items("samba")
        set_attribute(document, "users", "CN=seed-svc-spn", "pwdLastSet", OLD)

    result = result_of(check_of("AD-A-23"), variant(edit), "ad-samba")

    assert result.status == model.Status.FINDING
    assert f"{DOMAIN_SID}-1105" in finding_sids(result)


def test_ad_a_23_finds_an_old_password_when_the_managed_accounts_are_hidden() -> None:
    """The service accounts are read even when the managed ones are not."""

    def edit(document: dict[str, Any]) -> None:
        set_attribute(
            document, "users", "CN=seed-svc-spn", "pwdLastSet", YEAR_2000
        )

    result = result_of(check_of("AD-A-23"), variant(edit))

    assert result.status == model.Status.FINDING
    assert f"{DOMAIN_SID}-1105" in finding_sids(result)
    assert "gMSA objects not visible to this account" in result.note


def test_ad_a_23_leaves_the_key_distribution_account_alone() -> None:
    """The key distribution account is the business of AD-A-27."""

    def edit(document: dict[str, Any]) -> None:
        document["collector"] = "samba"
        document["settings"]["items"] = docs.settings_items("samba")
        set_attribute(document, "users", "CN=krbtgt", "pwdLastSet", OLD)

    result = result_of(check_of("AD-A-23"), variant(edit), "ad-samba")

    assert result.status == model.Status.PASS
    assert f"{DOMAIN_SID}-502" not in finding_sids(result)


def test_ad_a_23_lists_the_group_managed_service_accounts() -> None:
    """The managed service accounts and their breadth are in the note."""

    def edit(document: dict[str, Any]) -> None:
        add_managed_service_account(document)

    result = result_of(check_of("AD-A-23"), variant(edit))

    assert result.status == model.Status.PASS
    assert "seed-gmsa" in result.note


def test_ad_a_23_counts_every_reader_of_the_managed_password() -> None:
    """The readers are the trustees of the allowed ACEs of the descriptor."""

    def edit(document: dict[str, Any]) -> None:
        add_managed_service_account(
            document,
            readers=(f"{DOMAIN_SID}-1114", f"{DOMAIN_SID}-1115"),
        )

    result = result_of(check_of("AD-A-23"), variant(edit))

    assert result.status == model.Status.PASS
    assert "seed-gmsa: 2" in result.note


def test_ad_a_23_counts_a_reader_of_the_managed_password_once() -> None:
    """A trustee that is named twice is one reader."""

    def edit(document: dict[str, Any]) -> None:
        add_managed_service_account(
            document,
            readers=(f"{DOMAIN_SID}-1114", f"{DOMAIN_SID}-1114"),
        )

    result = result_of(check_of("AD-A-23"), variant(edit))

    assert result.status == model.Status.PASS
    assert "seed-gmsa: 1" in result.note


def test_ad_a_23_is_unknown_when_the_membership_is_no_descriptor() -> None:
    """A membership that is not a descriptor proves nothing about it."""

    def edit(document: dict[str, Any]) -> None:
        add_managed_service_account(document)
        row = row_of(document, "gmsa", "CN=seed-gmsa")
        row["a"]["msDS-GroupMSAMembership"] = [sid_blob(f"{DOMAIN_SID}-1114")]

    result = result_of(check_of("AD-A-23"), variant(edit))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ERROR


def test_ad_a_23_finds_a_managed_account_that_did_not_rotate() -> None:
    """A managed service account whose password is old is a finding."""

    def edit(document: dict[str, Any]) -> None:
        add_managed_service_account(document, OLD)

    result = result_of(check_of("AD-A-23"), variant(edit))

    assert result.status == model.Status.FINDING
    assert f"{DOMAIN_SID}-1118" in finding_sids(result)


def test_ad_a_23_is_unknown_when_the_managed_accounts_are_not_all_read() -> None:
    """A managed account query that did not complete proves nothing.

    The half of the check that judges the managed accounts is left
    unjudged, so the check does not report a pass it cannot prove.
    """

    def edit(document: dict[str, Any]) -> None:
        add_managed_service_account(document, OLD)
        set_status(document, "gmsa", "truncated", "time_limit")

    result = result_of(check_of("AD-A-23"), variant(edit))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.TRUNCATED
    assert "gMSA inventory not complete (status truncated)" in result.note


def test_ad_a_23_judges_the_service_accounts_when_the_managed_query_failed() -> (
    None
):
    """The other half of the check is judged even when the query failed."""

    def edit(document: dict[str, Any]) -> None:
        set_attribute(document, "users", "CN=seed-svc-spn", "pwdLastSet", OLD)
        add_managed_service_account(document, OLD)
        set_status(document, "gmsa", "truncated", "time_limit")

    result = result_of(check_of("AD-A-23"), variant(edit))

    assert result.status == model.Status.FINDING
    assert f"{DOMAIN_SID}-1105" in finding_sids(result)
    assert "gMSA inventory not complete (status truncated)" in result.note


def test_ad_a_23_the_fix_holds_no_directory_text() -> None:
    """The fix of AD-A-23 names the account by its SID only."""

    def edit(document: dict[str, Any]) -> None:
        set_attribute(document, "users", "CN=seed-svc-spn", "pwdLastSet", OLD)
        add_managed_service_account(document)

    assert_fix_holds_no_directory_text("AD-A-23", variant(edit))


def test_ad_a_23_takes_the_reason_of_a_status_from_the_runner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The mapping of a status to a reason is the runner's alone.

    The check holds no copy of it: a second copy would drift from the
    one the runner reads the same status with.
    """
    seen: list[str] = []

    def spy(status: str) -> model.UnknownReason:
        seen.append(status)
        return model.UnknownReason.ERROR

    monkeypatch.setattr(runner, "reason_for_status", spy)

    def edit(document: dict[str, Any]) -> None:
        set_status(document, "gmsa", "truncated", "time_limit")

    result = result_of(check_of("AD-A-23"), variant(edit))

    assert seen == ["truncated"]
    assert result.reason == model.UnknownReason.ERROR


# ---- AD-A-24: the stale users ----------------------------------------------


def test_ad_a_24_passes_on_the_measured_document() -> None:
    """No account of the lab domain is old enough to be stale."""
    result = result_of(check_of("AD-A-24"), measured())

    assert result.status == model.Status.PASS
    assert result.findings == ()


def test_ad_a_24_finds_an_account_that_never_logged_on() -> None:
    """An old account that never logged on is a finding."""

    def edit(document: dict[str, Any]) -> None:
        set_attribute(
            document,
            "users",
            "CN=seed-neverlogon",
            "whenCreated",
            "20200101000000.0Z",
        )

    result = result_of(check_of("AD-A-24"), variant(edit))

    assert result.status == model.Status.FINDING
    assert f"{DOMAIN_SID}-1111" in finding_sids(result)


def test_ad_a_24_finds_an_account_that_logged_on_long_ago() -> None:
    """An old account whose last logon is old is a finding."""

    def edit(document: dict[str, Any]) -> None:
        set_attribute(
            document,
            "users",
            "CN=seed-neverlogon",
            "whenCreated",
            "20200101000000.0Z",
        )
        set_attribute(
            document, "users", "CN=seed-neverlogon", "lastLogonTimestamp", OLD
        )

    result = result_of(check_of("AD-A-24"), variant(edit))

    assert result.status == model.Status.FINDING
    assert f"{DOMAIN_SID}-1111" in finding_sids(result)


def test_ad_a_24_leaves_a_new_account_alone() -> None:
    """An account that was created yesterday is not stale."""

    def edit(document: dict[str, Any]) -> None:
        set_attribute(
            document,
            "users",
            "CN=seed-neverlogon",
            "whenCreated",
            "20261108172923.0Z",
        )

    result = result_of(check_of("AD-A-24"), variant(edit))

    assert result.status == model.Status.PASS
    assert result.findings == ()


def test_ad_a_24_leaves_a_disabled_account_alone() -> None:
    """A disabled account logs on nowhere."""

    def edit(document: dict[str, Any]) -> None:
        set_attribute(
            document,
            "users",
            "CN=seed-neverlogon",
            "whenCreated",
            "20200101000000.0Z",
        )
        set_attribute(
            document, "users", "CN=seed-neverlogon", "userAccountControl", 514
        )

    result = result_of(check_of("AD-A-24"), variant(edit))

    assert result.status == model.Status.PASS
    assert result.findings == ()


def test_ad_a_24_is_unknown_when_a_required_attribute_is_missing() -> None:
    """A readable object without a required attribute proves nothing."""

    def edit(document: dict[str, Any]) -> None:
        drop_attribute(document, "users", "CN=seed-neverlogon", "whenCreated")

    result = result_of(check_of("AD-A-24"), variant(edit))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ACCESS_DENIED


def test_ad_a_24_the_fix_holds_no_directory_text() -> None:
    """The fix of AD-A-24 names the account by its SID only."""

    def edit(document: dict[str, Any]) -> None:
        set_attribute(
            document,
            "users",
            "CN=seed-neverlogon",
            "whenCreated",
            "20200101000000.0Z",
        )

    assert_fix_holds_no_directory_text("AD-A-24", variant(edit))


# ---- AD-A-25: the stale computers -------------------------------------------


def test_ad_a_25_passes_on_the_measured_document() -> None:
    """No computer of the lab domain holds a stale trust."""
    result = result_of(check_of("AD-A-25"), measured())

    assert result.status == model.Status.PASS
    assert result.findings == ()


def test_ad_a_25_finds_a_computer_with_an_old_machine_password() -> None:
    """A computer whose machine password is old is a finding."""

    def edit(document: dict[str, Any]) -> None:
        set_attribute(document, "computers", "CN=WINMEMBER1", "pwdLastSet", OLD)

    result = result_of(check_of("AD-A-25"), variant(edit))

    assert result.status == model.Status.FINDING
    assert f"{DOMAIN_SID}-1104" in finding_sids(result)


def test_ad_a_25_finds_a_computer_that_never_logged_on() -> None:
    """A computer that never logged on and holds an old password."""

    def edit(document: dict[str, Any]) -> None:
        set_attribute(document, "computers", "CN=seed-pc-unc", "pwdLastSet", OLD)

    result = result_of(check_of("AD-A-25"), variant(edit))

    assert result.status == model.Status.FINDING
    assert f"{DOMAIN_SID}-1116" in finding_sids(result)


def test_ad_a_25_leaves_the_domain_controller_alone() -> None:
    """A domain controller is trusted by the design of the directory."""

    def edit(document: dict[str, Any]) -> None:
        set_attribute(document, "computers", "CN=WINDC1", "pwdLastSet", OLD)

    result = result_of(check_of("AD-A-25"), variant(edit))

    assert result.status == model.Status.PASS
    assert f"{DOMAIN_SID}-1000" not in finding_sids(result)


def test_ad_a_25_leaves_a_computer_created_today_alone() -> None:
    """A computer of today holds no stale trust yet."""

    def edit(document: dict[str, Any]) -> None:
        set_attribute(document, "computers", "CN=WINMEMBER1", "pwdLastSet", 0)
        set_attribute(
            document,
            "computers",
            "CN=WINMEMBER1",
            "whenCreated",
            "20261108172923.0Z",
        )

    result = result_of(check_of("AD-A-25"), variant(edit))

    assert result.status == model.Status.PASS
    assert result.findings == ()


def test_ad_a_25_finds_a_computer_created_in_2020_with_no_password() -> None:
    """A computer of 2020 that never set its password holds a stale trust."""

    def edit(document: dict[str, Any]) -> None:
        set_attribute(document, "computers", "CN=WINMEMBER1", "pwdLastSet", 0)
        set_attribute(
            document,
            "computers",
            "CN=WINMEMBER1",
            "whenCreated",
            "20200101000000.0Z",
        )

    result = result_of(check_of("AD-A-25"), variant(edit))

    assert result.status == model.Status.FINDING
    assert f"{DOMAIN_SID}-1104" in finding_sids(result)


def test_ad_a_25_is_unknown_when_the_query_did_not_complete() -> None:
    """A query that did not complete proves nothing."""

    def edit(document: dict[str, Any]) -> None:
        set_status(document, "computers", "denied", "access_denied")

    result = result_of(check_of("AD-A-25"), variant(edit))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ACCESS_DENIED


def test_ad_a_25_the_fix_holds_no_directory_text() -> None:
    """The fix of AD-A-25 names the computer by its SID only."""

    def edit(document: dict[str, Any]) -> None:
        set_attribute(document, "computers", "CN=WINMEMBER1", "pwdLastSet", OLD)

    assert_fix_holds_no_directory_text("AD-A-25", variant(edit))


# ---- AD-A-26: the smart card accounts ---------------------------------------


def test_ad_a_26_passes_on_the_measured_document() -> None:
    """No account of the lab domain needs a smart card."""
    result = result_of(check_of("AD-A-26"), measured())

    assert result.status == model.Status.PASS
    assert result.findings == ()


def test_ad_a_26_finds_a_smart_card_account_with_an_old_password() -> None:
    """An account that needs a smart card keeps the hash of its password."""

    def edit(document: dict[str, Any]) -> None:
        set_attribute(
            document,
            "users",
            "CN=seed-svc-spn",
            "userAccountControl",
            512 | 0x00040000,
        )
        set_attribute(document, "users", "CN=seed-svc-spn", "pwdLastSet", OLD)

    result = result_of(check_of("AD-A-26"), variant(edit))

    assert result.status == model.Status.FINDING
    assert f"{DOMAIN_SID}-1105" in finding_sids(result)


def test_ad_a_26_leaves_a_smart_card_account_with_a_new_password_alone() -> None:
    """A smart card account whose password is new is no finding."""

    def edit(document: dict[str, Any]) -> None:
        set_attribute(
            document,
            "users",
            "CN=seed-svc-spn",
            "userAccountControl",
            512 | 0x00040000,
        )

    result = result_of(check_of("AD-A-26"), variant(edit))

    assert result.status == model.Status.PASS
    assert result.findings == ()


def test_ad_a_26_is_unknown_when_a_required_attribute_is_missing() -> None:
    """A readable object without a required attribute proves nothing."""

    def edit(document: dict[str, Any]) -> None:
        drop_attribute(document, "users", "CN=seed-svc-spn", "pwdLastSet")

    result = result_of(check_of("AD-A-26"), variant(edit))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ACCESS_DENIED


def test_ad_a_26_the_fix_holds_no_directory_text() -> None:
    """The fix of AD-A-26 names the account by its SID only."""

    def edit(document: dict[str, Any]) -> None:
        set_attribute(
            document,
            "users",
            "CN=seed-svc-spn",
            "userAccountControl",
            512 | 0x00040000,
        )
        set_attribute(document, "users", "CN=seed-svc-spn", "pwdLastSet", OLD)

    assert_fix_holds_no_directory_text("AD-A-26", variant(edit))


# ---- AD-A-27: the key distribution account ---------------------------------


def test_ad_a_27_passes_on_the_measured_document() -> None:
    """The password of the key distribution account is not old."""
    result = result_of(check_of("AD-A-27"), measured())

    assert result.status == model.Status.PASS
    assert result.findings == ()


def test_ad_a_27_finds_an_old_key_distribution_password() -> None:
    """A password of the key distribution account that is old is a finding."""

    def edit(document: dict[str, Any]) -> None:
        set_attribute(document, "users", "CN=krbtgt", "pwdLastSet", OLD)

    result = result_of(check_of("AD-A-27"), variant(edit))

    assert result.status == model.Status.FINDING
    assert f"{DOMAIN_SID}-502" in finding_sids(result)


def test_ad_a_27_says_the_password_was_never_recorded() -> None:
    """A password last set time of 0 is never recorded, not "no password"."""

    def edit(document: dict[str, Any]) -> None:
        set_attribute(document, "users", "CN=krbtgt", "pwdLastSet", 0)

    result = result_of(check_of("AD-A-27"), variant(edit))

    assert result.status == model.Status.FINDING
    finding = result.findings[0]
    assert "password last set time is 0 (never recorded)" in finding.title
    evidence = finding.objects[0].evidence
    assert evidence is not None
    assert "password last set time is 0 (never recorded)" in evidence
    assert "holds no password" not in result.note


def test_ad_a_27_is_unknown_when_a_required_attribute_is_missing() -> None:
    """A readable object without a required attribute proves nothing."""

    def edit(document: dict[str, Any]) -> None:
        drop_attribute(document, "users", "CN=krbtgt", "pwdLastSet")

    result = result_of(check_of("AD-A-27"), variant(edit))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ACCESS_DENIED


def test_ad_a_27_the_fix_holds_no_directory_text() -> None:
    """The fix of AD-A-27 names the account by its SID only."""

    def edit(document: dict[str, Any]) -> None:
        set_attribute(document, "users", "CN=krbtgt", "pwdLastSet", OLD)

    assert_fix_holds_no_directory_text("AD-A-27", variant(edit))


def test_ad_a_27_the_fix_explains_the_reset() -> None:
    """The fix of AD-A-27 explains and runs no command at all."""

    def edit(document: dict[str, Any]) -> None:
        set_attribute(document, "users", "CN=krbtgt", "pwdLastSet", OLD)

    assert fix_commands("AD-A-27", variant(edit), "windows") == []
    assert fix_commands("AD-A-27", variant(edit), "samba") == []


# ---- AD-A-30: the pre-windows 2000 compatible access group ------------------


def test_ad_a_30_passes_on_the_measured_document() -> None:
    """The group of the lab domain holds neither Everybody nor Anonymous."""
    result = result_of(check_of("AD-A-30"), measured())

    assert result.status == model.Status.PASS
    assert result.findings == ()


def test_ad_a_30_finds_the_group_with_everyone_in_it() -> None:
    """Everybody in the group is a finding."""

    def edit(document: dict[str, Any]) -> None:
        add_row(
            document,
            "fsps",
            "CN=S-1-1-0,CN=ForeignSecurityPrincipals,"
            "DC=win,DC=newton,DC=test",
            objectSid=sid_blob("S-1-1-0"),
        )
        add_member(
            document,
            "CN=Pre-Windows 2000 Compatible Access",
            "CN=S-1-1-0,CN=ForeignSecurityPrincipals,"
            "DC=win,DC=newton,DC=test",
        )

    result = result_of(check_of("AD-A-30"), variant(edit))

    assert result.status == model.Status.FINDING
    assert "S-1-1-0" in finding_sids(result)


def test_ad_a_30_is_unknown_when_the_group_hides_a_member() -> None:
    """A member value that names no object proves nothing."""

    def edit(document: dict[str, Any]) -> None:
        add_member(
            document,
            "CN=Pre-Windows 2000 Compatible Access",
            "CN=S-1-5-7,CN=ForeignSecurityPrincipals,"
            "DC=win,DC=newton,DC=test",
        )

    result = result_of(check_of("AD-A-30"), variant(edit))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ACCESS_DENIED
    assert "S-1-5-7" not in result.note


def test_ad_a_30_is_unknown_when_the_group_is_missing() -> None:
    """A document without the group proves nothing about it."""

    def edit(document: dict[str, Any]) -> None:
        drop_row(document, "groups", "CN=Pre-Windows 2000 Compatible Access")

    result = result_of(check_of("AD-A-30"), variant(edit))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ACCESS_DENIED


def test_ad_a_30_the_fix_holds_no_directory_text() -> None:
    """The fix of AD-A-30 names the group by its SID only."""

    def edit(document: dict[str, Any]) -> None:
        add_row(
            document,
            "fsps",
            "CN=S-1-1-0,CN=ForeignSecurityPrincipals,"
            "DC=win,DC=newton,DC=test",
            objectSid=sid_blob("S-1-1-0"),
        )
        add_member(
            document,
            "CN=Pre-Windows 2000 Compatible Access",
            "CN=S-1-1-0,CN=ForeignSecurityPrincipals,"
            "DC=win,DC=newton,DC=test",
        )

    assert_fix_holds_no_directory_text("AD-A-30", variant(edit))


def test_ad_a_30_the_windows_fix_explains_the_change() -> None:
    """The Windows step explains the change and runs no command at all.

    The command that removed the member was never proven, so the step
    tells the owner what to do in the console of the directory.
    """

    def edit(document: dict[str, Any]) -> None:
        add_row(
            document,
            "fsps",
            "CN=S-1-1-0,CN=ForeignSecurityPrincipals,"
            "DC=win,DC=newton,DC=test",
            objectSid=sid_blob("S-1-1-0"),
        )
        add_member(
            document,
            "CN=Pre-Windows 2000 Compatible Access",
            "CN=S-1-1-0,CN=ForeignSecurityPrincipals,"
            "DC=win,DC=newton,DC=test",
        )

    check = check_of("AD-A-30")
    report = runner.run(variant(edit), "ad-windows", checks=[check])
    finding = report.results[0].findings[0]

    assert finding.fix is not None
    assert finding.fix.windows.commands == ()
    changes = finding.fix.windows.changes
    assert "ANONYMOUS LOGON" in changes
    assert "Everyone" in changes
    assert "Pre-Windows 2000 Compatible Access" in changes
    assert "Active Directory Users and Computers" in changes
    assert "Builtin" in changes


def test_ad_a_30_the_samba_fix_removes_the_member() -> None:
    """The Samba step takes the member value out of the group."""

    def edit(document: dict[str, Any]) -> None:
        add_row(
            document,
            "fsps",
            "CN=S-1-1-0,CN=ForeignSecurityPrincipals,"
            "DC=win,DC=newton,DC=test",
            objectSid=sid_blob("S-1-1-0"),
        )
        add_member(
            document,
            "CN=Pre-Windows 2000 Compatible Access",
            "CN=S-1-1-0,CN=ForeignSecurityPrincipals,"
            "DC=win,DC=newton,DC=test",
        )

    commands = fix_commands("AD-A-30", variant(edit), "samba")

    assert commands
    for command in commands:
        assert "ldbmodify" in command
        assert "delete: member" in command


# ---- AD-A-31: the hybrid sync accounts --------------------------------------


def test_ad_a_31_passes_on_the_measured_document() -> None:
    """The domain holds no single sign-on account of a hybrid tenant."""
    result = result_of(check_of("AD-A-31"), measured())

    assert result.status == model.Status.PASS
    assert result.findings == ()


def test_ad_a_31_finds_the_single_sign_on_computer() -> None:
    """The account of the single sign-on of the tenant is a computer."""

    def edit(document: dict[str, Any]) -> None:
        add_single_sign_on_computer(document, OLD)

    result = result_of(check_of("AD-A-31"), variant(edit))

    assert result.status == model.Status.FINDING
    assert SINGLE_SIGN_ON_SID in finding_sids(result)


def test_ad_a_31_puts_the_age_of_the_password_in_the_evidence() -> None:
    """The evidence of the finding holds the age of the machine password."""

    def edit(document: dict[str, Any]) -> None:
        add_single_sign_on_computer(document, OLD)

    result = result_of(check_of("AD-A-31"), variant(edit))

    evidence = result.findings[0].objects[0].evidence
    assert evidence is not None
    assert "days old" in evidence


def test_ad_a_31_is_a_high_finding_for_the_single_sign_on_account() -> None:
    """The account of the single sign-on of the tenant is a high finding."""

    def edit(document: dict[str, Any]) -> None:
        add_single_sign_on_computer(document, OLD)

    result = result_of(check_of("AD-A-31"), variant(edit))

    assert result.findings[0].severity == model.Severity.HIGH


def test_ad_a_31_leaves_a_new_single_sign_on_computer_alone() -> None:
    """A single sign-on account whose password is new is no finding."""

    def edit(document: dict[str, Any]) -> None:
        add_single_sign_on_computer(document, RECENT)

    result = result_of(check_of("AD-A-31"), variant(edit))

    assert result.status == model.Status.PASS
    assert result.findings == ()


def test_ad_a_31_leaves_a_user_row_alone() -> None:
    """The account of the single sign-on is a computer and never a user."""

    def edit(document: dict[str, Any]) -> None:
        set_attribute(
            document,
            "users",
            "CN=seed-nested",
            "sAMAccountName",
            SINGLE_SIGN_ON_NAME,
        )

    result = result_of(check_of("AD-A-31"), variant(edit))

    assert result.status == model.Status.PASS
    assert result.findings == ()


def test_ad_a_31_finds_a_synchronization_account_of_the_hybrid_tenant() -> None:
    """An account that synchronizes the tenant is a finding."""

    def edit(document: dict[str, Any]) -> None:
        add_hybrid_user(document, "MSOL_abc123")

    result = result_of(check_of("AD-A-31"), variant(edit))

    assert result.status == model.Status.FINDING
    assert HYBRID_USER_SID in finding_sids(result)


def test_ad_a_31_finds_a_synchronization_account_in_any_case() -> None:
    """The name of an account of the tenant is read in any case."""

    def edit(document: dict[str, Any]) -> None:
        add_hybrid_user(document, "aad_abc123")

    result = result_of(check_of("AD-A-31"), variant(edit))

    assert result.status == model.Status.FINDING
    assert HYBRID_USER_SID in finding_sids(result)


def test_ad_a_31_leaves_a_name_that_only_looks_like_one_alone() -> None:
    """A name that starts like one of them is not one of them."""

    def edit(document: dict[str, Any]) -> None:
        add_hybrid_user(document, "MSOLX")

    result = result_of(check_of("AD-A-31"), variant(edit))

    assert result.status == model.Status.PASS
    assert result.findings == ()


def test_ad_a_31_reports_one_affected_object_for_every_account() -> None:
    """Every account of the tenant is an object of its own."""

    def edit(document: dict[str, Any]) -> None:
        add_hybrid_user(document, "MSOL_abc123")
        add_hybrid_user(document, "AAD_abc123", HYBRID_USER_SID_TWO)

    result = result_of(check_of("AD-A-31"), variant(edit))

    assert result.status == model.Status.FINDING
    affected = [
        affected
        for finding in result.findings
        for affected in finding.objects
    ]
    assert len(affected) == 2
    assert len(result.findings) == 2


def test_ad_a_31_is_a_high_finding_for_a_synchronization_account() -> None:
    """An account that synchronizes the tenant is a high finding."""

    def edit(document: dict[str, Any]) -> None:
        add_hybrid_user(document, "MSOL_abc123")

    result = result_of(check_of("AD-A-31"), variant(edit))

    assert result.findings[0].severity == model.Severity.HIGH


def test_ad_a_31_finds_the_single_sign_on_computer_that_never_rolled_over() -> (
    None
):
    """A machine password that was never set is a finding."""

    def edit(document: dict[str, Any]) -> None:
        add_single_sign_on_computer(document, 0)

    result = result_of(check_of("AD-A-31"), variant(edit))

    assert result.status == model.Status.FINDING
    evidence = result.findings[0].objects[0].evidence
    assert evidence == (
        "password last set time is 0 or absent (never rolled over)"
    )


def test_ad_a_31_finds_the_single_sign_on_computer_without_a_password_time() -> (
    None
):
    """A machine password the collector did not read is a finding too."""

    def edit(document: dict[str, Any]) -> None:
        add_single_sign_on_computer(document, 0)
        drop_attribute(
            document, "computers", "CN=AZUREADSSOACC", "pwdLastSet"
        )

    result = result_of(check_of("AD-A-31"), variant(edit))

    assert result.status == model.Status.FINDING
    evidence = result.findings[0].objects[0].evidence
    assert evidence == (
        "password last set time is 0 or absent (never rolled over)"
    )


def test_ad_a_31_is_unknown_when_a_required_attribute_is_missing() -> None:
    """A readable object without a required attribute proves nothing."""

    def edit(document: dict[str, Any]) -> None:
        drop_attribute(
            document, "computers", "CN=WINMEMBER1", "sAMAccountName"
        )

    result = result_of(check_of("AD-A-31"), variant(edit))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ACCESS_DENIED


def test_ad_a_31_the_fix_holds_no_directory_text() -> None:
    """The fix of AD-A-31 names the account by its SID only."""

    def edit(document: dict[str, Any]) -> None:
        add_single_sign_on_computer(document, OLD)

    assert_fix_holds_no_directory_text("AD-A-31", variant(edit))


# ---- AD-A-32: the read-only domain controllers -----------------------------


def test_ad_a_32_passes_when_the_domain_has_no_read_only_controller() -> None:
    """A domain without a read-only domain controller caches no principal."""
    result = result_of(check_of("AD-A-32"), measured())

    assert result.status == model.Status.PASS
    assert "no read-only domain controller" in result.note


def test_ad_a_32_finds_a_broad_password_replication_policy() -> None:
    """A principal in the allowed group is cached by every controller."""

    def edit(document: dict[str, Any]) -> None:
        set_attribute(
            document, "computers", "CN=WINMEMBER1", "primaryGroupID", 521
        )
        add_member(
            document,
            "CN=Allowed RODC Password Replication Group",
            "CN=Administrator,CN=Users,DC=win,DC=newton,DC=test",
        )

    result = result_of(check_of("AD-A-32"), variant(edit))

    assert result.status == model.Status.FINDING
    assert f"{DOMAIN_SID}-571" in finding_sids(result)


def test_ad_a_32_is_unknown_when_the_allowed_group_hides_a_member() -> None:
    """A member value that names no object proves nothing."""

    def edit(document: dict[str, Any]) -> None:
        set_attribute(
            document, "computers", "CN=WINMEMBER1", "primaryGroupID", 521
        )
        add_member(
            document,
            "CN=Allowed RODC Password Replication Group",
            "CN=seed-gone,OU=NewtonSeeds,DC=win,DC=newton,DC=test",
        )

    result = result_of(check_of("AD-A-32"), variant(edit))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ACCESS_DENIED
    assert "seed-gone" not in result.note


def test_ad_a_32_is_unknown_when_the_query_did_not_complete() -> None:
    """A query that did not complete proves nothing."""

    def edit(document: dict[str, Any]) -> None:
        set_status(document, "computers", "denied", "access_denied")

    result = result_of(check_of("AD-A-32"), variant(edit))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ACCESS_DENIED


def test_ad_a_32_is_unknown_on_samba() -> None:
    """The read-only domain controller policy is a Windows feature."""

    def edit(document: dict[str, Any]) -> None:
        document["collector"] = "samba"
        document["settings"]["items"] = docs.settings_items("samba")

    result = result_of(check_of("AD-A-32"), variant(edit), "ad-samba")

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.UNSUPPORTED


def test_ad_a_32_the_fix_holds_no_directory_text() -> None:
    """The fix of AD-A-32 names the group by its SID only."""

    def edit(document: dict[str, Any]) -> None:
        set_attribute(
            document, "computers", "CN=WINMEMBER1", "primaryGroupID", 521
        )
        add_member(
            document,
            "CN=Allowed RODC Password Replication Group",
            "CN=Administrator,CN=Users,DC=win,DC=newton,DC=test",
        )

    assert_fix_holds_no_directory_text("AD-A-32", variant(edit))


# ---- the constants of the module -------------------------------------------


def test_constants() -> None:
    """The constants of the module are the documented ones."""
    assert accounts.UAC_ACCOUNTDISABLE == 0x00000002
    assert accounts.UAC_PASSWD_NOTREQD == 0x00000020
    assert accounts.UAC_INTERDOMAIN_TRUST == 0x00000800
    assert accounts.UAC_WORKSTATION_TRUST == 0x00001000
    assert accounts.UAC_SERVER_TRUST == 0x00002000
    assert accounts.UAC_TRUSTED_FOR_DELEGATION == 0x00080000
    assert accounts.UAC_NOT_DELEGATED == 0x00100000
    assert accounts.UAC_DONT_REQUIRE_PREAUTH == 0x00400000
    assert accounts.UAC_PROTOCOL_TRANSITION == 0x01000000
    assert accounts.ENC_DES_CBC_CRC == 0x00000001
    assert accounts.ENC_DES_CBC_MD5 == 0x00000002
    assert accounts.ENC_RC4 == 0x00000004
    assert accounts.ENC_AES128 == 0x00000008
    assert accounts.ENC_AES256 == 0x00000010
    assert accounts.ENC_AES256_SK == 0x00000020
    assert accounts.ENC_FAST_SUPPORTED == 0x00010000
    assert accounts.ENC_AES_ONLY == 24
    assert accounts.UAC_ENCRYPTED_TEXT_PWD_ALLOWED == 0x00000080
    assert accounts.UAC_DONT_EXPIRE_PASSWORD == 0x00010000
    assert accounts.UAC_SMARTCARD_REQUIRED == 0x00040000
    assert accounts.PWD_PROPERTIES_REVERSIBLE_ENCRYPTION == 0x00000010
    assert accounts.RID_ALLOWED_RODC_REPLICATION == 571
    assert accounts.RID_DENIED_RODC_REPLICATION == 572
    assert accounts.EVERYONE_SID == "S-1-1-0"
    assert accounts.ANONYMOUS_SID == "S-1-5-7"
    assert accounts.PRE_WINDOWS_2000_GROUP_SID == "S-1-5-32-554"
    assert accounts.BUILTIN_ACCOUNT_RIDS == (500, 501, 502)
    assert accounts.STALE_DAYS == 90
    assert accounts.SMARTCARD_PASSWORD_DAYS == 90
    assert accounts.KRBtGT_PASSWORD_DAYS == 180
    assert accounts.SERVICE_ACCOUNT_PASSWORD_DAYS == 365
    assert accounts.HYBRID_ACCOUNT_PASSWORD_DAYS == 30
    assert accounts.SINGLE_SIGN_ON_ACCOUNT == "AZUREADSSOACC$"
    assert accounts.SAME_DOMAIN_PRIVILEGED_RIDS == (
        512,
        516,
        518,
        519,
        498,
        521,
        500,
    )
    assert accounts.HYBRID_ACCOUNT_PREFIXES == ("MSOL_", "AAD_")
    assert [level.value for level in model.Severity] == [
        "low",
        "medium",
        "high",
    ]


def test_the_protected_set_of_the_module_is_the_documented_one() -> None:
    """The protected groups and accounts are the AdminSDHolder ones."""
    assert accounts.PROTECTED_BUILTIN_SIDS == (
        "S-1-5-32-544",
        "S-1-5-32-548",
        "S-1-5-32-549",
        "S-1-5-32-550",
        "S-1-5-32-551",
        "S-1-5-32-552",
    )
    assert accounts.PROTECTED_DOMAIN_RIDS == (512, 516, 518, 519, 521, 526, 527)
    assert accounts.PROTECTED_USER_RIDS == (500, 502)


# ---- the fix commands of the module ----------------------------------------


def test_the_windows_commands_are_cmdlets_of_the_active_directory_module() -> None:
    """Every Windows command of every fix is a cmdlet of the module."""
    allowed = {
        "Add-ADGroupMember",
        "Disable-ADAccount",
        "Remove-ADGroupMember",
        "Set-ADAccountControl",
        "Set-ADComputer",
        "Set-ADUser",
    }
    for check_id, document in command_documents():
        for command in fix_commands(check_id, document, "windows"):
            assert command.split(" ")[0] in allowed


def test_no_change_step_holds_a_read_only_command() -> None:
    """A step that claims a change never runs a cmdlet that only reads."""
    for check_id, document in command_documents():
        for command in fix_commands(check_id, document, "windows"):
            assert not command.startswith(("Get-AD", "Search-AD", "Test-AD"))


def test_the_windows_commands_never_name_an_object_with_set_adobject() -> None:
    """Set-ADObject takes no SID, so it never names an object here."""
    for check_id, document in command_documents():
        for command in fix_commands(check_id, document, "windows"):
            assert "Set-ADObject" not in command


def test_the_windows_commands_use_the_parameters_of_the_module() -> None:
    """The parameter of an attribute is the one the module has."""
    for check_id, document in command_documents():
        for command in fix_commands(check_id, document, "windows"):
            assert "-primarygroupid" not in command.lower()
            assert "-cannotdelegate" not in command.lower()


def test_the_samba_commands_take_an_attribute_away_with_the_delete_form() -> None:
    """An attribute is removed with delete: <attr>, never with an empty value."""
    removals = {
        "AD-A-07": "servicePrincipalName",
        "AD-A-10": "msDS-KeyCredentialLink",
        "AD-A-12": "msDS-AllowedToDelegateTo",
        "AD-A-13": "msDS-AllowedToActOnBehalfOfOtherIdentity",
    }
    documents = dict(command_documents())
    for check_id, attribute in removals.items():
        commands = fix_commands(check_id, documents[check_id], "samba")
        assert commands
        for command in commands:
            assert f"delete: {attribute}" in command
            assert f"{attribute}:" not in command


def test_every_samba_command_writes_a_value_or_deletes_an_attribute() -> None:
    """A Samba command never leaves an attribute with an empty value."""
    for check_id, document in command_documents():
        for command in fix_commands(check_id, document, "samba"):
            assert (
                "replace:" in command
                or "delete:" in command
                or "add: member" in command
            )


def test_every_fix_command_is_one_line() -> None:
    """Every command of every fix of every check is a single line.

    A command with a line break in it prints on two lines, and the second
    line is not the command the owner read.
    """
    for check_id, document in command_documents():
        for platform in ("windows", "samba"):
            for command in fix_commands(check_id, document, platform):
                assert "\n" not in command, (check_id, platform, command)
                assert "\r" not in command, (check_id, platform, command)


def test_every_rendered_fix_command_is_one_line() -> None:
    """The rendered command of every fix of every check is a single line."""
    for check_id, document in command_documents():
        report = runner.run(document, "ad-windows", checks=[check_of(check_id)])
        rendered = render.render(report)
        for result in rendered["results"]:
            for finding in result["findings"]:
                for platform in ("windows", "samba"):
                    for command in finding["fix"][platform]["commands"]:
                        assert "\n" not in command, (check_id, platform, command)
                        assert "\r" not in command, (check_id, platform, command)


# ---- the document with the ACL seeds ----------------------------------------


def test_the_acl_document_gives_the_same_statuses_as_the_measured_one() -> None:
    """The document with the ACL seeds gives the same statuses.

    The seeded security descriptors do not change what the account checks
    find: the same check is the same status on both documents.
    """
    for check_id in CHECK_IDS:
        check = check_of(check_id)
        assert (
            result_of(check, acl_measured()).status
            == result_of(check, measured()).status
        ), check_id


def test_the_acl_document_renders_without_error() -> None:
    """The report of the document with the ACL seeds is rendered."""
    report = runner.run(
        acl_measured(), "ad-windows", checks=list(accounts.CHECKS)
    )

    rendered = render.render(report)

    assert len(rendered["results"]) == len(CHECK_IDS)


# ---- the catalogue ---------------------------------------------------------


def test_the_catalogue_holds_the_account_checks_of_this_part() -> None:
    """The module holds exactly the checks of this part."""
    assert tuple(check.id for check in accounts.CHECKS) == CHECK_IDS


def test_the_catalogue_of_the_audit_holds_the_account_checks() -> None:
    """The catalogue of the audit reads the checks of this module."""
    from newton_mcp.ad import catalogue as the_catalogue

    ids = [check.id for check in the_catalogue.CHECKS]
    for check_id in CHECK_IDS:
        assert check_id in ids


def test_the_check_ids_are_unique() -> None:
    """No id of the catalogue is twice."""
    ids = [check.id for check in accounts.CHECKS]
    assert len(ids) == len(set(ids))


def test_no_check_writes_compliant_or_non_compliant() -> None:
    """The words of the specification never appear in a check."""
    for check in accounts.CHECKS:
        texts = [check.title, *check.maps_to]
        for text in texts:
            assert "compliant" not in text.lower()


def test_a_hostile_name_never_reaches_a_command() -> None:
    """A name with shell characters in it stays out of every command."""

    def edit(document: dict[str, Any]) -> None:
        row = row_of(document, "users", "CN=seed-svc-spn")
        row["dn"] = (
            "CN=seed-svc-spn'; DROP--$(id)`,OU=NewtonSeeds,"
            "DC=win,DC=newton,DC=test"
        )
        row["a"]["sAMAccountName"] = ["seed-svc-spn'; DROP--$(id)`"]
        row["a"]["servicePrincipalName"] = ["HTTP/'; DROP--$(id)`"]

    document = variant(edit)
    report = runner.run(document, "ad-windows", checks=[check_of("AD-A-07")])
    strings = directory_strings(report)
    rendered = render.render(report)
    for result in rendered["results"]:
        for finding in result["findings"]:
            for platform in ("windows", "samba"):
                for command in finding["fix"][platform]["commands"]:
                    render.assert_no_directory_text(command, strings)


