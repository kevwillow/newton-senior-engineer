"""The runner: the identity guard, the sentinels and the UNKNOWN paths."""

from __future__ import annotations

import json
from typing import Any

import pytest

from newton_mcp.ad import catalogue, model, runner

import docs


AUDIT_SID = docs.AUDIT_SID
ADMIN_SID = docs.ADMIN_SID
KRBTGT_SID = docs.KRBTGT_SID
DOMAIN_ADMINS_SID = docs.DOMAIN_ADMINS_SID
DOMAIN_USERS_SID = docs.DOMAIN_USERS_SID
USER_SID = f"{docs.DOMAIN_SID}-1107"


def user_row(dn: str, sid: str, **attrs: object) -> dict[str, Any]:
    values: dict[str, object] = {"objectSid": docs.sid_blob(sid)}
    values.update(attrs)
    return docs.row(dn, **values)


def group_row(dn: str, sid: str, member: list[str] | None = None) -> dict[str, Any]:
    values: dict[str, object] = {"objectSid": docs.sid_blob(sid)}
    if member is not None:
        values["member"] = member
    return docs.row(dn, **values)


def audit_document(
    *,
    identity_sid: str = AUDIT_SID,
    token_group_sids: list[str] | None = None,
    users: list[dict[str, Any]] | None = None,
    groups: list[dict[str, Any]] | None = None,
    computers: list[dict[str, Any]] | None = None,
    collector: str = "windows",
    statuses: dict[str, tuple[str, str]] | None = None,
    file_statuses: dict[str, tuple[str, str]] | None = None,
) -> Any:
    """A document whose sentinels are all there."""
    admin_dn = f"CN=Administrator,{docs.DOMAIN_DN}"
    if users is None:
        users = [
            user_row(admin_dn, ADMIN_SID, primaryGroupID="512"),
            user_row(f"CN=krbtgt,{docs.DOMAIN_DN}", KRBTGT_SID),
            user_row(f"CN=audit,{docs.DOMAIN_DN}", identity_sid),
        ]
    if groups is None:
        groups = [
            group_row(f"CN=Domain Admins,{docs.DOMAIN_DN}", DOMAIN_ADMINS_SID),
            group_row(f"CN=Domain Users,{docs.DOMAIN_DN}", DOMAIN_USERS_SID),
        ]
    if computers is None:
        computers = [
            user_row(f"CN=DC01,{docs.DOMAIN_DN}", f"{docs.DOMAIN_SID}-1200",
                     primaryGroupID="516")
        ]
    document = docs.document(
        users=users,
        groups=groups,
        computers=computers,
        domain_head=[
            docs.row(docs.DOMAIN_DN, objectSid=docs.sid_blob(docs.DOMAIN_SID))
        ],
    )
    for query_id, (status, error_code) in (statuses or {}).items():
        document["queries"][query_id] = {
            "status": status,
            "error_code": error_code,
            "rows": document["queries"][query_id]["rows"],
        }
    for section_id, (status, error_code) in (file_statuses or {}).items():
        document["files"][section_id] = {
            "status": status,
            "error_code": error_code,
            "items": document["files"][section_id]["items"],
        }
    document["collector"] = collector
    document["settings"]["items"] = docs.settings_items(collector)
    document["identity"]["sid"] = identity_sid
    document["identity"]["token_group_sids"] = (
        token_group_sids
        if token_group_sids is not None
        else [DOMAIN_USERS_SID, "S-1-5-11"]
    )
    return docs.wire.parse(
        json.dumps(document).encode("utf-8"),
        docs.queryset.load(),
    )


def make_check(
    check_id: str = "AD-TEST-01",
    *,
    queries: tuple[str, ...] = ("users",),
    files: tuple[str, ...] = (),
    required_attrs: tuple[str, ...] = (),
    sentinels: tuple[str, ...] = (),
    evaluate: Any = None,
) -> catalogue.Check:
    """A check that passes unless the test says otherwise."""

    def passing(document: Any) -> model.CheckResult:
        return model.CheckResult(
            check_id=check_id,
            title="a test check",
            severity=model.Severity.MEDIUM,
            status=model.Status.PASS,
        )

    return catalogue.Check(
        id=check_id,
        title="a test check",
        severity=model.Severity.MEDIUM,
        evaluate=evaluate if evaluate is not None else passing,
        queries=queries,
        files=files,
        required_attrs=required_attrs,
        sentinels=sentinels,
    )


def test_the_audit_runs_with_an_ordinary_key() -> None:
    """An ordinary account may audit."""
    report = runner.run(audit_document(), "ad-windows", checks=[make_check()])

    assert report.results[0].status == model.Status.PASS
    assert report.domain == "win.newton.test"
    assert report.collector == "windows"


def test_a_privileged_key_is_refused() -> None:
    """The audit account is RID 500."""
    document = audit_document(
        identity_sid=ADMIN_SID,
        users=[
            user_row(f"CN=Administrator,{docs.DOMAIN_DN}", ADMIN_SID),
            user_row(f"CN=krbtgt,{docs.DOMAIN_DN}", KRBTGT_SID),
        ],
    )

    with pytest.raises(runner.PrivilegedKey) as caught:
        runner.run(document, "ad-windows", checks=[make_check()])

    assert str(caught.value) == runner.IDENTITY_GUARD_MESSAGE
    assert caught.value.reason == "rid_500"


def test_a_key_that_is_nested_in_domain_admins_is_refused() -> None:
    """The guard computes the nested membership itself."""
    nested_dn = f"CN=Nested,{docs.DOMAIN_DN}"
    nested_sid = f"{docs.DOMAIN_SID}-1201"
    document = audit_document(
        users=[
            user_row(f"CN=Administrator,{docs.DOMAIN_DN}", ADMIN_SID),
            user_row(f"CN=krbtgt,{docs.DOMAIN_DN}", KRBTGT_SID),
            user_row(f"CN=audit,{docs.DOMAIN_DN}", AUDIT_SID),
        ],
        groups=[
            group_row(
                f"CN=Domain Admins,{docs.DOMAIN_DN}",
                DOMAIN_ADMINS_SID,
                [nested_dn],
            ),
            group_row(f"CN=Nested,{docs.DOMAIN_DN}", nested_sid, [
                f"CN=audit,{docs.DOMAIN_DN}"
            ]),
            group_row(f"CN=Domain Users,{docs.DOMAIN_DN}", DOMAIN_USERS_SID),
        ],
    )

    with pytest.raises(runner.PrivilegedKey) as caught:
        runner.run(document, "ad-windows", checks=[make_check()])

    assert caught.value.reason == "privileged_member"


def test_a_key_whose_primary_group_is_domain_admins_is_refused() -> None:
    """The primary group is a membership no member value shows."""
    document = audit_document(
        users=[
            user_row(f"CN=Administrator,{docs.DOMAIN_DN}", ADMIN_SID),
            user_row(f"CN=krbtgt,{docs.DOMAIN_DN}", KRBTGT_SID),
            user_row(f"CN=audit,{docs.DOMAIN_DN}", AUDIT_SID, primaryGroupID="512"),
        ],
    )

    with pytest.raises(runner.PrivilegedKey) as caught:
        runner.run(document, "ad-windows", checks=[make_check()])

    assert caught.value.reason == "privileged_member"


def test_a_key_that_is_not_in_the_users_is_refused() -> None:
    """The guard does not trust the token alone."""
    document = audit_document(
        users=[
            user_row(f"CN=Administrator,{docs.DOMAIN_DN}", ADMIN_SID),
            user_row(f"CN=krbtgt,{docs.DOMAIN_DN}", KRBTGT_SID),
        ],
    )

    with pytest.raises(runner.PrivilegedKey) as caught:
        runner.run(document, "ad-windows", checks=[make_check()])

    assert caught.value.reason == "not_in_users"


def test_a_key_that_holds_a_privileged_token_sid_is_refused() -> None:
    """A privileged group in the token stops the audit."""
    document = audit_document(token_group_sids=[DOMAIN_ADMINS_SID])

    with pytest.raises(runner.PrivilegedKey) as caught:
        runner.run(document, "ad-windows", checks=[make_check()])

    assert caught.value.reason == "privileged_token"


def test_the_guard_runs_even_when_no_check_is_wanted() -> None:
    """The guard is first and always."""
    document = audit_document(
        identity_sid=ADMIN_SID,
        users=[
            user_row(f"CN=Administrator,{docs.DOMAIN_DN}", ADMIN_SID),
            user_row(f"CN=krbtgt,{docs.DOMAIN_DN}", KRBTGT_SID),
        ],
    )

    with pytest.raises(runner.PrivilegedKey):
        runner.run(document, "ad-windows", checks=[])


def test_a_failed_sentinel_makes_the_check_unknown() -> None:
    """A sentinel that fails is UNKNOWN(access_denied)."""
    document = audit_document(
        computers=[
            user_row(f"CN=DC01,{docs.DOMAIN_DN}", f"{docs.DOMAIN_SID}-1200")
        ],
    )
    check = make_check(sentinels=("computers",))

    report = runner.run(document, "ad-windows", checks=[check])

    result = report.results[0]
    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ACCESS_DENIED


def test_a_failing_sentinel_of_a_groups_query_stops_the_audit() -> None:
    """The groups sentinel wants RID 512 and RID 513.

    The guard needs that data to compute the privileged set, so a
    groups query that fails it stops the audit before any check runs.
    """
    document = audit_document(
        groups=[
            group_row(f"CN=Domain Admins,{docs.DOMAIN_DN}", DOMAIN_ADMINS_SID)
        ]
    )
    check = make_check(queries=("groups",), sentinels=("groups",))

    with pytest.raises(runner.PrivilegedKey) as caught:
        runner.run(document, "ad-windows", checks=[check])

    assert caught.value.reason == "cannot_verify"


def test_a_missing_required_attribute_makes_the_check_unknown() -> None:
    """A readable object without a required attribute is UNKNOWN."""
    document = audit_document(
        users=[
            user_row(f"CN=Administrator,{docs.DOMAIN_DN}", ADMIN_SID),
            user_row(f"CN=krbtgt,{docs.DOMAIN_DN}", KRBTGT_SID),
            user_row(f"CN=audit,{docs.DOMAIN_DN}", AUDIT_SID),
        ],
    )
    check = make_check(required_attrs=("userAccountControl",))

    report = runner.run(document, "ad-windows", checks=[check])

    result = report.results[0]
    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ACCESS_DENIED


def test_an_exception_inside_a_check_is_that_check_unknown() -> None:
    """One broken check never stops the audit."""

    def broken(document: Any) -> model.CheckResult:
        raise RuntimeError("the check is broken")

    check = make_check(evaluate=broken)

    report = runner.run(audit_document(), "ad-windows", checks=[check])

    result = report.results[0]
    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ERROR


def test_a_query_status_that_is_not_ok_maps_to_its_reason() -> None:
    """A status other than ok maps to the reason of the same name."""
    document = audit_document(statuses={"gmsa": ("truncated", "size_limit")})
    check = make_check(queries=("gmsa",))

    report = runner.run(document, "ad-windows", checks=[check])

    result = report.results[0]
    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.TRUNCATED


def test_a_file_section_that_is_not_ok_maps_to_its_reason() -> None:
    """A file section that did not complete is UNKNOWN."""
    document = audit_document(file_statuses={"gpp": ("truncated", "size_limit")})
    check = make_check(files=("gpp",))

    report = runner.run(document, "ad-windows", checks=[check])

    result = report.results[0]
    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.TRUNCATED


def test_a_denied_query_is_access_denied() -> None:
    """A denied read is UNKNOWN(access_denied)."""
    document = audit_document(statuses={"gmsa": ("denied", "access_denied")})

    report = runner.run(
        document, "ad-windows", checks=[make_check(queries=("gmsa",))]
    )

    assert report.results[0].reason == model.UnknownReason.ACCESS_DENIED


def test_an_empty_query_an_ordinary_account_may_not_see_is_unknown() -> None:
    """Empty is "could not read", never PASS."""
    document = audit_document()
    check = make_check(queries=("psos",))

    report = runner.run(document, "ad-windows", checks=[check])

    result = report.results[0]
    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ACCESS_DENIED
    assert result.note == runner.NOT_VISIBLE_NOTE


def test_an_empty_query_of_a_samba_collector_is_a_real_empty() -> None:
    """A root read sees the empty."""
    document = audit_document(collector="samba")
    check = make_check(queries=("psos",))

    report = runner.run(document, "ad-samba", checks=[check])

    assert report.results[0].status == model.Status.PASS


def test_a_finding_is_reported_as_a_finding() -> None:
    """A check that finds something reports a finding."""

    def finding(document: Any) -> model.CheckResult:
        return model.CheckResult(
            check_id="AD-TEST-01",
            title="a test check",
            severity=model.Severity.MEDIUM,
            status=model.Status.FINDING,
            findings=(
                model.Finding(
                    check_id="AD-TEST-01",
                    severity=model.Severity.MEDIUM,
                    title="something is wrong",
                    objects=(
                        model.Affected(sid=USER_SID, name="a user", dn="CN=a"),
                    ),
                ),
            ),
        )

    report = runner.run(audit_document(), "ad-windows", checks=[make_check(evaluate=finding)])

    result = report.results[0]
    assert result.status == model.Status.FINDING
    assert result.findings[0].title == "something is wrong"
    assert report.counts["FINDING"] == 1
    assert report.counts["medium"] == 1


def test_the_counts_are_by_status_and_by_severity() -> None:
    """The report counts what it found."""
    report = runner.run(audit_document(), "ad-windows", checks=[make_check()])

    assert report.counts["PASS"] == 1
    assert report.counts["FINDING"] == 0
    assert report.counts["UNKNOWN"] == 0
    assert report.counts["medium"] == 1


def test_the_report_carries_the_scope_note() -> None:
    """Every report says what it did not look at."""
    report = runner.run(audit_document(), "ad-windows", checks=[make_check()])

    assert "AD-A-43" in report.scope_note
    assert report.generated


def test_the_catalogue_holds_each_check_once() -> None:
    """The checks of the three modules are in the catalogue, each one once."""
    ids = [check.id for check in catalogue.CHECKS]
    assert ids
    assert len(ids) == len(set(ids))
    assert "AD-A-01" in ids
    assert "AD-A-33" in ids
    assert "AD-A-51" in ids


def test_the_guard_refuses_when_the_users_query_did_not_complete() -> None:
    """A privileged set that is partial is not a verification."""
    document = audit_document(statuses={"users": ("denied", "access_denied")})

    with pytest.raises(runner.PrivilegedKey) as caught:
        runner.run(document, "ad-windows", checks=[make_check()])

    assert caught.value.reason == "cannot_verify"


def test_the_guard_refuses_when_the_groups_query_did_not_complete() -> None:
    """The groups carry the privileged membership."""
    document = audit_document(statuses={"groups": ("truncated", "size_limit")})

    with pytest.raises(runner.PrivilegedKey) as caught:
        runner.run(document, "ad-windows", checks=[make_check()])

    assert caught.value.reason == "cannot_verify"


def test_the_guard_refuses_when_the_fsps_query_did_not_complete() -> None:
    """A foreign security principal may be a privileged member."""
    document = audit_document(statuses={"fsps": ("denied", "access_denied")})

    with pytest.raises(runner.PrivilegedKey) as caught:
        runner.run(document, "ad-windows", checks=[make_check()])

    assert caught.value.reason == "cannot_verify"


def test_the_guard_refuses_when_the_users_sentinel_fails() -> None:
    """The users sentinel must hold RID 500 and RID 502."""
    document = audit_document(
        users=[
            user_row(f"CN=Administrator,{docs.DOMAIN_DN}", ADMIN_SID),
            user_row(f"CN=audit,{docs.DOMAIN_DN}", AUDIT_SID),
        ],
    )

    with pytest.raises(runner.PrivilegedKey) as caught:
        runner.run(document, "ad-windows", checks=[make_check()])

    assert caught.value.reason == "cannot_verify"


def test_the_guard_refuses_when_the_groups_sentinel_fails() -> None:
    """The groups sentinel must hold RID 512 and RID 513."""
    document = audit_document(
        groups=[
            group_row(f"CN=Domain Admins,{docs.DOMAIN_DN}", DOMAIN_ADMINS_SID)
        ]
    )

    with pytest.raises(runner.PrivilegedKey) as caught:
        runner.run(document, "ad-windows", checks=[make_check()])

    assert caught.value.reason == "cannot_verify"


def test_the_document_must_be_the_collector_of_the_platform() -> None:
    """A document of another collector is refused."""
    document = audit_document(collector="samba")

    with pytest.raises(runner.CollectorMismatch) as caught:
        runner.run(document, "ad-windows", checks=[make_check()])

    assert str(caught.value) == runner.COLLECTOR_MISMATCH_MESSAGE


def test_a_platform_that_is_not_an_ad_platform_is_refused() -> None:
    """The audit only runs on the two AD platforms."""
    with pytest.raises(runner.CollectorMismatch) as caught:
        runner.run(audit_document(), "openwrt", checks=[make_check()])

    assert str(caught.value) == runner.PLATFORM_MISMATCH_MESSAGE


def test_the_collector_of_the_platform_is_accepted() -> None:
    """The samba document runs on the samba platform."""
    report = runner.run(
        audit_document(collector="samba"),
        "ad-samba",
        checks=[make_check()],
    )

    assert report.collector == "samba"
