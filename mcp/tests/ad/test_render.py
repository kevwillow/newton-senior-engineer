"""The renderer: the envelope, the redaction and the fix commands."""

from __future__ import annotations

import json
from typing import Any

import pytest

from newton_mcp.ad import model, render


USER_SID = "S-1-5-21-1004336348-1177238915-682003330-1107"
USER_NAME = "svc-backup"
USER_DN = f"CN={USER_NAME},OU=People,DC=win,DC=newton,DC=test"

# The distinguished name of the domain object of the lab domain.
DOMAIN_DN = "DC=win,DC=newton,DC=test"

# The distinguished name of the template of the protected objects.
ADMINSDHOLDER_DN = "CN=AdminSDHolder,CN=System,DC=win,DC=newton,DC=test"


def make_report(
    *,
    objects: tuple[model.Affected, ...] | None = None,
    fix: model.Fix | None = None,
) -> model.AuditReport:
    """A report with one finding."""
    finding = model.Finding(
        check_id="AD-TEST-01",
        severity=model.Severity.MEDIUM,
        title="something is wrong",
        objects=objects
        if objects is not None
        else (model.Affected(sid=USER_SID, name=USER_NAME, dn=USER_DN),),
        maps_to=("AD-A-01",),
        fix=fix,
    )
    result = model.CheckResult(
        check_id="AD-TEST-01",
        title="something is wrong",
        severity=model.Severity.MEDIUM,
        status=model.Status.FINDING,
        findings=(finding,),
    )
    return model.AuditReport(
        domain="win.newton.test",
        collector="windows",
        counts={"PASS": 0, "FINDING": 1, "UNKNOWN": 0},
        results=(result,),
        generated="2026-11-08T12:00:00Z",
        scope_note=model.SCOPE_NOTE,
    )


def test_the_name_of_an_object_is_in_the_envelope() -> None:
    """A directory name is data, never an instruction."""
    rendered = render.render(make_report())

    name = rendered["results"][0]["findings"][0]["objects"][0]["name"]
    assert name["kind"] == "untrusted-device-data"
    assert USER_NAME in name["text"]


def test_the_distinguished_name_of_an_object_is_in_the_envelope() -> None:
    """A distinguished name is data too."""
    rendered = render.render(make_report())

    dn = rendered["results"][0]["findings"][0]["objects"][0]["dn"]
    assert dn["kind"] == "untrusted-device-data"
    assert USER_DN in dn["text"]


def test_the_domain_is_in_the_envelope() -> None:
    """The domain name comes from the directory."""
    rendered = render.render(make_report())

    assert rendered["domain"]["kind"] == "untrusted-device-data"
    assert "win.newton.test" in rendered["domain"]["text"]


def test_the_sid_is_not_in_an_envelope() -> None:
    """A SID is formatted by Newton from the binary value."""
    rendered = render.render(make_report())

    affected = rendered["results"][0]["findings"][0]["objects"][0]
    assert affected["sid"] == USER_SID


def test_a_fix_command_names_the_object_by_its_sid() -> None:
    """The only substitution of a command is a SID or a GUID."""
    fix = model.Fix(
        windows=model.FixStep(
            summary="turn the flag off",
            commands=("Set-ADAccountControl -Identity '{sid}' -DoesNotRequirePreAuth $false",),
        ),
        samba=model.FixStep(
            summary="turn the flag off",
            commands=("ldbmodify -H '{sid}' --add='userAccountControl: 512'",),
        ),
    )

    rendered = render.render(make_report(fix=fix))

    windows = rendered["results"][0]["findings"][0]["fix"]["windows"]
    assert windows["commands"][0] == (
        f"Set-ADAccountControl -Identity '{USER_SID}' -DoesNotRequirePreAuth $false"
    )
    samba = rendered["results"][0]["findings"][0]["fix"]["samba"]
    assert USER_SID in samba["commands"][0]


def test_a_command_that_holds_a_directory_string_is_refused() -> None:
    """A command with a name in it never reaches the owner."""
    fix = model.Fix(
        windows=model.FixStep(
            summary="turn the flag off",
            commands=(f"Set-ADAccountControl -Identity '{USER_NAME}'",),
        ),
        samba=model.FixStep(summary="turn the flag off"),
    )

    with pytest.raises(render.RenderError):
        render.render(make_report(fix=fix))


def test_the_proof_of_a_command_is_public() -> None:
    """The proof is a function of its own."""
    with pytest.raises(render.RenderError):
        render.assert_no_directory_text(
            "Set-ADAccountControl -Identity 'the user'",
            ["the user"],
        )


def test_a_command_without_a_directory_string_passes_the_proof() -> None:
    """The proof passes a command that holds no directory text."""
    render.assert_no_directory_text(
        f"Set-ADAccountControl -Identity '{USER_SID}'",
        [USER_NAME, USER_DN],
    )


def test_a_command_without_an_identifier_is_refused() -> None:
    """A placeholder with no value never reaches the owner."""
    fix = model.Fix(
        windows=model.FixStep(
            summary="turn the flag off",
            commands=("Set-ADAccountControl -Identity '{sid}'",),
        ),
        samba=model.FixStep(summary="turn the flag off"),
    )
    report = make_report(fix=fix, objects=(model.Affected(name=USER_NAME),))

    with pytest.raises(render.RenderError):
        render.render(report)


def test_a_secret_in_a_directory_string_is_redacted() -> None:
    """A secret-looking value never reaches the model."""
    report = make_report(
        objects=(
            model.Affected(
                sid=USER_SID,
                name="password=hunter2",
                dn=USER_DN,
            ),
        )
    )

    rendered = json.dumps(render.render(report))

    assert "hunter2" not in rendered


def test_the_report_carries_its_counts_and_its_status() -> None:
    """The model reads the status of every check."""
    rendered = render.render(make_report())

    assert rendered["results"][0]["status"] == "FINDING"
    assert rendered["results"][0]["severity"] == "medium"
    assert rendered["counts"]["FINDING"] == 1
    assert rendered["collector"] == "windows"
    assert rendered["generated"] == "2026-11-08T12:00:00Z"


def test_the_report_carries_the_scope_note() -> None:
    """Every report says what it did not look at."""
    rendered = render.render(make_report())

    assert "AD-A-43" in rendered["scope_note"]


@pytest.mark.parametrize(
    "hostile",
    [
        "'",
        '"',
        ";",
        "$()",
        "`id`",
        "\n",
        "‛",
        "‘",
        "name`whoami`",
        "$(rm -rf /)",
        "| tee",
        "&",
    ],
)
def test_a_hostile_name_never_ends_up_inside_a_command(hostile: str) -> None:
    """A hostile directory name stays out of every command.

    The command is the template and the identifier, nothing else: the
    name never reaches it, whatever the name holds.
    """
    windows_template = (
        "Set-ADAccountControl -Identity '{sid}' -DoesNotRequirePreAuth $false"
    )
    samba_template = "ldbmodify -H '{sid}' --add='userAccountControl: 512'"
    fix = model.Fix(
        windows=model.FixStep(
            summary="turn the flag off",
            commands=(windows_template,),
        ),
        samba=model.FixStep(
            summary="turn the flag off",
            commands=(samba_template,),
        ),
    )
    report = make_report(
        fix=fix,
        objects=(
            model.Affected(
                sid=USER_SID,
                name=hostile,
                dn=f"CN={hostile},OU=People,DC=win,DC=newton,DC=test",
            ),
        ),
    )

    rendered = render.render(report)

    finding = rendered["results"][0]["findings"][0]
    assert finding["fix"]["windows"]["commands"] == (
        windows_template.replace("{sid}", USER_SID),
    )
    assert finding["fix"]["samba"]["commands"] == (
        samba_template.replace("{sid}", USER_SID),
    )
    for command in finding["fix"]["windows"]["commands"]:
        assert USER_SID in command
    for command in finding["fix"]["samba"]["commands"]:
        assert USER_SID in command


def test_an_unknown_result_carries_its_reason() -> None:
    """The reason of an UNKNOWN is the reason of the query."""
    result = model.CheckResult(
        check_id="AD-TEST-02",
        title="a test check",
        severity=model.Severity.LOW,
        status=model.Status.UNKNOWN,
        reason=model.UnknownReason.ACCESS_DENIED,
        note="none visible to the audit account",
    )
    report = model.AuditReport(
        domain="win.newton.test",
        collector="windows",
        counts={},
        results=(result,),
        generated="2026-11-08T12:00:00Z",
        scope_note=model.SCOPE_NOTE,
    )

    rendered = render.render(report)

    assert rendered["results"][0]["reason"] == "access_denied"
    note = rendered["results"][0]["note"]
    assert note["kind"] == "untrusted-device-data"
    assert "none visible to the audit account" in note["text"]


def test_a_sid_that_is_not_canonical_is_refused() -> None:
    """A command never carries a SID that is not canonical."""
    fix = model.Fix(
        windows=model.FixStep(
            summary="turn the flag off",
            commands=("Set-ADAccountControl -Identity '{sid}'",),
        ),
        samba=model.FixStep(summary="turn the flag off"),
    )
    report = make_report(
        fix=fix,
        objects=(model.Affected(sid="S-01-5-21-1-2-3-512"),),
    )

    with pytest.raises(render.RenderError):
        render.render(report)


def test_a_sid_that_ends_in_a_newline_is_refused() -> None:
    """A SID that ends in a newline never reaches a command."""
    fix = model.Fix(
        windows=model.FixStep(
            summary="turn the flag off",
            commands=("Set-ADAccountControl -Identity '{sid}'",),
        ),
        samba=model.FixStep(summary="turn the flag off"),
    )
    report = make_report(
        fix=fix,
        objects=(model.Affected(sid=f"{USER_SID}\n"),),
    )

    with pytest.raises(render.RenderError):
        render.render(report)


def test_a_guid_that_ends_in_a_newline_is_refused() -> None:
    """A GUID that ends in a newline never reaches a command."""
    fix = model.Fix(
        windows=model.FixStep(
            summary="turn the flag off",
            commands=("Set-GPO -Guid '{guid}'",),
        ),
        samba=model.FixStep(summary="turn the flag off"),
    )
    report = make_report(
        fix=fix,
        objects=(
            model.Affected(guid="00112233-4455-6677-8899-aabbccddeeff\n"),
        ),
    )

    with pytest.raises(render.RenderError):
        render.render(report)


def test_the_title_of_a_finding_is_enveloped() -> None:
    """A finding title may name an object, so it is enveloped."""
    rendered = render.render(make_report())

    title = rendered["results"][0]["findings"][0]["title"]
    assert title["kind"] == "untrusted-device-data"
    assert "something is wrong" in title["text"]


# ---- the display name of an object -------------------------------------------


def rendered_object(**fields: Any) -> dict[str, Any]:
    """The rendered object of a report that holds one object."""
    report = make_report(objects=(model.Affected(**fields),))
    rendered = render.render(report)
    return rendered["results"][0]["findings"][0]["objects"][0]


def test_the_domain_object_gets_a_display_name() -> None:
    """The domain object reads as the name of the domain."""
    obj = rendered_object(sid=USER_SID, dn=DOMAIN_DN)

    assert "win.newton.test" in obj["name"]["text"]


def test_the_admin_sd_holder_gets_a_display_name() -> None:
    """The template of the protected objects reads as its own name."""
    obj = rendered_object(sid=USER_SID, dn=ADMINSDHOLDER_DN)

    assert obj["name"]["text"] == "AdminSDHolder"


def test_a_display_name_decodes_the_escaped_comma_of_a_name() -> None:
    """An escaped comma in a name is a comma."""
    obj = rendered_object(
        sid=USER_SID,
        dn=r"CN=Doe\, John,OU=People,DC=win,DC=newton,DC=test",
    )

    assert obj["name"]["text"] == "Doe, John"


def test_a_display_name_decodes_the_hex_escape_of_a_name() -> None:
    """A hex escape in a name is the character it stands for."""
    obj = rendered_object(
        sid=USER_SID,
        dn=r"CN=Doe\2CJohn,OU=People,DC=win,DC=newton,DC=test",
    )

    assert obj["name"]["text"] == "Doe,John"


def test_the_display_name_of_an_object_is_the_name_it_has() -> None:
    """A name the directory gave is never derived over."""
    obj = rendered_object(sid=USER_SID, name=USER_NAME, dn=USER_DN)

    assert obj["name"]["text"] == USER_NAME


def test_an_object_without_a_name_and_without_a_dn_has_no_name() -> None:
    """An object that names nothing has no display name."""
    obj = rendered_object(sid=USER_SID)

    assert obj["name"] is None


def test_a_derived_display_name_is_in_the_envelope() -> None:
    """A name Newton derived is data too."""
    obj = rendered_object(sid=USER_SID, dn=DOMAIN_DN)

    assert obj["name"]["kind"] == "untrusted-device-data"


def test_a_derived_display_name_never_ends_up_inside_a_command() -> None:
    """The name Newton derived stays out of every command."""
    template = (
        "Set-ADAccountControl -Identity '{sid}' -DoesNotRequirePreAuth $false"
    )
    fix = model.Fix(
        windows=model.FixStep(
            summary="turn the flag off",
            commands=(template,),
        ),
        samba=model.FixStep(summary="turn the flag off"),
    )
    report = make_report(
        fix=fix,
        objects=(model.Affected(sid=USER_SID, dn=DOMAIN_DN),),
    )

    rendered = render.render(report)

    finding = rendered["results"][0]["findings"][0]
    assert finding["fix"]["windows"]["commands"] == (
        template.replace("{sid}", USER_SID),
    )
