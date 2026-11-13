"""The domain checks over the measured documents.

Every check is tested three times: on the measured document of the lab
(the file is named in the helper ``measured``), on a variant that
passes, and on a variant that cannot prove anything.  The variants are
made by editing the measured document in the helper, so every test says
which measurement it builds on.

The fix of a finding is rendered with ``render.render`` and every
command is checked with ``render.assert_no_directory_text``: a
directory-originated string never ends up inside a command.
"""

from __future__ import annotations

from typing import Any

from newton_mcp.ad import catalogue, model, render, runner, values

import measured


def check_of(check_id: str) -> catalogue.Check:
    """The check of the catalogue with that id."""
    for check in catalogue.CHECKS:
        if check.id == check_id:
            return check
    raise KeyError("the catalogue does not hold the check")


def run_check(check_id: str, document: Any) -> model.CheckResult:
    """The result of one check over a document, through the runner.

    The runner proves that the audit was allowed to see the data before
    the check runs: a query that did not complete, a sentinel that
    failed or a missing attribute make the check UNKNOWN.
    """
    report = runner.run(document, "ad-windows", checks=[check_of(check_id)])
    return report.results[0]


def evaluate_check(check_id: str, document: Any) -> model.CheckResult:
    """The result of one check, without the runner.

    The Administrator's document does not go through the runner: the
    identity guard refuses a privileged key, and that is what the guard
    is for.
    """
    return check_of(check_id).evaluate(document)


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


def assert_the_result_is_clean(result: model.CheckResult) -> model.CheckResult:
    """The result of a check, with its fix rendered and proven clean.

    The Administrator's document does not go through the runner: the
    identity guard refuses a privileged key.  The result of the check
    is rendered on its own.
    """
    report = model.AuditReport(
        domain="win.newton.test",
        collector="windows",
        counts={},
        results=(result,),
        generated="2026-11-08T00:00:00Z",
        scope_note="",
    )
    payload = render.render(report)
    strings = directory_strings(report)
    for entry in payload["results"]:
        for finding in entry["findings"]:
            if not finding["fix"]:
                continue
            for step in (finding["fix"]["windows"], finding["fix"]["samba"]):
                for command in step["commands"]:
                    render.assert_no_directory_text(command, strings)
    return result


# ---- the constants ----------------------------------------------------------


def test_constants() -> None:
    """The trust attributes, the heuristics and the limits are the documented ones."""
    assert values.TRUST_ATTRIBUTE_NON_TRANSITIVE == 0x1
    assert values.TRUST_ATTRIBUTE_UPLEVEL_ONLY == 0x2
    assert values.TRUST_ATTRIBUTE_QUARANTINED_DOMAIN == 0x4
    assert values.TRUST_ATTRIBUTE_FOREST_TRANSITIVE == 0x8
    assert values.TRUST_ATTRIBUTE_CROSS_ORGANIZATION == 0x10
    assert values.TRUST_ATTRIBUTE_WITHIN_FOREST == 0x20
    assert values.TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL == 0x40
    assert values.TRUST_ATTRIBUTE_USES_RC4_ENCRYPTION == 0x80
    assert values.TRUST_ATTRIBUTE_FLAGS == {
        0x00000001: "NON_TRANSITIVE",
        0x00000002: "UPLEVEL_ONLY",
        0x00000004: "QUARANTINED_DOMAIN",
        0x00000008: "FOREST_TRANSITIVE",
        0x00000010: "CROSS_ORGANIZATION",
        0x00000020: "WITHIN_FOREST",
        0x00000040: "TREAT_AS_EXTERNAL",
        0x00000080: "USES_RC4_ENCRYPTION",
    }
    assert values.DS_HEURISTICS_LIST_OBJECT == 3
    assert values.DS_HEURISTICS_BLOCK_ANONYMOUS_OPS == 7
    assert values.DS_HEURISTICS_ADMINSD_MASK == 10
    assert values.DS_HEURISTICS_ADMINSD_EXCLUDE == 20
    assert values.ds_heuristics_positions("0010001001") == {
        1: 0,
        2: 0,
        3: 1,
        4: 0,
        5: 0,
        6: 0,
        7: 1,
        8: 0,
        9: 0,
        10: 1,
    }


# ---- AD-A-33: the domain password and lockout policy -----------------------


def test_ad_a_33_finds_the_weak_password_policy_of_the_measured_domain() -> None:
    """The measured domain takes a password of seven characters."""
    result = assert_the_fix_is_clean("AD-A-33", measured.audit_document())

    assert result.status == model.Status.FINDING
    assert len(result.findings) == 2
    assert "14" in result.findings[0].title
    assert "lock" in result.findings[1].title


def test_ad_a_33_passes_when_the_policy_is_strong() -> None:
    """A policy of fourteen characters with a lockout passes."""
    raw = measured.audit_json()
    row = raw["queries"]["domain_head"]["rows"][0]
    row["a"]["minPwdLength"] = ["14"]
    row["a"]["lockoutThreshold"] = ["5"]

    result = run_check("AD-A-33", measured.parse(raw))

    assert result.status == model.Status.PASS
    assert result.findings == ()


def test_ad_a_33_is_unknown_without_the_policy() -> None:
    """A domain head without the policy is UNKNOWN, never PASS."""
    raw = measured.audit_json()
    measured.drop_attribute(raw["queries"]["domain_head"]["rows"][0], "minPwdLength")

    result = run_check("AD-A-33", measured.parse(raw))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ACCESS_DENIED


def test_the_domain_object_of_the_report_has_a_display_name() -> None:
    """The domain object reads as the name of the domain.

    The directory gives the domain no name of its own: the name is
    derived from its distinguished name, so the report shows what the
    object is.
    """
    report = runner.run(
        measured.audit_document(),
        "ad-windows",
        checks=[check_of("AD-A-33")],
    )
    payload = render.render(report)

    obj = payload["results"][0]["findings"][0]["objects"][0]
    assert "win.newton.test" in obj["name"]["text"]


def test_the_fix_of_ad_a_33_explains_the_change() -> None:
    """The fix of the domain policy is an explanation, not a command.

    The cmdlet takes the two lockout values as TimeSpans: a plain
    number would be read as days, so the summary names the TimeSpan
    form.  The Samba step names the command of the Samba tools and the
    values to choose, and runs nothing.
    """
    report = runner.run(
        measured.audit_document(),
        "ad-windows",
        checks=[check_of("AD-A-33")],
    )
    payload = render.render(report)
    fix = payload["results"][0]["findings"][0]["fix"]

    assert fix["windows"]["commands"] == ()
    assert fix["samba"]["commands"] == ()
    assert "Set-ADDefaultDomainPasswordPolicy" in fix["windows"]["summary"]
    assert "00:30:00" in fix["windows"]["summary"]
    assert "LockoutDuration 30" not in fix["windows"]["summary"]
    assert (
        "samba-tool domain passwordsettings set" in fix["samba"]["summary"]
    )
    assert fix["windows"]["changes"]
    assert fix["windows"]["revert"]
    assert fix["samba"]["changes"]
    assert fix["samba"]["revert"]


# ---- AD-A-34: the Kerberos policy -------------------------------------------


def test_ad_a_34_reads_the_kerberos_policy_of_the_linked_gpo() -> None:
    """The GPO linked at the domain head carries the Kerberos policy."""
    result = run_check("AD-A-34", measured.audit_document())

    assert result.status == model.Status.PASS
    assert "MaxTicketAge 10" in result.note
    assert "MaxClockSkew 5" in result.note


def test_ad_a_34_passes_with_the_edited_policy() -> None:
    """The policy of the edited document is read as it is."""
    raw = measured.audit_json()
    for item in raw["files"]["gpttmpl"]["items"]:
        if item["section"] == "Kerberos Policy" and item["key"] == "MaxTicketAge":
            item["value"] = "4"

    result = run_check("AD-A-34", measured.parse(raw))

    assert result.status == model.Status.PASS
    assert "MaxTicketAge 4" in result.note


def test_ad_a_34_finds_a_ticket_that_lives_too_long() -> None:
    """A ticket age of more than ten hours is a finding."""
    raw = measured.audit_json()
    for item in raw["files"]["gpttmpl"]["items"]:
        if item["section"] == "Kerberos Policy" and item["key"] == "MaxTicketAge":
            item["value"] = "11"

    result = assert_the_fix_is_clean("AD-A-34", measured.parse(raw))

    assert result.status == model.Status.FINDING
    assert len(result.findings) == 1
    assert "MaxTicketAge" in (result.findings[0].objects[0].evidence or "")


def test_ad_a_34_finds_a_renewal_that_lives_too_long() -> None:
    """A renewal age of more than seven days is a finding."""
    raw = measured.audit_json()
    for item in raw["files"]["gpttmpl"]["items"]:
        if item["section"] == "Kerberos Policy" and item["key"] == "MaxRenewAge":
            item["value"] = "8"

    result = assert_the_fix_is_clean("AD-A-34", measured.parse(raw))

    assert result.status == model.Status.FINDING
    assert len(result.findings) == 1


def test_ad_a_34_finds_a_clock_skew_that_is_too_large() -> None:
    """A clock skew of more than five minutes is a finding."""
    raw = measured.audit_json()
    for item in raw["files"]["gpttmpl"]["items"]:
        if item["section"] == "Kerberos Policy" and item["key"] == "MaxClockSkew":
            item["value"] = "6"

    result = assert_the_fix_is_clean("AD-A-34", measured.parse(raw))

    assert result.status == model.Status.FINDING
    assert len(result.findings) == 1


def test_ad_a_34_reads_the_first_gpo_the_domain_head_links() -> None:
    """The first link of the domain head is the one that configures it."""
    raw = measured.audit_json()
    head = raw["queries"]["domain_head"]["rows"][0]
    seed = (
        "[LDAP://CN={4A06E176-48DD-4B65-B2B0-214B24EB0F59},CN=Policies,"
        "CN=System,DC=win,DC=newton,DC=test;0]"
    )
    head["a"]["gPLink"] = [seed + head["a"]["gPLink"][0]]
    for key, value in (
        ("MaxTicketAge", "40"),
        ("MaxServiceAge", "600"),
        ("MaxRenewAge", "7"),
        ("MaxClockSkew", "5"),
    ):
        raw["files"]["gpttmpl"]["items"].append(
            {
                "gpo": "{4A06E176-48DD-4B65-B2B0-214B24EB0F59}",
                "section": "Kerberos Policy",
                "key": key,
                "value": value,
            }
        )

    result = run_check("AD-A-34", measured.parse(raw))

    assert result.status == model.Status.FINDING
    assert "MaxTicketAge 40" in result.note


def test_ad_a_34_skips_a_link_that_is_disabled() -> None:
    """A link that is disabled configures nothing."""
    raw = measured.audit_json()
    head = raw["queries"]["domain_head"]["rows"][0]
    head["a"]["gPLink"] = [
        head["a"]["gPLink"][0].replace(";0]", ";1]"),
    ]

    result = run_check("AD-A-34", measured.parse(raw))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.NOT_COLLECTED


def test_ad_a_34_is_unknown_without_the_kerberos_policy() -> None:
    """A template without the Kerberos policy proves nothing."""
    raw = measured.audit_json()
    raw["files"]["gpttmpl"]["items"] = [
        item
        for item in raw["files"]["gpttmpl"]["items"]
        if item["section"] != "Kerberos Policy"
    ]

    result = run_check("AD-A-34", measured.parse(raw))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.NOT_COLLECTED


def test_ad_a_34_passes_on_the_measured_samba_document_with_the_stock_template() -> None:
    """AD-A-34 passes on a stock Samba domain controller.

    The template of the Default Domain Policy of a stock Samba DC holds
    ten keys of the [System Access] section and one of the [Kerberos
    Policy] section that no check of Newton reads.  A key that is not
    read is dropped silently, so the check is not left with a scan it
    may not trust, and it passes on the policy of the template.
    """
    raw = measured.samba_json()
    raw["files"]["gpttmpl"]["items"] = [
        {
            "gpo": "{31B2F340-016D-11D2-945F-00C04FB984F9}",
            "section": "Kerberos Policy",
            "key": key,
            "value": value,
        }
        for key, value in (
            ("MaxTicketAge", "10"),
            ("MaxServiceAge", "600"),
            ("MaxRenewAge", "7"),
            ("MaxClockSkew", "5"),
        )
    ]

    report = runner.run(
        measured.parse(raw), "ad-samba", checks=[check_of("AD-A-34")]
    )
    result = report.results[0]

    assert result.status == model.Status.PASS
    assert "MaxTicketAge 10" in result.note
    assert "MaxClockSkew 5" in result.note


def test_ad_a_34_is_unknown_when_a_template_file_was_refused() -> None:
    """A template the collector refused is not a proof of anything.

    The policy of the GPO may sit in the file that was refused, so the
    check cannot say that the policy is good.
    """
    raw = measured.audit_json()
    raw["files"]["gpttmpl"]["parse_refused"] = 1

    result = run_check("AD-A-34", measured.parse(raw))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.PARSE_REFUSED
    assert "refused 1" in result.note


def test_the_note_of_a_refused_scan_counts_the_items_and_the_files() -> None:
    """The note of a refused scan says what was refused and what was skipped.

    A key of a template that no check reads is dropped and not counted,
    so the count of the refusals is a count of items and not a count of
    files.
    """
    raw = measured.audit_json()
    raw["files"]["gpttmpl"]["parse_refused"] = 1
    raw["files"]["gpttmpl"]["skipped_special"] = 2

    result = run_check("AD-A-34", measured.parse(raw))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.PARSE_REFUSED
    assert "refused 1 item(s)" in result.note
    assert "skipped 2 special file(s)" in result.note


def test_ad_a_34_finds_a_policy_of_a_section_that_refused_a_file() -> None:
    """A policy that was read is judged, whatever the counts are."""
    raw = measured.audit_json()
    raw["files"]["gpttmpl"]["parse_refused"] = 1
    for item in raw["files"]["gpttmpl"]["items"]:
        if item["section"] == "Kerberos Policy" and item["key"] == "MaxTicketAge":
            item["value"] = "11"

    result = assert_the_fix_is_clean("AD-A-34", measured.parse(raw))

    assert result.status == model.Status.FINDING
    assert len(result.findings) == 1


# ---- AD-A-35: the fine-grained password policies ----------------------------


def test_ad_a_35_is_unknown_on_the_measured_audit_document() -> None:
    """The audit account cannot read the password settings."""
    result = run_check("AD-A-35", measured.audit_document())

    assert result.status == model.Status.UNKNOWN


def test_ad_a_35_finds_the_seeded_policy_in_the_measured_admin_document() -> None:
    """The Administrator document holds the seeded policy of the lab."""
    result = assert_the_result_is_clean(
        evaluate_check("AD-A-35", measured.admin_document())
    )

    assert result.status == model.Status.FINDING
    assert len(result.findings) == 1
    affected = result.findings[0].objects[0]
    assert affected.dn is not None and "seed-pso" in affected.dn
    assert affected.evidence is not None
    assert "minimum password length is 4" in affected.evidence


def test_ad_a_35_passes_when_the_policy_is_strong() -> None:
    """A policy of fourteen characters with a lockout passes."""
    raw = measured.audit_json()
    measured.set_query_status(raw, "psos", "ok")
    row = dict(measured.admin_json()["queries"]["psos"]["rows"][0])
    row["a"]["msDS-MinimumPasswordLength"] = ["14"]
    row["a"]["msDS-LockoutThreshold"] = ["5"]
    raw["queries"]["psos"]["rows"] = [row]

    result = run_check("AD-A-35", measured.parse(raw))

    assert result.status == model.Status.PASS
    assert result.findings == ()


def test_ad_a_35_is_unknown_when_the_settings_are_empty() -> None:
    """An empty list of settings is "could not read", never "nothing there"."""
    raw = measured.audit_json()
    measured.set_query_status(raw, "psos", "ok")
    raw["queries"]["psos"]["rows"] = []

    result = run_check("AD-A-35", measured.parse(raw))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ACCESS_DENIED


# ---- AD-A-36, AD-A-37 and AD-A-38: the configured protocols -----------------


# The GPO that is linked at the unit of the domain controllers.
DC_GPO = "{6AC1786C-016F-11D2-945F-00C04fB984F9}"


def registry_item(document: dict[str, Any], name: str) -> dict[str, Any]:
    """The settings item of the collector host of that name."""
    for item in document["settings"]["items"]:
        if item["key"].lower().endswith(name.lower()):
            return item
    raise KeyError("the document does not carry the setting")


def test_ad_a_36_is_unknown_when_the_signing_setting_was_not_read() -> None:
    """The measured host does not report the signing setting."""
    result = run_check("AD-A-36", measured.audit_document())

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.UNAVAILABLE
    assert "configured; observed not collected" in result.note


def test_ad_a_36_passes_when_the_signing_is_required() -> None:
    """A signing setting of two requires every bind to be signed."""
    raw = measured.audit_json()
    measured.set_setting(raw, "LDAPServerIntegrity", "2")

    result = run_check("AD-A-36", measured.parse(raw))

    assert result.status == model.Status.PASS
    assert "configured; observed not collected" in result.note


def test_ad_a_36_is_unknown_when_a_template_file_was_refused() -> None:
    """A template the collector refused is not a proof of anything."""
    raw = measured.audit_json()
    measured.set_setting(raw, "LDAPServerIntegrity", "2")
    raw["files"]["gpttmpl"]["parse_refused"] = 1

    result = run_check("AD-A-36", measured.parse(raw))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.PARSE_REFUSED


def test_ad_a_36_finds_a_host_that_does_not_require_signing() -> None:
    """A signing setting of zero accepts a bind that is not signed."""
    raw = measured.audit_json()
    measured.set_setting(raw, "LDAPServerIntegrity", "0")

    result = assert_the_fix_is_clean("AD-A-36", measured.parse(raw))

    assert result.status == model.Status.FINDING
    assert len(result.findings) == 1
    assert "signing" in result.findings[0].title


def test_ad_a_36_reads_the_gpo_of_the_unit_of_the_domain_controllers() -> None:
    """The GPO that configures the domain controllers is the one of their unit."""
    raw = measured.audit_json()
    raw["files"]["gpttmpl"]["items"].append(
        {
            "gpo": DC_GPO,
            "section": "Registry Values",
            "key": (
                "HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters"
                "\\LDAPServerIntegrity"
            ),
            "value": "0",
        }
    )

    result = assert_the_fix_is_clean("AD-A-36", measured.parse(raw))

    assert result.status == model.Status.FINDING
    assert len(result.findings) == 1
    assert "LDAPServerIntegrity 0" in result.note


def test_ad_a_36_does_not_read_a_gpo_of_a_link_that_is_disabled() -> None:
    """A link that is disabled configures nothing."""
    raw = measured.audit_json()
    raw["files"]["gpttmpl"]["items"].append(
        {
            "gpo": DC_GPO,
            "section": "Registry Values",
            "key": (
                "HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters"
                "\\LDAPServerIntegrity"
            ),
            "value": "0",
        }
    )
    for row in raw["queries"]["ous"]["rows"]:
        if "OU=Domain Controllers" in row["dn"]:
            row["a"]["gPLink"] = [
                row["a"]["gPLink"][0].replace(";0]", ";1]"),
            ]

    result = run_check("AD-A-36", measured.parse(raw))

    assert result.status == model.Status.UNKNOWN


def test_ad_a_36_the_registry_of_the_host_wins_over_the_gpo() -> None:
    """The value of the collector host is the one that counts."""
    raw = measured.audit_json()
    measured.set_setting(raw, "LDAPServerIntegrity", "2")
    raw["files"]["gpttmpl"]["items"].append(
        {
            "gpo": DC_GPO,
            "section": "Registry Values",
            "key": (
                "HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters"
                "\\LDAPServerIntegrity"
            ),
            "value": "0",
        }
    )

    result = run_check("AD-A-36", measured.parse(raw))

    assert result.status == model.Status.PASS


def test_ad_a_37_is_unknown_when_the_channel_binding_was_not_read() -> None:
    """The measured host does not report the channel binding setting."""
    result = run_check("AD-A-37", measured.audit_document())

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.UNAVAILABLE


def test_ad_a_37_passes_when_the_channel_binding_is_enforced() -> None:
    """A channel binding setting of one enforces the binding."""
    raw = measured.audit_json()
    measured.set_setting(raw, "LdapEnforceChannelBinding", "1")

    result = run_check("AD-A-37", measured.parse(raw))

    assert result.status == model.Status.PASS


def test_ad_a_37_is_unknown_when_a_template_file_was_refused() -> None:
    """A template the collector refused is not a proof of anything."""
    raw = measured.audit_json()
    measured.set_setting(raw, "LdapEnforceChannelBinding", "1")
    raw["files"]["gpttmpl"]["parse_refused"] = 1

    result = run_check("AD-A-37", measured.parse(raw))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.PARSE_REFUSED


def test_ad_a_37_finds_a_host_that_does_not_enforce_channel_binding() -> None:
    """A channel binding setting of zero accepts a bind without it."""
    raw = measured.audit_json()
    measured.set_setting(raw, "LdapEnforceChannelBinding", "0")

    result = assert_the_fix_is_clean("AD-A-37", measured.parse(raw))

    assert result.status == model.Status.FINDING
    assert len(result.findings) == 1


def test_ad_a_38_is_unknown_when_the_ntlm_settings_were_not_read() -> None:
    """The measured host does not report the NTLM settings."""
    result = run_check("AD-A-38", measured.audit_document())

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.UNAVAILABLE


def ntlm_host(document: dict[str, Any], **values: str) -> None:
    """The NTLM settings of the collector host, every one of them read.

    The allow list of the vulnerable channels is left as the collector
    reported it: the registry holds no value of it, and that is the
    good state.
    """
    measured.set_setting(document, "LmCompatibilityLevel", values.get("level", "5"))
    measured.set_setting(document, "NoLMHash", values.get("lm_hash", "1"))
    measured.set_setting(document, "RestrictAnonymous", values.get("anonymous", "0"))
    measured.set_setting(
        document, "RestrictSendingNTLMTraffic", values.get("sending", "2")
    )
    measured.set_setting(
        document, "RestrictReceivingNTLMTraffic", values.get("receiving", "2")
    )
    measured.set_setting(document, "RestrictNTLMInDomain", values.get("domain", "2"))
    measured.set_setting(
        document, "FullSecureChannelProtection", values.get("secure_channel", "1")
    )


def test_ad_a_38_passes_when_the_ntlm_restrictions_are_on() -> None:
    """Every NTLM restriction of the host is on."""
    raw = measured.audit_json()
    ntlm_host(raw)

    result = run_check("AD-A-38", measured.parse(raw))

    assert result.status == model.Status.PASS
    assert "configured; observed not collected" in result.note


def test_ad_a_38_is_unknown_when_a_template_file_was_refused() -> None:
    """A template the collector refused is not a proof of anything."""
    raw = measured.audit_json()
    ntlm_host(raw)
    raw["files"]["gpttmpl"]["skipped_special"] = 1

    result = run_check("AD-A-38", measured.parse(raw))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.PARSE_REFUSED


def test_ad_a_38_finds_a_host_that_still_stores_the_lm_hash() -> None:
    """A host that stores the LM hash is not protected."""
    raw = measured.audit_json()
    ntlm_host(raw, lm_hash="0")

    result = assert_the_fix_is_clean("AD-A-38", measured.parse(raw))

    assert result.status == model.Status.FINDING
    assert len(result.findings) == 1
    assert "NoLMHash" in (result.findings[0].objects[0].evidence or "")


def test_ad_a_38_reports_every_weak_value() -> None:
    """Each value that is read on its own is judged on its own."""
    raw = measured.audit_json()
    ntlm_host(raw, lm_hash="0", sending="0")

    result = assert_the_fix_is_clean("AD-A-38", measured.parse(raw))

    assert result.status == model.Status.FINDING
    assert len(result.findings) == 2
    evidence = " ".join(
        (finding.objects[0].evidence or "") for finding in result.findings
    )
    assert "NoLMHash" in evidence
    assert "RestrictSendingNTLMTraffic" in evidence


def test_ad_a_38_treats_an_absent_allow_list_as_the_good_state() -> None:
    """The registry holds no allow list of the vulnerable channels."""
    raw = measured.audit_json()
    ntlm_host(raw)
    measured.set_setting(raw, "VulnerableChannelAllowList", "", "unavailable")

    result = run_check("AD-A-38", measured.parse(raw))

    assert result.status == model.Status.PASS


def test_ad_a_38_finds_an_allow_list_of_the_vulnerable_channels() -> None:
    """An allow list of the vulnerable channels is a weakness."""
    raw = measured.audit_json()
    ntlm_host(raw)
    measured.set_setting(raw, "VulnerableChannelAllowList", "present")

    result = assert_the_fix_is_clean("AD-A-38", measured.parse(raw))

    assert result.status == model.Status.FINDING
    assert len(result.findings) == 1
    assert "VulnerableChannelAllowList" in (
        result.findings[0].objects[0].evidence or ""
    )


def test_ad_a_38_is_unknown_for_a_setting_that_was_not_read() -> None:
    """A setting the collector could not read leaves that setting unknown."""
    raw = measured.audit_json()
    ntlm_host(raw)
    registry_item(raw, "LmCompatibilityLevel")["status"] = "denied"

    result = run_check("AD-A-38", measured.parse(raw))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ACCESS_DENIED
    assert "LmCompatibilityLevel" in result.note


# ---- AD-A-43: the dSHeuristics ----------------------------------------------


def test_ad_a_43_evaluates_the_defaults_when_the_heuristics_are_absent() -> None:
    """The measured directory service carries no dSHeuristics.

    The defaults are the heuristics that are not set, and they are
    evaluated: the check never answers UNKNOWN for a missing
    attribute, and the defaults block the anonymous operations.
    """
    result = run_check("AD-A-43", measured.audit_document())

    assert result.status == model.Status.PASS
    assert result.findings == ()
    assert "defaults apply" in result.note


def test_ad_a_43_passes_when_the_heuristics_are_on() -> None:
    """A directory service that blocks the anonymous operations passes."""
    raw = measured.audit_json()
    raw["queries"]["dir_service"]["rows"][0]["a"]["dSHeuristics"] = ["0010001001"]

    result = run_check("AD-A-43", measured.parse(raw))

    assert result.status == model.Status.PASS
    assert "anonymous operations blocked" in result.note


def test_ad_a_43_finds_a_heuristic_of_two_at_position_seven() -> None:
    """The seventh character is the position the specification counts.

    A 2 at position 7 allows the anonymous operations; a 2 at another
    position is not the heuristic of the anonymous operations.
    """
    raw = measured.audit_json()
    raw["queries"]["dir_service"]["rows"][0]["a"]["dSHeuristics"] = ["0000002"]

    result = assert_the_fix_is_clean("AD-A-43", measured.parse(raw))

    assert result.status == model.Status.FINDING
    assert len(result.findings) == 1
    assert "allows" in result.findings[0].title


def test_ad_a_43_passes_when_position_seven_is_zero() -> None:
    """A 0 at position 7 is the default: the anonymous operations stay blocked."""
    raw = measured.audit_json()
    raw["queries"]["dir_service"]["rows"][0]["a"]["dSHeuristics"] = ["0010000"]

    result = run_check("AD-A-43", measured.parse(raw))

    assert result.status == model.Status.PASS
    assert result.findings == ()


def test_ad_a_43_does_not_find_a_two_at_another_position() -> None:
    """Only the position 7 carries the heuristic of the anonymous operations."""
    raw = measured.audit_json()
    raw["queries"]["dir_service"]["rows"][0]["a"]["dSHeuristics"] = ["0020000"]

    result = run_check("AD-A-43", measured.parse(raw))

    assert result.status == model.Status.PASS
    assert result.findings == ()


def test_ad_a_43_does_not_find_the_list_object_that_is_off() -> None:
    """The list-object heuristic is off by default: it is a note, not a finding.

    A directory service that hides nothing from a list is the default
    of Windows, and the check says so in its note.
    """
    raw = measured.audit_json()
    raw["queries"]["dir_service"]["rows"][0]["a"]["dSHeuristics"] = ["0000000"]

    result = run_check("AD-A-43", measured.parse(raw))

    assert result.status == model.Status.PASS
    assert result.findings == ()
    assert "list object not hidden" in result.note


def test_ad_a_43_finds_a_directory_service_that_allows_anonymous() -> None:
    """A heuristic of 2 allows the anonymous operations."""
    raw = measured.audit_json()
    raw["queries"]["dir_service"]["rows"][0]["a"]["dSHeuristics"] = ["0010002001"]

    result = assert_the_fix_is_clean("AD-A-43", measured.parse(raw))

    assert result.status == model.Status.FINDING
    assert len(result.findings) == 1
    assert "allows" in result.findings[0].title


def test_ad_a_43_finds_a_mask_of_the_admin_sd_that_is_not_one() -> None:
    """The masks of the AdminSDHolder protection must be 1."""
    raw = measured.audit_json()
    raw["queries"]["dir_service"]["rows"][0]["a"]["dSHeuristics"] = ["0010001002"]

    result = assert_the_fix_is_clean("AD-A-43", measured.parse(raw))

    assert result.status == model.Status.FINDING
    assert len(result.findings) == 1
    assert "AdminSDHolder" in result.findings[0].title


def test_ad_a_43_notes_the_positions_it_does_not_read() -> None:
    """A position Newton does not read is noted, not judged."""
    raw = measured.audit_json()
    raw["queries"]["dir_service"]["rows"][0]["a"]["dSHeuristics"] = ["0010001011"]

    result = run_check("AD-A-43", measured.parse(raw))

    assert result.status == model.Status.PASS
    assert "9 is 1" in result.note


# ---- AD-A-44: the machine account quota -------------------------------------


def test_ad_a_44_finds_the_machine_account_quota_of_the_measured_domain() -> None:
    """The measured domain lets an ordinary account join ten computers."""
    result = assert_the_fix_is_clean("AD-A-44", measured.audit_document())

    assert result.status == model.Status.FINDING
    assert len(result.findings) == 1
    assert result.findings[0].objects[0].evidence is not None
    assert "10" in result.findings[0].objects[0].evidence


def test_ad_a_44_passes_when_the_quota_is_zero() -> None:
    """A quota of zero stops the join."""
    raw = measured.audit_json()
    raw["queries"]["domain_head"]["rows"][0]["a"]["ms-DS-MachineAccountQuota"] = ["0"]

    result = run_check("AD-A-44", measured.parse(raw))

    assert result.status == model.Status.PASS
    assert result.findings == ()


def test_ad_a_44_is_unknown_without_the_quota() -> None:
    """A domain head without the quota proves nothing."""
    raw = measured.audit_json()
    measured.drop_attribute(
        raw["queries"]["domain_head"]["rows"][0], "ms-DS-MachineAccountQuota"
    )

    result = run_check("AD-A-44", measured.parse(raw))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ACCESS_DENIED


# ---- AD-A-45: the functional levels -----------------------------------------


def test_ad_a_45_reads_the_functional_level_of_the_measured_domain() -> None:
    """The measured domain runs at the level of its schema."""
    result = run_check("AD-A-45", measured.audit_document())

    assert "Windows Server 2025" in result.note
    assert "Recycle Bin is not enabled" in result.note


def test_ad_a_45_finds_that_the_recycle_bin_is_not_enabled() -> None:
    """A forest without the Recycle Bin loses a deleted object for good."""
    result = assert_the_fix_is_clean("AD-A-45", measured.audit_document())

    assert result.status == model.Status.FINDING
    assert len(result.findings) == 1
    assert "Recycle Bin" in result.findings[0].title


def test_ad_a_45_finds_a_domain_below_the_level_of_2016() -> None:
    """A domain below the level of Windows Server 2016 is a finding."""
    raw = measured.audit_json()
    raw["queries"]["domain_head"]["rows"][0]["a"]["msDS-Behavior-Version"] = ["6"]

    result = assert_the_fix_is_clean("AD-A-45", measured.parse(raw))

    assert result.status == model.Status.FINDING
    assert len(result.findings) == 2


def test_ad_a_45_finds_a_forest_below_the_level_of_2016() -> None:
    """A configuration set below the level of Windows Server 2016 is a finding."""
    raw = measured.audit_json()
    raw["queries"]["partitions"]["rows"][0]["a"]["msDS-Behavior-Version"] = ["5"]

    result = assert_the_fix_is_clean("AD-A-45", measured.parse(raw))

    assert result.status == model.Status.FINDING
    assert len(result.findings) == 2


def test_ad_a_45_passes_with_the_recycle_bin_enabled() -> None:
    """The Recycle Bin is read from the optional features."""
    raw = measured.audit_json()
    for row in raw["queries"]["optional_features"]["rows"]:
        if "Recycle Bin" in row["dn"]:
            row["a"]["msDS-EnabledFeatureBL"] = ["OU=NewtonSeeds,DC=win,DC=newton,DC=test"]

    result = run_check("AD-A-45", measured.parse(raw))

    assert result.status == model.Status.PASS
    assert "Recycle Bin is enabled in 1 places" in result.note


def test_ad_a_45_is_unknown_when_the_schema_is_not_read() -> None:
    """The functional level of the schema is unknown without it."""
    raw = measured.audit_json()
    measured.set_query_status(raw, "schema_head", "denied", "access_denied")

    result = run_check("AD-A-45", measured.parse(raw))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ACCESS_DENIED


def test_ad_a_45_is_unknown_when_the_level_of_the_domain_is_not_read() -> None:
    """A domain head without a functional level proves nothing."""
    raw = measured.audit_json()
    measured.drop_attribute(
        raw["queries"]["domain_head"]["rows"][0], "msDS-Behavior-Version"
    )

    result = run_check("AD-A-45", measured.parse(raw))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.NOT_COLLECTED


# ---- AD-A-46: the LAPS deployment --------------------------------------------


def test_ad_a_46_finds_that_laps_is_not_deployed() -> None:
    """The measured schema carries no LAPS attribute."""
    result = assert_the_fix_is_clean("AD-A-46", measured.audit_document())

    assert result.status == model.Status.FINDING
    assert len(result.findings) == 2


def test_ad_a_46_passes_when_laps_is_deployed() -> None:
    """A schema with the LAPS attributes and an expiry time passes."""
    raw = measured.audit_json()
    raw["queries"]["schema_laps"]["rows"] = [
        {
            "dn": "CN=ms-Mcs-AdmPwd,CN=Schema,CN=Configuration,"
            "DC=win,DC=newton,DC=test",
            "a": {"lDAPDisplayName": ["ms-Mcs-AdmPwd"]},
        }
    ]
    raw["queries"]["computers"]["rows"][0]["a"]["ms-Mcs-AdmPwdExpirationTime"] = [
        "20261108T120000.0Z"
    ]

    result = run_check("AD-A-46", measured.parse(raw))

    assert result.status == model.Status.PASS
    assert result.findings == ()


def test_ad_a_46_is_unknown_when_the_schema_was_not_read() -> None:
    """The LAPS attributes are unknown when the schema was not read."""
    raw = measured.audit_json()
    measured.set_query_status(raw, "schema_laps", "denied", "access_denied")

    result = run_check("AD-A-46", measured.parse(raw))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ACCESS_DENIED


# ---- AD-A-48: the trusts -----------------------------------------------------


def test_ad_a_48_passes_when_the_measured_domain_has_no_trust() -> None:
    """The measured domain has no trust."""
    result = run_check("AD-A-48", measured.audit_document())

    assert result.status == model.Status.PASS
    assert "no trust" in result.note


def trust_row(attributes: str | None) -> dict[str, Any]:
    """A trusted domain object of the measured domain."""
    row: dict[str, Any] = {
        "dn": "CN=partner.test,CN=System,DC=win,DC=newton,DC=test",
        "a": {
            "trustPartner": ["partner.test"],
            "trustDirection": ["3"],
            "trustType": ["2"],
            "securityIdentifier": [measured.sid_blob(measured.AUDIT_SID)],
        },
    }
    if attributes is not None:
        row["a"]["trustAttributes"] = [attributes]
    return row


def test_ad_a_48_finds_a_trust_that_does_not_filter_the_sids() -> None:
    """A trust without the quarantined attribute does not filter the SIDs."""
    raw = measured.audit_json()
    raw["queries"]["trusts"]["rows"] = [trust_row("8")]

    result = assert_the_fix_is_clean("AD-A-48", measured.parse(raw))

    assert result.status == model.Status.FINDING
    assert len(result.findings) == 1
    assert "SIDs" in result.findings[0].title


def test_ad_a_48_passes_when_the_trust_filters_the_sids() -> None:
    """A trust that quarantines the other domain filters its SIDs."""
    raw = measured.audit_json()
    raw["queries"]["trusts"]["rows"] = [trust_row("12")]

    result = run_check("AD-A-48", measured.parse(raw))

    assert result.status == model.Status.PASS
    assert result.findings == ()


def test_ad_a_48_finds_a_forest_trust_that_treats_the_domain_as_external() -> None:
    """A forest trust that treats the other domain as external is a finding."""
    raw = measured.audit_json()
    raw["queries"]["trusts"]["rows"] = [trust_row("76")]

    result = assert_the_fix_is_clean("AD-A-48", measured.parse(raw))

    assert result.status == model.Status.FINDING
    assert len(result.findings) == 1
    assert "external" in result.findings[0].title


def test_ad_a_48_is_unknown_when_a_trust_carries_no_attributes() -> None:
    """A trust without its attributes proves nothing about its protections."""
    raw = measured.audit_json()
    raw["queries"]["trusts"]["rows"] = [trust_row(None)]

    result = run_check("AD-A-48", measured.parse(raw))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.NOT_COLLECTED


def test_ad_a_48_is_unknown_when_the_trusts_were_not_read() -> None:
    """The trusts are unknown when the query did not complete."""
    raw = measured.audit_json()
    measured.set_query_status(raw, "trusts", "denied", "access_denied")

    result = run_check("AD-A-48", measured.parse(raw))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ACCESS_DENIED


# ---- AD-A-55: the SYSVOL content --------------------------------------------


def test_ad_a_55_finds_the_seeded_cpassword_of_the_measured_domain() -> None:
    """The SYSVOL of the measured domain holds the seeded cpassword."""
    result = assert_the_fix_is_clean("AD-A-55", measured.audit_document())

    assert result.status == model.Status.FINDING
    assert len(result.findings) == 1
    affected = result.findings[0].objects[0]
    assert affected.guid == "4a06e176-48dd-4b65-b2b0-214b24eb0f59"
    assert "cpassword" in result.findings[0].title
    assert affected.evidence is not None and "cpassword" in affected.evidence


def test_ad_a_55_passes_when_sysvol_holds_no_credential() -> None:
    """A SYSVOL without a credential passes."""
    raw = measured.audit_json()
    raw["files"]["gpp"]["items"] = []

    result = run_check("AD-A-55", measured.parse(raw))

    assert result.status == model.Status.PASS
    assert result.findings == ()


def test_ad_a_55_is_unknown_when_the_files_were_not_read() -> None:
    """The SYSVOL is unknown when the scan did not complete."""
    raw = measured.audit_json()
    measured.set_file_status(raw, "gpp", "truncated", "size_limit")

    result = run_check("AD-A-55", measured.parse(raw))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.TRUNCATED


def test_ad_a_55_is_unknown_when_a_file_of_the_sysvol_was_refused() -> None:
    """A file the collector refused may hold a credential.

    The scan of the SYSVOL is not complete, so the check cannot say
    that the SYSVOL holds no credential: it is UNKNOWN, and the reason
    says that a file was refused.
    """
    raw = measured.audit_json()
    raw["files"]["gpp"]["items"] = []
    raw["files"]["gpp"]["parse_refused"] = 1

    result = run_check("AD-A-55", measured.parse(raw))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.PARSE_REFUSED
    assert "refused 1" in result.note
    assert "skipped 0" in result.note


def test_ad_a_55_is_unknown_when_a_special_file_was_skipped() -> None:
    """A file the collector skipped may hold a credential."""
    raw = measured.audit_json()
    raw["files"]["gpp"]["items"] = []
    raw["files"]["gpp"]["skipped_special"] = 1

    result = run_check("AD-A-55", measured.parse(raw))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.PARSE_REFUSED
    assert "refused 0" in result.note
    assert "skipped 1" in result.note


def test_ad_a_55_finds_the_credential_of_a_section_that_refused_a_file() -> None:
    """A credential that was found is a finding, whatever the counts are."""
    raw = measured.audit_json()
    raw["files"]["gpp"]["parse_refused"] = 1
    raw["files"]["gpp"]["skipped_special"] = 1

    result = assert_the_fix_is_clean("AD-A-55", measured.parse(raw))

    assert result.status == model.Status.FINDING
    assert len(result.findings) == 1


# ---- AD-A-60: the FSMO roles --------------------------------------------------


def test_ad_a_60_reads_the_role_holder_of_the_measured_domain() -> None:
    """The role of the measured domain is held by its domain controller."""
    result = run_check("AD-A-60", measured.audit_document())

    assert result.status == model.Status.PASS
    assert "WINDC1" in result.note


def test_ad_a_60_finds_a_holder_that_is_not_a_domain_controller() -> None:
    """A role held by an object that is not a controller is a finding."""
    raw = measured.audit_json()
    raw["queries"]["domain_head"]["rows"][0]["a"]["fSMORoleOwner"] = [
        "CN=NTDS Settings,CN=GHOST,CN=Servers,CN=Default-First-Site-Name,"
        "CN=Sites,CN=Configuration,DC=win,DC=newton,DC=test"
    ]

    result = assert_the_fix_is_clean("AD-A-60", measured.parse(raw))

    assert result.status == model.Status.FINDING
    assert len(result.findings) == 1


def test_ad_a_60_is_unknown_when_the_domain_head_was_not_read() -> None:
    """The role holders are unknown without the domain head."""
    raw = measured.audit_json()
    measured.set_query_status(raw, "domain_head", "denied", "access_denied")

    result = run_check("AD-A-60", measured.parse(raw))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ACCESS_DENIED


# ---- AD-A-67: the operating system of the domain controllers ------------------


def test_ad_a_67_reads_the_operating_system_of_the_measured_domain() -> None:
    """The domain controller of the measured domain runs Windows Server."""
    result = run_check("AD-A-67", measured.audit_document())

    assert result.status == model.Status.PASS
    assert "Windows Server 2025" in result.note
    assert "10.0 (26100)" in result.note


def test_ad_a_67_passes_with_the_edited_build() -> None:
    """The build of the domain controller is read as it is."""
    raw = measured.audit_json()
    for row in raw["queries"]["computers"]["rows"]:
        if row["a"].get("primaryGroupID") == ["516"]:
            row["a"]["operatingSystemVersion"] = ["10.0 (9999)"]

    result = run_check("AD-A-67", measured.parse(raw))

    assert result.status == model.Status.PASS
    assert "10.0 (9999)" in result.note


def test_ad_a_67_is_unknown_when_the_computers_were_not_read() -> None:
    """The domain controllers are unknown without the computers."""
    raw = measured.audit_json()
    measured.set_query_status(raw, "computers", "error", "other")

    result = run_check("AD-A-67", measured.parse(raw))

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ERROR


# ---- the fixes ---------------------------------------------------------------


def test_the_fix_of_the_heuristics_explains_the_change() -> None:
    """No documented cmdlet writes the dSHeuristics of the directory service."""
    raw = measured.audit_json()
    raw["queries"]["dir_service"]["rows"][0]["a"]["dSHeuristics"] = ["0000002001"]

    report = runner.run(measured.parse(raw), "ad-windows", checks=[check_of("AD-A-43")])
    payload = render.render(report)
    fix = payload["results"][0]["findings"][0]["fix"]

    assert fix["windows"]["commands"] == ()
    assert fix["samba"]["commands"] == ()
    assert "position 7" in fix["windows"]["summary"]


def test_the_fix_of_a_trust_explains_the_change() -> None:
    """No documented cmdlet writes the trust attributes of a trust."""
    raw = measured.audit_json()
    raw["queries"]["trusts"]["rows"] = [trust_row("8")]

    report = runner.run(measured.parse(raw), "ad-windows", checks=[check_of("AD-A-48")])
    payload = render.render(report)
    fix = payload["results"][0]["findings"][0]["fix"]

    assert fix["windows"]["commands"] == ()
    assert fix["samba"]["commands"] == ()
    assert "trustAttributes" in fix["windows"]["summary"]


def test_the_fix_of_a_sysvol_credential_does_not_delete_the_gpo() -> None:
    """The fix of a credential in the SYSVOL does not delete the GPO."""
    result = assert_the_fix_is_clean("AD-A-55", measured.audit_document())
    report = runner.run(
        measured.audit_document(), "ad-windows", checks=[check_of("AD-A-55")]
    )
    payload = render.render(report)
    fix = payload["results"][0]["findings"][0]["fix"]

    assert fix["windows"]["commands"] == ()
    assert fix["samba"]["commands"] == ()
    assert result.status == model.Status.FINDING


def test_the_fix_of_the_machine_account_quota_names_the_domain_by_its_sid() -> None:
    """The Samba fix of the quota names the domain by its SID."""
    result = assert_the_fix_is_clean("AD-A-44", measured.audit_document())
    report = runner.run(
        measured.audit_document(), "ad-windows", checks=[check_of("AD-A-44")]
    )
    payload = render.render(report)
    fix = payload["results"][0]["findings"][0]["fix"]

    assert fix["windows"]["commands"] == ()
    assert "dsacls" not in fix["windows"]["summary"]
    assert "dn: <SID=" in fix["samba"]["commands"][0]
    assert result.status == model.Status.FINDING


def test_the_fix_of_the_laps_schema_does_not_add_an_attribute() -> None:
    """No documented cmdlet adds the LAPS attributes to the schema."""
    result = assert_the_fix_is_clean("AD-A-46", measured.audit_document())
    report = runner.run(
        measured.audit_document(), "ad-windows", checks=[check_of("AD-A-46")]
    )
    payload = render.render(report)
    fixes = [
        finding["fix"] for finding in payload["results"][0]["findings"]
    ]

    for fix in fixes:
        assert fix["windows"]["commands"] == ()
        assert fix["samba"]["commands"] == ()
    assert result.status == model.Status.FINDING
