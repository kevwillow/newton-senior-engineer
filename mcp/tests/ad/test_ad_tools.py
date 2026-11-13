"""The two MCP tools of the Active Directory audit.

The audit is one chain: the collector document is fetched, validated,
run over by the catalogue and rendered.  Every failure of the chain
refuses with a fixed message, and the document of the fixture is the
one measured on the lab DC (WINDC1).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import newton_mcp.server as server
from newton_mcp import envelope
from newton_mcp.ad import catalogue, model, queryset, tools, transport

import docs


FIXTURES = Path(__file__).with_name("fixtures")
AUDIT_FIXTURE = FIXTURES / "win-dc-audit-r3.json"
ADMIN_FIXTURE = FIXTURES / "win-dc-admin-r3.json"

# The directory strings of the synthetic finding of the envelope test.
FINDING_NAME = "Sample Audit Account"
FINDING_DN = "CN=SampleAccount,OU=Accounts,DC=example,DC=test"


@pytest.fixture
def inventory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict:
    """One AD device and one router, both synthetic."""
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("key ssh-ed25519 synthetic\n", encoding="utf-8")
    key_file = tmp_path / "newton-key"
    key_file.write_text("synthetic private key placeholder\n", encoding="utf-8")
    devices = {
        "dc1": server.Device(
            name="dc1",
            platform="ad-windows",
            host="192.0.2.10",
            user="newton-audit@win.newton.test",
            known_hosts=known_hosts,
            key_file=key_file,
        ),
        "router1": server.Device(
            name="router1",
            platform="openwrt",
            host="192.0.2.1",
            user="root",
        ),
    }
    monkeypatch.setattr(server, "load_inventory", lambda: devices)
    return devices


def _fetch_bytes(monkeypatch: pytest.MonkeyPatch, raw: bytes) -> None:
    """The transport hands the collector document back."""

    def fake_fetch(device: object) -> bytes:
        return raw

    monkeypatch.setattr(transport, "fetch", fake_fetch)


def test_the_audit_returns_a_rendered_report(
    inventory: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The measured audit document comes back as a rendered report."""
    _fetch_bytes(monkeypatch, AUDIT_FIXTURE.read_bytes())

    result = server.newton_ad_audit(device="dc1")

    assert result["result"] == "ok"
    assert result["collector"] == "windows"
    assert result["domain"]["kind"] == "untrusted-device-data"
    assert result["domain"]["text"].endswith("win.newton.test")
    assert [r["id"] for r in result["results"]] == [c.id for c in catalogue.CHECKS]
    counts = result["counts"]
    assert counts["PASS"] + counts["FINDING"] + counts["UNKNOWN"] == len(catalogue.CHECKS)


def _envelopes(tree: object) -> list[dict]:
    """Every envelope of a result tree."""
    found: list[dict] = []
    if isinstance(tree, dict):
        if envelope.is_envelope(tree):
            return [tree]
        for value in tree.values():
            found.extend(_envelopes(value))
    elif isinstance(tree, list):
        for value in tree:
            found.extend(_envelopes(value))
    return found


def _outside_an_envelope(tree: object, text: str) -> list[str]:
    """Every string of a result tree that holds the text outside an envelope."""
    found: list[str] = []
    if isinstance(tree, dict):
        if envelope.is_envelope(tree):
            return found
        for value in tree.values():
            found.extend(_outside_an_envelope(value, text))
    elif isinstance(tree, list):
        for value in tree:
            found.extend(_outside_an_envelope(value, text))
    elif isinstance(tree, str) and text in tree:
        found.append(tree)
    return found


def test_the_report_names_no_directory_text_outside_an_envelope(
    inventory: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every directory string of the report is inside an envelope.

    The catalogue is one synthetic check whose finding carries a name and
    a distinguished name: both are directory text and both have to sit
    inside an envelope, nowhere else in the report.
    """

    def evaluate(document: object) -> model.CheckResult:
        return model.CheckResult(
            check_id="AD-T-ENVELOPE",
            title="A check with a finding",
            severity=model.Severity.MEDIUM,
            status=model.Status.FINDING,
            findings=(
                model.Finding(
                    check_id="AD-T-ENVELOPE",
                    severity=model.Severity.MEDIUM,
                    title="A finding about one account",
                    objects=(
                        model.Affected(
                            sid="S-1-5-21-1111111111-2222222222-3333333333-1107",
                            name=FINDING_NAME,
                            dn=FINDING_DN,
                        ),
                    ),
                ),
            ),
        )

    check = catalogue.Check(
        id="AD-T-ENVELOPE",
        title="A check with a finding",
        severity=model.Severity.MEDIUM,
        evaluate=evaluate,
        queries=("domain_head",),
        sentinels=("domain_head",),
    )
    monkeypatch.setattr(catalogue, "CHECKS", [check])
    _fetch_bytes(monkeypatch, AUDIT_FIXTURE.read_bytes())

    result = server.newton_ad_audit(device="dc1")

    envelopes = _envelopes(result)
    assert any(FINDING_DN in one["text"] for one in envelopes)
    assert any(FINDING_NAME in one["text"] for one in envelopes)
    assert _outside_an_envelope(result, FINDING_DN) == []
    assert _outside_an_envelope(result, FINDING_NAME) == []
    assert result["scope_note"]
    assert result["generated"].endswith("Z")


def test_a_privileged_key_is_refused(
    inventory: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The administrator document is refused by the identity guard."""
    _fetch_bytes(monkeypatch, ADMIN_FIXTURE.read_bytes())

    result = server.newton_ad_audit(device="dc1")

    assert result == {
        "error": "this key is a privileged account; Newton refuses to audit with it"
    }


def test_a_document_of_another_collector_is_refused(
    inventory: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A samba document on a windows device is refused."""
    document = docs.minimal_document(collector="samba")
    _fetch_bytes(monkeypatch, json.dumps(document).encode("utf-8"))

    result = server.newton_ad_audit(device="dc1")

    assert result == {
        "error": "the document is not the collector of the platform of the inventory"
    }


def test_a_document_that_breaks_the_contract_is_refused(
    inventory: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A document that is not JSON is refused by the wire."""
    _fetch_bytes(monkeypatch, b"not json at all")

    result = server.newton_ad_audit(device="dc1")

    assert result == {"error": "collector document invalid: the document is not JSON"}


def test_a_transport_failure_is_refused(
    inventory: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A session that did not answer is a refusal, not a crash."""

    def fake_fetch(device: object) -> bytes:
        raise transport.AdTransportError(transport.MESSAGES["unreachable"])

    monkeypatch.setattr(transport, "fetch", fake_fetch)

    result = server.newton_ad_audit(device="dc1")

    assert result == {"error": transport.MESSAGES["unreachable"]}


def test_an_unknown_check_id_is_refused_with_the_count_only(
    inventory: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The message says how many ids were not known and names none."""
    _fetch_bytes(monkeypatch, AUDIT_FIXTURE.read_bytes())

    result = server.newton_ad_audit(device="dc1", checks=["nope", "also-nope"])

    assert result == {"error": "2 of 2 check ids are not known"}
    assert "nope" not in result["error"]


def test_the_selected_checks_are_the_ones_of_the_catalogue(
    inventory: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A check id of the catalogue runs that check."""
    _fetch_bytes(monkeypatch, AUDIT_FIXTURE.read_bytes())
    ran: list[str] = []

    def evaluate(document: object) -> model.CheckResult:
        ran.append("ran")
        return model.CheckResult(
            check_id="AD-T-TEST",
            title="A test check",
            severity=model.Severity.LOW,
            status=model.Status.PASS,
        )

    check = catalogue.Check(
        id="AD-T-TEST",
        title="A test check",
        severity=model.Severity.LOW,
        evaluate=evaluate,
        queries=("domain_head",),
        sentinels=("domain_head",),
    )
    monkeypatch.setattr(catalogue, "CHECKS", [check])

    result = server.newton_ad_audit(device="dc1", checks=["AD-T-TEST"])

    assert result["result"] == "ok"
    assert ran == ["ran"]
    assert [one["id"] for one in result["results"]] == ["AD-T-TEST"]


def test_a_router_tool_is_refused_on_an_ad_device(
    inventory: dict,
) -> None:
    """The capability gate stops a router tool on an AD device."""
    result = server.newton_read(device="dc1", command="uci show")

    assert result == {
        "error": "newton_read is not available for platform ad-windows"
    }


def test_the_audit_tool_is_refused_on_a_router(
    inventory: dict,
) -> None:
    """The AD tool does not run on an OpenWrt device."""
    result = server.newton_ad_audit(device="router1")

    assert result == {
        "error": "newton_ad_audit is not available for platform openwrt"
    }


def test_the_check_list_holds_the_catalogue_and_the_deferred_list(
    inventory: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The list names every check and the deferred ids of the spec."""

    def evaluate(document: object) -> model.CheckResult:
        raise AssertionError("the list must not run a check")

    windows_only = catalogue.Check(
        id="AD-T-WINDOWS",
        title="A windows only check",
        severity=model.Severity.HIGH,
        evaluate=evaluate,
        platforms=("ad-windows",),
    )
    both = catalogue.Check(
        id="AD-T-BOTH",
        title="A check of both platforms",
        severity=model.Severity.MEDIUM,
        evaluate=evaluate,
    )
    monkeypatch.setattr(catalogue, "CHECKS", [windows_only, both])

    result = server.newton_ad_list_checks()

    assert result["result"] == "ok"
    assert result["checks"] == [
        {
            "id": "AD-T-WINDOWS",
            "title": "A windows only check",
            "severity": "high",
            "platforms": ["ad-windows"],
        },
        {
            "id": "AD-T-BOTH",
            "title": "A check of both platforms",
            "severity": "medium",
            "platforms": ["ad-windows", "ad-samba"],
        },
    ]
    assert "39-42" in result["deferred"]
    assert "AD CS" in result["deferred"]


def test_the_check_list_is_answered_whatever_the_catalogue_holds(
    inventory: dict,
) -> None:
    """The list answers with the deferred list and the catalogue."""
    result = server.newton_ad_list_checks()

    assert result["result"] == "ok"
    assert result["deferred"]
    assert isinstance(result["checks"], list)


def test_the_deferred_list_is_the_one_of_the_spec() -> None:
    """The deferred list is the list the spec writes in section 8."""
    assert tools.DEFERRED == (
        "15",
        "28",
        "29",
        "39-42",
        "47",
        "49",
        "50",
        "54 (file half)",
        "56",
        "58",
        "59",
        "61-66",
        "67 (host half)",
        "68-80",
        "82",
        "83",
        "AD CS",
    )


def test_the_audit_uses_the_query_set_of_the_package() -> None:
    """The document is validated against the shipped query set."""
    assert queryset.load().sha256 == AUDIT_FIXTURE_HASH


AUDIT_FIXTURE_HASH = "f6a57d9647e829b61abdb74aa45a6256653d7b67674ebd3966bd931ddf069116"
