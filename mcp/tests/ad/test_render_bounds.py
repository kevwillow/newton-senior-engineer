"""The cost and the size of the rendered audit report.

The proof that no directory string reached a fix command strips every
string of the report once, not once per command, so a domain with many
findings renders in time linear in its size.  The report lists a bounded
number of findings and objects per check and keeps the findings inside a
byte budget, with the full counts and a note, so a real-size domain does
not hand the model megabytes.  The tool runs off the event loop, so a
long audit cannot block a confirm or an abort of another change.
"""

from __future__ import annotations

import asyncio
import json
import threading
from pathlib import Path

import pytest
from mcp.shared.memory import create_connected_server_and_client_session

import newton_mcp.server as server
from newton_mcp.ad import model, render, transport


BASE_SID = "S-1-5-21-1004336348-1177238915-682003330-"
TEMPLATE = "Set-ADAccountControl -Identity '{sid}' -DoesNotRequirePreAuth $false"
FIXTURE = Path(__file__).with_name("fixtures") / "win-dc-audit-r3.json"


def _fix() -> model.Fix:
    return model.Fix(
        windows=model.FixStep(summary="turn the flag off", commands=(TEMPLATE,)),
        samba=model.FixStep(summary="turn the flag off", commands=(TEMPLATE,)),
    )


def _finding(index: int, *, objects: int = 1, evidence: str | None = None) -> model.Finding:
    return model.Finding(
        check_id="AD-TEST-01",
        severity=model.Severity.MEDIUM,
        title="something is wrong",
        objects=tuple(
            model.Affected(
                sid=f"{BASE_SID}{5000 + index * 100 + one}",
                name=f"user{index:05d}x{one}",
                dn=f"CN=user{index:05d}x{one},OU=Staff,DC=win,DC=newton,DC=test",
                evidence=evidence,
            )
            for one in range(objects)
        ),
        maps_to=("AD-A-01",),
        fix=_fix(),
    )


def _result(check_id: str, findings: tuple[model.Finding, ...]) -> model.CheckResult:
    return model.CheckResult(
        check_id=check_id,
        title="something is wrong",
        severity=model.Severity.MEDIUM,
        status=model.Status.FINDING,
        findings=findings,
    )


def _report(*results: model.CheckResult) -> model.AuditReport:
    return model.AuditReport(
        domain="win.newton.test",
        collector="windows",
        counts={"PASS": 0, "FINDING": len(results), "UNKNOWN": 0},
        results=results,
        generated="2026-11-08T12:00:00Z",
        scope_note=model.SCOPE_NOTE,
    )


# ---- the proof is linear --------------------------------------


def test_the_proof_strips_every_string_once(monkeypatch: pytest.MonkeyPatch) -> None:
    """Each directory string and each command is stripped of its quoting
    once: the proof costs strings plus commands, not their product."""
    calls = 0
    original = render._without_quoting

    def counting(text: str) -> str:
        nonlocal calls
        calls += 1
        return original(text)

    monkeypatch.setattr(render, "_without_quoting", counting)
    findings = tuple(_finding(index) for index in range(8))
    report = _report(_result("AD-TEST-01", findings))
    strings = len(render._directory_strings(report))
    commands = 2 * len(findings)

    render.render(report)

    assert strings == 16
    assert calls <= strings + commands


def test_the_linear_proof_still_refuses_a_directory_string_in_a_command() -> None:
    """The faster proof refuses what the old one refused: a name inside a
    command, behind quoting, of any length among others of other lengths."""
    proof = render.DirectoryText(["x" * 300, "", "'", "svc", "OU=People"])

    with pytest.raises(render.RenderError):
        proof.check("Disable-ADAccount -Identity 'svc'")
    with pytest.raises(render.RenderError):
        proof.check("Get-ADUser -SearchBase \"OU=Peo'ple\"")
    proof.check("Disable-ADAccount -Identity 'S-1-5-21-1-2-3-1105'")


# ---- the report is bounded --------------------------------------


def test_a_check_lists_a_bounded_number_of_findings_with_the_total() -> None:
    total = render.MAX_FINDINGS_PER_CHECK + 15
    report = _report(_result("AD-TEST-01", tuple(_finding(i) for i in range(total))))

    rendered = render.render(report)

    result = rendered["results"][0]
    assert len(result["findings"]) == render.MAX_FINDINGS_PER_CHECK
    assert result["findings_total"] == total
    assert result["findings_truncated"] is True
    assert rendered["truncated"] is True
    assert "checks" in rendered["truncated_note"]


def test_a_finding_lists_a_bounded_number_of_objects_with_the_total() -> None:
    total = render.MAX_OBJECTS_PER_FINDING + 7
    report = _report(_result("AD-TEST-01", (_finding(0, objects=total),)))

    rendered = render.render(report)

    finding = rendered["results"][0]["findings"][0]
    assert len(finding["objects"]) == render.MAX_OBJECTS_PER_FINDING
    assert finding["objects_total"] == total
    assert finding["objects_truncated"] is True
    assert rendered["truncated"] is True


def test_the_findings_of_the_report_stay_inside_the_byte_budget() -> None:
    """Many checks, each at its cap with long evidence: the findings past
    the budget are left out, the counts stay, and the note says so."""
    evidence = "e" * 2000
    results = tuple(
        _result(
            f"AD-TEST-{check:02d}",
            tuple(
                _finding(check * 100 + i, evidence=evidence)
                for i in range(render.MAX_FINDINGS_PER_CHECK)
            ),
        )
        for check in range(40)
    )

    rendered = render.render(_report(*results))

    size = len(json.dumps(rendered["results"]))
    assert size <= render.MAX_FINDINGS_BYTES + 40 * 400
    assert rendered["truncated"] is True
    assert len(rendered["results"]) == 40
    dropped = [r for r in rendered["results"] if not r["findings"]]
    assert dropped
    for result in dropped:
        assert result["findings_total"] == render.MAX_FINDINGS_PER_CHECK
        assert result["findings_truncated"] is True


def _big_check(check_id: str, base: int) -> model.CheckResult:
    """A check whose findings together pass the byte budget, each well inside it."""
    evidence = "e" * 7000
    return _result(
        check_id,
        tuple(
            _finding(base + i, objects=3, evidence=evidence)
            for i in range(render.MAX_FINDINGS_PER_CHECK)
        ),
    )


def test_a_check_too_large_on_its_own_lists_the_findings_that_fit() -> None:
    """Asked for alone, a check whose findings pass the budget together
    still lists the ones that fit, not none, and says it is truncated."""
    rendered = render.render(_report(_big_check("AD-TEST-01", 0)))

    result = rendered["results"][0]
    assert result["findings"], "a check asked for alone listed none of its findings"
    assert len(result["findings"]) < render.MAX_FINDINGS_PER_CHECK
    assert result["findings_truncated"] is True
    assert result["findings_total"] == render.MAX_FINDINGS_PER_CHECK
    assert len(json.dumps(result["findings"])) <= render.MAX_FINDINGS_BYTES
    assert rendered["truncated"] is True


def test_a_check_after_a_cut_check_still_lists_its_findings() -> None:
    """The budget is spent in order, and a smaller check after one that was
    cut still lists the findings that fit."""
    rendered = render.render(
        _report(_big_check("AD-TEST-01", 0), _result("AD-TEST-02", (_finding(900),)))
    )

    first, second = rendered["results"]
    assert first["findings_truncated"] is True
    assert len(second["findings"]) == 1
    assert second["findings_truncated"] is False


def test_the_note_says_a_finding_too_large_on_its_own_is_not_listed() -> None:
    """One finding that alone passes the budget cannot be listed, whatever
    `checks` holds: the note and the tool description say so."""
    base = _finding(0)
    huge = model.Finding(
        check_id=base.check_id,
        severity=base.severity,
        title=base.title,
        objects=tuple(
            model.Affected(
                sid=f"{BASE_SID}{7000 + one}",
                name="n" * 10_000,
                dn="CN=" + "d" * 10_000,
                evidence="e" * 10_000,
            )
            for one in range(render.MAX_OBJECTS_PER_FINDING)
        ),
        maps_to=base.maps_to,
        fix=base.fix,
    )
    rendered = render.render(_report(_result("AD-TEST-01", (huge,))))

    assert rendered["results"][0]["findings"] == []
    assert rendered["truncated"] is True
    note = rendered["truncated_note"]
    assert "a finding that alone passes the budget is never listed" in note
    tool = server.mcp._tool_manager.get_tool("newton_ad_audit")
    assert tool is not None
    assert "a finding that alone passes the budget is never listed" in (tool.description or "")


def test_a_small_report_is_not_marked_truncated() -> None:
    rendered = render.render(_report(_result("AD-TEST-01", (_finding(0),))))

    result = rendered["results"][0]
    assert result["findings_total"] == 1
    assert result["findings_truncated"] is False
    assert result["findings"][0]["objects_total"] == 1
    assert result["findings"][0]["objects_truncated"] is False
    assert rendered["truncated"] is False
    assert rendered["truncated_note"] is None


def test_the_audit_description_states_the_caps() -> None:
    tool = server.mcp._tool_manager.get_tool("newton_ad_audit")
    assert tool is not None
    description = tool.description or ""
    assert f"at most {render.MAX_FINDINGS_PER_CHECK} findings" in description
    assert f"at most {render.MAX_OBJECTS_PER_FINDING} objects" in description
    assert f"{render.MAX_FINDINGS_BYTES} bytes" in description
    assert "findings_total" in description


# ---- the tool runs off the event loop ---------------------------


@pytest.fixture
def ad_device(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
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
    }
    monkeypatch.setattr(server, "load_inventory", lambda: devices)


def test_the_audit_tool_leaves_the_event_loop_free(
    ad_device: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """While the audit runs, the server's event loop still runs other
    work: the fetch waits for a coroutine on the loop, which can only run
    when the audit is off the loop."""
    raw = FIXTURE.read_bytes()
    loop_ran = threading.Event()

    def fetch(device: object) -> bytes:
        if not loop_ran.wait(5):
            raise transport.AdTransportError("the event loop was blocked")
        return raw

    monkeypatch.setattr(transport, "fetch", fetch)

    async def run() -> dict:
        async with create_connected_server_and_client_session(
            server.mcp._mcp_server
        ) as client:
            async def release() -> None:
                await asyncio.sleep(0.05)
                loop_ran.set()

            call = asyncio.create_task(
                client.call_tool("newton_ad_audit", {"device": "dc1"})
            )
            await release()
            result = await call
            return json.loads(result.content[0].text)  # type: ignore[union-attr]

    result = asyncio.run(run())

    assert result.get("result") == "ok", result
