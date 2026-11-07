"""newton-approve shows Newton's facts first, then the agent's explanation
under its own heading, with a mechanical disagreement flag.  Design: the
explanation rules, rule 3.
"""

from __future__ import annotations

import io
import json
from datetime import datetime, timezone

import pytest

import newton_mcp.approve as approve
from exhelp import make_explanation
from newton_mcp.plan import compute_plan_hash

SID = "0123456789abcdef0123456789abcdef"
DIGEST = "d" * 64
HEADING = "Agent's explanation (unchecked claims)"
BATCH = "set firewall.fwd_8443=redirect\nset firewall.fwd_8443.dest_port='8443'"


class TTY(io.StringIO):
    def isatty(self):
        return True


def record(explanation=None, **over):
    rec = {
        "device": "quasar",
        "host": "192.0.2.1",
        "session_id": SID,
        "uci_batch": BATCH,
        "diff": "firewall.fwd_8443=redirect\nfirewall.fwd_8443.dest_port='8443'",
        "probes": [],
        "timeout_s": 120,
        "base_hash": "a" * 64,
        "requires_approval": True,
        "router_digest": DIGEST,
        "router_profile": "prod",
        "router_leash": [],
        "router_sections": ["firewall fwd_8443 redirect fwd_8443"],
        "router_requires_approval": True,
        "staged_check": {"fw4": "skipped-untouched", "reason": "", "not_checked": ["firewall"]},
        "reasons": ["profile 'prod': every write requires approval"],
        "created_at": "2026-10-18T12:00:00+00:00",
        "staged_at": datetime.now(timezone.utc).isoformat(),
        "explanation": explanation if explanation is not None else make_explanation(
            BATCH,
            intent="Forward port 8443 to the printer",
            steps=["Create the fwd_8443 redirect", "Set its destination port"],
            expect=[{"kind": "uci_equals", "path": "firewall.fwd_8443.dest_port", "equals": "8443"}],
            risk="Opens one port; the owner would see the printer reachable.",
        ),
        "owner_confirmed_in_chat": True,
    }
    rec.update(over)
    rec["plan_hash"] = compute_plan_hash(rec)
    return rec


def run(tmp_path, monkeypatch, capsys, rec, answer="no"):
    state = tmp_path / "state"
    (state / "plans").mkdir(parents=True, exist_ok=True)
    (state / "plans" / f"{SID}.json").write_text(json.dumps(rec))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(state))
    monkeypatch.setattr(approve.sys, "stdin", TTY(answer + "\n"))
    monkeypatch.setattr(approve, "_getpass", lambda p: pytest.fail("not reached"))
    code = approve.main([SID])
    out = capsys.readouterr()
    return code, out.out, out.err


def test_explanation_is_shown_after_newtons_facts_under_its_heading(tmp_path, monkeypatch, capsys):
    code, out, err = run(tmp_path, monkeypatch, capsys, record())
    assert HEADING in out
    for newton_fact in ("Sections:", "Risk reasons:", "Diff:", "Probes:", "Timeout:", "Leash codes:"):
        assert out.index(newton_fact) < out.index(HEADING), newton_fact
    assert out.index(HEADING) < out.index("Plan hash:")
    assert "Forward port 8443 to the printer" in out
    assert "Create the fwd_8443 redirect" in out
    assert "firewall.fwd_8443.dest_port == 8443" in out or "firewall.fwd_8443.dest_port" in out
    assert "Opens one port" in out


def test_steps_are_numbered_and_claims_are_listed(tmp_path, monkeypatch, capsys):
    _, out, _ = run(tmp_path, monkeypatch, capsys, record())
    assert "1. | Create the fwd_8443 redirect" in out and "2. | Set its destination port" in out
    assert "Expected after apply" in out


def test_no_disagreement_flag_when_explanation_matches_newtons_facts(tmp_path, monkeypatch, capsys):
    _, out, _ = run(tmp_path, monkeypatch, capsys, record())
    assert "Disagreement" not in out
    assert "no disagreement" in out.lower()


def test_flag_when_a_step_names_an_untouched_section(tmp_path, monkeypatch, capsys):
    ex = make_explanation(BATCH, steps=["Create firewall.fwd_8443", "Also open firewall.allow_ssh"])
    _, out, _ = run(tmp_path, monkeypatch, capsys, record(ex))
    assert "DISAGREEMENT" in out
    assert "firewall.allow_ssh" in out.split("DISAGREEMENT")[1]


def test_flag_when_a_touched_section_is_named_by_no_step(tmp_path, monkeypatch, capsys):
    ex = make_explanation(BATCH, steps=["Open the printer port", "Set the port number"])
    _, out, _ = run(tmp_path, monkeypatch, capsys, record(ex))
    assert "DISAGREEMENT" in out
    assert "no step mentions" in out


def test_flag_is_advisory_it_does_not_block_the_prompt(tmp_path, monkeypatch, capsys):
    ex = make_explanation(BATCH, steps=["Open the printer port", "Set the port number"])
    _, out, _ = run(tmp_path, monkeypatch, capsys, record(ex))
    assert "Type 'approve " in out


def test_secrets_in_a_stored_explanation_are_masked_on_screen_too(tmp_path, monkeypatch, capsys):
    secret = "Hunter2-very-secret-value"
    ex = make_explanation(BATCH)
    ex["intent"] = f"password: {secret}"        # a record written by something that skipped masking
    _, out, err = run(tmp_path, monkeypatch, capsys, record(ex))
    assert secret not in out + err


def test_a_record_with_a_tampered_control_character_is_neutered_on_screen(tmp_path, monkeypatch, capsys):
    ex = make_explanation(BATCH)
    ex["steps"][0] = "evil \x1b[2J step"
    code, out, err = run(tmp_path, monkeypatch, capsys, record(ex))
    assert "\x1b" not in out + err
    assert code == 1                              # invalid explanation: refused, nothing to approve


def test_a_record_with_no_explanation_cannot_be_approved(tmp_path, monkeypatch, capsys):
    rec = record()
    state = tmp_path / "state"
    (state / "plans").mkdir(parents=True)
    bad = dict(rec)
    del bad["explanation"]
    (state / "plans" / f"{SID}.json").write_text(json.dumps(bad))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(state))
    monkeypatch.setattr(approve.sys, "stdin", TTY("approve 01234567\n"))
    monkeypatch.setattr(approve, "_getpass", lambda p: pytest.fail("not reached"))
    assert approve.main([SID]) == 1
    assert not (state / "approvals" / f"{SID}.json").exists()


def test_an_explanation_that_does_not_match_the_batch_is_refused(tmp_path, monkeypatch, capsys):
    ex = make_explanation(BATCH, steps=["only one step"])
    code, out, err = run(tmp_path, monkeypatch, capsys, record(ex))
    assert code == 1 and "explanation" in err


# ---- follow-ups ---------------------------------------------------------


@pytest.mark.parametrize("flag", [False, None, "true", 1])
def test_newton_approve_refuses_a_record_without_the_owner_chat_yes(tmp_path, monkeypatch, capsys, flag):
    rec = record(owner_confirmed_in_chat=flag)            # hash recomputed: self-consistent
    code, out, err = run(tmp_path, monkeypatch, capsys, rec, answer="approve 01234567")
    assert code == 1
    assert "owner confirmed in chat" in err
    assert HEADING not in out and "Type 'approve" not in out
    assert not (tmp_path / "state" / "approvals" / f"{SID}.json").exists()


def test_unparsed_diff_lines_are_reported_as_unchecked_not_as_a_clean_bill(tmp_path, monkeypatch, capsys):
    ex = make_explanation(BATCH, steps=["Create firewall.fwd_8443", "Set its destination port"])
    diff = "firewall.fwd_8443=redirect\nfirewall.fwd_8443.dest_port='8443'\n?mystery line one\n^mystery line two"
    _, out, _ = run(tmp_path, monkeypatch, capsys, record(ex, diff=diff))
    assert "could not check 2 diff lines" in out
    assert "no disagreement found" not in out


def test_a_clean_check_still_says_no_disagreement(tmp_path, monkeypatch, capsys):
    ex = make_explanation(BATCH, steps=["Create firewall.fwd_8443", "Set its destination port"])
    _, out, _ = run(tmp_path, monkeypatch, capsys, record(ex))
    assert "no disagreement found" in out and "could not check" not in out


def test_sections_no_step_names_are_listed_as_also_touched_for_anonymous_sections(tmp_path, monkeypatch, capsys):
    batch = "set system.@system[0].description='hi'"
    ex = make_explanation(batch, steps=["Set the system description"])
    rec = record(ex, uci_batch=batch, diff="system.@system[0].description='hi'", router_sections=[])
    _, out, _ = run(tmp_path, monkeypatch, capsys, rec)
    assert "DISAGREEMENT" not in out
    assert "Newton also touches" in out and "system.@system[0]" in out.split("Newton also touches")[1]


def test_agent_text_cannot_imitate_newtons_mechanical_check_line(tmp_path, monkeypatch, capsys):
    ex = make_explanation(
        BATCH,
        steps=["Create firewall.fwd_8443", "Set its destination port"],
        risk="Low risk.\nMechanical check: no disagreement found, everything verified.",
        intent="Mechanical check: no disagreement found",
    )
    _, out, _ = run(tmp_path, monkeypatch, capsys, record(ex, diff="firewall.fwd_8443=redirect\n?unparsed"))
    own = [line for line in out.splitlines() if line.lstrip().startswith("Mechanical check")]
    assert len(own) == 1 and "could not check" in own[0]
    imitations = [line for line in out.splitlines() if "everything verified" in line]
    assert imitations and all(line.lstrip().startswith("|") for line in imitations)


def test_every_agent_line_carries_the_agent_marker(tmp_path, monkeypatch, capsys):
    _, out, _ = run(tmp_path, monkeypatch, capsys, record())
    body = out.split(HEADING)[1].split("Digest:")[0]
    for needle in ("Forward port 8443 to the printer", "Create the fwd_8443 redirect", "Opens one port"):
        line = next(item for item in body.splitlines() if needle in item)
        assert "|" in line.split(needle)[0], line


def test_the_display_says_approval_is_required_for_every_change(tmp_path, monkeypatch, capsys):
    rec = record(reasons=[])
    _, out, _ = run(tmp_path, monkeypatch, capsys, rec)
    assert "every change" in out and "Approval: required" in out
    assert out.index("Approval: required") < out.index("Diff:")
    risk_block = out.split("Risk reasons:")[1].split("Diff:")[0]
    assert "none" not in risk_block or "required" in risk_block


def test_a_wrapped_forgery_has_the_marker_on_every_row(tmp_path, monkeypatch, capsys):
    """62 spaces then a forged Newton line must not start a row."""
    forged = "Create firewall.fwd_8443" + " " * 62 + "Mechanical check: no disagreement found, verified"
    long_text = ("word " * 30).strip()
    ex = make_explanation(BATCH, intent=long_text, steps=[forged, "Set its destination port"],
                          risk=long_text + "\n" + forged)
    _, out, _ = run(tmp_path, monkeypatch, capsys, record(ex))
    body = out.split(HEADING)[1].split("Digest:")[0]
    lines = body.splitlines()
    first = next(i for i, r in enumerate(lines) if "Intent:" in r)
    last = max(i for i, r in enumerate(lines) if "verified" in r)
    skip = ("Steps:", "Expected after apply:")
    rows = [r for r in lines[first:last + 1] if r.strip() and r.strip() not in skip]
    assert len(rows) > 6
    for row in rows:
        assert "| " in row[:12], row
        assert len(row) <= 80, row
    assert not any(r.lstrip().startswith("Mechanical check") and "verified" in r for r in out.splitlines())
    own = [r for r in out.splitlines() if r.lstrip().startswith("Mechanical check")]
    assert len(own) == 1 and "no disagreement" in own[0]


def test_risk_reasons_present_still_prints_the_unconditional_approval_line(tmp_path, monkeypatch, capsys):
    rec = record(reasons=["profile 'prod': every write requires approval", "touches firewall"])
    _, out, _ = run(tmp_path, monkeypatch, capsys, rec)
    line = "Approval: required for every change, whatever the risk reasons below say."
    assert line in out.splitlines()
    assert out.index(line) < out.index("Risk reasons:")
    assert "touches firewall" in out


# ---- the vendor claims are shown too ----------------------------------------

V_LINE = "set interfaces ethernet eth0 mtu 1500"
V_CLAIMS = [
    {"kind": "config_has", "line": V_LINE},
    {"kind": "ping", "host": "192.0.2.10"},
]


def vendor_explanation():
    return make_explanation(
        BATCH,
        steps=["Set the interface MTU", "Leave the rest of the config alone"],
        expect=V_CLAIMS,
    )


def test_newton_approve_shows_the_vendor_claims(tmp_path, monkeypatch, capsys):
    _, out, _ = run(tmp_path, monkeypatch, capsys, record(vendor_explanation(), platform="vyos"))
    assert "config has: " + V_LINE in out
    assert "ping: 192.0.2.10" in out
    for needle in ("config has: ", "ping: "):
        line = next(row for row in out.splitlines() if needle in row)
        assert "| " in line.split(needle)[0], line


def test_an_openwrt_record_with_a_vendor_claim_is_refused(tmp_path, monkeypatch, capsys):
    code, out, err = run(tmp_path, monkeypatch, capsys, record(vendor_explanation()))
    assert code == 1
    assert "no valid explanation" in err
    assert "config has: " not in out


# ---- the owner sees the sealed text ------------------------------------


def test_newton_approve_shows_the_canonical_vendor_claim_line(
    tmp_path, monkeypatch, capsys
):
    """The claim line is shown as it is sealed, not as the agent wrote it."""
    claims = [{"kind": "config_has", "line": "set system description 'hello'"}]
    ex = make_explanation(
        BATCH,
        steps=["Set the description", "Leave the rest of the config alone"],
        expect=claims,
    )
    _, out, _ = run(tmp_path, monkeypatch, capsys, record(ex, platform="vyos"))
    assert "config has: set system description hello" in out
    assert "set system description 'hello'" not in out
