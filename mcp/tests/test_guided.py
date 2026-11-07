"""R1: ``newton_guided_recommend`` (ROADMAP item 7, guided setup).

The guided tool consumes a 10-question interview and returns a
``guided_setup_report`` whose controls, statuses and reasons are
DERIVED from the real manifest and tier files; it never reaches the
device, never accepts a path/command/shell argument, and the report
is built only from the fixed question table and the manifest data
(no device text).

Mapping rules (spec section 2; provenance of each (question, answer)
-> control id, with optional tier / form selector, is the fixed
table in ``newton_mcp.guided``):

* ``strictness`` answers pick the tier (normal/stricter/maximum ->
  standard/hardened/lockdown).
* Yes-style answers pick a control id (with tier / form-of selector
  for ids that appear under more than one tier).
* "no" / "no extra" answers add NO recommendation.

Status derivation (R1):

1. id not in manifest          -> "gap"    ("not in manifest")
2. manifest lab == "not-yet"   -> "gap"    ("not-yet")
3. ``lab_bound`` names the batch -> "gap"    ("current batch is nonportable")
4. lab == "audit"              -> "audit-only"
5. the tier file skipped it (lab-bound or conditional) -> "skipped"
6. empty batch otherwise       -> "gap"    ("no active lines")
7. otherwise                   -> "plan-ready"

Fail closed: an unknown question id, unknown answer, non-string
answer, non-dict ``answers``, or missing ``strictness`` is refused
and the error message never echoes the rejected value.
"""

from __future__ import annotations

import asyncio
import inspect
import json
from pathlib import Path

import pytest

import newton_mcp.guided as guided
import newton_mcp.probes as probes
import newton_mcp.server as server
import newton_mcp.tiers as tiers
from newton_mcp.server import NewtonError


# ---- the 10 interview questions (spec section 2) ---------------------------


QUESTION_IDS_IN_ORDER = [
    "device_kind",
    "strictness",
    "admin_source",
    "admin_access",
    "ssh_password_off",
    "inbound_services",
    "upnp",
    "segments",
    "wifi_wpa2",
    "dns",
    "ipv6_off",
    "remote_vpn",
    "log_time_hosts",
    "fw_update_check",
]


LEGACY_QUESTION_IDS = [
    "strictness",
    "wifi_wpa2",
    "guest_network",
    "upnp",
    "iot_network",
    "ssh_password_off",
    "dnssec",
    "encrypted_dns",
    "ipv6_off",
    "fw_update_check",
]


def test_questions_returns_the_fourteen_v2_questions_in_spec_order():
    """questions() returns the 14 v2 spec questions in the order they
    appear in section 3; every entry has the six contract keys
    (id, text, type, answers, max, applies_to)."""
    qs = guided.questions()
    assert len(qs) == 14
    assert [q["id"] for q in qs] == QUESTION_IDS_IN_ORDER
    for q in qs:
        assert set(q) == {"id", "text", "type", "answers", "max", "applies_to"}
        assert isinstance(q["id"], str) and q["id"]
        assert isinstance(q["text"], str) and q["text"]
        assert isinstance(q["answers"], tuple)
        # enum and multi_enum have at least two allowed values;
        # port_list and host_lists have an empty answers tuple.
        if q["type"] in {"enum", "multi_enum"}:
            assert len(q["answers"]) >= 2
            assert all(isinstance(a, str) for a in q["answers"])
            assert len(set(q["answers"])) == len(q["answers"])
        else:
            assert q["answers"] == ()


# ---- the (question, answer) -> manifest-tuple cross product ---------------


def _all_control_ids() -> set[str]:
    return {c["id"] for c in probes._load_controls(probes.manifest_path())}


def test_every_question_x_answer_resolves_to_a_known_manifest_or_a_tier():
    """For every (question, answer) in the interview, recommend() with
    just that answer (and ``strictness=normal``) either picks a known
    tier or maps to a control id that actually exists in the real
    manifest, and the chosen tier is one of the three."""
    known_ids = _all_control_ids()
    q_by_id = {q["id"]: q for q in guided.LEGACY_QUESTIONS}
    for qid in LEGACY_QUESTION_IDS:
        for answer in q_by_id[qid]["answers"]:
            answers = {"strictness": "normal", qid: answer}
            # the only possible refuse path: unknown id or bad values
            report = guided.recommend(answers)
            assert report["report"] == "guided_setup_report"
            assert report["tier"] in tiers.TIER_NAMES
            # if the answer mapped to a control, the id must exist
            for rec in report["recommendations"]:
                assert rec["control_id"] in known_ids, (
                    qid, answer, rec["control_id"]
                )
            # and the answer was echoed when validated
            if qid != "strictness":
                echo = {a["id"]: a["answer"] for a in report["answers"]}
                assert echo[qid] == answer


# ---- status derivation follows the manifest -------------------------------


def _status(control_id, controls=None, directory=None):
    return guided.control_status(control_id, controls=controls, directory=directory)


def test_control_status_flips_to_gap_when_control_is_removed(tmp_path):
    """A control id not in the manifest is gap ('not in manifest')."""
    # baseline: OW-MGMT-03 is plan-ready
    base = _status("OW-MGMT-03")
    assert base["status"] != "gap"
    # copy the manifest minus OW-MGMT-03
    src = Path(probes.manifest_path())
    dst = tmp_path / "manifest.toml"
    dst.write_text(
        "\n".join(
            line for line in src.read_text(encoding="utf-8").splitlines()
            if not (line.startswith("id = ") and "OW-MGMT-03" in line)
        )
    )
    monkey = pytest.MonkeyPatch()
    monkey.setenv("NEWTON_MANIFEST", str(dst))
    try:
        after = guided.control_status("OW-MGMT-03")
        assert after["status"] == "gap"
        assert "not in manifest" in after["reason"]
    finally:
        monkey.undo()


def test_control_status_flips_to_gap_when_lab_changes_to_not_yet(tmp_path):
    """Editing the control's ``lab`` to ``not-yet`` flips its status to
    gap with a 'not-yet' reason."""
    # OW-FW-01 (standard, lab=proven) -> plan-ready with the real manifest
    base = _status("OW-FW-01")
    assert base["status"] == "plan-ready"
    src = Path(probes.manifest_path())
    text = src.read_text(encoding="utf-8")
    new_lines = []
    in_block = False
    replaced = False
    for line in text.splitlines():
        if line.startswith("id = "):
            in_block = ("OW-FW-01" in line)
            if not in_block and replaced:
                pass  # leave the flag alone for the next block
        if in_block and line.startswith("lab = ") and not replaced:
            new_lines.append("lab = 'not-yet'")
            replaced = True
        else:
            new_lines.append(line)
    assert replaced, "did not find the OW-FW-01 lab line"
    dst = tmp_path / "manifest.toml"
    dst.write_text("\n".join(new_lines) + "\n")
    monkey = pytest.MonkeyPatch()
    monkey.setenv("NEWTON_MANIFEST", str(dst))
    try:
        after = guided.control_status("OW-FW-01")
        assert after["status"] == "gap"
        assert "not-yet" in after["reason"]
    finally:
        monkey.undo()


def test_control_status_flips_to_gap_when_lab_bound_is_added(tmp_path):
    """Adding a lab_bound that names the batch to a plan-ready control flips it
    to gap ('current batch is nonportable')."""
    base = _status("OW-FW-01")
    assert base["status"] == "plan-ready"
    src = Path(probes.manifest_path())
    text = src.read_text(encoding="utf-8")
    new_lines = []
    in_block = False
    replaced = False
    for line in text.splitlines():
        if line.startswith("id = "):
            in_block = ("OW-FW-01" in line)
        if in_block and line.startswith("lab_bound = ") and not replaced:
            new_lines.append("lab_bound = ['batch']")
            replaced = True
        else:
            new_lines.append(line)
    assert replaced, "did not find the OW-FW-01 lab_bound line"
    dst = tmp_path / "manifest.toml"
    dst.write_text("\n".join(new_lines) + "\n")
    monkey = pytest.MonkeyPatch()
    monkey.setenv("NEWTON_MANIFEST", str(dst))
    try:
        after = guided.control_status("OW-FW-01")
        assert after["status"] == "gap"
        assert "nonportable" in after["reason"]
    finally:
        monkey.undo()


def test_control_status_skipped_via_tier_conditional():
    """Standard OW-FW-06 is conditional (needs the miniupnpd-nftables
    package), so the tier file marks it skipped -- control_status
    must return 'skipped' with a reason naming the package."""
    info = _status("OW-FW-06")
    # When both standard + opt-in entries share the id, the choice
    # picks the BASE entry (form_of == ''), i.e. standard.
    assert info["status"] == "skipped"
    assert "conditional" in info["reason"]
    assert "miniupnpd-nftables" in info["reason"]


def test_control_status_audit_only():
    """An ``audit`` lab with no batch is audit-only (e.g. OW-FW-05)."""
    info = _status("OW-FW-05")
    assert info["status"] == "audit-only"


def test_control_status_plan_ready_for_a_plan_ready_control():
    """OW-MGMT-03 (standard, lab=proven, batch non-empty, not
    conditional in the tier file) is plan-ready."""
    info = _status("OW-MGMT-03")
    assert info["status"] == "plan-ready"


# ---- recommend(): fail-closed validation ----------------------------------


def test_recommend_refuses_missing_strictness():
    """An answers dict with no strictness is refused (strictness is
    the only mandatory answer; partial answers are otherwise OK)."""
    with pytest.raises(guided.GuidedError) as excinfo:
        guided.recommend({})
    msg = str(excinfo.value)
    assert "strictness" in msg


def test_recommend_refuses_unknown_question_id():
    """An unknown question id is refused; the rejected value never
    appears in the error message."""
    with pytest.raises(guided.GuidedError) as excinfo:
        guided.recommend({"strictness": "normal", "totally_bogus": "yes"})
    msg = str(excinfo.value)
    assert "totally_bogus" not in msg
    assert "question" in msg.lower() or "id" in msg.lower()


def test_recommend_refuses_unknown_answer():
    with pytest.raises(guided.GuidedError) as excinfo:
        guided.recommend({"strictness": "bogus"})
    msg = str(excinfo.value)
    assert "bogus" not in msg


def test_recommend_refuses_non_string_answer():
    for bad in [1, 2.0, True, None, ["yes"], ("yes",)]:
        with pytest.raises((guided.GuidedError, TypeError)):
            guided.recommend({"strictness": bad})


def test_recommend_refuses_non_dict_answers():
    for bad in ["yes", 42, ["yes"], None, ("strictness", "normal")]:
        with pytest.raises((guided.GuidedError, TypeError)):
            guided.recommend(bad)


def test_recommend_partial_answers_are_allowed_and_list_unanswered():
    """Partial answers are fine except strictness; the unanswered
    question ids appear under the report's 'unanswered' key."""
    report = guided.recommend({"strictness": "normal"})
    assert report["report"] == "guided_setup_report"
    assert report["tier"] == "standard"
    # strictness was answered
    answered_ids = {a["id"] for a in report["answers"]}
    assert "strictness" in answered_ids
    # every other question id is in 'unanswered'
    unanswered = set(report["unanswered"])
    assert answered_ids.isdisjoint(unanswered)
    assert "strictness" not in unanswered


def test_recommend_echoes_strictness_and_keeps_partial_drops_no_questions():
    """When all questions are answered, the answers echo carries
    only entries for the validated (id, value) pairs."""
    report = guided.recommend({
        "strictness": "normal",
        "guest_network": "yes",
    })
    ids = [a["id"] for a in report["answers"]]
    assert ids == ["strictness", "guest_network"]
    # and the report's unanswered list is everything else
    unanswered_ids = report["unanswered"]
    assert "guest_network" not in unanswered_ids
    assert "strictness" not in unanswered_ids


# ---- recommend(): the happy path returns the expected shape ----------------


def test_recommend_with_yes_answers_creates_recommendations_for_each():
    """strictness=maximum + every yes-able question produces a list
    of recommendations, one per question × answer with a control
    mapping; each recommendation carries the required keys."""
    answers = {
        "strictness": "maximum",
        "wifi_wpa2": "all_wpa3",
        "guest_network": "yes",
        "upnp": "no",
        "iot_network": "no",
        "ssh_password_off": "no",
        "dnssec": "no",
        "encrypted_dns": "no",
        "ipv6_off": "no",
        "fw_update_check": "no",
    }
    report = guided.recommend(answers)
    assert report["report"] == "guided_setup_report"
    assert report["tier"] == "lockdown"
    recs = report["recommendations"]
    assert isinstance(recs, list)
    # guest_network=yes => OW-ZONE-01
    assert any(r["control_id"] == "OW-ZONE-01" for r in recs)
    # the audit / scans lists are present, ordered, and document the
    # consent-required state
    for s in ("nmap_inside", "nmap_outside", "wifi_scan", "kismet"):
        assert s in report["scans_not_run"]
    # approval note
    assert "owner approval" in report["approval"].lower() or "approval" in report["approval"].lower()
    # every recommendation carries the contract keys
    required = {
        "control_id", "current_state", "desired_state", "owner_reason",
        "evidence", "benefit", "breakage_or_preconditions",
        "confidence", "status",
    }
    for rec in recs:
        assert set(rec).issuperset(required), (rec, required)
        assert rec["confidence"] in {"high", "medium", "low"}
        assert rec["status"] in {"plan-ready", "audit-only", "skipped", "gap"}


def test_recommend_for_upnp_yes_picks_opt_in_form_of_ow_fw_06():
    """``upnp=yes`` picks the opt-in form of OW-FW-06 (not the
    standard one) -- control_status for that entry is plan-ready
    because the opt-in entry has no lab_bound and a non-empty batch."""
    answers = {"strictness": "normal", "upnp": "yes"}
    report = guided.recommend(answers)
    recs = [r for r in report["recommendations"] if r["control_id"] == "OW-FW-06"]
    assert recs, recs
    assert recs[0]["status"] == "plan-ready"


# ---- the report is built only from the fixed tables / manifest ------------


def test_recommend_report_never_echoed_device_text(monkeypatch):
    """recommend() never reaches the device and never echoes device
    text; the report values come from the fixed tables and the
    manifest only."""
    # even if NewtonService.device/read/run explodes, recommend goes
    # through its own path.  This proves the report is constructed
    # without touching the device.
    def explode(*a, **k):
        raise AssertionError("device method called by recommend()")

    monkeypatch.setattr(server.NewtonService, "device", explode)
    monkeypatch.setattr(server.NewtonService, "read", explode)
    monkeypatch.setattr(server.NewtonService, "run_script", explode)
    # recommend runs without inventory
    monkeypatch.delenv("NEWTON_INVENTORY", raising=False)
    report = guided.recommend({
        "strictness": "maximum",
        "guest_network": "yes",
        "upnp": "no",
        "iot_network": "yes",
        "ssh_password_off": "yes",
        "dnssec": "yes",
        "encrypted_dns": "no",
        "ipv6_off": "yes",
        "fw_update_check": "yes",
    })
    # JSON roundtrip: every value is from the fixed tables / manifest
    blob = json.dumps(report)
    # the manifest's notes may appear because we copy them into
    # breakage_or_preconditions -- but strings outside the manifest's
    # known control list never appear in the IDs or status values.
    for rec in report["recommendations"]:
        assert rec["status"] in {"plan-ready", "audit-only", "skipped", "gap"}
        assert rec["control_id"] in _all_control_ids()
    # and the scans_not_run lines are the four fixed strings only
    assert set(report["scans_not_run"]) == {
        "nmap_inside", "nmap_outside", "wifi_scan", "kismet",
    }


# ---- the MCP tool surface --------------------------------------------------


def test_guided_tool_in_tool_names():
    """``newton_guided_recommend`` is registered in ``TOOL_NAMES``."""
    assert "newton_guided_recommend" in server.TOOL_NAMES


def test_guided_tool_in_mcp_in_memory_listing():
    from mcp.shared.memory import create_connected_server_and_client_session

    async def listed():
        async with create_connected_server_and_client_session(
            server.mcp._mcp_server
        ) as session:
            await session.initialize()
            return await session.list_tools()

    response = asyncio.run(listed())
    names = {tool.name for tool in response.tools}
    assert "newton_guided_recommend" in names


def test_guided_tool_input_schema_has_only_optional_answers_no_path_or_command():
    """The guided tool accepts only an optional ``answers`` object.
    It has no path/command/file/device/tier argument."""
    from mcp.shared.memory import create_connected_server_and_client_session

    async def listed():
        async with create_connected_server_and_client_session(
            server.mcp._mcp_server
        ) as session:
            await session.initialize()
            return await session.list_tools()

    response = asyncio.run(listed())
    tool = next(t for t in response.tools if t.name == "newton_guided_recommend")
    props = tool.inputSchema["properties"]
    assert set(props) == {"answers"}
    # answers is an optional object (type may be 'object' directly or
    # inside an anyOf with 'null').
    answers = props["answers"]
    if "type" in answers:
        assert answers["type"] == "object"
    else:
        types = []
        for alt in answers.get("anyOf", []):
            t = alt.get("type")
            if t in {"object", "null"}:
                types.append(t)
        assert "object" in types and "null" in types
    # answers is optional
    required = tool.inputSchema.get("required", [])
    assert "answers" not in required


def test_guided_tool_returns_questions_when_no_answers_or_empty():
    """Calling the tool with no answers (or an empty dict) returns
    the interview, not a report."""
    out_empty = server.newton_guided_recommend()
    out_blank = server.newton_guided_recommend({})
    for out in (out_empty, out_blank):
        assert "questions" in out
        ids = [q["id"] for q in out["questions"]]
        assert ids == QUESTION_IDS_IN_ORDER
        # no report key when answering questions
        assert "report" not in out or out.get("report") is None


def test_guided_tool_returns_report_when_answers_present():
    """Calling the tool with a strictness answer returns a full
    ``guided_setup_report`` dict (no device access path -- the
    tool wrapper never enters NewtonService.device)."""
    out = server.newton_guided_recommend({
        "strictness": "normal",
        "guest_network": "yes",
    })
    assert out["result"] == "ok"
    assert out["report"]["report"] == "guided_setup_report"
    assert any(r["control_id"] == "OW-ZONE-01" for r in out["report"]["recommendations"])


def test_guided_tool_never_calls_device_for_any_path(monkeypatch):
    """With NO inventory / no SSH, the tool path runs both the
    questions and the report flows without touching the device."""
    calls = []

    def explode(self, *a, **k):
        calls.append(("device", a, k))
        raise AssertionError("NewtonService.device must not be called")

    def explode_run(self, *a, **k):
        calls.append(("run", a, k))
        raise AssertionError("NewtonService.run_script must not be called")

    monkeypatch.setattr(server.NewtonService, "device", explode)
    monkeypatch.setattr(server.NewtonService, "run_script", explode_run)
    monkeypatch.delenv("NEWTON_INVENTORY", raising=False)

    # questions path
    server.newton_guided_recommend()
    # report path
    server.newton_guided_recommend({"strictness": "maximum", "dnssec": "yes"})
    assert calls == []


# ---- generic error routing -----------------------------------------------


def test_guided_recommend_routes_unexpected_exception_to_generic_handler(
    monkeypatch, tmp_path,
):
    """When ``guided.recommend`` raises something other than a
    NewtonError, the tool must take the same path as every other tool:
    one entry in mcp-errors.log and the generic ``internal server
    error`` answer that hides the real cause from the model."""
    def explode(_answers):
        raise RuntimeError("boom-marker")

    monkeypatch.setattr(guided, "recommend", explode)

    # The autouse ``_isolate_state_dir`` fixture points NEWTON_STATE_DIR
    # at ``tmp_path / "state"``; the log path matches.
    log = tmp_path / "state" / "mcp-errors.log"

    result = server.newton_guided_recommend({"strictness": "normal"})

    assert result == {"error": "internal server error"}
    assert "boom-marker" not in str(result)

    assert log.exists(), "mcp-errors.log should be created on the first unexpected error"
    text = log.read_text(encoding="utf-8")
    assert "RuntimeError" in text
    assert "boom-marker" in text

    headers = [
        line for line in text.splitlines()
        if "tool=newton_guided_recommend" in line
    ]
    assert len(headers) == 1, text
    assert "device=-" in headers[0]

    # The audit log is written by both the unexpected-error branch and
    # the happy path with ``device=-``; assert that the error branch
    # fired rather than the real cause leaking.
    audit = (tmp_path / "state" / "mcp-audit.log").read_text(encoding="utf-8")
    assert (
        "tool=newton_guided_recommend device=- result=error"
        in audit
    ), audit


def test_guided_recommend_import_error_routes_to_generic_handler(
    monkeypatch, tmp_path,
):
    """If the relative import of ``newton_mcp.guided`` itself fails (a
    broken install or a partially-built deploy), the tool must NOT
    propagate the ImportError as-is.  The same generic-error path used
    for any other unexpected exception applies: one mcp-errors.log
    entry and ``{"error": "internal server error"}``."""
    import sys

    import newton_mcp

    log = tmp_path / "state" / "mcp-errors.log"

    # Force ``from . import guided`` to raise ImportError.  Setting the
    # module entry to None in sys.modules alone is not enough: Python's
    # import machinery also resolves ``from . import X`` via the parent
    # package's cached ``X`` attribute, so we drop that attribute too.
    monkeypatch.setitem(sys.modules, "newton_mcp.guided", None)
    monkeypatch.delattr(newton_mcp, "guided", raising=False)
    monkeypatch.delattr(server, "guided", raising=False)

    result = server.newton_guided_recommend()

    assert result == {"error": "internal server error"}

    assert log.exists(), (
        "mcp-errors.log should be created on the first unexpected error"
    )
    text = log.read_text(encoding="utf-8")
    assert "ImportError" in text or "ModuleNotFoundError" in text

    headers = [
        line for line in text.splitlines()
        if "tool=newton_guided_recommend" in line
    ]
    assert len(headers) == 1, text
    assert "device=-" in headers[0]

    audit = (tmp_path / "state" / "mcp-audit.log").read_text(encoding="utf-8")
    assert (
        "tool=newton_guided_recommend device=- result=error"
        in audit
    ), audit


def test_guided_recommend_questions_route_logs_unexpected_exception(
    monkeypatch, tmp_path,
):
    """Same guarantee for the no-answers questions path: an
    unexpected exception from ``guided.questions`` must reach the
    generic handler rather than propagating as-is."""
    def explode():
        raise RuntimeError("questions-boom")

    monkeypatch.setattr(guided, "questions", explode)

    log = tmp_path / "state" / "mcp-errors.log"

    result = server.newton_guided_recommend()

    assert result == {"error": "internal server error"}
    assert "questions-boom" not in str(result)

    assert log.exists()
    text = log.read_text(encoding="utf-8")
    assert "RuntimeError" in text
    assert "questions-boom" in text

    headers = [
        line for line in text.splitlines()
        if "tool=newton_guided_recommend" in line
    ]
    assert len(headers) == 1, text


# ---- module surface --------------------------------------------------------


def test_questions_and_QUESTIONS_are_consistent():
    """``QUESTIONS`` and ``questions()`` agree across the six
    contract keys."""
    qs = guided.questions()
    assert len(qs) == len(guided.QUESTIONS)
    for q, recorded in zip(qs, guided.QUESTIONS):
        assert q["id"] == recorded["id"]
        assert q["text"] == recorded["text"]
        assert q["type"] == recorded["type"]
        assert tuple(q["answers"]) == tuple(recorded["answers"])
        assert q["max"] == recorded["max"]
        assert q["applies_to"] == recorded["applies_to"]


def test_guidedmodule_exports_the_expected_symbols():
    """The module exposes the names the test suite (and the tool)
    import: ``questions``, ``QUESTIONS``, ``recommend``,
    ``control_status``, ``GuidedError``."""
    for name in ("questions", "QUESTIONS", "recommend",
                 "control_status", "GuidedError"):
        assert hasattr(guided, name), name


def test_recommend_signature_does_not_take_device():
    """``recommend`` is a pure function in / out -- no device arg."""
    sig = inspect.signature(guided.recommend)
    for name in sig.parameters:
        assert name not in {"device", "device_name"}, name


def test_recommend_source_does_not_call_apply_or_run_script():
    """Recommendation must never reach the apply or read paths."""
    src = inspect.getsource(guided.recommend)
    assert "apply" not in src, src
    assert "run_script" not in src, src
    assert "subprocess" not in src, src
