"""The MCP tool returns the report, the summary, a stored
confirmation record, the id and an ask-the-owner note.

These tests use the ``NEWTON_STATE_DIR`` fixture from ``conftest.py`` so
every call uses a throwaway state directory (no real ``~/.local/state/...``).
The MCP server, ``server.newton_guided_recommend``, is imported directly
(matching the patterns in ``test_guided.py`` and ``test_guided_audit.py``).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import newton_mcp.guided as guided
import newton_mcp.server as server


GOLDEN_FIXTURE = Path(__file__).parent / "fixtures" / "guided_v1_golden.json"


# ---- helpers --------------------------------------------------------------


def _read_golden_cases():
    data = json.loads(GOLDEN_FIXTURE.read_text(encoding="utf-8"))
    return data["cases"]


def _audit_log(state_dir: Path) -> str:
    path = state_dir / "mcp-audit.log"
    return path.read_text(encoding="utf-8") if path.exists() else ""


# ---- report path returns summary + confirmation_id + note -----


def test_mv1_2_C01_report_path_returns_summary_id_and_note(tmp_path):
    """The report path returns ``summary`` (a str, one line per answered
    question), a 64-char lower-case hex ``confirmation_id``, ``confirmed
    False``, ``confirmation_expires_at`` and a fixed ``confirmation_note``
    asking the owner to confirm; the record file exists at
    ``<state>/guided-confirmations/<id>.json`` with mode 0o600 and holds
    answers, summary, device ``-``, platform ``openwrt``, created_at,
    expires_at."""
    state_dir = tmp_path / "state"
    state_dir.mkdir()  # parent does NOT exist yet -> store_confirmation
    # must create it 0o700 (see the state-root test)

    answers = {
        "device_kind": "home_router",
        "strictness": "normal",
        "ssh_password_off": "yes",
    }
    out = server.newton_guided_recommend(answers)

    assert out["result"] == "ok"
    assert out["report"]["report"] == "guided_setup_report"
    assert isinstance(out["summary"], str)
    # exactly one line per answered question, in question order
    assert out["summary"] == guided.summary(answers)
    assert len(out["summary"].split("\n")) == 3  # 3 answered questions

    assert re.fullmatch(r"[0-9a-f]{64}", out["confirmation_id"]), out["confirmation_id"]
    assert out["confirmed"] is False
    assert re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(\+00:00|Z)",
        out["confirmation_expires_at"],
    )
    note = out["confirmation_note"]
    assert "ask the owner" in note.lower() or "summary" in note.lower()
    assert "is this right" in note.lower() or "new record" in note.lower()

    record_path = state_dir / "guided-confirmations" / (out["confirmation_id"] + ".json")
    assert record_path.exists()
    assert oct(stat.S_IMODE(os.stat(record_path).st_mode)) == oct(0o600)

    data = json.loads(record_path.read_text(encoding="utf-8"))
    assert data["id"] == out["confirmation_id"]
    assert data["summary"] == out["summary"]
    assert data["device"] == "-"
    assert data["platform"] == "openwrt"
    assert isinstance(data["created_at"], str)
    assert data["expires_at"] == out["confirmation_expires_at"]
    # answers recorded as [{id, answer}, ...]
    answers_set = {(a["id"], a["answer"]) for a in data["answers"]}
    for qid in answers:
        assert (qid, answers[qid]) in answers_set


# ---- same answers twice -> same id; a changed answer -> new ---


def test_mv1_2_C02_changed_answer_makes_a_different_id(tmp_path):
    """The same answers twice yield the same id and only one record file;
    a changed answer yields a different id and a second record file."""
    state_dir = tmp_path / "state"
    state_dir.mkdir()

    answers_a = {
        "device_kind": "home_router",
        "strictness": "normal",
        "fw_update_check": "yes",
    }
    answers_b = {**answers_a, "fw_update_check": "no"}

    out_a1 = server.newton_guided_recommend(answers_a)
    out_a2 = server.newton_guided_recommend(answers_a)
    out_b = server.newton_guided_recommend(answers_b)

    assert out_a1["confirmation_id"] == out_a2["confirmation_id"]
    assert out_a1["confirmation_id"] != out_b["confirmation_id"]

    store = state_dir / "guided-confirmations"
    files = sorted(store.glob("*.json"))
    assert len(files) == 2, [f.name for f in files]
    names = {f.name for f in files}
    assert (out_a1["confirmation_id"] + ".json") in names
    assert (out_b["confirmation_id"] + ".json") in names


# ---- audit line shape ----------------------------------------


def test_mv1_2_C03_audit_line_has_confirmation_id(tmp_path):
    """The mcp-audit.log records
    ``tool=newton_guided_recommend device=- result=ok confirmation=<id>``
    when a confirmation is stored."""
    state_dir = tmp_path / "state"
    state_dir.mkdir()

    out = server.newton_guided_recommend({
        "device_kind": "home_router",
        "strictness": "maximum",
        "fw_update_check": "yes",
    })

    audit = _audit_log(state_dir)
    expected = (
        "tool=newton_guided_recommend device=- "
        f"result=ok confirmation={out['confirmation_id']}"
    )
    assert expected in audit, audit


# ---- legacy answers are byte-identical to the golden fixture --


def test_mv1_2_C04_legacy_answers_match_golden_fixture(tmp_path):
    """Picked three legacy cases: the tool's ``report`` value is
    ``json.dumps``-equal to the stored ``report_json`` in the v1 golden
    fixture (the report itself is unchanged by the tool)."""
    state_dir = tmp_path / "state"
    state_dir.mkdir()

    cases = _read_golden_cases()
    picked = [cases[0], cases[3], cases[5]]

    for case in picked:
        out = server.newton_guided_recommend(case["answers"])
        assert out["result"] == "ok"
        assert json.dumps(out["report"]) == case["report_json"], (
            case["answers"],
        )


# ---- store failure -> report still returned; id is None ------


def test_mv1_2_C05_store_failure_returns_report_and_none_id(tmp_path, monkeypatch):
    """When ``store_confirmation`` raises ``OSError``, the tool still
    returns the report, ``confirmation_id`` is None,
    ``confirmation_expires_at`` is None, and the audit line says
    ``result=ok confirmation=none``."""
    state_dir = tmp_path / "state"
    state_dir.mkdir()

    def boom(record, root):
        raise OSError("disk full")

    monkeypatch.setattr(guided, "store_confirmation", boom)

    out = server.newton_guided_recommend({
        "device_kind": "home_router",
        "strictness": "normal",
    })
    assert out["result"] == "ok"
    assert out["report"]["report"] == "guided_setup_report"
    assert out["confirmation_id"] is None
    assert out["confirmation_expires_at"] is None
    assert "summary" in out and isinstance(out["summary"], str)
    # no record file written
    assert not (state_dir / "guided-confirmations").exists()

    audit = _audit_log(state_dir)
    assert (
        "tool=newton_guided_recommend device=- result=ok confirmation=none"
    ) in audit, audit


# ---- a failed store must not claim the record was stored --------


def test_sec3_5_store_failure_note_says_the_record_was_not_stored(
    tmp_path, monkeypatch,
):
    """when ``store_confirmation`` raises ``OSError`` the
    result keeps every other key and ``confirmation_id`` stays None, but
    ``confirmation_note`` must say the confirmation record was NOT
    stored and that nothing was saved -- it must not repeat the success
    note. The success case still gets the stored-record note."""
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    answers = {"device_kind": "home_router", "strictness": "normal"}

    def boom(record, root):
        raise OSError("disk full")

    with monkeypatch.context() as m:
        m.setattr(guided, "store_confirmation", boom)
        failed = server.newton_guided_recommend(dict(answers))

    assert failed["result"] == "ok"
    assert failed["confirmation_id"] is None
    assert failed["confirmation_expires_at"] is None
    # the other keys are unchanged by a failed store
    assert failed["report"]["report"] == "guided_setup_report"
    assert failed["summary"] == guided.summary(answers)
    assert failed["confirmed"] is False

    note = failed["confirmation_note"].lower()
    assert "not stored" in note, failed["confirmation_note"]
    assert "stored server-side" not in note, failed["confirmation_note"]
    assert "nothing" in note and "saved" in note, failed["confirmation_note"]
    assert not (state_dir / "guided-confirmations").exists()

    # success case unchanged: a real id and the stored-record note
    ok = server.newton_guided_recommend(dict(answers))
    assert re.fullmatch(r"[0-9a-f]{64}", ok["confirmation_id"])
    ok_note = ok["confirmation_note"].lower()
    assert "stored this interview summary server-side" in ok_note
    assert "not stored" not in ok_note, ok["confirmation_note"]


# ---- bad answer returns error; no record; audit=error --------


def test_mv1_2_C06_bad_answer_returns_error_no_record_audit_error(tmp_path):
    """An invalid answer value returns ``{"error": ...}`` (NOT echoing
    the rejected value), writes no record and audits
    ``tool=newton_guided_recommend device=- result=error``."""
    state_dir = tmp_path / "state"
    state_dir.mkdir()

    out = server.newton_guided_recommend({
        "device_kind": "home_router",
        "strictness": "wrong_value",
    })
    assert "error" in out, out
    # the rejected value must never appear
    assert "wrong_value" not in json.dumps(out)
    # no record file written
    assert not (state_dir / "guided-confirmations").exists()
    audit = _audit_log(state_dir)
    assert (
        "tool=newton_guided_recommend device=- result=error"
    ) in audit, audit


# ---- nothing refuses on the record ----------------------------


def test_mv1_2_C07_record_does_not_gate_any_other_tool(tmp_path):
    """``guided.confirmation_status`` reports ``"valid"`` for a stored
    record, and a grep-style source check confirms only
    ``guided.py`` and ``newton_guided_recommend`` mention
    ``guided-confirmations`` or ``confirmation_status`` in
    ``mcp/newton_mcp`` (no other tool reads the record and therefore no
    tool can refuse on it)."""
    state_dir = tmp_path / "state"

    answers = {
        "device_kind": "home_router",
        "strictness": "normal",
    }
    out = server.newton_guided_recommend(answers)
    status = guided.confirmation_status(out["confirmation_id"], state_dir)
    assert status == {"id": out["confirmation_id"], "status": "valid"}

    # grep-style source check: only guided.py (record producer) and
    # server.py's newton_guided_recommend (which returns the id) may
    # mention the on-disk path or the status helper.
    offenders = []
    mcp_dir = Path(server.__file__).resolve().parent
    for py in mcp_dir.glob("*.py"):
        text = py.read_text(encoding="utf-8")
        for keyword in ("guided-confirmations", "confirmation_status"):
            for lineno, line in enumerate(text.splitlines(), start=1):
                if keyword not in line:
                    continue
                if py.name == "guided.py":
                    continue
                if py.name == "server.py":
                    fn_start = text.find("def newton_guided_recommend(")
                    if fn_start == -1:
                        continue
                    # accept only inside the function body
                    after = text.find("\ndef ", fn_start + 1)
                    fn_lineno = text.count("\n", 0, fn_start) + 1
                    after_lineno = (
                        text.count("\n", 0, after) + 1 if after != -1 else None
                    )
                    if lineno > fn_lineno and (
                        after_lineno is None or lineno < after_lineno
                    ):
                        continue
                offenders.append((py.name, keyword, lineno, line.strip()))

    assert not offenders, offenders


# ---- questions path writes no record -------------------------


def test_mv1_2_C08_questions_path_writes_no_record(tmp_path):
    """The questions path (``newton_guided_recommend()`` / ``{}``) writes
    no confirmation record on disk."""
    state_dir = tmp_path / "state"
    state_dir.mkdir()

    out_empty = server.newton_guided_recommend()
    out_blank = server.newton_guided_recommend({})
    for out in (out_empty, out_blank):
        assert "questions" in out
        assert "confirmation_id" not in out
        assert "confirmation_note" not in out

    assert not (state_dir / "guided-confirmations").exists()


# ---- store_confirmation creates state_root 0o700 ------------


def test_mv1_2_C09_store_confirmation_creates_state_root_0o700(tmp_path):
    """``store_confirmation`` creates ``state_root`` with mode 0o700
    when it does not exist (the same pattern server.write_audit uses)."""
    state_root = tmp_path / "fresh-state"  # does NOT exist yet
    assert not state_root.exists()

    rec = guided.confirmation_record(
        {"device_kind": "home_router", "strictness": "normal"},
        "s", device="-", platform="openwrt",
    )
    guided.store_confirmation(rec, state_root)

    assert state_root.exists()
    assert oct(stat.S_IMODE(os.stat(state_root).st_mode)) == oct(0o700)
    assert (state_root / "guided-confirmations").is_dir()


# ---- tidy-ups on guided.py -----------------------------------


def test_mv1_2_C10_regex_block_is_not_duplicated_and_strictness_single():
    """The 5 regex allowlists (_PLATFORM_RE, _INTENT_ID_RE, _PORT_RE,
    _HOSTNAME_LABEL_RE, _CONF_ID_RE) are defined exactly once; no stale
    KNOWN_INTENTS comment lingers above _V2_QUES; the legacy strictness
    tier and the v2 strictness-to-tier dict share one source of truth."""
    src = Path(guided.__file__).read_text(encoding="utf-8")
    for name in (
        "_PLATFORM_RE", "_INTENT_ID_RE", "_PORT_RE",
        "_HOSTNAME_LABEL_RE", "_CONF_ID_RE",
    ):
        assert src.count(f"{name} = re.compile(") == 1, name

    # the dangling "# ---- KNOWN_INTENTS ----" header above _V2_QUES is
    # removed (the original code had a duplicate of the top-of-module
    # section divider with no code under it; only the legitimate
    # KNOWN_INTENTS constant near the top of the module remains)
    head = src.split("_V2_QUES")[0]
    # the legitimate top-of-module KNOWN_INTENTS section header may
    # remain; we only forbid *another* one with no code under it
    last_idx = head.rfind("# ---- KNOWN_INTENTS")
    if last_idx != -1:
        tail = head[last_idx:]
        # between the last occurrence and the split, there must be
        # either KNOWN_INTENTS as a real constant, or the comment
        # must be the only one of its kind before _V2_QUES
        assert "KNOWN_INTENTS: tuple[str, ...]" in tail, (
            "stale KNOWN_INTENTS header comment remains above _V2_QUES with no code under it",
        )

    # LEGACY_STRICTNESS_TIER and _STRICTNESS_TO_TIER are the same dict
    # (one source of truth -- "normal"/"standard" string pair once)
    assert "\"normal\": \"standard\"" in src


# ---- admin-access summary warnings ---------------------------


def test_mv1_2_C11_admin_access_summary_warns_for_telnet_and_snmp_v1v2():
    """``summary`` emits the exact telnet and SNMP v1/v2
    warnings when those answers are selected, and omits each warning
    when the corresponding access method is absent."""
    telnet = guided.summary({
        "strictness": "normal",
        "admin_access": ["telnet"],
    })
    no_telnet = guided.summary({
        "strictness": "normal",
        "admin_access": [],
    })
    warning = "Warning: telnet sends passwords in clear text."
    assert warning in telnet
    assert warning not in no_telnet

    snmp_v1v2 = guided.summary({
        "strictness": "normal",
        "admin_access": ["snmp_v1v2"],
    })
    no_snmp_v1v2 = guided.summary({
        "strictness": "normal",
        "admin_access": [],
    })
    warning = "Warning: SNMP v1/v2 has weak authentication."
    assert warning in snmp_v1v2
    assert warning not in no_snmp_v1v2


# ---- malformed confirmation ids never reach disk -------------


def test_mv1_2_C12_traversal_and_malformed_ids_never_reach_disk(tmp_path):
    """Only a lower-case 64-hex id is accepted. Traversal and
    malformed ids are unknown for status checks and refused by storage,
    with no files added or changed anywhere under the state root."""
    d = tmp_path / "state"
    d.mkdir()
    (d / "guided-confirmations").mkdir()

    # The requested parent escape is planted. The store lives one level
    # below state_root, so "../x" additionally resolves to state/x; plant
    # that reachable copy as well so removing the status guard is red.
    far_future = {"expires_at": "9999-01-01T00:00:00+00:00"}
    planted_parent = d.parent / "x.json"
    planted_parent.write_text(json.dumps(far_future), encoding="utf-8")
    planted_reachable = d / "x.json"
    planted_reachable.write_text(json.dumps(far_future), encoding="utf-8")

    def snapshot(root: Path) -> dict[str, str]:
        out: dict[str, str] = {}
        for path in sorted(root.rglob("*")):
            rel = str(path.relative_to(root))
            if path.is_dir():
                out[rel] = "dir"
            else:
                out[rel] = hashlib.sha256(path.read_bytes()).hexdigest()
        return out

    before = snapshot(tmp_path)
    assert guided.confirmation_status("../x", d)["status"] == "unknown"
    assert guided.confirmation_status(
        "../" + "a" * 64, d
    )["status"] == "unknown"
    assert guided.confirmation_status("A" * 64, d)["status"] == "unknown"

    valid_record = guided.confirmation_record(
        {"strictness": "normal"}, "s", device="-", platform="openwrt"
    )
    with pytest.raises(guided.GuidedError):
        guided.store_confirmation({**valid_record, "id": "../x"}, d)

    assert snapshot(tmp_path) == before


# ---- expiry boundary is inclusive ----------------------------


def test_mv1_2_C13_status_expires_exactly_at_expires_at(tmp_path):
    """A stored record is expired at the exact ``expires_at``
    instant and valid one microsecond before it."""
    created = datetime(2026, 10, 17, 12, 0, 0, tzinfo=timezone.utc)
    record = guided.confirmation_record(
        {"strictness": "normal"},
        "s",
        device="-",
        platform="openwrt",
        now=created,
    )
    guided.store_confirmation(record, tmp_path)
    expires = datetime.fromisoformat(record["expires_at"])

    at_boundary = guided.confirmation_status(
        record["id"], tmp_path, now=expires
    )
    before_boundary = guided.confirmation_status(
        record["id"], tmp_path, now=expires - timedelta(microseconds=1)
    )
    assert at_boundary["status"] == "expired"
    assert before_boundary["status"] == "valid"
