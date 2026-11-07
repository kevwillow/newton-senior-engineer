"""``reasons``, ``router_leash``, ``router_profile``, ``router_sections``
and ``router_requires_approval`` are part of the canonical plan identity.

These five fields are already on the stored plan record (the planner writes
them around server.py:1546-1553) and ``newton-approve`` already prints them
(approve.py:319, 472, 507-510), but they were NOT in ``PLAN_HASH_FIELDS``.
A hand-edit on a stored file therefore passed the hash check unchanged, so
approve and apply both accepted a record whose displayed risk reasons,
router profile / leash / sections or "router requires approval" flag had
been swapped out after the fact.  Editing any of them on disk must
invalidate the hash, and an old record without them must be refused too
(the standard ``canonical_plan_json`` missing-field path, no compatibility
branch).
"""

from __future__ import annotations

import copy
import io
import json
import subprocess
from pathlib import Path

import pytest

import newton_mcp.approve as approve
import newton_mcp.server as server
from exhelp import explained, record_fields
from newton_mcp.plan import PLAN_HASH_FIELDS, canonical_plan_json, compute_plan_hash


SID = "0123456789abcdef0123456789abcdef"
DIGEST = "d" * 64
BASE_HASH = "b" * 64

DISPLAY_FIELDS = (
    "reasons",
    "router_leash",
    "router_profile",
    "router_sections",
    "router_requires_approval",
)


# Plan output the staged-router stub returns.  ``APPROVAL required`` keeps
# the host policy honest (requires_approval stays True, so approve reaches
# the hash check rather than bailing on "nothing to approve" before a
# missing-field tampering can fail).  The first five test cases in this
# module (assertion + editing + canonical JSON) work with either;
# the missing-field cases need APPROVAL required.
PLAN_OUTPUT = (
    "BACKUP /tmp/skilltest.tar.gz (2 config files)\n"
    f"STAGED session={SID} from /tmp/changes.uci diff={'1' * 64}\n"
    f"BASEHASH {BASE_HASH}\n"
    f"PROBES 0 {'a' * 64}\n"
    "PROFILE lab\n"
    "LEASH wan-rule firewall.wan_rule.src\n"
    "SECTION dhcp skilltest host-reservation skilltest\n"
    "APPROVAL required\n"
    f"PLANDIGEST {DIGEST}\n"
    "----- diff -----\n"
    "dhcp.skilltest='host'\n"
    "dhcp.skilltest.name='skilltest'\n"
    "dhcp.skilltest.mac='02:00:00:00:00:99'\n"
    "dhcp.skilltest.ip='192.0.2.99'\n"
    "----------------\n"
)


# ---- shared fixture ----------------------------------------------------------


@pytest.fixture
def configured(tmp_path, monkeypatch):
    inventory = tmp_path / "devices.toml"
    inventory.write_text(
        '[devices.quasar]\nplatform = "openwrt"\nhost = "192.0.2.1"\nuser = "root"\n'
        'profile = "lab"\nlab = true\n'
    )
    inventory.chmod(0o644)
    monkeypatch.setenv("NEWTON_INVENTORY", str(inventory))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))
    return tmp_path


def _drive_planner(monkeypatch):
    """Stub ``NewtonService.run_script`` / ``read`` so a real
    ``newton_plan_change`` call returns the canned ``PLAN_OUTPUT`` and the
    planner writes a real record on disk carrying every display field."""
    captured: list[list] = []

    def fake_script(self, device, *args, **kwargs):
        captured.append(args)
        return subprocess.CompletedProcess(args, 0, PLAN_OUTPUT, "")

    def fake_read(self, device, command):
        return {"exit_code": 1, "stdout": "", "stderr": "", "truncated": False}

    monkeypatch.setattr(server.NewtonService, "run_script", fake_script)
    monkeypatch.setattr(server.NewtonService, "read", fake_read)
    return captured


def _write_record(configured, record):
    plans = configured / "state" / "plans"
    plans.mkdir(parents=True, exist_ok=True)
    (plans / f"{SID}.json").write_text(json.dumps(record))


# ---- (a) every display field is in PLAN_HASH_FIELDS --------------------------


@pytest.mark.parametrize("name", DISPLAY_FIELDS)
def test_display_field_is_in_plan_hash_fields(name):
    """``PLAN_HASH_FIELDS`` must list every display field; otherwise the
    canonical identity omits it and ``compute_plan_hash`` does not change
    when an attacker rewrites the field on disk."""
    assert name in PLAN_HASH_FIELDS


# ---- (b) editing a display field on disk is refused by approve and apply ----


def _make_real_record(configured, monkeypatch):
    """Run a real ``newton_plan_change`` so the on-disk record is whatever
    the planner writes (all five display fields included), then load it."""
    _drive_planner(monkeypatch)
    result = server.newton_plan_change(
        "quasar", "set dhcp.skilltest=host", **explained("set dhcp.skilltest=host"),
    )
    assert "error" not in result, result
    return json.loads((configured / "state" / "plans" / f"{SID}.json").read_text())


def test_real_plan_call_writes_every_display_field(configured, monkeypatch):
    """Sanity: the planner itself stamps every display field on disk, so
    a test that re-hashes what the planner wrote does not need to inject
    defaults by hand.  Keeps the helpers in this module honest -- if
    planner output silently drops a field, this fails first."""
    record = _make_real_record(configured, monkeypatch)
    for name in DISPLAY_FIELDS:
        assert name in record, name


def test_editing_a_display_field_changes_the_plan_hash(configured, monkeypatch):
    """For each display field, two records identical except for that field
    must produce different hashes -- the field is now part of the
    canonical identity."""
    record = _make_real_record(configured, monkeypatch)
    base = record["plan_hash"]
    tampered = copy.deepcopy(record)
    tampered["reasons"] = ["forged reason the operator never saw"]
    assert compute_plan_hash(tampered) != base
    tampered = copy.deepcopy(record)
    tampered["router_leash"] = ["forged-leash-code"]
    assert compute_plan_hash(tampered) != base
    tampered = copy.deepcopy(record)
    tampered["router_profile"] = "prod"  # the canned plan is "lab"; flip it
    assert compute_plan_hash(tampered) != base
    tampered = copy.deepcopy(record)
    tampered["router_sections"] = ["forged section"]
    assert compute_plan_hash(tampered) != base
    tampered = copy.deepcopy(record)
    # The canned plan already stamps router_requires_approval=True; toggle to False.
    tampered["router_requires_approval"] = False
    assert compute_plan_hash(tampered) != base


def test_canonical_plan_json_requires_every_display_field(configured, monkeypatch):
    """``canonical_plan_json`` refuses a record that lacks one of the five
    display fields -- the existing missing-field ``ValueError`` every
    caller already turns into ``"plan record was modified or is invalid"``."""
    record = _make_real_record(configured, monkeypatch)
    for name in DISPLAY_FIELDS:
        dropped = copy.deepcopy(record)
        del dropped[name]
        with pytest.raises(ValueError):
            canonical_plan_json(dropped)


def test_apply_refuses_a_record_with_an_edited_display_field(configured, monkeypatch):
    """Apply path: a stored plan_hash was computed with the ORIGINAL
    display field value; rewriting the field on disk leaves the stored
    hash unchanged, so apply's hash compare fails and the standard
    "plan record was modified or is invalid" refusal is returned.

    Drives a real plan call, then tampers the persisted record with the
    same display-field edits above; run_script must not be called for any
    of them."""
    record = _make_real_record(configured, monkeypatch)

    class TTYStringIO(io.StringIO):
        def isatty(self):
            return True

    monkeypatch.setattr(approve.sys, "stdin", TTYStringIO(f"approve {SID[:8]}\n"))
    monkeypatch.setattr(
        approve, "_getpass", lambda prompt: pytest.fail("getpass must not run"),
    )

    # The canned plan already stamps ``router_requires_approval=True``; flipping
    # to False swaps what the operator is shown (router said no but record says yes).
    for name, tampered_value in (
        ("reasons", ["forged reason the operator never saw"]),
        ("router_leash", ["forged-leash-code"]),
        ("router_profile", "prod"),
        ("router_sections", ["forged section"]),
        ("router_requires_approval", False),
    ):
        tampered = copy.deepcopy(record)
        tampered[name] = tampered_value
        _write_record(configured, tampered)

        calls: list = []
        monkeypatch.setattr(
            server.NewtonService, "run_script",
            lambda *a, calls_=calls, **k: (
                calls_.append(a) or subprocess.CompletedProcess(a, 0, f"CONFIRMED session={SID}", "")
            ),
        )
        result = server.newton_apply_change("quasar", SID)
        assert "plan record was modified or is invalid" in result["error"], (name, result)
        assert calls == [], f"apply reached the router after editing {name}"


def test_approve_refuses_a_record_with_an_edited_display_field(
    configured, monkeypatch, capsys
):
    """Approve path: ``_load_plan`` recomputes the hash with the new
    ``PLAN_HASH_FIELDS`` and sees the stored ``plan_hash`` does not match.
    ``ValueError`` is raised, the CLI prints the standard refusal, and
    no approval file is written."""
    record = _make_real_record(configured, monkeypatch)

    class TTYStringIO(io.StringIO):
        def isatty(self):
            return True

    monkeypatch.setattr(approve.sys, "stdin", TTYStringIO(f"approve {SID[:8]}\n"))
    monkeypatch.setattr(
        approve, "_getpass", lambda prompt: pytest.fail("getpass must not run"),
    )

    # The canned plan already stamps ``router_requires_approval=True``; flipping
    # to False swaps what the operator is shown (router said no but record says yes).
    for name, tampered_value in (
        ("reasons", ["forged reason the operator never saw"]),
        ("router_leash", ["forged-leash-code"]),
        ("router_profile", "prod"),
        ("router_sections", ["forged section"]),
        ("router_requires_approval", False),
    ):
        tampered = copy.deepcopy(record)
        tampered[name] = tampered_value
        _write_record(configured, tampered)

        result = approve.main([SID])
        out = capsys.readouterr()
        assert result == 1, (name, out)
        assert "plan record was modified or is invalid" in out.err, (name, out)
        assert not (configured / "state" / "approvals" / f"{SID}.json").exists(), name


# ---- (c) a record missing the field is refused the same way -----------------


def test_apply_refuses_an_old_record_missing_a_display_field(configured, monkeypatch):
    """An old plan record was written without one of the five
    display fields.  ``canonical_plan_json`` raises ``ValueError``; apply
    turns that into the standard refusal.  No compatibility path."""
    record = _make_real_record(configured, monkeypatch)

    for name in DISPLAY_FIELDS:
        old = copy.deepcopy(record)
        # stored plan_hash was computed under the legacy field set
        legacy_hash = compute_plan_hash({**old, name: __default_for(name)})
        old["plan_hash"] = legacy_hash
        del old[name]
        _write_record(configured, old)

        calls: list = []
        monkeypatch.setattr(
            server.NewtonService, "run_script",
            lambda *a, calls_=calls, **k: (
                calls_.append(a) or subprocess.CompletedProcess(a, 0, f"CONFIRMED session={SID}", "")
            ),
        )
        result = server.newton_apply_change("quasar", SID)
        assert "plan record was modified or is invalid" in result["error"], (name, result)


def test_approve_refuses_an_old_record_missing_a_display_field(
    configured, monkeypatch, capsys
):
    """Same for ``newton-approve``: an old record raises the same
    ``ValueError`` during ``_load_plan``, prints the standard refusal and
    refuses without an approval file."""
    record = _make_real_record(configured, monkeypatch)

    class TTYStringIO(io.StringIO):
        def isatty(self):
            return True

    monkeypatch.setattr(approve.sys, "stdin", TTYStringIO(f"approve {SID[:8]}\n"))
    monkeypatch.setattr(
        approve, "_getpass", lambda prompt: pytest.fail("getpass must not run"),
    )

    for name in DISPLAY_FIELDS:
        old = copy.deepcopy(record)
        legacy_hash = compute_plan_hash({**old, name: __default_for(name)})
        old["plan_hash"] = legacy_hash
        del old[name]
        _write_record(configured, old)

        assert approve.main([SID]) == 1
        out = capsys.readouterr()
        assert "plan record was modified or is invalid" in out.err, (name, out)
        assert not (configured / "state" / "approvals" / f"{SID}.json").exists(), name


# ---- helper ---------------------------------------------------------------


def __default_for(name):
    """A realistic default for each display field, so the legacy hash
    computation in the missing-field tests matches what a toolchain of the
    day would have produced.  ``reasons`` is the typical reason list a
    router-side required approval would stamp; the router fields match the
    canned ``PLAN_OUTPUT`` (``APPROVAL required``)."""
    if name == "reasons":
        return ["profile 'prod': every write requires approval"]
    if name == "router_leash":
        return ["wan-rule firewall.wan_rule.src"]
    if name == "router_profile":
        return "lab"
    if name == "router_sections":
        return ["dhcp skilltest host-reservation skilltest"]
    if name == "router_requires_approval":
        return True
    raise AssertionError(name)
