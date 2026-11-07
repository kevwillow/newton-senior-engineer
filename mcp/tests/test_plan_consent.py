"""A plan inside a live grant skips the owner's chat yes.

The owner's scoped grant IS the consent for a change the
grant covers, so the agent does not have to ask for a second yes in the
chat for every change of a kind the owner already allowed.  The plan
records WHERE the consent came from (``consent_basis``) and how risky the
plan is (``risk``); the apply path and ``newton-approve`` both accept a
waived record.

The grant only ever waives the CHAT yes.  The explanation is still
required, a HIGH change is never covered, a change the grant does not
cover still needs the owner in the chat, and a plan the policy calls
critical is never waived.

Everything here is synthetic: the approval key and the passphrase are
literals in this file, and no device is contacted (the router is faked at
``run_script``).
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import io
import json
import subprocess
import time
from datetime import datetime, timedelta, timezone

import pytest

import newton_mcp.approve as approve
import newton_mcp.server as server
from exhelp import make_explanation
from newton_mcp import grants
from newton_mcp.plan import compute_plan_hash
from test_approve import plan_record


SID = "0123456789abcdef0123456789abcdef"
BASE = "b" * 64
DIGEST = "d" * 64
DEVICE = "quasar"
K_HEX = "ab" * 32
GRANT_CLASS = "dhcp-reservations"
ALL_CLASSES = ("dhcp-reservations", "dns", "hostname", "wifi-name-key")

BATCH = "set dhcp.skilltest=host\nset dhcp.skilltest.name='skilltest'"
UNCOVERED_BATCH = BATCH + "\nset dhcp.skilltest.uid='1000'"
HIGH_BATCH = "set dropbear.@dropbear[0].Port=22"

# A diff the policy calls critical: a firewall zone change the diff does
# not identify may be the wan zone (or the management zone).
CRITICAL_DIFF = [
    "dhcp.skilltest='host'",
    "dhcp.skilltest.name='skilltest'",
    "firewall.@zone[1].input='ACCEPT'",
]

# The hash of the record ``test_approve.plan_record`` builds, pinned so a
# change to the canonical payload of an old-style record (one written
# before this field existed, with no ``consent_basis`` key) is caught here.
OLD_STYLE_HASH = "98b13855f43cd0934f6ba8a42ed932f0ec71db3f1ca5b6bd48c25812455e3169"

INVENTORY = """\
[devices.quasar]
platform = "openwrt"
host = "192.0.2.1"
user = "root"
"""


class TerminalInput(io.StringIO):
    def isatty(self):
        return True


def plan_output(diff=None):
    lines = diff or ["dhcp.skilltest='host'", "dhcp.skilltest.name='skilltest'"]
    return (
        "BACKUP /tmp/fake.tar.gz (2 config files)\n"
        f"STAGED session={SID}\n"
        f"BASEHASH {BASE}\n"
        f"PROBES 0 {'a' * 64}\n"
        "PROFILE lab\n"
        "SECTION dhcp skilltest host skilltest\n"
        "APPROVAL required\n"
        f"PLANDIGEST {DIGEST}\n"
        "----- diff -----\n"
        + "\n".join(lines)
        + "\n"
        "----------------\n"
    )


@pytest.fixture
def env(tmp_path, monkeypatch):
    inventory = tmp_path / "devices.toml"
    inventory.write_text(INVENTORY)
    monkeypatch.setenv("NEWTON_INVENTORY", str(inventory))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))
    calls = []

    def fake(self, device, *args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, plan_output(), "")

    monkeypatch.setattr(server.NewtonService, "run_script", fake)
    return tmp_path, calls


def plan_call(batch=BATCH, **kwargs):
    kwargs.setdefault("explanation", make_explanation(batch))
    return server.newton_plan_change(DEVICE, batch, **kwargs)


def stored(tmp_path):
    return json.loads((tmp_path / "state" / "plans" / f"{SID}.json").read_text())


def plans_dir(tmp_path):
    return tmp_path / "state" / "plans"


def no_plan_written(tmp_path):
    directory = plans_dir(tmp_path)
    return not directory.exists() or not list(directory.glob("*.json"))


def _open_grant(*, classes=(GRANT_CLASS,), hours=4, now=None):
    """Open the owner's grant on the device the plan names."""
    grants.open_grant(DEVICE, list(classes), hours, K_HEX, SID, now=now)


def _write_approval(tmp_path, record):
    approvals = tmp_path / "state" / "approvals"
    approvals.mkdir(parents=True, exist_ok=True)
    created = datetime.now(timezone.utc)
    expires = created + timedelta(minutes=20)
    (approvals / f"{SID}.json").write_text(json.dumps({
        "plan_id": SID,
        "plan_hash": record["plan_hash"],
        "device": DEVICE,
        "base_hash": record["base_hash"],
        "approved_by": "operator",
        "created_at": created.isoformat(),
        "expires_at": expires.isoformat(),
        "not_before": int(created.timestamp()),
        "not_after": int(expires.timestamp()),
        "token": "e" * 64,
    }))


def _write_fingerprint(state, device, k_hex):
    """Seed state/approval-fp/<device> with the fingerprint of *k_hex*."""
    fingerprint = hmac.new(
        bytes.fromhex(k_hex),
        b"newton-approval-fingerprint-v1",
        hashlib.sha256,
    ).hexdigest()
    directory = state / "approval-fp"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / device).write_text(f"v1 {fingerprint}\n")


# ---- the waived plan ----------------------------------------------------------


def test_a_plan_inside_a_live_grant_needs_no_chat_yes(env):
    tmp, calls = env
    _open_grant()

    result = plan_call()

    assert "error" not in result, result
    assert calls
    record = stored(tmp)
    assert record["owner_confirmed_in_chat"] is False
    assert record["consent_basis"] == "grant"
    assert record["risk"] == "low"
    assert record["plan_hash"] == compute_plan_hash(record)
    assert result["consent_basis"] == "grant"
    # the grant waives the CHAT yes only: the change still needs the
    # owner's out-of-band approval, where a human reads the diff.
    assert record["requires_approval"] is True


def test_the_same_plan_without_a_grant_asks_the_owner_in_chat(env):
    tmp, calls = env

    result = plan_call()

    assert "owner_confirmed_in_chat must be true" in result["error"]
    assert calls == []
    assert no_plan_written(tmp)


def test_a_waived_plan_still_needs_an_explanation(env):
    tmp, calls = env
    _open_grant()

    result = plan_call(explanation=None)

    assert "explanation is required" in result["error"]
    assert calls == []
    assert no_plan_written(tmp)


def test_a_plan_the_owner_confirmed_in_chat_carries_no_consent_basis(env):
    tmp, _ = env

    result = plan_call(owner_confirmed_in_chat=True)

    assert "error" not in result, result
    record = stored(tmp)
    assert record["owner_confirmed_in_chat"] is True
    assert "consent_basis" not in record
    assert record["risk"] == "low"
    assert result["consent_basis"] == "chat"


def test_a_chat_confirmed_plan_is_not_waived_even_under_a_grant(env):
    tmp, _ = env
    _open_grant()

    result = plan_call(owner_confirmed_in_chat=True)

    assert "error" not in result, result
    record = stored(tmp)
    assert record["owner_confirmed_in_chat"] is True
    assert "consent_basis" not in record
    assert result["consent_basis"] == "chat"


# ---- what a grant never waives ------------------------------------------------


def test_a_change_the_grant_does_not_cover_is_refused(env):
    tmp, calls = env
    _open_grant()

    result = plan_call(batch=UNCOVERED_BATCH)

    assert "owner_confirmed_in_chat must be true" in result["error"]
    assert calls == []
    assert no_plan_written(tmp)


def test_a_high_change_is_refused_even_under_the_widest_grant(env):
    tmp, calls = env
    _open_grant(classes=ALL_CLASSES)

    result = plan_call(batch=HIGH_BATCH)

    assert "owner_confirmed_in_chat must be true" in result["error"]
    assert calls == []
    assert no_plan_written(tmp)


def test_an_expired_grant_does_not_waive_the_chat_yes(env):
    tmp, calls = env
    _open_grant(hours=1, now=time.time() - 7200)

    result = plan_call()

    assert "owner_confirmed_in_chat must be true" in result["error"]
    assert calls == []
    assert no_plan_written(tmp)


def test_the_grant_skips_chat_flag_can_be_turned_off(env, monkeypatch):
    tmp, calls = env
    _open_grant()
    monkeypatch.setenv("NEWTON_GRANT_SKIPS_CHAT", "0")

    result = plan_call()

    assert "owner_confirmed_in_chat must be true" in result["error"]
    assert calls == []
    assert no_plan_written(tmp)


def test_a_critical_plan_under_a_grant_is_refused(env, monkeypatch):
    tmp, _ = env
    _open_grant()
    monkeypatch.setattr(
        server.NewtonService,
        "run_script",
        lambda self, device, *a, **k: subprocess.CompletedProcess(
            a, 0, plan_output(diff=CRITICAL_DIFF), ""
        ),
    )

    result = plan_call()

    assert "owner_confirmed_in_chat must be true" in result["error"]
    assert no_plan_written(tmp)


# ---- the identity -------------------------------------------------------------


def test_editing_the_consent_basis_on_disk_breaks_the_hash(env):
    tmp, _ = env
    _open_grant()
    assert "error" not in plan_call()
    record = stored(tmp)
    before = record["plan_hash"]

    tampered = copy.deepcopy(record)
    tampered["consent_basis"] = "chat"

    assert compute_plan_hash(tampered) != before


def test_apply_refuses_a_record_whose_consent_basis_was_edited(env, monkeypatch):
    tmp, calls = env
    _open_grant()
    assert "error" not in plan_call()
    record = stored(tmp)
    tampered = copy.deepcopy(record)
    tampered["consent_basis"] = "chat"
    (plans_dir(tmp) / f"{SID}.json").write_text(json.dumps(tampered))
    calls.clear()

    result = server.newton_apply_change(DEVICE, SID)

    assert "plan record was modified or is invalid" in result["error"]
    assert calls == []


def test_an_old_style_record_still_hashes_identically():
    """A record written before this field existed carries no ``consent_basis``
    key, and its canonical payload must not grow: the hash of every
    record already on disk stays the hash it was written with."""
    record = plan_record(staged_at="2026-10-07T12:00:00+00:00")

    assert "consent_basis" not in record
    assert compute_plan_hash(record) == OLD_STYLE_HASH


def test_the_consent_basis_is_part_of_the_identity_when_it_is_there():
    record = plan_record(staged_at="2026-10-07T12:00:00+00:00")

    with_basis = {**record, "consent_basis": "grant"}

    assert compute_plan_hash(with_basis) != compute_plan_hash(record)


# ---- apply and approve --------------------------------------------------------


def test_apply_accepts_a_waived_record(env, monkeypatch):
    tmp, calls = env
    _open_grant()
    assert "error" not in plan_call()
    record = stored(tmp)
    _write_approval(tmp, record)

    def fake_apply(self, device, *args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, f"CONFIRMED session={SID}", "")

    monkeypatch.setattr(server.NewtonService, "run_script", fake_apply)
    calls.clear()

    result = server.newton_apply_change(DEVICE, SID)

    assert result.get("result") == "confirmed", result
    assert calls


def test_newton_approve_accepts_a_waived_record(env, monkeypatch, capsys):
    tmp, _ = env
    _open_grant()
    assert "error" not in plan_call()
    state = tmp / "state"
    passphrase = "made-up-waived-pass"
    k = approve.derive_k(passphrase.encode("utf-8"), DEVICE)
    _write_fingerprint(state, DEVICE, k)
    monkeypatch.setattr(approve, "_getpass", lambda prompt: passphrase)
    monkeypatch.setattr(approve.sys, "stdin", TerminalInput(f"approve {SID[:8]}\n"))

    assert approve.main([SID]) == 0

    out = capsys.readouterr()
    assert "Approved plan" in out.out, out
    assert (state / "approvals" / f"{SID}.json").exists()


def test_newton_approve_still_refuses_a_record_with_neither_consent(env, monkeypatch, capsys):
    """A record with no chat yes and no grant is refused as before."""
    tmp, _ = env
    assert "error" not in plan_call(owner_confirmed_in_chat=True)
    record = stored(tmp)
    record["owner_confirmed_in_chat"] = False
    record["plan_hash"] = compute_plan_hash(record)
    (plans_dir(tmp) / f"{SID}.json").write_text(json.dumps(record))
    monkeypatch.setattr(approve.sys, "stdin", TerminalInput(f"approve {SID[:8]}\n"))
    monkeypatch.setattr(
        approve, "_getpass", lambda prompt: pytest.fail("getpass must not run")
    )

    assert approve.main([SID]) == 1

    out = capsys.readouterr()
    assert "does not say the owner confirmed in chat" in out.err, out
    assert not (tmp / "state" / "approvals" / f"{SID}.json").exists()
