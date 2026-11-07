"""SECRET-LEAK-LITE-1: the audit line for a plan's explanation carries no free-form
explanation text.  ``explanation.py`` redaction only catches ``name=value`` forms,
so a secret inside prose such as "the wifi key is superSecret-9af3" survives
into the intent field, and so into the audit line, the plan file, and the plan
hash.  We do not try to detect secrets in prose: the audit line just carries
``intent_len=<n>`` and ``intent_sha256=<12 hex>`` and no text, no steps, no risk.

The plan file and the approve screen still show the full explanation.
"""

from __future__ import annotations

import hashlib
import json
import subprocess

import pytest

import newton_mcp.server as server
from exhelp import explained
from newton_mcp.plan import compute_plan_hash

SID = "0123456789abcdef0123456789abcdef"
BASE = "b" * 64
DIGEST = "d" * 64
BATCH = "set dhcp.skilltest=host\nset dhcp.skilltest.name='skilltest'"
INVENTORY = """\
[devices.quasar]
platform = "openwrt"
host = "192.0.2.1"
user = "root"

[devices.labplain]
platform = "openwrt"
host = "192.0.2.2"
user = "root"
profile = "lab"

[devices.lab1]
platform = "openwrt"
host = "192.0.2.3"
user = "root"
profile = "lab"
lab = true
"""

INTENT_TEXT = "the wifi key is superSecret-9af3 for guests"
STEP_MARKER = "stepMarkerXYZZY-7c3a"
RISK_MARKER = "riskMarkerWYSIQ-41df"


def plan_output():
    return (
        "BACKUP /tmp/fake.tar.gz (2 config files)\n"
        f"STAGED session={SID}\n"
        f"BASEHASH {BASE}\n"
        f"PROBES 0 {'a' * 64}\n"
        "PROFILE lab\n"
        f"SECTION dhcp skilltest host skilltest\n"
        "APPROVAL not-required\n"
        f"PLANDIGEST {DIGEST}\n"
        "----- diff -----\n"
        "dhcp.skilltest='host'\n"
        "dhcp.skilltest.name='skilltest'\n"
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


def plan_call(device="quasar", batch=BATCH, **kw):
    return server.newton_plan_change(device, batch, **kw)


def stored(tmp_path):
    return json.loads((tmp_path / "state" / "plans" / f"{SID}.json").read_text())


def audit_log(tmp_path):
    return (tmp_path / "state" / "mcp-audit.log").read_text()


def expected_sha12(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]


def test_audit_line_carries_intent_len_and_short_hash_and_no_text(env):
    tmp, _ = env
    result = plan_call(
        **explained(
            BATCH,
            intent=INTENT_TEXT,
            steps=[
                f"Apply host entry {STEP_MARKER} for the printer",
                f"Apply host name {STEP_MARKER} for the printer",
            ],
            risk=f"A wrong value would expose {RISK_MARKER} on the guest network.",
        )
    )
    assert "error" not in result, result

    log = audit_log(tmp)

    for forbidden in (
        "superSecret-9af3",
        STEP_MARKER,
        RISK_MARKER,
        "wifi",
        "key",
        "is",
        "for",
        "guests",
    ):
        assert forbidden not in log, f"audit log leaked {forbidden!r}"

    assert f"session={SID}" in log
    assert f"intent_len={len(INTENT_TEXT)}" in log
    assert f"intent_sha256={expected_sha12(INTENT_TEXT)}" in log
    assert "intent=" not in log
    assert "\x1b" not in log


def test_stored_plan_file_and_plan_hash_are_unchanged_by_the_fix(env):
    tmp, _ = env
    explanation = {
        "intent": INTENT_TEXT,
        "steps": [
            f"Apply host entry {STEP_MARKER} for the printer",
            f"Apply host name {STEP_MARKER} for the printer",
        ],
        "expect": [{"kind": "probe", "probe": ["iface-absent", "guestx"]}],
        "risk": f"A wrong value would expose {RISK_MARKER} on the guest network.",
    }
    kwargs = {"explanation": explanation, "owner_confirmed_in_chat": True}

    result = plan_call(**kwargs)
    assert "error" not in result, result

    record = stored(tmp)
    assert record["explanation"] == explanation
    assert set(record["explanation"]) == {"intent", "steps", "expect", "risk"}
    assert record["owner_confirmed_in_chat"] is True

    recomputed = compute_plan_hash(record)
    assert recomputed == record["plan_hash"]
