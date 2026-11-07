"""Server wiring for client-vantage outcome checks.

These tests cover the plan and apply paths that carry client claims from the
agent's explanation to the registered inside vantage.  Every device and
vantage is synthetic and every subprocess is stubbed.
"""

from __future__ import annotations

import json
import re
import stat
import subprocess
from pathlib import Path

import pytest

from exhelp import make_explanation, record_fields_display

from newton_mcp import client_checks as cc
from newton_mcp import explanation as ex
from newton_mcp import server
from newton_mcp.plan import compute_plan_hash


SID = "fd595e20f2cd6c2b928fe3156f82d5db"
BATCH = "set dhcp.skilltest=host"
BASE_HASH = "8" * 64
ROUTER_DIGEST = "3" * 64
PROBES_SHA = "1" * 64
C_DNS = {"kind": "client_dns", "zone": "guest"}
C_BLOCKED = {"kind": "client_blocked", "zone": "guest", "to": "router"}
DUMP = {
    "interface": [
        {
            "interface": "guest",
            "up": True,
            "ipv4-address": [{"address": "10.0.0.1", "mask": 8}],
        }
    ]
}
PLAN_OUTPUT = f"""BACKUP /tmp/newton-backup.tar.gz (2 config files)
STAGED session={SID} from f
BASEHASH {BASE_HASH}
PROBES 0 {PROBES_SHA}
PROFILE lab
APPROVAL not-required
PLANDIGEST {ROUTER_DIGEST}
----- diff -----
dhcp.skilltest='host'
----------------
"""


def write_inventory(
    tmp_path,
    monkeypatch,
    *,
    zones=(("guest", "192.0.2.50"),),
    role="inside",
    include_vantage=True,
):
    key = tmp_path / "scan.key"
    key.write_text("synthetic-key", encoding="utf-8")
    key.chmod(0o600)
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("synthetic host key\n", encoding="utf-8")
    inventory = tmp_path / "devices.toml"
    lines = [
        '[devices.quasar]',
        'platform = "openwrt"',
        'host = "192.0.2.1"',
        'user = "root"',
        'profile = "lab"',
        'lab = true',
    ]
    if include_vantage:
        lines.extend(
            [
                "",
                "[vantages.inside-a]",
                'host = "vantage.example.invalid"',
                'user = "newton"',
                f'key_file = "{key}"',
                f'known_hosts = "{known_hosts}"',
                f'role = "{role}"',
                'devices = ["quasar"]',
                "zones = [",
            ]
        )
        for name, src in zones:
            lines.append(
                f'  {{ name = "{name}", src = "{src}", canary = "192.0.2.1:53" }},'
            )
        lines.append("]")
    inventory.write_text("\n".join(lines) + "\n", encoding="utf-8")
    monkeypatch.setenv("NEWTON_INVENTORY", str(inventory))
    return inventory


def write_script_directory(tmp_path, monkeypatch, *, with_runner=True):
    home = tmp_path / "newton-home"
    scripts = home / "scripts"
    scripts.mkdir(parents=True)
    change = scripts / "owrt-change.sh"
    change.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    change.chmod(0o755)
    runner = scripts / "newton-vantage-run"
    if with_runner:
        runner.write_text("#!/usr/bin/env python3\nexit 0\n", encoding="utf-8")
        runner.chmod(0o755)
    monkeypatch.setenv("NEWTON_HOME", str(home))
    return scripts


def dump_result():
    return {
        "exit_code": 0,
        "stdout": {
            "kind": "untrusted-device-data",
            "source": "quasar:ubus call network.interface dump",
            "text": json.dumps(DUMP),
        },
        "stderr": {
            "kind": "untrusted-device-data",
            "source": "quasar:ubus call network.interface dump",
            "text": "",
        },
        "truncated": False,
    }


def client_plan(service, expect, *, timeout_s=180):
    explanation = make_explanation(BATCH, expect=expect)
    return service.plan(
        "quasar",
        BATCH,
        timeout_s=timeout_s,
        explanation=explanation,
        owner_confirmed_in_chat=True,
    )


def stored_explanation(expect):
    raw = make_explanation(BATCH, expect=expect)
    if raw["expect"] and raw["expect"][0].get("kind") == "client_blocked":
        raw["expect"][0]["targets"] = [
            "10.0.0.1:22",
            "10.0.0.1:443",
            "10.0.0.1:80",
        ]
    return ex.parse_explanation(raw, change_lines=1, allow_targets=True)


def client_record(*, expect=None, requires_approval=False):
    expect = expect if expect is not None else [C_DNS]
    record = {
        "device": "quasar",
        "host": "192.0.2.1",
        "session_id": SID,
        "uci_batch": BATCH,
        "diff": "dhcp.skilltest='host'",
        "probes": [],
        "timeout_s": 180,
        "base_hash": BASE_HASH,
        "requires_approval": requires_approval,
        "router_digest": ROUTER_DIGEST,
        "explanation": stored_explanation(expect),
        "owner_confirmed_in_chat": True,
        "created_at": "2026-10-25T09:00:00+00:00",
        "staged_at": "2026-10-25T09:00:00+00:00",
        **record_fields_display(),
    }
    record["reasons"] = []
    record["plan_hash"] = compute_plan_hash(record)
    return record


def write_plan(tmp_path, record):
    directory = tmp_path / "state" / "plans"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{SID}.json"
    path.write_text(json.dumps(record), encoding="utf-8")
    return path


def write_approval(tmp_path, record):
    directory = tmp_path / "state" / "approvals"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{SID}.json"
    approval = {
        "plan_id": SID,
        "plan_hash": record["plan_hash"],
        "device": record["device"],
        "base_hash": record["base_hash"],
        "approved_by": "operator",
        "created_at": "2100-01-01T00:00:00+00:00",
        "expires_at": "2100-01-01T00:30:00+00:00",
        "not_before": 4102444800,
        "not_after": 4102446600,
        "token": "e" * 64,
    }
    path.write_text(json.dumps(approval), encoding="utf-8")
    return path


def local_check_log(word="no-answer"):
    return "\n".join(
        [
            f"APPLYING session={SID}",
            f"VERIFY FAILED session={SID} - not confirming; waiting for automatic rollback",
            f"VERIFY DETAIL session={SID} round=3 exit=1 stage=local-check "
            "(last failed round; stderr and stdout follow, each last 20 lines, at most 2 KB)",
            f"VERIFY STDERR session={SID}: vantage-check: claim 1 FAIL {word}",
            f"ROLLBACK WINDOW PASSED session={SID} rolled back by the guard",
        ]
    ) + "\n"


def test_vc05_01_client_claim_without_a_registered_vantage_is_refused_before_contact(
    tmp_path, monkeypatch
):
    write_inventory(tmp_path, monkeypatch, include_vantage=False)
    monkeypatch.setattr(
        server.NewtonService,
        "run_script",
        lambda *args, **kwargs: pytest.fail("must not run the change script"),
    )
    monkeypatch.setattr(
        server.NewtonService,
        "read",
        lambda *args, **kwargs: pytest.fail("must not contact the router"),
    )
    monkeypatch.setattr(
        server.NewtonService,
        "_refuse_failing_fw4",
        lambda *args, **kwargs: pytest.fail("must resolve the vantage first"),
    )
    with pytest.raises(server.NewtonError, match="no inside vantage serves zone guest"):
        client_plan(server.NewtonService(), [C_DNS])


def test_vc05_02_client_claim_below_the_minimum_timeout_is_refused(
    tmp_path, monkeypatch
):
    write_inventory(tmp_path, monkeypatch)
    monkeypatch.setattr(
        server.NewtonService,
        "run_script",
        lambda *args, **kwargs: pytest.fail("must not run the change script"),
    )
    with pytest.raises(server.NewtonError, match="timeout_s.*150"):
        client_plan(server.NewtonService(), [C_DNS], timeout_s=90)


def test_vc05_03_agent_supplied_targets_are_refused(tmp_path, monkeypatch):
    write_inventory(tmp_path, monkeypatch)
    monkeypatch.setattr(
        server.NewtonService,
        "run_script",
        lambda *args, **kwargs: pytest.fail("must not run the change script"),
    )
    explanation = make_explanation(
        BATCH,
        expect=[
            {
                "kind": "client_blocked",
                "zone": "guest",
                "to": "router",
                "targets": ["10.0.0.1:22"],
            }
        ],
    )
    with pytest.raises(server.NewtonError, match="targets are derived by Newton"):
        server.NewtonService().plan(
            "quasar",
            BATCH,
            timeout_s=180,
            explanation=explanation,
            owner_confirmed_in_chat=True,
        )


def test_vc05_04_an_outside_vantage_cannot_serve_a_client_claim(
    tmp_path, monkeypatch
):
    write_inventory(tmp_path, monkeypatch, role="outside")
    monkeypatch.setattr(
        server.NewtonService,
        "run_script",
        lambda *args, **kwargs: pytest.fail("must not run the change script"),
    )
    with pytest.raises(server.NewtonError, match="no inside vantage serves zone guest"):
        client_plan(server.NewtonService(), [C_DNS])


def test_vc05_05_router_block_targets_are_derived_and_stored(tmp_path, monkeypatch):
    write_inventory(tmp_path, monkeypatch)
    reads = []
    monkeypatch.setattr(
        server.NewtonService,
        "run_script",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            [], 0, PLAN_OUTPUT, ""
        ),
    )
    monkeypatch.setattr(
        server.NewtonService,
        "read",
        lambda self, device, command: reads.append(command) or dump_result(),
    )
    planned = client_plan(server.NewtonService(), [C_BLOCKED])
    record = json.loads(
        (tmp_path / "state" / "plans" / f"{SID}.json").read_text(encoding="utf-8")
    )
    claim = record["explanation"]["expect"][0]
    assert claim["targets"] == [
        "10.0.0.1:22",
        "10.0.0.1:443",
        "10.0.0.1:80",
    ]
    assert reads == ["ubus call network.interface dump"]
    assert record["plan_hash"] == planned["plan_hash"]
    assert record["plan_hash"] == compute_plan_hash(record)
    reparsed = ex.parse_explanation(
        record["explanation"], change_lines=1, allow_targets=True
    )
    assert reparsed == record["explanation"]


def test_vc05_06_a_changed_client_zone_changes_the_stored_plan_hash(
    tmp_path, monkeypatch
):
    write_inventory(
        tmp_path,
        monkeypatch,
        zones=(("guest", "192.0.2.50"), ("lounge", "192.0.2.51")),
    )
    monkeypatch.setattr(
        server.NewtonService,
        "run_script",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            [], 0, PLAN_OUTPUT, ""
        ),
    )
    service = server.NewtonService()
    first = client_plan(service, [{"kind": "client_dns", "zone": "guest"}])
    first_record = json.loads(
        (tmp_path / "state" / "plans" / f"{SID}.json").read_text(encoding="utf-8")
    )
    second = client_plan(service, [{"kind": "client_dns", "zone": "lounge"}])
    second_record = json.loads(
        (tmp_path / "state" / "plans" / f"{SID}.json").read_text(encoding="utf-8")
    )
    assert first["plan_hash"] != second["plan_hash"]
    assert first_record["explanation"]["expect"][0]["zone"] == "guest"
    assert second_record["explanation"]["expect"][0]["zone"] == "lounge"
    assert second_record["plan_hash"] == compute_plan_hash(second_record)
    assert ex.parse_explanation(
        second_record["explanation"], change_lines=1, allow_targets=True
    ) == second_record["explanation"]


def test_vc04_01_apply_sets_the_local_check_and_spec_environment(
    tmp_path, monkeypatch
):
    write_inventory(tmp_path, monkeypatch)
    scripts = write_script_directory(tmp_path, monkeypatch)
    monkeypatch.delenv("OWRT_LOCAL_CHECK", raising=False)
    monkeypatch.delenv("NEWTON_VANTAGE_SPEC_DIR", raising=False)
    record = client_record()
    write_plan(tmp_path, record)
    seen = {}

    def fake_run(self, device, *args, **kwargs):
        env = self.script_env(device)
        if kwargs.get("extra_env"):
            env.update(kwargs["extra_env"])
        seen["env"] = env
        spec = Path(env["NEWTON_VANTAGE_SPEC_DIR"]) / f"{SID}.json"
        seen["spec"] = spec
        seen["mode"] = stat.S_IMODE(spec.stat().st_mode)
        seen["content"] = json.loads(spec.read_text(encoding="utf-8"))
        return subprocess.CompletedProcess(
            [], 0, f"CONFIRMED session={SID}", ""
        )

    monkeypatch.setattr(server.NewtonService, "run_script", fake_run)
    result = server.NewtonService().apply("quasar", SID)
    assert result["result"] == "confirmed"
    assert cc.LOCAL_CHECK_RE.fullmatch(seen["env"]["OWRT_LOCAL_CHECK"])
    assert seen["env"]["OWRT_LOCAL_CHECK"] == (
        f"'{scripts / 'newton-vantage-run'}' {SID}"
    )
    assert seen["env"]["NEWTON_VANTAGE_SPEC_DIR"] == str(
        tmp_path / "state" / "vantage-runs"
    )
    assert seen["mode"] == 0o600
    assert seen["content"]["version"] == 1
    assert seen["content"]["sid"] == SID
    assert seen["content"]["groups"][0]["zone"] == "guest"
    assert seen["content"]["groups"][0]["checks"] == [
        {"claim": 1, "kind": "client_dns"}
    ]
    assert not seen["spec"].exists()


def test_vc04_02_the_spec_is_removed_after_a_script_failure(tmp_path, monkeypatch):
    write_inventory(tmp_path, monkeypatch)
    write_script_directory(tmp_path, monkeypatch)
    record = client_record()
    write_plan(tmp_path, record)
    seen = {}

    def fake_run(self, device, *args, **kwargs):
        env = self.script_env(device)
        env.update(kwargs["extra_env"])
        spec = Path(env["NEWTON_VANTAGE_SPEC_DIR"]) / f"{SID}.json"
        seen["spec"] = spec
        assert spec.is_file()
        return subprocess.CompletedProcess([], 1, "ERROR: failed", "")

    monkeypatch.setattr(server.NewtonService, "run_script", fake_run)
    result = server.NewtonService().apply("quasar", SID)
    assert result["result"] == "error"
    assert not seen["spec"].exists()


def test_vc04_03_the_spec_is_removed_after_a_script_timeout(tmp_path, monkeypatch):
    write_inventory(tmp_path, monkeypatch)
    write_script_directory(tmp_path, monkeypatch)
    record = client_record()
    write_plan(tmp_path, record)
    seen = {}

    def fake_run(self, device, *args, **kwargs):
        env = self.script_env(device)
        env.update(kwargs["extra_env"])
        spec = Path(env["NEWTON_VANTAGE_SPEC_DIR"]) / f"{SID}.json"
        seen["spec"] = spec
        assert spec.is_file()
        raise subprocess.TimeoutExpired("owrt-change.sh", 480)

    monkeypatch.setattr(server.NewtonService, "run_script", fake_run)
    result = server.NewtonService().apply("quasar", SID)
    assert result["result"] == "unknown"
    assert not seen["spec"].exists()


def test_vc04_04_server_has_one_local_check_assignment_from_local_check_string():
    source = Path(server.__file__).read_text(encoding="utf-8")
    assignments = re.findall(
        r"(?m)^\s*extra_env\[\"OWRT_LOCAL_CHECK\"\]\s*=\s*(.+)$",
        source,
    )
    assert len(assignments) == 1
    assert "local_check_string" in assignments[0]


def test_vc04_05_apply_without_client_claims_leaves_the_local_check_env_untouched(
    tmp_path, monkeypatch
):
    write_inventory(tmp_path, monkeypatch)
    write_script_directory(tmp_path, monkeypatch)
    monkeypatch.setenv("OWRT_LOCAL_CHECK", "sentinel-local-check")
    monkeypatch.delenv("NEWTON_VANTAGE_SPEC_DIR", raising=False)
    record = client_record(expect=[{"kind": "probe", "probe": ["iface-absent", "guestx"]}])
    record["probes"] = [["iface-absent", "guestx"]]
    record["plan_hash"] = compute_plan_hash(record)
    write_plan(tmp_path, record)
    seen = {}

    def fake_run(self, device, *args, **kwargs):
        env = self.script_env(device)
        if kwargs.get("extra_env"):
            env.update(kwargs["extra_env"])
        seen["env"] = env
        return subprocess.CompletedProcess(
            [], 0, f"CONFIRMED session={SID}", ""
        )

    monkeypatch.setattr(server.NewtonService, "run_script", fake_run)
    result = server.NewtonService().apply("quasar", SID)
    assert result["result"] == "confirmed"
    assert seen["env"]["OWRT_LOCAL_CHECK"] == "sentinel-local-check"
    assert "NEWTON_VANTAGE_SPEC_DIR" not in seen["env"]


def test_vc01_01_a_local_check_failure_rolls_back_and_names_the_client_claim(
    tmp_path, monkeypatch
):
    write_inventory(tmp_path, monkeypatch)
    write_script_directory(tmp_path, monkeypatch)
    record = client_record()
    write_plan(tmp_path, record)
    monkeypatch.setattr(
        server.NewtonService,
        "run_script",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            [], 1, local_check_log(), ""
        ),
    )
    result = server.NewtonService().apply("quasar", SID)
    assert result["result"] == "rolled_back"
    assert result["failed_claim"] == {
        "claim": 1,
        "text": (
            "expect claim 1 failed: client in zone guest resolves names through "
            "the zone router (no-answer)"
        ),
    }


def test_vc04_06_a_missing_runner_is_refused_before_the_approval_is_consumed(
    tmp_path, monkeypatch
):
    write_inventory(tmp_path, monkeypatch)
    write_script_directory(tmp_path, monkeypatch, with_runner=False)
    record = client_record(requires_approval=True)
    write_plan(tmp_path, record)
    approval = write_approval(tmp_path, record)
    monkeypatch.setattr(
        server.NewtonService,
        "run_script",
        lambda *args, **kwargs: pytest.fail("must not run the change script"),
    )
    with pytest.raises(server.NewtonError, match="the vantage runner is missing"):
        server.NewtonService().apply("quasar", SID)
    assert approval.is_file()
    assert not (approval.parent / f"{SID}.claimed").exists()
    assert not (approval.parent / f"{SID}.used").exists()


def test_vc04_07_a_removed_vantage_is_refused_before_the_approval_is_consumed(
    tmp_path, monkeypatch
):
    write_inventory(tmp_path, monkeypatch)
    write_script_directory(tmp_path, monkeypatch)
    record = client_record(requires_approval=True)
    write_plan(tmp_path, record)
    approval = write_approval(tmp_path, record)
    write_inventory(tmp_path, monkeypatch, include_vantage=False)
    monkeypatch.setattr(
        server.NewtonService,
        "run_script",
        lambda *args, **kwargs: pytest.fail("must not run the change script"),
    )
    with pytest.raises(
        server.NewtonError,
        match="client check vantage no longer registered; plan again",
    ):
        server.NewtonService().apply("quasar", SID)
    assert approval.is_file()
    assert not (approval.parent / f"{SID}.claimed").exists()
    assert not (approval.parent / f"{SID}.used").exists()
