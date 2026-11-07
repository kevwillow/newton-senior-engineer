"""Change receipts (CR-01..CR-17).

Every apply that ends CONFIRMED, ROLLED BACK or UNKNOWN writes one readable
Markdown receipt under ``<state>/receipts``, built from records that already
exist (the plan record, the claimed approval, the script's audit lines for the
session).  These are not the getters' field receipts.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
from datetime import datetime
from pathlib import Path

import pytest

from exhelp import make_explanation, record_fields_display

import newton_mcp.change_receipt as cr
import newton_mcp.explanation as _explanation
import newton_mcp.server as server
from newton_mcp.plan import compute_plan_hash


SID = "fd595e20f2cd6c2b928fe3156f82d5db"
BASE_HASH = "8" * 64
ROUTER_DIGEST = "3" * 64
TOKEN = "e" * 64
BACKUP_NAME = "quasar-20261024T150000Z.tar.gz"


@pytest.fixture
def configured(tmp_path, monkeypatch):
    inventory = tmp_path / "devices.toml"
    inventory.write_text('[devices.quasar]\nplatform = "openwrt"\nhost = "192.0.2.1"\nuser = "root"\n')
    monkeypatch.setenv("NEWTON_INVENTORY", str(inventory))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("OWRT_AUDIT_LOG", str(tmp_path / "audit.log"))
    return tmp_path


@pytest.fixture
def configured_lab(tmp_path, monkeypatch):
    inventory = tmp_path / "devices-lab.toml"
    inventory.write_text(
        '[devices.quasar]\nplatform = "openwrt"\nhost = "192.0.2.1"\nuser = "root"\nprofile = "lab"\nlab = true\n'
    )
    monkeypatch.setenv("NEWTON_INVENTORY", str(inventory))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("OWRT_AUDIT_LOG", str(tmp_path / "audit.log"))
    return tmp_path


def _record(root, *, approval=True, diff="dhcp.nas.ip='192.0.2.20'", expect=None, intent=None, **updates):
    explanation = make_explanation("set dhcp.nas.ip=192.0.2.20")
    if expect is not None:
        explanation["expect"] = expect
    if intent is not None:
        explanation["intent"] = intent
    backup = root / "backups" / BACKUP_NAME
    backup.parent.mkdir(parents=True, exist_ok=True)
    backup.write_bytes(b"backup-bytes-" + bytes(range(40)))
    record = {
        "device": "quasar",
        "host": "192.0.2.1",
        "session_id": SID,
        "uci_batch": "set dhcp.nas.ip=192.0.2.20",
        "diff": diff,
        "probes": [["fail"]] + _explanation.claim_probes(explanation),
        "timeout_s": 90,
        "base_hash": BASE_HASH,
        "requires_approval": approval,
        "router_digest": ROUTER_DIGEST,
        "explanation": explanation,
        "owner_confirmed_in_chat": True,
        **record_fields_display(),
        "created_at": "2026-10-24T15:00:00+00:00",
        "staged_at": "2026-10-24T15:00:00+00:00",
        "backup_path": str(backup),
    }
    record.update(updates)
    record["plan_hash"] = compute_plan_hash(record)
    return record


def _write_plan(root, record):
    plans = root / "state" / "plans"
    plans.mkdir(parents=True, exist_ok=True)
    (plans / f"{SID}.json").write_text(json.dumps(record))


def _write_approval(root, record, approved_by="operator"):
    approvals = root / "state" / "approvals"
    approvals.mkdir(parents=True, exist_ok=True)
    created = "2099-01-01T00:00:00+00:00"
    expires = "2099-01-01T00:30:00+00:00"
    (approvals / f"{SID}.json").write_text(json.dumps({
        "plan_id": SID,
        "plan_hash": record["plan_hash"],
        "device": record["device"],
        "base_hash": record["base_hash"],
        "approved_by": approved_by,
        "created_at": created,
        "expires_at": expires,
        "not_before": int(datetime.fromisoformat(created).timestamp()),
        "not_after": int(datetime.fromisoformat(expires).timestamp()),
        "token": TOKEN,
    }))


def _run(monkeypatch, stdout, rc):
    monkeypatch.setattr(
        server.NewtonService, "run_script",
        lambda *a, **k: subprocess.CompletedProcess([], rc, stdout, ""),
    )


def _audit(root, *lines):
    path = root / "audit.log"
    with path.open("a") as f:
        for line in lines:
            f.write(f"2026-10-24T15:01:00-04:00 root@192.0.2.1 {line}\n")


def _receipts(root):
    d = root / "state" / "receipts"
    return sorted(p for p in d.glob("*.md")) if d.is_dir() else []


def _applied(root, monkeypatch, *, outcome="confirmed", approval=True, approved_by="operator", **rec):
    record = _record(root, approval=approval, **rec)
    _write_plan(root, record)
    if approval:
        _write_approval(root, record, approved_by=approved_by)
    final, rc = {
        "confirmed": (f"CONFIRMED session={SID} (3 consecutive passes: fresh ssh + router-side ping, dns, health and 2 probes)", 0),
        "rolled_back": (f"ROLLBACK WINDOW PASSED session={SID} - router reachable; rolled back by rpcd", 1),
        "unknown": (f"ALERT session={SID} status=confirmed after the rollback window", 1),
    }[outcome]
    _audit(root, f"APPLYING session={SID}", f"APPLIED session={SID} rollback=90s", final)
    _run(monkeypatch, f"APPLYING session={SID}\n{final}\n", rc)
    return record, server.newton_apply_change("quasar", SID)


# CR-01: each of the three outcomes writes exactly one receipt, with the outcome in capitals.
@pytest.mark.parametrize(("outcome", "word"), [
    ("confirmed", "CONFIRMED"), ("rolled_back", "ROLLED BACK"), ("unknown", "UNKNOWN"),
])
def test_cr01_each_outcome_writes_one_receipt(configured, monkeypatch, outcome, word):
    _, result = _applied(configured, monkeypatch, outcome=outcome)
    assert result["result"] == outcome
    files = _receipts(configured)
    assert len(files) == 1
    text = files[0].read_text()
    assert f"Outcome: {word}" in text
    assert SID in files[0].name and "quasar" in files[0].name


# CR-01b: an apply that never reached the router changed nothing and writes no receipt.
def test_cr01b_error_before_applying_writes_none(configured, monkeypatch):
    record = _record(configured)
    _write_plan(configured, record)
    _write_approval(configured, record)
    _run(monkeypatch, "lost connection before reaching the router", 1)
    assert server.newton_apply_change("quasar", SID)["result"] == "error"
    assert _receipts(configured) == []


# CR-11: an error after the APPLYING line (the token reached the router) is an UNKNOWN receipt.
def test_cr11_error_after_applying_line_is_unknown_receipt(configured, monkeypatch):
    record = _record(configured)
    _write_plan(configured, record)
    _write_approval(configured, record)
    _run(monkeypatch, f"APPLYING session={SID}\napply refused: something odd", 1)
    assert server.newton_apply_change("quasar", SID)["result"] == "error"
    files = _receipts(configured)
    assert len(files) == 1
    assert "UNKNOWN" in files[0].read_text()


# CR-02: the sections a human needs, with outcome-specific undo advice.
def test_cr02_sections_and_undo_advice(configured, monkeypatch):
    _applied(configured, monkeypatch, outcome="confirmed")
    text = _receipts(configured)[0].read_text()
    for heading in ("## What changed", "## Who approved", "## Checks", "## Backup", "## How to undo"):
        assert heading in text
    assert "dhcp.nas.ip='192.0.2.20'" in text
    assert "operator" in text and "newton-approve" in text
    assert BACKUP_NAME in text
    assert "sysupgrade -r" in text


def test_cr02b_rolled_back_says_nothing_to_undo(configured, monkeypatch):
    _applied(configured, monkeypatch, outcome="rolled_back")
    text = _receipts(configured)[0].read_text()
    assert "Nothing to undo" in text
    assert "sysupgrade -r" not in text


def test_cr02c_unknown_says_check_status_first(configured, monkeypatch):
    _applied(configured, monkeypatch, outcome="unknown")
    text = _receipts(configured)[0].read_text()
    assert "newton_change_status" in text


# CR-03: owner-only files, and no write through a symlinked receipts dir.
def test_cr03_modes(configured, monkeypatch):
    _applied(configured, monkeypatch)
    path = _receipts(configured)[0]
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700


def test_cr03b_symlinked_receipts_dir_is_refused(configured, monkeypatch):
    elsewhere = configured / "elsewhere"
    elsewhere.mkdir()
    state = configured / "state"
    state.mkdir(mode=0o700)
    (state / "receipts").symlink_to(elsewhere)
    _, result = _applied(configured, monkeypatch)
    assert result["result"] == "confirmed"
    assert list(elsewhere.iterdir()) == []


# CR-19: existing receipt directories are forced to 0700, and a directory owned by another uid is refused.
def test_cr19_existing_receipt_dirs_are_private_and_owned(configured, monkeypatch):
    state = configured / "state"
    receipts = state / "receipts"
    backups = receipts / "backups"
    backups.mkdir(parents=True)
    receipts.chmod(0o755)
    backups.chmod(0o755)

    assert cr._safe_dir(receipts, state) is True
    assert cr._safe_dir(backups, state) is True
    assert stat.S_IMODE(receipts.stat().st_mode) == 0o700
    assert stat.S_IMODE(backups.stat().st_mode) == 0o700

    actual_uid = os.geteuid()
    monkeypatch.setattr(cr.os, "geteuid", lambda: actual_uid + 1)
    assert cr._safe_dir(receipts, state) is False


# CR-04: secrets planted in the diff, the explanation and an audit line are masked.
def test_cr04_planted_secrets_are_masked(configured, monkeypatch):
    record = _record(
        configured,
        diff="wireless.guest.key='PlantedWifiKey9981'\ndhcp.nas.ip='192.0.2.20'",
        intent="Set the password=PlantedPassword7732 for the guest",
    )
    _write_plan(configured, record)
    _write_approval(configured, record)
    _audit(
        configured,
        f"APPLIED session={SID} rollback=90s",
        f"VERIFY STDERR session={SID}: key=PlantedStderrKey5521",
        f"ROLLBACK WINDOW PASSED session={SID} - rolled back",
    )
    _run(monkeypatch, f"APPLYING session={SID}\nROLLBACK WINDOW PASSED session={SID}\n", 1)
    server.newton_apply_change("quasar", SID)
    text = _receipts(configured)[0].read_text()
    for secret in ("PlantedWifiKey9981", "PlantedPassword7732", "PlantedStderrKey5521"):
        assert secret not in text


# CR-05: the receipt is derived: regenerating from the same records gives the same text.
def test_cr05_regenerate_equals_written(configured, monkeypatch):
    _applied(configured, monkeypatch)
    written = _receipts(configured)[0]
    assert cr.regenerate(configured / "state", SID) == written.read_text()


def test_cr05b_regenerate_follows_the_audit_log(configured, monkeypatch):
    """The outcome is not stored: a different audit entry gives a different receipt."""
    _applied(configured, monkeypatch, outcome="confirmed")
    (configured / "audit.log").write_text("")
    _audit(configured, f"ROLLBACK WINDOW PASSED session={SID} - rolled back")
    assert "Outcome: ROLLED BACK" in cr.regenerate(configured / "state", SID)


# CR-06: the approval token never reaches a receipt.
def test_cr06_token_never_in_receipt(configured, monkeypatch):
    _applied(configured, monkeypatch)
    assert TOKEN not in _receipts(configured)[0].read_text()


# CR-07: off-device copy of the backup, same bytes, owner-only; the receipt names its hash, never its content.
def test_cr07_backup_copy(configured, monkeypatch):
    record, _ = _applied(configured, monkeypatch)
    original = Path(record["backup_path"]).read_bytes()
    copy = configured / "state" / "receipts" / "backups" / f"{SID}.tar.gz"
    assert copy.read_bytes() == original
    assert stat.S_IMODE(copy.stat().st_mode) == 0o600
    text = _receipts(configured)[0].read_text()
    assert hashlib.sha256(original).hexdigest() in text
    assert "backup-bytes" not in text


def test_cr07b_missing_backup_still_writes_receipt(configured, monkeypatch):
    record = _record(configured)
    Path(record["backup_path"]).unlink()
    _write_plan(configured, record)
    _write_approval(configured, record)
    _audit(configured, f"CONFIRMED session={SID} (3 consecutive passes)")
    _run(monkeypatch, f"APPLYING session={SID}\nCONFIRMED session={SID}\n", 0)
    assert server.newton_apply_change("quasar", SID)["result"] == "confirmed"
    text = _receipts(configured)[0].read_text()
    assert "backup file not found" in text.lower()


# CR-20: the backup is streamed, hashed once, and its mode is set on the open descriptor.
def test_cr20_backup_copy_streams_hashes_once_and_uses_fchmod(configured, monkeypatch):
    record = _record(configured)
    source = Path(record["backup_path"])
    expected = hashlib.sha256(source.read_bytes()).hexdigest()
    state = configured / "state"
    tmp = state / "receipts" / "backups" / f"{SID}.tar.tmp"
    copy = state / "receipts" / "backups" / f"{SID}.tar.gz"
    real_sha256 = hashlib.sha256
    real_read_bytes = Path.read_bytes
    sha256_calls = 0
    fchmod_paths = []
    real_fchmod = os.fchmod
    real_chmod = os.chmod

    def counted_sha256(*args, **kwargs):
        nonlocal sha256_calls
        sha256_calls += 1
        return real_sha256(*args, **kwargs)

    def no_whole_file_reads(self):
        if self in (source, tmp, copy):
            raise OSError("whole-file reads are forbidden")
        return real_read_bytes(self)

    def tracked_fchmod(fd, mode):
        fchmod_paths.append((Path(os.readlink(f"/proc/self/fd/{fd}")), mode))
        return real_fchmod(fd, mode)

    def no_path_chmod_on_temp(path, mode, *args, **kwargs):
        if Path(path) == tmp:
            raise OSError("temporary backup mode must be set on its descriptor")
        return real_chmod(path, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "read_bytes", no_whole_file_reads)
    monkeypatch.setattr(cr.hashlib, "sha256", counted_sha256)
    monkeypatch.setattr(cr.os, "fchmod", tracked_fchmod)
    monkeypatch.setattr(cr.os, "chmod", no_path_chmod_on_temp)

    info = cr._copy_backup(state, record, SID)
    with copy.open("rb") as stream:
        copied = stream.read()
    assert copied == b"backup-bytes-" + bytes(range(40))
    assert info == (BACKUP_NAME, expected, f"off-device copy: receipts/backups/{SID}.tar.gz")
    assert sha256_calls == 1
    assert (tmp, 0o600) in fchmod_paths


def test_cr20b_backup_source_must_be_a_regular_file(configured, monkeypatch):
    record = _record(configured)
    source = Path(record["backup_path"])
    link = source.with_name("backup-link.tar.gz")
    link.symlink_to(source)
    record["backup_path"] = str(link)
    _write_plan(configured, record)
    _write_approval(configured, record)
    _audit(configured, f"CONFIRMED session={SID} (3 consecutive passes)")
    _run(monkeypatch, f"APPLYING session={SID}\nCONFIRMED session={SID}\n", 0)

    assert server.newton_apply_change("quasar", SID)["result"] == "confirmed"
    copy = configured / "state" / "receipts" / "backups" / f"{SID}.tar.gz"
    assert not copy.exists()
    assert "not a regular file" in _receipts(configured)[0].read_text().lower()


def test_cr20c_backup_larger_than_64_mib_is_not_copied(configured, monkeypatch):
    record = _record(configured)
    source = Path(record["backup_path"])
    with source.open("r+b") as stream:
        stream.truncate(64 * 1024 * 1024 + 1)
    _write_plan(configured, record)
    _write_approval(configured, record)
    _audit(configured, f"CONFIRMED session={SID} (3 consecutive passes)")
    _run(monkeypatch, f"APPLYING session={SID}\nCONFIRMED session={SID}\n", 0)

    assert server.newton_apply_change("quasar", SID)["result"] == "confirmed"
    copy = configured / "state" / "receipts" / "backups" / f"{SID}.tar.gz"
    assert not copy.exists()
    text = _receipts(configured)[0].read_text().lower()
    assert "not copied" in text
    assert "larger than the 64 mib limit" in text


# CR-08: a receipt problem never changes the apply result.
def test_cr08_write_failure_keeps_apply_result(configured, monkeypatch):
    def boom(*a, **k):
        raise OSError("disk full")
    monkeypatch.setattr(cr, "write_receipt", boom)
    _, result = _applied(configured, monkeypatch)
    assert result["result"] == "confirmed"


# CR-09: the getters' field receipts are a different thing and are not touched.
def test_cr09_field_receipts_untouched(configured, monkeypatch):
    _applied(configured, monkeypatch)
    assert not (configured / "state" / "field-receipts.jsonl").exists()


# CR-10: free text in a probe claim is never printed, only the probe name and argument count.
def test_cr10_probe_claim_text_not_printed(configured, monkeypatch):
    expect = [
        {"kind": "probe", "probe": ["log-has", "present", "PlantedClaimText4410"]},
        {"kind": "uci_equals", "path": "dhcp.nas.ip", "equals": "192.0.2.20"},
    ]
    _, result = _applied(configured, monkeypatch, expect=expect)
    assert result.get("result") == "confirmed", result
    text = _receipts(configured)[0].read_text()
    assert "PlantedClaimText4410" not in text
    assert "log-has" in text and "2 arguments" in text
    assert "dhcp.nas.ip" in text


# CR-12: an empty approved_by is shown as unknown, never blank.
def test_cr12_empty_approved_by(configured, monkeypatch):
    _applied(configured, monkeypatch, approved_by="")
    text = _receipts(configured)[0].read_text()
    assert "approved by: unknown" in text.lower()


# CR-13: a lab device that needed no approval says so.
def test_cr13_no_approval_needed(configured_lab, monkeypatch):
    _applied(configured_lab, monkeypatch, approval=False)
    assert "no approval needed" in _receipts(configured_lab)[0].read_text().lower()


# CR-14: with no audit log the same lines come from the apply output, and the receipt says so.
def test_cr14_audit_fallback_to_apply_output(configured, monkeypatch):
    record = _record(configured)
    _write_plan(configured, record)
    _write_approval(configured, record)
    _run(monkeypatch, f"APPLYING session={SID}\nCONFIRMED session={SID} (3 consecutive passes)\n", 0)
    server.newton_apply_change("quasar", SID)
    text = _receipts(configured)[0].read_text()
    assert "apply output" in text.lower()
    assert "CONFIRMED session=" in text


# CR-16: one mcp-audit line points at the receipt; it carries the session and outcome, no diff text.
def test_cr16_mcp_audit_line(configured, monkeypatch):
    _applied(configured, monkeypatch)
    audit = (configured / "state" / "mcp-audit.log").read_text()
    line = next(l for l in audit.splitlines() if "tool=newton_receipt" in l)
    assert f"session={SID}" in line and "outcome=confirmed" in line
    assert "192.0.2.20" not in line


# CR-17: plan() keeps the backup path out of the hash but in the record.
def test_cr17_backup_path_is_not_hash_bound(configured):
    record = _record(configured)
    other = dict(record, backup_path="/elsewhere/other.tar.gz")
    assert compute_plan_hash(other) == record["plan_hash"]


# CR-18: a claim value that looks like a secret is masked in the receipt even though the plan step refuses such
# claims upstream (defence in depth, tested on the renderer), and the approval record state is named.
def test_cr18_claim_text_masks_secret_looking_value():
    record = {"explanation": {"expect": [
        {"kind": "uci_equals", "path": "wireless.guest.key", "equals": "PlantedClaimKey3301"},
        {"kind": "uci_equals", "path": "system.@system[0].description", "equals": "password=PlantedClaimKey3302"},
    ]}}
    text = "\n".join(cr._claims_text(record))
    assert "PlantedClaimKey3301" not in text and "PlantedClaimKey3302" not in text


def test_cr18b_approval_state_is_named(configured, monkeypatch):
    _applied(configured, monkeypatch)
    assert "Approval record: used by this apply" in _receipts(configured)[0].read_text()


# CR-21: regenerating ignores its own later audit event when choosing the finish time.
def test_cr21_regenerate_finished_time_skips_receipt_audit_line(configured):
    record = _record(configured)
    _write_plan(configured, record)
    (configured / "audit.log").write_text(
        f"2026-10-24T15:01:00-04:00 root@192.0.2.1 APPLIED session={SID} rollback=90s\n"
        f"2026-10-24T15:02:00-04:00 root@192.0.2.1 CONFIRMED session={SID} (3 consecutive passes)\n"
        f"2026-10-24T15:03:00-04:00 tool=newton_receipt device=quasar "
        f"result=session={SID} outcome=confirmed file=receipt.md\n"
    )

    text = cr.regenerate(configured / "state", SID)
    assert "Applied: 2026-10-24T15:01:00-04:00" in text
    assert "Finished: 2026-10-24T15:02:00-04:00" in text
    assert "Finished: 2026-10-24T15:03:00-04:00" not in text
