"""the reboot line of a no-install auto plan.

The owner reads the same words in both places the plan is shown: the
approval dialog of the client and the terminal of ``newton-approve``.
The line says what happens when the router reboots while the change is
waiting: the change stays.

The line is shown ONCE.  An owner script shows its own line, in its
own part of the display, and an installed plan shows none: neither
changes here.

The record these tests show is the one the no-install plan really
writes: it is planned over the fake router, not written by hand, so
the display below is the display of a real record.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from newton_mcp import approval_proof
from newton_mcp import approve
from newton_mcp import change_classes
from newton_mcp import elicit_approval
from newton_mcp import noinstall_flow
from newton_mcp import owner_flow
from newton_mcp import owner_records
from newton_mcp import owner_script
from newton_mcp.plan import compute_plan_hash

import noinstall_answers
import noinstall_fakes
from noinstall_fakes import FakeRouter
from test_approve import TerminalInput, write_fingerprint
from test_owner_flow import FakeService, _device


DEVICE = "lab-r1"
DIGEST = "d" * 64
PASSPHRASE = "synthetic-reboot-passphrase"

#: The line, word for word.
REBOOT = owner_flow.REBOOT_LINE.format(120)

#: The batch of the plan: a DHCP reservation, the class Newton applies
#: itself on a no-install router.
BATCH = (
    "set dhcp.laptop=host\n"
    "set dhcp.laptop.mac='02:00:00:00:10:01'\n"
    "set dhcp.laptop.ip='10.109.0.55'\n"
)

#: The measured dhcp config of lab-r1.
DHCP = noinstall_answers.data("uci.get.dhcp")["values"]

#: The explanation of the plan.  Its claim is one Newton cannot check
#: here: a client claim needs a client on the network, and the
#: no-install path has no vantage on one.
EXPLANATION = {
    "intent": "give the laptop a fixed address",
    "steps": [
        "add the laptop to the dhcp config",
        "give it the mac address it has",
        "give it the address it keeps",
    ],
    "expect": [{"kind": "client_dhcp", "zone": "lab"}],
    "risk": "the laptop keeps its address",
}


def _answers(configs: dict[str, Any]) -> dict[tuple[str, str], Any]:
    """The answers of a router that holds the given configs."""
    def uci_get(_obj: str, _fn: str, args: dict[str, Any]) -> Any:
        return {"values": configs.get(str(args.get("config", "")), {})}

    return {
        ("file", "list"): {"entries": []},
        ("system", "board"): {"board_name": "lab-r1"},
        ("uci", "get"): uci_get,
    }


def _auto_plan(
    tmp_path: Path, monkeypatch
) -> tuple[str, dict[str, Any], Path]:
    """The plan of a no-install router, over the fake router.

    Returns the session id, the record the plan wrote and the state
    directory the record lives in.
    """
    state = tmp_path / "state"
    state.mkdir(mode=0o700, exist_ok=True)
    os.chmod(state, 0o700)
    monkeypatch.setenv("NEWTON_STATE_DIR", str(state))
    service = FakeService(state, {DEVICE: _device(tmp_path)})
    router = FakeRouter(_answers({"dhcp": DHCP}))
    result = noinstall_flow.plan(
        service,
        DEVICE,
        BATCH,
        120,
        explanation=EXPLANATION,
        owner_confirmed_in_chat=True,
        client_factory=noinstall_fakes.factory(router),
    )
    assert result["mode"] == "auto", result
    sid = str(result["session_id"])
    record = json.loads(
        (state / "plans" / f"{sid}.json").read_text(encoding="utf-8")
    )
    return sid, record, state


def _write_script(state: Path, sid: str, body: bytes) -> str:
    """Write the script of a plan on disk; return its sha256."""
    path = owner_records.script_path(state, sid)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(body)
    return owner_script.script_sha256(body)


def _owner_plan(state: Path, sid: str, record: dict[str, Any]) -> dict[str, Any]:
    """An owner-script plan: it shows its own reboot line.

    The scripts are written on disk and the digest of the record is
    built from their hashes, because the dialog reads them from there
    and refuses a record whose scripts do not match.
    """
    record = dict(record)
    record["router_leash"] = "owner-script"
    record.pop("mode", None)
    record.pop("reboot_line", None)
    restore_sid = "f" * 32
    record["restore_sid"] = restore_sid
    record["backup_manifest_sha256"] = "c" * 64
    apply_sha = _write_script(state, sid, b"#!/bin/sh\n# the apply script\n")
    restore_sha = _write_script(state, restore_sid, b"#!/bin/sh\n# the restore script\n")
    record["script_sha256"] = apply_sha
    record["router_digest"] = owner_records.expected_digest(
        record, apply_sha, restore_sha
    )
    record["plan_hash"] = compute_plan_hash(record)
    return record


def _installed_plan(record: dict[str, Any]) -> dict[str, Any]:
    """An installed plan: the display of it does not change."""
    record = dict(record)
    record["router_leash"] = ["mgmt-if"]
    record["router_profile"] = "prod"
    record.pop("mode", None)
    record.pop("reboot_line", None)
    record["plan_hash"] = compute_plan_hash(record)
    return record


def _dialog(record: dict[str, Any], sid: str) -> str:
    """The text the approval dialog shows."""
    explanation, digest = approve.validate_plan_for_approval(record)
    classification = change_classes.classify(str(record["uci_batch"]))
    return elicit_approval._dialog_text(
        DEVICE,
        sid,
        record,
        explanation,
        digest,
        False,
        approval_proof.LEVEL_PASSPHRASE,
        classification,
        False,
    )


# ---- the dialog ------------------------------------------------------------


def test_the_dialog_of_a_no_install_auto_plan_shows_the_reboot_line_once(
    tmp_path: Path, monkeypatch
) -> None:
    """The owner reads the reboot line once, in the dialog."""
    sid, record, _state = _auto_plan(tmp_path, monkeypatch)
    text = _dialog(record, sid)
    assert text.count("If the router reboots") == 1, text
    assert REBOOT in text


def test_the_dialog_of_an_owner_script_shows_the_reboot_line_once(
    tmp_path: Path, monkeypatch
) -> None:
    """An owner script shows its own line, and it is shown once."""
    sid, record, state = _auto_plan(tmp_path, monkeypatch)
    text = _dialog(_owner_plan(state, sid, record), sid)
    assert text.count("If the router reboots") == 1, text


def test_the_dialog_of_an_installed_plan_shows_no_reboot_line(
    tmp_path: Path, monkeypatch
) -> None:
    """The installed display does not change."""
    sid, record, _state = _auto_plan(tmp_path, monkeypatch)
    text = _dialog(_installed_plan(record), sid)
    assert "If the router reboots" not in text


def test_the_dialog_of_a_no_install_auto_plan_says_what_it_cannot_check(
    tmp_path: Path, monkeypatch
) -> None:
    """The owner is told what Newton cannot check.

    The no-install path has no vantage on the network, so a client
    claim cannot be checked here: the dialog says so, exactly as an
    owner script's dialog does.
    """
    sid, record, _state = _auto_plan(tmp_path, monkeypatch)
    assert record["not_verified"], record
    text = _dialog(record, sid)
    assert "What Newton cannot check:" in text, text
    assert "client_dhcp" in text, text


# ---- the terminal ----------------------------------------------------------


def _write_plan(
    tmp_path: Path, monkeypatch, record: dict[str, Any], sid: str
) -> Path:
    state = tmp_path / "state"
    plans = state / "plans"
    plans.mkdir(parents=True, exist_ok=True)
    (plans / f"{sid}.json").write_text(json.dumps(record), encoding="utf-8")
    monkeypatch.setenv("NEWTON_STATE_DIR", str(state))
    monkeypatch.setenv("SUDO_USER", "labuser")
    return state


def test_the_terminal_shows_the_reboot_line_once(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    """The owner reads the reboot line once, in the terminal too."""
    sid, record, _state = _auto_plan(tmp_path, monkeypatch)
    state = _write_plan(tmp_path, monkeypatch, record, sid)
    k = approve.derive_k(PASSPHRASE.encode("utf-8"), DEVICE)
    write_fingerprint(state, DEVICE, k)
    monkeypatch.setattr(
        approve, "_getpass", lambda prompt: PASSPHRASE
    )
    monkeypatch.setattr(approve.sys, "stdin", TerminalInput(f"approve {sid[:8]}\n"))

    assert approve.main([sid]) == 0

    out = capsys.readouterr().out
    assert out.count("If the router reboots") == 1, out
    assert REBOOT in out


def test_the_terminal_says_what_it_cannot_check(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    """The terminal says what Newton cannot check, as the dialog does."""
    sid, record, _state = _auto_plan(tmp_path, monkeypatch)
    state = _write_plan(tmp_path, monkeypatch, record, sid)
    k = approve.derive_k(PASSPHRASE.encode("utf-8"), DEVICE)
    write_fingerprint(state, DEVICE, k)
    monkeypatch.setattr(approve, "_getpass", lambda prompt: PASSPHRASE)
    monkeypatch.setattr(approve.sys, "stdin", TerminalInput(f"approve {sid[:8]}\n"))

    assert approve.main([sid]) == 0

    out = capsys.readouterr().out
    assert "What Newton cannot check:" in out, out
    assert "client_dhcp" in out, out


def test_the_terminal_of_an_installed_plan_shows_no_reboot_line(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    """The installed display does not change."""
    sid, record, _state = _auto_plan(tmp_path, monkeypatch)
    state = _write_plan(tmp_path, monkeypatch, _installed_plan(record), sid)
    k = approve.derive_k(PASSPHRASE.encode("utf-8"), DEVICE)
    write_fingerprint(state, DEVICE, k)
    monkeypatch.setattr(approve, "_getpass", lambda prompt: PASSPHRASE)
    monkeypatch.setattr(approve.sys, "stdin", TerminalInput(f"approve {sid[:8]}\n"))

    assert approve.main([sid]) == 0

    out = capsys.readouterr().out
    assert "If the router reboots" not in out
