"""The recovery line of an approval: what happens when Newton loses contact.

One line per mode of the plan, printed right after the "Timeout:" line
and before the reboot line; one line for an Active Directory write and
one for an Active Directory build stage.

Every line is a fact of Newton's own, so it never carries the agent
marker, and the terminal of ``newton-approve`` and the in-client dialog
show the same bytes: both go through the one print path.
"""

from __future__ import annotations

import base64
import copy
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from exhelp import make_explanation

from newton_mcp import approve
from newton_mcp import owner_flow
from newton_mcp.ad.build import plan as build_plan
from newton_mcp.adapters.routeros_write import _window_s
from newton_mcp.adapters.vendor_write import minutes_for
from newton_mcp.plan import compute_plan_hash

from test_approve import (
    TerminalInput,
    plan_record,
    refuse_getpass,
    write_plan,
    write_record,
)


#: The session id of the plan records of the tests.
SID = "0123456789abcdef0123456789abcdef"

#: The prefix every recovery line carries.
PREFIX = "If Newton loses contact: "

#: The line of an installed OpenWrt plan.
INSTALLED = (
    PREFIX
    + "the router puts the old settings back by itself {0}s after the apply; "
    + "its guard does it too if that fails, and after a reboot"
)

#: The line of a no-install auto plan.
NO_INSTALL = (
    PREFIX
    + "the router puts the old settings back by itself {0}s after the apply"
)

#: The line of a vendor plan whose device holds the revert itself.
VENDOR = (
    PREFIX
    + "the device's commit-confirm puts the old settings back {0}s after the apply"
)

#: The line of a RouterOS plan: the device reboots into its backup.
ROUTEROS = (
    PREFIX
    + "the router REBOOTS into its backup {0}s after the apply; traffic stops "
    + "during the reboot"
)

#: The line of a plan whose timeout cannot be read.
UNKNOWN = PREFIX + "unknown (the plan's timeout cannot be read)"

#: The line of an Active Directory write that arms an undo.
AD_PDC = PREFIX + "the PDC puts it back {0}s after the apply"

#: The line of an Active Directory unlock: it arms no undo.
AD_UNLOCK = PREFIX + "nothing is put back; an unlock stays written"

#: The line of the approval of an Active Directory build stage.
BUILD = (
    PREFIX
    + "the stage stops where it is and nothing is put back by itself; a resume "
    + "needs a new plan you approve, and the checkpoint above is the way back"
)


def _record(**fields: Any) -> dict[str, Any]:
    """A plan record with these fields, hashed again.

    A vendor plan carries a claim of its own platform, so the explanation
    of a vendor record is rebuilt with a ping claim.
    """
    record = plan_record()
    record.update(fields)
    platform = record.get("platform")
    if isinstance(platform, str) and platform != "openwrt":
        record["explanation"] = make_explanation(
            record["uci_batch"], expect=[{"kind": "ping", "host": "192.0.2.1"}]
        )
    record["plan_hash"] = compute_plan_hash(record)
    return record


def _terminal(tmp_path: Path, monkeypatch: Any, capsys: Any, **fields: Any) -> str:
    """The text the terminal shows for a plan with these fields."""
    state, _ = write_plan(tmp_path, monkeypatch)
    write_record(state, _record(**fields))
    return _show(monkeypatch, capsys)


def _show(monkeypatch: Any, capsys: Any) -> str:
    """The text the terminal shows for the plan that is on record."""
    monkeypatch.setattr(approve, "_getpass", refuse_getpass)
    monkeypatch.setattr(approve.sys, "stdin", TerminalInput("no\n"))
    assert approve.main([SID]) == 1
    return capsys.readouterr().out


# ---- the router and vendor plans -------------------------------------------


def test_the_installed_openwrt_plan_shows_the_installed_recovery_line(
    tmp_path: Path, monkeypatch: Any, capsys: Any
) -> None:
    """The installed plan says what puts the old settings back."""
    out = _terminal(tmp_path, monkeypatch, capsys, timeout_s=90)
    assert INSTALLED.format(90) in out.splitlines()


def test_the_no_install_openwrt_plan_shows_the_no_install_line_before_the_reboot_line(
    tmp_path: Path, monkeypatch: Any, capsys: Any
) -> None:
    """The no-install plan says less, and the line comes before the reboot line."""
    reboot = owner_flow.REBOOT_LINE.format(120)
    out = _terminal(
        tmp_path,
        monkeypatch,
        capsys,
        mode="auto",
        timeout_s=120,
        reboot_line=reboot,
    )
    lines = out.splitlines()
    assert NO_INSTALL.format(120) in lines
    assert lines.index(NO_INSTALL.format(120)) < lines.index(reboot)


@pytest.mark.parametrize(
    "platform,timeout_s,window",
    [
        ("vyos", 90, 120),
        ("junos", 600, 600),
        ("junos", 900, 600),
    ],
)
def test_the_vendor_plans_show_the_commit_confirm_line(
    platform: str,
    timeout_s: int,
    window: int,
    tmp_path: Path,
    monkeypatch: Any,
    capsys: Any,
) -> None:
    """The vendor plan says what the device's commit-confirm does."""
    assert minutes_for(timeout_s) * 60 == window
    out = _terminal(
        tmp_path, monkeypatch, capsys, platform=platform, timeout_s=timeout_s
    )
    assert VENDOR.format(window) in out.splitlines()


def test_the_routeros_plan_shows_the_backup_line(
    tmp_path: Path, monkeypatch: Any, capsys: Any
) -> None:
    """The RouterOS plan says that the device reboots into its backup."""
    window = _window_s(30)
    assert window >= 120
    out = _terminal(
        tmp_path, monkeypatch, capsys, platform="routeros", timeout_s=30
    )
    assert ROUTEROS.format(window) in out.splitlines()


@pytest.mark.parametrize("timeout_s", [True, "90"])
def test_an_unreadable_timeout_shows_the_unknown_line(
    timeout_s: Any, tmp_path: Path, monkeypatch: Any, capsys: Any
) -> None:
    """A plan whose timeout cannot be read says that it does not know."""
    out = _terminal(tmp_path, monkeypatch, capsys, timeout_s=timeout_s)
    assert UNKNOWN in out.splitlines()


def test_an_owner_script_shows_no_recovery_line(
    tmp_path: Path, monkeypatch: Any, capsys: Any
) -> None:
    """An owner script shows its own lines, never the recovery line."""
    out = _terminal(tmp_path, monkeypatch, capsys, router_leash="owner-script")
    assert "Leash: owner-script" in out
    assert "If Newton loses contact" not in out


def test_a_platform_newton_does_not_know_shows_no_recovery_line(
    tmp_path: Path, monkeypatch: Any, capsys: Any
) -> None:
    """A platform with no undo Newton knows has no line."""
    out = _terminal(tmp_path, monkeypatch, capsys, platform="eos", timeout_s=90)
    assert "If Newton loses contact" not in out


def test_the_dialog_shows_the_same_line_as_the_terminal(
    tmp_path: Path, monkeypatch: Any, capsys: Any
) -> None:
    """The in-client dialog shows the line of the terminal, byte for byte."""
    state, _ = write_plan(tmp_path, monkeypatch)
    record = _record(timeout_s=90)
    write_record(state, record)
    explanation, digest = approve.validate_plan_for_approval(record)
    rendered = approve.render_plan_text(SID, record, explanation, digest)
    assert INSTALLED.format(90) in rendered.splitlines()
    out = _show(monkeypatch, capsys)
    assert INSTALLED.format(90) in out.splitlines()
    assert INSTALLED.format(90) in rendered
    assert INSTALLED.format(90) in out


# ---- the Active Directory write ---------------------------------------------


#: The plan id of the Active Directory write of the tests.
AD_PLAN_ID = "0123456789abcdef0123456789abcdef"


def _ad_plan(verb: str, window: int) -> dict[str, Any]:
    """An Active Directory write plan of one verb."""
    return {
        "v": 1,
        "plan_id": AD_PLAN_ID,
        "txid": "a" * 32,
        "device": "win-dc1",
        "domain": "win-dc1",
        "pdc": "win-dc1",
        "verb": verb,
        "target": {
            "guid": "6f9619ff-8b86-d011-b42d-00c04fc964ff",
            "sid": "S-1-5-21-1-2-3-1105",
            "sam": "seed-asrep",
        },
        "before": {"uac": 512},
        "after": {"uac": 514},
        "window": window,
        "risk": "MED",
        "facts": {},
        "created_at": "2026-11-25T12:00:00+00:00",
        "digest": "0" * 64,
    }


def _ad_approval(
    tmp_path: Path, monkeypatch: Any, capsys: Any, plan: dict[str, Any]
) -> list[str]:
    """The lines the approval of an Active Directory write shows."""
    path = tmp_path / "state" / "ad-plans" / f"{AD_PLAN_ID}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(plan), encoding="utf-8")
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setattr(approve, "_getpass", refuse_getpass)
    monkeypatch.setattr(approve.sys, "stdin", TerminalInput("no\n"))
    ok, _refusal = approve.approve_ad_change(AD_PLAN_ID)
    assert ok is False
    return capsys.readouterr().out.splitlines()


def test_the_ad_write_shows_the_pdc_line_after_the_undo_line(
    tmp_path: Path, monkeypatch: Any, capsys: Any
) -> None:
    """The Active Directory write says what puts the change back."""
    lines = _ad_approval(tmp_path, monkeypatch, capsys, _ad_plan("disable", 600))
    undo = "Undo: the PDC puts it back 600s after the apply unless Newton confirms"
    assert any(line.startswith(undo) for line in lines), lines
    assert AD_PDC.format(600) in lines
    index = lines.index(AD_PDC.format(600))
    assert index == next(
        number for number, line in enumerate(lines) if line.startswith(undo)
    ) + 1


def test_the_ad_unlock_shows_the_unlock_line(
    tmp_path: Path, monkeypatch: Any, capsys: Any
) -> None:
    """An unlock arms no undo, so the line says that nothing is put back."""
    lines = _ad_approval(tmp_path, monkeypatch, capsys, _ad_plan("unlock", 120))
    assert AD_UNLOCK in lines
    assert lines.index(AD_UNLOCK) == lines.index("Undo: none, this stays written") + 1


# ---- the Active Directory build stage ---------------------------------------


#: The plan id of the build of the tests.
BUILD_PLAN_ID = "0123456789abcdef0123456789abcdef"

#: The instant the approvals of the build are made at.
BUILD_NOW = datetime(2027, 1, 1, tzinfo=timezone.utc)

#: The passphrase of the owner in the build tests.
BUILD_PASSPHRASE = "correct horse battery staple"

#: The id of the checkpoint of the build tests.
CHECKPOINT_ID = "3f2b1c4d-5e6f-4a8b-9c0d-1e2f3a4b5c6d"

#: The name of the checkpoint of the build tests.
CHECKPOINT_NAME = "m-hvcp-1"


def _ed25519_key(first: int) -> str:
    """One synthetic ed25519 public key."""
    return "ssh-ed25519 " + base64.b64encode(
        b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + bytes(range(first, first + 32))
    ).decode("ascii")


#: The inputs of the build of the tests: two servers, one baseline option,
#: one finding.  Every value is synthetic (RFC 5737 addresses).
BUILD_INPUTS: dict[str, Any] = {
    "domain": {
        "dns_name": "ad-build.test",
        "netbios": "ADBUILD",
        "functional_level": "Win2025",
        "site": "Default-First-Site-Name",
        "ou_tree": ["IT/Servers", "IT/Workstations"],
        "groups": ["IT Admins", "IT Operators"],
        "owner_admin": "owner-admin",
    },
    "servers": [
        {
            "device": "build1",
            "role": "dc1",
            "hostname": "DC1",
            "ip": "192.0.2.11",
            "prefix": 24,
            "gateway": "192.0.2.1",
            "forwarders": ["192.0.2.53"],
            "checkpoint": "hyperv",
        },
        {
            "device": "build2",
            "role": "dc2",
            "hostname": "DC2",
            "ip": "192.0.2.12",
            "prefix": 24,
            "gateway": "192.0.2.1",
            "forwarders": ["192.0.2.53"],
            "checkpoint": "proxmox",
            "vmgenid": "44387c6b-1f2e-4a5b-8c9d-0e1f2a3b4c5d",
            "agent": 1,
        },
    ],
    "baseline": {
        "version": "2026.11",
        "options": {"administrator": "random-password"},
    },
    "accepted_findings": [{"id": "AD-A-51", "reason": "owner-accepted"}],
    "ops": {
        "audit_public_key": _ed25519_key(64),
        "public_key": _ed25519_key(0),
        "write_helper_sha256": "0" * 64,
    },
}


class _Verifier:
    """The checkpoint adapter of the build tests: it verifies."""

    def verify(
        self,
        server_cfg: dict[str, Any],
        cp: dict[str, Any],
        kind: str,
        *,
        stage: str,
        not_before: int,
    ) -> bool:
        return True


class _Transport:
    """The helper transport of the build tests: every stage is done."""

    def __init__(self, done_at: int) -> None:
        self.done_at = done_at

    def send(self, device: str, request: dict[str, Any]) -> dict[str, Any]:
        completed = {stage: self.done_at for stage in build_plan.STAGE_IDS}
        return {
            "ok": True,
            "status": "done",
            "code": "",
            "checks": [],
            "completed": completed,
        }


def _write_build_run_state(
    tmp_path: Path, built: dict[str, Any], stage: str = "2"
) -> None:
    """The runner's state of one build, as the runner writes it."""
    path = tmp_path / "state" / "ad-build-plans" / f"{BUILD_PLAN_ID}.run.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "plan_id": BUILD_PLAN_ID,
                "plan_digest": build_plan.digest(built),
                "state": "stopped_for_approval",
                "stage": stage,
                "servers": {
                    "build1": {
                        "stage": stage,
                        "state": "stopped_for_approval",
                        "checkpoint": {"name": CHECKPOINT_NAME, "id": CHECKPOINT_ID},
                        "checkpoint_kind": "workgroup",
                    },
                },
            }
        ),
        encoding="utf-8",
    )


def test_the_ad_build_stage_approval_shows_the_stage_line_once_before_the_prompt(
    tmp_path: Path, monkeypatch: Any, capsys: Any
) -> None:
    """The stage approval says what a lost contact leaves behind."""
    built = build_plan.plan_build(copy.deepcopy(BUILD_INPUTS))
    path = tmp_path / "state" / "ad-build-plans" / f"{BUILD_PLAN_ID}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(built), encoding="utf-8")
    monkeypatch.setattr(
        approve, "_getpass", lambda prompt: BUILD_PASSPHRASE, raising=True
    )
    monkeypatch.setattr(
        approve.sys, "stdin", TerminalInput(f"approve {BUILD_PLAN_ID[:8]}\n")
    )
    assert approve.approve_ad_build(BUILD_PLAN_ID, now=BUILD_NOW) == 0
    capsys.readouterr()

    _write_build_run_state(tmp_path, built)
    monkeypatch.setattr(
        approve.sys, "stdin", TerminalInput(f"approve stage 2 of {BUILD_PLAN_ID[:8]}\n")
    )
    assert (
        approve.approve_ad_build_stage(
            BUILD_PLAN_ID,
            "2",
            verifier=_Verifier(),
            transport=_Transport(int(BUILD_NOW.timestamp()) - 3600),
            now=BUILD_NOW,
        )
        == 0
    )

    out = capsys.readouterr().out
    assert out.count(BUILD) == 1, out
    assert out.index(BUILD) < out.index("Type 'approve stage 2 of")
