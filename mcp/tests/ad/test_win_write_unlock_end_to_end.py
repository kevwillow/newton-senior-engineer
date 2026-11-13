"""An unlock on Windows, from the plan to the confirm, through the real helper.

CORE plans the unlock and applies it with ``newton_mcp.ad.write.plan`` and
``newton_mcp.ad.write.apply``; every request goes to the Windows helper
(``write.ps1``) run by the harness of ``win_write_harness.ps1`` against the
fake directory.  An unlock arms no undo and its record is confirmed at the
apply (SPEC-1.4-REQUEST section 3), so the confirm CORE sends once every DC
shows the after-image must answer ok and the change ends confirmed.

The harness starts from an empty store on every run, so the sender replays
every request CORE sent so far and answers with the last one: the store and
the directory are then the ones the helper would hold.

The tests are skipped, with a reason, when PowerShell 7.4 is not installed.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any, Mapping

import pytest

from newton_mcp.ad.write import apply as ad_apply, plan as ad_plan, request, store
from newton_mcp.server import Device
from pwsh_path import PWSH
from test_win_write_modes import (
    DEVICE,
    HARNESS,
    KEY_HEX,
    OU_GUID,
    OU_USERS,
    SEED_GUID,
    SEED_SAM,
    SEED_SID,
    _directory,
    _object,
)


NBF = 1800000000
EXP = 1800000600


@pytest.fixture(autouse=True)
def state_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """The state directory of the test."""
    root = tmp_path / "state"
    monkeypatch.setenv("NEWTON_STATE_DIR", str(root))
    return root


def _pwsh() -> str:
    """The shell of the tests, or a skip."""
    if not PWSH.is_file():
        pytest.skip(
            f"PowerShell 7.4 is not installed at {PWSH}: the Windows write "
            "helper cannot be exercised"
        )
    return str(PWSH)


def _locked_directory() -> dict[str, Any]:
    """The directory of the tests, with the seed account locked out."""
    return _directory(
        objects=[
            _object(
                f"CN={SEED_SAM},{OU_USERS}",
                SEED_GUID,
                SEED_SID,
                SEED_SAM,
                uac=512,
                lockout=1000,
                parent=OU_USERS,
            ),
            _object(
                OU_USERS,
                OU_GUID,
                None,
                None,
                object_class=["top", "organizationalUnit"],
            ),
        ]
    )


class WindowsDc:
    """The one DC of the domain: the real helper, replayed by the harness."""

    def __init__(self, workdir: Path, ldap: dict[str, Any]) -> None:
        self.workdir = workdir
        self.ldap = ldap
        self.sent: list[dict[str, Any]] = []
        self.last: dict[str, Any] = {}
        self.device = Device(
            name=DEVICE,
            platform="ad-windows-write",
            host="192.0.2.10",
            user="newton-ops@win.newton.test",
            ad_domain=DEVICE,
            ad_domain_guid="af9619ff-8b86-d011-b42d-00c04fc964ff",
        )

    def send(self, target: Any, body: Mapping[str, Any]) -> dict[str, Any]:
        """Replay every request so far, and answer with the last one."""
        assert target.name == DEVICE
        self.sent.append(dict(body))
        case = {
            "id": "unlock",
            "device": DEVICE,
            "ldap": self.ldap,
            "requests": [
                {"raw": json.dumps(one, sort_keys=True, separators=(",", ":")), "stage": "write"}
                for one in self.sent
            ],
        }
        path = self.workdir / f"case-{len(self.sent)}.json"
        path.write_text(json.dumps({"cases": [case]}), encoding="utf-8")
        finished = subprocess.run(
            [_pwsh(), "-NoProfile", "-NonInteractive", "-File", str(HARNESS), str(path)],
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
        assert finished.returncode == 0, finished.stderr[:2000]
        self.last = json.loads(finished.stdout)["cases"][0]
        result = self.last["results"][-1]
        response = result["response"]
        if not isinstance(response, dict):
            return {"v": 1, "code": result["code"]}
        return response

    def current_record(self, txid: str) -> dict[str, Any]:
        """The record of the transaction with the highest generation."""
        best: tuple[int, str] | None = None
        for name in self.last["files"]:
            prefix, suffix = txid + ".", ".json"
            if name.startswith(prefix) and name.endswith(suffix):
                generation = name[len(prefix) : -len(suffix)]
                if generation.isdigit() and (best is None or int(generation) > best[0]):
                    best = (int(generation), name)
        assert best is not None, "the transaction has no record"
        return json.loads(self.last["files"][best[1]])


def _approve(plan_id: str) -> None:
    """The approval of the plan, minted with the key of the lab."""
    record = store.read_json(store.plan_path(plan_id))
    digest = request.digest(record)
    store.write_json(
        store.approval_path(plan_id),
        {
            "plan_id": plan_id,
            "device": record["device"],
            "digest": digest,
            "nbf": NBF,
            "exp": EXP,
            "token": request.token(KEY_HEX, digest, NBF, EXP),
        },
    )


def test_a_verified_unlock_on_windows_ends_confirmed(tmp_path: Path) -> None:
    """Plan, apply, verify and confirm an unlock: the change is confirmed."""
    _pwsh()
    dc = WindowsDc(tmp_path, _locked_directory())
    devices = {DEVICE: dc.device}

    planned = ad_plan.plan_change(DEVICE, "unlock", [SEED_SAM], send=dc.send, devices=devices)
    assert planned["before"] == {"lockout": 1000}
    assert planned["after"] == {"lockout": 0}
    plan_id = str(planned["plan_id"])
    _approve(plan_id)

    result = ad_apply.apply_change(plan_id, send=dc.send, devices=devices, timeout_s=0.0)

    modes = [str(one["mode"]) for one in dc.sent]
    assert modes[-1] == "confirm"
    assert "abort" not in modes
    assert result["dcs"][DEVICE]["state"] == "matched"
    assert result["code"] == "ok"
    assert result["state"] == "confirmed"
    assert result["result"] == "ok"
    assert dc.current_record(str(planned["txid"]))["state"] == "confirmed"
    # an unlock arms no undo: no task was ever registered
    assert dc.last["tasks"] == []
