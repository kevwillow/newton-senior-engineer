"""The Samba write helper marks the refusals of its own install check, and
its sweep timer neither binds once per stuck record nor reads healthy while
an expired change stays armed.  The Windows helper marks its install check
the same way (read in the script: no PowerShell runs here)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from test_samba_write_helper import (  # noqa: F401  (dc is a fixture)
    NBF,
    TXID,
    Dc,
    _run_main,
    dc,
    dump,
)

MCP_ROOT = Path(__file__).resolve().parents[2]
WINDOWS_HELPER = MCP_ROOT / "newton_mcp" / "ad" / "collector" / "write.ps1"

SECOND = "fedcba9876543210fedcba9876543211"


# ---- the install check ------------------------------------------------------


def test_a_login_that_is_not_the_write_login_is_marked_install(dc: Dc) -> None:
    answer = dc.helper.handle([], dump(dc.request()), {"SUDO_USER": "root"})

    assert answer == {"v": 1, "code": "denied", "stage": "install"}


def test_an_unsafe_install_is_marked_install(dc: Dc) -> None:
    dc.tx.chmod(0o777)

    answer = dc.run(dc.request())

    assert answer == {"v": 1, "code": "unavailable", "stage": "install"}


@pytest.mark.parametrize("problem", ["mode", "name"])
def test_a_device_file_that_cannot_be_used_is_marked_install(dc: Dc, problem: str) -> None:
    device = dc.config / "device.txt"
    if problem == "mode":
        device.chmod(0o666)
    else:
        device.write_text("Not A Device Name!\n", encoding="utf-8")

    answer = dc.run(dc.request())

    assert answer == {"v": 1, "code": "unavailable", "stage": "install"}


def test_a_refusal_after_the_install_check_is_never_marked_install(dc: Dc) -> None:
    """A key that others may read is refused inside the apply, after the
    request was read: that refusal is not one of the install check."""
    (dc.config / "approval.key").chmod(0o644)

    answer = dc.run(dc.request())

    assert answer["code"] == "unavailable"
    assert "stage" not in answer


def test_a_schema_refusal_is_never_marked_install(dc: Dc) -> None:
    answer = dc.run(b"not json")

    assert answer["code"] == "schema"
    assert "stage" not in answer


def test_the_windows_helper_marks_its_install_check() -> None:
    text = WINDOWS_HELPER.read_text(encoding="utf-8")
    main = text[text.index("$install = Test-NewtonInstall"):]
    main = main[: main.index("} elseif ($args.Count -gt 0)")]
    assert "New-NewtonResponse $install" in main
    assert "['stage'] = 'install'" in main


# ---- the sweep timer --------------------------------------------------------


def _two_stuck_records(dc: Dc) -> None:
    """Two armed records past their undo_at."""
    assert dc.run(dc.request())["code"] == "ok"
    record = dc.record()
    record["txid"] = SECOND
    (dc.tx / f"{SECOND}.json").write_text(json.dumps(record), encoding="utf-8")
    dc.helper.current_time = lambda: float(NBF + 601)


def test_a_sweep_whose_bind_fails_binds_once_per_pass(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    _two_stuck_records(dc)
    binds: list[int] = []

    def down() -> Any:
        binds.append(1)
        raise dc.helper.Refused("unavailable", "kinit failed")

    monkeypatch.setattr(dc.helper, "bind", down)

    dc.helper.handle(["--sweep"], b"", {})

    assert len(binds) == 1
    assert dc.record()["state"] == "armed"
    assert dc.record(SECOND)["state"] == "armed"


def test_a_sweep_that_leaves_an_expired_change_armed_exits_non_zero(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    """systemctl status of the sweep unit is where the owner looks: an
    expired change whose undo could not run fails the unit."""
    _two_stuck_records(dc)

    def down() -> Any:
        raise dc.helper.Refused("unavailable", "kinit failed")

    monkeypatch.setattr(dc.helper, "bind", down)

    status, answer = _run_main(dc, monkeypatch, ["--sweep"])

    assert answer["code"] == "error"
    assert status != 0


def test_a_request_still_goes_on_when_the_sweep_leaves_a_change_armed(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    _two_stuck_records(dc)
    real = dc.helper.bind
    calls: list[int] = []

    def first_fails() -> Any:
        calls.append(1)
        if len(calls) == 1:
            raise dc.helper.Refused("unavailable", "kinit failed")
        return real()

    monkeypatch.setattr(dc.helper, "bind", first_fails)

    answer = dc.run({"v": 1, "mode": "status", "device": dc.request()["device"], "txid": TXID})

    assert answer["code"] == "ok"
