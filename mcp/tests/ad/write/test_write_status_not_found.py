"""An AD status the DC answers not_found always says what it means."""

from __future__ import annotations

from pathlib import Path

import pytest

from newton_mcp import server
from newton_mcp.ad.write import apply as ad_apply

from test_write_apply import _approved_plan, _lab


@pytest.fixture(autouse=True)
def state_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "state"
    monkeypatch.setenv("NEWTON_STATE_DIR", str(root))
    return root


def test_a_plan_never_applied_answers_not_found_with_a_message() -> None:
    """No receipt, no record on the DC: the answer says the DC holds no
    record of the change instead of a bare code."""
    lab = _lab()
    plan_id = _approved_plan(lab)

    status = ad_apply.change_status(plan_id, send=lab.send, devices=lab.devices)

    assert status["code"] == "not_found"
    message = " ".join(str(status.get("message", "")).split())
    assert message == " ".join(ad_apply.NOT_FOUND_MESSAGE.split())
    assert "holds no record of this change" in message


def test_the_status_description_names_not_found() -> None:
    tool = server.mcp._tool_manager.get_tool("newton_ad_change_status")
    flat = " ".join((tool.description or "").split())
    assert "armed, confirmed, undone, undo_failed, refused or not_found" in flat
    assert "holds no record of this change" in flat
