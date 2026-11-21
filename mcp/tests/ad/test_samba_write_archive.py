"""The sweep of the Samba write helper reads only the records that
can still need it.  A final record (undone, confirmed, refused, undo_failed)
moves to the store's archive once ARCHIVE_AFTER_S has passed its undo_at;
status, confirm, abort, undo and the replay check still find it there."""

from __future__ import annotations

import json
from typing import Any

import pytest

import fake_samba_write
from test_samba_write_helper import DEVICE, NBF, TXID, Dc, _unlock, dc  # noqa: F401

WEEK = 7 * 86400


def _status(dc: Dc, txid: str = TXID) -> dict[str, Any]:
    return dc.run({"v": 1, "mode": "status", "device": DEVICE, "txid": txid})


def _confirmed(dc: Dc) -> None:
    assert dc.run(dc.request())["code"] == "ok"
    answer = dc.run({"v": 1, "mode": "confirm", "device": DEVICE, "txid": TXID})
    assert answer["code"] == "ok"
    assert dc.record()["state"] == "confirmed"


def _at(dc: Dc, moment: int) -> None:
    dc.helper.current_time = lambda: float(moment)


def _archived(dc: Dc, txid: str = TXID) -> Any:
    return dc.tx / dc.helper.ARCHIVE_NAME / f"{txid}.json"


def _counting_reads(dc: Dc, monkeypatch: pytest.MonkeyPatch) -> list[str]:
    reads: list[str] = []
    real = dc.helper.read_record

    def counted(path: str) -> Any:
        reads.append(path)
        return real(path)

    monkeypatch.setattr(dc.helper, "read_record", counted)
    return reads


def test_a_final_record_past_the_window_moves_to_the_archive(dc: Dc) -> None:
    _confirmed(dc)
    undo_at = dc.record()["undo_at"]
    _at(dc, undo_at + WEEK)

    assert dc.helper.handle(["--sweep"], b"", {})["code"] == "ok"

    assert dc.records() == []
    assert json.loads(_archived(dc).read_text())["state"] == "confirmed"
    assert (_archived(dc).parent.stat().st_mode & 0o777) == 0o700


def test_a_final_record_inside_the_window_stays(dc: Dc) -> None:
    _confirmed(dc)
    _at(dc, dc.record()["undo_at"] + WEEK - 1)

    assert dc.helper.handle(["--sweep"], b"", {})["code"] == "ok"

    assert dc.records() == [f"{TXID}.json"]
    assert not _archived(dc).exists()


def test_an_armed_record_is_never_archived(dc: Dc) -> None:
    """An unlock the sweep could not settle stays armed for good: it stays
    in the store, however old."""
    payload = _unlock(dc)
    dc.fake.set_attribute(fake_samba_write.ALICE_DN, "lockoutTime", "1000")
    real = dc.helper.read_back
    dc.helper.read_back = lambda *args, **kwargs: {"lockout": 1000}
    try:
        dc.run(payload)
    finally:
        dc.helper.read_back = real
    record = dc.record()
    if record["state"] != "armed":
        record["state"] = "armed"
        (dc.tx / f"{TXID}.json").write_text(json.dumps(record))
    _at(dc, record["undo_at"] + 10 * WEEK)

    assert dc.helper.handle(["--sweep"], b"", {})["code"] == "ok"

    assert dc.records() == [f"{TXID}.json"]
    assert not _archived(dc).exists()


def test_the_sweep_stops_reading_archived_records(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    _confirmed(dc)
    _at(dc, dc.record()["undo_at"] + WEEK)
    dc.helper.handle(["--sweep"], b"", {})
    reads = _counting_reads(dc, monkeypatch)

    assert dc.helper.handle(["--sweep"], b"", {})["code"] == "ok"

    assert reads == []


def test_an_archived_record_still_answers_status_abort_undo_and_replay(
    dc: Dc,
) -> None:
    _confirmed(dc)
    later = dc.record()["undo_at"] + WEEK
    _at(dc, later)
    dc.helper.handle(["--sweep"], b"", {})
    assert dc.records() == []

    status = _status(dc)
    assert status["code"] == "ok"
    assert status["state"] == "confirmed"

    abort = dc.run({"v": 1, "mode": "abort", "device": DEVICE, "txid": TXID})
    assert abort["code"] == "conflict"

    undo = dc.undo()
    assert undo["code"] == "ok"
    assert undo["restored"] is False

    # a fresh approval of the same txid is a replay, never a second write
    again = dc.run(dc.request(nbf=later, exp=later + 600))
    assert again["code"] == "replay"
    assert dc.records() == []
    assert json.loads(_archived(dc).read_text())["state"] == "confirmed"


def test_a_failed_move_leaves_the_record_in_the_store(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    _confirmed(dc)
    _at(dc, dc.record()["undo_at"] + WEEK)

    def refused(*args: Any, **kwargs: Any) -> None:
        raise OSError("read-only")

    monkeypatch.setattr(dc.helper.os, "rename", refused)

    assert dc.helper.handle(["--sweep"], b"", {})["code"] == "ok"

    assert dc.records() == [f"{TXID}.json"]
    assert _status(dc)["state"] == "confirmed"


def test_a_record_of_an_unknown_state_is_never_archived(dc: Dc) -> None:
    _confirmed(dc)
    record = dc.record()
    record["state"] = "some-later-state"
    (dc.tx / f"{TXID}.json").write_text(json.dumps(record))
    _at(dc, record["undo_at"] + 10 * WEEK)

    assert dc.helper.handle(["--sweep"], b"", {})["code"] == "ok"

    assert dc.records() == [f"{TXID}.json"]
    assert not _archived(dc).exists()


def test_a_confirm_of_an_archived_record_reads_it_there(dc: Dc) -> None:
    """A confirm of an archived txid answers as it did before the move,
    never not_found, and never puts a record back in the store."""
    _confirmed(dc)
    _at(dc, dc.record()["undo_at"] + WEEK)
    dc.helper.handle(["--sweep"], b"", {})

    answer = dc.run({"v": 1, "mode": "confirm", "device": DEVICE, "txid": TXID})

    assert answer["code"] == "ok"
    assert dc.records() == []
    assert json.loads(_archived(dc).read_text())["state"] == "confirmed"


def test_an_archived_record_of_the_same_name_is_never_overwritten(dc: Dc) -> None:
    _confirmed(dc)
    _at(dc, dc.record()["undo_at"] + WEEK)
    archive = _archived(dc).parent
    archive.mkdir(mode=0o700)
    archive.chmod(0o700)
    _archived(dc).write_text('{"state":"undone"}')

    assert dc.helper.handle(["--sweep"], b"", {})["code"] == "ok"

    assert dc.records() == [f"{TXID}.json"]
    assert _archived(dc).read_text() == '{"state":"undone"}'


@pytest.mark.parametrize("kind", ["mode", "file"])
def test_an_archive_that_is_not_root_0700_is_never_used(dc: Dc, kind: str) -> None:
    _confirmed(dc)
    _at(dc, dc.record()["undo_at"] + WEEK)
    archive = _archived(dc).parent
    if kind == "mode":
        archive.mkdir()
        archive.chmod(0o755)
    else:
        archive.write_text("not a directory")

    assert dc.helper.handle(["--sweep"], b"", {})["code"] == "ok"

    assert dc.records() == [f"{TXID}.json"]
    assert _status(dc)["state"] == "confirmed"


def test_an_archive_of_another_owner_is_never_used(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    _confirmed(dc)
    now = dc.record()["undo_at"] + WEEK
    archive = _archived(dc).parent
    archive.mkdir(mode=0o700)
    archive.chmod(0o700)
    # the archive is owned by the test's uid; the helper now wants another
    monkeypatch.setattr(dc.helper, "INSTALL_OWNER_UID", archive.stat().st_uid + 1)

    assert dc.helper.sweep(now) is True

    assert dc.records() == [f"{TXID}.json"]
    assert not _archived(dc).exists()
