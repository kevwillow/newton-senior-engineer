"""The Samba write helper reports only outcomes the directory makes true.

A record state or answer the helper writes must be one the directory makes
true: a record is never refused while a write may still land, never undone
while the change is still there, and never left armed with nothing to run
its undo.
"""

from __future__ import annotations

import configparser
import copy
import json
from pathlib import Path
from typing import Any

import pytest

import fake_samba_write

from newton_mcp.ad import setupgen_write as write
from newton_mcp.ad.write import apply as core_apply
from newton_mcp.ad.write import request as core_request
from test_samba_write_helper import (  # noqa: F401  (dc is a fixture)
    DEVICE,
    KEY_HEX,
    NBF,
    SECRET,
    TXID,
    Dc,
    _move_request,
    _unlock,
    dc,
)


MCP_ROOT = Path(__file__).resolve().parents[2]
README = MCP_ROOT / "newton_mcp" / "ad" / "collector" / "README-samba-write.md"

#: A second transaction, whose undo always raises.
POISON = "fedcba9876543210fedcba9876543210"


def _status(dc: Dc, txid: str = TXID) -> dict[str, Any]:
    return dc.run({"v": 1, "mode": "status", "device": DEVICE, "txid": txid})


def _plant_poisoned_record(dc: Dc, monkeypatch: pytest.MonkeyPatch) -> None:
    """An expired armed record whose undo always raises (a search that
    fails with an LDB error, say), and a run_undo that raises for it.  Its
    target is another account: an armed record of the same target refuses
    the apply (see the guard tests at the end of this file)."""
    request = {k: v for k, v in dc.request(txid=POISON).items() if k != "token"}
    request["target"] = {"guid": fake_samba_write.BOB_GUID, "sid": fake_samba_write.BOB_SID,
                         "sam": "bob", "bit": 4194304}
    record = {
        "v": 1,
        "txid": POISON,
        "request": request,
        "state": "armed",
        "undo_at": NBF - 1,
        "restored": False,
        "conflicts": [],
        "created": None,
        "created_usnchanged": None,
    }
    (dc.tx / f"{POISON}.json").write_text(json.dumps(record), encoding="utf-8")
    real = dc.helper.undo_attribute

    def poisoned(directory: Any, record: Any) -> Any:
        if record.get("txid") == POISON:
            raise directory.ldb.LdbError(51, "busy")
        return real(directory, record)

    monkeypatch.setattr(dc.helper, "undo_attribute", poisoned)


# ---- one poisoned record never stops the others -------------------------


def test_a_poisoned_record_does_not_stop_another_transactions_undo(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert dc.run(dc.request())["code"] == "ok"
    _plant_poisoned_record(dc, monkeypatch)
    dc.helper.current_time = lambda: float(NBF + 601)

    answer = dc.undo()

    assert answer["code"] == "ok"
    assert answer["restored"] is True
    assert dc.record()["state"] == "undone"
    assert dc.fake.get_attribute(fake_samba_write.ALICE_DN, "userAccountControl") == "4194816"
    # the poisoned record is left armed, so a later pass tries it again
    assert dc.record(POISON)["state"] == "armed"


@pytest.mark.parametrize("mode", ["apply", "status", "confirm"])
def test_a_poisoned_record_does_not_stop_a_stdin_mode(
    dc: Dc, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    _plant_poisoned_record(dc, monkeypatch)
    if mode != "apply":
        assert dc.run(dc.request())["code"] == "ok"

    if mode == "apply":
        answer = dc.run(dc.request())
    else:
        answer = dc.run({"v": 1, "mode": mode, "device": DEVICE, "txid": TXID})

    assert answer["code"] == "ok"
    assert dc.record(POISON)["state"] == "armed"


# ---- a persistent sweep --------------------------------------------------


def test_the_sweep_mode_undoes_an_expired_armed_record(dc: Dc) -> None:
    """The sweep-only mode the sweep timer runs: an expired record whose
    one-shot timer was lost (a reboot) or whose undo failed is undone."""
    assert dc.run(dc.request())["code"] == "ok"
    dc.helper.current_time = lambda: float(NBF + 601)

    answer = dc.helper.handle(["--sweep"], b"", {})

    assert answer == {"v": 1, "code": "ok"}
    assert dc.record()["state"] == "undone"
    assert dc.fake.get_attribute(fake_samba_write.ALICE_DN, "userAccountControl") == "4194816"


def test_the_sweep_mode_retries_an_undo_whose_bind_failed(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert dc.run(dc.request())["code"] == "ok"
    dc.helper.current_time = lambda: float(NBF + 601)
    real = dc.helper.bind

    def down() -> Any:
        raise dc.helper.Refused("unavailable", "kinit failed")

    monkeypatch.setattr(dc.helper, "bind", down)
    assert dc.undo()["code"] == "unavailable"
    assert dc.record()["state"] == "armed"

    monkeypatch.setattr(dc.helper, "bind", real)
    assert dc.helper.handle(["--sweep"], b"", {})["code"] == "ok"
    assert dc.record()["state"] == "undone"


def test_the_sweep_mode_never_runs_through_the_ssh_channel(dc: Dc) -> None:
    answer = dc.helper.handle(["--sweep"], b"", {"SUDO_USER": "newton-ops-ssh"})
    assert answer["code"] == "denied"


def test_the_sweep_mode_takes_no_argument(dc: Dc) -> None:
    assert dc.helper.handle(["--sweep", TXID], b"", {})["code"] == "schema"


def _unit(script: str, name: str) -> configparser.ConfigParser:
    marker = f"cat > \"${{WORK_DIR}}/{name}\" <<'NEWTON_AD_UNIT_EOF'"
    start = script.index(marker) + len(marker)
    end = script.index("NEWTON_AD_UNIT_EOF", start)
    parser = configparser.ConfigParser(interpolation=None)
    parser.optionxform = str  # type: ignore[assignment]
    parser.read_string(script[start:end])
    return parser


@pytest.fixture
def samba_script() -> str:
    return write.samba_write_script(
        domain="lab.newton.test",
        pubkey=write.validate_public_key(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ),
        device="sambadc1",
        host="sambadc1.lab.newton.test",
        ous=["OU=Users,DC=lab,DC=newton,DC=test"],
    )


def test_the_setup_installs_a_sweep_service_that_runs_the_sweep_mode(samba_script: str) -> None:
    service = _unit(samba_script, "newton-ad-sweep.service")
    assert service["Service"]["Type"] == "oneshot"
    assert service["Service"]["ExecStart"] == "/usr/local/sbin/newton-ad-samba-write --sweep"


def test_the_setup_installs_a_persistent_sweep_timer(samba_script: str) -> None:
    timer = _unit(samba_script, "newton-ad-sweep.timer")
    assert timer["Timer"]["OnBootSec"] == "60"
    assert timer["Timer"]["OnUnitActiveSec"] == "60"
    assert timer["Timer"]["Unit"] == "newton-ad-sweep.service"
    assert timer["Install"]["WantedBy"] == "timers.target"


def test_the_setup_enables_the_timer_before_the_sudoers_line(samba_script: str) -> None:
    for unit in ("newton-ad-sweep.service", "newton-ad-sweep.timer"):
        assert (
            f'install -m 0644 -o root -g root "${{WORK_DIR}}/{unit}" '
            f'"/etc/systemd/system/{unit}"'
        ) in samba_script
    enable = samba_script.index("systemctl enable --now newton-ad-sweep.timer")
    assert samba_script.index("systemctl daemon-reload") < enable
    assert enable < samba_script.index('install -m 0440 -o root -g root "${SUDOERS_TMP}"')


# ---- a failed write is recorded by what the directory shows -----


def _user_create(dc: Dc) -> dict[str, Any]:
    payload = dc.request(verb="user-create")
    payload["secret"] = SECRET
    payload["target"] = {"parent_guid": fake_samba_write.SERVERS_OU_GUID, "sam": "newton-user"}
    payload["before"] = {"object": "absent"}
    payload["after"] = {"object": "present"}
    payload["token"] = core_request.token(
        KEY_HEX, core_request.digest(payload), payload["nbf"], payload["exp"]
    )
    return payload


@pytest.mark.parametrize("code", [19, 53])
def test_a_user_create_add_the_dc_refused_is_recorded_refused(dc: Dc, code: int) -> None:
    dc.fake.add_code = code

    answer = dc.run(_user_create(dc))

    assert answer["code"] == "error"
    record = dc.record()
    assert record["state"] == "refused"
    assert record["restored"] is False
    assert not dc.fake.has_object("CN=newton-user," + fake_samba_write.SERVERS_OU_DN)


def test_a_user_create_add_that_found_the_name_taken_is_a_conflict(dc: Dc) -> None:
    dc.fake.add_code = 68

    answer = dc.run(_user_create(dc))

    assert answer["code"] == "conflict"
    assert dc.record()["state"] == "refused"


@pytest.mark.parametrize(("code", "word"), [(50, "denied"), (53, "error"), (19, "error")])
def test_a_write_the_dc_refused_is_recorded_refused_not_undone(
    dc: Dc, code: int, word: str
) -> None:
    dc.fake.modify_code = code

    answer = dc.run(dc.request())

    assert answer["code"] == word
    record = dc.record()
    assert record["state"] == "refused"
    assert record["restored"] is False
    assert dc.fake.get_attribute(fake_samba_write.ALICE_DN, "userAccountControl") == "4194816"


@pytest.mark.parametrize("code", [1, 51, 52, 80])
def test_a_write_with_an_uncertain_code_stays_armed_with_its_timer(dc: Dc, code: int) -> None:
    """A code that may be the client's own (a lost connection, a busy or
    unavailable server) does not prove nothing was written: the record
    stays armed and the timer is not cancelled, so the undo runs later."""
    dc.fake.modify_code = code

    answer = dc.run(dc.request())

    assert answer["code"] == "error"
    assert dc.record()["state"] == "armed"
    assert not [line for line in dc.log_lines() if "systemctl" in line]


def test_a_write_whose_re_read_fails_stays_armed(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    dc.fake.modify_code = 50

    def failing(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("the re-read failed")

    monkeypatch.setattr(dc.helper, "read_back", failing)

    dc.run(dc.request())

    assert dc.record()["state"] == "armed"
    assert not [line for line in dc.log_lines() if "systemctl" in line]


# ---- an unlock whose write got no answer -------------------------


def test_an_unlock_whose_write_had_an_uncertain_code_stays_armed(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    def failing(directory: Any, request: Any) -> Any:
        raise directory.ldb.LdbError(80, "other")

    monkeypatch.setattr(dc.helper, "write_after", failing)

    dc.run(_unlock(dc))

    assert dc.record()["state"] == "armed"
    assert dc.fake.get_attribute(fake_samba_write.ALICE_DN, "lockoutTime") == "1000"


# ---- the abort of an unlock ---------------------------------------------


def test_the_abort_of_an_armed_unlock_is_refused_with_conflict(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = dc.helper.read_back

    def failing(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("the read-back failed")

    monkeypatch.setattr(dc.helper, "read_back", failing)
    dc.run(_unlock(dc))
    assert dc.record()["state"] == "armed"
    monkeypatch.setattr(dc.helper, "read_back", real)

    answer = dc.run({"v": 1, "mode": "abort", "device": DEVICE, "txid": TXID})

    assert answer["code"] == "conflict"
    assert dc.record()["state"] == "armed"
    assert dc.fake.get_attribute(fake_samba_write.ALICE_DN, "lockoutTime") == "0"


# ---- the sweep says what it does ----------------------------------------


def test_the_sweep_docstring_does_not_claim_a_record_it_did_not_undo_stays_armed(dc: Dc) -> None:
    doc = " ".join(str(dc.helper.sweep.__doc__).split())
    assert "never confirms anything" not in doc
    assert "a record it did not undo stays armed" not in doc
    assert "undo_failed" in doc


def test_the_readme_says_what_the_sweep_and_the_undo_record() -> None:
    text = " ".join(README.read_text(encoding="utf-8").split())
    assert "it never confirms anything" not in text
    assert "an object that is not there any more leaves the record in `undo_failed`" not in text
    assert "newton-ad-sweep.timer" in text


def test_a_user_create_that_landed_with_a_lost_answer_is_never_refused(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The add landed and its answer was lost; reading the undo facts of
    the new object then fails too.  The record is never refused, which
    would say nothing changed: the object found at the DN is left (it may
    not be Newton's) and the record says it is still there."""
    real = dc.helper.write_after

    def landed_then_lost(directory: Any, request: Any) -> Any:
        real(directory, request)
        raise directory.ldb.LdbError(80, "the answer was lost")

    def failing(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("the read failed")

    monkeypatch.setattr(dc.helper, "write_after", landed_then_lost)
    monkeypatch.setattr(dc.helper, "read_created", failing)

    answer = dc.run(_user_create(dc))

    assert answer["code"] == "error"
    assert dc.fake.has_object("CN=newton-user," + fake_samba_write.SERVERS_OU_DN)
    assert dc.record()["state"] == "undo_failed"


# ---- a lost answer is read again --------------------------------------


def test_a_user_create_found_at_its_dn_after_an_uncertain_code_is_never_deleted(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The add failed with a code that does not say whether it landed, and
    the re-read finds an object at the planned DN.  Presence there does not
    prove Newton's add made it (another admin may have created the same
    name): the object stays, and the record says it is still there."""
    real = dc.helper.write_after

    def landed_then_lost(directory: Any, request: Any) -> Any:
        real(directory, request)
        raise directory.ldb.LdbError(80, "the answer was lost")

    monkeypatch.setattr(dc.helper, "write_after", landed_then_lost)

    dc.run(_user_create(dc))

    dn = "CN=newton-user," + fake_samba_write.SERVERS_OU_DN
    assert dc.fake.has_object(dn)
    record = dc.record()
    assert record["state"] == "undo_failed"
    assert record["restored"] is False
    assert dn in record["conflicts"]


def test_an_undo_whose_answer_was_lost_is_recorded_by_the_directory(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The undo modify landed and its answer was lost (code 52).  The
    target shows the before-image again, so the record is undone, never
    undo_failed (which tells the owner the change is still written)."""
    assert dc.run(dc.request())["code"] == "ok"
    real = dc.helper._modify

    def landed_then_lost(directory: Any, *args: Any) -> None:
        real(directory, *args)
        raise directory.ldb.LdbError(52, "unavailable")

    monkeypatch.setattr(dc.helper, "_modify", landed_then_lost)

    answer = dc.run({"v": 1, "mode": "abort", "device": DEVICE, "txid": TXID})

    assert answer["code"] == "ok"
    assert answer["restored"] is True
    assert dc.record()["state"] == "undone"
    assert dc.fake.get_attribute(fake_samba_write.ALICE_DN, "userAccountControl") == "4194816"


def test_an_undo_whose_answer_was_lost_and_cannot_be_read_is_not_undone(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same lost answer, and the target cannot be read again: the
    record never says undone."""
    assert dc.run(dc.request())["code"] == "ok"
    real = dc.helper._modify

    def landed_then_lost(directory: Any, *args: Any) -> None:
        real(directory, *args)
        raise directory.ldb.LdbError(52, "unavailable")

    def unreadable(*args: Any) -> Any:
        raise RuntimeError("the re-read failed")

    monkeypatch.setattr(dc.helper, "_modify", landed_then_lost)
    monkeypatch.setattr(dc.helper, "_reread", unreadable)

    dc.run({"v": 1, "mode": "abort", "device": DEVICE, "txid": TXID})

    assert dc.record()["state"] != "undone"


# ---- a third value after a write whose outcome is unknown -------------------


def _raced_then_failed(dc: Dc, monkeypatch: pytest.MonkeyPatch, code: int, attribute: str,
                       value: bytes, *, land: bool) -> None:
    """The write fails with ``code``; somebody else wrote ``value`` to the
    target right after it (Newton's write may have landed first)."""
    real = dc.helper.write_after

    def raced(directory: Any, request: Any) -> Any:
        if land:
            real(directory, request)
        dc.fake.set_values(fake_samba_write.ALICE_DN, attribute, [value])
        raise directory.ldb.LdbError(code, "the answer was lost")

    monkeypatch.setattr(dc.helper, "write_after", raced)


@pytest.mark.parametrize("land", [False, True])
@pytest.mark.parametrize("code", [1, 52, 80])
def test_a_third_value_after_an_uncertain_code_is_unknown_never_refused(
    dc: Dc, monkeypatch: pytest.MonkeyPatch, code: int, land: bool
) -> None:
    """The re-read shows neither image: another change reached the target,
    and Newton's write may have landed before it.  The record is never
    refused (which says nothing changed); the undo is disarmed so it never
    writes over the other change, and the answer is not a conflict, so
    Newton reads the record."""
    _raced_then_failed(dc, monkeypatch, code, "userAccountControl", b"66048", land=land)

    answer = dc.run(dc.request())

    assert answer["code"] == "error"
    assert answer["live"] == {"uac": 66048}
    record = dc.record()
    assert record["state"] == "undo_failed"
    assert record["restored"] is False
    assert record["conflicts"] == [fake_samba_write.ALICE_GUID]
    assert [line for line in dc.log_lines() if "systemctl" in line]
    assert dc.fake.get_attribute(fake_samba_write.ALICE_DN, "userAccountControl") == "66048"


def test_a_third_value_after_a_code_the_server_answered_is_refused_with_the_conflict(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The server itself refused the write (50): nothing of Newton's was
    written, so the other change is a conflict and the record is refused."""
    _raced_then_failed(dc, monkeypatch, 50, "userAccountControl", b"66048", land=False)

    answer = dc.run(dc.request())

    assert answer["code"] == "conflict"
    assert dc.record()["state"] == "refused"


def test_an_unlock_whose_re_read_shows_a_third_lockout_is_unknown_never_refused(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The account was locked again by somebody else after an unlock whose
    answer was lost: the record stays armed (the unlock has no undo and its
    outcome is unknown), never refused, and the answer is not a conflict."""
    _raced_then_failed(dc, monkeypatch, 80, "lockoutTime", b"2000", land=True)

    answer = dc.run(_unlock(dc))

    assert answer["code"] == "error"
    assert answer["live"] == {"lockout": 2000}
    assert dc.record()["state"] == "armed"
    assert dc.fake.get_attribute(fake_samba_write.ALICE_DN, "lockoutTime") == "2000"


# ---- a re-read that cannot name a value is unreadable, never a third value ---


def test_a_failed_move_whose_parent_cannot_be_read_stays_armed(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The move failed with an uncertain code and the object's current
    parent cannot be read: the outcome is unknown, so the record stays
    armed with its timer, never refused."""
    def lost(directory: Any, request: Any) -> Any:
        dc.fake.objects.pop(fake_samba_write.SERVERS_OU_DN)
        raise directory.ldb.LdbError(80, "the answer was lost")

    monkeypatch.setattr(dc.helper, "write_after", lost)

    answer = dc.run(_move_request(dc))

    assert answer["code"] == "error"
    assert dc.record()["state"] == "armed"
    assert not [line for line in dc.log_lines() if "systemctl" in line]


@pytest.mark.parametrize(
    ("verb", "patch"),
    [("move", "by_dn"), ("maq", "by_dn"), ("uac-clear", "integer"), ("disable", "integer")],
)
def test_the_read_back_of_a_value_it_cannot_read_is_empty(
    dc: Dc, monkeypatch: pytest.MonkeyPatch, verb: str, patch: str
) -> None:
    """A parent, a domain head or a userAccountControl that cannot be read
    is no value at all: the read-back is empty (unreadable), never a value
    that matches neither image."""
    directory = dc.helper.bind()
    request = dc.request(verb=verb)
    if patch == "by_dn":
        monkeypatch.setattr(directory, "by_dn", lambda *args, **kwargs: None)
    else:
        monkeypatch.setattr(directory, "integer", lambda *args, **kwargs: None)

    assert dc.helper.read_back(directory, request, None) == {}


# ---- an undo whose outcome is unknown stays armed -------------------------


def _stop_lines(dc: Dc) -> list[str]:
    return [line for line in dc.log_lines() if "systemctl" in line]


def test_a_landed_write_whose_undo_raises_stays_armed_for_the_sweep(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The write landed, the run then failed, and the undo run at once
    raised: its outcome is unknown, so the record stays armed with its
    timer for the timer or the sweep, never undo_failed (still written)."""
    def failing(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("the read failed")

    def raising(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("the undo failed")

    monkeypatch.setattr(dc.helper, "read_back", failing)
    monkeypatch.setattr(dc.helper, "run_undo", raising)

    answer = dc.run(dc.request())

    assert answer["code"] == "error"
    assert dc.record()["state"] == "armed"
    assert not _stop_lines(dc)


def _undo_lost(dc: Dc, monkeypatch: pytest.MonkeyPatch, *, land: bool, code: int = 52) -> None:
    real = dc.helper._modify

    def lost(directory: Any, *args: Any) -> None:
        if land:
            real(directory, *args)
        raise directory.ldb.LdbError(code, "the answer was lost")

    monkeypatch.setattr(dc.helper, "_modify", lost)


def test_an_undo_whose_answer_was_lost_and_cannot_be_read_stays_armed(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert dc.run(dc.request())["code"] == "ok"
    _undo_lost(dc, monkeypatch, land=True)

    def unreadable(*args: Any) -> Any:
        raise RuntimeError("the re-read failed")

    monkeypatch.setattr(dc.helper, "_reread", unreadable)

    answer = dc.run({"v": 1, "mode": "abort", "device": DEVICE, "txid": TXID})

    assert answer["code"] == "error"
    assert dc.record()["state"] == "armed"
    assert not _stop_lines(dc)


def test_an_undo_whose_answer_was_lost_while_the_after_image_is_there_stays_armed(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The undo got no answer and the target still shows the after-image:
    the undo may still land, so the record stays armed for a later sweep."""
    assert dc.run(dc.request())["code"] == "ok"
    _undo_lost(dc, monkeypatch, land=False)
    dc.helper.current_time = lambda: float(NBF + 601)

    # the expired change stays armed: the sweep unit is recorded failed
    assert dc.helper.handle(["--sweep"], b"", {})["code"] == "error"

    assert dc.record()["state"] == "armed"
    assert dc.fake.get_attribute(fake_samba_write.ALICE_DN, "userAccountControl") == "512"


def test_an_undo_the_server_refused_while_the_after_image_is_there_is_undo_failed(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A code the server itself answered: the undo wrote nothing, so the
    change is still written and the record says so."""
    assert dc.run(dc.request())["code"] == "ok"
    _undo_lost(dc, monkeypatch, land=False, code=50)

    answer = dc.run({"v": 1, "mode": "abort", "device": DEVICE, "txid": TXID})

    assert answer["code"] == "ok"
    assert answer["restored"] is False
    assert dc.record()["state"] == "undo_failed"


def test_a_user_create_cleanup_whose_delete_answer_is_lost_and_cannot_be_read_stays_armed(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The uSNChanged of the new user is missing, its delete by GUID got no
    answer and the object of the GUID cannot be looked for: the record stays
    armed with its timer, never undo_failed."""
    dn = "CN=newton-user," + fake_samba_write.SERVERS_OU_DN
    guid = fake_samba_write.created_guid(dn)
    monkeypatch.setattr(dc.helper, "read_created", lambda directory, request: (guid, None))
    dc.fake.delete_code = 52
    real = dc.helper.Directory.by_guid_name

    def by_guid_name(self: Any, wanted: str, attrs: Any) -> Any:
        if wanted == guid and any(kind == "delete" for kind, _ in dc.fake.calls):
            raise RuntimeError("the search failed")
        return real(self, wanted, attrs)

    monkeypatch.setattr(dc.helper.Directory, "by_guid_name", by_guid_name)

    answer = dc.run(_user_create(dc))

    assert answer["code"] == "error"
    assert dc.record()["state"] == "armed"
    assert not _stop_lines(dc)


def test_a_user_create_cleanup_whose_delete_answer_is_lost_is_undo_failed_with_its_dn(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The undo facts of the new user are missing and no GUID was read: the
    account at the planned DN may not be Newton's, so no delete is sent (a
    delete that would land is never reached) and the record is undo_failed
    with the DN as the conflict, never undone."""
    monkeypatch.setattr(dc.helper, "read_created", lambda directory, request: (None, None))
    real = fake_samba_write.FakeSamDB.delete

    def landed_then_lost(self: Any, name: str, controls: Any = None) -> None:
        real(self, name, controls)
        raise fake_samba_write.LdbError(52, "the answer was lost")

    monkeypatch.setattr(fake_samba_write.FakeSamDB, "delete", landed_then_lost)

    answer = dc.run(_user_create(dc))

    assert answer["code"] == "error"
    record = dc.record()
    assert record["state"] == "undo_failed"
    assert record["restored"] is False
    assert record["conflicts"] == ["CN=newton-user," + fake_samba_write.SERVERS_OU_DN]
    assert dc.fake.has_object("CN=newton-user," + fake_samba_write.SERVERS_OU_DN)


# ---- the undo of a user-create whose delete answer was lost -----------------


def _created_then_delete_fails(
    dc: Dc, monkeypatch: pytest.MonkeyPatch, *, land: bool, code: int
) -> str:
    """A user-create applied ok; its undo delete then fails with ``code``
    (after deleting the object when ``land``)."""
    assert dc.run(_user_create(dc))["code"] == "ok"
    real = fake_samba_write.FakeSamDB.delete

    def failing(self: Any, name: str, controls: Any = None) -> None:
        if land:
            real(self, name, controls)
        raise fake_samba_write.LdbError(code, "the answer was lost")

    monkeypatch.setattr(fake_samba_write.FakeSamDB, "delete", failing)
    return "CN=newton-user," + fake_samba_write.SERVERS_OU_DN


def _undo_way(dc: Dc, way: str) -> dict[str, Any]:
    if way == "abort":
        return dc.run({"v": 1, "mode": "abort", "device": DEVICE, "txid": TXID})
    dc.helper.current_time = lambda: float(NBF + 601)
    if way == "timer":
        return dc.undo()
    return dc.helper.handle(["--sweep"], b"", {})


@pytest.mark.parametrize("way", ["abort", "timer", "sweep"])
@pytest.mark.parametrize("code", [1, 52, 80])
def test_the_undo_of_a_user_create_whose_delete_landed_with_a_lost_answer_is_undone(
    dc: Dc, monkeypatch: pytest.MonkeyPatch, way: str, code: int
) -> None:
    """The delete landed and its answer was lost: the object is gone, so
    the record is undone, never undo_failed (which says it is still
    there)."""
    dn = _created_then_delete_fails(dc, monkeypatch, land=True, code=code)

    _undo_way(dc, way)

    assert not dc.fake.has_object(dn)
    record = dc.record()
    assert record["state"] == "undone"
    assert record["restored"] is True


@pytest.mark.parametrize("way", ["abort", "timer", "sweep"])
def test_the_undo_of_a_user_create_whose_delete_got_no_answer_stays_armed(
    dc: Dc, monkeypatch: pytest.MonkeyPatch, way: str
) -> None:
    """The delete got no answer and the object is still there: the delete
    may still land, so the record stays armed for a later undo."""
    dn = _created_then_delete_fails(dc, monkeypatch, land=False, code=52)

    _undo_way(dc, way)

    assert dc.fake.has_object(dn)
    assert dc.record()["state"] == "armed"


def test_the_undo_of_a_user_create_whose_delete_answer_is_lost_and_cannot_be_read_stays_armed(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    _created_then_delete_fails(dc, monkeypatch, land=True, code=52)

    def unreadable(*args: Any) -> Any:
        raise RuntimeError("the re-read failed")

    monkeypatch.setattr(dc.helper, "_reread", unreadable)

    answer = dc.run({"v": 1, "mode": "abort", "device": DEVICE, "txid": TXID})

    assert answer["code"] == "error"
    assert dc.record()["state"] == "armed"
    assert not _stop_lines(dc)


@pytest.mark.parametrize("code", [50, 53])
def test_the_undo_of_a_user_create_whose_delete_the_server_refused_is_undo_failed(
    dc: Dc, monkeypatch: pytest.MonkeyPatch, code: int
) -> None:
    """A code the server itself answered: the delete wrote nothing, so the
    object is still there and the record says so."""
    dn = _created_then_delete_fails(dc, monkeypatch, land=False, code=code)

    answer = dc.run({"v": 1, "mode": "abort", "device": DEVICE, "txid": TXID})

    assert answer["code"] == "ok"
    assert answer["restored"] is False
    assert dc.fake.has_object(dn)
    record = dc.record()
    assert record["state"] == "undo_failed"
    assert record["restored"] is False


# ---- a confirm recorded whose directory flush then fails -----------------


def test_a_confirm_whose_record_reads_confirmed_after_a_write_error_answers_ok(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The record was replaced and the flush of its directory then failed:
    the record reads confirmed, so the confirm answers ok, never an error
    that tells Newton the confirm was not recorded."""
    assert dc.run(dc.request())["code"] == "ok"

    def failing(path: str) -> None:
        raise OSError("the flush failed")

    monkeypatch.setattr(dc.helper, "fsync_directory", failing)

    answer = dc.run({"v": 1, "mode": "confirm", "device": DEVICE, "txid": TXID})

    assert answer["code"] == "ok"
    assert dc.record()["state"] == "confirmed"


def test_a_confirm_whose_record_was_not_replaced_answers_an_error(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert dc.run(dc.request())["code"] == "ok"

    real = dc.helper.os.replace
    calls: list[str] = []

    def failing_once(source: str, target: str) -> None:
        if not calls:
            calls.append(target)
            raise OSError("the replace failed")
        real(source, target)

    monkeypatch.setattr(dc.helper.os, "replace", failing_once)

    answer = dc.run({"v": 1, "mode": "confirm", "device": DEVICE, "txid": TXID})

    assert answer["code"] == "error"
    assert calls
    assert dc.record()["state"] == "armed"


# ---- the sweep stops reading an unlock it cannot settle ---------------------


def _plant_armed_unlock(dc: Dc, txid: str = POISON) -> None:
    request = {k: v for k, v in _unlock(dc).items() if k != "token"}
    request["txid"] = txid
    record = {
        "v": 1, "txid": txid, "request": request, "state": "armed",
        "undo_at": NBF + 120, "restored": False, "conflicts": [],
        "created": None, "created_usnchanged": None,
    }
    (dc.tx / f"{txid}.json").write_text(json.dumps(record), encoding="utf-8")


@pytest.mark.parametrize(("late", "binds"), [(60, 1), (3600 + 60, 0)])
def test_the_sweep_reads_an_armed_unlock_only_for_a_bounded_time_after_undo_at(
    dc: Dc, monkeypatch: pytest.MonkeyPatch, late: int, binds: int
) -> None:
    """An unlock has no undo: the sweep reads it again to settle it, and an
    unlock it cannot settle (a third lockout, an account it cannot read)
    is read only for UNLOCK_SETTLE_S after its undo_at, never every minute
    forever.  The record then stays armed, and its status says the record
    does not say whether the unlock was written."""
    dc.fake.set_values(fake_samba_write.ALICE_DN, "lockoutTime", [b"2000"])
    _plant_armed_unlock(dc)
    dc.helper.current_time = lambda: float(NBF + 120 + late)
    real = dc.helper.bind
    calls: list[int] = []

    def counting() -> Any:
        calls.append(1)
        return real()

    monkeypatch.setattr(dc.helper, "bind", counting)

    assert dc.helper.handle(["--sweep"], b"", {})["code"] == "ok"

    assert len(calls) == binds
    assert dc.record(POISON)["state"] == "armed"
    assert dc.helper.UNLOCK_SETTLE_S == 3600


@pytest.mark.parametrize(("lockout", "state"), [(b"1000", "armed"), (b"0", "confirmed")])
def test_the_sweep_settles_an_armed_unlock_only_from_the_after_image(
    dc: Dc, lockout: bytes, state: str
) -> None:
    """An armed unlock is one whose write may still land (a code the server
    did not answer itself, then the before-image).  The sweep never records
    it refused from a before-image read after its undo_at: the unlock may
    land later, and Windows leaves it armed too.  Only the after-image
    settles it (confirmed)."""
    dc.fake.set_values(fake_samba_write.ALICE_DN, "lockoutTime", [lockout])
    _plant_armed_unlock(dc)
    dc.helper.current_time = lambda: float(NBF + 120 + 60)

    assert dc.helper.handle(["--sweep"], b"", {})["code"] == "ok"

    assert dc.record(POISON)["state"] == state


# ---- the module and the spec say what the sweep does ------------------------


SPEC = MCP_ROOT.parent / "docs" / "proposals" / "ad" / "SPEC-1.4-REQUEST.md"


def test_the_module_docstring_names_every_way_in_and_scopes_what_the_sweep_confirms(
    dc: Dc,
) -> None:
    doc = " ".join(str(dc.helper.__doc__).split())
    assert "The only other way in is the undo" not in doc
    assert "--sweep" in doc
    assert "The sweep never confirms anything." not in doc
    assert "never confirms a change that has an undo" in doc


@pytest.mark.parametrize("where", ["spec", "readme", "changelog", "module"])
def test_the_docs_say_the_sweep_never_records_an_armed_unlock_refused(
    dc: Dc, where: str
) -> None:
    if where == "module":
        text = str(dc.helper.sweep.__doc__) + str(dc.helper._settle_unlock.__doc__)
    else:
        path = {
            "spec": SPEC,
            "readme": README,
            "changelog": MCP_ROOT.parent / "CHANGELOG.md",
        }[where]
        text = path.read_text(encoding="utf-8")
    text = " ".join(text.split()).replace("`", "")
    assert "records it confirmed or refused" not in text, where
    assert "or refused (the before-image)" not in text, where
    assert "Still the before-image: nothing was written, so the record is refused" not in text
    assert "recorded confirmed or refused" not in text
    assert "its write may still land" in text, where


def test_the_spec_says_which_helper_reads_an_unlock_in_its_sweep() -> None:
    text = " ".join(SPEC.read_text(encoding="utf-8").split())
    assert "an unlock, which has no undo, is read again and recorded" not in text
    assert "The Windows sweep skips an unlock" in text


# ---- an undo the server answered is settled, never retried for ever ------


@pytest.mark.parametrize("code", [68, 16, 20])
def test_a_move_undo_the_server_refused_is_undo_failed_with_the_conflict(
    dc: Dc, monkeypatch: pytest.MonkeyPatch, code: int
) -> None:
    """The rename back is refused by the server itself (an object of the
    name already sits under the old parent, or another refusal it
    answered): nothing was renamed, so the undo ends undo_failed with the
    object in its conflicts, and a later sweep does not try it again."""
    assert dc.run(_move_request(dc))["code"] == "ok"

    class EveryName(dict):  # the rename of any name is refused with ``code``
        def get(self, key: Any, default: Any = None) -> Any:
            return code

    monkeypatch.setattr(dc.fake, "rename_errors", EveryName())

    answer = dc.run({"v": 1, "mode": "abort", "device": DEVICE, "txid": TXID})

    assert answer["code"] == "ok"
    assert answer["restored"] is False
    assert dc.record()["state"] == "undo_failed"
    assert dc.record()["conflicts"]
    dc.helper.current_time = lambda: float(NBF + 601)
    assert dc.helper.handle(["--sweep"], b"", {})["code"] == "ok"
    assert dc.record()["state"] == "undo_failed"


# ---- the after-image after a code the server answered -----------------------


@pytest.mark.parametrize("code", [53, 19, 50])
def test_an_after_image_after_a_code_the_server_answered_is_refused_never_undone(
    dc: Dc, monkeypatch: pytest.MonkeyPatch, code: int
) -> None:
    """The server itself refused Newton's write, which is atomic, so the
    after-image there is somebody else's same change: the record is refused
    with the conflict, the timer is cancelled, the answer is conflict with
    live, and the undo never puts the before-image over their value."""
    _raced_then_failed(dc, monkeypatch, code, "userAccountControl", b"512", land=False)

    answer = dc.run(dc.request())

    assert answer["code"] == "conflict"
    assert answer["live"] == {"uac": 512}
    record = dc.record()
    assert record["state"] == "refused"
    assert record["restored"] is False
    assert record["conflicts"] == [fake_samba_write.ALICE_GUID]
    assert [line for line in dc.log_lines() if "systemctl" in line]
    assert dc.fake.get_attribute(fake_samba_write.ALICE_DN, "userAccountControl") == "512"


@pytest.mark.parametrize("code", [1, 52, 80])
def test_an_after_image_after_an_uncertain_code_is_undone_now(
    dc: Dc, monkeypatch: pytest.MonkeyPatch, code: int
) -> None:
    """Control: a code that may be the client's own, and the after-image
    is Newton's write whose answer was lost, so the undo runs now."""
    _raced_then_failed(dc, monkeypatch, code, "userAccountControl", b"512", land=True)

    answer = dc.run(dc.request())

    assert answer["code"] == "error"
    assert dc.record()["state"] == "undone"
    assert dc.fake.get_attribute(fake_samba_write.ALICE_DN, "userAccountControl") == "4194816"


def test_an_unlock_after_image_after_a_code_the_server_answered_is_refused(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Newton's unlock did not land: somebody else unlocked the account.
    Refused with the conflict, never confirmed."""
    _raced_then_failed(dc, monkeypatch, 53, "lockoutTime", b"0", land=False)

    answer = dc.run(_unlock(dc))

    assert answer["code"] == "conflict"
    assert answer["live"] == {"lockout": 0}
    record = dc.record()
    assert record["state"] == "refused"
    assert record["conflicts"] == [fake_samba_write.ALICE_GUID]


# ---- the undo of a created user somebody renamed ----------------------------


@pytest.mark.parametrize("way", ["abort", "timer", "sweep"])
def test_the_undo_of_a_created_user_someone_renamed_is_undo_failed(dc: Dc, way: str) -> None:
    """The undo looks the account up by its created GUID: renamed (a new
    sAMAccountName, user principal name and uSNChanged), it is still there,
    so it is left and the record is undo_failed with it named."""
    assert dc.run(_user_create(dc))["code"] == "ok"
    dn = "CN=newton-user," + fake_samba_write.SERVERS_OU_DN
    created = dc.record()["created"]
    dc.fake.set_attribute(dn, "sAMAccountName", "renamed-user")
    dc.fake.set_attribute(dn, "userPrincipalName", "renamed-user@samba.newton.test")
    dc.fake.set_attribute(dn, "uSNChanged", "999999")

    _undo_way(dc, way)

    assert dc.fake.has_object(dn)
    record = dc.record()
    assert record["state"] == "undo_failed"
    assert record["restored"] is False
    assert record["conflicts"] == [created]


# ---- a malformed record never stops the sweep -------------------------------

#: A txid that sorts before TXID, so the sweep meets the malformed record first.
FIRST = "00000000000000000000000000000000"


def _plant_malformed_record(dc: Dc, request: Any) -> str:
    text = json.dumps({
        "v": 1, "txid": FIRST, "request": request, "state": "armed",
        "undo_at": NBF - 1, "restored": False, "conflicts": [],
        "created": None, "created_usnchanged": None,
    })
    (dc.tx / f"{FIRST}.json").write_text(text, encoding="utf-8")
    return text


@pytest.mark.parametrize("request_value", ["not-a-request", ["a", "list"]])
def test_a_malformed_record_never_stops_the_sweep(dc: Dc, request_value: Any) -> None:
    """A record whose request is not an object is skipped and left as it
    is; the sweep still undoes the other expired record."""
    assert dc.run(dc.request())["code"] == "ok"
    text = _plant_malformed_record(dc, request_value)
    dc.helper.current_time = lambda: float(NBF + 601)

    answer = dc.helper.handle(["--sweep"], b"", {})

    assert answer == {"v": 1, "code": "ok"}
    assert dc.record()["state"] == "undone"
    assert (dc.tx / f"{FIRST}.json").read_text(encoding="utf-8") == text


@pytest.mark.parametrize("mode", ["apply", "status"])
def test_a_malformed_record_never_stops_a_stdin_mode(dc: Dc, mode: str) -> None:
    if mode != "apply":
        assert dc.run(dc.request())["code"] == "ok"
    _plant_malformed_record(dc, "not-a-request")

    if mode == "apply":
        answer = dc.run(dc.request())
    else:
        answer = _status(dc)

    assert answer["code"] == "ok"


# ---- a user-create with no recorded GUID is never undone by a name lookup ---


NEW_USER_DN = "CN=newton-user," + fake_samba_write.SERVERS_OU_DN
MOVED_USER_DN = "CN=newton-user," + fake_samba_write.OTHER_OU_DN


def _created_without_guid(dc: Dc) -> None:
    """A user-create whose add landed while its record holds no created
    GUID: the helper stopped after the add and before it wrote the facts."""
    assert dc.run(_user_create(dc))["code"] == "ok"
    record = dc.record()
    record["created"] = None
    record["created_usnchanged"] = None
    (dc.tx / f"{TXID}.json").write_text(json.dumps(record), encoding="utf-8")


@pytest.mark.parametrize("way", ["abort", "timer", "sweep"])
@pytest.mark.parametrize("moved", [True, False])
def test_the_undo_of_a_user_create_with_no_guid_is_undo_failed_with_its_dn(
    dc: Dc, way: str, moved: bool
) -> None:
    """With no created GUID the undo cannot identify the account, so it is
    left and the record is undo_failed with the planned DN as the conflict.
    A name lookup never proves it gone: an account somebody moved away from
    the planned DN is still there, and one still at the planned DN may not
    be Newton's."""
    _created_without_guid(dc)
    if moved:
        dc.fake.move_object(NEW_USER_DN, MOVED_USER_DN)

    _undo_way(dc, way)

    assert dc.fake.has_object(MOVED_USER_DN if moved else NEW_USER_DN)
    record = dc.record()
    assert record["state"] == "undo_failed"
    assert record["restored"] is False
    assert record["conflicts"] == [NEW_USER_DN]
    assert not [line for line in dc.log_lines() if line.startswith("delete")]


def test_the_undo_of_a_user_create_whose_lost_delete_left_a_moved_account_stays_armed(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The created account was moved away from the planned DN, and its
    undo delete got no answer and did not land.  The re-read is by the
    created GUID, so the account is still there and the delete may still
    land: the record stays armed, never undone from the empty planned DN."""
    assert dc.run(_user_create(dc))["code"] == "ok"
    dc.fake.move_object(NEW_USER_DN, MOVED_USER_DN)
    dc.fake.delete_code = 52

    answer = dc.run({"v": 1, "mode": "abort", "device": DEVICE, "txid": TXID})

    assert answer["code"] == "error"
    assert dc.fake.has_object(MOVED_USER_DN)
    assert dc.record()["state"] == "armed"


# ---- an error the server answered never leaves an undo that runs ------------


def _fail_the_refused_record(dc: Dc, monkeypatch: pytest.MonkeyPatch) -> None:
    """Every record write whose state is refused fails; the others land."""
    real = dc.helper.write_record

    def failing(path: str, record: Any) -> None:
        if record.get("state") == "refused":
            raise OSError("the store is full")
        real(path, record)

    monkeypatch.setattr(dc.helper, "write_record", failing)


def _stops(dc: Dc) -> list[str]:
    return [line for line in dc.log_lines() if "systemctl" in line and "stop" in line]


@pytest.mark.parametrize(("code", "value"), [(53, b"512"), (50, b"66048"), (16, b"512")])
def test_an_answered_write_whose_refused_record_fails_is_never_a_conflict_and_never_undone(
    dc: Dc, monkeypatch: pytest.MonkeyPatch, code: int, value: bytes
) -> None:
    """The server answered the write, so nothing of Newton's was written,
    and somebody else wrote ``value`` (the after-image, or a third value).
    The refused record cannot be written: the timer is cancelled anyway,
    the answer is never conflict (Newton reads the armed record and reports
    apply_unknown), and the sweep after undo_at writes nothing."""
    _raced_then_failed(dc, monkeypatch, code, "userAccountControl", value, land=False)
    _fail_the_refused_record(dc, monkeypatch)

    answer = dc.run(dc.request())

    # the write's own code, except one that maps to conflict, which is error
    assert answer["code"] == {53: "error", 50: "denied", 16: "error"}[code]
    assert _stops(dc)
    record = dc.record()
    assert record["state"] == "armed"
    assert record["answered"] == code
    dc.helper.current_time = lambda: float(NBF + 601)
    # the expired change stays armed: the sweep unit is recorded failed
    assert dc.helper.handle(["--sweep"], b"", {})["code"] == "error"
    assert dc.fake.get_attribute(fake_samba_write.ALICE_DN, "userAccountControl") == value.decode()


def _fail_every_record_write(dc: Dc, monkeypatch: pytest.MonkeyPatch) -> None:
    """The store takes the first record of the apply and no write after it."""

    def failing(path: str, record: Any) -> None:
        raise OSError("the store is full")

    monkeypatch.setattr(dc.helper, "write_record", failing)


def _fail_every_record_write_after_the_armed_one(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The store takes the armed record of the apply and no write after it:
    neither the mark of an answered write nor the refused record lands."""
    real = dc.helper.write_record
    taken: list[int] = []

    def failing(path: str, record: Any) -> None:
        if not taken and record.get("state") == "armed" and "answered" not in record:
            taken.append(1)
            real(path, record)
            return
        raise OSError("the store is full")

    monkeypatch.setattr(dc.helper, "write_record", failing)


def _member_added_then_answered_20(dc: Dc, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """A member-add of alice; another admin adds alice first, so the
    server answers the add with 20 (the value is already there)."""

    def raced(directory: Any, request: Any) -> Any:
        dc.fake.add_member(fake_samba_write.GROUP_DN, fake_samba_write.ALICE_DN)
        raise directory.ldb.LdbError(20, "the value is already there")

    monkeypatch.setattr(dc.helper, "write_after", raced)
    return dc.request(
        verb="member-add",
        target={
            "group_guid": fake_samba_write.GROUP_GUID,
            "group_sid": fake_samba_write.GROUP_SID,
            "group_sam": "group1106",
            "member_guid": fake_samba_write.ALICE_GUID,
            "member_sid": fake_samba_write.ALICE_SID,
            "member_sam": "alice",
        },
        before={"member": "absent"},
        after={"member": "present"},
    )


@pytest.mark.parametrize(("code", "value"), [(53, b"512"), (50, b"66048"), (16, b"512")])
def test_an_answered_write_whose_mark_and_refused_record_both_fail_answers_unmarked(
    dc: Dc, monkeypatch: pytest.MonkeyPatch, code: int, value: bytes
) -> None:
    """The server answered the write, so nothing of Newton's was written,
    but the store took neither the mark nor the refused record.  The record
    on the disk is armed with no mark, so a later sweep cannot tell it from
    a write whose answer was lost: the answer says so (``unmarked``), is
    never ok or conflict, and Newton reports it apply_unknown."""
    _raced_then_failed(dc, monkeypatch, code, "userAccountControl", value, land=False)
    _fail_every_record_write_after_the_armed_one(dc, monkeypatch)

    answer = dc.run(dc.request())

    assert answer["code"] not in ("ok", "conflict")
    assert answer.get("unmarked") is True
    record = dc.record()
    assert record["state"] == "armed"
    assert "answered" not in record


def test_a_member_add_answered_20_whose_store_takes_nothing_answers_unmarked(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Another admin added the member first; the server answered 20 and the
    store took neither the mark nor the refused record.  The answer is an
    error that says the record is unmarked, never conflict (nothing written
    while the store says armed)."""
    payload = _member_added_then_answered_20(dc, monkeypatch)
    _fail_every_record_write_after_the_armed_one(dc, monkeypatch)

    answer = dc.run(payload)

    assert answer["code"] == "error"
    assert answer.get("unmarked") is True
    assert dc.record()["state"] == "armed"
    assert "answered" not in dc.record()


def test_an_answered_write_whose_mark_fails_and_target_cannot_be_read_answers_unmarked(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The mark did not land and the re-read raised: the record stays armed
    with its timer and no mark, and the answer says so."""
    _raced_then_failed(dc, monkeypatch, 53, "userAccountControl", b"512", land=False)
    _fail_every_record_write_after_the_armed_one(dc, monkeypatch)

    def unreadable(*_args: Any, **_kwargs: Any) -> Any:
        raise fake_samba_write.LdbError(1, "the target cannot be read")

    monkeypatch.setattr(dc.helper, "_reread", unreadable)

    answer = dc.run(dc.request())

    assert answer["code"] == "error"
    assert answer.get("unmarked") is True
    assert dc.record()["state"] == "armed"


def test_an_answered_write_whose_mark_fails_and_refused_record_lands_is_not_unmarked(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The mark did not land, the refused record (which carries the mark)
    did: the record is settled, so the answer is the conflict, with no
    ``unmarked``."""
    _raced_then_failed(dc, monkeypatch, 53, "userAccountControl", b"512", land=False)
    real = dc.helper.write_record

    def mark_fails(path: str, record: Any) -> None:
        if record.get("state") == "armed" and "answered" in record:
            raise OSError("the store is busy")
        real(path, record)

    monkeypatch.setattr(dc.helper, "write_record", mark_fails)

    answer = dc.run(dc.request())

    assert answer["code"] == "conflict"
    assert "unmarked" not in answer
    record = dc.record()
    assert record["state"] == "refused"
    assert record["answered"] == 53


@pytest.mark.parametrize("code", [1, 52])
def test_a_write_with_no_server_answer_is_never_unmarked(
    dc: Dc, monkeypatch: pytest.MonkeyPatch, code: int
) -> None:
    """A code the server may not have answered carries no mark by design
    (the write may land and the undo must run): never ``unmarked``."""
    _raced_then_failed(dc, monkeypatch, code, "userAccountControl", b"4194816", land=False)
    _fail_every_record_write_after_the_armed_one(dc, monkeypatch)

    answer = dc.run(dc.request())

    assert "unmarked" not in answer
    assert dc.record()["state"] == "armed"


def test_an_unlock_answered_whose_store_takes_nothing_is_never_unmarked(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unlock has no undo and the sweep only reads it again, so an
    unmarked unlock record writes nothing over anybody's change."""
    _raced_then_failed(dc, monkeypatch, 53, "lockoutTime", b"0", land=False)
    _fail_every_record_write_after_the_armed_one(dc, monkeypatch)

    answer = dc.run(_unlock(dc))

    assert "unmarked" not in answer


# ---- a write that was never sent never leaves an armed record ---------------


@pytest.mark.parametrize("way", ["timer", "sweep"])
def test_a_conflict_before_the_write_whose_store_fails_leaves_nothing_the_undo_writes_over(
    dc: Dc, monkeypatch: pytest.MonkeyPatch, way: str
) -> None:
    """Another admin made the same change first, so the live value is the
    after-image and the apply is refused before it writes.  The store then
    takes no write: the record on the disk must still not read armed, or
    the sweep after undo_at would write the before-image over the other
    admin's change."""
    dc.fake.set_values(fake_samba_write.ALICE_DN, "userAccountControl", [b"512"])
    real = dc.helper.write_record
    _fail_every_record_write(dc, monkeypatch)

    answer = dc.run(dc.request())

    assert answer["code"] != "ok"
    assert dc.record()["state"] != "armed"
    monkeypatch.setattr(dc.helper, "write_record", real)
    _undo_way(dc, way)
    assert dc.fake.get_attribute(fake_samba_write.ALICE_DN, "userAccountControl") == "512"
    assert not [line for line in dc.log_lines() if line.startswith("modify")]


def test_an_apply_whose_timer_cannot_be_armed_and_whose_store_fails_is_never_armed(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The timer cannot be armed, so nothing is sent; the store then takes
    no write.  The record never reads armed, so the sweep never runs an
    undo for a write that was never sent."""
    monkeypatch.setenv("NEWTON_FAKE_FAIL_SYSTEMD_RUN", "1")
    _fail_every_record_write(dc, monkeypatch)

    answer = dc.run(dc.request())

    assert answer["code"] == "unavailable"
    assert dc.record()["state"] == "refused"


def test_an_apply_whose_armed_record_cannot_be_written_sends_nothing(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The record reads armed only once the store took it: a store that
    refuses it stops the apply before the write, with an error, and the
    record says refused."""
    _fail_every_record_write(dc, monkeypatch)
    sent: list[int] = []
    real = dc.helper.write_after

    def counting(directory: Any, request: Any) -> Any:
        sent.append(1)
        return real(directory, request)

    monkeypatch.setattr(dc.helper, "write_after", counting)

    answer = dc.run(dc.request())

    assert answer["code"] == "error"
    assert sent == []
    assert dc.record()["state"] == "refused"
    assert dc.fake.get_attribute(fake_samba_write.ALICE_DN, "userAccountControl") == "4194816"


def _plant_answered_record(dc: Dc, code: int = 53) -> None:
    """An armed record whose write the server answered, while the target
    shows the after-image (somebody else's same change)."""
    request = {k: v for k, v in dc.request().items() if k != "token"}
    record = {
        "v": 1, "txid": TXID, "request": request, "state": "armed",
        "undo_at": NBF - 1, "restored": False, "conflicts": [],
        "created": None, "created_usnchanged": None, "answered": code,
    }
    (dc.tx / f"{TXID}.json").write_text(json.dumps(record), encoding="utf-8")
    dc.fake.set_values(fake_samba_write.ALICE_DN, "userAccountControl", [b"512"])


@pytest.mark.parametrize("way", ["abort", "timer", "sweep"])
def test_an_armed_record_whose_write_the_server_answered_is_never_undone(
    dc: Dc, way: str
) -> None:
    """The record says the server answered the apply's write: nothing of
    Newton's was written, so the abort, the timer and the sweep write
    nothing (the after-image there is somebody else's), the record is
    refused, and an abort answers conflict."""
    _plant_answered_record(dc)

    answer = _undo_way(dc, way)

    assert not [line for line in dc.log_lines() if line.startswith("modify")]
    assert dc.fake.get_attribute(fake_samba_write.ALICE_DN, "userAccountControl") == "512"
    assert dc.record()["state"] == "refused"
    if way == "abort":
        assert answer["code"] == "conflict"


def test_an_exception_after_the_write_was_sent_leaves_the_record_armed(dc: Dc) -> None:
    """The write raised something other than an LDB error after it was
    sent: it may have landed, so the record stays armed with its timer,
    never refused (which says nothing was written)."""
    dc.fake.modify_error = RuntimeError("the binding broke after the send")

    answer = dc.run(dc.request())

    assert answer["code"] == "error"
    assert dc.record()["state"] == "armed"
    assert not _stops(dc)


# ---- a record replaced on the disk whose directory flush then fails ---------


def _flush_fails_after_replace(
    dc: Dc, monkeypatch: pytest.MonkeyPatch, which: Any
) -> None:
    """The record write that ``which`` picks is replaced on the disk and the
    flush of its directory then raises: the record the helper wrote is
    there, and write_record raised all the same."""
    real_write = dc.helper.write_record
    real_flush = dc.helper.fsync_directory

    def failing_flush(directory: str) -> None:
        raise OSError(5, "the flush of the directory failed")

    def write(path: str, record: Any) -> None:
        if not which(record):
            real_write(path, record)
            return
        dc.helper.fsync_directory = failing_flush
        try:
            real_write(path, record)
        finally:
            dc.helper.fsync_directory = real_flush

    monkeypatch.setattr(dc.helper, "write_record", write)


def _first_armed(record: Any) -> bool:
    return record.get("state") == "armed" and "answered" not in record


def _once(which: Any) -> Any:
    taken: list[int] = []

    def pick(record: Any) -> bool:
        if not taken and which(record):
            taken.append(1)
            return True
        return False

    return pick


def _count_sends(dc: Dc, monkeypatch: pytest.MonkeyPatch) -> list[int]:
    sent: list[int] = []
    real = dc.helper.write_after

    def counting(directory: Any, request: Any) -> Any:
        sent.append(1)
        return real(directory, request)

    monkeypatch.setattr(dc.helper, "write_after", counting)
    return sent


@pytest.mark.parametrize("way", ["timer", "sweep"])
def test_an_armed_record_whose_flush_fails_is_rewritten_refused_and_nothing_is_sent(
    dc: Dc, monkeypatch: pytest.MonkeyPatch, way: str
) -> None:
    """The armed record was replaced on the disk and the flush of its
    directory then raised.  The helper never assumes the disk holds the
    old record: it reads armed, so the helper writes it refused again,
    sends nothing and stops the timer; the undo later writes nothing over
    another admin's same change."""
    _flush_fails_after_replace(dc, monkeypatch, _once(_first_armed))
    sent = _count_sends(dc, monkeypatch)

    answer = dc.run(dc.request())

    assert answer == {"v": 1, "code": "error"}
    assert sent == []
    assert dc.record()["state"] == "refused"
    assert _stops(dc)
    dc.fake.set_values(fake_samba_write.ALICE_DN, "userAccountControl", [b"512"])
    _undo_way(dc, way)
    assert dc.fake.get_attribute(fake_samba_write.ALICE_DN, "userAccountControl") == "512"


def test_an_armed_record_whose_flush_fails_and_whose_refused_rewrite_fails_answers_unmarked(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The armed record landed with a flush error and the refused record
    then cannot be written: the disk reads armed for a write that was never
    sent, so the answer says unmarked (Newton warns that the undo may write
    over somebody else's change) and the timer is stopped."""
    _flush_fails_after_replace(dc, monkeypatch, _once(_first_armed))
    _fail_the_refused_record(dc, monkeypatch)
    sent = _count_sends(dc, monkeypatch)

    answer = dc.run(dc.request())

    assert answer["code"] == "error"
    assert answer.get("unmarked") is True
    assert sent == []
    assert dc.record()["state"] == "armed"
    assert _stops(dc)


def test_an_armed_unlock_whose_flush_fails_and_whose_refused_rewrite_fails_is_never_unmarked(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unlock has no undo: the sweep only reads it again, so an armed
    unlock record writes nothing over anybody's change."""
    _flush_fails_after_replace(dc, monkeypatch, _once(_first_armed))
    _fail_the_refused_record(dc, monkeypatch)
    sent = _count_sends(dc, monkeypatch)

    answer = dc.run(_unlock(dc))

    assert answer["code"] == "error"
    assert "unmarked" not in answer
    assert sent == []


def test_an_apply_whose_armed_record_cannot_be_written_stops_the_timer(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fail_every_record_write(dc, monkeypatch)

    answer = dc.run(dc.request())

    assert answer == {"v": 1, "code": "error"}
    assert _stops(dc)


def test_a_conflict_whose_refused_record_flush_fails_answers_conflict(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The server answered 20 and the refused record landed with a flush
    error: the disk reads refused, so the answer is the conflict."""
    payload = _member_added_then_answered_20(dc, monkeypatch)
    _flush_fails_after_replace(dc, monkeypatch, lambda r: r.get("state") == "refused")

    answer = dc.run(payload)

    assert answer["code"] == "conflict"
    assert "unmarked" not in answer
    assert dc.record()["state"] == "refused"


def test_an_answered_after_image_whose_refused_record_flush_fails_answers_conflict(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    _raced_then_failed(dc, monkeypatch, 53, "userAccountControl", b"512", land=False)
    _flush_fails_after_replace(dc, monkeypatch, lambda r: r.get("state") == "refused")

    answer = dc.run(dc.request())

    assert answer["code"] == "conflict"
    assert answer["live"] == {"uac": 512}
    assert "unmarked" not in answer
    assert dc.record()["state"] == "refused"
    assert _stops(dc)


def test_an_answered_before_image_whose_refused_record_flush_fails_is_refused(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    _raced_then_failed(dc, monkeypatch, 53, "userAccountControl", b"4194816", land=False)
    _flush_fails_after_replace(dc, monkeypatch, lambda r: r.get("state") == "refused")

    answer = dc.run(dc.request())

    assert answer["code"] == "error"
    assert "unmarked" not in answer
    assert dc.record()["state"] == "refused"
    assert _stops(dc)


def _refused_before_the_send(dc: Dc, monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """write_after refuses before it sends anything (the parent is gone)."""
    sent: list[int] = []

    def refusing(directory: Any, request: Any) -> Any:
        raise dc.helper.Refused("not_found", "the parent of the new object is not there")

    monkeypatch.setattr(dc.helper, "write_after", refusing)
    return sent


def test_a_refusal_before_the_send_whose_refused_record_flush_fails_is_refused(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    _refused_before_the_send(dc, monkeypatch)
    _flush_fails_after_replace(dc, monkeypatch, lambda r: r.get("state") == "refused")

    answer = dc.run(dc.request())

    assert answer == {"v": 1, "code": "not_found"}
    assert dc.record()["state"] == "refused"


def test_a_refusal_before_the_send_whose_refused_record_fails_answers_unmarked(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Nothing was sent, but the refused record cannot be written: the disk
    reads armed, so the answer says unmarked."""
    _refused_before_the_send(dc, monkeypatch)
    _fail_the_refused_record(dc, monkeypatch)

    answer = dc.run(dc.request())

    assert answer["code"] == "not_found"
    assert answer.get("unmarked") is True
    assert dc.record()["state"] == "armed"


def test_an_answered_mark_whose_flush_fails_then_a_refused_record_answers_conflict(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    _raced_then_failed(dc, monkeypatch, 53, "userAccountControl", b"512", land=False)
    _flush_fails_after_replace(
        dc, monkeypatch, lambda r: r.get("state") == "armed" and "answered" in r
    )

    answer = dc.run(dc.request())

    assert answer["code"] == "conflict"
    assert "unmarked" not in answer
    record = dc.record()
    assert record["state"] == "refused"
    assert record["answered"] == 53


def test_an_answered_mark_whose_flush_fails_and_refused_record_fails_is_marked_not_unmarked(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The mark landed (with a flush error) and the refused record did not:
    the disk carries the mark, so the answer is not unmarked and the sweep
    writes nothing over the other change."""
    _raced_then_failed(dc, monkeypatch, 53, "userAccountControl", b"512", land=False)
    _flush_fails_after_replace(
        dc, monkeypatch, lambda r: r.get("state") == "armed" and "answered" in r
    )
    _fail_the_refused_record(dc, monkeypatch)

    answer = dc.run(dc.request())

    assert answer["code"] == "error"
    assert "unmarked" not in answer
    record = dc.record()
    assert record["state"] == "armed"
    assert record["answered"] == 53
    dc.helper.current_time = lambda: float(NBF + 601)
    # the expired change stays armed: the sweep unit is recorded failed
    assert dc.helper.handle(["--sweep"], b"", {})["code"] == "error"
    assert dc.fake.get_attribute(fake_samba_write.ALICE_DN, "userAccountControl") == "512"


@pytest.mark.parametrize(("code", "value"), [(53, b"512"), (50, b"66048"), (16, b"512")])
def test_an_answered_write_whose_mark_lands_and_refused_record_fails_is_not_unmarked(
    dc: Dc, monkeypatch: pytest.MonkeyPatch, code: int, value: bytes
) -> None:
    """The store took the mark and not the refused record: the disk says the
    server answered, so the answer never says unmarked."""
    _raced_then_failed(dc, monkeypatch, code, "userAccountControl", value, land=False)
    _fail_the_refused_record(dc, monkeypatch)

    answer = dc.run(dc.request())

    assert "unmarked" not in answer
    assert dc.record()["answered"] == code


def test_a_record_that_reads_refused_without_a_mark_is_not_unmarked(dc: Dc) -> None:
    """_unmarked reads the disk: a refused record keeps any undo from
    writing, mark or no mark."""
    assert dc.run(dc.request())["code"] == "ok"
    record = dc.record()
    record["state"] = "refused"
    (dc.tx / f"{TXID}.json").write_text(json.dumps(record), encoding="utf-8")
    exc = fake_samba_write.LdbError(53, "unwilling")

    extra = dc.helper._unmarked(str(dc.tx / f"{TXID}.json"), "uac-set", exc, "error", {})

    assert "unmarked" not in extra


def test_a_conflict_whose_record_cannot_be_read_back_is_not_unmarked(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A conflict answer means the refused record was written: a read-back
    that fails after it never adds unmarked to the conflict."""
    payload = _member_added_then_answered_20(dc, monkeypatch)
    monkeypatch.setattr(dc.helper, "read_record", lambda path: None)

    answer = dc.run(payload)

    assert answer["code"] == "conflict"
    assert "unmarked" not in answer


def test_an_ok_write_whose_last_record_flush_fails_answers_ok_and_stays_armed(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The last record of a write that landed was replaced on the disk and
    its flush failed: the record reads armed, so the change is not undone
    at once and the answer is ok."""
    armed: list[int] = []

    def second_armed(record: Any) -> bool:
        if record.get("state") == "armed":
            armed.append(1)
            return len(armed) == 2
        return False

    _flush_fails_after_replace(dc, monkeypatch, second_armed)

    answer = dc.run(dc.request())

    assert answer["code"] == "ok"
    assert dc.record()["state"] == "armed"
    assert dc.fake.get_attribute(fake_samba_write.ALICE_DN, "userAccountControl") == "512"


def test_an_abort_whose_undone_record_flush_fails_answers_ok(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert dc.run(dc.request())["code"] == "ok"
    _flush_fails_after_replace(dc, monkeypatch, lambda r: r.get("state") == "undone")

    answer = dc.run({"v": 1, "mode": "abort", "device": DEVICE, "txid": TXID})

    assert answer["code"] == "ok"
    assert answer["restored"] is True
    assert dc.record()["state"] == "undone"


# ---- a failed armed write whose read-back then fails ------------------------


def _armed_and_refused_fail_then_unreadable(
    dc: Dc, monkeypatch: pytest.MonkeyPatch, *, refused_lands: bool
) -> None:
    """The armed record lands and the flush of its directory raises; the
    refused record then raises too (landed with the same flush error when
    ``refused_lands``, or not at all); and from the failed armed write on,
    the store cannot be read back."""
    real_write = dc.helper.write_record
    real_read = dc.helper.read_record
    unreadable: list[int] = []

    def write(path: str, record: Any) -> None:
        if not unreadable and _first_armed(record):
            real_write(path, record)
            unreadable.append(1)
            raise OSError(5, "the flush of the directory failed")
        if unreadable and record.get("state") == "refused":
            if refused_lands:
                real_write(path, record)
            raise OSError(5, "the flush of the directory failed")
        real_write(path, record)

    def read(path: str) -> Any:
        if unreadable:
            return None
        return real_read(path)

    monkeypatch.setattr(dc.helper, "write_record", write)
    monkeypatch.setattr(dc.helper, "read_record", read)


@pytest.mark.parametrize("refused_lands", [False, True])
def test_an_armed_record_whose_read_back_fails_answers_unmarked_unless_it_reads_refused(
    dc: Dc, monkeypatch: pytest.MonkeyPatch, refused_lands: bool
) -> None:
    """The armed write failed and the store then cannot be read back: the
    helper cannot tell what the disk holds, so it acts as if the armed
    record landed.  Nothing is sent and the timer is stopped; the refused
    record it writes again raises, and since the disk does not read refused
    the answer says unmarked (even when that record did land)."""
    _armed_and_refused_fail_then_unreadable(dc, monkeypatch, refused_lands=refused_lands)
    sent = _count_sends(dc, monkeypatch)

    answer = dc.run(dc.request())

    assert answer["code"] == "error"
    assert answer.get("unmarked") is True
    assert sent == []
    assert _stops(dc)
    assert dc.record()["state"] == ("refused" if refused_lands else "armed")


def test_an_armed_unlock_whose_read_back_fails_is_never_unmarked(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    _armed_and_refused_fail_then_unreadable(dc, monkeypatch, refused_lands=False)
    sent = _count_sends(dc, monkeypatch)

    answer = dc.run(_unlock(dc))

    assert answer["code"] == "error"
    assert "unmarked" not in answer
    assert sent == []


# ---- a refusal after the timer was armed stops the timer ------------------


def test_a_move_answered_32_whose_refused_record_fails_is_never_a_conflict(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The rename answers 32 (the object to move is not there), so nothing
    was written, and the refused record then cannot be written: the disk
    reads armed with no mark.  The answer is never conflict (which Newton
    reports as nothing changed, dropping unmarked): it is an error that
    says unmarked, and the timer is stopped."""
    dc.fake.set_rename_error(fake_samba_write.ALICE_DN, 32)
    _fail_the_refused_record(dc, monkeypatch)

    answer = dc.run(_move_request(dc))

    assert answer["code"] == "error"
    assert answer.get("unmarked") is True
    assert dc.record()["state"] == "armed"
    assert _stops(dc)


def test_a_move_answered_32_whose_refused_record_lands_is_a_conflict(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    dc.fake.set_rename_error(fake_samba_write.ALICE_DN, 32)

    answer = dc.run(_move_request(dc))

    assert answer["code"] == "conflict"
    assert "unmarked" not in answer
    assert dc.record()["state"] == "refused"


@pytest.mark.parametrize("lands", [True, False])
def test_a_refusal_after_the_timer_was_armed_stops_the_timer(
    dc: Dc, monkeypatch: pytest.MonkeyPatch, lands: bool
) -> None:
    """write_after refuses before it sends anything: nothing was written,
    so the timer goes whether or not the refused record lands (a timer left
    running on an armed record would undo over somebody else's value)."""
    _refused_before_the_send(dc, monkeypatch)
    if not lands:
        _fail_the_refused_record(dc, monkeypatch)

    answer = dc.run(dc.request())

    assert answer["code"] == "not_found"
    assert _stops(dc)
    assert dc.record()["state"] == ("refused" if lands else "armed")


def _stop_raises(dc: Dc, monkeypatch: pytest.MonkeyPatch) -> None:
    """The systemctl stop of the timer cannot be spawned (EAGAIN)."""
    real = dc.helper.run_command

    def run(argv: Any) -> Any:
        if list(argv)[:2] == ["systemctl", "stop"]:
            raise OSError(11, "resource temporarily unavailable")
        return real(argv)

    monkeypatch.setattr(dc.helper, "run_command", run)


def test_a_timer_stop_that_raises_answers_false() -> None:
    """A cancel that cannot even be spawned is a cancel that failed."""
    import importlib.machinery
    import importlib.util

    path = str(MCP_ROOT / "newton_mcp" / "ad" / "collector" / "newton-ad-samba-write")
    loader = importlib.machinery.SourceFileLoader("samba_write_stop_probe", path)
    spec = importlib.util.spec_from_loader("samba_write_stop_probe", loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)

    def raising(argv: Any) -> Any:
        raise OSError(11, "resource temporarily unavailable")

    module.run_command = raising
    assert module.disarm_undo(TXID) is False


def test_an_armed_record_whose_flush_fails_and_whose_timer_stop_raises_is_written_refused(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The armed record landed with a flush error and the stop of the timer
    then raises: nothing was sent, so the record is still written refused."""
    _flush_fails_after_replace(dc, monkeypatch, _once(_first_armed))
    _stop_raises(dc, monkeypatch)
    sent = _count_sends(dc, monkeypatch)

    answer = dc.run(dc.request())

    assert answer == {"v": 1, "code": "error"}
    assert sent == []
    assert dc.record()["state"] == "refused"


def test_an_armed_record_whose_timer_stop_raises_and_refused_rewrite_fails_answers_unmarked(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    _flush_fails_after_replace(dc, monkeypatch, _once(_first_armed))
    _stop_raises(dc, monkeypatch)
    _fail_the_refused_record(dc, monkeypatch)
    sent = _count_sends(dc, monkeypatch)

    answer = dc.run(dc.request())

    assert answer["code"] == "error"
    assert answer.get("unmarked") is True
    assert sent == []
    assert dc.record()["state"] == "armed"


# ---- a record that cannot be read --------------------------------------------


def _record_read_throws(dc: Dc, monkeypatch: pytest.MonkeyPatch, txid: str = TXID) -> None:
    """Every open of the record of one transaction raises (a denied access, an
    IO error): the file is on the disk, and only its read fails."""
    import builtins

    real_open = builtins.open
    target = str(dc.tx / f"{txid}.json")

    def guarded(file: Any, *args: Any, **kwargs: Any) -> Any:
        if str(file) == target:
            raise PermissionError(13, "Permission denied", target)
        return real_open(file, *args, **kwargs)

    monkeypatch.setattr(dc.helper, "open", guarded, raising=False)


@pytest.mark.parametrize("way", ["status", "confirm", "abort", "undo", "sweep", "read"])
def test_a_record_that_cannot_be_read_is_never_taken_for_absent(
    dc: Dc, monkeypatch: pytest.MonkeyPatch, way: str
) -> None:
    """The armed record of a change that landed cannot be read.  A read that
    raises says nothing about the record: status, confirm, abort and the timer
    answer error, never not_found, and nothing is written; the sweep leaves the
    transaction for a later pass and never stops the mode that runs it."""
    assert dc.run(dc.request())["code"] == "ok"
    before = (dc.tx / f"{TXID}.json").read_bytes()
    _record_read_throws(dc, monkeypatch)
    dc.helper.current_time = lambda: float(NBF + 601)

    if way == "undo":
        answer = dc.undo()
    elif way == "sweep":
        answer = dc.helper.handle(["--sweep"], b"", {})
    elif way == "read":
        answer = dc.run({"v": 1, "mode": "read", "device": DEVICE, "verb": "uac-clear",
                         "target": {"sam": "alice"}})
    else:
        answer = dc.run({"v": 1, "mode": way, "device": DEVICE, "txid": TXID})

    if way in ("sweep", "read"):
        assert answer["code"] == "ok", answer
    else:
        assert answer["code"] == "error", answer
    assert (dc.tx / f"{TXID}.json").read_bytes() == before
    assert dc.fake.get_attribute(fake_samba_write.ALICE_DN, "userAccountControl") == "512"


def test_an_answered_write_whose_record_cannot_be_read_back_answers_unmarked(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    """_unmarked reads the disk: a record that cannot be read says nothing,
    so the answer says unmarked and never fails as a whole."""
    assert dc.run(dc.request())["code"] == "ok"
    _record_read_throws(dc, monkeypatch)
    exc = fake_samba_write.LdbError(53, "unwilling")

    extra = dc.helper._unmarked(str(dc.tx / f"{TXID}.json"), "uac-set", exc, "error", {})

    assert extra.get("unmarked") is True


# ---- an armed record never undoes a later confirmed change of its target ----

#: A second and a third transaction on the same target.
TXID_B = "1111111111111111aaaaaaaaaaaaaaaa"
TXID_C = "2222222222222222bbbbbbbbbbbbbbbb"


def _confirm(dc: Dc, txid: str) -> dict[str, Any]:
    return dc.run({"v": 1, "mode": "confirm", "device": DEVICE, "txid": txid})


def _armed_unanswered(dc: Dc) -> None:
    """Transaction A: a uac-clear whose write got no answer (52) and did not
    land.  The re-read shows the before-image, so the record stays armed
    and its timer runs the undo at undo_at."""
    dc.fake.modify_code = 52
    assert dc.run(dc.request())["code"] == "error"
    assert dc.record()["state"] == "armed"
    dc.fake.modify_code = None


def _modifies(dc: Dc) -> int:
    return len([one for one in dc.fake.calls if one[0] == "modify"])


def test_an_armed_record_never_undoes_a_later_confirmed_change_of_its_target(dc: Dc) -> None:
    """A stays armed after an unanswered write whose re-read shows the
    before-image.  B, the same change of the same target, is applied and
    confirmed when the DC takes it.  At A's undo_at the undo must not write
    the before-image over B's confirmed change: once confirmed, Newton does
    not undo it."""
    _armed_unanswered(dc)

    second = dc.run(dc.request(txid=TXID_B))
    if second["code"] == "ok":
        assert _confirm(dc, TXID_B)["code"] == "ok"
    dc.helper.current_time = lambda: float(NBF + 601)
    _status(dc)

    live = dc.fake.get_attribute(fake_samba_write.ALICE_DN, "userAccountControl")
    if dc.record(TXID_B)["state"] == "confirmed":
        assert live == "512"
    else:
        assert live == "4194816"


def test_an_apply_while_another_armed_record_names_the_target_is_a_conflict(dc: Dc) -> None:
    """The guard: while another armed record names the same target, a new
    apply is refused with conflict before anything is armed or written.  The
    answer carries the live value and armed, the record is refused, and A's
    undo at its undo_at finds the before-image and writes nothing."""
    _armed_unanswered(dc)
    writes = _modifies(dc)
    timers = [line for line in dc.log_lines() if "systemd-run" in line]

    second = dc.run(dc.request(txid=TXID_B))

    assert second["code"] == "conflict", second
    assert second["armed"] is True
    assert second["live"] == {"uac": 4194816}
    assert dc.record(TXID_B)["state"] == "refused"
    assert _modifies(dc) == writes
    assert [line for line in dc.log_lines() if "systemd-run" in line] == timers
    assert dc.record()["state"] == "armed"

    dc.helper.current_time = lambda: float(NBF + 601)
    _status(dc)

    assert dc.record()["state"] == "undone"
    assert _modifies(dc) == writes
    assert dc.fake.get_attribute(fake_samba_write.ALICE_DN, "userAccountControl") == "4194816"


def test_a_target_takes_a_new_change_once_its_armed_record_settles(dc: Dc) -> None:
    """The guard holds only while the other record is armed: once A's undo
    ran at its undo_at, a new apply of the same target goes through."""
    _armed_unanswered(dc)
    dc.helper.current_time = lambda: float(NBF + 601)

    answer = dc.run(dc.request(txid=TXID_C, nbf=NBF + 600, exp=NBF + 1200))

    assert answer["code"] == "ok", answer
    assert dc.record()["state"] == "undone"


def test_an_armed_change_of_the_same_attribute_by_another_verb_is_a_conflict(dc: Dc) -> None:
    """A disable writes the userAccountControl a uac-clear's undo writes
    back: it is the same target, so it is refused while A is armed."""
    _armed_unanswered(dc)

    answer = dc.run(dc.request(
        txid=TXID_B, verb="disable",
        target={"guid": fake_samba_write.ALICE_GUID, "sid": fake_samba_write.ALICE_SID,
                "sam": "alice"},
        before={"uac": 4194816}, after={"uac": 4194818},
    ))

    assert answer["code"] == "conflict", answer
    assert answer["armed"] is True


def test_an_armed_unlock_never_blocks_a_change_and_another_target_is_free(dc: Dc) -> None:
    """An unlock has no undo, so an armed unlock writes nothing back and
    never blocks a change of the account; another account is another target."""
    def failing(directory: Any, request: Any) -> Any:
        raise directory.ldb.LdbError(80, "other")

    real = dc.helper.write_after
    dc.helper.write_after = failing
    try:
        dc.run(_unlock(dc))
    finally:
        dc.helper.write_after = real
    assert dc.record()["state"] == "armed"

    assert dc.run(dc.request(txid=TXID_B))["code"] == "ok"
    other = dc.run(dc.request(
        txid=TXID_C, verb="disable",
        target={"guid": fake_samba_write.BOB_GUID, "sid": fake_samba_write.BOB_SID,
                "sam": "bob"},
        before={"uac": 512}, after={"uac": 514},
    ))
    assert other["code"] == "ok", other


def test_an_apply_whose_store_cannot_be_checked_for_an_armed_record_is_an_error(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A record of the store that cannot be read may be an armed record of
    the same target: the apply answers error and writes nothing."""
    _armed_unanswered(dc)
    writes = _modifies(dc)
    _record_read_throws(dc, monkeypatch)

    answer = dc.run(dc.request(txid=TXID_B))

    assert answer["code"] == "error", answer
    assert _modifies(dc) == writes
    assert dc.record(TXID_B)["state"] == "refused"


def test_an_armed_record_whose_undo_keeps_failing_still_blocks_its_target(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An expired armed record whose undo raises stays armed, and a later pass
    may still run it: an apply of its target is refused with conflict while
    it is armed, and the mode answers (the sweep failure never stops it)."""
    _plant_poisoned_record(dc, monkeypatch)
    record = dc.record(POISON)
    record["request"]["target"] = {"guid": fake_samba_write.ALICE_GUID,
                                   "sid": fake_samba_write.ALICE_SID,
                                   "sam": "alice", "bit": 4194304}
    (dc.tx / f"{POISON}.json").write_text(json.dumps(record), encoding="utf-8")

    answer = dc.run(dc.request())

    assert answer["code"] == "conflict", answer
    assert answer["armed"] is True
    assert dc.record(POISON)["state"] == "armed"


# ---- the apply's own cleanup of a new user deletes only by its GUID ----------

#: The objectGUID of somebody else's account at the planned DN.
REPLACEMENT_GUID = "cc2b3c4d-5e6f-4a8b-9c0d-1e2f3a4b5c6d"


def _moved_and_replaced(dc: Dc, monkeypatch: pytest.MonkeyPatch, *, with_guid: bool) -> list[str]:
    """After the add, and before the facts are read, somebody moves Newton's
    new user away and creates another account at the planned DN.  The facts
    then come back without the uSNChanged (``with_guid``: the GUID of
    Newton's object was read) or with neither.  The answer is the GUID of
    Newton's object."""
    seen: list[str] = []

    def read_created(directory: Any, request: Any) -> tuple[Any, Any]:
        message = directory.by_dn(NEW_USER_DN, ["objectGUID"])
        guid = directory.guid(message)
        seen.append(guid)
        dc.fake.move_object(NEW_USER_DN, MOVED_USER_DN)
        replacement = {name: list(values) for name, values in dc.fake.objects[MOVED_USER_DN].items()}
        replacement["objectguid"] = [fake_samba_write.guid_bytes(REPLACEMENT_GUID)]
        dc.fake.objects[NEW_USER_DN] = replacement
        return (guid if with_guid else None), None

    monkeypatch.setattr(dc.helper, "read_created", read_created)
    return seen


def _guid_at(dc: Dc, dn: str) -> str:
    return fake_samba_write.guid_text(dc.fake.values_of(dn, "objectGUID")[0])


def test_a_cleanup_with_no_guid_never_deletes_the_account_at_the_planned_dn(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The undo facts of the new user are missing and no GUID was read: an
    account at the planned DN may not be Newton's (here it is somebody
    else's, and Newton's was moved away), so nothing is deleted.  The record
    is undo_failed with the DN as the conflict, never undone."""
    _moved_and_replaced(dc, monkeypatch, with_guid=False)

    answer = dc.run(_user_create(dc))

    assert answer["code"] == "error"
    assert _guid_at(dc, NEW_USER_DN) == REPLACEMENT_GUID
    assert dc.fake.has_object(MOVED_USER_DN)
    assert not [one for one in dc.fake.calls if one[0] == "delete"]
    record = dc.record()
    assert record["state"] == "undo_failed"
    assert record["restored"] is False
    assert record["conflicts"] == [NEW_USER_DN]


def test_a_cleanup_with_a_guid_deletes_only_the_object_of_that_guid(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The GUID of Newton's new user was read and its uSNChanged was not: the
    cleanup deletes the object of that GUID wherever it is, and the
    replacement at the planned DN is kept.  The record is undone."""
    _moved_and_replaced(dc, monkeypatch, with_guid=True)

    answer = dc.run(_user_create(dc))

    assert answer["code"] == "error"
    assert _guid_at(dc, NEW_USER_DN) == REPLACEMENT_GUID
    assert not dc.fake.has_object(MOVED_USER_DN)
    record = dc.record()
    assert record["state"] == "undone"
    assert record["restored"] is True
    assert record["conflicts"] == []


@pytest.mark.parametrize(("landed", "state"), [(True, "undone"), (False, "undo_failed")])
def test_a_cleanup_by_guid_whose_delete_answer_is_lost_reads_the_guid_again(
    dc: Dc, monkeypatch: pytest.MonkeyPatch, landed: bool, state: str
) -> None:
    """The delete by GUID raised: the object of the GUID is looked for again.
    Gone is undone; still there is undo_failed with the GUID as the
    conflict; the replacement at the planned DN is kept either way."""
    seen = _moved_and_replaced(dc, monkeypatch, with_guid=True)
    real = fake_samba_write.FakeSamDB.delete

    def lost(self: Any, name: str, controls: Any = None) -> None:
        if landed:
            real(self, name, controls)
        raise fake_samba_write.LdbError(52, "the answer was lost")

    monkeypatch.setattr(fake_samba_write.FakeSamDB, "delete", lost)

    answer = dc.run(_user_create(dc))

    assert answer["code"] == "error"
    assert _guid_at(dc, NEW_USER_DN) == REPLACEMENT_GUID
    record = dc.record()
    assert record["state"] == state
    assert record["restored"] is landed
    assert record["conflicts"] == ([] if landed else [seen[0]])


# ---- every write acts on the object of its GUID, in the one request ---------
#
# Each write names its object by the GUID form of a DN, never by a DN a
# search answered earlier: somebody may move Newton's object away and create
# another at that DN between the search and the write.  The hook runs inside
# the write, before the fake finds the object, so the replacement is already
# at the DN when the write arrives.

#: Where somebody moves an account Newton writes.
MOVED_ALICE_DN = "CN=alice," + fake_samba_write.USERS_DN
#: Where somebody moves a group Newton writes.
MOVED_GROUP_DN = "CN=Group 1106," + fake_samba_write.OTHER_OU_DN


def _replace_during(dc: Dc, kind: str, dn: str, new_dn: str) -> list[str]:
    """The first write of ``kind`` (delete, modify, rename): before the fake
    finds its object, somebody moves the object at ``dn`` to ``new_dn`` and
    creates another (``REPLACEMENT_GUID``) at ``dn``.  The answer holds the
    name each write of that kind was sent with."""
    names: list[str] = []

    def hook(write: str, name: str) -> None:
        if write != kind:
            return
        names.append(name)
        if len(names) == 1:
            dc.fake.move_and_replace(dn, new_dn, REPLACEMENT_GUID)

    dc.fake.before_write = hook
    return names


def _member_request(dc: Dc) -> dict[str, Any]:
    return dc.request(
        verb="member-add",
        target={
            "group_guid": fake_samba_write.GROUP_GUID,
            "group_sid": fake_samba_write.GROUP_SID,
            "group_sam": "group1106",
            "member_guid": fake_samba_write.ALICE_GUID,
            "member_sid": fake_samba_write.ALICE_SID,
            "member_sam": "alice",
        },
        before={"member": "absent"},
        after={"member": "present"},
    )


@pytest.mark.parametrize("refused", [False, True])
def test_a_cleanup_by_guid_never_deletes_an_account_made_at_the_dn_during_the_delete(
    dc: Dc, monkeypatch: pytest.MonkeyPatch, refused: bool
) -> None:
    """The GUID of Newton's new user was read and its uSNChanged was not.
    Between the cleanup's lookup and its delete, somebody moves Newton's
    object away and creates another account at the planned DN: the delete
    names the GUID, so Newton's object is deleted wherever it is and the
    replacement is kept (a delete the server refuses leaves both, and the
    record is undo_failed with the GUID), never undone with the replacement
    gone."""
    guid = fake_samba_write.created_guid(NEW_USER_DN)
    monkeypatch.setattr(dc.helper, "read_created", lambda directory, request: (guid, None))
    names = _replace_during(dc, "delete", NEW_USER_DN, MOVED_USER_DN)
    if refused:
        dc.fake.delete_code = 50

    answer = dc.run(_user_create(dc))

    assert answer["code"] == "error"
    assert names, "the cleanup sent no delete"
    assert dc.fake.has_object(NEW_USER_DN), "the replacement was deleted"
    assert _guid_at(dc, NEW_USER_DN) == REPLACEMENT_GUID
    record = dc.record()
    if refused:
        assert _guid_at(dc, MOVED_USER_DN) == guid
        assert record["state"] == "undo_failed"
        assert record["conflicts"] == [guid]
    else:
        assert not dc.fake.has_object(MOVED_USER_DN)
        assert record["state"] == "undone"
        assert record["restored"] is True


@pytest.mark.parametrize("way", ["abort", "timer", "sweep"])
def test_the_undo_of_a_user_create_never_deletes_an_account_made_at_the_dn_during_the_delete(
    dc: Dc, way: str
) -> None:
    """The undo checks Newton's new user by its GUID; between that read and
    the delete somebody moves it away and creates another account at its
    DN.  The delete names the GUID: Newton's object is deleted, the
    replacement is kept and the record is undone."""
    assert dc.run(_user_create(dc))["code"] == "ok"
    guid = fake_samba_write.created_guid(NEW_USER_DN)
    names = _replace_during(dc, "delete", NEW_USER_DN, MOVED_USER_DN)

    _undo_way(dc, way)

    assert names, "the undo sent no delete"
    assert dc.fake.has_object(NEW_USER_DN), "the replacement was deleted"
    assert _guid_at(dc, NEW_USER_DN) == REPLACEMENT_GUID
    assert not dc.fake.has_object(MOVED_USER_DN)
    record = dc.record()
    assert record["state"] == "undone"
    assert record["restored"] is True
    assert dc.record()["created"] == guid


def test_the_undo_of_a_user_create_whose_guid_delete_is_refused_keeps_both_accounts(
    dc: Dc,
) -> None:
    assert dc.run(_user_create(dc))["code"] == "ok"
    guid = fake_samba_write.created_guid(NEW_USER_DN)
    _replace_during(dc, "delete", NEW_USER_DN, MOVED_USER_DN)
    dc.fake.delete_code = 50

    answer = dc.run({"v": 1, "mode": "abort", "device": DEVICE, "txid": TXID})

    assert answer["restored"] is False
    assert dc.fake.has_object(NEW_USER_DN), "the replacement was deleted"
    assert _guid_at(dc, NEW_USER_DN) == REPLACEMENT_GUID
    assert _guid_at(dc, MOVED_USER_DN) == guid
    assert dc.record()["state"] == "undo_failed"


def test_an_apply_modify_never_writes_an_account_made_at_the_dn_during_the_write(
    dc: Dc,
) -> None:
    """Between the read of the before-image and the modify, somebody moves
    the target away and creates another account (with the same value) at
    its DN: the modify names the GUID, so Newton's object takes the value
    and the replacement keeps its own."""
    _replace_during(dc, "modify", fake_samba_write.ALICE_DN, MOVED_ALICE_DN)

    answer = dc.run(dc.request())

    assert answer["code"] == "ok"
    assert _guid_at(dc, MOVED_ALICE_DN) == fake_samba_write.ALICE_GUID
    assert dc.fake.get_attribute(MOVED_ALICE_DN, "userAccountControl") == "512"
    assert _guid_at(dc, fake_samba_write.ALICE_DN) == REPLACEMENT_GUID
    assert dc.fake.get_attribute(fake_samba_write.ALICE_DN, "userAccountControl") == "4194816"


@pytest.mark.parametrize("way", ["abort", "timer", "sweep"])
def test_an_undo_modify_never_writes_an_account_made_at_the_dn_during_the_write(
    dc: Dc, way: str
) -> None:
    assert dc.run(dc.request())["code"] == "ok"
    _replace_during(dc, "modify", fake_samba_write.ALICE_DN, MOVED_ALICE_DN)

    _undo_way(dc, way)

    assert dc.fake.get_attribute(MOVED_ALICE_DN, "userAccountControl") == "4194816"
    assert _guid_at(dc, fake_samba_write.ALICE_DN) == REPLACEMENT_GUID
    assert dc.fake.get_attribute(fake_samba_write.ALICE_DN, "userAccountControl") == "512"
    assert dc.record()["state"] == "undone"


def test_a_member_add_never_writes_a_group_made_at_the_dn_during_the_write(dc: Dc) -> None:
    _replace_during(dc, "modify", fake_samba_write.GROUP_DN, MOVED_GROUP_DN)

    answer = dc.run(_member_request(dc))

    assert answer["code"] == "ok"
    assert dc.fake.get_attribute(MOVED_GROUP_DN, "member") == fake_samba_write.ALICE_DN
    assert _guid_at(dc, fake_samba_write.GROUP_DN) == REPLACEMENT_GUID
    assert dc.fake.get_attribute(fake_samba_write.GROUP_DN, "member") is None


def test_the_undo_of_a_member_add_never_writes_a_group_made_at_the_dn_during_the_write(
    dc: Dc,
) -> None:
    assert dc.run(_member_request(dc))["code"] == "ok"
    _replace_during(dc, "modify", fake_samba_write.GROUP_DN, MOVED_GROUP_DN)

    answer = dc.run({"v": 1, "mode": "abort", "device": DEVICE, "txid": TXID})

    assert answer["code"] == "ok"
    assert dc.fake.get_attribute(MOVED_GROUP_DN, "member") is None
    assert _guid_at(dc, fake_samba_write.GROUP_DN) == REPLACEMENT_GUID
    assert dc.fake.get_attribute(fake_samba_write.GROUP_DN, "member") == fake_samba_write.ALICE_DN
    assert dc.record()["state"] == "undone"


def test_a_move_never_renames_an_account_made_at_the_dn_during_the_rename(dc: Dc) -> None:
    _replace_during(dc, "rename", fake_samba_write.ALICE_DN, MOVED_ALICE_DN)

    answer = dc.run(_move_request(dc))

    assert answer["code"] == "ok"
    assert _guid_at(dc, "CN=alice," + fake_samba_write.OTHER_OU_DN) == fake_samba_write.ALICE_GUID
    assert _guid_at(dc, fake_samba_write.ALICE_DN) == REPLACEMENT_GUID
    assert not dc.fake.has_object(MOVED_ALICE_DN)


def test_the_undo_of_a_move_never_renames_an_account_made_at_the_dn_during_the_rename(
    dc: Dc,
) -> None:
    assert dc.run(_move_request(dc))["code"] == "ok"
    moved_to = "CN=alice," + fake_samba_write.OTHER_OU_DN
    _replace_during(dc, "rename", moved_to, MOVED_ALICE_DN)

    answer = dc.run({"v": 1, "mode": "abort", "device": DEVICE, "txid": TXID})

    assert answer["code"] == "ok"
    assert _guid_at(dc, fake_samba_write.ALICE_DN) == fake_samba_write.ALICE_GUID
    assert _guid_at(dc, moved_to) == REPLACEMENT_GUID
    assert not dc.fake.has_object(MOVED_ALICE_DN)
    assert dc.record()["state"] == "undone"


def test_every_write_of_the_helper_names_its_object_by_guid(dc: Dc) -> None:
    """The delete, the modify and the rename of a user-create, an attribute
    verb, a membership and a move, and of their undos, are each sent with
    the GUID form of the DN (the domain head of a maq is the one exception:
    it cannot be moved away)."""
    names: list[tuple[str, str]] = []
    dc.fake.before_write = lambda kind, name: names.append((kind, name))
    for payload in (dc.request(), _member_request(dc), _move_request(dc), _user_create(dc)):
        assert dc.run(payload)["code"] == "ok"
        assert dc.run({"v": 1, "mode": "abort", "device": DEVICE, "txid": TXID})["code"] == "ok"
        for path in dc.tx.glob("*.json"):
            path.unlink()

    kinds = {kind for kind, _ in names}
    assert kinds == {"modify", "rename", "delete"}
    assert all(name.startswith("<GUID=") and name.endswith(">") for _, name in names), names


# An undo reads the live value (or the members of the group) by the GUID it
# writes, never by a DN a lookup answered: between the GUID lookup and the
# next request, somebody may move Newton's object away and create another
# at that DN that already holds the before-image.  The hook runs at the next
# search or write after the first search of the object by its GUID.


def _replace_after_guid_lookup(
    dc: Dc, guid: str, dn: str, new_dn: str, attribute: str, values: list[bytes]
) -> list[bool]:
    """Somebody moves the object at ``dn`` to ``new_dn`` and creates another
    (``REPLACEMENT_GUID``) at ``dn`` whose ``attribute`` holds ``values``, at
    the first search or write that follows the first search of ``guid``.
    The answer holds True once the replacement is made."""
    import uuid

    escaped = dc.helper._escape_binary(uuid.UUID(guid).bytes_le)
    seen: list[bool] = []
    done: list[bool] = []
    record = dc.fake.record

    def fire() -> None:
        if seen and not done:
            done.append(True)
            dc.fake.move_and_replace(dn, new_dn, REPLACEMENT_GUID)
            dc.fake.objects[dn][attribute] = list(values)

    def hooked(kind: str, text: str) -> None:
        if kind == "search":
            fire()
            if escaped in text:
                seen.append(True)
        record(kind, text)

    dc.fake.record = hooked  # type: ignore[method-assign]
    dc.fake.before_write = lambda kind, name: fire()
    return done


@pytest.mark.parametrize("way", ["abort", "timer", "sweep"])
def test_an_attribute_undo_reads_the_live_value_by_guid_never_by_a_dn_a_lookup_answered(
    dc: Dc, way: str
) -> None:
    """The replacement at the DN holds the before-image: an undo that read
    the DN would find nothing to restore and say undone while Newton's
    object still holds the after-image."""
    assert dc.run(dc.request())["code"] == "ok"
    done = _replace_after_guid_lookup(
        dc,
        fake_samba_write.ALICE_GUID,
        fake_samba_write.ALICE_DN,
        MOVED_ALICE_DN,
        "useraccountcontrol",
        [b"4194816"],
    )

    _undo_way(dc, way)

    assert done, "the replacement was never made"
    assert _guid_at(dc, MOVED_ALICE_DN) == fake_samba_write.ALICE_GUID
    assert dc.fake.get_attribute(MOVED_ALICE_DN, "userAccountControl") == "4194816"
    assert _guid_at(dc, fake_samba_write.ALICE_DN) == REPLACEMENT_GUID
    record = dc.record()
    assert record["state"] == "undone"
    assert record["restored"] is True


@pytest.mark.parametrize("way", ["abort", "timer", "sweep"])
def test_a_membership_undo_reads_the_group_by_guid_never_by_a_dn_a_lookup_answered(
    dc: Dc, way: str
) -> None:
    """The replacement group at the DN has no member: an undo that read the
    DN would find the member already out and say undone while Newton's
    group still holds the member the apply added."""
    assert dc.run(_member_request(dc))["code"] == "ok"
    done = _replace_after_guid_lookup(
        dc, fake_samba_write.GROUP_GUID, fake_samba_write.GROUP_DN, MOVED_GROUP_DN, "member", []
    )

    _undo_way(dc, way)

    assert done, "the replacement was never made"
    assert _guid_at(dc, MOVED_GROUP_DN) == fake_samba_write.GROUP_GUID
    assert dc.fake.get_attribute(MOVED_GROUP_DN, "member") is None
    assert _guid_at(dc, fake_samba_write.GROUP_DN) == REPLACEMENT_GUID
    record = dc.record()
    assert record["state"] == "undone"
    assert record["restored"] is True


@pytest.mark.parametrize("after", ["group", "member"])
@pytest.mark.parametrize("way", ["abort", "timer", "sweep"])
def test_a_membership_undo_never_says_undone_when_the_member_moved_during_the_reads(
    dc: Dc, way: str, after: str
) -> None:
    """Right after the first search of the group (or of the member) by its
    GUID, somebody moves the member away (the group's member value follows
    it) and makes another account at its old DN.  The member's DN is read
    again after the group: an undo that took the group's list at the old DN
    for "the member is already out" would record undone while the member is
    still in the group."""
    import uuid

    assert dc.run(_member_request(dc))["code"] == "ok"
    guid = fake_samba_write.GROUP_GUID if after == "group" else fake_samba_write.ALICE_GUID
    escaped = dc.helper._escape_binary(uuid.UUID(guid).bytes_le)
    seen: list[bool] = []
    done: list[bool] = []
    record = dc.fake.record

    def fire() -> None:
        if seen and not done:
            done.append(True)
            dc.fake.move_and_replace(fake_samba_write.ALICE_DN, MOVED_ALICE_DN, REPLACEMENT_GUID)
            dc.fake.objects[fake_samba_write.GROUP_DN]["member"] = [MOVED_ALICE_DN.encode("utf-8")]

    def hooked(kind: str, text: str) -> None:
        if kind == "search":
            fire()
            if escaped in text:
                seen.append(True)
        record(kind, text)

    dc.fake.record = hooked  # type: ignore[method-assign]
    dc.fake.before_write = lambda kind, name: fire()

    _undo_way(dc, way)

    assert done, "the member was never moved"
    record_now = dc.record()
    if record_now["state"] == "undone":
        assert dc.fake.get_attribute(fake_samba_write.GROUP_DN, "member") is None
    else:
        assert record_now["restored"] is False
        assert dc.fake.get_attribute(fake_samba_write.GROUP_DN, "member") == MOVED_ALICE_DN


# ---- membership presence is decided in one search, by the member's GUID -----
#
# Somebody moves the member between any two of the helper's reads (and moves
# it back at the next one: A -> B -> A).  Presence decided by comparing a DN
# read in one search with the group's list read in another can then read
# "absent" while the member is in the group.  The fake's linked values follow
# the member (as Samba's do), so the truth is whether a value of the group's
# member names the object of the member's GUID.


def _member_in_group(dc: Dc) -> bool:
    """The member is in the group: a value of the group's member names the
    object that holds the member's GUID, wherever it is now."""
    wanted = fake_samba_write.guid_bytes(fake_samba_write.ALICE_GUID)
    for value in dc.fake.values_of(fake_samba_write.GROUP_DN, "member"):
        for dn, attributes in dc.fake.objects.items():
            if dn.lower() == value.decode("utf-8").lower():
                if wanted in attributes.get("objectguid", []):
                    return True
    return False


def _move_member_at(
    dc: Dc, start: int, back: bool, after_write: bool = False
) -> list[str]:
    """Before read or write number ``start`` (searches and modifies, counted
    from now, or from the first modify with ``after_write``) somebody moves
    the member to MOVED_ALICE_DN; with ``back``, before the next one they
    move it back.  The answer names each move."""
    moves: list[str] = []
    count = [0]
    written = [not after_write]
    record = dc.fake.record

    def hooked(kind: str, text: str) -> None:
        if kind == "modify" and not written[0]:
            written[0] = True
            record(kind, text)
            return
        if kind in ("search", "modify") and written[0]:
            count[0] += 1
            if count[0] == start:
                dc.fake.move_object(fake_samba_write.ALICE_DN, MOVED_ALICE_DN)
                moves.append("away")
            elif back and count[0] == start + 1 and moves:
                dc.fake.move_object(MOVED_ALICE_DN, fake_samba_write.ALICE_DN)
                moves.append("back")
        record(kind, text)

    dc.fake.record = hooked  # type: ignore[method-assign]
    return moves


@pytest.mark.parametrize("back", [False, True])
@pytest.mark.parametrize("start", [1, 2, 3])
@pytest.mark.parametrize("way", ["abort", "timer", "sweep"])
def test_a_member_add_undo_never_says_undone_with_the_member_moved_between_its_reads(
    dc: Dc, way: str, start: int, back: bool
) -> None:
    """The undo of a member-add, with the member moved before any one of its
    reads or its write (and moved back at the next one): undone means the
    member is out of the group; anything else says restored=false with the
    member still in it."""
    assert dc.run(_member_request(dc))["code"] == "ok"
    assert _member_in_group(dc)
    moves = _move_member_at(dc, start, back)

    _undo_way(dc, way)

    assert moves, "the member was never moved"
    record = dc.record()
    if record["state"] == "undone":
        assert record["restored"] is True
        assert not _member_in_group(dc)
    else:
        assert record["restored"] is False
        assert _member_in_group(dc)


@pytest.mark.parametrize(
    ("start", "back", "after_write"),
    [
        (1, False, False),
        (1, True, False),
        (2, False, False),
        (2, True, False),
        (3, False, False),
        (1, False, True),
        (1, True, True),
        (2, False, True),
    ],
)
@pytest.mark.parametrize("way", ["abort", "timer", "sweep"])
def test_a_member_add_undo_with_a_lost_answer_never_reads_the_member_out_by_a_move(
    dc: Dc, way: str, start: int, back: bool, after_write: bool
) -> None:
    """The undo's modify gets no answer and does not land, so the member is
    still in the group and the read-back decides the outcome.  A member moved
    before any read of the undo or of its read-back (and moved back at the
    next) never makes a read say "absent": the record is never undone,
    never restored."""
    assert dc.run(_member_request(dc))["code"] == "ok"
    dc.fake.modify_code = fake_samba_write.ERR_OTHER
    moves = _move_member_at(dc, start, back, after_write)

    _undo_way(dc, way)

    assert moves, "the member was never moved"
    assert _member_in_group(dc)
    record = dc.record()
    assert record["state"] != "undone"
    assert record["restored"] is False


def _member_remove_request(dc: Dc) -> dict[str, Any]:
    request = _member_request(dc)
    return dc.request(
        verb="member-remove",
        target=request["target"],
        before={"member": "present"},
        after={"member": "absent"},
    )


@pytest.mark.parametrize("back", [False, True])
@pytest.mark.parametrize("start", [1, 2, 3, 4, 5])
def test_a_member_remove_confirm_never_reads_the_member_out_by_a_move(
    dc: Dc, start: int, back: bool
) -> None:
    """Newton's member-remove landed, then somebody put the member back in
    the group: the target no longer shows the after-image, so the confirm
    is refused.  A member moved before any of the confirm's reads (and moved
    back at the next) never makes it read "absent" and confirm."""
    dc.fake.add_member(fake_samba_write.GROUP_DN, fake_samba_write.ALICE_DN)
    assert dc.run(_member_remove_request(dc))["code"] == "ok"
    assert not _member_in_group(dc)
    dc.fake.add_member(fake_samba_write.GROUP_DN, fake_samba_write.ALICE_DN)
    moves = _move_member_at(dc, start, back)

    answer = dc.run({"v": 1, "mode": "confirm", "device": DEVICE, "txid": TXID})

    assert moves, "the member was never moved"
    assert _member_in_group(dc)
    assert answer["code"] == "conflict"
    assert dc.record()["state"] == "armed"


@pytest.mark.parametrize("way", ["abort", "timer", "sweep"])
def test_a_member_value_without_its_guid_is_never_read_as_absent(
    dc: Dc, monkeypatch: pytest.MonkeyPatch, way: str
) -> None:
    """A member value the search answers without its GUID (the extended DN
    control not honoured) cannot be matched to the member: the presence
    cannot be read, so the undo of a member-add never says undone while
    the member is in the group."""
    assert dc.run(_member_request(dc))["code"] == "ok"
    monkeypatch.setattr(dc.fake, "extend_links", lambda message: None)

    _undo_way(dc, way)

    assert _member_in_group(dc)
    record = dc.record()
    assert record["state"] != "undone"
    assert record["restored"] is False


def test_the_helper_decides_membership_presence_in_one_search_by_guid() -> None:
    """Every membership presence of the helper is the one function that reads
    the group by its GUID with the extended DN control: no DN read in another
    search is compared with the group's member list."""
    import re

    source = Path(fake_samba_write.__file__).parent.parent.parent / (
        "newton_mcp/ad/collector/newton-ad-samba-write"
    )
    text = source.read_text(encoding="utf-8")
    assert '"extended_dn:1:1"' in text
    assert re.search(r"in\s+directory\.members\(", text) is None
    assert "_member_dn(directory, target.get(\"member_guid\")) != member" not in text


# ---- an attribute the bind cannot read is never read as a known value --------
#
# The helper binds as the DC's account, so the directory's ACLs apply: an
# attribute it has no read right on is left out of the answer and a filter
# on it behaves as if the object did not hold it (MS-ADTS 3.1.1.4.3; Samba's
# acl_read marks it inaccessible and ldb_match_message never matches it).
# An empty group and a group whose member the bind cannot read look the
# same, and so do a missing value and an unreadable one.  The fake's
# ``hidden`` knob models that.  A write still sees the values: the server
# checks a modify against the values it holds.


def _hide(dc: Dc, *names: str) -> None:
    dc.fake.hidden = {name.lower() for name in names}


@pytest.mark.parametrize("way", ["abort", "timer", "sweep"])
def test_a_member_add_undo_with_the_member_unreadable_never_says_undone_with_the_member_in(
    dc: Dc, way: str
) -> None:
    """Newton's member-add landed, then the group's member became unreadable
    to the bind.  An undo that took "no member value" for "the member is out"
    would record undone with nothing written while the member is in the
    group.  The undo writes the remove, and the server decides it."""
    assert dc.run(_member_request(dc))["code"] == "ok"
    assert _member_in_group(dc)
    _hide(dc, "member")

    _undo_way(dc, way)

    record = dc.record()
    assert not _member_in_group(dc)
    assert record["state"] == "undone"
    assert record["restored"] is True


@pytest.mark.parametrize("way", ["abort", "timer", "sweep"])
def test_a_member_add_undo_with_a_lost_answer_and_the_member_unreadable_stays_armed(
    dc: Dc, way: str
) -> None:
    """The undo's remove gets no answer and does not land, and the group's
    member cannot be read: the outcome is unknown, so the record stays armed
    (never undone, never restored) and a later pass runs the undo again."""
    assert dc.run(_member_request(dc))["code"] == "ok"
    _hide(dc, "member")
    dc.fake.modify_code = fake_samba_write.ERR_OTHER

    _undo_way(dc, way)

    assert _member_in_group(dc)
    record = dc.record()
    assert record["state"] == "armed"
    assert record["restored"] is False


@pytest.mark.parametrize("lost", [False, True])
@pytest.mark.parametrize("way", ["abort", "timer", "sweep"])
def test_a_member_remove_undo_with_the_member_unreadable_writes_the_member_back(
    dc: Dc, way: str, lost: bool
) -> None:
    """Newton's member-remove landed, then the group's member became
    unreadable.  The undo puts the member back with a write the server
    checks; with a lost answer the record stays armed."""
    dc.fake.add_member(fake_samba_write.GROUP_DN, fake_samba_write.ALICE_DN)
    assert dc.run(_member_remove_request(dc))["code"] == "ok"
    assert not _member_in_group(dc)
    _hide(dc, "member")
    if lost:
        dc.fake.modify_code = fake_samba_write.ERR_OTHER

    _undo_way(dc, way)

    record = dc.record()
    if lost:
        assert not _member_in_group(dc)
        assert record["state"] == "armed"
        assert record["restored"] is False
    else:
        assert _member_in_group(dc)
        assert record["state"] == "undone"
        assert record["restored"] is True


def test_a_member_add_read_back_with_the_member_unreadable_is_unreadable(dc: Dc) -> None:
    """The add landed (the server took it), and the group's member cannot be
    read: the read-back answers a target that cannot be read, never
    "absent"."""
    _hide(dc, "member")

    answer = dc.run(_member_request(dc))

    assert answer["code"] == "ok", answer
    assert answer["live"] == {}
    assert _member_in_group(dc)
    assert dc.record()["state"] == "armed"


def test_a_member_add_with_the_member_unreadable_and_already_in_writes_nothing(
    dc: Dc,
) -> None:
    """The group reads empty to the bind while the member is in it: the
    before-check cannot tell, and the add the server checks is refused (the
    value is there), so nothing is written and the record is refused."""
    dc.fake.add_member(fake_samba_write.GROUP_DN, fake_samba_write.ALICE_DN)
    _hide(dc, "member")

    answer = dc.run(_member_request(dc))

    assert answer["code"] == "conflict", answer
    assert _member_in_group(dc)
    assert dc.fake.values_of(fake_samba_write.GROUP_DN, "member") == [
        fake_samba_write.ALICE_DN.encode("utf-8")
    ]
    assert dc.record()["state"] == "refused"


def test_a_member_add_confirm_with_the_member_unreadable_is_refused(dc: Dc) -> None:
    assert dc.run(_member_request(dc))["code"] == "ok"
    _hide(dc, "member")

    answer = _confirm(dc, TXID)

    assert answer["code"] == "conflict"
    assert dc.record()["state"] == "armed"


def _etypes_request(dc: Dc) -> dict[str, Any]:
    """An enc-types of alice from no value to 24."""
    dc.fake.set_values(fake_samba_write.ALICE_DN, "msDS-SupportedEncryptionTypes", [])
    return dc.request(
        verb="enc-types",
        target={"guid": fake_samba_write.ALICE_GUID, "sid": fake_samba_write.ALICE_SID,
                "sam": "alice"},
        before={"etypes": "absent"},
        after={"etypes": 24},
    )


@pytest.mark.parametrize("lost", [False, True])
@pytest.mark.parametrize("way", ["abort", "timer", "sweep"])
def test_an_enc_types_undo_with_the_value_unreadable_never_says_undone_with_it_there(
    dc: Dc, way: str, lost: bool
) -> None:
    """Newton's enc-types put a value where there was none, then the value
    became unreadable to the bind.  An undo that took "no value" for "no
    value to remove" would record undone with the value still there.  The
    undo writes the remove, and the server decides it; with a lost answer
    the record stays armed."""
    assert dc.run(_etypes_request(dc))["code"] == "ok"
    _hide(dc, "msDS-SupportedEncryptionTypes")
    if lost:
        dc.fake.modify_code = fake_samba_write.ERR_OTHER

    _undo_way(dc, way)

    values = dc.fake.values_of(fake_samba_write.ALICE_DN, "msDS-SupportedEncryptionTypes")
    record = dc.record()
    if lost:
        assert values == [b"24"]
        assert record["state"] == "armed"
        assert record["restored"] is False
    else:
        assert values == []
        assert record["state"] == "undone"
        assert record["restored"] is True


def test_a_maq_confirm_with_the_quota_unreadable_is_refused(dc: Dc) -> None:
    """Newton's maq set the quota to 0, then somebody set it back to 10 and
    the quota became unreadable to the bind.  A confirm that took "no value"
    for 0 would record confirmed over somebody else's value."""
    answer = dc.run(dc.request(
        verb="maq", target={"guid": fake_samba_write.DOMAIN_GUID},
        before={"maq": 10}, after={"maq": 0},
    ))
    assert answer["code"] == "ok", answer
    dc.fake.set_values(fake_samba_write.DOMAIN_DN, "ms-DS-MachineAccountQuota", [b"10"])
    _hide(dc, "ms-DS-MachineAccountQuota")

    assert _confirm(dc, TXID)["code"] == "conflict"
    assert dc.record()["state"] == "armed"


def test_the_sweep_never_settles_an_armed_unlock_whose_lockout_cannot_be_read(
    dc: Dc,
) -> None:
    """An armed unlock whose write may still land, and an account whose
    lockoutTime the bind cannot read: "no value" is not the after-image 0
    (an unlock writes 0), so the sweep never records it confirmed."""
    _plant_armed_unlock(dc)
    _hide(dc, "lockoutTime")
    dc.helper.current_time = lambda: float(NBF + 120 + 60)

    assert dc.helper.handle(["--sweep"], b"", {})["code"] == "ok"

    assert dc.record(POISON)["state"] == "armed"
    assert dc.fake.get_attribute(fake_samba_write.ALICE_DN, "lockoutTime") == "1000"


# ---- the verification read of every DC is an outcome read ---------------------
#
# Newton reads the target back from every DC (read mode) and confirms only
# when every one shows the after-image.  Each DC binds as its own account, so
# a replica may hold another value it cannot read: its answer must never be
# the after-image.  The read answers ``outcome``, the image an outcome is
# read from (read_back), and Newton matches that, never the planning image
# ``live``.

ALICE_TARGET = {"guid": fake_samba_write.ALICE_GUID, "sid": fake_samba_write.ALICE_SID,
                "sam": "alice"}
ALICE_MEMBERSHIP = {
    "group_guid": fake_samba_write.GROUP_GUID, "group_sid": fake_samba_write.GROUP_SID,
    "group_sam": "group1106", "member_guid": fake_samba_write.ALICE_GUID,
    "member_sid": fake_samba_write.ALICE_SID, "member_sam": "alice",
}


def _replica_case(dc: Dc, case: str) -> tuple[dict[str, Any], dict[str, Any], tuple[str, ...]]:
    """The verb, target and after-image of a change the replica has not got
    yet (it holds another value), and the attribute its bind cannot read."""
    if case == "maq":
        dc.fake.set_values(fake_samba_write.DOMAIN_DN, "ms-DS-MachineAccountQuota", [b"10"])
        return ({"verb": "maq", "target": {"guid": fake_samba_write.DOMAIN_GUID}},
                {"maq": 0}, ("ms-DS-MachineAccountQuota",))
    if case == "unlock":
        dc.fake.set_values(fake_samba_write.ALICE_DN, "lockoutTime", [b"1000"])
        return {"verb": "unlock", "target": ALICE_TARGET}, {"lockout": 0}, ("lockoutTime",)
    if case == "enc-types":
        dc.fake.set_values(fake_samba_write.ALICE_DN, "msDS-SupportedEncryptionTypes", [b"16"])
        return ({"verb": "enc-types", "target": ALICE_TARGET}, {"etypes": 24},
                ("msDS-SupportedEncryptionTypes",))
    if case == "member-add":
        return ({"verb": "member-add", "target": ALICE_MEMBERSHIP}, {"member": "present"},
                ("member",))
    raise AssertionError(case)


REPLICA_CASES = ["maq", "unlock", "enc-types", "member-add"]


def _verify_on(dc: Dc, fields: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    """Newton's verification of one DC (apply._verify), answered by this
    helper."""
    plan = {"device": DEVICE, "after": after, **fields}
    replica = type("Device", (), {"name": "sdc2"})()
    return core_apply._verify(
        lambda device, payload, session_s: dc.run(payload), [replica], plan, 0, 0,
        lambda seconds: None, lambda: 0.0, 600.0,
    )["sdc2"]


@pytest.mark.parametrize("case", REPLICA_CASES)
def test_a_replica_whose_value_cannot_be_read_never_verifies_matched(dc: Dc, case: str) -> None:
    """The replica still holds the before value and its bind cannot read
    it: the read answers an outcome that is not the after-image, so the
    DC never reads matched and the change is never confirmed."""
    fields, after, hidden = _replica_case(dc, case)
    _hide(dc, *hidden)

    answer = dc.run({"v": 1, "mode": "read", **{"device": DEVICE}, **fields})

    assert answer["code"] == "ok", answer
    assert answer["outcome"] != after
    if case in ("maq", "unlock"):
        assert answer["outcome"] == {}
    state = _verify_on(dc, fields, after)
    assert state["state"] == "not_tested"
    assert state["live"] != after


@pytest.mark.parametrize("case", REPLICA_CASES)
def test_a_replica_that_shows_the_after_image_verifies_matched(dc: Dc, case: str) -> None:
    """The control: the replica holds the after-image and can read it."""
    fields, after, _hidden = _replica_case(dc, case)
    if case == "maq":
        dc.fake.set_values(fake_samba_write.DOMAIN_DN, "ms-DS-MachineAccountQuota", [b"0"])
    elif case == "unlock":
        dc.fake.set_values(fake_samba_write.ALICE_DN, "lockoutTime", [b"0"])
    elif case == "enc-types":
        dc.fake.set_values(fake_samba_write.ALICE_DN, "msDS-SupportedEncryptionTypes", [b"24"])
    else:
        dc.fake.add_member(fake_samba_write.GROUP_DN, fake_samba_write.ALICE_DN)

    answer = dc.run({"v": 1, "mode": "read", "device": DEVICE, **fields})

    assert answer["outcome"] == after
    assert _verify_on(dc, fields, after) == {"state": "matched", "live": after}


def test_a_read_of_a_user_account_control_the_bind_cannot_read_has_an_empty_outcome(
    dc: Dc,
) -> None:
    _hide(dc, "userAccountControl")

    answer = dc.run({"v": 1, "mode": "read", "device": DEVICE, "verb": "uac-clear",
                     "target": {**ALICE_TARGET, "bit": 4194304}})

    assert answer["live"] == {"uac": 0}
    assert answer["outcome"] == {}


#: One plan per verb whose before-image Newton reads from the outcome too:
#: the names, the value and the userAccountControl Alice holds.
SAMBA_READ_BEFORE_PLANS: dict[str, tuple[list[str], Any, int]] = {
    "uac-clear": (["alice"], 4194304, 4194816),
    "disable": (["alice"], None, 4194816),
    "enable": (["alice"], None, 4194818),
    "move": (["alice"], fake_samba_write.OTHER_OU_GUID, 4194816),
}


def _plan_on(dc: Dc, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, verb: str) -> dict[str, Any]:
    """Newton's plan of one verb, read from this helper."""
    from newton_mcp.ad.write import plan as ad_plan
    from newton_mcp.server import Device

    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))
    device = Device(name=DEVICE, platform="ad-samba-write", host="192.0.2.20",
                    user="newton-ops-ssh", ad_domain=DEVICE,
                    ad_domain_guid="af9619ff-8b86-d011-b42d-00c04fc964ff")
    names, value, uac = SAMBA_READ_BEFORE_PLANS[verb]
    dc.fake.set_values(fake_samba_write.ALICE_DN, "userAccountControl", [str(uac).encode()])
    return ad_plan.plan_change(DEVICE, verb, names, value,
                               send=lambda target, body: dc.run(body), devices={DEVICE: device})


def _unreadable_before(dc: Dc, monkeypatch: pytest.MonkeyPatch, verb: str) -> None:
    """The bind cannot read the before-image of the verb: the
    userAccountControl, or (a move) the objectGUID of Alice's parent OU
    alone (the fake hides an attribute on every object, so the parent's
    is taken away at the helper's read of it)."""
    if verb != "move":
        _hide(dc, "userAccountControl")
        return
    real = dc.helper.Directory.guid

    def guid(self: Any, message: Any) -> Any:
        if str(message.dn).lower() == fake_samba_write.SERVERS_OU_DN.lower():
            return None
        return real(self, message)

    monkeypatch.setattr(dc.helper.Directory, "guid", guid)


@pytest.mark.parametrize("verb", sorted(SAMBA_READ_BEFORE_PLANS))
def test_a_samba_plan_whose_before_image_the_bind_can_read_goes_ahead(
    dc: Dc, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, verb: str
) -> None:
    """The control of the refusal below."""
    assert _plan_on(dc, tmp_path, monkeypatch, verb)["verb"] == verb


@pytest.mark.parametrize("verb", sorted(SAMBA_READ_BEFORE_PLANS))
def test_a_samba_plan_whose_before_image_the_bind_cannot_read_is_refused(
    dc: Dc, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, verb: str
) -> None:
    """A userAccountControl or a parent the bind cannot read reads 0 or no
    parent in the planning image and is missing from the outcome: Newton
    never plans an undo that writes back a value nobody read."""
    from newton_mcp.ad.write.errors import WriteError

    _unreadable_before(dc, monkeypatch, verb)

    with pytest.raises(WriteError, match="cannot read"):
        _plan_on(dc, tmp_path, monkeypatch, verb)


def test_a_replica_read_of_an_enc_types_removal_takes_no_value_for_the_removal(dc: Dc) -> None:
    """No value is the after-image of an enc-types that removes the value
    (the known limit the read-back has too), and never a number."""
    dc.fake.set_values(fake_samba_write.ALICE_DN, "msDS-SupportedEncryptionTypes", [])
    fields = {"verb": "enc-types", "target": ALICE_TARGET}

    answer = dc.run({"v": 1, "mode": "read", "device": DEVICE, **fields})

    assert answer["outcome"] == {"etypes": "absent"}
    assert _verify_on(dc, fields, {"etypes": "absent"})["state"] == "matched"
    assert _verify_on(dc, fields, {"etypes": 24})["state"] == "not_tested"


# ---- a new user is proven gone only by a read that says so ------------------
#
# A filter on objectGUID behaves as if the object did not hold it when the
# bind cannot read it (MS-ADTS 3.1.1.4.3), so a subtree search that finds no
# (objectGUID=...) is no proof that the object is gone.  The proof is a base
# search of <GUID=...> that answers no such object: Samba's extended_dn_in
# resolves that name as the system (DSDB_FLAG_AS_SYSTEM) and answers
# LDB_ERR_NO_SUCH_OBJECT ("Base-DN '...' not found") only when no object
# holds the GUID.


NEW_USER_DN = "CN=newton-user," + fake_samba_write.SERVERS_OU_DN


def test_the_fake_resolves_a_guid_base_as_the_system_and_answers_no_such_object(dc: Dc) -> None:
    """The fake's contract: a base search of <GUID=...> finds the object of
    the GUID even when the bind cannot read objectGUID, one no object holds
    answers 32, and a filter on a hidden objectGUID matches nothing."""
    db = fake_samba_write.FakeSamDB()
    _hide(dc, "objectGUID")
    found = db.search(base="<GUID=%s>" % fake_samba_write.ALICE_GUID,
                      scope=fake_samba_write.SCOPE_BASE,
                      expression="(objectClass=*)", attrs=["userAccountControl"])
    assert [str(one.dn) for one in found] == [fake_samba_write.ALICE_DN]
    raw = fake_samba_write.guid_bytes(fake_samba_write.ALICE_GUID)
    escaped = "".join("\\%02x" % byte for byte in raw)
    assert db.search(base=db.domain_dn(), scope=fake_samba_write.SCOPE_SUBTREE,
                     expression="(objectGUID=%s)" % escaped, attrs=["cn"]) == []
    with pytest.raises(fake_samba_write.LdbError) as missing:
        db.search(base="<GUID=00000000-0000-4000-8000-000000000001>",
                  scope=fake_samba_write.SCOPE_BASE, expression="(objectClass=*)", attrs=["cn"])
    assert missing.value.args[0] == 32


def test_the_fake_matches_the_object_class_presence_filter_on_a_visible_object(dc: Dc) -> None:
    """The fake's contract: Samba's acl_read exempts the (objectClass=*)
    presence filter for an object the bind can see, so a base search of it
    answers the object even when its objectClass cannot be read; a filter
    on a hidden objectClass with a value still matches nothing."""
    db = fake_samba_write.FakeSamDB()
    _hide(dc, "objectGUID", "objectClass")
    found = db.search(base="<GUID=%s>" % fake_samba_write.ALICE_GUID,
                      scope=fake_samba_write.SCOPE_BASE,
                      expression="(objectClass=*)", attrs=["cn"])
    assert [str(one.dn) for one in found] == [fake_samba_write.ALICE_DN]
    assert db.search(base=fake_samba_write.ALICE_DN, scope=fake_samba_write.SCOPE_BASE,
                     expression="(objectClass=user)", attrs=["cn"]) == []


def test_the_fake_answers_no_such_object_for_a_base_the_bind_cannot_see(dc: Dc) -> None:
    """The fake's contract: an object the bind cannot see at all (no list
    right on its parent) answers 32 to a base search of its GUID name or
    its DN, and a subtree search never returns it."""
    db = fake_samba_write.FakeSamDB()
    dc.fake.invisible = {fake_samba_write.ALICE_DN.lower()}
    for base in ("<GUID=%s>" % fake_samba_write.ALICE_GUID, fake_samba_write.ALICE_DN):
        with pytest.raises(fake_samba_write.LdbError) as missing:
            db.search(base=base, scope=fake_samba_write.SCOPE_BASE,
                      expression="(objectClass=*)", attrs=["cn"])
        assert missing.value.args[0] == 32
    found = db.search(base=db.domain_dn(), scope=fake_samba_write.SCOPE_SUBTREE,
                      expression="(sAMAccountName=alice)", attrs=["cn"])
    assert found == []
    assert dc.fake.has_object(fake_samba_write.ALICE_DN)


@pytest.mark.parametrize("way", ["abort", "timer", "sweep"])
def test_a_user_create_undo_with_the_guid_unreadable_never_says_undone_with_the_user_there(
    dc: Dc, way: str
) -> None:
    """Newton's new user is there and its objectGUID became unreadable to
    the bind: a search by the GUID finds nothing.  An undo that took that
    for "gone" would record undone, restored, with the user still there.
    The undo reads the user by its GUID name, deletes it and records the
    outcome."""
    assert dc.run(_user_create(dc))["code"] == "ok"
    assert dc.fake.has_object(NEW_USER_DN)
    _hide(dc, "objectGUID")

    _undo_way(dc, way)

    record = dc.record()
    assert not dc.fake.has_object(NEW_USER_DN)
    assert record["state"] == "undone"
    assert record["restored"] is True


@pytest.mark.parametrize("way", ["abort", "timer", "sweep"])
def test_a_user_create_undo_with_a_lost_delete_and_the_guid_unreadable_stays_armed(
    dc: Dc, way: str
) -> None:
    """The undo's delete gets no answer and does not land, and the user's
    objectGUID cannot be read: the user is there, so the record stays armed
    (never undone) and a later pass runs the undo again."""
    assert dc.run(_user_create(dc))["code"] == "ok"
    _hide(dc, "objectGUID")
    dc.fake.delete_code = 52

    _undo_way(dc, way)

    assert dc.fake.has_object(NEW_USER_DN)
    record = dc.record()
    assert record["state"] == "armed"
    assert record["restored"] is False


def _answers_nothing(monkeypatch: pytest.MonkeyPatch, guid: str) -> None:
    """From now on the base search of that GUID name answers no entry and
    no error.  Samba does not answer so for an object the bind can see
    (acl_read exempts the objectClass presence filter) nor for one it
    cannot (no such object): the answer is the defensive case of
    ``Unreadable``, an answer that proves neither gone nor there."""
    real = fake_samba_write.FakeSamDB.search

    def search(self: Any, base: Any = None, scope: Any = None, *args: Any, **kwargs: Any) -> Any:
        if str(base).lower() == ("<GUID=%s>" % guid).lower() and scope == fake_samba_write.SCOPE_BASE:
            return []
        return real(self, base, scope, *args, **kwargs)

    monkeypatch.setattr(fake_samba_write.FakeSamDB, "search", search)


def test_a_user_create_undo_whose_user_answers_nothing_is_never_undone(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The base search of the user's GUID name answers no entry and no
    error.  It is never taken for gone: the record is undo_failed with the
    GUID named."""
    assert dc.run(_user_create(dc))["code"] == "ok"
    guid = dc.record()["created"]
    _answers_nothing(monkeypatch, guid)

    answer = dc.run({"v": 1, "mode": "abort", "device": DEVICE, "txid": TXID})

    assert answer["code"] == "ok", answer
    assert answer["restored"] is False
    assert dc.fake.has_object(NEW_USER_DN)
    record = dc.record()
    assert record["state"] == "undo_failed"
    assert record["conflicts"] == [guid]


@pytest.mark.parametrize("nothing", [False, True])
def test_a_user_create_cleanup_whose_lost_delete_meets_an_unreadable_guid_is_never_undone(
    dc: Dc, monkeypatch: pytest.MonkeyPatch, nothing: bool
) -> None:
    """The uSNChanged of the new user is missing, so the apply deletes it at
    once by its GUID.  The delete gets no answer and does not land, and the
    objectGUID then cannot be read (or the base search of the GUID name
    answers no entry): the user is there, so the record is never undone (it
    names the GUID)."""
    guid = fake_samba_write.created_guid(NEW_USER_DN)
    monkeypatch.setattr(dc.helper, "read_created", lambda directory, request: (guid, None))
    real = fake_samba_write.FakeSamDB.delete

    def lost(self: Any, name: str, controls: Any = None) -> None:
        dc.fake.hidden = {"objectguid"}
        if nothing:
            _answers_nothing(monkeypatch, guid)
        raise fake_samba_write.LdbError(52, "the answer was lost")

    monkeypatch.setattr(fake_samba_write.FakeSamDB, "delete", lost)
    assert real is not lost

    answer = dc.run(_user_create(dc))

    assert answer["code"] == "error"
    assert dc.fake.has_object(NEW_USER_DN)
    record = dc.record()
    assert record["state"] != "undone"
    assert record["restored"] is False
    assert record["conflicts"] == [guid]


# ---- the same-target guard holds for every verb with an undo ---------------


def _alice() -> dict[str, Any]:
    return {"guid": fake_samba_write.ALICE_GUID, "sid": fake_samba_write.ALICE_SID,
            "sam": "alice"}


def _bob() -> dict[str, Any]:
    return {"guid": fake_samba_write.BOB_GUID, "sid": fake_samba_write.BOB_SID, "sam": "bob"}


def _membership(member: dict[str, Any]) -> dict[str, Any]:
    return {
        "group_guid": fake_samba_write.GROUP_GUID, "group_sid": fake_samba_write.GROUP_SID,
        "group_sam": "group1106", "member_guid": member["guid"],
        "member_sid": member["sid"], "member_sam": member["sam"],
    }


def _same_target_case(dc: Dc, verb: str) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """The request of one verb on a target, and the same verb on another
    target (None when the verb has one target only: the domain's quota)."""
    fake = dc.fake
    if verb in ("uac-clear", "disable", "enable"):
        values = {"uac-clear": (b"4194816", 4194816, 512),
                  "disable": (b"512", 512, 514),
                  "enable": (b"514", 514, 512)}[verb]
        for dn in (fake_samba_write.ALICE_DN, fake_samba_write.BOB_DN):
            fake.set_values(dn, "userAccountControl", [values[0]])
        extra = {"bit": 4194304} if verb == "uac-clear" else {}
        shape = {"verb": verb, "before": {"uac": values[1]}, "after": {"uac": values[2]}}
        return ({**shape, "target": {**_alice(), **extra}},
                {**shape, "target": {**_bob(), **extra}})
    if verb == "enc-types":
        fake.set_values(fake_samba_write.BOB_DN, "msDS-SupportedEncryptionTypes", [b"0"])
        shape = {"verb": verb, "before": {"etypes": 0}, "after": {"etypes": 24}}
        return {**shape, "target": _alice()}, {**shape, "target": _bob()}
    if verb == "move":
        shape = {"verb": verb, "before": {"parent": fake_samba_write.SERVERS_OU_GUID},
                 "after": {"parent": fake_samba_write.OTHER_OU_GUID}}
        return {**shape, "target": _alice()}, {**shape, "target": _bob()}
    if verb == "maq":
        return ({"verb": verb, "target": {"guid": fake_samba_write.DOMAIN_GUID},
                 "before": {"maq": 10}, "after": {"maq": 20}}, None)
    if verb == "member-add":
        shape = {"verb": verb, "before": {"member": "absent"}, "after": {"member": "present"}}
        return ({**shape, "target": _membership(_alice())},
                {**shape, "target": _membership(_bob())})
    if verb == "member-remove":
        fake.add_member(fake_samba_write.GROUP_DN, fake_samba_write.ALICE_DN)
        fake.add_member(fake_samba_write.GROUP_DN, fake_samba_write.BOB_DN)
        shape = {"verb": verb, "before": {"member": "present"}, "after": {"member": "absent"}}
        return ({**shape, "target": _membership(_alice())},
                {**shape, "target": _membership(_bob())})
    if verb == "user-create":
        shape = {"verb": verb, "before": {"object": "absent"}, "after": {"object": "present"}}
        shape["secret"] = SECRET
        parent = fake_samba_write.SERVERS_OU_GUID
        return ({**shape, "target": {"parent_guid": parent, "sam": "newton-user"}},
                {**shape, "target": {"parent_guid": parent, "sam": "newton-user2"}})
    raise AssertionError(verb)


def _plant_armed(dc: Dc, txid: str, fields: dict[str, Any]) -> None:
    """An armed record of one request whose undo_at is still ahead."""
    request = {k: v for k, v in dc.request(txid=txid, **fields).items()
               if k not in ("token", "secret")}
    record = {
        "v": 1, "txid": txid, "request": request, "state": "armed",
        "undo_at": NBF + 600, "restored": False, "conflicts": [],
        "created": None, "created_usnchanged": None,
    }
    (dc.tx / f"{txid}.json").write_text(json.dumps(record), encoding="utf-8")


def _writes(dc: Dc) -> list[tuple[str, str]]:
    return [one for one in dc.fake.calls if one[0] in ("modify", "add", "rename", "delete")]


GUARDED_VERBS = [
    "uac-clear", "disable", "enable", "enc-types", "move", "maq",
    "member-add", "member-remove", "user-create",
]


@pytest.mark.parametrize("verb", GUARDED_VERBS)
def test_an_apply_of_a_target_another_armed_record_of_the_verb_names_is_refused(
    dc: Dc, verb: str
) -> None:
    """A is armed (its undo_at is ahead); B, the same verb on the same target,
    is refused with conflict and armed true before anything is armed or
    written, and B's record is refused."""
    first, _other = _same_target_case(dc, verb)
    _plant_armed(dc, TXID_C, first)
    timers = [line for line in dc.log_lines() if "systemd-run" in line]

    answer = dc.run(dc.request(txid=TXID_B, **first))

    assert answer["code"] == "conflict", answer
    assert answer["armed"] is True
    assert _writes(dc) == []
    assert [line for line in dc.log_lines() if "systemd-run" in line] == timers
    assert dc.record(TXID_B)["state"] == "refused"
    assert dc.record(TXID_C)["state"] == "armed"


@pytest.mark.parametrize("verb", [one for one in GUARDED_VERBS if one != "maq"])
def test_an_apply_of_another_target_of_the_same_verb_goes_through(dc: Dc, verb: str) -> None:
    """The control: the same verb on another target (another account, another
    member of the same group, another new name) is not refused by A."""
    first, other = _same_target_case(dc, verb)
    assert other is not None
    _plant_armed(dc, TXID_C, first)

    answer = dc.run(dc.request(txid=TXID_B, **other))

    assert answer["code"] == "ok", answer
    assert dc.record(TXID_C)["state"] == "armed"
