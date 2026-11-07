"""Unit tests of the newton-enrol command.

newton-enrol is the owner's own terminal tool: it enrols a TOTP
authenticator, chooses the approval level of a device and rotates the
approval passphrase.  Every secret here is synthetic -- the passphrase is
a literal in this file and the seed is a fixed 20-byte value -- so the
test can predict the code an authenticator would show.
"""

from __future__ import annotations

import subprocess
import sys

import pytest

import newton_mcp.approval_proof as proof
import newton_mcp.approve as approve
import newton_mcp.enrol as enrol
import newton_mcp.grants as grants


DEVICE = "pulsar"
PASSPHRASE = "synthetic-passphrase-for-tests"
SEED = b"0123456789abcdef0123"
SEED_B32 = proof.seed_to_base32(SEED)

_DERIVED: dict[tuple[str, str], str] = {}


def _k(device: str = DEVICE, passphrase: str = PASSPHRASE) -> str:
    """The approval key of *passphrase*; derive_k is slow, so memoise it."""
    key = (passphrase, device)
    if key not in _DERIVED:
        _DERIVED[key] = approve.derive_k(passphrase.encode("utf-8"), device)
    return _DERIVED[key]


def _write_fingerprint(device: str = DEVICE) -> str:
    """Record the fingerprint of the test passphrase, as setup does."""
    k_hex = _k(device)
    path = approve.state_dir() / "approval-fp" / device
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"v1 {approve.approval_fingerprint(k_hex)}\n", encoding="ascii")
    return k_hex


def _current_code(seed: bytes = SEED) -> str:
    """The code an authenticator shows for *seed* right now."""
    return proof.totp_code(seed, proof.totp_counter())


class FakeStdin:
    """A stdin stand-in: a terminal that hands out queued answers.

    An answer is either a string or a callable, so a test can hand out a
    TOTP code that is computed when the owner is asked for it.
    """

    def __init__(self, answers=(), tty: bool = True):
        self.answers = list(answers)
        self.tty = tty

    def isatty(self) -> bool:
        return self.tty

    def readline(self) -> str:
        if not self.answers:
            return ""
        answer = self.answers.pop(0)
        return answer() if callable(answer) else answer


class RecordedCalls(list):
    """The argv of every recorded call.

    ``kws`` holds the keyword arguments of each call, in the same order,
    so a test can see what the child process inherits.
    """

    def __init__(self):
        super().__init__()
        self.kws: list[dict] = []


@pytest.fixture
def calls(monkeypatch):
    """Replace subprocess.run with a recorder; no command is run."""
    recorded = RecordedCalls()

    def fake_run(argv, *args, **kwargs):
        recorded.append(list(argv))
        recorded.kws.append(kwargs)
        return subprocess.CompletedProcess(list(argv), 0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    return recorded


@pytest.fixture
def no_qrencode(monkeypatch):
    """Pretend qrencode is not installed."""
    monkeypatch.setattr("newton_mcp.enrol.shutil.which", lambda name: None)


def _type_passphrase(monkeypatch, passphrase: str = PASSPHRASE):
    monkeypatch.setattr(approve, "_getpass", lambda prompt: passphrase)


# ---- usage and the terminal ------------------------------------------------


def test_enrol_refuses_a_bad_command(monkeypatch):
    monkeypatch.setattr(sys, "stdin", FakeStdin())
    assert enrol.main(["frobnicate", DEVICE]) == 2


def test_enrol_refuses_too_few_arguments(monkeypatch):
    monkeypatch.setattr(sys, "stdin", FakeStdin())
    assert enrol.main([]) == 2
    assert enrol.main(["totp"]) == 2
    assert enrol.main(["level", DEVICE]) == 2
    assert enrol.main(["totp", DEVICE, "extra"]) == 2


def test_enrol_refuses_a_bad_device_name(monkeypatch):
    monkeypatch.setattr(sys, "stdin", FakeStdin())
    for bad in ("Pulsar", "1pulsar", "pulsar/x", "x" * 33, "pul sar"):
        assert enrol.main(["totp", bad]) == 2, bad


def test_enrol_refuses_an_unknown_level(monkeypatch):
    monkeypatch.setattr(sys, "stdin", FakeStdin())
    assert enrol.main(["level", DEVICE, "sms"]) == 2


def test_enrol_refuses_without_a_terminal(monkeypatch):
    monkeypatch.setattr(sys, "stdin", FakeStdin(tty=False))
    assert enrol.main(["totp", DEVICE]) == 1
    assert enrol.main(["rotate", DEVICE]) == 1
    assert enrol.main(["level", DEVICE, "passphrase"]) == 1


# ---- newton-enrol totp -----------------------------------------------------


def test_totp_enrols_the_seed_and_switches_the_level(monkeypatch, capsys, no_qrencode):
    k_hex = _write_fingerprint()
    monkeypatch.setattr(proof, "generate_seed", lambda: SEED)
    _type_passphrase(monkeypatch)
    monkeypatch.setattr(sys, "stdin", FakeStdin([lambda: _current_code()]))

    assert enrol.main(["totp", DEVICE]) == 0

    out = capsys.readouterr()
    assert "otpauth://totp/" in out.out
    assert SEED_B32 in out.out
    record = proof.load_totp(DEVICE)
    assert record is not None
    assert record["seed_b32"] == SEED_B32
    assert record["k"] == k_hex
    assert proof.get_level(DEVICE) == proof.LEVEL_TOTP


def test_totp_never_prints_the_passphrase_or_the_key(monkeypatch, capsys, no_qrencode):
    k_hex = _write_fingerprint()
    monkeypatch.setattr(proof, "generate_seed", lambda: SEED)
    _type_passphrase(monkeypatch)
    monkeypatch.setattr(sys, "stdin", FakeStdin([lambda: _current_code()]))

    assert enrol.main(["totp", DEVICE]) == 0

    out = capsys.readouterr()
    assert PASSPHRASE not in out.out
    assert PASSPHRASE not in out.err
    assert k_hex not in out.out
    assert k_hex not in out.err


def test_totp_refuses_a_wrong_passphrase(monkeypatch, capsys, no_qrencode):
    _write_fingerprint()
    monkeypatch.setattr(proof, "generate_seed", lambda: SEED)
    _type_passphrase(monkeypatch, "not-the-passphrase")
    monkeypatch.setattr(sys, "stdin", FakeStdin([lambda: _current_code()]))

    assert enrol.main(["totp", DEVICE]) == 1

    out = capsys.readouterr()
    assert "wrong approval passphrase" in out.err
    assert PASSPHRASE not in out.out
    assert PASSPHRASE not in out.err
    assert proof.load_totp(DEVICE) is None
    assert proof.get_level(DEVICE) == proof.LEVEL_PASSPHRASE


def test_totp_refuses_without_a_fingerprint(monkeypatch, capsys, no_qrencode):
    monkeypatch.setattr(proof, "generate_seed", lambda: SEED)
    _type_passphrase(monkeypatch)
    monkeypatch.setattr(sys, "stdin", FakeStdin([lambda: _current_code()]))

    assert enrol.main(["totp", DEVICE]) == 1

    out = capsys.readouterr()
    assert f"run newton-router-setup {DEVICE} approval-key first" in out.err
    assert proof.load_totp(DEVICE) is None
    assert proof.get_level(DEVICE) == proof.LEVEL_PASSPHRASE


def test_totp_stores_nothing_when_the_code_is_wrong(monkeypatch, capsys, no_qrencode):
    _write_fingerprint()
    monkeypatch.setattr(proof, "generate_seed", lambda: SEED)
    _type_passphrase(monkeypatch)
    monkeypatch.setattr(sys, "stdin", FakeStdin(["000000"]))

    assert enrol.main(["totp", DEVICE]) == 1

    out = capsys.readouterr()
    assert "does not match" in out.err
    assert proof.load_totp(DEVICE) is None
    assert proof.get_level(DEVICE) == proof.LEVEL_PASSPHRASE


def test_totp_refuses_a_code_that_is_not_six_digits(monkeypatch, no_qrencode):
    _write_fingerprint()
    monkeypatch.setattr(proof, "generate_seed", lambda: SEED)
    _type_passphrase(monkeypatch)
    monkeypatch.setattr(sys, "stdin", FakeStdin(["12345"]))

    assert enrol.main(["totp", DEVICE]) == 1
    assert proof.load_totp(DEVICE) is None


def test_totp_accepts_a_code_from_the_neighbouring_window(monkeypatch, no_qrencode):
    _write_fingerprint()
    monkeypatch.setattr(proof, "generate_seed", lambda: SEED)
    _type_passphrase(monkeypatch)
    monkeypatch.setattr(
        sys,
        "stdin",
        FakeStdin([lambda: proof.totp_code(SEED, proof.totp_counter() - 1)]),
    )

    assert enrol.main(["totp", DEVICE]) == 0
    assert proof.load_totp(DEVICE) is not None


def test_totp_shows_a_qr_code_when_qrencode_is_installed(monkeypatch, capsys, calls):
    _write_fingerprint()
    monkeypatch.setattr(proof, "generate_seed", lambda: SEED)
    monkeypatch.setattr("newton_mcp.enrol.shutil.which", lambda name: "/usr/bin/qrencode")
    _type_passphrase(monkeypatch)
    monkeypatch.setattr(sys, "stdin", FakeStdin([lambda: _current_code()]))

    assert enrol.main(["totp", DEVICE]) == 0

    out = capsys.readouterr()
    assert len(calls) == 1
    assert calls[0][:3] == ["qrencode", "-t", "ANSIUTF8"]
    assert calls[0][3].startswith("otpauth://totp/")


def test_totp_says_so_when_qrencode_is_missing(monkeypatch, capsys, no_qrencode, calls):
    _write_fingerprint()
    monkeypatch.setattr(proof, "generate_seed", lambda: SEED)
    _type_passphrase(monkeypatch)
    monkeypatch.setattr(sys, "stdin", FakeStdin([lambda: _current_code()]))

    assert enrol.main(["totp", DEVICE]) == 0

    out = capsys.readouterr()
    assert "qrencode not installed: type the seed into your authenticator app" in out.out
    assert calls == []


def test_totp_says_the_level_and_the_fallback(monkeypatch, capsys, no_qrencode):
    _write_fingerprint()
    monkeypatch.setattr(proof, "generate_seed", lambda: SEED)
    _type_passphrase(monkeypatch)
    monkeypatch.setattr(sys, "stdin", FakeStdin([lambda: _current_code()]))

    assert enrol.main(["totp", DEVICE]) == 0

    out = capsys.readouterr()
    assert "totp" in out.out
    assert "newton-approve" in out.out


# ---- newton-enrol level ----------------------------------------------------


def test_level_passphrase_sets_the_level_and_keeps_the_totp_record(monkeypatch):
    _write_fingerprint()
    proof.store_totp(DEVICE, SEED, _k())
    monkeypatch.setattr(sys, "stdin", FakeStdin())

    assert enrol.main(["level", DEVICE, "passphrase"]) == 0

    assert proof.get_level(DEVICE) == proof.LEVEL_PASSPHRASE
    assert proof.load_totp(DEVICE) is not None


def test_level_totp_needs_a_record(monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", FakeStdin())

    assert enrol.main(["level", DEVICE, "totp"]) == 1

    out = capsys.readouterr()
    assert f"newton-enrol totp {DEVICE}" in out.err
    assert proof.get_level(DEVICE) == proof.LEVEL_PASSPHRASE


def test_level_totp_sets_the_level_when_a_record_exists(monkeypatch):
    _write_fingerprint()
    proof.store_totp(DEVICE, SEED, _k())
    monkeypatch.setattr(sys, "stdin", FakeStdin())

    assert enrol.main(["level", DEVICE, "totp"]) == 0

    assert proof.get_level(DEVICE) == proof.LEVEL_TOTP


# ---- newton-enrol rotate ---------------------------------------------------


def _seed_rotatable_state(device: str = DEVICE) -> None:
    """Put the three files a rotation throws away in place."""
    proof.store_totp(device, SEED, _k())
    proof.record_failure(device)
    proof.write_ack(device)


def _rotated_files(device: str = DEVICE):
    state = approve.state_dir()
    return (
        state / "keys" / f"{device}.json",
        state / "lockout" / f"{device}.json",
        state / "acks" / f"{device}.json",
    )


def test_rotate_deletes_the_three_files_and_runs_the_setup(monkeypatch, tmp_path, calls):
    home = tmp_path / "newton-home"
    (home / "scripts").mkdir(parents=True)
    (home / "scripts" / "newton-router-setup").write_text("#!/bin/sh\n")
    monkeypatch.setenv("NEWTON_HOME", str(home))
    _seed_rotatable_state()
    monkeypatch.setattr(sys, "stdin", FakeStdin([f"rotate {DEVICE}"]))

    assert enrol.main(["rotate", DEVICE]) == 0

    for path in _rotated_files():
        assert not path.exists(), path
    assert proof.get_level(DEVICE) == proof.LEVEL_PASSPHRASE
    assert calls == [[str(home / "scripts" / "newton-router-setup"), DEVICE, "approval-key"]]


def test_rotate_runs_the_setup_without_the_authenticator_offer(
    monkeypatch, tmp_path, calls
):
    """A rotation runs the setup tool, and that run must not offer the
    authenticator app: the offer would be undone a second later, when
    the rotation throws the TOTP record away.  The setup tool is run
    with NEWTON_SKIP_TOTP_OFFER=1 in its environment."""
    home = tmp_path / "newton-home"
    (home / "scripts").mkdir(parents=True)
    (home / "scripts" / "newton-router-setup").write_text("#!/bin/sh\n")
    monkeypatch.setenv("NEWTON_HOME", str(home))
    _seed_rotatable_state()
    monkeypatch.setattr(sys, "stdin", FakeStdin([f"rotate {DEVICE}"]))

    assert enrol.main(["rotate", DEVICE]) == 0

    assert len(calls) == 1
    env = calls.kws[0]["env"]
    assert env["NEWTON_SKIP_TOTP_OFFER"] == "1"
    # the rest of the environment is inherited, not replaced
    assert env["NEWTON_HOME"] == str(home)


def test_rotate_uses_the_default_home_without_the_environment(monkeypatch, calls):
    monkeypatch.delenv("NEWTON_HOME", raising=False)
    # The default home is /opt/newton; pretend the setup tool is there so
    # the test does not depend on what this host has installed.
    monkeypatch.setattr("newton_mcp.enrol.os.path.isfile", lambda path: True)
    _seed_rotatable_state()
    monkeypatch.setattr(sys, "stdin", FakeStdin([f"rotate {DEVICE}"]))

    assert enrol.main(["rotate", DEVICE]) == 0
    assert calls == [
        ["/opt/newton/scripts/newton-router-setup", DEVICE, "approval-key"]
    ]


def test_rotate_needs_the_confirmation(monkeypatch, tmp_path, calls):
    home = tmp_path / "newton-home"
    (home / "scripts").mkdir(parents=True)
    (home / "scripts" / "newton-router-setup").write_text("#!/bin/sh\n")
    monkeypatch.setenv("NEWTON_HOME", str(home))
    _seed_rotatable_state()
    monkeypatch.setattr(sys, "stdin", FakeStdin(["rotate pulsarx"]))

    assert enrol.main(["rotate", DEVICE]) == 1

    for path in _rotated_files():
        assert path.exists(), path
    assert calls == []


def test_rotate_prints_the_command_when_the_setup_tool_is_missing(monkeypatch, tmp_path, capsys):
    home = tmp_path / "newton-home"
    home.mkdir()
    monkeypatch.setenv("NEWTON_HOME", str(home))
    _seed_rotatable_state()
    monkeypatch.setattr(sys, "stdin", FakeStdin([f"rotate {DEVICE}"]))

    assert enrol.main(["rotate", DEVICE]) == 1

    out = capsys.readouterr()
    expected = f"{home}/scripts/newton-router-setup {DEVICE} approval-key"
    assert expected in out.out + out.err


def test_rotate_propagates_the_setup_exit_code(monkeypatch, tmp_path):
    home = tmp_path / "newton-home"
    (home / "scripts").mkdir(parents=True)
    (home / "scripts" / "newton-router-setup").write_text("#!/bin/sh\n")
    monkeypatch.setenv("NEWTON_HOME", str(home))
    _seed_rotatable_state()
    monkeypatch.setattr(sys, "stdin", FakeStdin([f"rotate {DEVICE}"]))

    def fake_run(argv, *args, **kwargs):
        return subprocess.CompletedProcess(list(argv), 7)

    monkeypatch.setattr(subprocess, "run", fake_run)

    assert enrol.main(["rotate", DEVICE]) == 7
    # a failed key change on the router must not tear down the old proofs
    for path in _rotated_files():
        assert path.exists(), path


def test_rotate_keeps_the_old_proofs_when_the_setup_tool_is_missing(monkeypatch, tmp_path):
    home = tmp_path / "newton-home"
    home.mkdir()
    monkeypatch.setenv("NEWTON_HOME", str(home))
    _seed_rotatable_state()
    monkeypatch.setattr(sys, "stdin", FakeStdin([f"rotate {DEVICE}"]))

    assert enrol.main(["rotate", DEVICE]) == 1

    for path in _rotated_files():
        assert path.exists(), path


def test_totp_enrolment_burns_the_code_it_was_proved_with(monkeypatch, no_qrencode):
    _write_fingerprint()
    monkeypatch.setattr(proof, "generate_seed", lambda: SEED)
    _type_passphrase(monkeypatch)
    typed = _current_code()
    monkeypatch.setattr(sys, "stdin", FakeStdin([lambda: typed]))

    assert enrol.main(["totp", DEVICE]) == 0

    assert proof.verify_totp(DEVICE, typed) is None


# ---- newton-enrol grant-off -------------------------------------------------


def test_grant_off_ends_a_live_grant_without_a_terminal(monkeypatch, capsys):
    grants.open_grant(
        DEVICE,
        ["dns"],
        1,
        "ab" * 32,
        "0123456789abcdef0123456789abcdef",
    )
    monkeypatch.setattr(sys, "stdin", FakeStdin(tty=False))

    assert enrol.main(["grant-off", DEVICE]) == 0

    out = capsys.readouterr()
    assert "ended" in out.out.lower()
    assert grants.load_live_grant(DEVICE) is None


def test_grant_off_without_a_grant_says_there_was_none(monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", FakeStdin(tty=False))

    assert enrol.main(["grant-off", DEVICE]) == 0

    out = capsys.readouterr()
    assert "no easy grant" in out.out.lower()
