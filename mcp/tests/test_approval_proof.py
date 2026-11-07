"""Unit tests of the approval-proof helpers.

The module under test is pure host-side bookkeeping: it derives the
approval key from a passphrase, runs the TOTP arithmetic of RFC 6238,
keeps the lockout counter on disk and writes the acknowledgement the
in-client approval dialog shows.  Every value here is synthetic: the
passphrase is a literal in this file and the TOTP seed is the RFC 4226
test seed.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import importlib
import json
import struct
from pathlib import Path

import pytest

import newton_mcp.approve as approve
import newton_mcp.approval_proof as proof


# The RFC 4226 Appendix D seed and its ten HOTP values.
RFC_SEED = b"12345678901234567890"
RFC4226_CODES = [
    "755224",
    "287082",
    "359152",
    "969429",
    "338314",
    "254676",
    "287922",
    "162583",
    "399871",
    "520489",
]

NOW = 1_700_000_000
DEVICE = "pulsar"
K_HEX = "ab" * 32


def _truncated(seed: bytes, counter: int, digits: int) -> str:
    """The RFC 4226 truncation, recomputed here and not via the module."""
    digest = hmac.new(seed, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % (10 ** digits)).zfill(digits)


def _store_totp(device: str = DEVICE, seed: bytes = RFC_SEED, k_hex: str = K_HEX) -> str:
    proof.store_totp(device, seed, k_hex)
    return k_hex


def _state_file(*parts: str):
    return approve.state_dir().joinpath(*parts)


def _derived_k(passphrase: bytes, device: str = DEVICE) -> str:
    """``approve.derive_k`` is slow (600000 iterations), so memoise it."""
    key = (passphrase, device)
    if key not in _DERIVED:
        _DERIVED[key] = approve.derive_k(passphrase, device)
    return _DERIVED[key]


_DERIVED: dict[tuple[bytes, str], str] = {}


def _write_fingerprint(device: str, k_hex: str):
    path = _state_file("approval-fp", device)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"v1 {approve.approval_fingerprint(k_hex)}\n", encoding="ascii")
    return path


# --- TOTP arithmetic -------------------------------------------------------


@pytest.mark.parametrize("counter,expected", list(enumerate(RFC4226_CODES)))
def test_totp_code_matches_the_rfc4226_vectors(counter, expected):
    assert proof.totp_code(RFC_SEED, counter) == expected


def test_totp_code_matches_the_rfc6238_sha1_vector():
    """RFC 6238 Appendix B: SHA1 at T=59 gives the 8-digit 94287082.

    That value is the tail of the same dynamic truncation the 6-digit
    code is taken from, so the 6-digit code at that counter is 287082.
    """
    assert _truncated(RFC_SEED, 1, 8) == "94287082"
    assert proof.totp_code(RFC_SEED, 1) == "287082"


def test_totp_code_is_six_digits():
    code = proof.totp_code(RFC_SEED, 0)
    assert len(code) == 6
    assert code.isdigit()


def test_totp_code_zero_pads_a_short_value():
    short = [c for c in range(1000) if _truncated(RFC_SEED, c, 6).startswith("0")]
    assert short, "no short code in the first 1000 counters"
    for counter in short:
        assert proof.totp_code(RFC_SEED, counter) == _truncated(RFC_SEED, counter, 6)
        assert len(proof.totp_code(RFC_SEED, counter)) == 6


def test_totp_counter_is_now_over_the_step():
    assert proof.totp_counter(0) == 0
    assert proof.totp_counter(29.9) == 0
    assert proof.totp_counter(30) == 1
    assert proof.totp_counter(59) == 1
    assert proof.totp_counter(NOW) == NOW // 30


def test_generate_seed_is_twenty_random_bytes():
    first = proof.generate_seed()
    second = proof.generate_seed()
    assert isinstance(first, bytes)
    assert len(first) == 20
    assert first != second


def test_seed_to_base32_is_uppercase_without_padding():
    encoded = proof.seed_to_base32(RFC_SEED)
    assert encoded == base64.b32encode(RFC_SEED).decode("ascii").rstrip("=")
    assert "=" not in encoded
    assert encoded == encoded.upper()
    padded = encoded + "=" * (-len(encoded) % 8)
    assert base64.b32decode(padded) == RFC_SEED


def test_otpauth_uri_has_the_expected_shape():
    encoded = proof.seed_to_base32(RFC_SEED)
    assert proof.otpauth_uri(RFC_SEED, DEVICE) == (
        "otpauth://totp/Newton:pulsar"
        f"?secret={encoded}&issuer=Newton&algorithm=SHA1&digits=6&period=30"
    )


def test_otpauth_uri_quotes_the_device_and_the_issuer():
    uri = proof.otpauth_uri(RFC_SEED, DEVICE, issuer="New ton")
    assert uri.startswith("otpauth://totp/New%20ton:pulsar?")
    assert "&issuer=New%20ton" in uri


# --- the stored TOTP record ------------------------------------------------


def test_store_and_load_totp_round_trip():
    _store_totp()
    record = proof.load_totp(DEVICE)
    assert record is not None
    assert record["seed_b32"] == proof.seed_to_base32(RFC_SEED)
    assert record["k"] == K_HEX
    assert record["last_counter"] == 0


def test_the_stored_totp_file_and_its_directory_are_private():
    _store_totp()
    path = _state_file("keys", f"{DEVICE}.json")
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700
    assert approve.state_dir().stat().st_mode & 0o777 == 0o700


@pytest.mark.parametrize(
    "payload",
    [
        "{not json",
        json.dumps([1, 2, 3]),
        json.dumps({"seed_b32": "not base32!", "k": K_HEX, "last_counter": 0}),
        json.dumps({"seed_b32": proof.seed_to_base32(RFC_SEED), "k": "zz" * 32, "last_counter": 0}),
        json.dumps({"seed_b32": 17, "k": K_HEX, "last_counter": 0}),
        json.dumps({"seed_b32": proof.seed_to_base32(RFC_SEED), "k": K_HEX, "last_counter": "x"}),
        json.dumps({"seed_b32": proof.seed_to_base32(RFC_SEED), "k": K_HEX}),
    ],
)
def test_a_malformed_totp_record_loads_as_none(payload):
    path = _state_file("keys", f"{DEVICE}.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(payload, encoding="utf-8")
    assert proof.load_totp(DEVICE) is None


def test_a_missing_totp_record_loads_as_none():
    assert proof.load_totp(DEVICE) is None


def test_store_totp_refuses_a_key_that_is_not_hex():
    with pytest.raises(ValueError):
        proof.store_totp(DEVICE, RFC_SEED, "not-hex")
    with pytest.raises(ValueError):
        proof.store_totp(DEVICE, RFC_SEED, "AB" * 32)


def test_delete_totp_removes_the_record_and_tolerates_a_missing_one():
    _store_totp()
    proof.delete_totp(DEVICE)
    assert proof.load_totp(DEVICE) is None
    proof.delete_totp(DEVICE)


# --- verifying a TOTP code -------------------------------------------------


@pytest.mark.parametrize("offset", [-1, 0, 1])
def test_verify_totp_accepts_the_neighbouring_counters(offset):
    k_hex = _store_totp()
    counter = NOW // 30
    code = proof.totp_code(RFC_SEED, counter + offset)
    assert proof.verify_totp(DEVICE, code, now=NOW) == k_hex


def test_verify_totp_rejects_a_counter_two_steps_away():
    _store_totp()
    counter = NOW // 30
    assert proof.verify_totp(DEVICE, proof.totp_code(RFC_SEED, counter + 2), now=NOW) is None


def test_verify_totp_rejects_a_replayed_code():
    _store_totp()
    counter = NOW // 30
    code = proof.totp_code(RFC_SEED, counter)
    assert proof.verify_totp(DEVICE, code, now=NOW) is not None
    assert proof.verify_totp(DEVICE, code, now=NOW) is None


def test_verify_totp_rejects_an_older_counter_after_a_newer_one():
    _store_totp()
    counter = NOW // 30
    assert proof.verify_totp(DEVICE, proof.totp_code(RFC_SEED, counter), now=NOW) is not None
    assert proof.verify_totp(DEVICE, proof.totp_code(RFC_SEED, counter - 1), now=NOW) is None


def test_verify_totp_remembers_the_counter_it_accepted():
    _store_totp()
    counter = NOW // 30
    proof.verify_totp(DEVICE, proof.totp_code(RFC_SEED, counter), now=NOW)
    record = proof.load_totp(DEVICE)
    assert record is not None
    assert record["last_counter"] == counter


@pytest.mark.parametrize("code", ["abcdef", "12345", "1234567", "12 34 56", "", "   "])
def test_verify_totp_refuses_a_code_that_is_not_six_digits(code):
    _store_totp()
    assert proof.verify_totp(DEVICE, code, now=NOW) is None


def test_verify_totp_without_a_record_is_none():
    assert proof.verify_totp(DEVICE, "123456", now=NOW) is None


def test_verify_totp_returns_none_after_the_record_is_deleted():
    _store_totp()
    counter = NOW // 30
    proof.delete_totp(DEVICE)
    assert proof.verify_totp(DEVICE, proof.totp_code(RFC_SEED, counter), now=NOW) is None


# --- the passphrase check ---------------------------------------------------


def test_verify_passphrase_accepts_the_right_passphrase():
    k_hex = _derived_k(b"synthetic pass")
    _write_fingerprint(DEVICE, k_hex)
    status, key = proof.verify_passphrase(DEVICE, "synthetic pass")
    assert status == "ok"
    assert key == k_hex


def test_verify_passphrase_reports_a_wrong_passphrase():
    _write_fingerprint(DEVICE, _derived_k(b"synthetic pass"))
    status, key = proof.verify_passphrase(DEVICE, "wrong pass")
    assert status == "wrong"
    assert key is None


def test_verify_passphrase_reports_a_missing_fingerprint():
    status, key = proof.verify_passphrase(DEVICE, "synthetic pass")
    assert status == "no-fingerprint"
    assert key is None


def test_verify_passphrase_refuses_an_empty_passphrase():
    status, key = proof.verify_passphrase(DEVICE, "")
    assert status == "bad-input"
    assert key is None


# --- the lockout ------------------------------------------------------------


def test_two_failures_do_not_lock():
    assert proof.record_failure(DEVICE, now=1000.0) == 0
    assert proof.record_failure(DEVICE, now=1001.0) == 0
    assert proof.lock_remaining(DEVICE, now=1001.0) == 0


def test_the_third_failure_locks_for_five_minutes():
    proof.record_failure(DEVICE, now=1000.0)
    proof.record_failure(DEVICE, now=1001.0)
    assert proof.record_failure(DEVICE, now=1002.0) == 300
    assert proof.lock_remaining(DEVICE, now=1002.0) == 300
    assert proof.lock_remaining(DEVICE, now=1032.0) == 270


def test_the_lock_doubles_after_it_expires():
    for _ in range(3):
        proof.record_failure(DEVICE, now=1000.0)
    assert proof.lock_remaining(DEVICE, now=1300.0) == 0
    remaining = 0
    for _ in range(3):
        remaining = proof.record_failure(DEVICE, now=1301.0)
    assert remaining == 600


def test_the_lock_is_capped_at_a_day():
    path = _state_file("lockout", f"{DEVICE}.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"misses": 2, "locks": 9, "until": 0.0}), encoding="utf-8")
    assert proof.record_failure(DEVICE, now=1000.0) == proof.LOCK_MAX_S == 86400


def test_the_lockout_is_kept_on_disk():
    proof.record_failure(DEVICE, now=1000.0)
    path = _state_file("lockout", f"{DEVICE}.json")
    record = json.loads(path.read_text(encoding="utf-8"))
    assert record["misses"] == 1
    assert record["locks"] == 0
    assert record["until"] == 0.0
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700


def test_the_lockout_survives_a_fresh_import():
    for _ in range(3):
        proof.record_failure(DEVICE, now=1000.0)
    fresh = importlib.reload(proof)
    assert fresh.lock_remaining(DEVICE, now=1000.0) == 300


def test_a_corrupt_lockout_record_fails_closed():
    path = _state_file("lockout", f"{DEVICE}.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{not json", encoding="utf-8")
    assert proof.lock_remaining(DEVICE, now=1000.0) == 300
    rewritten = json.loads(path.read_text(encoding="utf-8"))
    assert rewritten["until"] == 1300.0


def test_record_success_clears_the_lockout():
    proof.record_failure(DEVICE, now=1000.0)
    proof.record_success(DEVICE)
    assert not _state_file("lockout", f"{DEVICE}.json").exists()
    assert proof.lock_remaining(DEVICE, now=1000.0) == 0
    proof.record_success(DEVICE)


# --- the level --------------------------------------------------------------


def test_the_level_defaults_to_passphrase():
    assert proof.get_level(DEVICE) == proof.LEVEL_PASSPHRASE


def test_the_default_level_is_named_in_one_place():
    """The default lives in the proof module, so no module has to repeat it."""
    assert proof.DEFAULT_LEVEL == proof.LEVEL_PASSPHRASE


def test_no_other_module_defines_a_default_level():
    """No second default may appear beside the one.

    A module that names the default itself would answer a different
    question from the one the proof module answers, and the two would
    drift apart.
    """
    import newton_mcp

    package = Path(newton_mcp.__file__).parent
    offenders = [
        path.name
        for path in sorted(package.glob("*.py"))
        if path.name != "approval_proof.py"
        and "DEFAULT_LEVEL =" in path.read_text(encoding="utf-8")
    ]

    assert offenders == []


def test_a_missing_level_file_follows_the_one_default(monkeypatch):
    monkeypatch.setattr(proof, "DEFAULT_LEVEL", proof.LEVEL_TOTP)

    assert proof.get_level(DEVICE) == proof.LEVEL_TOTP


def test_an_unknown_level_word_follows_the_one_default(monkeypatch):
    path = _state_file("levels", DEVICE)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("something else\n", encoding="utf-8")
    monkeypatch.setattr(proof, "DEFAULT_LEVEL", proof.LEVEL_TOTP)

    assert proof.get_level(DEVICE) == proof.LEVEL_TOTP


def test_an_unreadable_level_file_follows_the_one_default(monkeypatch):
    path = _state_file("levels", DEVICE)
    path.parent.mkdir(parents=True, exist_ok=True)
    # a directory in place of the file: reading it raises OSError
    path.mkdir()
    monkeypatch.setattr(proof, "DEFAULT_LEVEL", proof.LEVEL_TOTP)

    assert proof.get_level(DEVICE) == proof.LEVEL_TOTP


def test_set_level_writes_the_word():
    proof.set_level(DEVICE, proof.LEVEL_TOTP)
    assert proof.get_level(DEVICE) == proof.LEVEL_TOTP
    path = _state_file("levels", DEVICE)
    assert path.read_text(encoding="utf-8") == "totp\n"
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700


def test_set_level_refuses_another_level():
    with pytest.raises(ValueError):
        proof.set_level(DEVICE, "totp-ish")
    with pytest.raises(ValueError):
        proof.set_level(DEVICE, "")


def test_get_level_ignores_a_broken_file():
    path = _state_file("levels", DEVICE)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("something else\n", encoding="utf-8")
    assert proof.get_level(DEVICE) == proof.LEVEL_PASSPHRASE


# --- the acknowledgement ----------------------------------------------------


def test_the_acknowledgement_round_trips():
    assert proof.has_ack(DEVICE) is False
    proof.write_ack(DEVICE, now=NOW)
    assert proof.has_ack(DEVICE) is True
    assert proof.ack_path(DEVICE) == _state_file("acks", f"{DEVICE}.json")
    record = json.loads(proof.ack_path(DEVICE).read_text(encoding="utf-8"))
    assert record["acknowledged_at"] == "2023-11-14T22:13:20Z"
    assert proof.ack_path(DEVICE).stat().st_mode & 0o777 == 0o600
    assert proof.ack_path(DEVICE).parent.stat().st_mode & 0o777 == 0o700


# --- the dwell check --------------------------------------------------------


def test_dwell_ok():
    assert proof.dwell_ok(proof.MIN_DWELL_S) is True
    assert proof.dwell_ok(2.0) is True
    assert proof.dwell_ok(1.4) is False
    assert proof.dwell_ok(0.0) is False


# --- the dialog lock --------------------------------------------------------


def test_the_dialog_lock_excludes_a_second_holder_in_the_same_process():
    """flock locks the open file description, not the process.

    Two calls of one server (or one process and a second one) must not
    both open a dialog for the same device, so the second open of the
    lock file has to fail even inside the process that holds it.
    """
    with proof.device_dialog_lock(DEVICE):
        with pytest.raises(proof.DialogBusy):
            with proof.device_dialog_lock(DEVICE):
                pass


def test_the_dialog_lock_is_free_again_after_the_block_ends():
    with proof.device_dialog_lock(DEVICE):
        pass
    with proof.device_dialog_lock(DEVICE):
        pass


def test_the_dialog_lock_is_free_again_after_an_exception():
    with pytest.raises(RuntimeError):
        with proof.device_dialog_lock(DEVICE):
            raise RuntimeError("boom")
    with proof.device_dialog_lock(DEVICE):
        pass


def test_the_dialog_lock_does_not_tie_two_devices_together():
    with proof.device_dialog_lock(DEVICE):
        with proof.device_dialog_lock("pulsar-two"):
            pass


def test_the_dialog_lock_file_and_its_directory_are_private():
    with proof.device_dialog_lock(DEVICE):
        path = _state_file("locks", f"{DEVICE}.lock")
        assert path.stat().st_mode & 0o777 == 0o600
        assert path.parent.stat().st_mode & 0o777 == 0o700


@pytest.mark.parametrize("device", ["../x", "", "A", "pulsar/../x", "a" * 33])
def test_the_dialog_lock_refuses_a_bad_device_name(device):
    with pytest.raises(ValueError):
        with proof.device_dialog_lock(device):
            pass


# --- the device name is never a path ---------------------------------------


@pytest.mark.parametrize("device", ["../x", "", "A", "pulsar/../x", "a" * 33])
def test_every_function_refuses_a_bad_device_name(device):
    with pytest.raises(ValueError):
        proof.get_level(device)
    with pytest.raises(ValueError):
        proof.set_level(device, proof.LEVEL_TOTP)
    with pytest.raises(ValueError):
        proof.store_totp(device, RFC_SEED, K_HEX)
    with pytest.raises(ValueError):
        proof.load_totp(device)
    with pytest.raises(ValueError):
        proof.delete_totp(device)
    with pytest.raises(ValueError):
        proof.verify_totp(device, "123456", now=0.0)
    with pytest.raises(ValueError):
        proof.verify_passphrase(device, "synthetic pass")
    with pytest.raises(ValueError):
        proof.lock_remaining(device, now=0.0)
    with pytest.raises(ValueError):
        proof.record_failure(device, now=0.0)
    with pytest.raises(ValueError):
        proof.record_success(device)
    with pytest.raises(ValueError):
        proof.ack_path(device)
    with pytest.raises(ValueError):
        proof.has_ack(device)
    with pytest.raises(ValueError):
        proof.write_ack(device, now=0.0)
    with pytest.raises(ValueError):
        proof.otpauth_uri(RFC_SEED, device)


def test_verify_totp_accepts_one_code_once_across_threads(monkeypatch):
    """Two callers racing on the same code: exactly one gets the key.

    The load is slowed so that, without the flock around read-check-write,
    every thread would read the old counter and all would accept.
    """
    import threading
    import time as _time

    seed = b"12345678901234567890"
    k = "a" * 64
    proof.store_totp("pulsar", seed, k)
    now = 1_700_000_000.0
    code = proof.totp_code(seed, proof.totp_counter(now))
    real_load = proof.load_totp

    def slow_load(device):
        record = real_load(device)
        _time.sleep(0.05)
        return record

    monkeypatch.setattr(proof, "load_totp", slow_load)
    results = []

    def attempt():
        results.append(proof.verify_totp("pulsar", code, now=now))

    threads = [threading.Thread(target=attempt) for _ in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert results.count(k) == 1
    assert results.count(None) == 5


def test_write_approval_refuses_a_plan_id_that_is_not_32_hex():
    for bad in ("", "../x", "A" * 32, "a" * 31, "a" * 33):
        with pytest.raises(ValueError):
            approve.write_approval(bad, {})
