"""Approval proofs for the in-client approval dialog.

The console approval (``newton-approve``) proves the owner is present
by typing a passphrase in their own terminal.  The in-client dialog
(MCP elicitation) needs the same proof without a terminal, so the
pieces both surfaces share live here:

* the approval level of a device (a passphrase or a TOTP code),
* the TOTP arithmetic of RFC 6238 (over RFC 4226) and the seed file,
* the passphrase check against the fingerprint ``newton-router-setup``
  recorded,
* the lockout counter, kept on disk so a relaunched server cannot hand
  out a fresh set of attempts,
* the acknowledgement record and the dwell check the dialog uses,
* the per-device dialog lock, so two concurrent calls cannot open two
  approval dialogs for the same device.

Nothing here talks to a device and nothing here reads a secret out of
the environment.  The passphrase only ever lives in the caller's
argument: it is never stored, logged or returned.  Every file this
module writes holds a secret (a seed, a key, a counter), so the state
directory and the directories under it are 0700 and the files are 0600,
written atomically.
"""

from __future__ import annotations

import base64
import contextlib
import errno
import fcntl
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import struct
import tempfile
import time
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

from . import approve
from . import receipts as _receipts


# The two ways an owner can prove who they are.
LEVEL_PASSPHRASE = "passphrase"
LEVEL_TOTP = "totp"
LEVELS = (LEVEL_PASSPHRASE, LEVEL_TOTP)

# The level a device falls back to when it cannot say which proof it
# wants.  It is named here and nowhere else, so no other module has to
# repeat the default.
DEFAULT_LEVEL = LEVEL_PASSPHRASE

# The dwell the dialog enforces before it accepts the owner's answer:
# a click that arrives too fast is a mis-click, not a decision.
MIN_DWELL_S = 1.5

# The lockout: three failures lock the device out for five minutes, and
# every further lock doubles the wait up to a day.
LOCK_FREE_MISSES = 3
LOCK_BASE_S = 300
LOCK_MAX_S = 86400

# RFC 6238 with HMAC-SHA1, six digits, thirty-second steps.
TOTP_STEP_S = 30
TOTP_DIGITS = 6

# A TOTP code is exactly six digits; nothing else is a code.
CODE_RE = re.compile(r"^[0-9]{6}$")

# A stored seed is base32 without padding, so it is upper-case A-Z 2-7.
BASE32_RE = re.compile(r"^[A-Z2-7]+$")

# The outcomes of verify_passphrase.
PASS_OK = "ok"
PASS_WRONG = "wrong"
PASS_NO_FINGERPRINT = "no-fingerprint"
PASS_BAD_INPUT = "bad-input"


def _check_device(device: str) -> str:
    """Refuse a device name that is not a plain name.

    The name becomes a path under the state directory, so anything that
    could escape it (a slash, a dot, an upper-case letter) is refused
    rather than sanitised: a device Newton does not have a name for has
    no proof either.
    """
    if not isinstance(device, str) or not approve.DEVICE_NAME_RE.fullmatch(device):
        raise ValueError("device must be 1-32 characters of [a-z][a-z0-9-]")
    return device


def _state_subdir(name: str) -> Path:
    """Return ``state_dir()/name``, created 0700 and safe to write under.

    The state directory and the directory under it hold secrets, so
    both are 0700 (the mode ``mkdir`` applies is masked by the umask,
    hence the explicit chmod).  The write is refused outright when the
    state directory is a symlink, belongs to another user or is
    group- or world-writable, which is the same rule every other state
    write in Newton follows.
    """
    root = approve.state_dir()
    refusal = _receipts.check_state_dir(root)
    if refusal is not None:
        raise OSError(refusal)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    directory = root / name
    refusal = _receipts.check_state_dir_parent(directory)
    if refusal is not None:
        raise OSError(refusal)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    return directory


def _atomic_write_text(path: Path, text: str) -> None:
    """Write *text* to *path* atomically, with mode 0600.

    The same shape as ``approve._atomic_write`` (which writes JSON
    dicts and is reused for those): a temporary file in the same
    directory, fsynced, then renamed into place, so a crash mid-write
    leaves the old file rather than a half-written one.
    """
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


# --- the approval level ----------------------------------------------------


def _level_path(device: str) -> Path:
    return approve.state_dir() / "levels" / device


def get_level(device: str) -> str:
    """The approval level of *device*: ``passphrase`` or ``totp``.

    Anything unreadable or unexpected reads as ``DEFAULT_LEVEL``: the
    weaker proof is the safe default, because a device that cannot say
    which proof it wants must still be approvable.
    """
    _check_device(device)
    try:
        text = _level_path(device).read_text(encoding="utf-8")
    except (OSError, ValueError):
        return DEFAULT_LEVEL
    word = text.strip()
    return word if word in LEVELS else DEFAULT_LEVEL


def set_level(device: str, level: str) -> None:
    """Record that *device* is approved with *level*.

    Only the two known levels are accepted; the file holds one word
    and a newline, mode 0600.
    """
    _check_device(device)
    if level not in LEVELS:
        raise ValueError("level must be 'passphrase' or 'totp'")
    directory = _state_subdir("levels")
    _atomic_write_text(directory / device, f"{level}\n")


# --- TOTP -------------------------------------------------------------------


def totp_code(seed: bytes, counter: int) -> str:
    """The six-digit TOTP code of *seed* at *counter* (RFC 6238).

    This is RFC 4226's HOTP truncated: HMAC-SHA1 over the 8-byte
    big-endian counter, the low nibble of the last byte picks the
    offset of a 4-byte window, and the window is masked to 31 bits and
    taken modulo 10^6.  Six digits, zero padded.
    """
    if not isinstance(seed, (bytes, bytearray)) or len(seed) == 0:
        raise ValueError("seed must be non-empty bytes")
    if isinstance(counter, bool) or not isinstance(counter, int) or counter < 0:
        raise ValueError("counter must be a non-negative integer")
    digest = hmac.new(bytes(seed), struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    truncated = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(truncated % (10 ** TOTP_DIGITS)).zfill(TOTP_DIGITS)


def totp_counter(now: float | None = None) -> int:
    """The counter *now* falls in: the UNIX time divided by the step."""
    if now is None:
        now = time.time()
    return int(now) // TOTP_STEP_S


def generate_seed() -> bytes:
    """A fresh 20-byte TOTP seed from the system CSPRNG."""
    return secrets.token_bytes(20)


def seed_to_base32(seed: bytes) -> str:
    """The seed as base32, upper case and without padding.

    This is the form the authenticator app reads, and the form the
    seed is stored in; the padding carries no information and only
    makes the file harder to read.
    """
    if not isinstance(seed, (bytes, bytearray)):
        raise ValueError("seed must be bytes")
    return base64.b32encode(bytes(seed)).decode("ascii").rstrip("=")


def otpauth_uri(seed: bytes, device: str, issuer: str = "Newton") -> str:
    """The otpauth:// URI an authenticator app scans to enrol *device*.

    The issuer and the device are percent-quoted, so a name with a
    space or a colon in it cannot break the label apart.
    """
    _check_device(device)
    if not isinstance(issuer, str) or not issuer:
        raise ValueError("issuer must be a non-empty string")
    quoted_issuer = quote(issuer, safe="")
    label = f"{quoted_issuer}:{quote(device, safe='')}"
    return (
        f"otpauth://totp/{label}"
        f"?secret={quote(seed_to_base32(seed), safe='')}"
        f"&issuer={quoted_issuer}"
        f"&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_STEP_S}"
    )


def _totp_path(device: str) -> Path:
    return approve.state_dir() / "keys" / f"{device}.json"


def store_totp(device: str, seed: bytes, k_hex: str) -> None:
    """Store the TOTP seed and the approval key of *device*.

    The record is ``{"seed_b32", "k", "last_counter"}``; the counter
    starts at zero and moves up as codes are accepted, so a code cannot
    be used twice.  This does not change the level of the device: the
    caller decides that, so a half-enrolled device never starts
    answering for TOTP.
    """
    _check_device(device)
    if not isinstance(k_hex, str) or not approve.HEX64_RE.fullmatch(k_hex):
        raise ValueError("approval key must be 64 lowercase hexadecimal characters")
    seed_b32 = seed_to_base32(seed)
    directory = _state_subdir("keys")
    approve._atomic_write(
        directory / f"{device}.json",
        {"seed_b32": seed_b32, "k": k_hex, "last_counter": 0},
    )


def load_totp(device: str) -> dict[str, Any] | None:
    """The stored TOTP record of *device*, or ``None`` when there is none.

    A record that cannot be read, cannot be parsed or does not hold the
    expected shapes reads as no record at all: a half-written or
    hand-edited file must not be able to pose as a seed.
    """
    _check_device(device)
    try:
        raw = _totp_path(device).read_text(encoding="utf-8")
    except (OSError, ValueError):
        return None
    try:
        record = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(record, dict):
        return None
    seed_b32 = record.get("seed_b32")
    k_hex = record.get("k")
    last_counter = record.get("last_counter")
    if not isinstance(seed_b32, str) or not BASE32_RE.fullmatch(seed_b32):
        return None
    if not isinstance(k_hex, str) or not approve.HEX64_RE.fullmatch(k_hex):
        return None
    if (
        isinstance(last_counter, bool)
        or not isinstance(last_counter, int)
        or last_counter < 0
    ):
        return None
    try:
        base64.b32decode(seed_b32 + "=" * (-len(seed_b32) % 8))
    except (ValueError, TypeError):
        return None
    return {"seed_b32": seed_b32, "k": k_hex, "last_counter": last_counter}


def delete_totp(device: str) -> None:
    """Remove the TOTP record of *device*; a missing record is fine."""
    _check_device(device)
    try:
        _totp_path(device).unlink()
    except FileNotFoundError:
        pass


def verify_totp(device: str, code: str, now: float | None = None) -> str | None:
    """Check a TOTP *code* for *device* and return the approval key.

    The read of the last accepted counter and the write of the new one
    happen under an exclusive flock, so two server processes (or a
    relaunched one) cannot both accept the same code.  See
    ``_verify_totp_unlocked`` for the rules.
    """
    _check_device(device)
    directory = _state_subdir("keys")
    fd = os.open(directory / f"{device}.lock", os.O_CREAT | os.O_RDWR | os.O_CLOEXEC, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        return _verify_totp_unlocked(device, code, now)
    finally:
        os.close(fd)


def _verify_totp_unlocked(device: str, code: str, now: float | None) -> str | None:
    """Check a TOTP *code* for *device* and return the approval key.

    The counter of *now* and its two neighbours are accepted, so a
    clock that is a little off still works.  A code is accepted once:
    the counter it matched is written back to the record, and a code
    whose counter is not newer than the one already accepted is
    refused.  All three comparisons always run, so how long this call
    takes does not tell an attacker which window matched.

    Returns the stored approval key on success and ``None`` on any
    failure (a malformed code, no record, a wrong code, a replay).
    """
    _check_device(device)
    if not isinstance(code, str):
        return None
    candidate = code.strip()
    if not CODE_RE.fullmatch(candidate):
        return None
    record = load_totp(device)
    if record is None:
        return None
    seed_b32 = record["seed_b32"]
    seed = base64.b32decode(seed_b32 + "=" * (-len(seed_b32) % 8))
    current = totp_counter(now)
    matched: int | None = None
    for offset in (1, 0, -1):
        counter = current + offset
        if counter < 0:
            continue
        # Every window is compared, even after one matched: the loop
        # must not leak which one it was through its timing.
        if hmac.compare_digest(totp_code(seed, counter), candidate) and matched is None:
            matched = counter
    if matched is None:
        return None
    if matched <= record["last_counter"]:
        return None
    record["last_counter"] = matched
    approve._atomic_write(_totp_path(device), record)
    return record["k"]


def key_is_stale(device: str, k_hex: str) -> bool:
    """True when a stored key is not the device's key now.

    ``newton-router-setup approval-key`` can change the passphrase (and
    so the router's key) without touching the TOTP record or a live
    grant, which keep the key of the passphrase typed back then.  An approval minted
    with that key would only be refused by the router, so the dialog
    stops early and asks for a new enrolment.  Only a fingerprint that
    is there and differs counts: a missing one proves nothing either way.
    """
    _check_device(device)
    status = approve.check_approval_fingerprint(
        approve.state_dir() / "approval-fp" / device,
        approve.approval_fingerprint(k_hex),
    )
    return status == approve.APPROVAL_FP_MISMATCH


# --- the passphrase proof ----------------------------------------------------


def verify_passphrase(device: str, passphrase: str) -> tuple[str, str | None]:
    """Check an approval passphrase for *device*.

    The key is derived the same way ``newton-approve`` derives it and
    compared against the fingerprint ``newton-router-setup approval-key``
    stored, which catches a wrong passphrase at approve time instead of
    at apply time.  The passphrase itself is never written anywhere.

    Returns ``("ok", k)``, ``("wrong", None)`` for a passphrase that
    does not match, ``("no-fingerprint", None)`` when the device has no
    fingerprint on record, and ``("bad-input", None)`` for an empty
    passphrase.
    """
    _check_device(device)
    if not isinstance(passphrase, str) or passphrase == "":
        return (PASS_BAD_INPUT, None)
    try:
        k_hex = approve.derive_k(passphrase.encode("utf-8"), device)
    except ValueError:
        return (PASS_BAD_INPUT, None)
    status = approve.check_approval_fingerprint(
        approve.state_dir() / "approval-fp" / device,
        approve.approval_fingerprint(k_hex),
    )
    if status == approve.APPROVAL_FP_MATCH:
        return (PASS_OK, k_hex)
    if status == approve.APPROVAL_FP_MISMATCH:
        return (PASS_WRONG, None)
    return (PASS_NO_FINGERPRINT, None)


# --- the lockout ------------------------------------------------------------


def _lockout_path(device: str) -> Path:
    return approve.state_dir() / "lockout" / f"{device}.json"


def _load_lockout(device: str) -> tuple[dict[str, Any] | None, bool]:
    """The lockout record of *device* and whether it is unreadable.

    The second element is True when a file exists but cannot be read
    as a record.  The caller then fails closed: an unreadable counter
    must not read as "no failures yet".
    """
    try:
        raw = _lockout_path(device).read_text(encoding="utf-8")
    except FileNotFoundError:
        return (None, False)
    except (OSError, ValueError):
        return (None, True)
    try:
        record = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return (None, True)
    if not isinstance(record, dict):
        return (None, True)
    misses = record.get("misses")
    locks = record.get("locks")
    until = record.get("until")
    if isinstance(misses, bool) or not isinstance(misses, int) or misses < 0:
        return (None, True)
    if isinstance(locks, bool) or not isinstance(locks, int) or locks < 0:
        return (None, True)
    if isinstance(until, bool) or not isinstance(until, (int, float)):
        return (None, True)
    return ({"misses": misses, "locks": locks, "until": float(until)}, False)


def _write_lockout(device: str, record: dict[str, Any]) -> None:
    directory = _state_subdir("lockout")
    approve._atomic_write(directory / f"{device}.json", record)


def lock_remaining(device: str, now: float | None = None) -> int:
    """Seconds left of the lockout of *device*, 0 when it is not locked.

    A record that exists but cannot be read counts as a lock of
    ``LOCK_BASE_S`` seconds from now: a counter nobody can read must
    not hand out a free attempt.  The record is rewritten with a real
    deadline so the next call sees the same lock.
    """
    _check_device(device)
    moment = time.time() if now is None else float(now)
    record, unreadable = _load_lockout(device)
    if unreadable:
        _write_lockout(
            device,
            {"misses": 0, "locks": 1, "until": moment + LOCK_BASE_S},
        )
        return LOCK_BASE_S
    if record is None:
        return 0
    remaining = record["until"] - moment
    if remaining <= 0:
        return 0
    return math.ceil(remaining)


def record_failure(device: str, now: float | None = None) -> int:
    """Count one failed approval for *device* and return the lock left.

    Three failures lock the device out for five minutes; each further
    lock doubles the wait, up to a day.  A failure during a lock does
    not push the deadline further out, so the owner cannot be kept out
    for longer by trying again.

    The counter lives on disk, so a server that is restarted (or a
    second one that is started) cannot hand out a fresh set of attempts.
    """
    _check_device(device)
    moment = time.time() if now is None else float(now)
    record, unreadable = _load_lockout(device)
    if unreadable:
        record = {"misses": 0, "locks": 1, "until": moment + LOCK_BASE_S}
        _write_lockout(device, record)
        return LOCK_BASE_S
    if record is None:
        record = {"misses": 0, "locks": 0, "until": 0.0}
    locked = record["until"] > moment
    record["misses"] += 1
    if record["misses"] >= LOCK_FREE_MISSES:
        record["locks"] += 1
        record["misses"] = 0
        if not locked:
            window = min(LOCK_BASE_S * 2 ** (record["locks"] - 1), LOCK_MAX_S)
            record["until"] = moment + window
    _write_lockout(device, record)
    return lock_remaining(device, now=moment)


def record_success(device: str) -> None:
    """Clear the lockout of *device* after a successful approval."""
    _check_device(device)
    try:
        _lockout_path(device).unlink()
    except FileNotFoundError:
        pass


# --- the acknowledgement ----------------------------------------------------


def ack_path(device: str) -> Path:
    """Where the acknowledgement of *device* is kept."""
    _check_device(device)
    return approve.state_dir() / "acks" / f"{device}.json"


def has_ack(device: str) -> bool:
    """True when *device* has an acknowledgement on record."""
    return ack_path(device).is_file()


def write_ack(device: str, now: float | None = None) -> None:
    """Record that the owner acknowledged the warning for *device*."""
    _check_device(device)
    moment = time.time() if now is None else float(now)
    directory = _state_subdir("acks")
    stamp = (
        datetime.fromtimestamp(moment, tz=timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )
    approve._atomic_write(directory / f"{device}.json", {"acknowledged_at": stamp})


# --- the dwell check --------------------------------------------------------


def dwell_ok(seconds: float) -> bool:
    """True when the owner spent at least ``MIN_DWELL_S`` on the dialog.

    The dialog must not accept an answer that arrives in the same
    breath as the question: a mis-click is not an approval.
    """
    try:
        value = float(seconds)
    except (TypeError, ValueError):
        return False
    return value >= MIN_DWELL_S


# --- the dialog lock --------------------------------------------------------


class DialogBusy(Exception):
    """Another approval dialog for the same device is already open.

    The agent can start many ``newton_apply_change`` calls for one plan
    at once.  Without a lock each of them would open its own dialog, and
    a client that answers every dialog after the dwell would hand the
    caller one passphrase guess per call before the first failure was
    counted.  The lock turns the second and later calls into a fallback
    to the terminal instead.
    """


@contextlib.contextmanager
def device_dialog_lock(device: str) -> Iterator[None]:
    """Hold the approval-dialog lock of *device* for the block.

    The lock is an exclusive flock on ``state_dir()/locks/<device>.lock``,
    taken without blocking: when it is already held, :class:`DialogBusy`
    is raised instead of waiting, because a second dialog would ask the
    owner the same question twice.

    flock locks the open file description and not the process, so two
    opens in the same process exclude each other as well.  That is what
    makes the lock work between two concurrent calls of one server.
    """
    _check_device(device)
    directory = _state_subdir("locks")
    fd = os.open(directory / f"{device}.lock", os.O_CREAT | os.O_RDWR | os.O_CLOEXEC, 0o600)
    try:
        os.fchmod(fd, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno not in (errno.EACCES, errno.EAGAIN):
                raise
            raise DialogBusy(
                f"another approval dialog is open for {device}"
            ) from exc
        yield
    finally:
        os.close(fd)
