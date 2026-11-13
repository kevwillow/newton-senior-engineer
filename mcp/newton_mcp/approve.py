"""Out-of-band console approval for a persisted Newton plan."""

from __future__ import annotations

import contextlib
import getpass
import hashlib
import hmac
import io
import json
import os
import re
import sys
import tempfile
import textwrap
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from . import consequences as _consequences
from . import explanation as _explanation
from . import owner_records
from . import redact
from . import scans as _scans
from .adapters.registry import VENDOR_WRITE_PLATFORMS
from .client_checks import CLIENT_KINDS
from .plan import compute_plan_hash


PLAN_ID_RE = re.compile(r"^[0-9a-f]{32}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
DEVICE_NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")

# Module-level seam so tests inject a fake reader instead of a real tty.
_getpass = getpass.getpass


class ApprovalRefused(Exception):
    """The approval was refused; the message is what newton-approve says.

    WHY an exception: the terminal path and the in-client dialog
    run the same checks, so a refusal has to carry the exact wording both
    of them show the owner.  The message is the whole text that follows
    the ``newton-approve: `` prefix, so the terminal path prints it back
    byte for byte and the dialog shows the same words.
    """


def derive_k(passphrase: bytes, device: str) -> str:
    """Derive the router approval key K (design 5.4).

    K = PBKDF2-HMAC-SHA256(passphrase, b"newton-approve-v1:" + device
    UTF-8, 600000 iterations, 32 bytes), 64 lowercase hex.  The same
    contract as ``derive_k`` in scripts/newton-router-setup; this is the
    one shared host-side implementation.
    """
    if not isinstance(passphrase, (bytes, bytearray)) or len(passphrase) == 0:
        raise ValueError("passphrase must be non-empty bytes")
    if not isinstance(device, str) or not DEVICE_NAME_RE.fullmatch(device):
        raise ValueError("device must be 1-32 characters of [a-z][a-z0-9-]")
    return hashlib.pbkdf2_hmac(
        "sha256",
        bytes(passphrase),
        b"newton-approve-v1:" + device.encode("utf-8"),
        600000,
        32,
    ).hex()


# SW2 (design Item 2): the approval window travels inside the token as
# decimal UNIX seconds, 10 digits (the same shape the router's grammar
# class ``epoch`` accepts).  A window outside these bounds cannot be a
# real instant a router will ever check against.
APPROVAL_WINDOW_MIN_EPOCH = 1000000000
APPROVAL_WINDOW_MAX_EPOCH = 9999999999


def approval_token(k_hex: str, digest: str, not_before: int, not_after: int) -> str:
    """Compute the approval token (design 5.4, SW2 Item 2).

    HMAC-SHA256(K bytes, b"newton-approval-v2\\n" + digest + b"\\n" +
    NBF + b"\\n" + EXP + b"\\n"), 64 lowercase hex.  ``digest`` is the
    router's PLANDIGEST, read from the plan output; the host never
    recomputes it.  ``not_before``/``not_after`` are the UNIX seconds
    (floors) of the approval's ``created_at``/``expires_at``.

    Binding the window is the fix for an editable expiry: the expiry the router checks
    now comes out of the HMAC, so editing ``expires_at`` in the
    agent-writable approval file no longer extends the approval.
    """
    if not isinstance(k_hex, str) or not HEX64_RE.fullmatch(k_hex):
        raise ValueError("approval key must be 64 lowercase hexadecimal characters")
    if not isinstance(digest, str) or not HEX64_RE.fullmatch(digest):
        raise ValueError("plan digest must be 64 lowercase hexadecimal characters")
    for name, value in (("not_before", not_before), ("not_after", not_after)):
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not APPROVAL_WINDOW_MIN_EPOCH <= value <= APPROVAL_WINDOW_MAX_EPOCH
        ):
            raise ValueError(
                f"approval {name} must be an integer UNIX time in "
                f"[{APPROVAL_WINDOW_MIN_EPOCH}, {APPROVAL_WINDOW_MAX_EPOCH}]"
            )
    if not_after <= not_before:
        raise ValueError("approval not_after must be after not_before")
    return hmac.new(
        bytes.fromhex(k_hex),
        b"newton-approval-v2\n"
        + digest.encode("ascii")
        + b"\n"
        + str(not_before).encode("ascii")
        + b"\n"
        + str(not_after).encode("ascii")
        + b"\n",
        hashlib.sha256,
    ).hexdigest()


def read_passphrase_file(path) -> bytes:
    """Read a passphrase file the way setup does (round ap1 contract).

    The whole file is read and EXACTLY ONE trailing LF is stripped (a
    CRLF keeps its CR; two trailing LFs keep one), matching
    ``pp=${pp%$'\\n'}`` in scripts/newton-router-setup.
    """
    data = Path(path).read_bytes()
    if data.endswith(b"\n"):
        data = data[:-1]
    return data


def state_dir() -> Path:
    return Path(os.environ.get("NEWTON_STATE_DIR", "~/.local/state/newton")).expanduser()


def approval_fingerprint(k_hex: str) -> str:
    """The host-side fingerprint of K, used to catch a wrong approval
    passphrase at approve time (R1). HMAC-SHA256 of the literal message
    ``newton-approval-fingerprint-v1`` keyed with the 32 bytes of K, hex.

    Why storing this fingerprint is safe: the value is HMAC-SHA256(K
    bytes, constant), not K itself. Someone who reads it can test passphrase
    guesses offline, each guess costing a PBKDF2 run (600000 iterations of
    HMAC-SHA256), but the approval files already under
    state_dir()/'approvals'/<plan-id>.json allow the same test (they hold
    HMACs of K over a known digest), so the exposure does not grow.
    """
    if not isinstance(k_hex, str) or not HEX64_RE.fullmatch(k_hex):
        raise ValueError("approval key must be 64 lowercase hexadecimal characters")
    return hmac.new(
        bytes.fromhex(k_hex),
        b"newton-approval-fingerprint-v1",
        hashlib.sha256,
    ).hexdigest()


# Return values of check_approval_fingerprint (R1).
APPROVAL_FP_MISSING = "missing"
APPROVAL_FP_MATCH = "match"
APPROVAL_FP_MISMATCH = "mismatch"
FINGERPRINT_LINE_RE = re.compile(r"^v1 [0-9a-f]{64}$")


def check_approval_fingerprint(path: Path, expected_hex: str) -> str:
    """Compare expected_hex to the v1 <hex> stored at `path`.

    Returns ``APPROVAL_FP_MATCH`` (file present and matches), ``APPROVAL_FP_MISSING``
    (file absent -- the operator may not have run setup approval-key yet,
    or the state dir is different from the one setup used), or
    ``APPROVAL_FP_MISMATCH`` (file present but wrong, or malformed -- a
    malformed file is treated like a mismatch so a one-line edit can't
    disable the check).
    """
    try:
        text = path.read_text(encoding="ascii")
    except FileNotFoundError:
        return APPROVAL_FP_MISSING
    except (OSError, ValueError):
        # ValueError covers UnicodeDecodeError, raised when the file
        # holds a non-ASCII byte (read_text(encoding='ascii') is a
        # ValueError, not an OSError).  Treat them as a mismatch so a
        # one-byte corruption can't disable the check by raising a
        # traceback AFTER the passphrase prompt.
        return APPROVAL_FP_MISMATCH
    line = text.strip()
    if not FINGERPRINT_LINE_RE.fullmatch(line):
        return APPROVAL_FP_MISMATCH
    stored_hex = line.split(" ", 1)[1]
    return (APPROVAL_FP_MATCH
            if hmac.compare_digest(stored_hex, expected_hex)
            else APPROVAL_FP_MISMATCH)


def _sanitize_terminal_value(value: object) -> str:
    """Render non-printing characters without sending them to the terminal.

    ``str.isprintable()`` already refuses control, format and the
    non-U+0020 space characters (U+00A0 etc. are escaped via the same
    branch as ``\\uXXXX``/``\\xXX``); characters that pass it but still
    render as nothing are also escaped via
    the same branch, by consulting ``_explanation.BLANK_LOOKING``.  The
    set is shared with explanation.py so the two sites never drift.

    A literal backslash is rendered as TWO backslashes, so a typed ``\\``
    can never be mistaken for the escapes printed for real control
    characters: ``u\\ci`` + a real newline prints as ``u\\\\ci\\n`` while
    ``u\\ci`` + a typed backslash-n prints as ``u\\\\ci\\\\n``.
    """
    escaped = []
    for character in str(value):
        if character == "\\":
            escaped.append(r"\\")
            continue
        if character == " " or (
            character.isprintable()
            and character not in _explanation.BLANK_LOOKING
        ):
            escaped.append(character)
            continue
        codepoint = ord(character)
        if character == "\n":
            escaped.append(r"\n")
        elif character == "\r":
            escaped.append(r"\r")
        elif character == "\t":
            escaped.append(r"\t")
        elif codepoint <= 0xFF:
            escaped.append(f"\\x{codepoint:02x}")
        elif codepoint <= 0xFFFF:
            escaped.append(f"\\u{codepoint:04x}")
        else:
            escaped.append(f"\\U{codepoint:08x}")
    return "".join(escaped)


def _masked(value: str) -> str:
    """Redact a value and make it safe to print on the operator's terminal.

    Every agent-controlled string shown to the owner goes through this one
    function, so the terminal path and the in-client dialog mask
    exactly the same way.
    """
    return _sanitize_terminal_value(redact.redact_text(str(value)))


def _load_plan(plan_id: str) -> dict[str, Any]:
    try:
        value = json.loads(
            (state_dir() / "plans" / f"{plan_id}.json").read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("plan record not found or invalid") from exc
    if not isinstance(value, dict):
        raise ValueError("plan record not found or invalid")
    try:
        actual_hash = compute_plan_hash(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("plan record was modified or is invalid") from exc
    if value.get("plan_hash") != actual_hash or value.get("session_id") != plan_id:
        raise ValueError("plan record was modified or is invalid")
    return value


def _atomic_write(path: Path, value: dict[str, Any]) -> None:
    from . import receipts as _receipts
    # refuse before the mkdir below when the state dir or the parent of *path*
    # is unsafe to write under
    refusal = _receipts.check_state_write_path(path, state_dir())
    if refusal is not None:
        raise OSError(refusal)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


# the router rejects a stage older than ``2700 - t - 60`` seconds
# after staging (``t`` = the plan's timeout_s).  The matching line on
# the router is ``device/openwrt/newton-router/newton-router`` near
# :2477 (``age_limit=$(( 2700 - t - 60 ))``); if that number changes,
# this is the one host-side function that has to follow.  Returns the
# expiry as a tz-aware ``datetime`` in UTC, or ``None`` when the record
# carries no usable ``staged_at`` (caller prints ``unknown``).
STAGE_TOTAL_BUDGET_S = 2700
STAGE_OVERHEAD_S = 60


def stage_expiry(plan: dict[str, Any], now: datetime | None = None) -> datetime | None:
    """When does the router stop accepting this staged plan?

    ``expiry = staged_at + (STAGE_TOTAL_BUDGET_S - timeout_s - STAGE_OVERHEAD_S)``.
    The 2700/60 constants mirror the router's ``age_limit`` calculation
    (see module docstring); keeping them as named module constants means
    a single edit updates both this helper and any future refactor.
    """
    raw = plan.get("staged_at")
    if not isinstance(raw, str) or not raw:
        return None
    try:
        staged_at = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if staged_at.tzinfo is None:
        return None
    try:
        timeout_s = int(plan["timeout_s"])
    except (KeyError, TypeError, ValueError):
        return None
    if timeout_s < 0:
        return None
    return staged_at + timedelta(
        seconds=STAGE_TOTAL_BUDGET_S - timeout_s - STAGE_OVERHEAD_S
    )


_CHECK_WORD_RE = re.compile(r"[a-z0-9-]{1,40}")


def _staged_check_lines(staged: Any) -> list[str]:
    """Newton's own words for the staged-config check; anything odd is "unknown"."""
    if not isinstance(staged, dict):
        return ["Staged check: unknown"]
    fw4, reason, missing = staged.get("fw4"), staged.get("reason"), staged.get("not_checked")
    if (
        fw4 not in ("pass", "skipped-untouched", "not-checked")
        or not isinstance(reason, str)
        or (reason and not _CHECK_WORD_RE.fullmatch(reason))
        or not isinstance(missing, list)
        or not all(isinstance(m, str) and _CHECK_WORD_RE.fullmatch(m) for m in missing)
    ):
        return ["Staged check: unknown"]
    if fw4 == "pass":
        lines = ["Staged check: fw4 passed on the staged config"]
    elif fw4 == "skipped-untouched":
        lines = ["Staged check: fw4 not needed, the firewall config is untouched"]
    else:
        lines = [f"Staged check: fw4 NOT CHECKED ({reason or 'no reason given'})"]
    if missing:
        lines.append("NOT CHECKED before apply: " + ", ".join(missing))
    return lines


EXPLANATION_HEADING = "Agent's explanation (unchecked claims)"


def _canonical_claim_line(line: str, platform: str = "vyos") -> str:
    """The vendor claim line as it is sealed, not as the agent wrote it.

    The sealed probe carries the canonical re-render of the line, so the
    owner has to be shown that text: what the owner approves is what the
    device is checked against.  A line the vendor tokenizer refuses has no
    canonical form; the explanation was validated before this point, so
    that cannot happen, and the raw line is the last resort.
    """
    try:
        return _explanation.canonical_claim_line(line, platform)
    except ValueError:
        return line


def _claim_line(claim: dict[str, Any], platform: str = "vyos") -> str:
    kind = claim.get("kind")
    if kind == "uci_equals":
        return f"{claim['path']} == {claim['equals']}"
    if kind == "config_has":
        return f"config has: {_canonical_claim_line(claim['line'], platform)}"
    if kind == "ping":
        return f"ping: {claim['host']}"
    if kind in CLIENT_KINDS:
        # A client claim is printed in words: the zone and what the client
        # must see.  The addresses it is checked against are never printed.
        return _explanation.describe_claim(claim)
    return "probe: " + " ".join(claim["probe"])


AGENT_MARK = "| "


COLUMNS = 80


def platform_can_write(platform: str) -> bool:
    """True when Newton can write to a device of this platform.

    Only the vendor write path writes without the device-side guard of
    OpenWrt, so only those platforms carry the note that the approval is
    checked by the host alone.  A platform that cannot write at all
    never gets that note, and OpenWrt does not either: the guard on the
    device re-checks the approval there.
    """
    return platform in VENDOR_WRITE_PLATFORMS


def _print_agent(masked, label: str, value: str) -> None:
    """Print agent text after ``label``, wrapped so every row carries ``| ``.

    Runs of whitespace collapse to one space and the text wraps to fit
    ``COLUMNS`` including the label and marker, so the terminal never wraps a
    row to column 0 where the agent's text could pass for a Newton line.
    """
    text = " ".join(masked(value).split())
    width = max(20, COLUMNS - len(label) - len(AGENT_MARK))
    rows = textwrap.wrap(text, width=width, break_long_words=True, break_on_hyphens=False) or [""]
    pad = " " * len(label)
    for index, row in enumerate(rows):
        print(f"{label if index == 0 else pad}{AGENT_MARK}{row}")


def _print_explanation(explanation: dict[str, Any], plan: dict[str, Any], masked) -> None:
    """Print the agent's explanation below Newton's own facts.

    Everything here is the agent's claim, and every line of agent text starts
    with ``| `` after its indent; Newton's own lines (the heading, the notice,
    the mechanical check) never do.  The mechanical check compares the steps
    with the sections Newton itself found in the diff and the router's
    section facts; it only flags, it never blocks.
    """
    print(EXPLANATION_HEADING)
    print("  These are the agent's own statements; Newton has not verified them.")
    print("  Lines starting with '|' are the agent's text.")
    print("  Each expected claim will be checked after apply; a false one rolls the change back.")
    _print_agent(masked, "  Intent: ", explanation["intent"])
    print("  Steps:")
    for number, step in enumerate(explanation["steps"], start=1):
        _print_agent(masked, f"    {number}. ", step)
    print("  Expected after apply:")
    claim_platform = plan.get("platform")
    if not isinstance(claim_platform, str) or not claim_platform:
        claim_platform = "vyos"
    for claim in explanation["expect"]:
        _print_agent(masked, "    - ", _claim_line(claim, claim_platform))
    risk_lines = explanation["risk"].split("\n")
    _print_agent(masked, "  Risk: ", risk_lines[0])
    for extra in risk_lines[1:]:
        _print_agent(masked, "        ", extra)
    sections = plan.get("router_sections")
    check = _explanation.mechanical_check(
        explanation["steps"],
        str(plan.get("diff", "")),
        [str(item) for item in sections] if isinstance(sections, list) else [],
    )
    if check.disagreements:
        print("  DISAGREEMENT between the steps and Newton's facts above:")
        for flag in check.disagreements:
            print(f"    - {masked(flag)}")
    if check.also_touches:
        print("  Newton also touches (anonymous sections no step names):")
        for name in check.also_touches:
            print(f"    - {masked(name)}")
    if check.unparsed:
        word = "line" if check.unparsed == 1 else "lines"
        print(
            f"  Mechanical check: INCOMPLETE. Newton could not check {check.unparsed} diff {word} "
            "(not understood); read the Diff above yourself."
        )
    elif not check.disagreements:
        print(
            "  Mechanical check: no disagreement found between the steps and Newton's "
            "touched sections (this does not mean the explanation is right)."
        )


def validate_plan_for_approval(plan: dict[str, Any]) -> tuple[dict[str, Any], str]:
    """The checks the terminal path runs before it shows anything.

    Returns the parsed explanation (the plain-JSON form of
    ``_explanation.Explanation``) and the router digest the approval token
    binds to.  Raises ``ApprovalRefused`` with the exact wording
    newton-approve prints for each refusal, so both the terminal path and
    the in-client dialog say the same thing.
    """
    router_digest = plan.get("router_digest")
    if not isinstance(router_digest, str) or not HEX64_RE.fullmatch(router_digest):
        raise ApprovalRefused(
            "plan record has no valid router digest "
            "(64 lowercase hex); there is nothing to bind an approval token to"
        )
    if plan.get("requires_approval") is not True and plan.get("router_requires_approval") is not True:
        raise ApprovalRefused("nothing to approve: the plan does not require approval")
    # a plan with no valid explanation is never shown for approval.  The
    # check re-runs the planner's own rules, so a record edited by hand (or
    # one that carries control characters) is refused before anything prints.
    try:
        # The record says which platform the change is for: an OpenWrt
        # record carries the router's own claim kinds, a vendor record the
        # vendor ones.  A record without the field is an OpenWrt record.
        # This is the STORED explanation, so the client claims' targets
        # Newton derived are expected here.
        platform = plan.get("platform")
        if not isinstance(platform, str) or not platform:
            platform = "openwrt"
        explanation = _explanation.parse_explanation(
            plan.get("explanation"),
            change_lines=_explanation.change_lines(str(plan.get("uci_batch", ""))),
            platform=platform,
            allow_targets=True,
        )
    except (RuntimeError, OSError) as exc:
        raise ApprovalRefused(f"cannot mask the plan for display: {exc}") from None
    except _explanation.ExplanationError as exc:
        raise ApprovalRefused(
            f"plan record has no valid explanation ({_sanitize_terminal_value(exc)}); "
            "plan it again with the owner's explanation; approval not created"
        ) from None
    # A plan consented by a live grant carries no chat yes but
    # names its consent basis instead.  A human still reads the diff in
    # this terminal before approving it.
    if (
        plan.get("owner_confirmed_in_chat") is not True
        and plan.get("consent_basis") != "grant"
    ):
        raise ApprovalRefused(
            "plan record does not say the owner confirmed in chat; "
            "plan it again; approval not created"
        )
    return explanation, router_digest


def _owner_script_lines(plan_id: str, plan: dict[str, Any]) -> list[str]:
    """The owner-script lines: the script, its hashes and the blind spot.

    The script is read from disk and checked against the digest the
    record binds, so the owner approves the bytes Newton checked.  A
    script that was changed on disk is refused here, before anything
    is shown.
    """
    state = state_dir()
    try:
        apply_sha, restore_sha = owner_records.check_scripts(state, plan)
    except owner_records.RecordError as exc:
        raise ApprovalRefused(f"{exc}; approval not created") from None
    try:
        script = owner_records.read_script(state, plan_id)
    except owner_records.RecordError as exc:
        raise ApprovalRefused(f"{exc}; approval not created") from None
    try:
        text = script.decode("utf-8")
    except UnicodeDecodeError:
        raise ApprovalRefused(
            "the script of this plan is not text; approval not created"
        ) from None
    lines: list[str] = []
    lines.append("What this does:")
    for line in _consequences.describe(str(plan.get("uci_batch", ""))):
        lines.append(f"  - {line}")
    window = plan.get("timeout_s")
    lines.append(
        "If the router reboots or its web service restarts in the next "
        f"{_sanitize_terminal_value(window)} seconds, this change stays."
    )
    lines.append("Script sha256: " + owner_records.grouped_sha(apply_sha))
    lines.append("The script the owner runs, in full:")
    lines.append("")
    lines.extend(text.rstrip("\n").split("\n"))
    lines.append("")
    restore_sid = plan.get("restore_sid")
    if isinstance(restore_sid, str) and restore_sid:
        lines.append(f"Restore plan: {restore_sid}")
    lines.append("Restore script sha256: " + owner_records.grouped_sha(restore_sha))
    not_verified = plan.get("not_verified")
    if isinstance(not_verified, list) and not_verified:
        lines.append("What Newton cannot check:")
        for item in not_verified:
            lines.append(f"  - {_sanitize_terminal_value(item)}")
    return lines


def _print_plan_head(
    plan_id: str,
    plan: dict[str, Any],
    now: datetime | None = None,
) -> datetime | None:
    """Print Newton's own facts about the plan, up to the "Stage expires" line.

    Returns the stage expiry (a tz-aware datetime) or ``None`` when the
    record carries no usable ``staged_at``; the caller decides what an
    expiry that already passed means.  The caller passes the display time
    in so the printed stage window and the expiry check agree.
    """
    if now is None:
        now = datetime.now(timezone.utc)
    profile = plan.get("router_profile")
    leash = plan.get("router_leash")
    sections = plan.get("router_sections")
    reasons = plan.get("reasons")
    probes = plan.get("probes")
    try:
        shown_reasons = (
            [redact.redact_text(str(reason)) for reason in reasons]
            if isinstance(reasons, list) and reasons
            else None
        )
        shown_diff = redact.redact_text(str(plan["diff"]))
        shown_probes = (
            [redact.redact_text(" ".join(str(field) for field in probe)) for probe in probes]
            if isinstance(probes, list)
            else None
        )
    except (RuntimeError, OSError) as exc:
        raise ApprovalRefused(f"cannot mask the plan for display: {exc}") from None
    print(f"Plan: {plan_id}")
    print(f"Device: {_sanitize_terminal_value(plan['device'])}")
    print(f"Host: {_sanitize_terminal_value(plan['host'])}")
    print(f"Profile: {_masked(profile) if isinstance(profile, str) else 'unknown'}")
    # The vendor header: what the undo of this platform is, and who checks
    # the approval.  Both are Newton's own facts, so they never carry the
    # agent marker.
    platform = plan.get("platform")
    if not isinstance(platform, str) or not platform:
        platform = "openwrt"
    if platform == "routeros":
        print(
            "The undo is a reboot into the backup (RouterOS has no soft revert)"
        )
    if platform_can_write(platform):
        print(
            "Note: approval is checked by the Newton host only; the device "
            "does not re-check it"
        )
    if isinstance(leash, str):
        # An owner-script record: one code, not a list of them.
        print(f"Leash: {leash}")
    elif not isinstance(leash, list):
        print("Leash codes: unknown")
    elif not leash:
        print("Leash codes: none")
    else:
        print("Leash codes:")
        for code in leash:
            print(f"  - {_masked(code)}")
    if not isinstance(sections, list):
        print("Sections: unknown")
    elif not sections:
        print("Sections: none")
    else:
        print("Sections:")
        for section in sections:
            print(f"  - {_masked(section)}")
    if platform == "openwrt":
        for line in _staged_check_lines(plan.get("staged_check")):
            print(line)
    else:
        # Vendor plans have no fw4; their stage is the candidate diff shown above.
        print("Staged check: the vendor candidate diff above; no fw4 check on this platform")
    print("Approval: required for every change, whatever the risk reasons below say.")
    print("Risk reasons:")
    if shown_reasons is None:
        print("  - none (approval is still required for every change)")
    else:
        for reason in shown_reasons:
            print(f"  - {_sanitize_terminal_value(reason)}")
    print("Diff:")
    for line in shown_diff.split("\n"):
        print(_sanitize_terminal_value(line))
    if shown_probes is None:
        print("Probes: unknown")
    elif not shown_probes:
        print("Probes: none")
    else:
        print("Probes:")
        for probe in shown_probes:
            print(f"  - {_sanitize_terminal_value(probe)}")
    if plan.get("mode") == "auto":
        # A no-install auto plan: the owner is told what Newton cannot
        # check, exactly as an owner script is told.
        not_verified = plan.get("not_verified")
        if isinstance(not_verified, list) and not_verified:
            print("What Newton cannot check:")
            for item in not_verified:
                print(f"  - {_sanitize_terminal_value(item)}")
    print(f"Timeout: {_sanitize_terminal_value(plan['timeout_s'])}s")
    reboot = _reboot_line(plan)
    if reboot is not None:
        print(reboot)
    # the router's age limit is ``2700 - timeout_s - 60`` seconds
    # after staging.  We always print the line so an operator who aborts
    # can see what the device sees; a missing ``staged_at`` prints
    # ``unknown`` (a stage whose age cannot be computed is not silently
    # treated as fresh AND not refused).
    expiry = stage_expiry(plan, now=now)
    if expiry is None:
        print("Stage expires: unknown")
    else:
        local_expiry = expiry.astimezone()
        remaining_seconds = int((expiry - now).total_seconds())
        remaining_minutes = max(0, remaining_seconds // 60)
        print(
            f"Stage expires: {local_expiry.strftime('%H:%M:%S')} "
            f"(about {remaining_minutes} min from now)"
        )
    if owner_records.is_owner_record(plan):
        for line in _owner_script_lines(plan_id, plan):
            print(line)
    return expiry


def _reboot_line(plan: dict[str, Any]) -> str | None:
    """The reboot line of a no-install auto plan, or None.

    The auto plan of a no-install router carries the line in its
    record, and the line is computed here from the plan's own window,
    which the plan hash binds: the owner reads the line the plan was
    made with, not one an edited record could swap.

    An owner script shows its own line, in its own part of the
    display, so it is shown there and not here.  An installed plan
    carries no line at all: its display does not change.
    """
    line = plan.get("reboot_line")
    if not isinstance(line, str) or not line:
        return None
    if owner_records.is_owner_record(plan):
        return None
    window = plan.get("timeout_s")
    if isinstance(window, bool) or not isinstance(window, int):
        return None
    from . import owner_flow

    return owner_flow.REBOOT_LINE.format(window)

def _print_plan_tail(
    plan: dict[str, Any],
    explanation: dict[str, Any],
    router_digest: str,
    masked: Callable[[str], str],
) -> None:
    """Print the agent's explanation block, the digest and the plan hash.

    ``masked`` is the redaction+sanitising function the facts above used,
    passed in so the caller decides how a value is masked.
    """
    _print_explanation(explanation, plan, masked)
    print(f"Digest: {_sanitize_terminal_value(router_digest[:12])}")
    print(f"Plan hash: {_sanitize_terminal_value(plan['plan_hash'][:12])}")


def render_plan_text(
    plan_id: str,
    plan: dict[str, Any],
    explanation: dict[str, Any],
    router_digest: str,
    *,
    now: datetime | None = None,
) -> str:
    """The plan display as one string, for the in-client dialog.

    The text is the same bytes the terminal path prints between the
    "Plan:" line and the "Plan hash:" line -- the dialog shows the owner
    what the terminal would have shown.  The prompt is not part of it: the
    dialog asks in its own window.  An expired stage is refused with the
    terminal path's own wording.
    """
    if now is None:
        now = datetime.now(timezone.utc)
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        expiry = _print_plan_head(plan_id, plan, now)
        if expiry is not None and expiry <= now:
            expired_local = expiry.astimezone()
            raise ApprovalRefused(
                "the staged change has expired "
                f"(expired {expired_local.strftime('%H:%M:%S')}); "
                "plan it again; approval not created"
            )
        _print_plan_tail(plan, explanation, router_digest, _masked)
    return buffer.getvalue()


def mint_approval(
    plan_id: str,
    plan: dict[str, Any],
    router_digest: str,
    k_hex: str,
    approved_by: str,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Mint the approval record for a plan; nothing is written here.

    The window is 30 minutes, clamped to the stage expiry when the router
    would reject the stage first (R2).  A clamp that leaves no window at
    all is a refusal, not a stale record (R8 b-1).  The token is minted
    over the window the record carries (SW2), so an edited record cannot
    be talked into being accepted.
    """
    created = datetime.now(timezone.utc) if now is None else now
    thirty_min = created + timedelta(minutes=30)
    # never let the host-side approval outlive the device-side
    # stage window.  If the router would already reject the stage
    # before 30 min, the approval cannot do better -- the apply would
    # fail with stale-stage.  Unknown stage age leaves the 30-min
    # default in place (the operator still gets the same window they
    # had before R2).
    stage_expires = stage_expiry(plan, now=created)
    if stage_expires is not None and stage_expires < thirty_min:
        expires_at = stage_expires
    else:
        expires_at = thirty_min
    # R8 (b-1): the stage can expire while the operator is typing the
    # passphrase.  The earlier ``expiry <= now`` check only catches a
    # stage that was already expired when the plan was displayed; this
    # one catches the window in between, where the clamp produced an
    # expires_at that is NOT strictly after `created` -- writing such a
    # record would land a stale approval on disk.  Refuse instead.
    if expires_at <= created:
        raise ApprovalRefused(
            "the staged change expired while you typed; "
            "plan it again; approval not created"
        )
    # SW2 (design Item 2): the window is fixed BEFORE the token is
    # minted, because the token binds it.  not_before/not_after are the
    # UNIX-second floors of created/expires_at; the server refuses an
    # approval whose stored floors do not match those two fields, and the
    # router refuses a token minted over any other window.
    not_before = int(created.timestamp())
    not_after = int(expires_at.timestamp())
    try:
        token = approval_token(k_hex, router_digest, not_before, not_after)
    except ValueError as exc:
        del k_hex
        raise ApprovalRefused(f"{exc}; approval not created") from None
    del k_hex
    return {
        "plan_id": plan_id,
        "plan_hash": plan["plan_hash"],
        "device": plan["device"],
        "base_hash": plan["base_hash"],
        "approved_by": approved_by,
        "created_at": created.isoformat(),
        "expires_at": expires_at.isoformat(),
        "not_before": not_before,
        "not_after": not_after,
        "token": token,
    }


def write_approval(plan_id: str, approval: dict[str, Any]) -> None:
    """Write the approval record under the state dir (atomic, mode 0600).

    An OSError propagates: the caller prints its own message and the
    operator needs to know the write failed.
    """
    if not isinstance(plan_id, str) or not PLAN_ID_RE.fullmatch(plan_id):
        raise ValueError("plan id must be 32 lowercase hexadecimal characters")
    _atomic_write(state_dir() / "approvals" / f"{plan_id}.json", approval)


def _approve_scan(request_id: str) -> int:
    """Approve one stored scan request with the existing passphrase habit."""
    try:
        request = _scans.load_request(state_dir(), request_id)
    except _scans.ScanError as exc:
        print(f"newton-approve: {_sanitize_terminal_value(exc)}", file=sys.stderr)
        return 1
    if _scans.consent_path(state_dir(), request_id).with_suffix(".used").exists():
        print(
            "newton-approve: scan request was already used; plan a new scan request",
            file=sys.stderr,
        )
        return 1
    device = str(request["device"])
    print(f"Scan request: {_sanitize_terminal_value(request_id)}")
    print(f"Device: {_sanitize_terminal_value(device)}")
    print(f"Kind: {_sanitize_terminal_value(request['kind'])}")
    print(f"Profile: {_sanitize_terminal_value(request['profile'])}")
    print(f"Interface: {_sanitize_terminal_value(request['interface'])}")
    print(f"Target: {_sanitize_terminal_value(request['target'])}")
    if request["kind"] == _scans.WIFI_KIND:
        # The Wi-Fi survey.  The owner has to know that the radio
        # leaves the serving channel, that the scan transmits probe
        # requests, and that the router program may be too old for the
        # verb.  The same-name-other-AP check needs the router's own
        # BSSID, which a router with the radio off does not report.
        print(
            f"scan the air around {_sanitize_terminal_value(request['interface'])}: "
            "sends probe requests on all channels, may disturb connected "
            "clients briefly; keeps channel counts and look-alike names only."
        )
        print(f"Disruption: {_sanitize_terminal_value(_scans.WIFI_DISRUPTION_NOTE)}")
        print(
            "same-name-other-AP check unavailable while the radio is off; "
            "it runs only when the router reports its own BSSID."
        )
    else:
        # SC-1: the scan target came from the router's own interface report,
        # so a compromised router could change it.  Tell the approver the
        # source of the string they are about to approve so they cannot read
        # the row as if it were a host-controlled value.
        print(
            "Target source: the router's own interface report "
            "(a compromised router could change it)."
        )
    print(f"Vantage: {_sanitize_terminal_value(request['vantage'])}")
    print(f"Duration cap: {_sanitize_terminal_value(request['duration_cap_s'])}s")
    print(f"Kept: {_sanitize_terminal_value(request['kept'])}")
    print(f"Request hash: {_sanitize_terminal_value(str(request['request_hash'])[:12])}")
    expected = f"approve {request_id[:8]}"
    print(f"Type {expected!r} to approve: ", end="", flush=True)
    confirmation = sys.stdin.readline().rstrip("\r\n")
    if confirmation != expected:
        print("newton-approve: confirmation did not match; consent not created", file=sys.stderr)
        return 1
    try:
        passphrase = _getpass(
            f"approval passphrase for {_sanitize_terminal_value(device)}: "
        )
    except (EOFError, KeyboardInterrupt, OSError):
        print(
            "newton-approve: approval passphrase could not be read; consent not created",
            file=sys.stderr,
        )
        return 1
    if not passphrase:
        print(
            "newton-approve: approval passphrase must not be empty; consent not created",
            file=sys.stderr,
        )
        return 1
    try:
        passphrase_bytes = passphrase.encode("utf-8")
        k_hex = derive_k(passphrase_bytes, device)
        fingerprint = approval_fingerprint(k_hex)
    except ValueError as exc:
        print(f"newton-approve: {exc}; consent not created", file=sys.stderr)
        return 1
    fingerprint_status = check_approval_fingerprint(
        state_dir() / "approval-fp" / device, fingerprint
    )
    del passphrase, passphrase_bytes, k_hex, fingerprint
    if fingerprint_status == APPROVAL_FP_MISMATCH:
        print(
            "newton-approve: wrong approval passphrase for "
            f"{_sanitize_terminal_value(device)}; consent not created",
            file=sys.stderr,
        )
        return 1
    if fingerprint_status == APPROVAL_FP_MISSING:
        print(
            "newton-approve: no approval fingerprint on record for "
            f"{_sanitize_terminal_value(device)}; run newton-router-setup "
            f"{_sanitize_terminal_value(device)} approval-key first; consent not created",
            file=sys.stderr,
        )
        return 1
    created = datetime.now(timezone.utc)
    consent = {
        "request_id": request_id,
        "request_hash": request["request_hash"],
        "device": device,
        "approved_by": os.environ.get("SUDO_USER", ""),
        "created_at": created.isoformat(),
        "expires_at": (created + timedelta(minutes=30)).isoformat(),
    }
    try:
        _scans.save_consent(state_dir(), consent)
    except OSError as exc:
        print(f"newton-approve: could not write consent: {exc}", file=sys.stderr)
        return 1
    print(f"Approved scan request {request_id} for 30 minutes.")
    return 0


#: The level names of the approval proof.
LEVEL_PASSPHRASE = "passphrase"
LEVEL_TOTP = "totp"


def _lock_remaining(device: str) -> int:
    """The seconds the device is locked out for, or 0."""
    from . import approval_proof

    try:
        return approval_proof.lock_remaining(device)
    except Exception:
        return 0


def _record_failure(device: str) -> int:
    """Record one wrong answer; return the seconds of the lockout."""
    from . import approval_proof

    try:
        return approval_proof.record_failure(device)
    except Exception:
        return 0


def _locked_text(remaining: int) -> str:
    """The refusal of a locked device."""
    import math

    minutes = max(1, math.ceil(remaining / 60))
    return (
        f"too many wrong answers; try again in {minutes} min; approval not created"
    )


def _wrong_text(remaining: int) -> str:
    """The refusal of a wrong answer."""
    if remaining > 0:
        import math

        minutes = max(1, math.ceil(remaining / 60))
        return f"wrong approval answer; try again in {minutes} min; approval not created"
    return "wrong approval answer; approval not created"


def _ask_proof(
    device: str,
    level: str,
    proof_prompt: str | None,
    lockout: bool,
) -> tuple[str | None, str | None]:
    """Ask the owner for the proof, and return the key it proves.

    The passphrase never reaches the environment, the argv, a log or a
    file: it is read here, in this function, and dropped as soon as the
    key is derived from it.

    Returns ``(key, None)`` on success and ``(None, the refusal)`` on
    failure.
    """
    from . import approval_proof

    safe_device = _sanitize_terminal_value(device)
    if level == LEVEL_TOTP:
        prompt = proof_prompt or f"6-digit code for {safe_device}: "
        try:
            code = _getpass(prompt)
        except (EOFError, KeyboardInterrupt, OSError):
            return None, "the approval code could not be read; approval not created"
        code = code.strip() if isinstance(code, str) else ""
        if approval_proof.CODE_RE.fullmatch(code) is None:
            remaining = approval_proof.record_failure(device)
            return None, _wrong_text(remaining)
        key = approval_proof.verify_totp(device, code)
        if key is None:
            remaining = approval_proof.record_failure(device)
            return None, _wrong_text(remaining)
        approval_proof.record_success(device)
        return key, None

    prompt = proof_prompt or f"approval passphrase for {safe_device}: "
    try:
        passphrase = _getpass(prompt)
    except (EOFError, KeyboardInterrupt, OSError):
        return None, "approval passphrase could not be read; approval not created"
    if not passphrase:
        return None, "approval passphrase must not be empty; approval not created"
    status, key = approval_proof.verify_passphrase(device, passphrase)
    # The passphrase and the intermediate UTF-8 bytes are dropped here;
    # Python cannot guarantee the underlying memory is zeroed, so this
    # is best effort -- none of them is ever printed, logged or written.
    del passphrase
    if status == approval_proof.PASS_OK and key is not None:
        return key, None
    if status == approval_proof.PASS_NO_FINGERPRINT:
        return None, (
            f"no approval fingerprint on record for {safe_device}; run "
            f"newton-router-setup {safe_device} approval-key first; "
            "approval not created"
        )
    if status == approval_proof.PASS_BAD_INPUT:
        return None, "the approval passphrase cannot be used; approval not created"
    if lockout:
        remaining = approval_proof.record_failure(device)
        return None, _wrong_text(remaining)
    return None, f"wrong approval passphrase for {safe_device}; approval not created"


def approve_plan(
    plan_id: str,
    plan: dict[str, Any],
    *,
    program: str = "newton-approve",
    now: datetime | None = None,
    level: str | None = None,
    proof_prompt: str | None = None,
    lockout: bool = False,
) -> tuple[bool, str]:
    """The interactive approval of one plan.

    This is the ONE implementation of the interactive approval: the
    ``newton-approve`` command and the owner-script run both call it,
    so the rules -- the plan that is shown, the confirmation line, the
    proof, the lockout and the fingerprint -- exist once.

    The plan and the questions are printed here.  The return value is
    ``(True, "")`` when the approval was written and ``(False, the
    refusal)`` when it was not; the caller prints the refusal with its
    own name, so the same refusal reads the same in both places.
    """
    if level is None:
        level = LEVEL_PASSPHRASE
    device = str(plan.get("device", ""))
    if now is None:
        now = datetime.now(timezone.utc)
    try:
        explanation, router_digest = validate_plan_for_approval(plan)
        expiry = _print_plan_head(plan_id, plan, now)
        if expiry is not None and expiry <= now:
            expired_local = expiry.astimezone()
            raise ApprovalRefused(
                "the staged change has expired "
                f"(expired {expired_local.strftime('%H:%M:%S')}); "
                "plan it again; approval not created"
            )
        _print_plan_tail(plan, explanation, router_digest, _masked)
    except ApprovalRefused as exc:
        return False, str(exc)

    expected = f"approve {plan_id[:8]}"
    print(f"Type {expected!r} to approve: ", end="", flush=True)
    confirmation = sys.stdin.readline().rstrip("\r\n")
    if confirmation != expected:
        return False, "confirmation did not match; approval not created"

    if lockout:
        remaining = _lock_remaining(device)
        if remaining > 0:
            return False, _locked_text(remaining)

    k_hex, refusal = _ask_proof(device, level, proof_prompt, lockout)
    if refusal is not None:
        return False, refusal

    try:
        approval = mint_approval(
            plan_id,
            plan,
            router_digest,
            k_hex,
            os.environ.get("SUDO_USER", ""),
        )
    except ApprovalRefused as exc:
        del k_hex
        return False, f"{exc}; approval not created"
    del k_hex
    try:
        write_approval(plan_id, approval)
    except OSError as exc:
        return False, f"could not write approval: {exc}"
    # R8 (b-1): the final 'Approved plan ... for N minutes' line is
    # truthful.  When the clamp shortened the window to something
    # shorter than 30 minutes, print the real number of minutes
    # (rounded down, at least 1); keep the exact old "30 minutes"
    # text when the default 30-minute window applied.
    window_seconds = (
        datetime.fromisoformat(approval["expires_at"])
        - datetime.fromisoformat(approval["created_at"])
    ).total_seconds()
    del approval
    window_minutes = max(1, int(window_seconds // 60))
    print(f"Approved plan {plan_id} for {window_minutes} minutes.")
    return True, ""


def _ad_high_reasons(facts: Any) -> list[str]:
    """The reasons a change of a domain is HIGH, in the words of the flow."""
    reasons: list[str] = []
    if not isinstance(facts, dict):
        return reasons
    for one in facts.values():
        if not isinstance(one, dict):
            continue
        if one.get("privileged") is True:
            reasons.append("the target is a privileged object")
        if one.get("admin_count") == 1:
            reasons.append("the target has an adminCount of 1")
        if one.get("dc_account") is True:
            reasons.append("the target is a domain controller account")
    return reasons


def _print_ad_plan(plan: dict[str, Any]) -> None:
    """Show every field of an AD plan to the owner.

    Every name the directory gave is masked and sanitised: it is data,
    never text the terminal may act on.  The password of a new account
    is not shown here: ``_print_ad_password`` prints it once the approval
    exists.
    """
    device = str(plan.get("device", ""))
    print(f"Plan: {_sanitize_terminal_value(plan.get('plan_id', ''))}")
    print(f"Domain: {_sanitize_terminal_value(device)}")
    print(f"Verb: {_sanitize_terminal_value(plan.get('verb', ''))}")
    target = plan.get("target")
    if isinstance(target, dict):
        print("Target:")
        for key in sorted(target):
            value = target[key]
            shown = _masked(value) if isinstance(value, str) else _sanitize_terminal_value(value)
            print(f"  - {key}: {shown}")
    for label in ("before", "after"):
        values = plan.get(label)
        if isinstance(values, dict):
            shown = ", ".join(
                f"{key}={_masked(value) if isinstance(value, str) else _sanitize_terminal_value(value)}"
                for key, value in sorted(values.items())
            )
            print(f"{label.capitalize()}: {shown}")
    print(f"Risk: {_sanitize_terminal_value(plan.get('risk', ''))}")
    print(f"Window: {_sanitize_terminal_value(plan.get('window', ''))}s")


def _print_ad_password(plan: dict[str, Any], first: bool) -> None:
    """The password of a new account, printed at the first approval only.

    It is printed with the sanitiser alone, never with the redactor: a
    redactor that rewrote part of it would show the owner a password
    that is not the one the account gets.  A later approval of the same
    plan never prints it again, and the apply drops it from the plan
    record once it has been sent to the DC.
    """
    secret = plan.get("secret")
    if not isinstance(secret, str) or not secret:
        return
    if not first:
        print(
            "The password of the new account was shown at the first approval "
            "of this plan and is not shown again."
        )
        return
    print(
        "Password of the new account (shown once, at the first approval; "
        "Newton drops it from the plan record once the apply has sent it):"
    )
    print(f"  {_sanitize_terminal_value(secret)}")


def approve_ad_change(
    plan_id: str,
    *,
    now: datetime | None = None,
) -> tuple[bool, str]:
    """The interactive approval of one Active Directory change.

    The plan is shown in full and the canonical bytes are built here,
    through ``request.canonical_bytes`` of the write package: the digest
    in the plan file is never read, because the agent can write that
    file.  The token is minted over the digest this function computed.

    The terminal checks, the lockout and the sanitising are the ones of
    the router flow.
    """
    from .ad.write import request as _ad_request

    if not isinstance(plan_id, str) or PLAN_ID_RE.fullmatch(plan_id) is None:
        return False, "plan id must be 32 lowercase hexadecimal characters"
    path = state_dir() / "ad-plans" / f"{plan_id}.json"
    try:
        plan = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError):
        return False, "plan record not found or invalid"
    if not isinstance(plan, dict) or plan.get("plan_id") != plan_id:
        return False, "plan record not found or invalid"
    device = plan.get("device")
    if not isinstance(device, str) or DEVICE_NAME_RE.fullmatch(device) is None:
        return False, "plan record not found or invalid"
    try:
        canonical = _ad_request.canonical_bytes(plan)
    except (_ad_request.RequestRefused, KeyError, TypeError, ValueError):
        return False, "plan record does not hold the fields of a request"
    digest = hashlib.sha256(canonical).hexdigest()

    _print_ad_plan(plan)
    if str(plan.get("risk", "")) == "HIGH":
        print(f"NEWTON  HIGH RISK  APPROVAL  {_sanitize_terminal_value(device)}  plan {plan_id[:8]}")
        print("WHY THIS IS HIGH RISK")
        for reason in _ad_high_reasons(plan.get("facts")):
            print(f"  - {_sanitize_terminal_value(reason)}")

    expected = f"approve {plan_id[:8]}"
    print(f"Type {expected!r} to approve: ", end="", flush=True)
    confirmation = sys.stdin.readline().rstrip("\r\n")
    if confirmation != expected:
        return False, "confirmation did not match; approval not created"

    remaining = _lock_remaining(device)
    if remaining > 0:
        return False, _locked_text(remaining)

    try:
        passphrase = _getpass(
            f"approval passphrase for {_sanitize_terminal_value(device)}: "
        )
    except (EOFError, KeyboardInterrupt, OSError):
        return False, "approval passphrase could not be read; approval not created"
    if not passphrase:
        return False, "approval passphrase must not be empty; approval not created"
    try:
        passphrase_bytes = passphrase.encode("utf-8")
        k_hex = derive_k(passphrase_bytes, device)
        fingerprint = approval_fingerprint(k_hex)
    except ValueError as exc:
        del passphrase
        return False, f"{exc}; approval not created"
    del passphrase, passphrase_bytes
    status = check_approval_fingerprint(
        state_dir() / "approval-fp" / device, fingerprint
    )
    del fingerprint
    if status == APPROVAL_FP_MISMATCH:
        del k_hex
        return False, _wrong_text(_record_failure(device))
    if status == APPROVAL_FP_MISSING:
        del k_hex
        return False, (
            f"no approval fingerprint on record for {_sanitize_terminal_value(device)}; "
            "run sudo -u newton /usr/local/bin/newton-ad-setup approval-key "
            f"{_sanitize_terminal_value(device)} on the Newton host first "
            "(from a source tree: scripts/newton-ad-setup approval-key "
            f"{_sanitize_terminal_value(device)}); approval not created"
        )

    created = datetime.now(timezone.utc) if now is None else now
    not_before = int(created.timestamp())
    not_after = not_before + 1800
    try:
        minted = _ad_request.token(k_hex, digest, not_before, not_after)
    except ValueError as exc:
        del k_hex
        return False, f"{exc}; approval not created"
    del k_hex
    approval = {
        "plan_id": plan_id,
        "device": device,
        "digest": digest,
        "nbf": not_before,
        "exp": not_after,
        "token": minted,
        "created_at": created.isoformat(),
        "approved_by": os.environ.get("SUDO_USER", ""),
    }
    approval_file = state_dir() / "ad-plans" / f"{plan_id}.approval.json"
    first = not approval_file.exists()
    try:
        _atomic_write(approval_file, approval)
    except OSError as exc:
        return False, f"could not write approval: {exc}"
    print(f"Approved plan {plan_id} for 30 minutes.")
    _print_ad_password(plan, first)
    return True, ""


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args and args[0] == "ad-change":
        if len(args) != 2:
            print(
                "usage: newton-approve ad-change <32-hex-plan-id>",
                file=sys.stderr,
            )
            return 2
        plan_id = args[1]
        if not PLAN_ID_RE.fullmatch(plan_id):
            print(
                "newton-approve: plan id must be 32 lowercase hexadecimal characters",
                file=sys.stderr,
            )
            return 2
        if not sys.stdin.isatty():
            print("newton-approve: stdin must be an interactive terminal", file=sys.stderr)
            return 1
        ok, refusal = approve_ad_change(plan_id)
        if not ok:
            print(f"newton-approve: {refusal}", file=sys.stderr)
            return 1
        return 0
    if len(args) != 1:
        print("usage: newton-approve <32-hex-plan-or-scan-request-id>", file=sys.stderr)
        return 2
    plan_id = args[0]
    if not PLAN_ID_RE.fullmatch(plan_id):
        print("newton-approve: plan id must be 32 lowercase hexadecimal characters", file=sys.stderr)
        return 2
    if not sys.stdin.isatty():
        print("newton-approve: stdin must be an interactive terminal", file=sys.stderr)
        return 1
    if not (state_dir() / "plans" / f"{plan_id}.json").exists():
        return _approve_scan(plan_id)
    try:
        plan = _load_plan(plan_id)
    except ValueError as exc:
        print(f"newton-approve: {exc}", file=sys.stderr)
        return 1

    ok, refusal = approve_plan(plan_id, plan)
    if not ok:
        print(f"newton-approve: {refusal}", file=sys.stderr)
        return 1
    return 0
