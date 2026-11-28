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
from collections.abc import Callable, Mapping
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Protocol

from . import consequences as _consequences
from . import explanation as _explanation
from . import net_rules as _net_rules
from . import owner_records
from . import redact
from . import scans as _scans
from .adapters.registry import VENDOR_WRITE_PLATFORMS
from .client_checks import CLIENT_KINDS
from .plan import compute_plan_hash


PLAN_ID_RE = re.compile(r"^[0-9a-f]{32}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
DEVICE_NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")

#: The prefix of the line that tells the owner what happens to the change
#: when Newton loses contact in the middle of the apply.  It is Newton's
#: own fact, so it never carries the agent marker.
RECOVERY_PREFIX = "If Newton loses contact: "

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



def _launcher(name: str) -> str:
    """The command an owner types for one of Newton's tools.

    An installed Newton (its launchers set NEWTON_HOME) refuses the bare
    name: the hint is the sudo form of the installed launcher.  A source
    tree keeps the bare name.
    """
    if os.environ.get("NEWTON_HOME"):
        return f"sudo -u newton /usr/local/bin/{name}"
    return name

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
    """Read a passphrase file the way setup does.

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
APPROVAL_FP_DAMAGED = "damaged"
FINGERPRINT_LINE_RE = re.compile(r"^v1 [0-9a-f]{64}$")


def check_approval_fingerprint(path: Path, expected_hex: str) -> str:
    """Compare expected_hex to the v1 <hex> stored at `path`.

    Returns ``APPROVAL_FP_MATCH`` (file present and matches), ``APPROVAL_FP_MISSING``
    (file absent -- the operator may not have run setup approval-key yet,
    or the state dir is different from the one setup used),
    ``APPROVAL_FP_MISMATCH`` (a v1 fingerprint that differs: a wrong
    passphrase), or ``APPROVAL_FP_DAMAGED`` (the file is there but cannot
    be read or is not a v1 line).  A damaged file never approves, so a
    one-line edit cannot disable the check, and it is not a wrong answer:
    the callers name it and count no failure.
    """
    try:
        text = path.read_text(encoding="ascii")
    except FileNotFoundError:
        return APPROVAL_FP_MISSING
    except (OSError, ValueError):
        # ValueError covers UnicodeDecodeError, raised when the file
        # holds a non-ASCII byte (read_text(encoding='ascii') is a
        # ValueError, not an OSError).  A damaged file refuses, so a
        # one-byte corruption can't disable the check by raising a
        # traceback AFTER the passphrase prompt.
        return APPROVAL_FP_DAMAGED
    line = text.strip()
    if not FINGERPRINT_LINE_RE.fullmatch(line):
        return APPROVAL_FP_DAMAGED
    stored_hex = line.split(" ", 1)[1]
    return (APPROVAL_FP_MATCH
            if hmac.compare_digest(stored_hex, expected_hex)
            else APPROVAL_FP_MISMATCH)


def _confirm_typed(expected: str) -> str | None:
    """Ask the owner to type ``expected``; None when they did, else the refusal.

    Spaces around the answer are ignored (a pasted line often carries a
    trailing one).  Ctrl-C or the end of input at the prompt is a refusal
    of its own, never a traceback, and a wrong answer names what to type.
    The caller appends what was not created.
    """
    print(f"Type {expected!r} to approve: ", end="", flush=True)
    try:
        line = sys.stdin.readline()
    except (KeyboardInterrupt, OSError, ValueError):
        print(file=sys.stderr)
        return "confirmation could not be read"
    if not line:
        print(file=sys.stderr)
        return "confirmation could not be read"
    if line.strip() != expected:
        return f"confirmation did not match: type {expected!r} exactly"
    return None


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

#: The heading of the block that lists the owner's network rules.
RULES_HEADING = "Your network rules checked on this change:"


def _rule_claims(expect: Any) -> list[dict[str, Any]]:
    """The rule claims of an expect list: the claims the server added.

    A rule claim carries ``source: "rule"`` and the rule's id; the
    agent may not write either (explanation.py refuses an explanation
    that does), so every claim that carries them came from the owner's
    rules file.
    """
    return [
        claim
        for claim in (expect if isinstance(expect, list) else [])
        if isinstance(claim, dict) and claim.get("source") == "rule"
    ]


def _rule_labels(rule_ids: list[Any]) -> dict[str, str]:
    """The labels of the rules, read from the rules file at approval time.

    The label is the owner's own text and it is NOT in the claim: it is
    read here, by rule id, from the rules file next to the inventory.  A
    file that cannot be loaded (gone, broken, refused) or a rule that is
    not in it gives no label: the rule is then shown without one.
    """
    wanted = {rule_id for rule_id in rule_ids if isinstance(rule_id, str)}
    if not wanted:
        return {}
    try:
        loaded = _net_rules.load_rules(_net_rules.rules_file())
    except _net_rules.NetRuleError:
        return {}
    labels: dict[str, str] = {}
    for rules in loaded.values():
        for rule in rules:
            if rule.id in wanted and rule.label:
                labels[rule.id] = rule.label
    return labels


def _rule_lines(expect: Any) -> list[str]:
    """One line per rule claim: ``- <rule id>: <sentence>`` and the label.

    The sentence is built from the claim's own fields (never from a
    device), and the label is read from the rules file at approval time.
    A label is escaped the way approve.py escapes every other piece of
    owner text, so no control byte ever reaches the terminal.
    """
    claims = _rule_claims(expect)
    if not claims:
        return []
    labels = _rule_labels([claim.get("rule") for claim in claims])
    lines: list[str] = []
    for claim in claims:
        rule = _net_rules.claim_rule(claim)
        if rule is None:
            continue
        line = f"- {rule.id}: {_net_rules.rule_sentence(rule)}"
        label = labels.get(rule.id)
        if label:
            line += f" ({_sanitize_terminal_value(label)})"
        lines.append(line)
    return lines


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
        if isinstance(claim, dict) and claim.get("source") == "rule":
            # the owner's own rules are listed in their own block below,
            # not as the agent's text
            continue
        _print_agent(masked, "    - ", _claim_line(claim, claim_platform))
    rule_lines = _rule_lines(explanation["expect"])
    if rule_lines:
        print(f"  {RULES_HEADING}")
        for line in rule_lines:
            print(f"    {line}")
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
    # The recipe the plan came from: its title, its id and its version,
    # and the risk sentence the recipe file carries.  Both are owner
    # text (a file of the recipes dir), so they are masked and escaped
    # like every other line of this display.
    recipe = plan.get("recipe")
    if isinstance(recipe, dict):
        recipe_title = recipe.get("title")
        recipe_id = recipe.get("id")
        recipe_version = recipe.get("version")
        if (
            isinstance(recipe_title, str)
            and isinstance(recipe_id, str)
            and isinstance(recipe_version, int)
            and not isinstance(recipe_version, bool)
        ):
            print(
                f"Recipe: {_masked(recipe_title)} "
                f"({_masked(recipe_id)} v{recipe_version})"
            )
        recipe_risk = recipe.get("risk")
        if isinstance(recipe_risk, str):
            print(f"Recipe risk: {_masked(recipe_risk)}")
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
    recovery = recovery_line(plan)
    if recovery is not None:
        print(recovery)
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


def recovery_line(plan: dict[str, Any]) -> str | None:
    """The approval text's recovery line for a router or vendor plan, or None for an owner script or a platform with no undo.

    The timeout is read before the platform: a plan whose timeout cannot
    be read gets the "unknown" line, whatever its platform.

    The line says what puts the old settings back when Newton loses
    contact in the middle of the apply.  It is a fact of Newton's own, so
    it never carries the agent marker, and it is computed from the plan's
    own window: the owner reads the line the plan was made with.

    A plan whose timeout cannot be read says so in the line itself, and a
    platform Newton knows no undo for has no line at all.  An owner script
    shows its own lines and never this one, the way ``_reboot_line`` does.
    """
    if owner_records.is_owner_record(plan):
        return None
    platform = plan.get("platform")
    if not isinstance(platform, str) or not platform:
        platform = "openwrt"
    timeout = plan.get("timeout_s")
    if isinstance(timeout, bool) or not isinstance(timeout, int):
        return RECOVERY_PREFIX + "unknown (the plan's timeout cannot be read)"
    if platform == "openwrt":
        if plan.get("mode") == "auto":
            return (
                RECOVERY_PREFIX
                + "the router puts the old settings back by itself "
                + f"{timeout}s after the apply"
            )
        return (
            RECOVERY_PREFIX
            + "the router puts the old settings back by itself "
            + f"{timeout}s after the apply; its guard does it too if that "
            + "fails, and after a reboot"
        )
    if platform in ("vyos", "junos"):
        from .adapters.vendor_write import minutes_for

        try:
            window = minutes_for(timeout) * 60
        except (TypeError, ValueError):
            return RECOVERY_PREFIX + "unknown (the plan's timeout cannot be read)"
        return (
            RECOVERY_PREFIX
            + "the device's commit-confirm puts the old settings back "
            + f"{window}s after the apply"
        )
    if platform == "routeros":
        from .adapters.routeros_write import _window_s

        window = _window_s(timeout)
        return (
            RECOVERY_PREFIX
            + "the router REBOOTS into its backup "
            + f"{window}s after the apply; traffic stops during the reboot"
        )
    return None


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
    # the stage can expire while the operator is typing the
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
        # the scan target came from the router's own interface report,
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
    refusal = _confirm_typed(expected)
    if refusal is not None:
        print(f"newton-approve: {refusal}; consent not created", file=sys.stderr)
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
    if fingerprint_status == APPROVAL_FP_DAMAGED:
        print(
            "newton-approve: the approval fingerprint file for "
            f"{_sanitize_terminal_value(device)} is damaged; run "
            "sudo -u newton /usr/local/bin/newton-router-setup "
            f"{_sanitize_terminal_value(device)} approval-key again; consent not created",
            file=sys.stderr,
        )
        return 1
    if fingerprint_status == APPROVAL_FP_MISSING:
        print(
            "newton-approve: no approval fingerprint on record for "
            f"{_sanitize_terminal_value(device)}; run {_launcher('newton-router-setup')} "
            f"{_sanitize_terminal_value(device)} approval-key first; consent not created",
            file=sys.stderr,
        )
        return 1
    if fingerprint_status != APPROVAL_FP_MATCH:
        # fail closed on any other answer
        print("newton-approve: the approval fingerprint could not be checked; consent not created", file=sys.stderr)
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


def _record_success(device: str) -> None:
    """Clear the wrong-answer count of the device after a correct proof.

    Best effort: a count that cannot be cleared never refuses an approval
    the owner proved (the next wrong answer still counts).
    """
    from . import approval_proof

    try:
        approval_proof.record_success(device)
    except Exception:
        return


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
        # clears the count on every path, as the TOTP branch does: the
        # terminal path counts nothing but a correct answer there is proof
        _record_success(device)
        return key, None
    if status == approval_proof.PASS_NO_FINGERPRINT:
        return None, (
            f"no approval fingerprint on record for {safe_device}; run "
            f"{_launcher('newton-router-setup')} {safe_device} approval-key first; "
            "approval not created"
        )
    if status == approval_proof.PASS_DAMAGED:
        return None, (
            f"the approval fingerprint file for {safe_device} is damaged; run "
            f"sudo -u newton /usr/local/bin/newton-router-setup {safe_device} approval-key again; "
            "approval not created"
        )
    if status == approval_proof.PASS_BAD_INPUT:
        return None, "the approval passphrase cannot be used; approval not created"
    if lockout:
        remaining = approval_proof.record_failure(device)
        return None, _wrong_text(remaining)
    return None, f"wrong approval passphrase for {safe_device}; approval not created"


#: The warning the first approval of a device shows, in the dialog and
#: in the terminal alike (ADR-019 item 4).
FIRST_APPROVAL_WARNING = (
    "FIRST APPROVAL ON THIS DEVICE\n"
    "Newton will change this live router.\n"
    "Every change auto-undoes unless confirmed.\n"
    "Only you can approve.\n"
    "The agent can be wrong."
)


def _first_approval(device: str) -> bool:
    """True when *device* has no acknowledgement of the warning yet."""
    from . import approval_proof

    try:
        return not approval_proof.has_ack(device)
    except Exception:
        # a device whose acknowledgement cannot be checked is warned
        return True


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

    first_time = _first_approval(device)
    if first_time:
        print()
        print(FIRST_APPROVAL_WARNING)
        print()

    expected = f"approve {plan_id[:8]}"
    refusal = _confirm_typed(expected)
    if refusal is not None:
        return False, f"{refusal}; approval not created"

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
    # the final 'Approved plan ... for N minutes' line is
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
    if first_time:
        # The acknowledgement is stored only after a successful
        # approval, as the dialog does: a failed answer must not
        # silence the warning (ADR-019 item 4).
        from . import approval_proof

        try:
            approval_proof.write_ack(device)
        except Exception:
            print(
                "The first-approval acknowledgement could not be saved; "
                "the warning is shown again next time."
            )
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
    verb = plan.get("verb")
    if verb == "unlock":
        # An unlock arms no undo; its window field is fixed and unused,
        # so no Window line suggests it could be put back.
        print("Undo: none, this stays written")
        print(RECOVERY_PREFIX + "nothing is put back; an unlock stays written")
        return
    window = _sanitize_terminal_value(plan.get("window", ""))
    reverse = (
        " (none for this verb)" if verb in ("uac-clear", "user-create") else ""
    )
    print(
        f"Undo: the PDC puts it back {window}s after the apply unless Newton "
        f"confirms; after a confirm only a reverse plan{reverse}"
    )
    print(RECOVERY_PREFIX + f"the PDC puts it back {window}s after the apply")
    print(
        "The undo runs on the PDC only. A change made meanwhile on another DC, "
        "or a PDC role move while armed, is not covered. The undo time is "
        "wall-clock on the DC."
    )
    print(f"Window: {window}s")


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
    refusal = _confirm_typed(expected)
    if refusal is not None:
        return False, f"{refusal}; approval not created"

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
    if status == APPROVAL_FP_DAMAGED:
        # never approves, and is not a wrong answer: no failure is counted
        del k_hex
        safe = _sanitize_terminal_value(device)
        if os.environ.get("NEWTON_HOME"):
            setup = f"sudo -u newton /usr/local/bin/newton-ad-setup approval-key {safe} again on the Newton host"
        else:
            setup = f"scripts/newton-ad-setup approval-key {safe} again from this source tree"
        return False, (
            f"the approval fingerprint file for {safe} is damaged; run "
            f"{setup}; approval not created"
        )
    if status == APPROVAL_FP_MISSING:
        del k_hex
        safe = _sanitize_terminal_value(device)
        if os.environ.get("NEWTON_HOME"):
            # the installed launcher: the source-tree form would store the
            # fingerprint in the caller's own state directory, never read here
            return False, (
                f"no approval fingerprint on record for {safe}; "
                "run sudo -u newton /usr/local/bin/newton-ad-setup approval-key "
                f"{safe} on the Newton host first; approval not created"
            )
        return False, (
            f"no approval fingerprint on record for {safe}; run "
            f"scripts/newton-ad-setup approval-key {safe} from this source tree first "
            "(an installed Newton: sudo -u newton /usr/local/bin/newton-ad-setup "
            f"approval-key {safe}, then sudo -u newton /usr/local/bin/newton-approve); "
            "approval not created"
        )
    if status != APPROVAL_FP_MATCH:
        # fail closed on any other answer
        del k_hex
        return False, "the approval fingerprint could not be checked; approval not created"

    # the proof matched: a correct answer clears the wrong-answer count
    _record_success(device)
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


# --------------------------------------------------------------------------
# The approval of an AD build (PLAN-1.5 task 2)
#
# The plan of a build is one document: the owner approves its bytes
# once, and the helpers receive those bytes with every request.  The
# approval of the plan mints one token per server, over the digest of
# those bytes, and the approval of a stage mints one token per server,
# over the digest of the stage, which binds the checkpoint of the stage.
#
# The secrets of the build are derived from the key of the forest root
# and are shown once, in the owner's terminal: they are never written
# in the state directory, and the runner never holds them.
# --------------------------------------------------------------------------


#: The window of the plan token of a build: six hours (PLAN-1.5,
#: Constraints).
BUILD_PLAN_WINDOW_S = 6 * 60 * 60

#: The window of a stage token of a build: thirty minutes (PLAN-1.5,
#: Constraints).
BUILD_STAGE_WINDOW_S = 30 * 60

#: The refusal codes of the build helper (PLAN-1.5, task 3) and the one
#: of the checkpoint adapter (PLAN-1.5, task 7).  The approval of a
#: build answers with one of them and with no other.
BUILD_REFUSAL_CODES: tuple[str, ...] = (
    "bad_token",
    "expired",
    "out_of_order",
    "journal_busy",
    "already_done",
    "plan_mismatch",
    "schema",
    "checkpoint_unverified",
)

#: The kinds of checkpoint of the design (DESIGN-1.5, "Checkpoints").
BUILD_CHECKPOINT_KINDS: tuple[str, ...] = ("workgroup", "dc")

#: The kind of the checkpoint of every stage that takes one (DESIGN-1.5,
#: "Checkpoints"): stage 2 takes a workgroup checkpoint, the stages 3,
#: 4 and 6 a DC one, and stage 7 a DC one on DC1 and a workgroup one on
#: DC2.
BUILD_CHECKPOINT_OF_STAGE: dict[tuple[str, str], str] = {
    ("dc1", "2"): "workgroup",
    ("dc1", "3"): "dc",
    ("dc1", "4"): "dc",
    ("dc1", "6"): "dc",
    ("dc1", "7"): "dc",
    ("dc2", "7"): "workgroup",
}

#: The stages whose checkpoint of a server without a hypervisor is the
#: all-critical backup (DESIGN-1.5, "Checkpoints", "No hypervisor"): the
#: stages 2 and 7.  The stages 3, 4 and 6 take the system-state backup,
#: which cannot undo a promotion and is therefore never the one of the
#: stages 2 and 7.  The wbadmin adapter demands the same, from the stage
#: it is given (``newton_mcp.ad.build.checkpoint``; the maintainer, 2026-11-13).
BUILD_WBADMIN_ALL_CRITICAL_STAGES: tuple[str, ...] = ("2", "7")

#: The labels the sections of the plan are printed under.
_BUILD_PLAN_LABELS: dict[str, str] = {
    "domain": "Domain",
    "servers": "Servers",
    "baseline": "Baseline",
    "accepted_findings": "Accepted findings",
    "ops": "Stage 8, the newton-ops and newton-audit setup",
    "stages": "Stages",
    "resume_from": "Resumed from",
    "start_stage": "Starts at stage",
    "secrets_from": "Passwords of plan",
}

#: The labels the items of a list of the plan are printed under.
_BUILD_ITEM_LABELS: dict[str, str] = {
    "Servers": "Server",
    "Accepted findings": "Finding",
}

#: The stage of a file name: the stage ids of the design are numbers.
_BUILD_STAGE_FILE_RE = re.compile(r"^[0-9]{1,2}$")


class CheckpointVerifier(Protocol):
    """The checkpoint adapter of the build (PLAN-1.5, task 7).

    The adapter answers one question: is this checkpoint of this server
    good enough to undo this stage?  It is the adapter that reads the
    hypervisor, the Proxmox task log or the backup, so the approval
    asks it itself and never believes the runner's own word.

    The stage is passed by keyword (the maintainer, 2026-11-13): the kind alone
    does not tell DC1's stage 7 from the stages 3, 4 and 6, and on a
    server without a hypervisor only an all-critical backup can undo
    the promotion of stage 2 or 7.
    """

    def verify(
        self,
        server_cfg: Mapping[str, Any],
        cp: Mapping[str, Any],
        kind: str,
        *,
        stage: str,
        not_before: int,
    ) -> bool:
        """True when the checkpoint may be relied on for the stage, and
        was taken no earlier than ``not_before`` (DESIGN-1.5
        "Checkpoints")."""
        ...


class CheckpointVerifierCallable(Protocol):
    """A callable adapter: the arguments of ``CheckpointVerifier.verify``."""

    def __call__(
        self,
        server_cfg: Mapping[str, Any],
        cp: Mapping[str, Any],
        kind: str,
        *,
        stage: str,
        not_before: int,
    ) -> bool: ...


#: What the approval of a stage takes: an adapter with a ``verify``
#: method, or a callable with the same arguments.
CheckpointAdapter = CheckpointVerifier | CheckpointVerifierCallable


def build_plan_dir() -> Path:
    """The directory the AD build plans and their approvals live in."""
    return state_dir() / "ad-build-plans"


def _checked_build_id(plan_id: str) -> str:
    """The plan id, when it may be used as a file name."""
    if not isinstance(plan_id, str) or PLAN_ID_RE.fullmatch(plan_id) is None:
        raise ValueError("plan id must be 32 lowercase hexadecimal characters")
    return plan_id


def build_plan_path(plan_id: str) -> Path:
    """The path of one build plan."""
    return build_plan_dir() / f"{_checked_build_id(plan_id)}.json"


def build_approval_path(plan_id: str) -> Path:
    """The path of the plan approval of one build, beside its plan."""
    return build_plan_dir() / f"{_checked_build_id(plan_id)}.approval.json"


def build_stage_approval_path(plan_id: str, stage: str) -> Path:
    """The path of the stage approval of one build, beside its plan."""
    if not isinstance(stage, str) or _BUILD_STAGE_FILE_RE.fullmatch(stage) is None:
        raise ValueError("the stage of a file name must be a stage of the design")
    return (
        build_plan_dir()
        / f"{_checked_build_id(plan_id)}.stage-{stage}.approval.json"
    )


def build_run_state_path(plan_id: str) -> Path:
    """The path of the runner's state of one build, beside its plan.

    The runner writes it when it stops for an approval: it holds the
    digest of the plan that is running, the stage it stopped at and, for
    every server, the checkpoint that was taken before the stage.  The
    approval reads the checkpoint from here and verifies it itself.
    """
    return build_plan_dir() / f"{_checked_build_id(plan_id)}.run.json"


def _refuse_build(code: str, message: str) -> int:
    """Print one refusal of the approval of a build and return its code.

    A refusal that mirrors a refusal of the build helper carries the
    code of that helper, so the owner and the runner read the same
    words.  A refusal of the owner herself -- a confirmation that did
    not match, a passphrase that did not -- carries no code, because
    the helper never sees it.
    """
    if code and code not in BUILD_REFUSAL_CODES:
        raise ValueError("the code of a build refusal is not one of the codes")
    shown = f"{code}: {message}" if code else message
    print(f"newton-approve: {shown}", file=sys.stderr)
    return 1


def _load_build_plan(plan_id: str) -> tuple[dict[str, Any], str]:
    """The plan of one build and the digest of its canonical bytes.

    The digest is computed here, from the bytes of the plan, and never
    read from the plan file: the agent can write that file.
    """
    from .ad.build import plan as _build_plan

    try:
        record = json.loads(build_plan_path(plan_id).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError):
        raise ApprovalRefused("plan record not found or invalid") from None
    if not isinstance(record, dict):
        raise ApprovalRefused("plan record not found or invalid")
    try:
        digest = _build_plan.digest(record)
    except _build_plan.BuildPlanRefused:
        raise ApprovalRefused("plan record is not a build plan") from None
    return record, digest


def _print_build_field(label: str, value: Any, indent: str) -> None:
    """Print one field of the plan, and every field under it.

    The plan is printed field by field, so no field of it can be left
    out of what the owner sees.  Every value goes through the
    sanitiser: it is data, never text the terminal may act on.
    """
    if isinstance(value, dict):
        print(f"{indent}{label}:")
        for key in value:
            _print_build_field(str(key), value[key], indent + "  ")
        return
    if isinstance(value, list):
        if value and all(isinstance(item, dict) for item in value):
            print(f"{indent}{label}:")
            item_label = _BUILD_ITEM_LABELS.get(label, "Item")
            for number, item in enumerate(value, start=1):
                print(f"{indent}  {item_label} {number}:")
                for key in item:
                    _print_build_field(str(key), item[key], indent + "    ")
            return
        shown = ", ".join(_sanitize_terminal_value(item) for item in value)
        print(f"{indent}{label}: {shown}")
        return
    print(f"{indent}{label}: {_sanitize_terminal_value(value)}")


def _print_build_plan(plan_id: str, built: dict[str, Any], digest: str) -> None:
    """Print the plan of one build, field by field."""
    print(f"Plan: {_sanitize_terminal_value(plan_id)}")
    print(f"Digest: {_sanitize_terminal_value(digest[:12])}")
    for key in built:
        _print_build_field(
            _BUILD_PLAN_LABELS.get(key, key), built[key], "  "
        )


def _ask_build_passphrase(plan_id: str) -> tuple[bytes | None, str]:
    """Ask the owner for the passphrase of the build.

    The passphrase is read here, in this function, and dropped as soon
    as the key of every server is derived from it.  It never reaches
    the environment, the argv, a log or a file.
    """
    prompt = (
        "approval passphrase for the AD build "
        f"{_sanitize_terminal_value(plan_id[:8])}: "
    )
    try:
        passphrase = _getpass(prompt)
    except (EOFError, KeyboardInterrupt, OSError):
        return None, "approval passphrase could not be read; approval not created"
    if not passphrase:
        return None, "approval passphrase must not be empty; approval not created"
    try:
        return passphrase.encode("utf-8"), ""
    except UnicodeEncodeError:
        return None, "approval passphrase cannot be used; approval not created"


def _build_lock_remaining(built: dict[str, Any]) -> int:
    """The longest lockout of a server of the plan, or 0.

    The build approvals honour the wrong-answer lockout of every server
    the passphrase is for, as approve_ad_change does for its one
    device, and check it before the passphrase is asked.
    """
    remaining = 0
    for server in built["servers"]:
        remaining = max(remaining, _lock_remaining(server["device"]))
    return remaining


def _build_server_keys(passphrase: bytes, built: dict[str, Any]) -> dict[str, str]:
    """The key of every server of the plan, derived from one passphrase."""
    from .ad.build import plan as _build_plan

    keys: dict[str, str] = {}
    for server in built["servers"]:
        device = server["device"]
        keys[device] = _build_plan.server_key(passphrase, device)
    return keys


def _build_dc1_key(built: dict[str, Any], keys: dict[str, str]) -> str | None:
    """The key of the forest root: the secrets of the domain are its."""
    for server in built["servers"]:
        if server["role"] == "dc1":
            return keys.get(server["device"])
    return None


def _load_build_plan_approval(plan_id: str) -> dict[str, Any]:
    """The approval of the plan of one build.

    The record is written by the approval of the plan and by nothing
    else: it is the only thing that says the owner read these bytes
    and said yes.  A record that is not there, or that cannot be
    read, is a refusal and never a skip.
    """
    try:
        record = json.loads(
            build_approval_path(plan_id).read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError, ValueError):
        raise ApprovalRefused("the plan has no approval on record") from None
    if not isinstance(record, dict):
        raise ApprovalRefused("the plan approval is not an object")
    return record


def _check_build_fingerprints(
    record: dict[str, Any], keys: dict[str, str]
) -> str | None:
    """The server whose passphrase is not the one of the plan approval.

    The plan approval holds the fingerprint of the key of every server:
    the fingerprint is the hash of the key under a constant, so it does
    not grow what a reader of the state directory can do.  A passphrase
    that does not match it would mint tokens the helpers refuse, so it
    is caught here instead.

    A record that is not there, that cannot be read, or that holds no
    fingerprint for a server, is a refusal and never a skip: a skip
    would mint a token over the key of a passphrase that may be wrong.

    The record is the one the caller already read, so the fingerprints
    and the plan tokens checked after them come from the same bytes.
    """
    fingerprints = record.get("fingerprints")
    if not isinstance(fingerprints, dict):
        raise ApprovalRefused("the plan approval holds no fingerprint")
    for device, key in keys.items():
        stored = fingerprints.get(device)
        if not isinstance(stored, str):
            raise ApprovalRefused(
                "the plan approval holds no fingerprint for "
                f"{_sanitize_terminal_value(device)}"
            )
        if not hmac.compare_digest(stored, approval_fingerprint(key)):
            return device
    return None


def _check_build_plan_tokens(
    record: dict[str, Any], keys: dict[str, str], digest: str
) -> bool:
    """Whether the plan tokens of the approval are over this plan.

    The fingerprints of the approval depend on the passphrase and the
    device, not on the plan: a record copied from an approved plan onto
    another plan, with its id and its digest swapped, carries them
    unchanged.  The plan tokens are over the digest of the plan that was
    approved, so only the key of every server over this digest and the
    window of the record gives them back.  A token that is not there,
    or a window that is not one, is a mismatch.
    """
    from .ad.build import plan as _build_plan

    tokens = record.get("tokens")
    if not isinstance(tokens, dict):
        return False
    for device, key in keys.items():
        stored = tokens.get(device)
        if not isinstance(stored, str):
            return False
        try:
            expected = _build_plan.plan_token(
                key, digest, record.get("nbf"), record.get("exp")
            )
        except (ValueError, TypeError):
            return False
        if not hmac.compare_digest(stored, expected):
            return False
    return True


def _check_setup_fingerprints(keys: dict[str, str]) -> str | None:
    """The server whose passphrase is not the one of its own setup.

    The fingerprint of a device is written by the setup of that device.
    When it is on record and it does not match, the passphrase is wrong
    and no token may be minted.  When it is not on record there is
    nothing to compare, and the helpers refuse a token of a wrong
    passphrase themselves.
    """
    for device, key in keys.items():
        status = check_approval_fingerprint(
            state_dir() / "approval-fp" / device, approval_fingerprint(key)
        )
        if status == APPROVAL_FP_MISMATCH:
            return device
    return None


def _setup_fingerprints_missing(keys: dict[str, str]) -> list[str]:
    """The servers whose setup wrote no fingerprint on record.

    A fresh build has none: the fingerprint of the setup of a server is
    written when the setup of that server runs, and the setup of a
    server of a build is the bootstrap of that server.
    """
    missing: list[str] = []
    for device, key in keys.items():
        status = check_approval_fingerprint(
            state_dir() / "approval-fp" / device, approval_fingerprint(key)
        )
        if status == APPROVAL_FP_MISSING:
            missing.append(device)
    return missing


def _restore_cost(method: str, stage: str) -> str:
    """What it costs to restore the checkpoint of a stage.

    The words are the ones of the design and of the measurements: a
    snapshot is rolled back and the VM is started again, a Proxmox
    rollback leaves the VM stopped, and a backup of a server without a
    hypervisor is a bare-metal restore or a DSRM restore.

    Without a hypervisor the stage says which backup the checkpoint
    is: the all-critical one before the stages 2 and 7, the system-state
    one before the stages 3, 4 and 6.  A system-state backup cannot
    undo a promotion, so it is never the one of the stages 2 and 7.
    """
    if method == "hyperv":
        return (
            "a snapshot rollback of the VM from the Hyper-V host "
            "(Restore-VMSnapshot) and a start of the VM again"
        )
    if method == "proxmox":
        return (
            "a snapshot rollback of the VM with the Proxmox token; the VM is "
            "left stopped and the owner starts it again"
        )
    if stage in BUILD_WBADMIN_ALL_CRITICAL_STAGES:
        return (
            "a bare-metal restore or a DSRM restore from the all-critical "
            "backup; it is not a quick rollback"
        )
    return (
        "a system-state restore of the domain controller through DSRM; it "
        "cannot undo a promotion, so the all-critical backup is the one "
        "that can"
    )


def _verify_checkpoint(
    adapter: CheckpointAdapter,
    server_cfg: Mapping[str, Any],
    checkpoint: Mapping[str, Any],
    kind: str,
    *,
    stage: str,
    not_before: int,
) -> object:
    """Ask the adapter about one checkpoint of one stage.

    The adapter is an object with a ``verify`` method or a callable
    with the same arguments; the stage goes by keyword (the maintainer,
    2026-11-13), so an adapter that cannot take it raises.  An adapter
    that raises is an adapter that cannot answer, and an adapter that
    cannot answer refuses.  The answer is returned as the adapter gave
    it: only ``True`` verifies, and a truthy answer of another type is
    never turned into a yes.
    """
    method = getattr(adapter, "verify", None)
    if callable(method):
        return method(server_cfg, checkpoint, kind, stage=stage, not_before=not_before)
    if callable(adapter):
        return adapter(server_cfg, checkpoint, kind, stage=stage, not_before=not_before)
    raise TypeError("the checkpoint adapter has no verify")


def build_plan_approve_command(plan_id: str) -> str:
    """The command the owner runs to approve the plan of a build again."""
    return f"{_launcher('newton-approve')} ad-build {plan_id}"


def _plan_approval_open(approval: Mapping[str, Any], at: datetime) -> bool:
    """True while the plan approval of a build is still open at ``at``.

    The approval is open while ``at`` is before its EXP (the maintainer,
    2026-11-13).  An EXP that is not an integer is never open.
    """
    exp = approval.get("exp")
    if not isinstance(exp, int) or isinstance(exp, bool):
        return False
    return int(at.timestamp()) < exp


def _plan_approval_expired_text(plan_id: str) -> str:
    """The refusal of a stage whose plan approval is no longer open."""
    return (
        "the plan approval has expired or holds no expiry; re-approve the "
        f"plan with {build_plan_approve_command(plan_id)}; no token was written"
    )


def _plan_approval_expired_waiting_text(stage: str) -> str:
    """The refusal of a stage whose plan approval is no longer open while
    a server waits at the stage with its checkpoint taken (F1 of tri-e1;
    DESIGN-1.5 open point 52).

    A second approval of the same plan would not get the run going: its
    NBF raises the checkpoint's ``not_before`` past the waiting
    checkpoint, every adapter refuses a checkpoint older than the bound,
    and the runner never takes a stage's checkpoint again.  Only a resume
    plan at the stage, which the owner approves, goes on.
    """
    return (
        "the plan approval has expired or holds no expiry while the run "
        f"waits at stage {stage} with its checkpoint taken; a second "
        "approval of this plan does not restart it (its NBF is later than "
        "that checkpoint, which then never verifies, and the runner does "
        "not take it again): the run goes on only through a resume plan "
        f"(resume_from this plan, start_stage {stage}) the owner approves; "
        "no token was written"
    )


def _run_waits_with_checkpoint(plan_id: str, digest: str, stage: str) -> bool:
    """True when the run state of this plan has a server waiting for the
    approval of ``stage`` with a checkpoint recorded.  Used only to word a
    refusal: a state that cannot be read, or is of another plan, is False.
    """
    try:
        state = _load_build_run_state(plan_id)
    except ApprovalRefused:
        return False
    if state.get("plan_digest") != digest:
        return False
    servers = state.get("servers")
    if not isinstance(servers, dict):
        return False
    return any(
        isinstance(entry, dict)
        and entry.get("stage") == stage
        and entry.get("state") == "stopped_for_approval"
        and isinstance(entry.get("checkpoint"), dict)
        for entry in servers.values()
    )


def approve_ad_build(plan_id: str, *, now: datetime | None = None) -> int:
    """The approval of the plan of one AD build.

    Every field of the plan is printed, the key of every server is
    derived from the one passphrase of the owner, every DC's DSRM
    password (each from that server's key) and the admin password (from
    DC1's) are shown in the terminal, and one plan token per server is
    written.  The passwords are salted with the build's first plan's
    digest (``plan.secrets_digest``), so a resume plan shows the ones the
    first plan installed (DESIGN-1.5 open points 71 and 72).

    The passphrase is asked a second time when no fingerprint of the
    setup of a server is on record: a typo of the passphrase would
    derive the wrong key, and the DSRM and the admin password would
    come from it.

    The plan token covers the read and the reversible stages of that
    server and is good for six hours.  A refusal that mirrors a refusal
    of the build helper carries the code of that helper, and nothing is
    written when the approval is refused.
    """
    from .ad.build import plan as _build_plan

    if not isinstance(plan_id, str) or PLAN_ID_RE.fullmatch(plan_id) is None:
        return _refuse_build(
            "",
            "the plan id must be 32 lowercase hexadecimal characters",
        )
    try:
        built, digest = _load_build_plan(plan_id)
    except ApprovalRefused as exc:
        return _refuse_build("", f"{exc}; approval not created")

    _print_build_plan(plan_id, built, digest)

    expected = f"approve {plan_id[:8]}"
    print(f"Type {expected!r} to approve: ", end="", flush=True)
    confirmation = sys.stdin.readline().rstrip("\r\n")
    if confirmation != expected:
        return _refuse_build(
            "",
            "the confirmation did not match; approval not created",
        )

    remaining = _build_lock_remaining(built)
    if remaining > 0:
        return _refuse_build("", _locked_text(remaining))

    passphrase, refusal = _ask_build_passphrase(plan_id)
    if refusal:
        return _refuse_build("", refusal)

    try:
        keys = _build_server_keys(passphrase, built)
    except ValueError as exc:
        del passphrase
        return _refuse_build("", f"{exc}; approval not created")

    wrong = _check_setup_fingerprints(keys)
    if wrong is not None:
        del passphrase
        return _refuse_build(
            "",
            f"{_sanitize_terminal_value(wrong)}: "
            f"{_wrong_text(_record_failure(wrong))}",
        )

    if _setup_fingerprints_missing(keys):
        again, refusal = _ask_build_passphrase(plan_id)
        if refusal:
            del passphrase
            return _refuse_build("", refusal)
        same = hmac.compare_digest(again, passphrase)
        del again
        if not same:
            del passphrase
            return _refuse_build(
                "",
                "the two passphrases are not the same; approval not created",
            )
    del passphrase

    created = datetime.now(timezone.utc) if now is None else now
    not_before = int(created.timestamp())
    not_after = not_before + BUILD_PLAN_WINDOW_S

    tokens: dict[str, str] = {}
    fingerprints: dict[str, str] = {}
    try:
        for device, key in keys.items():
            tokens[device] = _build_plan.plan_token(
                key, digest, not_before, not_after
            )
            fingerprints[device] = approval_fingerprint(key)
    except ValueError as exc:
        return _refuse_build("schema", f"{exc}; approval not created")

    dc1_key = _build_dc1_key(built, keys)
    if dc1_key is None:
        return _refuse_build(
            "schema",
            "the plan has no forest root; approval not created",
        )
    # The salt of the secrets is the build's first plan's digest
    # (DESIGN-1.5 open point 71): the plan's own for a first plan, its
    # signed secrets_from for a resume plan, as the helper derives them.
    salt = _build_plan.secrets_digest(built)
    # Every DC's DSRM password, each from that server's own K: DC1's helper
    # sets DC1's at the promotion, DC2's helper writes DC2's at the join
    # (DESIGN-1.5 "Secrets"; review finding 3 of task 8 part E).
    dsrms: list[tuple[str, str, str]] = []
    for role in ("dc1", "dc2"):
        for server in built["servers"]:
            if server["role"] == role:
                device = server["device"]
                dsrms.append(
                    (
                        device,
                        role,
                        _build_plan.derive_secret(
                            keys[device], salt, _build_plan.DSRM_INFO
                        ),
                    )
                )
    admin = _build_plan.derive_secret(dc1_key, salt, _build_plan.ADMIN_INFO)
    del keys, dc1_key

    record = {
        "plan_id": plan_id,
        "kind": "plan",
        "plan_digest": digest,
        "nbf": not_before,
        "exp": not_after,
        "created_at": created.isoformat(),
        "approved_by": os.environ.get("SUDO_USER", ""),
        "tokens": tokens,
        "fingerprints": fingerprints,
    }
    try:
        _atomic_write(build_approval_path(plan_id), record)
    except OSError as exc:
        return _refuse_build("", f"could not write approval: {exc}")
    if salt == digest:
        shown = "shown once, here and nowhere else"
    else:
        shown = "the first plan's, unchanged; here and nowhere else"
        print(
            "This plan resumes the build: the passwords are the passwords of "
            f"the build's first plan {_sanitize_terminal_value(salt[:12])}, "
            "the ones the servers keep or are given."
        )
    for device, role, dsrm in dsrms:
        print(
            f"DSRM password of {_sanitize_terminal_value(device)} ({role}) "
            f"({shown}):"
        )
        print(f"  {_sanitize_terminal_value(dsrm)}")
    print(f"Owner's first admin password ({shown}):")
    print(f"  {_sanitize_terminal_value(admin)}")
    print(f"Approved plan {plan_id} for {BUILD_PLAN_WINDOW_S // 60} minutes.")
    return 0


def _load_build_run_state(plan_id: str) -> dict[str, Any]:
    """The runner's state of one build."""
    try:
        state = json.loads(build_run_state_path(plan_id).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError):
        raise ApprovalRefused("the run has not stopped for approval") from None
    if not isinstance(state, dict):
        raise ApprovalRefused("the run state is not an object")
    return state


def approve_ad_build_stage(
    plan_id: str,
    stage: str,
    *,
    verifier: CheckpointAdapter | None = None,
    transport: Any = None,
    now: datetime | None = None,
) -> int:
    """The approval of one irreversible stage of an AD build.

    The plan is read and its approval is read before anything else:
    the approval of the plan is the only thing that says the owner
    approved these bytes, and the runner's state file is written by
    the agent and says nothing of the sort.

    The checkpoint of the stage is verified here, through the adapter
    itself: the runner's state says which checkpoint was taken, and the
    adapter says whether it may be relied on.  A stage whose checkpoint
    does not verify is refused, whatever the runner's state says.

    The checkpoint and what it costs to restore it are printed, and one
    stage token per server is written.  The token is over the digest of
    the stage, which holds the id of the verified checkpoint, and is
    good for thirty minutes.

    The plan approval must still be open (the maintainer, 2026-11-13): at or past
    its EXP the stage is refused with ``expired``.  When a server already
    waits at the stage with its checkpoint taken, the refusal names a
    resume plan at the stage (a second approval of this plan strands that
    checkpoint; open point 52); otherwise it names the plan approval.
    Stage 9 is covered by the plan token, so it
    never gets a stage token.

    The adapter is told how old the checkpoint may be: ``not_before``, the
    later of the plan approval's NBF and the previous stage's recorded
    completion on that server, which the approval reads itself from the
    helper's journal through ``transport`` (a status under the plan
    token), never from the runner's state file (DESIGN-1.5 "Checkpoints").
    A read that fails, a journal with no completion of the previous stage,
    or a time that is not a UTC second refuses the stage.
    """
    from .ad.build import plan as _build_plan
    from .ad.build import transport as _build_transport

    if not isinstance(plan_id, str) or PLAN_ID_RE.fullmatch(plan_id) is None:
        return _refuse_build(
            "",
            "the plan id must be 32 lowercase hexadecimal characters",
        )
    if not isinstance(stage, str) or stage not in _build_plan.STAGE_IDS:
        return _refuse_build(
            "schema",
            "the stage is not one of the stages of the design; no token was written",
        )
    kind = _build_plan.STAGE_KINDS[stage]
    if kind == "final":
        # The maintainer, 2026-11-13: the final stage runs under the plan approval.
        return _refuse_build(
            "schema",
            "stage 9 is the final stage and the plan token covers it; it "
            "needs no stage token; no token was written",
        )
    if kind != "irreversible":
        return _refuse_build(
            "schema",
            "the plan token covers this stage; it needs no stage token; "
            "no token was written",
        )

    try:
        built, digest = _load_build_plan(plan_id)
    except ApprovalRefused as exc:
        return _refuse_build("schema", f"{exc}; no token was written")

    try:
        approval = _load_build_plan_approval(plan_id)
    except ApprovalRefused as exc:
        return _refuse_build("plan_mismatch", f"{exc}; no token was written")

    if approval.get("kind") != "plan" or approval.get("plan_digest") != digest:
        return _refuse_build(
            "plan_mismatch",
            "the plan on record is not the plan that was approved; "
            "no token was written",
        )
    if not _plan_approval_open(
        approval, datetime.now(timezone.utc) if now is None else now
    ):
        if _run_waits_with_checkpoint(plan_id, digest, stage):
            return _refuse_build("expired", _plan_approval_expired_waiting_text(stage))
        return _refuse_build("expired", _plan_approval_expired_text(plan_id))
    fingerprints = approval.get("fingerprints")
    if not isinstance(fingerprints, dict):
        return _refuse_build(
            "plan_mismatch",
            "the plan approval holds no fingerprint; no token was written",
        )

    try:
        state = _load_build_run_state(plan_id)
    except ApprovalRefused as exc:
        return _refuse_build("schema", f"{exc}; no token was written")

    if state.get("plan_digest") != digest:
        return _refuse_build(
            "plan_mismatch",
            "the run is not running this plan; no token was written",
        )

    servers = state.get("servers")
    if not isinstance(servers, dict) or not servers:
        return _refuse_build(
            "schema",
            "the run state holds no server; no token was written",
        )

    plan_servers = {server["device"]: server for server in built["servers"]}
    waiting: list[tuple[str, dict[str, Any], dict[str, Any], str]] = []
    for device in sorted(servers):
        entry = servers[device]
        if not isinstance(entry, dict):
            return _refuse_build(
                "schema",
                "the run state of a server is not an object; no token was written",
            )
        if entry.get("stage") != stage:
            continue
        if entry.get("state") == "done":
            return _refuse_build(
                "already_done",
                "the stage is done; no token was written",
            )
        if entry.get("state") != "stopped_for_approval":
            return _refuse_build(
                "schema",
                "the run is not waiting for the approval of this stage; "
                "no token was written",
            )
        server = plan_servers.get(device)
        if server is None:
            return _refuse_build(
                "schema",
                "the run state holds a server the plan does not have; "
                "no token was written",
            )
        if not isinstance(fingerprints.get(device), str):
            return _refuse_build(
                "plan_mismatch",
                "the plan approval holds no fingerprint for "
                f"{_sanitize_terminal_value(device)}; no token was written",
            )
        if stage not in _build_plan.stage_graph(built, server):
            return _refuse_build(
                "schema",
                "the stage is not in the graph of the server; no token was written",
            )
        checkpoint = entry.get("checkpoint")
        if not isinstance(checkpoint, dict):
            return _refuse_build(
                "schema",
                "the run state holds no checkpoint; no token was written",
            )
        checkpoint_id = checkpoint.get("id")
        if (
            not isinstance(checkpoint_id, str)
            or _build_plan.CHECKPOINT_ID_RE.fullmatch(checkpoint_id) is None
        ):
            return _refuse_build(
                "schema",
                "the checkpoint of the stage holds no id of the design; "
                "no token was written",
            )
        checkpoint_name = checkpoint.get("name")
        if not isinstance(checkpoint_name, str) or not checkpoint_name:
            return _refuse_build(
                "schema",
                "the checkpoint of the stage holds no name; no token was written",
            )
        checkpoint_kind = entry.get("checkpoint_kind")
        if checkpoint_kind not in BUILD_CHECKPOINT_KINDS:
            return _refuse_build(
                "schema",
                "the run state holds no kind of checkpoint; no token was written",
            )
        expected_kind = BUILD_CHECKPOINT_OF_STAGE.get((server["role"], stage))
        if expected_kind is None or checkpoint_kind != expected_kind:
            return _refuse_build(
                "schema",
                "the checkpoint of the stage is not the kind the design gives it; "
                "no token was written",
            )
        waiting.append(
            (
                device,
                server,
                {"name": checkpoint_name, "id": checkpoint_id},
                checkpoint_kind,
            )
        )

    if not waiting:
        return _refuse_build(
            "schema",
            "no server waits for the approval of this stage; no token was written",
        )

    run_id = state.get("run", plan_id)
    if not isinstance(run_id, str) or PLAN_ID_RE.fullmatch(run_id) is None:
        return _refuse_build(
            "schema",
            "the run state holds no run id; no token was written",
        )
    plan_tokens = approval.get("tokens")
    for device, server, checkpoint, checkpoint_kind in waiting:
        if verifier is None:
            return _refuse_build(
                "checkpoint_unverified",
                "there is no checkpoint adapter; the checkpoint could not be "
                "verified; no token was written",
            )
        if transport is None:
            return _refuse_build(
                "checkpoint_unverified",
                "there is no helper transport; the journal that bounds the "
                "checkpoint could not be read; no token was written",
            )
        plan_token = plan_tokens.get(device) if isinstance(plan_tokens, dict) else None
        try:
            completed = _build_transport.read_completions(
                transport,
                device,
                run=run_id,
                plan_bytes=_build_plan.canonical_bytes(built),
                token=plan_token if isinstance(plan_token, str) else "",
                nbf=approval.get("nbf"),  # type: ignore[arg-type]
                exp=approval.get("exp"),  # type: ignore[arg-type]
            )
            not_before = _build_transport.journal_not_before(
                completed,
                graph=_build_plan.stage_graph(built, server),
                stage=stage,
                plan_nbf=approval.get("nbf"),  # type: ignore[arg-type]
            )
        except (_build_transport.JournalUnreadable, ValueError) as exc:
            return _refuse_build(
                "checkpoint_unverified",
                "the journal of "
                f"{_sanitize_terminal_value(device)} gave no bound for the "
                f"checkpoint ({_sanitize_terminal_value(str(exc))}); "
                "no token was written",
            )
        # The DC reads of the real adapters go through this server's
        # helper, under its plan token, for this stage (PLAN-1.5 task 8
        # part B0); a verifier that reads through no helper has nothing
        # to open.
        open_reads = getattr(verifier, "open_reads", None)
        close_reads = getattr(verifier, "close_reads", None)
        try:
            if callable(open_reads):
                open_reads(
                    device,
                    run=run_id,
                    plan_bytes=_build_plan.canonical_bytes(built),
                    token=plan_token if isinstance(plan_token, str) else "",
                    nbf=approval.get("nbf"),
                    exp=approval.get("exp"),
                    stage=stage,
                )
            verified = _verify_checkpoint(
                verifier,
                server,
                checkpoint,
                checkpoint_kind,
                stage=stage,
                not_before=not_before,
            )
        except Exception as exc:
            return _refuse_build(
                "checkpoint_unverified",
                "the checkpoint of "
                f"{_sanitize_terminal_value(device)} could not be verified "
                f"({_sanitize_terminal_value(type(exc).__name__)}); "
                "no token was written",
            )
        finally:
            if callable(close_reads):
                close_reads(device)
        if verified is not True:
            return _refuse_build(
                "checkpoint_unverified",
                "the checkpoint of "
                f"{_sanitize_terminal_value(device)} did not verify; "
                "no token was written",
            )

    print(f"Plan: {_sanitize_terminal_value(plan_id)}")
    print(f"Digest: {_sanitize_terminal_value(digest[:12])}")
    print(f"Stage: {_sanitize_terminal_value(stage)} ({_sanitize_terminal_value(kind)})")
    for device, server, checkpoint, checkpoint_kind in waiting:
        print(f"Server {device} ({server['role']}):")
        print(f"  Checkpoint method: {_sanitize_terminal_value(server['checkpoint'])}")
        print(
            "  Checkpoint: "
            f"{_sanitize_terminal_value(checkpoint['name'])} "
            f"({_sanitize_terminal_value(checkpoint['id'])})"
        )
        print(f"  Checkpoint kind: {_sanitize_terminal_value(checkpoint_kind)}")
        print(
            "  Restore cost: "
            f"{_restore_cost(server['checkpoint'], stage)}"
        )

    print(
        RECOVERY_PREFIX
        + "the stage stops where it is and nothing is put back by itself; "
        + "a resume needs a new plan you approve, and the checkpoint above "
        + "is the way back"
    )

    expected = f"approve stage {stage} of {plan_id[:8]}"
    print(f"Type {expected!r} to approve: ", end="", flush=True)
    confirmation = sys.stdin.readline().rstrip("\r\n")
    if confirmation != expected:
        return _refuse_build(
            "",
            "the confirmation did not match; approval not created",
        )

    remaining = _build_lock_remaining(built)
    if remaining > 0:
        return _refuse_build("", _locked_text(remaining))

    passphrase, refusal = _ask_build_passphrase(plan_id)
    if refusal:
        return _refuse_build("", refusal)

    try:
        keys = _build_server_keys(passphrase, built)
    except ValueError as exc:
        del passphrase
        return _refuse_build("", f"{exc}; approval not created")
    del passphrase

    try:
        wrong = _check_build_fingerprints(approval, keys)
    except ApprovalRefused as exc:
        return _refuse_build("", f"{exc}; approval not created")
    if wrong is not None:
        return _refuse_build(
            "",
            f"{_sanitize_terminal_value(wrong)}: "
            f"{_wrong_text(_record_failure(wrong))}",
        )
    if not _check_build_plan_tokens(approval, keys, digest):
        return _refuse_build(
            "plan_mismatch",
            "the plan approval was not minted for this plan; "
            "no token was written",
        )

    created = datetime.now(timezone.utc) if now is None else now
    if not _plan_approval_open(approval, created):
        # The owner may have taken the plan approval past its EXP at the
        # prompts; the check is made again on the clock of the token.
        return _refuse_build("expired", _plan_approval_expired_text(plan_id))
    not_before = int(created.timestamp())
    not_after = not_before + BUILD_STAGE_WINDOW_S

    entries: dict[str, Any] = {}
    for device, server, checkpoint, checkpoint_kind in waiting:
        key = keys.get(device)
        if key is None:
            return _refuse_build(
                "schema",
                "the plan has no server of the run; no token was written",
            )
        try:
            stage_digest = _build_plan.stage_digest(
                digest, stage, checkpoint["id"]
            )
        except _build_plan.BuildPlanRefused:
            return _refuse_build(
                "schema",
                "the id of the checkpoint is outside its grammar; "
                "no token was written",
            )
        try:
            token = _build_plan.plan_token(key, stage_digest, not_before, not_after)
        except ValueError as exc:
            return _refuse_build(
                "schema",
                f"{exc}; no token was written",
            )
        entries[device] = {
            "token": token,
            "stage_digest": stage_digest,
            "checkpoint": {
                "name": checkpoint["name"],
                "id": checkpoint["id"],
            },
            "checkpoint_kind": checkpoint_kind,
        }
    del keys

    record = {
        "plan_id": plan_id,
        "kind": "stage",
        "stage": stage,
        "plan_digest": digest,
        "nbf": not_before,
        "exp": not_after,
        "created_at": created.isoformat(),
        "approved_by": os.environ.get("SUDO_USER", ""),
        "servers": entries,
    }
    try:
        _atomic_write(build_stage_approval_path(plan_id, stage), record)
    except OSError as exc:
        return _refuse_build("", f"could not write approval: {exc}")
    print(
        f"Approved stage {stage} of plan {plan_id} for "
        f"{BUILD_STAGE_WINDOW_S // 60} minutes."
    )
    return 0


def _main_ad_build(args: list[str]) -> int:
    """``newton-approve ad-build <plan-id>``: the approval of a build plan."""
    if len(args) != 2:
        print("usage: newton-approve ad-build <32-hex-plan-id>", file=sys.stderr)
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
    return approve_ad_build(plan_id)


def build_stage_approve_command(plan_id: str, stage: str) -> str:
    """The command the owner runs to approve one stage of a build."""
    return f"{_launcher('newton-approve')} ad-build-stage {plan_id} {stage}"


def _main_ad_build_stage(args: list[str]) -> int:
    """``newton-approve ad-build-stage <plan-id> <stage>``: the approval of
    one irreversible stage.  The checkpoint adapters and the helper
    transport come from the owner's build config (``ad-build.toml`` in
    Newton's config directory), never from the runner."""
    if len(args) != 3:
        print(
            "usage: newton-approve ad-build-stage <32-hex-plan-id> <stage>",
            file=sys.stderr,
        )
        return 2
    plan_id, stage = args[1], args[2]
    if not PLAN_ID_RE.fullmatch(plan_id):
        print(
            "newton-approve: plan id must be 32 lowercase hexadecimal characters",
            file=sys.stderr,
        )
        return 2
    if _BUILD_STAGE_FILE_RE.fullmatch(stage) is None:
        print("newton-approve: the stage must be a stage of the design", file=sys.stderr)
        return 2
    if not sys.stdin.isatty():
        print("newton-approve: stdin must be an interactive terminal", file=sys.stderr)
        return 1
    from .ad.build import config as _build_config

    try:
        loaded = _build_config.load_config()
    except _build_config.BuildConfigError as exc:
        return _refuse_build(
            "checkpoint_unverified",
            f"{exc} ({_sanitize_terminal_value(str(_build_config.config_path()))}); "
            "no token was written",
        )
    build_transport = _build_config.build_transport(loaded)
    return approve_ad_build_stage(
        plan_id,
        stage,
        verifier=_build_config.build_adapters(loaded, transport=build_transport),
        transport=build_transport,
    )


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
        if not (state_dir() / "ad-plans" / f"{plan_id}.json").exists() and (
            (state_dir() / "plans" / f"{plan_id}.json").exists()
            or _scans.request_path(state_dir(), plan_id).exists()
        ):
            # The reverse of the hint below: a router plan or a scan
            # request is approved without the ad-change word.
            print(
                "newton-approve: this is not an Active Directory plan but a "
                "router plan or a scan request; approve it without the "
                f"ad-change word: {_launcher('newton-approve')} {plan_id}",
                file=sys.stderr,
            )
            return 2
        ok, refusal = approve_ad_change(plan_id)
        if not ok:
            print(f"newton-approve: {refusal}", file=sys.stderr)
            return 1
        return 0
    if args and args[0] == "ad-build":
        return _main_ad_build(args)
    if args and args[0] == "ad-build-stage":
        return _main_ad_build_stage(args)
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
        if _scans.request_path(state_dir(), plan_id).exists():
            return _approve_scan(plan_id)
        if (state_dir() / "ad-plans" / f"{plan_id}.json").exists():
            print(
                "newton-approve: this is an Active Directory plan; approve it "
                f"with the ad-change word: {_launcher('newton-approve')} ad-change {plan_id}",
                file=sys.stderr,
            )
            return 2
        print(
            "newton-approve: no plan or scan request with this id; it was "
            "mistyped, or the plan was dropped: plan the change again",
            file=sys.stderr,
        )
        return 1
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


if __name__ == "__main__":
    raise SystemExit(main())
