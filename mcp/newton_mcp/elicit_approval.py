"""Collect an owner's approval through an MCP elicitation dialog.

The agent never receives an approval input: the only proof that counts is
the answer the owner enters in the client.  The dialog therefore writes the
same approval record as ``newton-approve`` and leaves the agent out of the
proof path entirely.
"""

from __future__ import annotations

import asyncio
import hmac
import math
import os
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal

from mcp.server.fastmcp import Context
from pydantic import BaseModel, Field, create_model

from . import approval_proof
from . import approve
from . import change_classes
from . import grants
from . import owner_records
from . import plan as _plan


OutcomeStatus = Literal["skip", "approved", "fallback", "declined", "wrong", "locked"]
MIN_DWELL_S = approval_proof.MIN_DWELL_S

# How long the dialog waits for an answer.  The dialog is drawn by the
# client, and a client that cannot draw it never answers: without a
# bound the call would wait for ever and the session would look hung.
# 180 s leaves the owner time to read the plan and type the passphrase:
# at 60 s the owner's first live answer arrived after the wait.
ELICIT_TIMEOUT_S = 180.0

# The passphrase field of the dialog shows what is typed.  The owner is
# told to clear the screen, because the passphrase may be on it for
# anyone who can see that screen.  The notice names no product: the
# client may be anything.
CLEAR_NOTICE = (
    "Your passphrase was visible as you typed it. If others can see this "
    "screen, clear it: `clear && printf '\\e[3J'` or your terminal's "
    "Clear Buffer."
)

GRANT_HOURS_FIELD_TITLE = (
    "Also allow more changes of this kind for how many hours? (0 = no)"
)
#: The lengths the dialog offers, as the strings the form returns.  The SDK
#: takes only plain str for a form field, so the choice is shown to the
#: client as a JSON-schema enum and checked again where the answer is read.
GRANT_HOURS_CHOICES = ("0", "1", "4", "8")
GRANT_USED_PREFIX = "EASY GRANT"
GRANT_OPENED_PREFIX = "EASY GRANT OPENED"

#: The leash and the profile of a no-install auto plan.
NO_INSTALL_LEASH = "rpcd"
NO_INSTALL_PROFILE = "no-install"

_HIGH_REASON_PHRASES = {
    change_classes.REASON_INTERNET_EXPOSURE: (
        "Exposes something to the internet."
    ),
    change_classes.REASON_MANAGEMENT_ACCESS: (
        "Changes who can manage the router."
    ),
    change_classes.REASON_RUNS_COMMANDS: (
        "Makes the router run commands."
    ),
}
_POLICY_CRITICAL_REASON = "Newton's policy marks this change as critical."


@dataclass(frozen=True)
class Outcome:
    """The result of trying to collect approval in the client."""

    status: OutcomeStatus
    message: str
    notice: str = ""
    grant_used: bool = False
    grant_note: str = ""


def _elicit_timeout_s() -> float:
    """How long the dialog waits for an answer, in seconds.

    The environment variable is read at every call, so a deployment can
    set it and a test can make it small.  Only a positive number is a
    timeout; anything else (a typo, an empty value, a number that is not
    finite) falls back to :data:`ELICIT_TIMEOUT_S`.
    """
    raw = os.environ.get("NEWTON_ELICIT_TIMEOUT_S")
    if raw is None:
        return ELICIT_TIMEOUT_S
    try:
        value = float(raw.strip())
    except ValueError:
        return ELICIT_TIMEOUT_S
    if not math.isfinite(value) or value <= 0:
        return ELICIT_TIMEOUT_S
    return value


def _terminal_hint(session_id: str) -> str:
    return f"sudo -u newton /usr/local/bin/newton-approve {session_id}"


def _with_hint(message: str, session_id: str) -> str:
    safe = approve._sanitize_terminal_value(message).strip()
    return f"{safe}; approve in your terminal: {_terminal_hint(session_id)}"


def _skip(session_id: str) -> Outcome:
    if approve.PLAN_ID_RE.fullmatch(session_id):
        return Outcome("skip", _terminal_hint(session_id))
    return Outcome("skip", "approval dialog skipped")


def _fallback(message: str, session_id: str) -> Outcome:
    return Outcome("fallback", _with_hint(message, session_id))


def _declined(message: str, session_id: str) -> Outcome:
    return Outcome("declined", _with_hint(message, session_id))


def _wrong(device_name: str, remaining: int, session_id: str) -> Outcome:
    if remaining > 0:
        minutes = max(1, math.ceil(remaining / 60))
        message = f"wrong approval answer; try again in {minutes} min"
    else:
        record, unreadable = approval_proof._load_lockout(device_name)
        attempts = 0
        if record is not None and not unreadable:
            attempts = max(
                0,
                approval_proof.LOCK_FREE_MISSES - int(record.get("misses", 0)),
            )
        message = f"wrong approval answer; {attempts} attempts remain"
    return Outcome("wrong", _with_hint(message, session_id))


def _locked(remaining: int, session_id: str) -> Outcome:
    minutes = max(1, math.ceil(remaining / 60))
    message = (
        f"too many wrong answers; try again in {minutes} min or approve in your terminal"
    )
    safe = approve._sanitize_terminal_value(message).strip()
    return Outcome("locked", f"{safe}; {_terminal_hint(session_id)}")


def _approval_exists(session_id: str) -> bool:
    directory = approve.state_dir() / "approvals"
    return any(
        os.path.lexists(directory / f"{session_id}{suffix}")
        for suffix in (".json", ".claimed", ".used")
    )


def _load_plan(session_id: str) -> dict[str, Any] | None:
    """The stored plan record of *session_id*, or ``None``.

    ``approve._load_plan`` is the one that knows what a plan record must
    look like: it checks the plan hash and the session id, so a record
    whose body was edited after it was written reads as no plan at all.
    The dialog must not show a plan the approval token cannot bind.
    """
    if not approve.PLAN_ID_RE.fullmatch(session_id):
        return None
    try:
        return approve._load_plan(session_id)
    except ValueError:
        return None


def _client_can_elicit(ctx: Context) -> bool:
    try:
        params = ctx.session.client_params
        elicitation = params.capabilities.elicitation
    except (AttributeError, TypeError):
        return False
    if elicitation is None:
        return False
    try:
        form = elicitation.form
        url = elicitation.url
    except (AttributeError, TypeError):
        return False
    return form is not None or url is None


def _approval_model(level: str, offer_grant: bool = False) -> type[BaseModel]:
    title = "Approval passphrase" if level == approval_proof.LEVEL_PASSPHRASE else "6-digit code"
    secret_fields: dict[str, Any] = {
        "secret": (str, Field(title=title)),
    }
    if offer_grant:
        secret_fields["grant_hours"] = (
            str,
            Field(
                default="0",
                title=GRANT_HOURS_FIELD_TITLE,
                json_schema_extra={"enum": list(GRANT_HOURS_CHOICES)},
            ),
        )
    return create_model("ApprovalSecret", **secret_fields)


def _high_confirmation_model(device_name: str) -> type[BaseModel]:
    return create_model(
        "HighRiskConfirmation",
        confirm=(
            str,
            Field(title=f"Type the words: {device_name} HIGH (not your passphrase)"),
        ),
    )


def _class_labels(classes: frozenset[str]) -> str:
    return ", ".join(
        change_classes.CLASS_LABELS[name] for name in sorted(classes)
    )


def _local_time(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp).astimezone().strftime("%H:%M")


def _grant_note(
    prefix: str, classes: frozenset[str], until: float
) -> str:
    return f"{prefix}: {_class_labels(classes)} until {_local_time(until)}"


def _high_reason_lines(
    classification: change_classes.Classification,
) -> list[str]:
    lines = [
        _HIGH_REASON_PHRASES[reason]
        for reason in classification.high_reasons
        if reason in _HIGH_REASON_PHRASES
    ]
    return lines or [_POLICY_CRITICAL_REASON]


def _grant_dialog_text(
    device_name: str, classes: frozenset[str]
) -> list[str]:
    safe_device = approve._sanitize_terminal_value(device_name)
    return [
        "EASY GRANT",
        f"You can let Newton make more changes of exactly these kinds on {safe_device} "
        f"without asking again until the chosen time: {_class_labels(classes)}.",
        "It never covers firewall exposure, admin access or commands.",
        "Any failed change ends this grant.",
    ]


#: The most characters the approval dialog may carry.  A script that
#: does not fit is not shortened: the owner must see the whole script
#: or approve it in the terminal.
OWNER_SCRIPT_MESSAGE_CAP = 8000


def _dialog_text(
    device_name: str,
    session_id: str,
    plan: dict[str, Any],
    explanation: dict[str, Any],
    router_digest: str,
    first_time: bool,
    level: str,
    classification: change_classes.Classification,
    high: bool,
) -> str:
    from . import consequences

    safe_device = approve._sanitize_terminal_value(device_name)
    banner = (
        f"NEWTON  HIGH RISK  APPROVAL  {safe_device}  plan {session_id[:8]}"
        if high
        else f"NEWTON  APPROVAL  {safe_device}  plan {session_id[:8]}"
    )
    rendered = approve.render_plan_text(
        session_id,
        plan,
        explanation,
        router_digest,
    ).rstrip()
    uci_batch = str(plan["uci_batch"])
    parts = [
        banner,
        "WHAT THIS DOES",
        *consequences.describe(uci_batch),
        *consequences.alternatives(uci_batch),
        rendered,
    ]
    if high:
        parts.extend(["WHY THIS IS HIGH RISK", *_high_reason_lines(classification)])
    elif classification.grantable:
        parts.extend(_grant_dialog_text(device_name, classification.classes))
    if first_time:
        parts.append(
            "FIRST APPROVAL ON THIS DEVICE\n"
            "Newton will change this live router.\n"
            "Every change auto-undoes unless confirmed.\n"
            "Only you can approve.\n"
            "The agent can be wrong."
        )
    if level == approval_proof.LEVEL_PASSPHRASE:
        parts.append("Enter your approval passphrase")
    else:
        parts.append("Enter the 6-digit code from your authenticator app")
    message = "\n".join(parts)
    if owner_records.is_owner_record(plan):
        if len(message) > OWNER_SCRIPT_MESSAGE_CAP:
            raise approve.ApprovalRefused(
                "the script of this plan does not fit in the approval dialog; "
                f"approve and run this one with `newton-router-setup "
                f"{safe_device} owner-run {session_id}`"
            )
    return message


def _types_of_record(plan: dict[str, Any]) -> dict[tuple[str, str], str] | None:
    """The types of the sections a no-install record touches.

    The class of a change of a section the router already holds needs
    the type the router holds, and a no-install plan carries those
    types.  They are used ONLY when the record is a no-install auto
    plan whose router digest verifies: the digest binds the types to
    the ops, the base hash and the risk of the record, so a record
    whose types were edited on disk does not verify and its types are
    not used.

    An installed record carries no such types: it classifies without
    them, exactly as it always did.
    """
    if plan.get("router_leash") != NO_INSTALL_LEASH:
        return None
    if plan.get("router_profile") != NO_INSTALL_PROFILE:
        return None
    stored = plan.get("router_digest")
    if not isinstance(stored, str) or not stored:
        return None
    try:
        actual = _plan.router_digest(plan)
    except (TypeError, ValueError):
        return None
    if not hmac.compare_digest(stored, actual):
        return None
    return change_classes.types_of_record(plan)


async def collect_approval(
    ctx: Context,
    device_name: str,
    session_id: str,
) -> Outcome:
    """Collect and verify owner approval without exposing it to the agent."""
    if os.environ.get("NEWTON_ELICIT_APPROVAL") == "0":
        return _skip(session_id)

    plan = _load_plan(session_id)
    if plan is None:
        return _skip(session_id)
    if plan.get("device") != device_name:
        return _skip(session_id)
    if plan.get("requires_approval") is not True:
        return _skip(session_id)
    if owner_records.is_owner_record(plan):
        # An owner script is the owner's own bytes: the owner is asked
        # for it at the owner-run, in their own terminal, where the
        # exact bytes are shown.  A grant covers what Newton applies
        # itself, never an owner script, and an approval written here
        # would skip that question.
        return _skip(session_id)
    if _approval_exists(session_id):
        return _skip(session_id)

    try:
        explanation, router_digest = approve.validate_plan_for_approval(plan)
    except approve.ApprovalRefused as exc:
        return _fallback(str(exc), session_id)

    # the types the router holds for the sections the change touches:
    # the class of a change of a section the router already holds needs
    # them, and the grant is decided from that class.  Only a no-install
    # record whose router digest verifies carries them: an installed
    # record has no such types, and a record whose digest does not
    # verify is a record that was edited.
    classification = change_classes.classify(
        str(plan.get("uci_batch", "")),
        types=_types_of_record(plan),
    )
    high = (
        classification.high
        or plan.get("risk") == "critical"
        or owner_records.is_owner_record(plan)
    )
    grant_key: str | None = None
    if os.environ.get("NEWTON_EASY_GRANTS") != "0" and not high:
        grant_key = grants.covers(device_name, classification)
    if grant_key is not None:
        if _approval_exists(session_id):
            return _skip(session_id)
        approved_by = "grant:" + ",".join(sorted(classification.classes))
        record = grants.load_live_grant(device_name)
        if record is None:
            return _fallback("the easy grant ended before approval", session_id)
        # The record read now must be the one that granted coverage: a
        # grant replaced or narrowed in between (another server process)
        # must not lend its predecessor's key.
        if record["k"] != grant_key or not set(classification.classes) <= set(
            record["classes"]
        ):
            return _fallback("the easy grant changed before approval", session_id)
        # A key from before a passphrase change would only be refused by
        # the router; the grant it came from is over.
        if approval_proof.key_is_stale(device_name, grant_key):
            grants.revoke_grant(device_name)
            return _fallback(
                "the easy grant was opened with an older approval passphrase "
                "and has ended",
                session_id,
            )
        try:
            approval = approve.mint_approval(
                session_id,
                plan,
                router_digest,
                grant_key,
                approved_by=approved_by,
            )
        except approve.ApprovalRefused as exc:
            return _fallback(str(exc), session_id)
        except Exception:
            return _fallback("the approval record could not be created", session_id)
        try:
            approve.write_approval(session_id, approval)
        except OSError:
            return _fallback("the approval record could not be written", session_id)
        grant_note = _grant_note(
            GRANT_USED_PREFIX, classification.classes, float(record["until"])
        )
        return Outcome(
            "approved",
            "approved by your easy grant",
            grant_used=True,
            grant_note=grant_note,
        )
    if plan.get("consent_basis") == "grant":
        return Outcome(
            "fallback",
            "The easy grant for this kind of change has ended. "
            "Plan the change again and ask the owner first.",
        )

    if not _client_can_elicit(ctx):
        return _fallback("this client cannot show an approval dialog", session_id)

    try:
        with approval_proof.device_dialog_lock(device_name):
            return await _collect_locked(
                ctx,
                device_name,
                session_id,
                plan,
                explanation,
                router_digest,
                classification,
                high,
            )
    except approval_proof.DialogBusy:
        return _fallback(
            "another approval dialog is already open for this device",
            session_id,
        )
    except (OSError, ValueError):
        return _fallback("the approval dialog could not be opened", session_id)


async def _confirm_high(
    ctx: Context,
    device_name: str,
    session_id: str,
    classification: change_classes.Classification,
) -> Outcome | None:
    """Ask the required second confirmation, or return why it was refused."""
    safe_device = approve._sanitize_terminal_value(device_name)
    message = "\n".join(
        [
            "NEWTON  HIGH RISK  SECOND CONFIRMATION",
            "This is a second question, not a password prompt.",
            "Do not type your passphrase or an authenticator code here.",
            "WHY THIS IS HIGH RISK",
            *_high_reason_lines(classification),
            f"Type the words: {safe_device} HIGH",
        ]
    )
    model = _high_confirmation_model(safe_device)
    timeout_s = _elicit_timeout_s()
    try:
        started = time.monotonic()
        result = await asyncio.wait_for(
            ctx.elicit(message=message, schema=model),
            timeout=timeout_s,
        )
        action = result.action
    except asyncio.TimeoutError:
        return _declined(
            f"second confirmation timed out after {timeout_s:g} seconds; "
            "nothing approved. An answer typed after that is ignored, even "
            "if the dialog is still on the screen",
            session_id,
        )
    except Exception:
        return _declined(
            "second confirmation not given; nothing approved", session_id
        )
    if action != "accept":
        return _declined(
            "second confirmation not given; nothing approved", session_id
        )
    if not approval_proof.dwell_ok(time.monotonic() - started):
        return _declined(
            "second confirmation not given; nothing approved", session_id
        )
    try:
        confirmation = result.data.confirm
    except (AttributeError, TypeError):
        return _declined(
            "second confirmation not given; nothing approved", session_id
        )
    if confirmation != f"{safe_device} HIGH":
        return _declined(
            "second confirmation not given; nothing approved", session_id
        )
    return None


async def _collect_locked(
    ctx: Context,
    device_name: str,
    session_id: str,
    plan: dict[str, Any],
    explanation: dict[str, Any],
    router_digest: str,
    classification: change_classes.Classification,
    high: bool,
) -> Outcome:
    """The approval itself, run with the device's dialog lock held.

    The lock is held from the lock check to the write of the approval
    record.  Two concurrent calls for one device must not both open a
    dialog: the second one would be a second guess at the passphrase,
    taken before the first failure was counted.
    """
    if _approval_exists(session_id):
        # Another call for this plan wrote the approval while this one
        # was on its way here: there is nothing left to ask.
        return _skip(session_id)

    remaining = approval_proof.lock_remaining(device_name)
    if remaining > 0:
        return _locked(remaining, session_id)

    level = approval_proof.get_level(device_name)
    notice = CLEAR_NOTICE if level == approval_proof.LEVEL_PASSPHRASE else ""
    if level == approval_proof.LEVEL_PASSPHRASE:
        fingerprint = approve.state_dir() / "approval-fp" / device_name
        if not fingerprint.exists():
            safe_device = approve._sanitize_terminal_value(device_name)
            return _fallback(
                f"no approval fingerprint on record for {safe_device}; "
                f"run newton-router-setup {safe_device} approval-key",
                session_id,
            )
    elif approval_proof.load_totp(device_name) is None:
        safe_device = approve._sanitize_terminal_value(device_name)
        return _fallback(
            f"no TOTP approval key on record for {safe_device}; "
            f"run newton-router-setup {safe_device} approval-key",
            session_id,
        )

    first_time = not approval_proof.has_ack(device_name)
    offer_grant = classification.grantable and not high
    model = _approval_model(level, offer_grant)
    try:
        message = _dialog_text(
            device_name,
            session_id,
            plan,
            explanation,
            router_digest,
            first_time,
            level,
            classification,
            high,
        )
    except approve.ApprovalRefused as exc:
        return _fallback(str(exc), session_id)
    except Exception:
        return _fallback("the approval plan could not be shown", session_id)

    timeout_s = _elicit_timeout_s()
    try:
        started = time.monotonic()
        result = await asyncio.wait_for(
            ctx.elicit(message=message, schema=model),
            timeout=timeout_s,
        )
        action = result.action
    except asyncio.TimeoutError:
        # Nobody answered.  This is not a wrong answer, so no failure is
        # counted: the owner did not get a chance to answer at all.  The
        # lock is released by the context manager that took it.
        # The client may keep the dialog on the screen after this, and an
        # answer typed there goes nowhere; the message says so.
        return Outcome(
            "fallback",
            f"The approval dialog timed out after {timeout_s:g} seconds; "
            "nothing was approved. An answer typed after that is ignored, "
            "even if the dialog is still on the screen. Ask for the change "
            f"again, or run {_terminal_hint(session_id)} in your terminal.",
        )
    except Exception:
        return _fallback("the client could not show an approval dialog", session_id)

    elapsed = time.monotonic() - started
    if action != "accept":
        if elapsed < MIN_DWELL_S:
            return _fallback(
                "the client answered at once without showing a dialog",
                session_id,
            )
        return _declined("you declined", session_id)

    if not approval_proof.dwell_ok(elapsed):
        try:
            approval_proof.record_failure(device_name)
        except Exception:
            return _fallback("the failed approval could not be recorded", session_id)
        return _fallback(
            "answer came back too fast to be a person",
            session_id,
        )

    try:
        data = result.data
        secret = data.secret
    except (AttributeError, TypeError):
        return _fallback("the client returned no approval answer", session_id)

    try:
        if level == approval_proof.LEVEL_PASSPHRASE:
            status, key = approval_proof.verify_passphrase(device_name, secret)
            if status == approval_proof.PASS_NO_FINGERPRINT:
                return _fallback(
                    "no approval fingerprint on record for "
                    f"{approve._sanitize_terminal_value(device_name)}; "
                    "run newton-router-setup "
                    f"{approve._sanitize_terminal_value(device_name)} approval-key",
                    session_id,
                )
            if status != approval_proof.PASS_OK or key is None:
                remaining = approval_proof.record_failure(device_name)
                return _wrong(device_name, remaining, session_id)
        else:
            key = approval_proof.verify_totp(device_name, secret)
            if key is None:
                remaining = approval_proof.record_failure(device_name)
                return _wrong(device_name, remaining, session_id)
            if approval_proof.key_is_stale(device_name, key):
                del key
                return _fallback(
                    "the authenticator app was set up with an older approval "
                    "passphrase; set it up again with sudo -u newton "
                    "/usr/local/bin/newton-enrol totp "
                    f"{approve._sanitize_terminal_value(device_name)}",
                    session_id,
                )
    except Exception:
        return _fallback("the approval answer could not be checked", session_id)

    if high:
        second = await _confirm_high(
            ctx, device_name, session_id, classification
        )
        if second is not None:
            return second

    grant_note = ""
    grant_hours = getattr(data, "grant_hours", "0")
    if grant_hours not in GRANT_HOURS_CHOICES:
        del key
        return _fallback("the grant length could not be checked", session_id)
    if not high and grant_hours != "0":
        try:
            # The grant record stores K until it ends so a plan inside the
            # grant can mint the same approval token without the secret.
            grants.open_grant(
                device_name,
                classification.classes,
                int(grant_hours),
                key,
                session_id,
            )
        except (OSError, ValueError):
            return _fallback("the easy grant could not be opened", session_id)
        record = grants.load_live_grant(device_name)
        if record is None:
            return _fallback("the easy grant could not be opened", session_id)
        grant_note = _grant_note(
            GRANT_OPENED_PREFIX, classification.classes, float(record["until"])
        )

    try:
        approval_proof.record_success(device_name)
    except Exception:
        del key
        return _fallback("the successful approval could not be recorded", session_id)

    try:
        approval = approve.mint_approval(
            session_id,
            plan,
            router_digest,
            key,
            approved_by=f"elicit:{level}",
        )
    except approve.ApprovalRefused as exc:
        del key
        return _fallback(str(exc), session_id)
    except Exception:
        del key
        return _fallback("the approval record could not be created", session_id)

    del key
    try:
        approve.write_approval(session_id, approval)
    except OSError:
        return _fallback("the approval record could not be written", session_id)

    if first_time:
        try:
            # The acknowledgement of the first-approval warning is
            # stored here and nowhere else, after a successful approval
            # (ADR-019 item 4).  The repetition is the protection: a
            # failed answer -- a typo, or one forged by the agent,
            # which knows the public device name -- must not silence
            # the warning, or the owner would approve without ever
            # seeing it.
            approval_proof.write_ack(device_name)
        except Exception:
            # The approval is on disk and valid; only the record of the
            # owner's first-approval acknowledgement is missing, so the
            # warning is shown again next time.  Saying the approval
            # failed would be a lie: it did not.
            return Outcome(
                "approved",
                "approved, but the first-approval acknowledgement could not be saved",
                notice=notice,
                grant_note=grant_note,
            )

    return Outcome(
        "approved",
        "approved in the client dialog",
        notice=notice,
        grant_note=grant_note,
    )
