"""The AD change apply, status and abort (DESIGN-1.4 section 1).

The apply sends the request of the plan to the domain controller of the
domain, and then reads the target back from **every** DC of the domain
that has a write entry in the inventory, over a fresh session.  The
confirm is sent only when each of those DCs shows the after-image.  A DC
of the domain without a write entry is never read: Newton does not list
the DCs of the directory itself.  A DC that has not caught up within the window is NOT
TESTED, and the abort goes out instead of the confirm: the DC puts the
before-image back itself.  A confirm the DC answers with anything but ok
is ``not_confirmed``, and Newton reads the DC's record to say what it
holds: still armed, or, when the undo already ran (its undo_at passed or
an abort ran it), that undo's dc_state.  A record that reads confirmed
is the confirm recorded, and the change is ``confirmed``.

Before the apply is sent, and once the runner's pre-flight has passed, a
pending receipt (apply_unknown) is written and synced to the disk; when it
cannot be written, nothing is sent.  The final receipt replaces it, so a
plan with no receipt was never sent from this host, and a receipt still
pending is an earlier apply that may have reached the DC until the DC's
record of the txid answers not_found.

A session that fails on the way to the DC (no answer, or not one JSON
object) is a result, never an exception: the receipt is written, the
result says which step was lost, and the owner reads the truth from the
DC with newton_ad_change_status.  A change that was written but never
confirmed is put back by the DC itself at or after its undo_at, when the
DC next runs the undo: on a Samba DC whose write setup was run with this
release, a sweep timer retries an undo whose run did not finish or that a
reboot dropped about once a minute (an undo_failed record is final); an
older Samba DC and a Windows DC retry it at the next Newton request to it.
The exception is a new user whose objectGUID the DC did not record (the
connection can fail between the add and that record): the DC never deletes
an account by its name, so it leaves that user in place and records
undo_failed with its DN in conflicts.
After a lost apply the DC may already have run the undo, when it could
not finish the apply after its write: its record then says undone or
undo_failed.

The receipt never holds the secret of a user-create, and the plan
record drops it once the apply has sent it; a plan record that cannot be
rewritten keeps it, and the result then names that in secret_error.
"""

from __future__ import annotations

import fcntl
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from ...adapters.ssh_cli import RunnerRefused
from . import inventory, plan as _plan, request, store, transport
from .errors import WriteError


#: The function that sends one request to one helper.
Send = Callable[[Any, Mapping[str, Any]], dict[str, Any]]

#: How often a DC is read again while it has not caught up.
POLL_S = 10.0

#: How long one DC may take to show the after-image.  Each DC has its own
#: budget, and the read-back as a whole stops at READBACK_RESERVE_S before
#: the end of the undo window.
TIMEOUT_S = 120.0

#: What the read-back leaves of the undo window: the confirm or abort
#: session (one transport session) and a margin, so it reaches the DC
#: before the DC runs its own undo.
READBACK_RESERVE_S = float(transport.TIMEOUT_S) + 30.0

#: The state of a receipt.
STATE_CONFIRMED = "confirmed"
STATE_NOT_TESTED = "not_tested"
STATE_CONFLICT = "conflict"
STATE_REFUSED = "refused"
#: The session failed while the apply was sent: Newton does not know
#: whether the DC wrote the change.
STATE_APPLY_UNKNOWN = "apply_unknown"
#: Every DC showed the after-image, then the session failed while the
#: confirm was sent: Newton does not know whether the confirm arrived.  With
#: the code not_sent the SSH runner refused it before it left the Newton
#: host: it was not sent, so the DC holds the change as it did (no record is
#: read on that path).
STATE_CONFIRM_UNKNOWN = "confirm_unknown"
#: Every DC showed the after-image, and the DC answered the confirm with
#: something other than ok.  The DC's record says what it holds: still
#: armed, or, when its undo already ran (undo_at passed or an abort ran it),
#: undone or undo_failed (an unlock stays written); a record that reads
#: confirmed makes the state confirmed.  When the record cannot be read,
#: Newton does not know whether the confirm was recorded (a DC can land the
#: confirmed record and still answer error).
STATE_NOT_CONFIRMED = "not_confirmed"
#: The automatic abort was refused, failed, or its answer was lost:
#: Newton does not know whether it ran.  With the code not_sent the SSH
#: runner refused it before it left the Newton host: it did not run, so the
#: DC holds the change as it did (no record is read on that path, and the
#: DC's own undo may already have run).
STATE_ABORT_FAILED = "abort_failed"
#: The DC already holds this transaction: an earlier apply of the plan
#: reached it.  The receipt of that apply is kept as it is.  With the code
#: not_sent, Newton caught the second apply itself and sent nothing: the
#: earlier apply reached the DC, or may have.
STATE_REPLAY = "replay"

#: The failures of a session to a write helper.
LINK_ERRORS: tuple[type[Exception], ...] = (transport.TransportError, RunnerRefused)

#: What the owner is told for each state above.  The text is Newton's own.
APPLY_UNKNOWN_MESSAGE = (
    "The connection to the domain controller failed while the apply was "
    "sent, so Newton does not know whether the change was written. Run "
    "newton_ad_change_status to read it from the DC. A change that was "
    "written is normally armed and not confirmed, and the DC puts the "
    "before-image back itself at or after its undo_at, when it next runs the "
    "undo, except a new user whose objectGUID the DC did not record (the "
    "connection can fail between the add and that record): the DC leaves "
    "that user in place and records undo_failed with its DN in conflicts, so "
    "read the account with the admin tools. But the DC may already have run "
    "the undo, when it could not finish the apply after its write: undone "
    "means the before-image is back; undo_failed means the DC did not put it "
    "back: it is still written, or someone else changed the target and "
    "conflicts names it, so read the target and plan the reverse change if "
    "Newton has one."
)
CONFIRM_UNKNOWN_MESSAGE = (
    "Every domain controller showed the change, then the connection failed "
    "while the confirm was sent, so Newton does not know whether the confirm "
    "arrived. Run newton_ad_change_status to read it from the DC. A change "
    "that is not confirmed is put back by the DC itself at or after its "
    "undo_at, when it next runs the undo."
)
NOT_CONFIRMED_MESSAGE = (
    "Every domain controller showed the change during verify, then the DC "
    "answered the confirm with an error or a conflict, so the confirm was "
    "not recorded. The DC's record of the change is still armed: the DC "
    "runs the undo itself at or after its undo_at, when it next runs the "
    "undo, and the undo puts the before-image back unless another change "
    "reached the target first (then it writes nothing and records "
    "undo_failed). Run newton_ad_change_status to read it from the DC."
)
NOT_CONFIRMED_NO_RECORD_MESSAGE = (
    "Every domain controller showed the change during verify, then the DC "
    "answered the confirm with an error or a conflict, and Newton could not "
    "read the DC's record of the change, so Newton does not know whether the "
    "confirm was recorded. Run newton_ad_change_status to read it from the "
    "DC: confirmed means the confirm was recorded and the change stays; "
    "armed means the DC runs the undo itself at or after its undo_at, when it "
    "next runs the undo; undone means the before-image is back; undo_failed "
    "means the undo did not put it back, so read the target and plan the "
    "reverse change if it needs one."
)
#: The DC refused the apply with conflict because another armed record of
#: the DC names the same target: its undo could write over this change.
ARMED_CONFLICT_MESSAGE = (
    "The domain controller refused the apply: another change of the same "
    "target is still armed on the DC (an apply whose confirm or abort did not "
    "finish), and its undo could write over this change, so nothing was "
    "written. Read that change with newton_ad_change_status and confirm or "
    "abort it, or wait until its undo_at has passed, then plan this change "
    "again."
)
CONFIRMED_ON_RECORD_MESSAGE = (
    "Every domain controller showed the change during verify. The DC "
    "answered the confirm with an error or a conflict, but its record "
    "shows it confirmed: the confirm was recorded, the undo does not run, "
    "and the change stays written."
)
NOT_CONFIRMED_STATE_MESSAGE = (
    "Every domain controller showed the change during verify, then the DC "
    "answered the confirm with an error or a conflict, so this confirm was "
    "not recorded. dc_state is the DC's record of the change. Run "
    "newton_ad_change_status to read it from the DC again."
)
CONFIRM_AFTER_UNDO_MESSAGE = (
    "Every domain controller showed the change during verify, but when the "
    "confirm arrived the DC had already run the undo (its undo_at had "
    "passed, or an abort ran it), so the confirm was refused: dc_state is "
    "the DC's record of that undo (undone means the before-image is back; "
    "undo_failed means the DC did not put it back: it is still written, or "
    "someone else changed the target and conflicts names it, so read the "
    "target and plan the reverse change if Newton has one)."
)
#: An unlock has no undo, so it stays written whatever the confirm got.
#: The helpers normally record an unlock confirmed when it is written, but
#: a Windows DC whose confirmed record could not be written keeps it armed
#: (and answers the apply ok), so neither message says what the record
#: reads: the owner reads it with newton_ad_change_status.  A conflict is
#: also the answer when the PDC emulator could not read the account or the
#: record is not one a confirm accepts, so it never claims a new lockout.
UNLOCK_NOT_CONFIRMED_MESSAGE = (
    "Every domain controller showed the unlock during verify, then the DC "
    "answered the confirm with an error. An unlock has no undo, so it stays "
    "written whatever the DC's record says: the DC normally records an "
    "unlock confirmed when it is written, and a record it could not write "
    "stays armed. Run newton_ad_change_status to read the DC's record of it."
)
UNLOCK_CONFIRM_CONFLICT_MESSAGE = (
    "Every domain controller showed the unlock during verify, then the PDC "
    "emulator answered the confirm with a conflict: it may have read the "
    "account locked again (a lockout that reached it after the verify, which "
    "is not Newton's), or it could not read the account, or its record of "
    "the unlock was not one a confirm accepts. An unlock has no undo: "
    "Newton's unlock stays written whatever the DC's record says (normally "
    "confirmed; armed when the DC could not write it). Look at the account's "
    "lockout with the admin tools, and run newton_ad_change_status to read "
    "the DC's record of it."
)
ABORT_FAILED_MESSAGE = (
    "A domain controller did not show the change in time, and Newton does "
    "not know whether the automatic abort ran (the DC refused it or failed, "
    "or the connection failed before its answer arrived). Run "
    "newton_ad_change_status to read the change from the DC. A change that "
    "is still armed is put back by the DC itself at or after its undo_at, "
    "when it next runs the undo."
)
ABORT_ALREADY_RAN_MESSAGE = (
    "A domain controller did not show the change in time. When the "
    "automatic abort arrived the DC had already run the undo, so the abort "
    "was refused: dc_state is the DC's record of that undo (undone means "
    "the before-image is back; undo_failed means the DC did not put it "
    "back: it is still written, or someone else changed the target and "
    "conflicts names it, so read the target and plan the reverse change if "
    "Newton has one)."
)
ABORT_LOST_MESSAGE = (
    "The connection to the domain controller failed while the abort was "
    "sent, so Newton does not know whether it arrived. Run "
    "newton_ad_change_status to read the change from the DC. A change that "
    "is still armed is put back by the DC itself at or after its undo_at, "
    "when it next runs the undo, except "
    "a new user whose objectGUID the DC did not record: the DC leaves that "
    "user in place and records undo_failed with its DN in conflicts."
)
#: The same states for an unlock, which arms no undo: it is confirmed once
#: written on the PDC emulator and stays written, so no rollback is promised.
UNLOCK_APPLY_UNKNOWN_MESSAGE = (
    "The connection to the domain controller failed while the unlock was "
    "sent, so Newton does not know whether it was written. Run "
    "newton_ad_change_status to read it from the DC. An unlock has no undo: "
    "if it was written, it stays written."
)
UNLOCK_CONFIRM_UNKNOWN_MESSAGE = (
    "Every domain controller showed the unlock, then the connection failed "
    "while the confirm was sent. Run newton_ad_change_status to read it from "
    "the DC. An unlock has no undo: once written on the PDC emulator it "
    "stays written, and the DC normally records it confirmed then (a DC "
    "that cannot write that record keeps it armed)."
)
UNLOCK_LAG_MESSAGE = (
    "A domain controller did not show the unlock in time. An unlock has no "
    "undo, so nothing was aborted: it stays written on the PDC emulator and "
    "reaches the other domain controllers by replication. Run "
    "newton_ad_change_status to read it from the DC."
)
UNLOCK_ABORT_LOST_MESSAGE = (
    "The connection to the domain controller failed while the abort was "
    "sent. An unlock has no undo, so there is nothing to abort: if it was "
    "written, it stays written. Run newton_ad_change_status to read it "
    "from the DC."
)
#: A confirm, an abort or a status the SSH runner refused before it left the
#: Newton host (code not_sent): nothing was sent, so the DC holds what it held.
CONFIRM_NOT_SENT_MESSAGE = (
    "Every domain controller showed the change, then Newton refused the "
    "confirm before it left this host, so the confirm was not sent and the "
    "DC holds the change as it did: a change still armed is put back by the "
    "DC itself at or after its undo_at, when it next runs the undo, except a "
    "new user whose objectGUID the DC did not record: the DC leaves that user "
    "in place and records undo_failed with its DN in conflicts. Run "
    "newton_ad_change_status to read it from the DC."
)
UNLOCK_CONFIRM_NOT_SENT_MESSAGE = (
    "Every domain controller showed the unlock, then Newton refused the "
    "confirm before it left this host, so the confirm was not sent. An "
    "unlock has no undo: it stays written, and the DC normally records it "
    "confirmed when it is written (a DC that cannot write that record keeps "
    "it armed). Run newton_ad_change_status to read it from the DC."
)
ABORT_NOT_SENT_MESSAGE = (
    "A domain controller did not show the change in time, and Newton "
    "refused the automatic abort before it left this host, so the abort was "
    "not sent and the DC holds the change as it did: a change still armed is "
    "put back by the DC itself at or after its undo_at, when it next runs the "
    "undo, except a new user whose objectGUID the DC did not record: the DC "
    "leaves that user in place and records undo_failed with its DN in "
    "conflicts. Run newton_ad_change_status to read the change from the DC."
)
ABORT_TOOL_NOT_SENT_MESSAGE = (
    "Newton refused the abort before it left this host, so the abort was "
    "not sent and the DC holds the change as it did: a change that is still "
    "armed is put back by the DC itself at or after its undo_at, when it "
    "next runs the undo, except a new user whose objectGUID the DC did not "
    "record: the DC leaves that user in place and records undo_failed with "
    "its DN in conflicts. Run newton_ad_change_status to read it from the DC."
)
UNLOCK_ABORT_NOT_SENT_MESSAGE = (
    "Newton refused the abort before it left this host, so the abort was "
    "not sent. An unlock has no undo, so there is nothing to abort: if it "
    "was written, it stays written. Run newton_ad_change_status to read it "
    "from the DC."
)
STATUS_NOT_SENT_MESSAGE = (
    "Newton refused the status request before it left this host, so it was "
    "not sent and the status could not be read. Fix the cause and try "
    "newton_ad_change_status again."
)
REFUSED_BEFORE_SEND_MESSAGE = (
    "Newton refused the request before it left this host, so nothing was "
    "sent to the domain controller and nothing changed. Fix the cause and "
    "apply the same plan again."
)
DC_ERROR_MESSAGE = (
    "The domain controller answered the apply with an error, and its record "
    "of the change does not show it refused, so Newton does not know whether "
    "the change was written. Run newton_ad_change_status to read it from the "
    "DC: armed means the DC puts the before-image back itself at or after "
    "its undo_at, when it next runs the undo (except a new user whose "
    "objectGUID the DC did not record: the DC leaves that user in place and "
    "records undo_failed with its DN in conflicts); undone means the "
    "before-image is back; undo_failed means the DC did not put it back: it is still "
    "written, or someone else changed the target and conflicts names it, so "
    "read the target and plan the reverse change if Newton has one. Do not "
    "apply the plan again."
)
#: The DC did not change the target (it answered the write with its own
#: error code, or never sent it), but its store took neither the mark that
#: says so nor the refused record: the record may still read armed (the
#: helper may not have been able to read it back at all), and the DC's undo
#: cannot tell it from a write that landed.
UNMARKED_MESSAGE = (
    "The domain controller did not change the target (it answered the "
    "write with its own error, or never sent it), but it could not record "
    "that: its record of the change may still read armed. When the "
    "DC next runs the undo (at or after its undo_at, or at its sweep), the "
    "undo may write the before-image over the current value, and that value "
    "may be somebody else's change. Read the target with the admin tools now "
    "and after the undo_at, run newton_ad_change_status to read the DC's "
    "record, and fix the DC's transaction store (a full disk, say). Do not "
    "apply the plan again."
)
DC_ERROR_NO_RECORD_MESSAGE = (
    "The domain controller answered the apply with an error, and Newton "
    "could not read the DC's record of the change, so Newton does not know "
    "whether the change was written. Run newton_ad_change_status to read it "
    "from the DC: refused means nothing changed; armed means the DC puts the "
    "before-image back itself at or after its undo_at, when it next runs the "
    "undo (except a new user whose objectGUID the DC did not record: the DC "
    "leaves that user in place and records undo_failed with its DN in "
    "conflicts); undone means the before-image is back; undo_failed means the DC "
    "did not put it back: it is still written, or someone else changed the "
    "target and conflicts names it, so read the target and plan the reverse "
    "change if Newton has one. Do not apply the plan again."
)
UNLOCK_DC_ERROR_MESSAGE = (
    "The domain controller answered the unlock with an error, and its record "
    "of the change does not show it refused, so Newton does not know whether "
    "it was written. Run newton_ad_change_status to read it from the DC. An "
    "unlock has no undo: if it was written, it stays written."
)
UNLOCK_DC_ERROR_NO_RECORD_MESSAGE = (
    "The domain controller answered the unlock with an error, and Newton "
    "could not read the DC's record of the change, so Newton does not know "
    "whether it was written. Run newton_ad_change_status to read it from the "
    "DC. An unlock has no undo: if it was written, it stays written."
)
#: A DC error whose re-read showed neither image: somebody else changed the
#: target, and Newton's write may have landed before that change.
THIRD_VALUE_MESSAGE = (
    "The domain controller answered the apply with an error, then read the "
    "target again and found neither the before-image nor the after-image: "
    "another change reached the target, and Newton does not know whether its "
    "own write landed before that change. live is the value the DC read. The "
    "DC never writes the before-image over another change, so it does not "
    "put this one back. Read the target with the admin tools and plan a new "
    "change if it needs one. Do not apply the plan again."
)
UNLOCK_THIRD_VALUE_MESSAGE = (
    "The domain controller answered the unlock with an error, then read the "
    "account again and found a lockout that is neither the one of the plan "
    "nor unlocked: another change locked the account again, and Newton does "
    "not know whether its unlock landed before that change. live is the "
    "value the DC read. An unlock has no undo: if it was written, it stays "
    "written. Look at the account's lockout with the admin tools."
)
#: The status of an unlock whose record is still armed.  An unlock arms no
#: undo, so armed there does not mean anything will be put back.
UNLOCK_ARMED_MESSAGE = (
    "This unlock's record is still armed: the domain controller could not "
    "settle the unlock's record after the write, so the record does not say "
    "whether the unlock was written. An unlock has no undo, so nothing is put back "
    "at undo_at: if it was written, it stays written. Look at the account's "
    "lockout with the admin tools."
)
DC_REFUSED_MESSAGE = (
    "The domain controller refused the change before writing it, so "
    "nothing changed."
)
#: The next step of each pre-write code the DC can name, added after
#: DC_REFUSED_MESSAGE.  The text is Newton's own; the DC's code only picks it.
DC_REFUSED_NEXT_STEPS: dict[str, str] = {
    "expired": (
        "The approval was outside its window when the DC checked it (an "
        "approval lasts 30 minutes): approve the plan again with "
        "newton-approve ad-change and the plan id, then apply it."
    ),
    "bad_token": (
        "The DC did not accept the approval token: its approval key does not "
        "match the one the approval was made with. Check that the passphrase "
        "typed on the DC and at newton-approve is the same, then approve the "
        "plan again and apply it. When every approval is refused this way, "
        "the DC holds a key made from another passphrase, so run the DC's write setup "
        "again with the domain's passphrase (on every DC of the domain), and "
        "check that its printed fingerprint is the one newton-ad-setup "
        "approval-key printed on the Newton host."
    ),
    "risk_mismatch": (
        "The DC derived another risk level for this change than the plan "
        "holds: the target is not as it was when it was planned. Read it "
        "with the admin tools and plan the change again."
    ),
    "not_pdc": (
        "The DC the change went to does not hold the PDC emulator role: make "
        "the inventory's write entry for the domain name the PDC emulator, "
        "then plan the change again."
    ),
    "privileged": (
        "A privileged account or group is involved (the target, or the write "
        "account itself is in a privileged group): Newton does not change "
        "privileged objects, and its write account must stay out of "
        "privileged groups."
    ),
    "schema": (
        "The DC's write helper did not accept the form of the request: check "
        "that the DC runs the write setup of this Newton version."
    ),
    "not_found": (
        "The target of the change is not on the DC as the plan names it (it "
        "was deleted or moved since the plan): read it with the admin tools "
        "and plan the change again if it still needs one."
    ),
    "denied": (
        "The DC's write helper does not allow this change on the target as "
        "it is now (the change does not fit the live object, or the target "
        "is one Newton never writes, such as the write account, krbtgt or a "
        "trust account): read the target with the admin tools and plan the "
        "change again if it still needs one. The DC also answers denied when "
        "the directory refused the write account (it lacks the delegation the "
        "write setup grants on the OU): when a new plan is refused the same "
        "way, run the DC's write setup again on that DC, then plan the change "
        "again."
    ),
    "unavailable": (
        "The DC's write helper could not run the change: its install, its "
        "approval key or the timer of its undo is not usable. Run the DC's "
        "write setup again, then plan the change again: the DC keeps a "
        "record of this plan, so it refuses the same plan a second time."
    ),
}
#: For a user-create the password left the plan record with this apply, so
#: an approval step cannot help: the same plan can never be applied again.
#: The new plan of the user gets a new password, so the one shown for this
#: plan, which no account holds, is said to be discarded.
NEW_PASSWORD_NOTE = (
    "The new plan has a new password, shown at its first approval: the "
    "password shown for this plan was never set on any account, so discard it."
)
DC_REFUSED_USER_CREATE_STEP = (
    "The password of the new user left the plan record with this apply, so "
    "this plan cannot be applied again: fix the cause and plan the new user "
    f"again. {NEW_PASSWORD_NOTE}"
)
#: The codes whose own next step applies the same plan again: for a
#: user-create the step below is said instead, then
#: DC_REFUSED_USER_CREATE_STEP.
DC_REFUSED_USER_CREATE_STEPS: dict[str, str] = {
    "expired": (
        "The approval was outside its window when the DC checked it (an "
        "approval lasts 30 minutes)."
    ),
    "bad_token": (
        "The DC did not accept the approval token: its approval key does not "
        "match the one the approval was made with. Check that the passphrase "
        "typed on the DC and at newton-approve is the same; when every "
        "approval is refused this way, run the DC's write setup again with "
        "the domain's passphrase (on every DC of the domain)."
    ),
    "unavailable": (
        "The DC's write helper could not run the change: its install, its "
        "approval key or the timer of its undo is not usable. Run the DC's "
        "write setup again."
    ),
}
#: The next step of a refusal of the helper's own install check (the answer
#: carries stage install): it refused before it read the request, so the DC
#: holds no record of it and the same plan can go out again.
INSTALL_REFUSED_STEP = (
    "The DC's write helper refused the request before reading it: its "
    "install check failed (the install, its approval key file or its device "
    "file is missing or others may change them, or on Samba the login is not "
    "the write login). Run the DC's write setup again on that DC, then apply "
    "the same plan (approve it again first with newton-approve ad-change "
    "when its 30-minute approval has passed): the DC holds no record of it."
)
INSTALL_REFUSED_USER_CREATE_STEP = (
    "The DC's write helper refused the request before reading it: its "
    "install check failed (the install, its approval key file or its device "
    "file is missing or others may change them, or on Samba the login is not "
    "the write login). Run the DC's write setup again on that DC."
)
#: The codes of the install check of both helpers: a refusal of that check
#: carries stage install, and nothing of the request was read.
INSTALL_CODES = frozenset({"unavailable", "denied"})
#: A retry of a user-create whose earlier apply the DC refused before
#: writing it: the password left the plan with that apply, so nothing is sent.
SECRET_SPENT_MESSAGE = (
    "The domain controller refused an earlier apply of this plan before "
    "writing it, so nothing was written, and the password of the new user "
    "left the plan record with that apply: this plan cannot be applied "
    "again, and Newton sent nothing. Fix the cause of the earlier refusal "
    "(its receipt keeps its message) and plan the new user again. "
    f"{NEW_PASSWORD_NOTE}"
)
#: Added to a conflict a user-create's apply met: the DC wrote nothing, and
#: the password left the plan record with the apply.
USER_CREATE_CONFLICT_STEP = (
    "The password of the new user left the plan record with this apply, so "
    "this plan cannot be applied again: plan the new user again if it still "
    f"needs one. {NEW_PASSWORD_NOTE}"
)
#: The DC refused with conflict and no other armed change: the target's
#: live value is not the plan's before-image, so somebody changed it.
STALE_TARGET_MESSAGE = (
    "The domain controller refused the apply: the target changed since the "
    "plan (its live value, in live, is not the plan's before-image), so "
    "nothing was written. Read the target with the admin tools and plan the "
    "change again from its value now."
)
#: A move's conflict whose live parent is empty: the DC could not read the
#: object's current parent (Windows answers "", Samba null), so the target
#: may not have changed at all.
UNREADABLE_PARENT_MESSAGE = (
    "The domain controller refused the move: it could not read the object's "
    "current parent (the parent was deleted, or the write account cannot read "
    "it), so nothing was written and the target may not have changed. Check "
    "the object's parent with the admin tools, and that the write account can "
    "read it, then plan the change again."
)
#: The same conflict, but the live value is the plan's after-image:
#: somebody else made the planned change, so there is nothing to apply.
ALREADY_HELD_MESSAGE = (
    "The domain controller refused the apply: the target already holds the "
    "planned value (its live value, in live, is the plan's after-image, so "
    "somebody else made this change since the plan), so nothing was written "
    "and nothing needs applying."
)


def _dc_refused_message(code: object, verb: object, install: bool = False) -> str:
    """DC_REFUSED_MESSAGE with the next step of the code the DC named, or
    of the helper's install check when ``install``."""
    step = DC_REFUSED_NEXT_STEPS.get(code) if isinstance(code, str) else None
    if verb == "user-create":
        # The password left the plan record with this apply, whatever the
        # code: the next step is always a new plan of the user.
        if install:
            step = INSTALL_REFUSED_USER_CREATE_STEP
        elif isinstance(code, str) and code in DC_REFUSED_USER_CREATE_STEPS:
            step = DC_REFUSED_USER_CREATE_STEPS[code]
        if step is None:
            return f"{DC_REFUSED_MESSAGE} {DC_REFUSED_USER_CREATE_STEP}"
        return f"{DC_REFUSED_MESSAGE} {step} {DC_REFUSED_USER_CREATE_STEP}"
    if install:
        step = INSTALL_REFUSED_STEP
    return DC_REFUSED_MESSAGE if step is None else f"{DC_REFUSED_MESSAGE} {step}"
REPLAY_MESSAGE = (
    "The domain controller already holds this transaction: an earlier apply "
    "of this plan reached it, and this apply changed nothing. The receipt of "
    "the earlier apply is kept. Run newton_ad_change_status to read what the "
    "DC holds, and do not apply the plan again."
)
#: A second apply of a plan whose earlier apply reached the DC, or may
#: have: Newton sends nothing and keeps the earlier receipt.
EARLIER_APPLY_MESSAGE = (
    "An earlier apply of this plan reached the domain controller, or may "
    "have, so the change may already be written. Newton refused this apply "
    "before it left this host: nothing was sent, and the receipt of the "
    "earlier apply is kept as it was. Run newton_ad_change_status to read "
    "the change from the DC, and read the target with the admin tools "
    "before planning anything new. Do not apply the plan again."
)
#: The receipt Newton writes, and fsyncs, before it sends an apply: until
#: the final receipt replaces it, it says Newton does not know the outcome.
PENDING_MESSAGE = (
    "Newton was about to send this apply to the domain controller and does "
    "not yet know the outcome: if this receipt still reads so, Newton "
    "stopped before it recorded the DC's answer, and the change may or may "
    "not be written. Run newton_ad_change_status to read it from the DC."
)
#: The pending receipt could not be written, so the apply was not sent.
PENDING_REFUSED_MESSAGE = (
    "Newton could not record this apply on this host before sending it (a "
    "full or read-only state directory, say), so nothing was sent to the "
    "domain controller: this apply changed nothing. Fix the state directory "
    "of the Newton host and apply the same plan again."
)
PENDING_ERROR_MESSAGE = (
    "Newton could not write the receipt of this apply on this host (a full "
    "disk, say), so it did not send the apply: fix the state directory of "
    "the Newton host."
)
#: A refusal before anything left this host, on a retry whose earlier
#: attempt left a pending receipt (the DC held no record of the txid when
#: the retry read it): that receipt is kept, never replaced by refused.
#: A DC refusal before its write, on a retry over an earlier attempt's
#: pending receipt, while the DC held no record of the txid: it says
#: nothing about that earlier attempt.
EARLIER_PENDING_DC_REFUSED_MESSAGE = (
    "The domain controller refused this apply before writing it, so this "
    "apply changed nothing. An earlier apply of this plan stopped after "
    "Newton recorded that it was about to send it, and the domain controller "
    "held no record of the change when Newton read it just now; that earlier "
    "apply may still be on its way, so its receipt is kept and reads "
    "apply_unknown. Read the status again before changing the target another "
    "way; fix the cause and apply the same plan again."
)
#: The same, for a user-create: the retry sent the password, so the plan
#: is spent and every later apply of it is refused.
EARLIER_PENDING_DC_REFUSED_USER_CREATE_MESSAGE = (
    "The domain controller refused this apply before writing it, so this "
    "apply changed nothing. An earlier apply of this plan stopped after "
    "Newton recorded that it was about to send it, and the domain controller "
    "held no record of the change when Newton read it just now; that earlier "
    "apply may still be on its way, so its receipt is kept and reads "
    "apply_unknown. This apply sent the password, so the plan cannot be "
    "applied again: read the status again, then fix the cause and plan the "
    "user again."
)
#: Newton could not record a retry (its pending receipt or its lock) while
#: an earlier attempt's pending receipt was there; the DC was not read.
EARLIER_PENDING_NOT_SENT_MESSAGE = (
    "Newton could not record this apply on this host (a full or read-only "
    "state directory, say), so nothing was sent: this apply changed nothing. "
    "An earlier apply of this plan stopped after Newton recorded that it was "
    "about to send it and may have reached the domain controller; its receipt "
    "is kept and reads apply_unknown. Fix the state directory of the Newton "
    "host and read the status with newton_ad_change_status before changing "
    "the target another way."
)
EARLIER_PENDING_REFUSED_MESSAGE = (
    "Newton refused this apply before it left this host, so this apply sent "
    "nothing. An earlier apply of this plan stopped after Newton recorded "
    "that it was about to send it, and the domain controller held no record "
    "of the change when Newton read it just now; the receipt of that earlier "
    "apply is kept and reads apply_unknown. Fix the cause and apply the same "
    "plan again."
)
#: The status of a change whose receipt is still pending, when the DC holds
#: no record of the txid: both helpers create the record before they write.
PENDING_NOT_FOUND_MESSAGE = (
    "The domain controller holds no record of this change, and Newton's "
    "receipt says only that it was about to send the apply: no apply of this "
    "plan had reached the DC's write when it was read (Newton stopped before "
    "it sent the apply, or the DC refused it before writing anything), unless "
    "an apply sent before Newton stopped is still on its way to the DC. Read "
    "the status again before changing the target another way; apply the same "
    "plan again to send it."
)
#: A status the DC answers not_found when the receipt is not a pending one.
NOT_FOUND_MESSAGE = (
    "The domain controller holds no record of this change that it can read: "
    "as far as the DC shows, no apply of this plan reached its write (the plan "
    "was never applied, or the DC refused it before writing anything). A plan "
    "that was never applied can be applied with newton_ad_apply_change."
)
#: A status the DC answers not_found when the receipt of an earlier apply
#: is final and does not read refused (the apply's session failed, say):
#: Newton refuses a second apply of the plan, so it is never offered.
EARLIER_NOT_FOUND_MESSAGE = (
    "The domain controller holds no record of this change that it can read, "
    "but the receipt of an earlier apply on this host does not say the DC "
    "refused it (the session of that apply failed, say): that apply may not "
    "have reached the DC, or may still be on its way to it. Newton refuses "
    "a second apply of this plan, so it cannot be applied again. Read the "
    "status again before changing the target another way; when it still "
    "reads not_found, read the target with the admin tools and plan the "
    "change again if it still needs one."
)
#: A status the DC answers not_found for a user-create whose password left
#: the plan record with an earlier apply the DC refused before its write.
SPENT_NOT_FOUND_MESSAGE = (
    "The domain controller holds no record of this change that it can read: "
    "as far as the DC shows, no apply of this plan reached its write. The "
    "password of the new user left the plan record with an earlier apply, so "
    "this plan cannot be applied again: plan the new user again if it still "
    f"needs one. {NEW_PASSWORD_NOTE}"
)
#: A status the DC answers refused when the receipt on this host does not
#: hold the DC's refusal: the DC's record keeps the state only.
REFUSED_STATUS_MESSAGE = (
    f"{DC_REFUSED_MESSAGE} The DC's record keeps no reason, and the receipt "
    "of the apply on this host, which keeps it, could not be read or does "
    "not hold it: read the target with the admin tools and plan the change "
    "again if it still needs one."
)
#: A status or an abort the helper answers unavailable or denied: its install
#: check refused it, or (unavailable) its store was busy.
HELPER_REFUSED_MESSAGE = (
    "The domain controller's write helper refused this request or could not "
    "run it (code unavailable or denied): its install check failed (the "
    "install, its approval key file or its device file is missing or others "
    "may change them, or on Samba the login is not the write login), or its "
    "store was busy. Try again in a minute; when it answers the same, run "
    "the DC's write setup again on that DC, then run newton_ad_change_status."
)
#: An abort the DC answers with an error: the undo may or may not have run.
ABORT_ERROR_MESSAGE = (
    "The domain controller answered the abort with an error, so Newton does "
    "not know whether its undo ran. Run newton_ad_change_status to read the "
    "change from the DC."
)
STATUS_LOST_MESSAGE = (
    "The connection to the domain controller failed, so the status could "
    "not be read. Try newton_ad_change_status again."
)
#: Both helpers answer a status with error when the record of the change
#: cannot be read (a read that raises), and never name a state then.
STATUS_ERROR_MESSAGE = (
    "The domain controller answered the status with an error, so the state "
    "of the change could not be read (its record of the change may not be "
    "readable for now: a sharing violation or an IO error, say). Try "
    "newton_ad_change_status again."
)


def _try_send(sender: "Send", device: Any, payload: Mapping[str, Any]) -> dict[str, Any] | None:
    """One send, or None when the session to the helper failed."""
    try:
        return sender(device, payload)
    except LINK_ERRORS:
        return None


#: DC answer codes both helpers give only before they write anything.
#: They say nothing about an earlier apply of the same txid, though: a
#: helper of an earlier release checks the token and the window before the
#: replay, so it answers a retry of an apply it holds (one whose receipt
#: was never written on this host) expired or bad_token.  Such an answer is
#: refused only when the DC's record read by txid is not there or says
#: refused.  Every other code but conflict and replay is decided by the
#: DC's record of the transaction: error, denied and not_found can follow a
#: write that was tried (the write's own LDAP code, or an exception after
#: it), and any other code is treated the same way rather than trusted.
PRE_WRITE_CODES: frozenset[str] = frozenset(
    {"schema", "bad_token", "expired", "privileged", "not_pdc", "risk_mismatch"}
)


def _refused_before_send(exc: BaseException | None) -> bool:
    """A failure raised before anything left the Newton host: the SSH
    runner's pre-flight refusal, or the transport's own size check (which
    the apply's contract check makes unreachable today)."""
    if isinstance(exc, RunnerRefused):
        return True
    return isinstance(exc, transport.TransportError) and exc.code == "schema"


def _link_code(exc: BaseException | None) -> str:
    """The contract word of a failed session."""
    if isinstance(exc, RunnerRefused):
        return "not_sent"
    code = getattr(exc, "code", None)
    return code if isinstance(code, str) else "unavailable"


def _load_plan(plan_id: str, domain: str | None = None) -> dict[str, Any]:
    """The plan of one change."""
    if not isinstance(plan_id, str) or not plan_id:
        raise WriteError("the plan id is not a name")
    try:
        plan = store.read_json(store.plan_path(plan_id))
    except (OSError, ValueError):
        raise WriteError("the plan record is not found or is invalid") from None
    if domain is not None and plan.get("device") != domain:
        raise WriteError("the plan belongs to another domain")
    if not isinstance(plan, dict) or plan.get("plan_id") != plan_id:
        raise WriteError("the plan record is not found or is invalid")
    return plan


def _load_approval(plan_id: str) -> dict[str, Any]:
    """The approval of one plan, beside the plan."""
    try:
        approval = store.read_json(store.approval_path(plan_id))
    except (OSError, ValueError):
        raise WriteError("the plan is not approved") from None
    if not isinstance(approval, dict):
        raise WriteError("the plan is not approved")
    for field in ("nbf", "exp", "token"):
        if field not in approval:
            raise WriteError("the plan is not approved")
    return approval


def _request_of(plan: Mapping[str, Any], approval: Mapping[str, Any]) -> dict[str, Any]:
    """The request of the apply: the plan, the window and the token."""
    payload: dict[str, Any] = {
        "v": 1,
        "mode": "apply",
        "device": plan["device"],
        "txid": plan["txid"],
        "verb": plan["verb"],
        "target": plan["target"],
        "before": plan["before"],
        "after": plan["after"],
        "window": plan["window"],
        "risk": plan["risk"],
        "nbf": approval["nbf"],
        "exp": approval["exp"],
        "token": approval["token"],
    }
    secret = plan.get("secret")
    if isinstance(secret, str):
        payload["secret"] = secret
    return payload


def _drop_secret(plan_id: str, plan: Mapping[str, Any]) -> str | None:
    """Drop the password of a user-create from the plan record.

    The password goes to the DC once.  After the apply has sent it, the
    txid is spent (a second apply is a replay), so nothing needs it
    again, and the plan record keeps every other field.  A request
    refused before it left the Newton host keeps it: nothing was sent.  A record that
    cannot be rewritten keeps the password; the apply itself goes on, and
    the answer is the text the result then carries as secret_error (None
    when nothing was left behind).
    """
    if "secret" not in plan:
        return None
    kept = {key: value for key, value in plan.items() if key != "secret"}
    try:
        store.write_json(store.plan_path(plan_id), kept)
    except OSError:
        return SECRET_ERROR_MESSAGE
    return None


def _earlier_apply(plan_id: str, plan: Mapping[str, Any]) -> tuple[bool, str | None, bool]:
    """Whether an earlier apply of the plan reached the DC, or may have.

    A receipt in any state but refused is one: the DC answered that apply,
    or the session failed after the request left this host.  A receipt
    that cannot be read, or whose presence cannot be checked, is treated
    the same way.  A user-create whose plan
    record no longer holds its secret is one too, whatever the receipt
    reads, a refused one included: the secret leaves the plan record only
    once an apply has sent it.  A pending receipt (written before a send,
    never replaced by the final one) is one too, until the DC's record says
    otherwise: the caller reads it by txid.  The answer is that, the state
    of the earlier receipt when it was read, and whether it was pending.
    """
    secret_gone = plan.get("verb") == "user-create" and not isinstance(plan.get("secret"), str)
    path = store.receipt_path(plan_id)
    try:
        present = path.exists()
    except OSError:
        return True, None, False
    if not present:
        return secret_gone, None, False
    try:
        receipt = store.read_json(path)
    except (OSError, ValueError):
        return True, None, False
    state = receipt.get("state") if isinstance(receipt, dict) else None
    state = state if isinstance(state, str) else None
    if isinstance(receipt, dict) and receipt.get("pending") is True:
        return secret_gone, state, True
    return state != STATE_REFUSED or secret_gone, state, False


def _dc_refused_receipt(plan_id: str) -> bool:
    """Whether the plan's receipt is a refusal the DC answered before its
    write (its message is the DC_REFUSED_MESSAGE one), or a conflict (the
    DC answered conflict, with no unmarked, before writing anything): that
    apply reached the DC, so it sent the password of a user-create."""
    try:
        receipt = store.read_json(store.receipt_path(plan_id))
    except (OSError, ValueError):
        return False
    if not isinstance(receipt, dict) or receipt.get("pending") is True:
        return False
    if receipt.get("state") == STATE_CONFLICT:
        return receipt.get("code") == "conflict"
    if receipt.get("state") != STATE_REFUSED:
        return False
    message = receipt.get("message")
    return isinstance(message, str) and message.startswith(DC_REFUSED_MESSAGE)


def _write_pending(plan_id: str, plan: Mapping[str, Any], created: datetime) -> bool:
    """Write, and fsync, the pending receipt of an apply about to be sent.

    The answer is whether it was written: an apply whose attempt cannot be
    recorded is never sent, so a plan with no receipt was never sent.
    """
    receipt = {
        "v": 1,
        "plan_id": plan_id,
        "txid": plan["txid"],
        "device": plan["device"],
        "verb": plan["verb"],
        "risk": plan.get("risk"),
        "window": plan.get("window"),
        "target": plan.get("target"),
        "before": plan.get("before"),
        "after": plan.get("after"),
        "state": STATE_APPLY_UNKNOWN,
        "pending": True,
        "code": None,
        "message": PENDING_MESSAGE,
        "dcs": {},
        "created_at": created.isoformat(),
    }
    return _write_receipt(plan_id, receipt) is None


def _no_preflight(target: Any, payload: Mapping[str, Any]) -> None:
    """The pre-flight of an injected sender: its own refusals are raised
    by the send itself."""


def _read_request(plan: Mapping[str, Any]) -> dict[str, Any]:
    """The request of the verification read."""
    return {
        "v": 1,
        "mode": "read",
        "device": plan["device"],
        "verb": plan["verb"],
        "target": plan["target"],
    }


def _pdc_of(plan: Mapping[str, Any], devices: Mapping[str, Any]) -> Any:
    """The domain controller the plan was built against."""
    name = plan.get("pdc")
    if isinstance(name, str):
        device = devices.get(name)
        if device is not None and inventory.is_write_device(device):
            return device
    raise WriteError("the plan does not name the domain controller of its domain")


#: What the owner is told when the receipt of an apply could not be written
#: on the Newton host.  The AD result is unchanged: the DC's record holds it.
#: The plan record of a user-create could not be rewritten without its
#: password after the apply sent it.
SECRET_ERROR_MESSAGE = (
    "Newton sent the new user's initial password to the domain controller "
    "but could not remove it from the plan record on this host (a full or "
    "read-only state directory, say): the password is still stored there. "
    "Fix the state directory of the Newton host and delete that plan "
    "record, or change the user's password with the admin tools."
)
RECEIPT_ERROR_MESSAGE = (
    "Newton could not write the receipt of this apply on this host (a full "
    "disk, say), so the result above is not kept here: run "
    "newton_ad_change_status to read the change from the DC, and fix the "
    "state directory of the Newton host."
)


def _write_receipt(plan_id: str, receipt: Mapping[str, Any]) -> str | None:
    """Write the receipt of one change.

    A receipt that cannot be written never replaces the AD result: the
    answer is the text the result then carries as receipt_error, or None
    when the receipt was written.
    """
    path = store.receipt_path(plan_id)
    try:
        store.write_json(path, dict(receipt))
    except OSError:
        return RECEIPT_ERROR_MESSAGE
    return None


def _with_receipt_error(
    result: dict[str, Any], error: str | None, secret_error: str | None = None
) -> dict[str, Any]:
    if error is not None:
        result["receipt_error"] = error
    if secret_error is not None:
        result["secret_error"] = secret_error
    return result


APPLY_BUSY_MESSAGE = (
    "Another apply of this plan is running on this Newton host, so this one "
    "was not sent and no receipt was written. Read the status with "
    "newton_ad_change_status once that apply has ended."
)


def _reads_pending(plan_id: str) -> bool:
    """Whether the plan's receipt reads pending (an earlier attempt's); a
    receipt that cannot be read is taken for one."""
    try:
        path = store.receipt_path(plan_id)
        if not path.exists():
            return False
        receipt = store.read_json(path)
    except (OSError, ValueError):
        return True
    return isinstance(receipt, dict) and receipt.get("pending") is True


def apply_change(plan_id: str, **kwargs: Any) -> dict[str, Any]:
    """Apply one approved change and verify it on every DC with a write entry.

    One apply of a plan runs at a time on this host: a per-plan lock in the
    receipts directory is held from the check for an earlier apply to the
    final receipt, and a second apply while it is held is refused before
    anything is sent or written.  See ``_apply_change`` for the rest.
    """
    # A plan id that cannot name a file is no plan: the same answer
    # status and abort give, before any path is built from it.
    if not isinstance(plan_id, str) or store.PLAN_ID_RE.fullmatch(plan_id) is None:
        raise WriteError("the plan record is not found or is invalid")
    # kiss: one host only; two Newton hosts sharing a plan are not locked.
    directory = store.receipts_dir()
    try:
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        lock = os.open(directory / f".{store.receipt_path(plan_id).stem}.lock",
                       os.O_RDWR | os.O_CREAT, 0o600)
    except OSError:
        return {
            "result": "error",
            "plan_id": plan_id,
            "state": STATE_REFUSED,
            "code": "not_sent",
            "message": (
                EARLIER_PENDING_NOT_SENT_MESSAGE if _reads_pending(plan_id)
                else PENDING_REFUSED_MESSAGE
            ),
            "dcs": {},
            "receipt_error": PENDING_ERROR_MESSAGE,
        }
    try:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return {
                "result": "error",
                "plan_id": plan_id,
                "state": STATE_REPLAY,
                "code": "not_sent",
                "message": APPLY_BUSY_MESSAGE,
                "dcs": {},
            }
        return _apply_change(plan_id, **kwargs)
    finally:
        os.close(lock)


def _apply_change(
    plan_id: str,
    *,
    domain: str | None = None,
    send: Send | None = None,
    preflight: Callable[[Any, Mapping[str, Any]], None] | None = None,
    devices: Mapping[str, Any] | None = None,
    poll_s: float = POLL_S,
    timeout_s: float = TIMEOUT_S,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Apply one approved change and verify it on every DC with a write entry.

    The DCs are the write entries of the inventory that name the domain: a
    DC of the domain without a write entry is never read.

    Before the apply is sent, and once the runner's pre-flight has passed,
    a pending receipt (apply_unknown) is written and fsynced; when it
    cannot be written, nothing is sent.  The final receipt replaces it.
    """
    plan = _load_plan(plan_id, domain)
    approval = _load_approval(plan_id)
    inventory_devices = _plan.load_devices(devices)
    dcs = inventory.domain_dcs(inventory_devices, str(plan["device"]))
    if not dcs:
        raise WriteError("the domain has no write entry")
    pdc = _pdc_of(plan, inventory_devices)
    sender = send if send is not None else transport.send
    if preflight is None:
        preflight = transport.preflight if send is None else _no_preflight

    payload = _request_of(plan, approval)
    try:
        request.parse_request(json.dumps(payload).encode("utf-8"))
    except request.RequestRefused as exc:
        raise WriteError(f"the request of the plan does not fit the contract: {exc}") from None

    earlier, earlier_state, pending = _earlier_apply(plan_id, plan)
    if pending and not earlier:
        # An earlier attempt wrote its pending receipt and no final one: it
        # may have reached the DC.  Only the DC's not_found says no apply of
        # the txid reached its write (both helpers create the record before
        # they write); anything else, a status that cannot be read included,
        # keeps the plan from being sent.
        record = _try_send(
            sender,
            pdc,
            {"v": 1, "mode": "status", "device": plan["device"], "txid": plan["txid"]},
        )
        earlier = not (isinstance(record, dict) and record.get("code") == "not_found")
    if (
        earlier
        and not pending
        and earlier_state in (STATE_REFUSED, STATE_CONFLICT)
        and plan.get("verb") == "user-create"
        and not isinstance(plan.get("secret"), str)
        and _dc_refused_receipt(plan_id)
    ):
        # The DC refused the earlier apply before its write and the password
        # left with it: nothing was written, so the answer never says the
        # change may be, and the refused receipt is kept as it is.  A refused
        # receipt of an apply that never left this host kept the password,
        # so another apply sent it: that one keeps EARLIER_APPLY_MESSAGE.
        return {
            "result": "error",
            "plan_id": plan_id,
            "state": STATE_REFUSED,
            "code": "not_sent",
            "message": SECRET_SPENT_MESSAGE,
            "dcs": {},
        }
    if earlier:
        # A second apply of the same plan is never sent: the txid is spent
        # and a user-create's secret is gone, so the DC could only answer
        # replay or a pre-write refusal, and the receipt that may describe
        # a write is never overwritten.
        message = EARLIER_APPLY_MESSAGE
        if earlier_state is not None:
            message += f" The receipt of the earlier apply reads {earlier_state}."
        return {
            "result": "error",
            "plan_id": plan_id,
            "state": STATE_REPLAY,
            "code": "not_sent",
            "message": message,
            "dcs": {},
        }

    # A final receipt this attempt may replace (one reading refused): kept
    # aside so a replay answer can put it back over this attempt's pending
    # receipt, as REPLAY_MESSAGE says.
    prior: Any = None
    if not pending:
        try:
            if store.receipt_path(plan_id).exists():
                prior = store.read_json(store.receipt_path(plan_id))
        except (OSError, ValueError):
            prior = None
    created = datetime.now(timezone.utc) if now is None else now
    lost: BaseException | None = None
    secret_error: str | None = None
    answer: dict[str, Any] | None = None
    apply_started = clock()
    try:
        preflight(pdc, payload)
    except LINK_ERRORS as exc:
        lost = exc
    else:
        if not _write_pending(plan_id, plan, created):
            return {
                "result": "error",
                "plan_id": plan_id,
                "state": STATE_REFUSED,
                "code": "not_sent",
                "message": EARLIER_PENDING_NOT_SENT_MESSAGE if pending else PENDING_REFUSED_MESSAGE,
                "dcs": {},
                "receipt_error": PENDING_ERROR_MESSAGE,
            }
        # The DC's undo_at is its clock at the apply plus the window: read
        # before the apply is sent, this moment is never later than that.
        apply_started = clock()
        try:
            answer = sender(pdc, payload)
        except LINK_ERRORS as exc:
            answer = None
            lost = exc
        finally:
            if not _refused_before_send(lost):
                secret_error = _drop_secret(plan_id, plan)
    unlock = plan.get("verb") == "unlock"
    if answer is None and pending and _refused_before_send(lost):
        # Nothing left this host, but an earlier attempt's pending receipt
        # was there: a refused receipt is never written over it.
        return {
            "result": "error",
            "plan_id": plan_id,
            "state": STATE_REFUSED,
            "code": _link_code(lost),
            "message": EARLIER_PENDING_REFUSED_MESSAGE,
            "dcs": {},
        }
    if answer is None:
        code = _link_code(lost)
        apply_unknown = UNLOCK_APPLY_UNKNOWN_MESSAGE if unlock else APPLY_UNKNOWN_MESSAGE
        unknown_state = STATE_APPLY_UNKNOWN
        if _refused_before_send(lost):
            # Nothing left this host, and no earlier attempt left a pending
            # receipt: this attempt's own pending receipt, if it was
            # written, is replaced by the refused one.
            apply_unknown = REFUSED_BEFORE_SEND_MESSAGE
            unknown_state = STATE_REFUSED
        receipt = {
            "v": 1,
            "plan_id": plan_id,
            "txid": plan["txid"],
            "device": plan["device"],
            "verb": plan["verb"],
            "risk": plan.get("risk"),
            "window": plan.get("window"),
            "target": plan.get("target"),
            "before": plan.get("before"),
            "after": plan.get("after"),
            "state": unknown_state,
            "code": code,
            "message": apply_unknown,
            "dcs": {},
            "created_at": created.isoformat(),
        }
        receipt_error = _write_receipt(plan_id, receipt)
        return _with_receipt_error({
            "result": "error",
            "plan_id": plan_id,
            "state": unknown_state,
            "code": code,
            "message": apply_unknown,
            "dcs": {},
        }, receipt_error, secret_error)
    code = answer.get("code")
    if code != "ok":
        message: str | None = None
        # A re-read after the failed write that shows neither image: both
        # helpers answer it with the write's own code and the live value,
        # and record it undo_failed (an unlock stays armed), never refused.
        live = answer.get("live")
        third = (
            isinstance(live, dict)
            and bool(live)
            and live != plan.get("before")
            and live != plan.get("after")
        )
        # An answer that carries unmarked says the DC's record may still
        # read armed, so its undo may run: it is never reported as nothing
        # changed (a conflict or a pre-write refusal), and the record is read.
        unmarked = answer.get("unmarked") is True and not unlock
        never_held = False
        if code == "conflict" and not unmarked:
            state = STATE_CONFLICT
            if answer.get("armed") is True:
                message = ARMED_CONFLICT_MESSAGE
            elif isinstance(live, dict) and live and live == plan.get("after"):
                message = ALREADY_HELD_MESSAGE
            elif (
                plan.get("verb") == "move"
                and isinstance(live, dict)
                and "parent" in live
                and live["parent"] in ("", None)
            ):
                message = UNREADABLE_PARENT_MESSAGE
            else:
                message = STALE_TARGET_MESSAGE
            if plan.get("verb") == "user-create":
                message = f"{message} {USER_CREATE_CONFLICT_STEP}"
        elif code == "replay":
            state, message = STATE_REPLAY, REPLAY_MESSAGE
        else:
            # A refusal of the helper's own install check (marked stage
            # install): it refused before it read the request, so this apply
            # wrote nothing and created no record, and a status read would
            # meet the same check.
            install = (
                isinstance(code, str)
                and code in INSTALL_CODES
                and answer.get("stage") == "install"
                and not unmarked
            )
            record = None if install else _try_send(
                sender,
                pdc,
                {"v": 1, "mode": "status", "device": plan["device"], "txid": plan["txid"]},
            )
            # A pre-write code with no record of the txid on the DC: no
            # apply of this txid ever reached its write (both helpers
            # create the record before they write anything).
            never_held = install or (
                code in PRE_WRITE_CODES
                and not unmarked
                and isinstance(record, dict)
                and record.get("code") == "not_found"
            )
            if never_held or (
                isinstance(record, dict)
                and record.get("code") == "ok"
                and record.get("state") == "refused"
            ):
                state, message = STATE_REFUSED, _dc_refused_message(
                    code, plan.get("verb"), install
                )
            elif unmarked:
                # The DC answered the write itself, and its store took
                # neither the mark nor the refused record: its undo may run
                # over somebody else's value.
                state, message = STATE_APPLY_UNKNOWN, UNMARKED_MESSAGE
            elif third:
                state = STATE_APPLY_UNKNOWN
                message = UNLOCK_THIRD_VALUE_MESSAGE if unlock else THIRD_VALUE_MESSAGE
            elif isinstance(record, dict) and record.get("code") == "ok":
                state = STATE_APPLY_UNKNOWN
                message = UNLOCK_DC_ERROR_MESSAGE if unlock else DC_ERROR_MESSAGE
            else:
                # The status session failed or the DC did not answer it ok:
                # no record was read.
                state = STATE_APPLY_UNKNOWN
                message = (
                    UNLOCK_DC_ERROR_NO_RECORD_MESSAGE if unlock else DC_ERROR_NO_RECORD_MESSAGE
                )
        receipt = {
            "v": 1,
            "plan_id": plan_id,
            "txid": plan["txid"],
            "device": plan["device"],
            "verb": plan["verb"],
            "risk": plan.get("risk"),
            "window": plan.get("window"),
            "target": plan.get("target"),
            "before": plan.get("before"),
            "after": plan.get("after"),
            "state": state,
            "code": code,
            "dcs": {},
            "created_at": created.isoformat(),
        }
        if message is not None:
            receipt["message"] = message
        if third and state == STATE_APPLY_UNKNOWN:
            receipt["live"] = live
        elif state == STATE_CONFLICT and isinstance(live, dict) and live:
            # the DC's value now, which made the before-image stale
            receipt["live"] = live
        receipt_error: str | None = None
        if pending and never_held:
            # The refusal says nothing about the earlier attempt: its pending
            # receipt (this attempt's replaced it in the same state) stays.
            return _with_receipt_error({
                "result": "error",
                "plan_id": plan_id,
                "state": STATE_REFUSED,
                "code": code,
                "message": (
                    EARLIER_PENDING_DC_REFUSED_USER_CREATE_MESSAGE
                    if plan.get("verb") == "user-create"
                    else EARLIER_PENDING_DC_REFUSED_MESSAGE
                ),
                "dcs": {},
            }, None, secret_error)
        if state != STATE_REPLAY:
            receipt_error = _write_receipt(plan_id, receipt)
        elif not pending:
            # A replay never overwrites the receipt of an earlier apply: the
            # pending receipt of an earlier attempt that may have reached the
            # DC stays as it is; an earlier final receipt is put back over
            # this attempt's own pending one; with neither, the replay
            # receipt replaces this attempt's pending receipt.
            receipt_error = _write_receipt(plan_id, prior if isinstance(prior, dict) else receipt)
        result: dict[str, Any] = {
            "result": "error",
            "plan_id": plan_id,
            "state": state,
            "code": code,
            "dcs": {},
        }
        if message is not None:
            result["message"] = message
        if third and state == STATE_APPLY_UNKNOWN:
            result["live"] = live
        elif state == STATE_CONFLICT and isinstance(live, dict) and live:
            result["live"] = live
        return _with_receipt_error(result, receipt_error, secret_error)

    readback_deadline = apply_started + max(
        TIMEOUT_S, float(plan["window"]) - READBACK_RESERVE_S
    )
    if send is None:
        def reader(device: Any, body: Mapping[str, Any], session_s: float) -> dict[str, Any]:
            return transport.send(device, body, timeout_s=session_s)
    else:
        def reader(device: Any, body: Mapping[str, Any], session_s: float) -> dict[str, Any]:
            return sender(device, body)
    states = _verify(reader, dcs, plan, poll_s, timeout_s, sleep, clock, readback_deadline)
    every = all(
        isinstance(one, dict) and one.get("state") == "matched"
        for one in states.values()
    )
    # The undo answer of an automatic abort: what it restored and what it
    # left changed, so the owner is told about the conflicts.
    undo: dict[str, Any] = {}
    message: str | None = None
    mode = "confirm" if every else "abort"
    lost = None
    sent: dict[str, Any] | None
    if unlock and not every:
        # An unlock arms no undo and stays written once written on the PDC
        # emulator, so there is nothing to abort: the helpers refuse it.
        sent = None
    else:
        try:
            sent = sender(
                pdc,
                {
                    "v": 1,
                    "mode": mode,
                    "device": plan["device"],
                    "txid": plan["txid"],
                },
            )
        except LINK_ERRORS as exc:
            sent = None
            lost = exc
    ran: dict[str, Any] | None = None
    dc_record: dict[str, Any] | None = None
    if (
        not unlock
        and sent is not None
        and sent.get("code") != "ok"
        and (every or sent.get("code") == "conflict")
    ):
        # A confirm the DC did not record, or an abort it refused with
        # conflict: the record says what the DC holds.  It may be no longer
        # armed because the DC's timer or sweep, or an abort, ran the undo
        # first.
        dc_record = _status_of(sender, pdc, plan)
        if dc_record is not None and dc_record.get("state") in ("undone", "undo_failed"):
            ran = dc_record
    if unlock and not every:
        state = STATE_NOT_TESTED
        code = "ok"
        message = UNLOCK_LAG_MESSAGE
    elif every:
        if sent is None:
            state = STATE_CONFIRM_UNKNOWN
            code = _link_code(lost)
            if _refused_before_send(lost):
                # Nothing left this host: the confirm never reached the DC.
                message = (
                    UNLOCK_CONFIRM_NOT_SENT_MESSAGE if unlock else CONFIRM_NOT_SENT_MESSAGE
                )
            else:
                message = (
                    UNLOCK_CONFIRM_UNKNOWN_MESSAGE if unlock else CONFIRM_UNKNOWN_MESSAGE
                )
        elif sent.get("code") == "ok":
            state = STATE_CONFIRMED
            code = "ok"
        elif dc_record is not None and dc_record.get("state") == "confirmed":
            # The DC recorded the confirm and then answered it with an
            # error (its record was replaced, a later flush failed): the
            # record reads confirmed and the undo finds it so.
            state = STATE_CONFIRMED
            code = "ok"
            message = CONFIRMED_ON_RECORD_MESSAGE
            undo = {"dc_state": "confirmed"}
        elif ran is not None:
            # The DC had already run the undo (undo_at passed, or an abort
            # ran it), and its record says what the undo did.
            state = STATE_NOT_CONFIRMED
            code = sent.get("code")
            message = CONFIRM_AFTER_UNDO_MESSAGE
            undo = {
                "restored": ran.get("restored"),
                "conflicts": ran.get("conflicts"),
                "dc_state": ran.get("state"),
            }
        else:
            # The DC answered the confirm with something other than ok, and
            # its record does not read confirmed, or could not be read (then
            # Newton does not know whether the confirm was recorded).  The
            # message says only what the DC's record holds; an unlock stays
            # written.
            state = STATE_NOT_CONFIRMED
            code = sent.get("code")
            if unlock:
                message = (
                    UNLOCK_CONFIRM_CONFLICT_MESSAGE
                    if code == "conflict"
                    else UNLOCK_NOT_CONFIRMED_MESSAGE
                )
            elif dc_record is None:
                message = NOT_CONFIRMED_NO_RECORD_MESSAGE
            elif dc_record.get("state") == "armed":
                message = NOT_CONFIRMED_MESSAGE
                undo = {"dc_state": "armed"}
            else:
                message = NOT_CONFIRMED_STATE_MESSAGE
                undo = {"dc_state": dc_record.get("state")}
    elif ran is not None:
        # The abort found the record no longer armed: the DC's own timer
        # or start-up sweep ran the undo first.  Its record says what the
        # undo did.
        record = ran
        state = STATE_NOT_TESTED
        code = "conflict"
        message = ABORT_ALREADY_RAN_MESSAGE
        undo = {
            "restored": record.get("restored"),
            "conflicts": record.get("conflicts"),
            "dc_state": record.get("state"),
        }
    elif sent is None or sent.get("code") != "ok":
        # Newton does not know whether the undo ran: neither restored nor
        # conflicts are known.
        state = STATE_ABORT_FAILED
        code = _link_code(lost) if sent is None else sent.get("code")
        # An abort the runner refused before it left this host did not run.
        message = (
            ABORT_NOT_SENT_MESSAGE
            if sent is None and _refused_before_send(lost)
            else ABORT_FAILED_MESSAGE
        )
        undo = {"restored": None, "conflicts": None}
    else:
        state = STATE_NOT_TESTED
        code = sent.get("code")
        undo = {
            "restored": sent.get("restored"),
            "conflicts": sent.get("conflicts"),
        }
    said = {} if message is None else {"message": message}

    receipt = {
        "v": 1,
        "plan_id": plan_id,
        "txid": plan["txid"],
        "device": plan["device"],
        "verb": plan["verb"],
        "risk": plan.get("risk"),
        "window": plan.get("window"),
        "target": plan.get("target"),
        "before": plan.get("before"),
        "after": plan.get("after"),
        "state": state,
        "code": code,
        "dcs": states,
        **undo,
        **said,
        "created_at": created.isoformat(),
    }
    receipt_error = _write_receipt(plan_id, receipt)
    return _with_receipt_error({
        "result": "ok" if state == STATE_CONFIRMED else "error",
        "plan_id": plan_id,
        "state": state,
        "code": code,
        "dcs": states,
        **undo,
        **said,
    }, receipt_error, secret_error)


def _status_of(sender: Send, pdc: Any, plan: Mapping[str, Any]) -> dict[str, Any] | None:
    """The DC's record of the transaction, or None when it was not read."""
    record = _try_send(
        sender,
        pdc,
        {"v": 1, "mode": "status", "device": plan["device"], "txid": plan["txid"]},
    )
    if isinstance(record, dict) and record.get("code") == "ok":
        return record
    return None


def _verify(
    reader: Callable[[Any, Mapping[str, Any], float], dict[str, Any]],
    dcs: list[Any],
    plan: Mapping[str, Any],
    poll_s: float,
    timeout_s: float,
    sleep: Callable[[float], None],
    clock: Callable[[], float],
    readback_deadline: float,
) -> dict[str, dict[str, Any]]:
    """Read the target back from every DC until every one shows the after-image.

    The image matched is the answer's ``outcome``, never its planning image
    ``live``: each DC binds as its own account, and a value its bind cannot
    read is an empty outcome there (a missing quota or lockoutTime reads 0
    in ``live``).  An answer with no outcome never matches.

    Each DC has its own ``timeout_s``, counted from its first read.  The
    read-back as a whole ends at ``readback_deadline``: no read starts
    after it, each read session is given only the time left before it
    (``reader``'s third argument), and a DC not read by then is
    not_tested, so the confirm or abort still reaches the PDC before its
    undo runs.

    The deadlines are read from the clock, so a test that injects one
    waits exactly as long as the timeout and no longer.
    """
    states: dict[str, dict[str, Any]] = {}
    read_request = _read_request(plan)
    after = plan["after"]
    for device in dcs:
        state = "not_tested"
        live: Any = None
        deadline = min(clock() + timeout_s, readback_deadline)
        while True:
            left = readback_deadline - clock()
            if left <= 0:
                break
            try:
                answer = reader(device, read_request, left)
            except Exception:
                answer = {}
            if answer.get("code") == "ok":
                live = answer.get("outcome")
                if isinstance(live, dict) and live == after:
                    state = "matched"
                    break
            remaining = deadline - clock()
            if remaining <= 0:
                break
            sleep(min(poll_s, remaining) if poll_s > 0 else 0)
        states[device.name] = {"state": state, "live": live}
    return states


def _not_found_message(plan_id: str, plan: Mapping[str, Any]) -> str:
    """What a not_found from the DC means, given the receipt on this host:
    it never offers an apply that ``_apply_change`` would refuse."""
    path = store.receipt_path(plan_id)
    try:
        receipt: Any = store.read_json(path) if path.exists() else None
    except (OSError, ValueError):
        return EARLIER_NOT_FOUND_MESSAGE
    if isinstance(receipt, dict) and receipt.get("pending") is True:
        # With a pending receipt (an apply was about to be sent) only now is
        # nothing changed known.
        return PENDING_NOT_FOUND_MESSAGE
    if receipt is not None and (
        not isinstance(receipt, dict) or receipt.get("state") != STATE_REFUSED
    ):
        return EARLIER_NOT_FOUND_MESSAGE
    if plan.get("verb") == "user-create" and not isinstance(plan.get("secret"), str):
        return SPENT_NOT_FOUND_MESSAGE
    return NOT_FOUND_MESSAGE


def _refused_status_message(plan_id: str, plan: Mapping[str, Any]) -> str:
    """The reason of a change the DC holds refused: the receipt of its apply
    on this host keeps it (the DC's record keeps the state only)."""
    try:
        receipt = store.read_json(store.receipt_path(plan_id))
    except (OSError, ValueError):
        receipt = None
    if (
        isinstance(receipt, dict)
        and receipt.get("state") == STATE_REFUSED
        and receipt.get("txid") == plan.get("txid")
        and isinstance(receipt.get("message"), str)
        and str(receipt["message"]).startswith(DC_REFUSED_MESSAGE)
    ):
        return str(receipt["message"])
    if plan.get("verb") == "user-create" and not isinstance(plan.get("secret"), str):
        return f"{REFUSED_STATUS_MESSAGE} {DC_REFUSED_USER_CREATE_STEP}"
    return REFUSED_STATUS_MESSAGE


def change_status(
    plan_id: str,
    *,
    domain: str | None = None,
    send: Send | None = None,
    devices: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """The state of one change, as the domain controller holds it."""
    plan = _load_plan(plan_id, domain)
    inventory_devices = _plan.load_devices(devices)
    pdc = _pdc_of(plan, inventory_devices)
    sender = send if send is not None else transport.send
    try:
        answer = sender(
            pdc,
            {
                "v": 1,
                "mode": "status",
                "device": plan["device"],
                "txid": plan["txid"],
            },
        )
    except LINK_ERRORS as exc:
        return {
            "result": "error",
            "plan_id": plan_id,
            "txid": plan["txid"],
            "code": _link_code(exc),
            "state": None,
            "message": (
                STATUS_NOT_SENT_MESSAGE if _refused_before_send(exc) else STATUS_LOST_MESSAGE
            ),
        }
    result: dict[str, Any] = {
        "result": "ok" if answer.get("code") == "ok" else "error",
        "plan_id": plan_id,
        "txid": plan["txid"],
        "code": answer.get("code"),
        "state": answer.get("state"),
        "undo_at": answer.get("undo_at"),
        "restored": answer.get("restored"),
        "conflicts": answer.get("conflicts"),
    }
    if answer.get("code") == "error":
        result["message"] = STATUS_ERROR_MESSAGE
    if answer.get("code") == "not_found":
        # The DC holds no record of the txid.
        result["message"] = _not_found_message(plan_id, plan)
    if answer.get("code") in INSTALL_CODES:
        result["message"] = HELPER_REFUSED_MESSAGE
    if answer.get("code") == "ok" and answer.get("state") == STATE_REFUSED:
        result["message"] = _refused_status_message(plan_id, plan)
    if plan.get("verb") == "unlock" and answer.get("state") == "armed":
        # An unlock arms no undo: its armed record is one the DC could not
        # settle, and nothing runs at its undo_at.
        result["message"] = UNLOCK_ARMED_MESSAGE
    return result


#: The answer to the abort of a confirmed change.  The text is Newton's
#: own, never the directory's.
CONFIRMED_ABORT_MESSAGE = (
    "This change is already confirmed, so abort cannot reverse it. Abort "
    "works only on an armed change (one whose confirm was lost). To reverse "
    "a confirmed change, plan the opposite change with newton_ad_plan_change "
    "and approve it (enable for disable, member-remove for member-add, the "
    "old value for enc-types, maq or move). A uac-clear and a user-create "
    "have no opposite verb: the owner reverses them with the admin tools."
)


#: The answer to the abort of an unlock: it has no undo and no opposite verb.
UNLOCK_ABORT_MESSAGE = (
    "An unlock has no undo, so abort cannot reverse it: once written it "
    "stays written, and the DC normally records it confirmed then (a DC "
    "that cannot write that record keeps it armed). dc_state is the domain "
    "controller's record of it."
)


def _abort_lost_message(unlock: bool, exc: BaseException) -> str:
    """What the owner is told when the abort tool's session failed: an
    abort the runner refused before it left this host was not sent."""
    if _refused_before_send(exc):
        return UNLOCK_ABORT_NOT_SENT_MESSAGE if unlock else ABORT_TOOL_NOT_SENT_MESSAGE
    return UNLOCK_ABORT_LOST_MESSAGE if unlock else ABORT_LOST_MESSAGE


def abort_change(
    plan_id: str,
    *,
    domain: str | None = None,
    send: Send | None = None,
    devices: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Abort one change: the domain controller puts the before-image back."""
    plan = _load_plan(plan_id, domain)
    inventory_devices = _plan.load_devices(devices)
    pdc = _pdc_of(plan, inventory_devices)
    sender = send if send is not None else transport.send
    try:
        answer = sender(
            pdc,
            {
                "v": 1,
                "mode": "abort",
                "device": plan["device"],
                "txid": plan["txid"],
            },
        )
    except LINK_ERRORS as exc:
        return {
            "result": "error",
            "plan_id": plan_id,
            "txid": plan["txid"],
            "code": _link_code(exc),
            "state": None,
            "restored": None,
            "conflicts": None,
            "message": _abort_lost_message(plan.get("verb") == "unlock", exc),
        }
    if plan.get("verb") == "unlock":
        # An unlock has no undo, whatever the helper answered (an older
        # Samba helper answered ok, restored false): the state is the DC's
        # own record, never undone or undo_failed derived from restored.
        record = _status_of(sender, pdc, plan) or {}
        return {
            "result": "error",
            "plan_id": plan_id,
            "txid": plan["txid"],
            "code": answer.get("code"),
            "state": None,
            "dc_state": record.get("state"),
            "restored": None,
            "conflicts": None,
            "message": UNLOCK_ABORT_MESSAGE,
        }
    ok = answer.get("code") == "ok"
    message = None
    if answer.get("code") == "conflict":
        # Both helpers abort only an armed change.  A confirmed one is
        # reversed by a new plan of the opposite change.  A status that
        # cannot be read adds no message.
        status = _try_send(sender, pdc, {
            "v": 1,
            "mode": "status",
            "device": plan["device"],
            "txid": plan["txid"],
        }) or {}
        if status.get("code") == "ok" and status.get("state") == "confirmed":
            message = CONFIRMED_ABORT_MESSAGE
    elif answer.get("code") == "not_found":
        # No record of the txid: there was nothing on the DC to abort.
        message = f"Nothing was aborted: {_not_found_message(plan_id, plan)}"
    elif answer.get("code") == "error":
        message = ABORT_ERROR_MESSAGE
    elif answer.get("code") in INSTALL_CODES:
        message = HELPER_REFUSED_MESSAGE
    restored = answer.get("restored")
    # The abort answer carries no state: for every verb but an unlock
    # (handled above), both helpers record ``undone`` exactly when the undo
    # restored the before-image, ``undo_failed`` otherwise, so the state is
    # named by the same rule.  A refused abort claims no state at all.
    state = ("undone" if restored is True else "undo_failed") if ok else None
    result: dict[str, Any] = {
        "result": "ok" if ok else "error",
        "plan_id": plan_id,
        "txid": plan["txid"],
        "code": answer.get("code"),
        "state": state,
        "restored": restored,
        "conflicts": answer.get("conflicts"),
    }
    if message is not None:
        result["message"] = message
    return result
