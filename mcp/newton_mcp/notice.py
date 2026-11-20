"""The fixed result notice shown after a change attempt.

The owner and the agent need the same short sentence, with the same outcome
word every time.  The summary comes from Newton's deterministic description
of the staged change, never from router output.
"""

from __future__ import annotations

from typing import Any


_CONFIRMED = "CONFIRMED"
_ROLLED_BACK = "ROLLED BACK"
_UNKNOWN = "UNKNOWN"
_NOT_APPLIED = "NOT APPLIED"
_HELD = "APPLIED, NOT CONFIRMED YET"
_NOT_CONFIRMED = "NOT CONFIRMED"
_CHECK_ROUTER = "Check the router before doing anything else."
_CONFIRM_OR_ABORT = "Confirm or abort it before the window closes."


def result_line(
    result: dict[str, Any],
    device: str,
    session_id: str,
    summary: str,
    grant_note: str = "",
) -> str:
    """Return the one-line NEWTON RESULT notice for one change attempt."""
    word = _NOT_APPLIED
    if isinstance(result, dict) and "error" not in result:
        outcome = result.get("result")
        if outcome == "confirmed":
            word = _CONFIRMED
        elif outcome == "rolled_back":
            word = _ROLLED_BACK
        elif outcome == "unknown":
            word = _UNKNOWN
        elif outcome == "held":
            word = _HELD
        elif outcome == "not_confirmed":
            word = _NOT_CONFIRMED
    summary_lines = str(summary).splitlines()
    summary_line = summary_lines[0] if summary_lines else ""
    line = (
        f"NEWTON RESULT: {word}  {device}  {session_id[:8]}  {summary_line}"
    )
    if grant_note:
        note_line = str(grant_note).splitlines()[0]
        line += f"  ({note_line})"
    if word in {_ROLLED_BACK, _UNKNOWN, _NOT_CONFIRMED}:
        line += f"  {_CHECK_ROUTER}"
    if word == _HELD:
        line += f"  {_CONFIRM_OR_ABORT}"
    return line
