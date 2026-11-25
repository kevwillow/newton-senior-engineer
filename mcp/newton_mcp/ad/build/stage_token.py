"""The token rule of every stage (DESIGN-1.5 "Tokens").

The design gives every stage one of three kinds and two kinds of
token: the plan token, per server, covers the stages of the plan that
are ``read`` or ``reversible``, and a stage token, per server and per
irreversible stage, covers the rest.

Stage 9 is of the kind ``final``: it removes the build account and
the helper.  The plan token covers it (the maintainer, 2026-11-13), the way it
covers the reversible stages, and no stage token ever opens it.  It
still runs only in its turn: the helper refuses it out of order like
any other stage.

This module is the rule of the host side.  The helper holds the same
rule, and the two must answer the same way.
"""

from __future__ import annotations

from .plan import STAGE_IDS, STAGE_KINDS


#: The kind of the token that covers each kind of stage.  The kinds
#: the design gives to the stages are the three of the stage table.
TOKEN_KINDS: dict[str, str] = {
    "read": "plan",
    "reversible": "plan",
    "irreversible": "stage",
    # The maintainer, 2026-11-13: the final stage runs under the plan approval.
    "final": "plan",
}

#: The kind of the final stage.
FINAL_KIND = "final"

#: The final stage: the cleanup, covered by the plan token.
FINAL_STAGE = "9"

#: The code the refusal of a stage carries.
REFUSAL_CODE = "schema"


class StageTokenRefused(Exception):
    """A stage is refused with one of the codes of the rule.

    The code is the word the caller answers with; the message is for
    the log and for the owner.
    """

    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(message or code)
        self.code = code
        self.message = message or code


def token_kind(stage: str) -> str:
    """The kind of the token that covers one stage.

    ``plan`` for the stages of the plan that are ``read``,
    ``reversible`` or ``final`` (stage 9, the maintainer, 2026-11-13), ``stage`` for
    the irreversible ones.

    Raises ``StageTokenRefused`` with the code ``schema`` for a stage
    that is not one of the design.
    """
    if not isinstance(stage, str) or stage not in STAGE_IDS:
        raise StageTokenRefused(
            REFUSAL_CODE, "the stage is not one of the stages of the design"
        )
    return TOKEN_KINDS[STAGE_KINDS[stage]]
