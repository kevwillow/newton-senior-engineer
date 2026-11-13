"""The errors of the AD write path.

One exception carries a message the model may read.  The refusal of a
request itself is ``request.RequestRefused``: it carries the code of the
contract and it belongs to the helper.  This one is Newton's own: the
plan could not be built, the apply could not run, the inventory does not
hold the entries the domain needs.
"""

from __future__ import annotations


class WriteError(Exception):
    """The AD write path refuses, with a message for the model."""
