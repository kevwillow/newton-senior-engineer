"""The Newton side of the Active Directory build (DESIGN-1.5, PLAN-1.5).

The package holds the model of the build plan (``plan``): the grammar
of its inputs, the canonical bytes the owner approves, the digest of
those bytes, the digest of a stage, the stage graph of every server and
the two secrets derived from the server's key.

It holds the bootstrap of a server (``bootstrap``), the script the
owner runs once on the fresh server, and the token rule of every stage
(``stage_token``), which refuses the stage whose kind the token rules
of the design do not cover.

Nothing in the package opens a socket or reads a clock, and the one
file it reads is the build helper, which the bootstrap reads; it reads
nothing else and writes nothing.  The plan is a document, and the
document is what every later packet signs.
"""

from __future__ import annotations
