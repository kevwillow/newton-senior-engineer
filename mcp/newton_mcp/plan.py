"""Canonical Newton plan identity.

A persisted plan record carries the identity fields listed in
``PLAN_HASH_FIELDS`` plus ``created_at``, the router-derived facts
``manifest_checks`` / ``manifest_checks_auto``, the risk word ``risk``
and the computed ``plan_hash``.

The plan hash covers every field in ``PLAN_HASH_FIELDS`` (the sealed
probe list, the router's plan digest, the agent's explanation, the
wall-clock of the last live stage on the device, and the displayed
router facts ``reasons``, ``router_profile``, ``router_leash``,
``router_sections`` and ``router_requires_approval``) and the
staged-config check result ``staged_check``.  It also covers
``consent_basis`` when the record carries it: the basis says
WHO consented to the plan -- the owner in the chat, or a live grant --
so it is part of what an approval binds.  Creation time and any
non-listed bookkeeping are metadata.  Canonical JSON uses
lexicographically sorted keys, no insignificant whitespace, UTF-8 text,
and JSON's normal escaping rules with non-ASCII characters left
unescaped.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any


PLAN_HASH_FIELDS = (
    "device",
    "host",
    "session_id",
    "uci_batch",
    "diff",
    "probes",
    "timeout_s",
    "base_hash",
    "requires_approval",
    "router_digest",
    # the agent's explanation and the owner's chat yes are part of
    # what an approval binds.  Editing either on a stored record, or
    # approving a plan whose explanation later changed, must not verify.
    "explanation",
    "owner_confirmed_in_chat",
    # staged_at is the wall-clock of the LAST live stage on the
    # device; approve.py uses it to compute the router's stage window.
    # Editing only the timestamp on a stored record must invalidate the
    # hash, otherwise a future staged_at silently bypasses the
    # host-side expiry check.
    "staged_at",
    # the displayed risk reasons and the router-derived facts
    # (profile, leash, sections, the router's "approval required" flag)
    # are bound by the plan hash.  newton-approve prints them
    # (approve.py:319, 472, 507-510) so an edited plan file can swap
    # what the operator sees after the fact.  Editing any of these on a
    # stored record -- or trying to apply one written before this
    # change -- must invalidate the hash; no compatibility path.
    "reasons",
    "router_leash",
    "router_profile",
    "router_sections",
    "router_requires_approval",
    # The result of the check of the STAGED config (fw4 check on the staged
    # files, plus the list of touched packages nothing could check).  An approval
    # binds to it: a plan that was not checked cannot be swapped for one that was.
    "staged_check",
)


def canonical_plan_json(record: Mapping[str, Any]) -> str:
    """Return the one canonical JSON representation used for plan identity."""
    missing = [field for field in PLAN_HASH_FIELDS if field not in record]
    if missing:
        raise ValueError(f"plan record is missing: {', '.join(missing)}")
    payload = {field: record[field] for field in PLAN_HASH_FIELDS}
    # The consent basis says WHO consented to this plan -- the
    # owner in the chat, or a live grant.  When the record carries it, it
    # is part of the identity, so a stored record cannot be edited from
    # "grant" to "chat" (or back) and still verify.  A record WITHOUT
    # the key is an old-style record (the owner confirmed in chat): its
    # canonical payload must not grow, or every plan already on disk
    # would stop verifying.
    if "consent_basis" in record:
        payload["consent_basis"] = record["consent_basis"]
    return json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def compute_plan_hash(record: Mapping[str, Any]) -> str:
    """Return lowercase SHA-256 of UTF-8 encoded canonical plan JSON."""
    return hashlib.sha256(canonical_plan_json(record).encode("utf-8")).hexdigest()


#: The router facts the digest of a no-install record binds.
ROUTER_DIGEST_FIELDS = (
    "router_leash",
    "base_hash",
    "ops",
    "section_types",
    "risk",
)


def router_digest(record: Mapping[str, Any]) -> str:
    """The digest that binds the router facts of a no-install record.

    The plan hash does not cover the ops, so this is what binds them.
    The digest covers the leash, the base hash and the ops, and also
    the two facts the apply reads from the router again: the type of
    every section the change touches and the risk the policy gave the
    change.  A record whose types or risk were edited on disk does not
    verify against this digest, and the apply recomputes both from the
    router anyway.

    The function lives here, and not in the flow that writes the
    record, because the approval dialog has to check the digest too
    and it may not import the flow (the flow imports the server).
    """
    payload = {field: record.get(field) for field in ROUTER_DIGEST_FIELDS}
    canonical = json.dumps(
        payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
