"""Split a tier .uci into probe-safe batches, resolve placeholders.

The router's sealed-probe cap is 32 lines and 4096 bytes (design 3.6,
mirrored in ``newton_mcp.probes``).  Hardened and Lockdown, lab-bound
controls excluded, seal 31 and 30 lines in all; a batch also leaves room
for the most expect claims, so a tier is split by the cap less that
reserve and not by a fixed count.  This module reads the
generated ``<tier>.uci`` next to the manifest, classifies each block
(lab-bound / conditional / empty / active), and partitions the active
ones in MANIFEST order into batches that each fit the cap.  A
control's active lines are never split across batches: the planner
keeps one block per plan.

The module is pure (no I/O other than reading the tier .uci file next
to ``manifest_path()``, so the ``NEWTON_MANIFEST`` override moves
both).  It does not ssh, does not touch device state, and contains no
lab names / hosts / paths in the code paths.  The router cap is read
through ``probes.MAX_PROBE_LINES`` / ``probes.MAX_PROBES_BYTES`` at
call time so a test can monkeypatch the caps and exercise the
overflow path without rewriting the manifest.

Placeholders are ``{name}`` (name = ``[a-z][a-z0-9_]{0,31}``).  They
are resolved by simple single-pass substitution (``str.replace``) so a
value can never inject another placeholder, and ``validate_values``
refuses any value that is not a single bounded token (so a value can
never inject a quote, space, newline, brace or shell meta-character).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from . import probes, touched
from .explanation import MAX_CLAIMS


TIER_NAMES: tuple[str, ...] = ("standard", "hardened", "lockdown")

# the agent's expect claims (up to MAX_CLAIMS) are sealed as probe lines
# after the batch's own, under the same 32-line / 4096-byte router cap.  A batch
# is sized to leave room for the most claims, so ``newton_plan_tier`` can plan
# every batch with any allowed explanation.  The byte reserve is for the
# longest ``uci_equals`` claim the router accepts: ``uci-equals`` TAB path (a
# field is at most 128) TAB equals (at most 128) LF.
CLAIM_RESERVE_LINES = MAX_CLAIMS
MAX_CLAIM_SEALED_BYTES = len("uci-equals") + 128 + 128 + 2 + 1
CLAIM_RESERVE_BYTES = MAX_CLAIMS * MAX_CLAIM_SEALED_BYTES


class TierError(ValueError):
    """A tier split / placeholder / value violation; the message names
    the offending control id or placeholder name and never echoes a bad
    value."""


_HEADER_RE = re.compile(r"^# (OW-[A-Z0-9]+-[0-9]+) (.*)$")
_LAB_BOUND_RE = re.compile(r"^\s*#\s*lab-bound:")
_CONDITIONAL_RE = re.compile(r"^\s*#\s*conditional:")
_CONDITIONAL_PKG_RE = re.compile(r"package\s+([A-Za-z0-9_.+-]+)")
_NAME_RE = re.compile(r"[a-z][a-z0-9_]{0,31}")
_PLACEHOLDER_RE = re.compile(r"\{([a-z][a-z0-9_]{0,31})\}")
_ANON_SELECTOR_RE = re.compile(r"^@[a-z_]+\[-?[0-9]{1,3}\]$")
_BARE_VALUE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")


# ---- file parsing ------------------------------------------------------------


def _parse_tier_file(path: Path) -> list[dict[str, Any]]:
    """Parse ``<tier>.uci`` into per-control blocks.

    Each block is ``{"id", "title", "body": [lines]}``; the header line
    (``# OW-XXX-NN title``) and the comment markers
    (``# lab-bound:`` / ``# conditional:`` / ``# no lines of its own``)
    stay INSIDE the block so the classifier can see them.  The header
    regex matches ``build.py``'s output exactly.
    """
    blocks: list[dict[str, Any]] = []
    cur: dict[str, Any] | None = None
    for raw in path.read_text(encoding="utf-8").splitlines():
        m = _HEADER_RE.match(raw)
        if m:
            if cur is not None:
                blocks.append(cur)
            cur = {"id": m.group(1), "title": m.group(2), "body": []}
            continue
        if cur is None:
            continue
        cur["body"].append(raw)
    if cur is not None:
        blocks.append(cur)
    return blocks


def _classify_block(body: list[str]) -> tuple[str, list[str], str | None]:
    """Return ``(kind, active_lines, conditional_package)``.

    ``kind`` is one of:

    * ``"lab-bound"``        -- the block carries a ``# lab-bound:``
      comment marker; the operator's lab runs those batches, the
      planner must NEVER carry them.  ``active_lines`` is the block's
      active lines.  They are NOT included in any batch's text; the
      batch's probe cap is sized from the batch's OWN text only.
    * ``"conditional"``      -- a ``# conditional: needs package ...``
      marker names a package the router does not have; every batch
      line is commented out in the .uci, so ``active_lines`` is
      ``[]``.  Refused with reason starting ``"conditional"`` naming
      the package.
    * ``"active"``           -- no marker; ``active_lines`` is the
      block's non-empty, non-comment lines.
    * ``"empty"``            -- no marker AND no active lines
      (e.g. ``# no lines of its own ...``).  Not skipped, not batched.
    """
    lab_bound = False
    conditional_pkg: str | None = None
    active: list[str] = []
    for line in body:
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            if _LAB_BOUND_RE.match(line):
                lab_bound = True
                continue
            cm = _CONDITIONAL_RE.match(line)
            if cm:
                pm = _CONDITIONAL_PKG_RE.search(line)
                if pm is not None:
                    conditional_pkg = pm.group(1)
                continue
            continue
        active.append(line)
    if lab_bound:
        return "lab-bound", active, None
    if conditional_pkg is not None:
        return "conditional", [], conditional_pkg
    if not active:
        return "empty", [], None
    return "active", active, None


# ---- batch arithmetic --------------------------------------------------------


def _batch_probes(
    text: str,
    controls: list[dict[str, Any]],
) -> tuple[list[int], int, int]:
    """The same totals ``plan()`` would compute for ``text``.

    Returns ``(entry_indexes, line_count, byte_count)``.  The byte
    count uses ``touched.sealed_probes_bytes`` of every entry's
    probes (in manifest order), so the operator can see the cap the
    router would enforce.  The caps are read at call time from
    ``probes`` so a test can monkeypatch ``probes.MAX_PROBE_LINES``.
    """
    indexes = touched.touched_entries(controls, text, "", [])
    line_count = 0
    byte_count = 0
    for idx in indexes:
        ctl_probes = controls[idx].get("probes")
        if not isinstance(ctl_probes, list):
            continue
        line_count += len(ctl_probes)
        byte_count += touched.sealed_probes_bytes(ctl_probes)
    return indexes, line_count, byte_count


# ---- public API --------------------------------------------------------------


def split_tier(
    tier: str,
    *,
    controls: list[dict[str, Any]] | None = None,
    directory: Path | None = None,
    max_lines: int | None = None,
    max_bytes: int | None = None,
) -> dict[str, Any]:
    """Partition ``<tier>.uci`` into probe-safe batches in manifest order.

    Returns ``{"tier", "batches", "skipped"}``.  Each batch is
    ``{"index", "control_ids", "lines", "text", "probe_lines",
    "probe_bytes", "placeholders"}``.  ``skipped`` is a list of
    ``{"id", "reason"}`` for lab-bound and conditional blocks.

    Lab-bound and conditional blocks never touch any batch's text or
    ``control_ids`` (the planner must NEVER carry them; the operator
    sees them in ``skipped``).  Blocks with no active lines are
    ignored.  The active blocks are partitioned in MANIFEST order by a
    simple greedy: a candidate batch is ``current_text + block_text``,
    the candidate's probe lines / bytes are computed via
    ``_batch_probes``, and if the current batch is non-empty AND the
    candidate exceeds ``max_lines`` or ``max_bytes``, the current
    batch is closed and the block starts a new one.  A block whose
    text alone exceeds the cap is refused with ``TierError`` naming
    its id (split it before retrying).

    ``max_lines`` / ``max_bytes`` default to ``probes.MAX_PROBE_LINES``
    / ``probes.MAX_PROBES_BYTES`` read at call time (so a test can
    monkeypatch the caps), less ``CLAIM_RESERVE_LINES`` /
    ``CLAIM_RESERVE_BYTES`` so each batch has room for the most expect
    claims.  A value larger than the router cap is
    refused -- a caller can be stricter, never looser, than the
    router's seal.  A value smaller than 1 is refused.

    ``controls`` defaults to the manifest under ``NEWTON_MANIFEST``
    (or the real ``profiles/openwrt/manifest.toml``).  ``directory``
    defaults to the directory of ``probes.manifest_path()`` so the
    override moves the .uci files too.
    """
    if tier not in TIER_NAMES:
        raise TierError(f"unknown tier: {tier!r}")
    if controls is None:
        controls = probes._load_controls(probes.manifest_path())
    if directory is None:
        directory = Path(probes.manifest_path()).parent
    if max_lines is None:
        max_lines = max(1, probes.MAX_PROBE_LINES - CLAIM_RESERVE_LINES)
    if max_bytes is None:
        max_bytes = max(1, probes.MAX_PROBES_BYTES - CLAIM_RESERVE_BYTES)
    if not isinstance(max_lines, int) or max_lines < 1:
        raise TierError(
            f"max_lines must be a positive integer (>= 1), got {max_lines!r}"
        )
    if not isinstance(max_bytes, int) or max_bytes < 1:
        raise TierError(
            f"max_bytes must be a positive integer (>= 1), got {max_bytes!r}"
        )
    if max_lines > probes.MAX_PROBE_LINES:
        raise TierError(
            f"max_lines={max_lines} is larger than the router cap"
            f" {probes.MAX_PROBE_LINES}; a caller can only be stricter"
            f" than the router, never looser"
        )
    if max_bytes > probes.MAX_PROBES_BYTES:
        raise TierError(
            f"max_bytes={max_bytes} is larger than the router cap"
            f" {probes.MAX_PROBES_BYTES}; a caller can only be stricter"
            f" than the router, never looser"
        )
    tier_path = directory / f"{tier}.uci"
    if not tier_path.is_file():
        raise TierError(f"tier file not found: {tier_path}")

    blocks = _parse_tier_file(tier_path)

    skipped: list[dict[str, str]] = []
    classified: list[tuple[str, str, list[str]]] = []
    for block in blocks:
        kind, active, pkg = _classify_block(block["body"])
        if kind == "lab-bound":
            skipped.append({
                "id": block["id"],
                "reason": "lab-bound: names an interface, zone or address"
                " that exists only in the lab",
            })
            continue
        if kind == "conditional":
            skipped.append({
                "id": block["id"],
                "reason": f"conditional: needs package {pkg};"
                          " lines are commented out below",
            })
            continue
        if kind == "empty":
            continue
        classified.append(("active", block["id"], active))

    batches: list[dict[str, Any]] = []
    cur_lines: list[str] = []        # the lines for the next batch.text
    cur_control_ids: list[str] = []

    def close_batch() -> None:
        nonlocal cur_lines, cur_control_ids
        if not cur_control_ids:
            cur_lines = []
            cur_control_ids = []
            return
        text = "\n".join(cur_lines) + "\n"
        # The batch's probe line/byte totals are computed from the
        # batch's OWN text (the planner ships this text; the cap is
        # checked against it).  ``seal_manifest_ids`` is called on
        # the same text by the MCP server.
        _, line_count, byte_count = _batch_probes(text, controls)
        batches.append({
            "index": len(batches),
            "control_ids": list(cur_control_ids),
            "lines": list(cur_lines),
            "text": text,
            "probe_lines": line_count,
            "probe_bytes": byte_count,
            "placeholders": tier_placeholders(text),
        })
        cur_lines = []
        cur_control_ids = []

    def _overflow_message(cid: str, line_count: int, byte_count: int) -> str:
        return (
            f"control {cid} alone seals {line_count} probe lines /"
            f" {byte_count} probe bytes, more than the {max_lines}-line /"
            f" {max_bytes}-byte cap; split it before retrying"
        )

    for kind, cid, active in classified:
        # candidate_lines is the lines of the current batch + the new
        # block: exactly what plan() would seal for that batch's text.
        # Lab-bound text is excluded (it never touches any batch's text).
        candidate_lines = cur_lines + active
        candidate_text = "\n".join(candidate_lines) + "\n" if candidate_lines else ""
        _, cand_probe_lines, cand_probe_bytes = _batch_probes(
            candidate_text, controls
        )
        if cand_probe_lines > max_lines or cand_probe_bytes > max_bytes:
            if not cur_control_ids:
                # The block alone overflows: an operator error, not a
                # batch boundary.
                raise TierError(_overflow_message(
                    cid, cand_probe_lines, cand_probe_bytes
                ))
            # Close the current batch (its lines stay small) and start
            # a new one with this block alone.  The block alone must
            # fit -- if not, refuse (a block we cannot place is an
            # operator error).
            close_batch()
            solo_text = "\n".join(active) + "\n"
            _, solo_lines, solo_bytes = _batch_probes(solo_text, controls)
            if solo_lines > max_lines or solo_bytes > max_bytes:
                raise TierError(_overflow_message(
                    cid, solo_lines, solo_bytes
                ))
            cur_lines = list(active)
            cur_control_ids = [cid]
            continue
        # Fits: commit the block to the current batch.
        cur_lines.extend(active)
        cur_control_ids.append(cid)

    close_batch()
    return {
        "tier": tier,
        "batches": batches,
        "skipped": skipped,
    }


def tier_placeholders(text: str) -> list[str]:
    """Sorted unique ``{name}`` names in ``text`` (``[a-z][a-z0-9_]{0,31}``)."""
    seen: set[str] = set()
    for match in _PLACEHOLDER_RE.finditer(text):
        seen.add(match.group(1))
    return sorted(seen)


def validate_values(values: Any) -> None:
    """Refuse any value/name that could break the substitution.

    Rules:

    * ``values`` must be ``None`` or a ``dict``.
    * every key matches ``[a-z][a-z0-9_]{0,31}``.
    * every value is a ``str`` matching
      ``^(?:@[a-z_]+\\[-?[0-9]{1,3}\\]|[A-Za-z0-9_.:-]{1,64})$``: an
      anonymous-section selector like ``@zone[1]`` or a single
      bounded token (no quote, space, newline, brace, shell
      meta-character, or ``$`` substitution).
    * a bad value's KEY is named in the error message; the bad value
      itself is NEVER echoed (the redactor's job starts here).
    """
    if values is None:
        return
    if not isinstance(values, dict):
        raise TierError("values must be a dict or None")
    for key in values:
        if not isinstance(key, str) or not _NAME_RE.fullmatch(key):
            raise TierError(f"placeholder name {key!r} does not match the"
                            f" required shape [a-z][a-z0-9_]{{0,31}}")
        value = values[key]
        if not isinstance(value, str):
            raise TierError(f"placeholder {key!r} value is not a string")
        if _ANON_SELECTOR_RE.fullmatch(value):
            continue
        if _BARE_VALUE_RE.fullmatch(value):
            continue
        raise TierError(f"placeholder {key!r} value is not a single bounded"
                        f" token (quote, space, newline, brace, ``;``,"
                        f" ``$(...)``, or empty / over-long strings are"
                        f" refused)")


def resolve_batch(
    text: str,
    values: dict[str, str] | None,
    *,
    tier_names: list[str] | None = None,
) -> str:
    """Substitute every ``{name}`` in ``text`` with ``values[name]``.

    ``validate_values`` runs first (so a single bad value refuses the
    whole call).  When ``tier_names`` is given, ``values`` keys must be
    a subset of it (extras are refused by name).  Every placeholder
    referenced by ``text`` must have a value (missing names are
    refused, names sorted).  The substitution is a single pass of
    ``str.replace`` so a value can never inject another placeholder.
    """
    if values is None:
        values = {}
    validate_values(values)
    if tier_names is not None:
        tier_set = set(tier_names)
        extras = sorted(key for key in values if key not in tier_set)
        if extras:
            raise TierError(
                f"value name(s) not in this tier's placeholders: {', '.join(extras)}"
            )
    needed = tier_placeholders(text)
    missing = [name for name in needed if name not in values]
    if missing:
        raise TierError(
            f"missing value for placeholder(s): {', '.join(missing)}"
        )
    out = text
    for name in needed:
        out = out.replace("{" + name + "}", values[name])
    return out


def list_tiers(
    *,
    controls: list[dict[str, Any]] | None = None,
    directory: Path | None = None,
    max_lines: int | None = None,
    max_bytes: int | None = None,
) -> list[dict[str, Any]]:
    """Return the split_tier summary for each of the three tiers.

    ``max_lines`` / ``max_bytes`` are passed through to ``split_tier``
    (default = ``probes.MAX_PROBE_LINES`` / ``probes.MAX_PROBES_BYTES``
    at call time).
    """
    out: list[dict[str, Any]] = []
    if directory is None:
        directory = Path(probes.manifest_path()).parent
    for tier in TIER_NAMES:
        info = split_tier(
            tier,
            controls=controls,
            directory=directory,
            max_lines=max_lines,
            max_bytes=max_bytes,
        )
        non_skipped_ids = {s["id"] for s in info["skipped"]}
        blocks_by_id = {b["id"]: b for b in _parse_tier_file(
            directory / f"{tier}.uci"
        )}
        controls_with_lines = 0
        for cid, block in blocks_by_id.items():
            if cid in non_skipped_ids:
                continue
            if _classify_block(block["body"])[0] == "active":
                controls_with_lines += 1
        placeholders: set[str] = set()
        for batch in info["batches"]:
            placeholders.update(tier_placeholders(batch["text"]))
        out.append({
            "tier": tier,
            "controls": controls_with_lines,
            "batches": len(info["batches"]),
            "probe_lines": sum(b["probe_lines"] for b in info["batches"]),
            "placeholders": sorted(placeholders),
            "skipped": info["skipped"],
        })
    return out