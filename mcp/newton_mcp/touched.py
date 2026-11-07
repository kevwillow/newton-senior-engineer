"""Derive which manifest ``probes`` controls a staged UCI change touches.

ADR-010: a single shared function the MCP server and the lab runner both
call, so the two paths derive the same ids from the same change.  The module
is pure: no I/O at import or call time other than calling
``policy.parse_diff_line`` / ``parse_section_fact_line``.  Manifest parsing
is the caller's job (this module is import-safe from the lab runner that
already imports the same ``newton_mcp.probes``).

A *requirement* is a 5-tuple ``(kind, config, section, option, value)``:

* kind         "set" | "add_list"
* section "name"            a named section
* section "@type[-1]"       a section-creating ``set cfg.sec=type``
* section "@type[i]"         a specific anonymous section by index
* section "@type[*]"         any anonymous section of that type (diff only)
* section "cfgXXXXXX"       a raw anonymous section id the diff did not resolve
* option None               the requirement is section-level (a ``set cfg.sec=type``)
* value        unquoted string; exact string equality after unquoting

A *fact* has the same shape.  Facts come from the staged batch (``set`` /
``add_list`` lines, with their values unquoted) AND from the router diff
(lines parsed with ``policy.parse_diff_line``: only op ``""`` or ``""+""``
with a value satisfy).  ``delete`` / ``del_list`` and the structural verbs
in the staged batch NEVER satisfy a requirement, and ``-`` / ``@`` / ``^``
diff lines NEVER satisfy one either.  Section resolution uses the same
``SECTION`` lines as before: a cfgXXXXXX or named diff section also emits
the ``@<type>[*]`` wildcard form, batch anonymous ``@type[i]`` must match
the exact index on the other side.

Match rules:

* A control with ANY ``{placeholder}`` anywhere in its batch is NEVER
  matched (lab-bound; not convertible on the host).  A control with no
  requirements (only ``delete`` / ``del_list`` lines, or an empty batch)
  is NEVER matched either.  A control without a ``probes`` key is out of
  scope and silently skipped (the older ``check``-based controls).
* A control MATCHES iff EVERY requirement is satisfied by some staged
  fact with the same kind, config, section (per ``_section_match``),
  option and value.  A partial application is never "the control"; no
  auto check, never a false rollback.
* Verb compat: ``import`` / ``commit`` / ``revert`` and any unknown verb
  are silently skipped.  Junk lines (bad quoting, garbage paths) are
  skipped too; this module never raises.

API:

* ``touched_entries(controls, uci_batch, diff, section_lines) -> list[int]``
  -- manifest indexes in manifest order, each once, only entries WITH a
  ``probes`` key.
* ``touched_control_ids(...)`` is the deduped-id view of the same entries
  (kept for messages and the on-disk record).
* ``derive_touched_ids(uci_batch, diff, section_lines)`` stays (lab runner
  convenience: load the manifest and return the deduped ids).
* ``derive_touched_entries(uci_batch, diff, section_lines)`` is the new
  manifest-index counterpart.
* ``needs_restage(sealed_entries, diff_entries)`` compares entry INDEXES.
* ``seal_manifest_ids(caller_ids, auto_entry_indexes, extra_probes=...)``
  validates caller ids by id (refuses an id that names more than one
  entry) and expands auto entries by INDEX (a duplicate-id sibling is
  fine).  Returns ``(sealed_entries, manifest_probes)``; the caller maps
  indexes to ids for messages and the record.

Manifest indexing matters because the same id may name more than one
``[[control]]`` entry (``OW-FW-06`` has one entry with ``'0'`` and one with
``'1'``; ``OW-MGMT-01`` has one ``Interface`` and one ``DirectInterface``
form).  Identifying by INDEX keeps the two forms straight.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from typing import Iterable

from .policy import parse_diff_line, parse_section_fact_line


_NAMED_SEC_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_ANON_SEC_RE = re.compile(r"^@([A-Za-z0-9_-]{1,32})\[(-?[0-9]{1,3}|[*])\]$")
_OPT_RE = re.compile(r"^[A-Za-z0-9_]{1,64}$")
_CFG_RE = re.compile(r"^[a-z0-9_-]{1,32}$")
_CFG_ANON_RE = re.compile(r"^cfg[0-9a-f]{6}$")
_PLACEHOLDER_RE = re.compile(r"\{[a-zA-Z_][a-zA-Z0-9_]*\}")


# Requirement/fact kind values.
_SET = "set"
_ADD_LIST = "add_list"


@dataclass(frozen=True)
class _Requirement:
    """One 5-tuple ``(kind, cfg, section, option, value)``.

    Used as both a requirement (parsed from a control's ``batch``) and a
    fact (parsed from the staged batch or the router diff).  Frozen so
    facts are hashable and dedupable in a set.
    """

    kind: str                # _SET or _ADD_LIST
    cfg: str
    section: str
    option: str | None
    value: str


def _section_kind(section: str) -> tuple[str, str]:
    """``("named", name)`` / ``("anon", type)`` / ``("cfgxxx", id)``."""
    if _CFG_ANON_RE.fullmatch(section):
        return ("cfgxxx", section)
    m = _ANON_SEC_RE.fullmatch(section)
    if m:
        return ("anon", m.group(1))
    return ("named", section)


def _section_index(section: str) -> str:
    """The numeric/wildcard index portion of an anon section, or ``""``."""
    m = _ANON_SEC_RE.fullmatch(section)
    return m.group(2) if m else ""


def _section_match(sec_c: str, sec_s: str) -> bool:
    """Does a control section ``sec_c`` match a staged section ``sec_s``?

    * named == named: exact;
    * anon == anon: same type, then index. Both specific indexes must be
      equal. A wildcard index (``[-1]`` from an ``add`` or ``set cfg.sec=type``,
      ``[*]`` from a diff) matches any specific index on the other side;
    * mixed named/anon or any cfgxxx: no match.
    """
    kc, vc = _section_kind(sec_c)
    ks, vs = _section_kind(sec_s)
    if kc == "named" and ks == "named":
        return vc == vs
    if kc == "anon" and ks == "anon":
        if vc != vs:
            return False
        ix_c = _section_index(sec_c)
        ix_s = _section_index(sec_s)
        if ix_c in {"-1", "*"} or ix_s in {"-1", "*"}:
            return True
        return ix_c == ix_s
    return False


def _split_batch_words(line: str) -> list[str]:
    try:
        return shlex.split(line, posix=True)
    except ValueError:
        return line.split()


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]
    return value


def _parse_batch_path(path: str) -> tuple[str, str, str | None] | None:
    """``cfg.section[.option]`` -> ``(cfg, sec, opt)``; option may carry a
    trailing ``+``/``-`` for list verbs (``option+=v``), and a ``set`` arg
    may have ``=value`` glued on (we strip the value first)."""
    if "=" in path:
        path = path.split("=", 1)[0]
    parts = path.split(".")
    if len(parts) < 2 or len(parts) > 3:
        return None
    cfg = parts[0]
    sec = parts[1]
    opt = parts[2] if len(parts) == 3 else None
    if opt is not None and opt.endswith(("+", "-")):
        opt = opt[:-1]
    if not _CFG_RE.fullmatch(cfg):
        return None
    if not (_NAMED_SEC_RE.fullmatch(sec) or _ANON_SEC_RE.fullmatch(sec)):
        return None
    if opt is not None and not _OPT_RE.fullmatch(opt):
        return None
    return cfg, sec, opt


def _parse_batch_path_with_marker(
    path: str,
) -> tuple[str, str, str | None, str | None] | None:
    """Like ``_parse_batch_path`` but also returns the trailing ``+`` /
    ``-`` on the option (the list verb).  ``marker`` is ``None`` for a
    plain ``option``, ``"+"`` for ``option+``, ``"-"`` for ``option-``.
    """
    if "=" in path:
        path = path.split("=", 1)[0]
    parts = path.split(".")
    if len(parts) < 2 or len(parts) > 3:
        return None
    cfg = parts[0]
    sec = parts[1]
    opt = parts[2] if len(parts) == 3 else None
    marker: str | None = None
    if opt is not None and opt.endswith(("+", "-")):
        marker = opt[-1]
        opt = opt[:-1]
    if not _CFG_RE.fullmatch(cfg):
        return None
    if not (_NAMED_SEC_RE.fullmatch(sec) or _ANON_SEC_RE.fullmatch(sec)):
        return None
    if opt is not None and not _OPT_RE.fullmatch(opt):
        return None
    return cfg, sec, opt, marker


# ---- the new requirement / fact API ----------------------------------------


def _parse_batch_facts(uci_batch: str) -> set[_Requirement]:
    """Staged UCI batch -> set of satisfying facts.

    Facts are LAST-WINS in batch order (defect 2): the router is about
    to commit the batch in order, and a fact set must reflect the final
    on-router state of every (cfg, section, option) the batch touches.

    * ``set cfg.sec.opt='v'``             replaces any earlier set fact
                                          for that ``(cfg, sec, opt)``;
                                          also drops any earlier add_list
                                          facts for the same option
                                          (a plain ``set`` resets the list
                                          to a single value).
    * ``add_list cfg.sec.opt='v'``        adds a fact (one per line).
    * ``del_list cfg.sec.opt='v'`` / ``set cfg.sec.opt-='v'``
                                          removes a matching earlier
                                          add_list fact (and ONLY those
                                          for that value).
    * ``delete cfg.sec.opt``              removes the earlier set / all
                                          add_list facts of that option.
    * ``delete cfg.sec``                  removes every earlier fact of
                                          that section (and the
                                          section-level set fact if any).
    * ``set cfg.sec=type``                changes the type of the section;
                                          the options that are on it stay
                                          on it, so their facts stay too
                                          (only the section's own fact
                                          is replaced).

    Structural verbs (``add`` / ``rename`` / ``reorder``), the staging
    verbs (``import`` / ``commit`` / ``revert``) and junk lines never
    produce or alter facts; junk lines (bad quoting, garbage paths) are
    silently skipped.
    """
    facts: dict[tuple[str, str, str | None], _Requirement] = {}
    add_list_facts: list[_Requirement] = []
    if not isinstance(uci_batch, str):
        return set()
    for raw in uci_batch.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        words = _split_batch_words(line)
        if not words:
            continue
        verb = words[0]
        rest = words[1:]
        if verb == "set" and len(rest) >= 1:
            text = rest[0]
            if "=" not in text:
                continue
            path, _, raw_value = text.partition("=")
            parsed = _parse_batch_path_with_marker(path)
            if parsed is None:
                continue
            cfg, sec, opt, marker = parsed
            if marker == "-":
                # ``set foo.option-='v'`` is UCI sugar for ``del_list
                # foo.option='v'`` (REMOVES ``v``).
                if opt is None:
                    continue
                value = _unquote(raw_value)
                add_list_facts = [
                    f for f in add_list_facts
                    if not (f.cfg == cfg and f.section == sec
                            and f.option == opt and f.value == value)
                ]
                continue
            if marker == "+":
                # ``set foo.option+='x'`` is UCI sugar for
                # ``add_list foo.option='x'``; the kind follows.
                if opt is None:
                    continue
                value = _unquote(raw_value)
                add_list_facts.append(
                    _Requirement(_ADD_LIST, cfg, sec, opt, value)
                )
                continue
            value = _unquote(raw_value)
            key = (cfg, sec, opt)
            if opt is None:
                # A section-level set changes the TYPE of the section.
                # uci keeps the options that are on it, so the facts of
                # those options stay: only the section's own fact is
                # replaced.  A ``delete cfg.sec`` is what takes the
                # whole section away.
                facts.pop(key, None)
                facts[key] = _Requirement(_SET, cfg, sec, opt, value)
            else:
                # option-level set: drop any earlier set for the same
                # option AND drop every earlier add_list for the same
                # option (a plain ``set`` resets the list).
                facts.pop(key, None)
                add_list_facts = [
                    f for f in add_list_facts
                    if not (f.cfg == cfg and f.section == sec
                            and f.option == opt)
                ]
                facts[key] = _Requirement(_SET, cfg, sec, opt, value)
        elif verb == "add_list" and len(rest) >= 1:
            text = rest[0]
            if "=" not in text:
                continue
            path, _, raw_value = text.partition("=")
            parsed = _parse_batch_path_with_marker(path)
            if parsed is None:
                continue
            cfg, sec, opt, _marker = parsed
            if opt is None:
                continue
            value = _unquote(raw_value)
            add_list_facts.append(
                _Requirement(_ADD_LIST, cfg, sec, opt, value)
            )
        elif verb == "del_list" and len(rest) >= 1:
            text = rest[0]
            if "=" not in text:
                continue
            path, _, raw_value = text.partition("=")
            parsed = _parse_batch_path_with_marker(path)
            if parsed is None:
                continue
            cfg, sec, opt, _marker = parsed
            if opt is None:
                continue
            value = _unquote(raw_value)
            add_list_facts = [
                f for f in add_list_facts
                if not (f.cfg == cfg and f.section == sec
                        and f.option == opt and f.value == value)
            ]
        elif verb == "delete" and rest:
            parsed = _parse_batch_path(rest[0])
            if parsed is None:
                continue
            cfg, sec, opt = parsed
            if opt is not None:
                facts.pop((cfg, sec, opt), None)
                add_list_facts = [
                    f for f in add_list_facts
                    if not (f.cfg == cfg and f.section == sec
                            and f.option == opt)
                ]
            else:
                # whole section: drop every fact and every add_list
                # fact of that section (and the section-level set fact).
                keys_to_drop = [
                    k for k in facts
                    if k[0] == cfg and k[1] == sec
                ]
                for k in keys_to_drop:
                    facts.pop(k, None)
                add_list_facts = [
                    f for f in add_list_facts
                    if not (f.cfg == cfg and f.section == sec)
                ]
    return set(facts.values()) | set(add_list_facts)


def _parse_diff_facts(
    diff: str, section_lines: Iterable[str] = ()
) -> set[_Requirement]:
    """Router diff -> set of satisfying facts.

    Only lines with op ``""`` or ``+`` AND a value produce facts; ``-``,
    ``@`` and ``^`` NEVER satisfy a requirement.  cfgXXXXXX and named
    diff sections resolve through the SECTION lines to ALSO emit the
    ``@<type>[*]`` wildcard form.
    """
    section_facts: dict[tuple[str, str], tuple[str | None, str | None]] = {}
    for raw in section_lines or ():
        if not isinstance(raw, str):
            continue
        parsed = parse_section_fact_line(raw)
        if parsed is not None:
            section_facts[parsed[0]] = parsed[1]
    facts: set[_Requirement] = set()
    if not isinstance(diff, str):
        return facts
    for raw in diff.splitlines():
        change = parse_diff_line(raw)
        if change is None or not change.parsed:
            continue
        cfg = change.config
        sec = change.section
        opt = change.option
        value = change.value
        if cfg is None or value is None:
            continue
        if change.op not in ("", "+"):
            continue
        kind = _ADD_LIST if change.op == "+" else _SET
        if _CFG_ANON_RE.fullmatch(sec):
            fact = section_facts.get((cfg, sec))
            facts.add(_Requirement(kind, cfg, sec, opt, value))
            if fact is not None and fact[0]:
                facts.add(_Requirement(kind, cfg, f"@{fact[0]}[*]", opt, value))
        elif _ANON_SEC_RE.fullmatch(sec):
            m = _ANON_SEC_RE.fullmatch(sec)
            facts.add(_Requirement(kind, cfg, f"@{m.group(1)}[*]", opt, value))
        else:
            fact = section_facts.get((cfg, sec))
            facts.add(_Requirement(kind, cfg, sec, opt, value))
            if fact is not None and fact[0]:
                facts.add(_Requirement(kind, cfg, f"@{fact[0]}[*]", opt, value))
    return facts


def _control_requirements(control: dict) -> list[_Requirement] | None:
    """A control's ``batch`` -> list of requirements.

    Returns:

    * ``None`` when ANY batch line contains a ``{placeholder}`` (the
      control is lab-bound; never matched).
    * ``[]`` when the batch has no usable ``set`` / ``add_list`` lines.
      Also never matched (the bug-fix: a control with only ``delete``
      lines, or an empty batch, must not be a false rollback).
    * ``[Requirement, ...]`` otherwise.  ``delete`` / ``del_list`` /
      structural verbs / unknown verbs / junk lines are IGNORED for
      matching.

    Junk lines (bad quoting, garbage paths) are silently skipped; never
    raises.
    """
    batch = control.get("batch")
    if not isinstance(batch, list):
        return []
    requirements: list[_Requirement] = []
    for raw in batch:
        if not isinstance(raw, str):
            continue
        if _PLACEHOLDER_RE.search(raw):
            return None
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        words = _split_batch_words(line)
        if not words:
            continue
        verb = words[0]
        rest = words[1:]
        if verb == "set" and len(rest) >= 1:
            text = rest[0]
            if "=" not in text:
                continue
            path, _, raw_value = text.partition("=")
            parsed = _parse_batch_path_with_marker(path)
            if parsed is None:
                continue
            cfg, sec, opt, marker = parsed
            if marker == "-":
                # ``set foo.option-='v'`` is UCI sugar for ``del_list``
                # (REMOVES ``v``); it does NOT produce a requirement.
                continue
            if marker == "+":
                # ``set foo.option+='x'`` is UCI sugar for add_list.
                kind = _ADD_LIST
            else:
                kind = _SET
            if opt is None and kind == _ADD_LIST:
                continue
            value = _unquote(raw_value)
            requirements.append(_Requirement(kind, cfg, sec, opt, value))
        elif verb == "add_list" and len(rest) >= 1:
            text = rest[0]
            if "=" not in text:
                continue
            path, _, raw_value = text.partition("=")
            parsed = _parse_batch_path_with_marker(path)
            if parsed is None:
                continue
            cfg, sec, opt, _marker = parsed
            if opt is None:
                continue
            value = _unquote(raw_value)
            requirements.append(_Requirement(_ADD_LIST, cfg, sec, opt, value))
    # A section-level requirement (``set cfg.sec=type``, option None) is
    # dropped when the control ALSO has at least one option-level
    # requirement: re-applying only the option lines onto an already
    # existing section never produces a section-create line in the diff,
    # so the section-level requirement would never be satisfied then.
    # A control whose ONLY requirements are section-level keeps them.
    has_option_req = any(req.option is not None for req in requirements)
    if has_option_req:
        requirements = [req for req in requirements if req.option is not None]
    return requirements


def _requirement_satisfied(req: _Requirement, facts: set[_Requirement]) -> bool:
    """Is ``req`` satisfied by some fact in ``facts``?

    Equal kind, config, option, value AND a section that matches per
    ``_section_match``.  Same-kind-only: a ``set`` requirement is satisfied
    by a ``set`` fact with that value, an ``add_list`` requirement by an
    ``add_list`` fact with that value.
    """
    for f in facts:
        if (f.kind == req.kind and f.cfg == req.cfg
                and f.option == req.option and f.value == req.value
                and _section_match(req.section, f.section)):
            return True
    return False


# ---- the public API ---------------------------------------------------------


def touched_entries(
    controls: list[dict],
    uci_batch: str,
    diff: str = "",
    section_lines: Iterable[str] = (),
) -> list[int]:
    """Manifest entry indexes whose requirements are ALL satisfied.

    Only entries WITH a ``probes`` key are considered (the older
    ``check``-based controls are out of scope).  Indexes come back in
    manifest order, each at most once.  The union of batch facts and
    diff facts is the satisfaction set.

    A control with ANY ``{placeholder}`` in its batch is NEVER matched.
    A control with no requirements is NEVER matched.  A partial
    application of a control is not "the control": no auto check, never
    a false rollback.
    """
    facts = _parse_batch_facts(uci_batch)
    if diff:
        facts |= _parse_diff_facts(diff, section_lines)
    out: list[int] = []
    for index, control in enumerate(controls):
        if not isinstance(control, dict):
            continue
        if "probes" not in control:
            continue
        requirements = _control_requirements(control)
        if not requirements:
            continue
        if all(_requirement_satisfied(req, facts) for req in requirements):
            out.append(index)
    return out


def touched_control_ids(
    controls: list[dict],
    uci_batch: str,
    diff: str = "",
    section_lines: Iterable[str] = (),
) -> list[str]:
    """Manifest ids whose requirements are ALL satisfied by the staged change.

    Same matching rules as ``touched_entries``; returns the deduped ids
    of those entries in manifest order (for messages and the on-disk
    record).  A duplicate-id sibling only appears once here, but in the
    sealed probe file both entries' probes are sealed (see
    ``seal_manifest_ids``).
    """
    entries = touched_entries(controls, uci_batch, diff, section_lines)
    out: list[str] = []
    seen: set[str] = set()
    for index in entries:
        control = controls[index]
        if not isinstance(control, dict):
            continue
        cid = control.get("id")
        if isinstance(cid, str) and cid not in seen:
            seen.add(cid)
            out.append(cid)
    return out


def needs_restage(
    sealed_entries: list[int],
    diff_entries: list[int],
) -> tuple[bool, list[int]]:
    """Does the diff ask for indexes outside what the plan already sealed?

    Returns ``(needs_restage, missing)``. ``missing`` is the
    (stable-ordered, deduped) subset of ``diff_entries`` that is NOT in
    ``sealed_entries``; an empty list means no restage needed.  The MCP
    server and the lab runner both call this so they make the same
    decision.  Entry INDEXES are compared (a duplicate-id sibling is
    distinct from its sibling).
    """
    sealed_set = set(sealed_entries)
    missed = [i for i in diff_entries if i not in sealed_set]
    if not missed:
        return False, []
    seen: set[int] = set()
    deduped: list[int] = []
    for i in missed:
        if i not in seen:
            seen.add(i)
            deduped.append(i)
    return True, deduped


def sealed_probes_bytes(probes: list[list[str]]) -> int:
    """Sum of the sealed probe bytes (TAB + LF), matching the router seal."""
    total = 0
    for probe in probes:
        total += sum(len(f) for f in probe) + max(0, len(probe) - 1) + 1
    return total


def entry_ids(controls: list[dict], indexes: list[int]) -> list[str]:
    """Map entry INDEXES to their control ids, deduped, in the input order.

    Used by callers that need ids for messages or the on-disk record after
    a ``seal_manifest_ids`` / ``touched_entries`` round-trip; an index
    whose control has no valid id is skipped.
    """
    out: list[str] = []
    seen: set[str] = set()
    for index in indexes:
        if not isinstance(index, int) or not 0 <= index < len(controls):
            continue
        control = controls[index]
        if not isinstance(control, dict):
            continue
        cid = control.get("id")
        if isinstance(cid, str) and cid not in seen:
            seen.add(cid)
            out.append(cid)
    return out


def seal_manifest_ids(
    caller_ids: list[str],
    auto_entry_indexes: list[int],
    *,
    controls: list[dict] | None = None,
    extra_probes: "list[list[str]] | None" = None,
) -> tuple[list[int], list[list[str]]]:
    """Combine caller ids + auto entries (preserve order, caller first) and
    expand each into its probe list, refusing with a clear message if the
    cumulative count breaks the router's sealed-probe cap.

    ``caller_ids`` go through the by-id lookup as today: an id that names
    more than one manifest entry stays REFUSED for the caller path,
    matching the existing ``expand_manifest_checks`` refusal.  An id
    that names no manifest entry is also REFUSED.

    ``auto_entry_indexes`` are expanded BY INDEX (the indexes
    ``derive_touched_entries`` / ``touched_entries`` returned): a
    duplicate-id sibling in the auto path is fine; each entry
    contributes its own probes.  Probe lines of one id twice are fine
    (a duplicate-id sibling seals both entries' probe lines).

    ``extra_probes`` are probes the caller (MCP) or the lab runner's
    scenario brings to the plan; their lines and bytes count into the
    same ``MAX_PROBE_LINES`` / ``MAX_PROBES_BYTES`` cap the manifest
    controls share.  This is the ONE place the cap is enforced: the lab
    runner and the MCP server call this function with the caller's /
    scenario's probes and refuse together, so a refusal names the
    control ids being added (never a bare ``too-many`` from later
    ``validate_probes``).

    Returns ``(sealed_entries, manifest_probes)``.  ``sealed_entries``
    is the list of entry INDEXES that were sealed (caller first, then
    auto entries that were not already sealed by id); the caller maps
    them to ids for messages and the record.  Refuses with
    ``ValueError`` (caller wraps in ``NewtonError``) if a caller id is
    unknown or ambiguous, an entry has no probe form yet, the entry's
    probes are malformed, or the seal would push the plan past the
    ``MAX_PROBE_LINES`` or ``MAX_PROBES_BYTES`` cap (the message names
    the offender id and the ids being added, with the line and byte
    totals that pushed the plan past the cap).
    """
    from .probes import (
        CONTROL_ID_RE,
        MAX_PROBES_BYTES,
        MAX_PROBE_LINES,
        _load_controls,
        _safe,
        manifest_path,
    )

    if controls is None:
        controls = _load_controls(manifest_path())

    # Caller-side duplicate ids are a real error (matching the old
    # expand_manifest_checks refusal).
    seen_caller: set[str] = set()
    caller_deduped: list[str] = []
    for cid in caller_ids:
        if not isinstance(cid, str) or not CONTROL_ID_RE.fullmatch(cid):
            raise ValueError(f"invalid manifest check id: {_safe(cid)}")
        if cid in seen_caller:
            raise ValueError(f"manifest check id given twice: {_safe(cid)}")
        seen_caller.add(cid)
        caller_deduped.append(cid)

    # by-id index for caller-id validation.
    by_id: dict[str, list[int]] = {}
    for index, control in enumerate(controls):
        if isinstance(control, dict):
            cid = control.get("id")
            if isinstance(cid, str):
                by_id.setdefault(cid, []).append(index)
    for cid in caller_deduped:
        matches = by_id.get(cid)
        if matches is None:
            raise ValueError(f"unknown manifest check id: {cid}")
        if len(matches) > 1:
            raise ValueError(
                f"manifest check id matches more than one control: {cid}"
            )

    # Build the ordered (id, index) list: caller first (by id -> single
    # index), then auto entries (by index).  Dedup by ENTRY INDEX: a
    # caller id and an auto entry pointing at the same entry collapse
    # silently; a duplicate-id sibling (different index, same id) is
    # fine for the auto path and BOTH entries contribute their own
    # probes (probe lines of one id twice are fine).  The caller maps
    # the returned indexes to a deduped id list for the record.
    seen_indexes: set[int] = set()
    combined: list[tuple[str, int]] = []
    for cid in caller_deduped:
        idx = by_id[cid][0]
        if idx in seen_indexes:
            continue
        seen_indexes.add(idx)
        combined.append((cid, idx))
    for index in auto_entry_indexes:
        if not isinstance(index, int) or not 0 <= index < len(controls):
            continue
        if index in seen_indexes:
            continue
        control = controls[index]
        if not isinstance(control, dict):
            continue
        cid = control.get("id")
        if not isinstance(cid, str) or not CONTROL_ID_RE.fullmatch(cid):
            continue
        seen_indexes.add(index)
        combined.append((cid, index))

    extra = list(extra_probes) if extra_probes else []
    extra_lines = len(extra)
    extra_bytes = sum(
        sum(len(f) for f in probe) + max(0, len(probe) - 1) + 1
        for probe in extra
    )

    manifest_probes: list[list[str]] = []
    sealed_entries: list[int] = []
    total_bytes = 0
    for cid, index in combined:
        control = controls[index]
        if "probes" not in control:
            host = control.get("check_host") or "none"
            raise ValueError(
                f"manifest check {cid} has no probe form yet "
                f"(check_host {host} or not yet converted)"
            )
        ctl_probes = control["probes"]
        if not isinstance(ctl_probes, list) or not all(
            isinstance(probe, list) and all(isinstance(f, str) for f in probe)
            for probe in ctl_probes
        ):
            raise ValueError(
                f"manifest check {cid} has an invalid probes entry"
            )
        new_lines = len(ctl_probes)
        ctl_bytes = sum(
            sum(len(f) for f in probe) + max(0, len(probe) - 1) + 1
            for probe in ctl_probes
        )
        if extra_lines + len(manifest_probes) + new_lines > MAX_PROBE_LINES:
            offender = combined.index((cid, index))
            pending = [c for c, _ in combined[offender:]]
            raise ValueError(
                f"manifest check {cid} would push the plan past the "
                f"{MAX_PROBE_LINES}-probe cap; "
                f"{extra_lines + len(manifest_probes) + new_lines}/{MAX_PROBE_LINES} lines, "
                f"{extra_bytes + total_bytes + ctl_bytes}/{MAX_PROBES_BYTES} bytes; "
                f"control ids being added: {pending!r}"
            )
        if extra_bytes + total_bytes + ctl_bytes > MAX_PROBES_BYTES:
            offender = combined.index((cid, index))
            pending = [c for c, _ in combined[offender:]]
            raise ValueError(
                f"manifest check {cid} would push the plan past the "
                f"{MAX_PROBES_BYTES}-byte cap; "
                f"{extra_lines + len(manifest_probes) + new_lines}/{MAX_PROBE_LINES} lines, "
                f"{extra_bytes + total_bytes + ctl_bytes}/{MAX_PROBES_BYTES} bytes; "
                f"control ids being added: {pending!r}"
            )
        for probe in ctl_probes:
            manifest_probes.append(list(probe))
        total_bytes += ctl_bytes
        sealed_entries.append(index)
    return sealed_entries, manifest_probes


def derive_touched_ids(
    uci_batch: str,
    diff: str = "",
    section_lines: Iterable[str] = (),
) -> list[str]:
    """Convenience: load the manifest (NEWTON_MANIFEST honoured) and derive
    the touched control ids in manifest order.  Import-safe from the lab
    runner that already imports ``newton_mcp.probes`` for the manifest path."""
    from .probes import _load_controls, manifest_path
    return touched_control_ids(
        _load_controls(manifest_path()), uci_batch, diff, section_lines
    )


def derive_touched_entries(
    uci_batch: str,
    diff: str = "",
    section_lines: Iterable[str] = (),
) -> list[int]:
    """Convenience: load the manifest and derive the touched entry INDEXES
    in manifest order.  Used by the MCP server and the lab runner to
    compare what is sealed against what the diff surfaces; ids are only
    used for messages and the record.
    """
    from .probes import _load_controls, manifest_path
    return touched_entries(
        _load_controls(manifest_path()), uci_batch, diff, section_lines
    )
