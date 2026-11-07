"""R1: split a tier .uci into probe-safe batches, validate placeholders, resolve.

The whole tier file exceeds the router's 32-line / 4096-byte sealed-probe
cap (standard seals 19, hardened seals 31, lockdown seals 30), so one plan
cannot carry the whole tier unless the lab-bound blocks are excluded.
``newton_mcp.tiers.split_tier`` partitions the non-skipped blocks in
MANIFEST order into ordered batches that each fit the cap, so the MCP
server can ship the tier as a sequence of ``plan`` calls.  The router cap
does NOT change: ``tiers`` reads ``probes.MAX_PROBE_LINES`` and
``probes.MAX_PROBES_BYTES`` at call time, so a test can monkeypatch the
caps and exercise the overflow path without rewriting the manifest.

Lab-bound blocks (``# lab-bound:``) are excluded from batches and listed
in ``skipped`` (the .uci still has the lines un-commented by design of
``profiles/build.py``; the planner must never carry them).  Conditional
blocks (``# conditional: needs package ...``) are skipped too (every
batch line is commented out in the .uci, but the planner also names the
package so the operator sees the reason).  Blocks with NO active lines
(e.g. ``# no lines of its own ...``) are ignored, not skipped.

The batch cap is sized from each batch's OWN text only -- what ``plan()``
will actually seal for that text -- never from the "worst case" text of
all blocks (lab-bound or active).  A caller can be stricter than the
router cap with the optional ``max_lines`` / ``max_bytes`` keyword args;
a value larger than the router cap or smaller than 1 is refused.

``resolve_batch`` substitutes ``{name}`` placeholders with operator
values, refusing missing or unknown names and refusing any value that
isn't a single bounded token (so a value can never inject another
placeholder, a quote, a space, a shell meta-character, or a brace).
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

import newton_mcp.probes as probes
import newton_mcp.tiers as tiers
import newton_mcp.touched as touched
from newton_mcp.explanation import MAX_CLAIMS


# ---- parsing helpers used by the test bodies --------------------------------


_HEADER_RE = re.compile(r"^# (OW-[A-Za-z0-9]+-[0-9]+) (.*)$")


def _active_lines_of_block(block_lines: list[str]) -> list[str]:
    """A line is active iff it is non-empty and not a comment line."""
    out: list[str] = []
    for line in block_lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        out.append(line)
    return out


def _file_blocks(tier: str) -> list[tuple[str, list[str]]]:
    """Parse the tier file into ``(id, body_lines)`` in file order.

    The header regex is the same one ``split_tier`` uses; the parser is
    duplicated here so the test for "every active line lands once in
    order" is independent of the implementation.
    """
    path = Path(probes.manifest_path()).parent / f"{tier}.uci"
    blocks: list[tuple[str, list[str]]] = []
    cur_id: str | None = None
    cur_lines: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        m = _HEADER_RE.match(raw)
        if m:
            if cur_id is not None:
                blocks.append((cur_id, cur_lines))
            cur_id = m.group(1)
            cur_lines = []
        elif cur_id is not None:
            cur_lines.append(raw)
    if cur_id is not None:
        blocks.append((cur_id, cur_lines))
    return blocks


def _expected_active_lines(tier: str, skipped_ids: set[str]) -> list[str]:
    """The file's active lines, minus the lab-bound and conditional blocks."""
    out: list[str] = []
    for cid, body in _file_blocks(tier):
        if cid in skipped_ids:
            continue
        out.extend(_active_lines_of_block(body))
    return out


# Real measured facts (lab-bound excluded): standard seals 19, hardened 31,
# lockdown 30 -- each fits a single batch under the router's 32-line cap.
_REAL_PROBE_LINES = {
    "standard": 19,
    "hardened": 31,
    "lockdown": 30,
}


# ---- split_tier: the cap, the manifest order, the line/byte totals -----------


@pytest.mark.parametrize("tier", list(_REAL_PROBE_LINES))
def test_tier_is_one_batch_with_the_whole_router_cap(tier):
    """Each tier's non-lab-bound probe lines fit the router cap, so a split
    at the full router cap is exactly one batch (no phantom logic adding
    lab-bound text to the candidate)."""
    info = tiers.split_tier(
        tier, max_lines=probes.MAX_PROBE_LINES, max_bytes=probes.MAX_PROBES_BYTES
    )
    assert len(info["batches"]) == 1, (
        f"{tier} should fit in 1 batch at the router cap, "
        f"got {len(info['batches'])}"
    )
    batch = info["batches"][0]
    assert batch["probe_lines"] == _REAL_PROBE_LINES[tier], (
        f"{tier} total probe_lines={batch['probe_lines']}, "
        f"expected {_REAL_PROBE_LINES[tier]}"
    )
    assert batch["probe_lines"] <= probes.MAX_PROBE_LINES
    assert batch["probe_bytes"] <= probes.MAX_PROBES_BYTES


_DEFAULT_BATCHES = {"standard": 1, "hardened": 2, "lockdown": 2}


@pytest.mark.parametrize("tier", list(_REAL_PROBE_LINES))
def test_default_cap_leaves_room_for_the_most_expect_claims(tier):
    """the default split reserves room for MAX_CLAIMS claim lines (and
    their longest bytes), so every batch plans with a full explanation."""
    info = tiers.split_tier(tier)
    assert len(info["batches"]) == _DEFAULT_BATCHES[tier]
    assert sum(b["probe_lines"] for b in info["batches"]) == _REAL_PROBE_LINES[tier]
    for batch in info["batches"]:
        assert batch["probe_lines"] + MAX_CLAIMS <= probes.MAX_PROBE_LINES
        assert batch["probe_bytes"] + tiers.CLAIM_RESERVE_BYTES <= probes.MAX_PROBES_BYTES


@pytest.mark.parametrize("tier", list(_REAL_PROBE_LINES))
def test_tier_batches_round_trip_through_seal_manifest_ids(tier):
    """Each batch's ``probe_lines`` must match what
    ``touched.seal_manifest_ids`` would seal for the batch's own text.

    The probe file the router seals is one TAB-joined line per probe, so
    ``len(manifest_probes)`` is the number of probe lines and must equal
    ``batch["probe_lines"]``.
    """
    info = tiers.split_tier(tier)
    controls = probes._load_controls(probes.manifest_path())
    for batch in info["batches"]:
        sealed_entries, manifest_probes = touched.seal_manifest_ids(
            caller_ids=[],
            auto_entry_indexes=touched.touched_entries(
                controls, batch["text"], "", []
            ),
            controls=controls,
        )
        assert len(manifest_probes) == batch["probe_lines"], (
            f"{tier} batch {batch['index']}: round-trip mismatch "
            f"{len(manifest_probes)} != {batch['probe_lines']}"
        )


def test_split_tier_returned_dict_has_no_controls_key():
    """The returned dict must not carry the whole ``controls`` list."""
    info = tiers.split_tier("hardened")
    assert "controls" not in info, (
        f"info keys: {sorted(info)}"
    )


@pytest.mark.parametrize("tier", ["hardened", "lockdown"])
def test_max_lines_16_splits_into_at_least_two_batches(tier):
    """With max_lines=16 (stricter than the router cap) hardened and
    lockdown split into >= 2 batches, each within the cap, in file order.
    The phantom logic in the OLD code would split at different boundaries
    (the lab-bound text contributed phantom probes to the cap check)."""
    info = tiers.split_tier(tier, max_lines=16)
    assert len(info["batches"]) >= 2, (
        f"{tier} with max_lines=16 should split into >=2 batches, "
        f"got {len(info['batches'])}"
    )
    for batch in info["batches"]:
        assert batch["probe_lines"] <= 16, (
            f"{tier} batch {batch['index']} probe_lines={batch['probe_lines']}"
            f" > 16"
        )


@pytest.mark.parametrize("tier", ["hardened", "lockdown"])
def test_max_lines_16_preserves_active_lines_in_file_order(tier):
    """With max_lines=16: every active line of every non-skipped block lands
    in exactly one batch, in manifest order.  No control id is split across
    batches (a control id appears in exactly one batch)."""
    info = tiers.split_tier(tier, max_lines=16)
    skipped_ids = {s["id"] for s in info["skipped"]}
    expected = _expected_active_lines(tier, skipped_ids)
    joined_lines: list[str] = []
    for batch in info["batches"]:
        joined_lines.extend(batch["lines"])
    assert joined_lines == expected, (
        f"{tier}: active lines mismatch\n"
        f"  expected={expected!r}\n"
        f"  got     ={joined_lines!r}"
    )
    # a control id appears in exactly one batch
    all_ids: list[str] = []
    for batch in info["batches"]:
        for cid in batch["control_ids"]:
            assert cid not in all_ids, (
                f"{tier}: control {cid} appears in two batches"
            )
            all_ids.append(cid)


def test_every_active_line_lands_once_in_order():
    """Every active line of every non-skipped block lands in exactly one
    batch, in manifest order.  The concatenation of batch texts equals
    the file's active lines of non-skipped blocks."""
    for tier in tiers.TIER_NAMES:
        info = tiers.split_tier(tier)
        skipped_ids = {s["id"] for s in info["skipped"]}
        expected = _expected_active_lines(tier, skipped_ids)
        # the joined batch text minus its trailing newline must match the
        # file's active lines (the batch texts may end with "\n").
        joined_lines: list[str] = []
        for batch in info["batches"]:
            joined_lines.extend(batch["lines"])
        assert joined_lines == expected, (
            f"{tier}: active lines mismatch\n"
            f"  expected={expected!r}\n"
            f"  got     ={joined_lines!r}"
        )


def test_control_never_split():
    """A control's active lines are never split across batches: every
    block's lines live in exactly one batch, with the same line count
    and the same first/last lines."""
    for tier in tiers.TIER_NAMES:
        info = tiers.split_tier(tier)
        skipped_ids = {s["id"] for s in info["skipped"]}
        blocks_by_id = dict(_file_blocks(tier))
        # every control id in batches.control_ids appears with the
        # exact block size (or, for the empty-line blocks, never).
        batch_ids_seen: list[str] = []
        for batch in info["batches"]:
            for cid in batch["control_ids"]:
                assert cid not in batch_ids_seen, (
                    f"{tier}: control {cid} appears in two batches"
                )
                batch_ids_seen.append(cid)
                body = blocks_by_id[cid]
                assert len(_active_lines_of_block(body)) == len(batch["control_ids"]) or \
                    len(batch["lines"]) >= len(_active_lines_of_block(body))
                # the body's active lines must equal batch["lines"] for
                # the block's slice; we instead verify by line-count and
                # first/last-line match per control below.
        # per-control line-count check across all batches.
        expected_active: dict[str, list[str]] = {}
        for cid, body in blocks_by_id.items():
            if cid in skipped_ids:
                continue
            active = _active_lines_of_block(body)
            if not active:
                continue
            expected_active[cid] = active
        # each batch concatenates the active lines of its control_ids.
        for batch in info["batches"]:
            concatenated: list[str] = []
            for cid in batch["control_ids"]:
                concatenated.extend(expected_active[cid])
            assert concatenated == batch["lines"], (
                f"{tier} batch {batch['index']}: lines don't match its control_ids"
            )


def test_lab_bound_control_is_skipped():
    info = tiers.split_tier("hardened")
    skipped_by_id = {s["id"]: s for s in info["skipped"]}
    assert "OW-MGMT-02" in skipped_by_id
    assert skipped_by_id["OW-MGMT-02"]["reason"].startswith("lab-bound")
    # OW-FW-06 is conditional, so it is skipped with a reason starting
    # with "conditional".
    assert "OW-FW-06" in skipped_by_id
    assert skipped_by_id["OW-FW-06"]["reason"].startswith("conditional")
    # and no batch text contains the lab-only 10.109.0.11 address or the
    # {client_lab_ip} placeholder (both belong to lab-bound blocks).
    for batch in info["batches"]:
        assert "10.109.0.11" not in batch["text"]
        assert "{client_lab_ip}" not in batch["text"]


def test_list_tiers_reports_placeholders_and_skipped():
    tiers_list = tiers.list_tiers()
    by_name = {t["tier"]: t for t in tiers_list}
    assert set(by_name) == set(tiers.TIER_NAMES)
    # hardened's non-skipped blocks include {fw_wan_zone} and
    # {fw_allow_ping}; OW-ZONE-02 / OW-LOG-01 are lab-bound.
    assert set(by_name["hardened"]["placeholders"]) >= {
        "fw_wan_zone", "fw_allow_ping"
    }
    assert "lan_device" not in by_name["hardened"]["placeholders"]
    assert "client_lab_ip" not in by_name["hardened"]["placeholders"]
    # every tier carries OW-FW-06 in skipped with reason starting "conditional"
    for tier in ("standard", "hardened", "lockdown"):
        skipped = {s["id"]: s for s in by_name[tier]["skipped"]}
        assert "OW-FW-06" in skipped
        assert skipped["OW-FW-06"]["reason"].startswith("conditional")
    # probe_lines is the sum over the batches (split_tier is the source
    # of truth for that number).
    for tier in ("standard", "hardened", "lockdown"):
        info = tiers.split_tier(tier)
        assert by_name[tier]["probe_lines"] == sum(
            b["probe_lines"] for b in info["batches"]
        )
        assert by_name[tier]["batches"] == len(info["batches"])


# ---- placeholders and validation --------------------------------------------


def test_tier_placeholders_returns_sorted_unique_names():
    text = (
        "set firewall.{fw_wan_zone}.input='DROP'\n"
        "set firewall.{fw_allow_ping}.enabled='0'\n"
        "set firewall.{fw_wan_zone}.log='1'\n"
    )
    assert tiers.tier_placeholders(text) == ["fw_allow_ping", "fw_wan_zone"]


def test_validate_values_accepts_only_bounded_tokens():
    # good values
    tiers.validate_values({
        "wan_zone": "@zone[1]",
        "iface": "eth3.40",
        "addr": "192.168.1.5",
    })
    # bad values, each refused by name.  An empty string and a 65-char
    # token carry no secret payload, but the redactor's job is to never
    # echo the BAD value, so we still confirm the key-only message.
    for bad in (
        "'DROP'",            # quote
        "DROP\n",            # newline
        "DROP DROP",         # space
        "DROP;DROP",         # ;
        "$(reboot)",          # $(...)
        "{a}",               # braces
        "x" * 65,            # too long
    ):
        with pytest.raises(tiers.TierError) as excinfo:
            tiers.validate_values({"k": bad})
        msg = str(excinfo.value)
        assert "k" in msg, (bad, msg)
        assert bad not in msg, (bad, msg)  # the bad value is never echoed
    # empty string is refused too (the key is named).
    with pytest.raises(tiers.TierError, match="k"):
        tiers.validate_values({"k": ""})


def test_validate_values_refuses_non_string_value():
    for bad in (1, 1.5, True, None, ["x"], b"x"):
        with pytest.raises(tiers.TierError, match="k"):
            tiers.validate_values({"k": bad})


def test_validate_values_refuses_bad_name():
    with pytest.raises(tiers.TierError, match="Bad-Name"):
        tiers.validate_values({"Bad-Name": "x"})
    # empty key
    with pytest.raises(tiers.TierError):
        tiers.validate_values({"": "x"})
    # non-str key
    with pytest.raises(tiers.TierError):
        tiers.validate_values({1: "x"})  # type: ignore[dict-item]


def test_validate_values_refuses_non_dict():
    with pytest.raises(tiers.TierError):
        tiers.validate_values("nope")  # type: ignore[arg-type]
    # None is accepted (no values means no validation to do)
    tiers.validate_values(None)


def test_missing_value_is_refused_by_name():
    """A batch whose text references {fw_wan_zone} without a value raises
    TierError mentioning the placeholder name."""
    info = tiers.split_tier("hardened")
    batch_with_fw_wan_zone = next(
        b for b in info["batches"] if "{fw_wan_zone}" in b["text"]
    )
    with pytest.raises(tiers.TierError, match="fw_wan_zone"):
        tiers.resolve_batch(batch_with_fw_wan_zone["text"], {})
    # with a value, the output has no `{` at all.
    out = tiers.resolve_batch(
        batch_with_fw_wan_zone["text"],
        {"fw_wan_zone": "wan", "fw_allow_ping": "Allow-Ping"},
    )
    assert "{" not in out


def test_unknown_value_name_refused():
    """When ``tier_names`` is given, values for names not in the tier are
    refused (the operator never sees a surprise carrier)."""
    info = tiers.split_tier("hardened")
    batch = info["batches"][0]
    tier_names = tiers.tier_placeholders(batch["text"])
    # an extra name in values is refused.
    with pytest.raises(tiers.TierError, match="bogus"):
        tiers.resolve_batch(
            batch["text"], {"fw_wan_zone": "wan", "bogus": "x"},
            tier_names=tier_names,
        )


def test_resolution_is_single_pass():
    """A value can never carry another placeholder.  ``{fw_wan_zone}=wan{a}``
    is refused at validate_values (it has a brace); the substitution is
    a single str.replace pass and never re-scans the result."""
    # a value containing ``{`` is refused by validate_values.
    with pytest.raises(tiers.TierError):
        tiers.validate_values({"k": "{a}"})
    # a value that does NOT contain ``{`` is accepted; resolve_batch
    # performs single-pass replacement and the substituted text contains
    # no `{`.
    text = "set firewall.{fw_wan_zone}.input='DROP'\n"
    out = tiers.resolve_batch(text, {"fw_wan_zone": "wan"})
    assert out == "set firewall.wan.input='DROP'\n"
    # a value that contains a ``{`` was already refused at validation, so
    # the call below is the validate_values guard and never reaches the
    # substitution pass.


# ---- determinism, error shape, control flow ---------------------------------


def test_split_is_deterministic():
    """Two calls of split_tier on the same tier produce identical dicts."""
    a = tiers.split_tier("hardened")
    b = tiers.split_tier("hardened")
    assert a == b


def test_unknown_tier_refused():
    with pytest.raises(tiers.TierError, match="bogus"):
        tiers.split_tier("bogus")
    with pytest.raises(tiers.TierError):
        tiers.split_tier("")
    # list_tiers works fine (no per-tier input) -- an unknown tier only
    # surfaces via split_tier with a bad name.


def test_tier_too_big_block_refused(monkeypatch):
    """A single block whose probe lines alone exceed the cap raises
    TierError naming the block's id.  Patching MAX_PROBE_LINES to 1 in
    the probes module forces every block with >=1 probe to overflow."""
    monkeypatch.setattr(probes, "MAX_PROBE_LINES", 1)
    monkeypatch.setattr(probes, "MAX_PROBES_BYTES", 4096)
    with pytest.raises(tiers.TierError) as excinfo:
        tiers.split_tier("hardened")
    msg = str(excinfo.value)
    # the message names the offending control id (the first block whose
    # touched probe lines exceed 1).
    assert "OW-MGMT-01" in msg or "OW-FW-02" in msg or "OW-MGMT-05" in msg, msg


# ---- max_lines / max_bytes keyword args -------------------------------------


def test_max_lines_above_router_cap_refused():
    """A caller cannot be LOOSER than the router cap: a value larger than
    ``probes.MAX_PROBE_LINES`` is refused (the planner cannot seal it)."""
    with pytest.raises(tiers.TierError, match="max_lines"):
        tiers.split_tier("hardened", max_lines=probes.MAX_PROBE_LINES + 1)


def test_max_bytes_above_router_cap_refused():
    """A caller cannot be LOOSER than the router cap on bytes either."""
    with pytest.raises(tiers.TierError, match="max_bytes"):
        tiers.split_tier("hardened", max_bytes=probes.MAX_PROBES_BYTES + 1)


def test_max_lines_zero_refused():
    """Values smaller than 1 are refused."""
    with pytest.raises(tiers.TierError, match="max_lines"):
        tiers.split_tier("hardened", max_lines=0)


def test_max_bytes_zero_refused():
    with pytest.raises(tiers.TierError, match="max_bytes"):
        tiers.split_tier("hardened", max_bytes=0)


def test_max_lines_negative_refused():
    with pytest.raises(tiers.TierError, match="max_lines"):
        tiers.split_tier("hardened", max_lines=-1)

def test_max_bytes_splits_batches_too():
    # the planted "bytes cap ignored" defect survived without this
    whole = tiers.split_tier(
        "hardened", max_lines=probes.MAX_PROBE_LINES, max_bytes=probes.MAX_PROBES_BYTES
    )
    small = tiers.split_tier("hardened", max_bytes=700)
    assert len(whole["batches"]) == 1
    assert len(small["batches"]) >= 2
    assert all(b["probe_bytes"] <= 700 for b in small["batches"])
