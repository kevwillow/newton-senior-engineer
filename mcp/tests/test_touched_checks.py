"""ADR-010: the live checks of every manifest control a plan touches must run.

The pure module under test is ``newton_mcp.touched``.  The MCP server
integration is here too: ``newton_plan_change`` derives touched entries
from the batch alone before the plan, then again from the router diff
after parse_plan (the diff-only case aborts the staged session and
re-plans once with the union; a second miss aborts and raises).

The match rule is REQUIREMENT-BASED (defect A): a control's ``batch``
becomes a list of ``(kind, cfg, section, option, value)`` requirements;
the control matches iff every requirement is satisfied by some staged
fact (batch + diff) with the same kind, cfg, section, option and value.
delete / del_list / structural verbs in the control's batch are IGNORED
for matching.  A control with any ``{placeholder}`` in its batch is
NEVER matched.  A control with no requirements is NEVER matched.  The
manifest entries are identified by INDEX (defect A): two entries with
the same id but different values are distinct (one wins per staged value;
both sealed when both values are staged; the id appears ONCE in the
record).

A custom fake script records every call's args and reads the probe file
the planner writes, so a test can assert both the probes the router saw
and the ids the plan stored as ``manifest_checks_auto``.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
from typing import Any

import pytest

from exhelp import explained

import newton_mcp.probes as probes
import newton_mcp.server as server
import newton_mcp.touched as touched


SID = "0123456789abcdef0123456789abcdef"
BASE_HASH = "b" * 64
DIGEST = "d" * 64
PROBES_SHA = "a" * 64


# ---- shared fixtures (parallel to test_probes_host) ----------------------------


@pytest.fixture
def configured(tmp_path, monkeypatch):
    inventory = tmp_path / "devices.toml"
    inventory.write_text(
        '[devices.quasar]\nplatform = "openwrt"\nhost = "192.0.2.1"\n'
        'user = "root"\n'
    )
    monkeypatch.setenv("NEWTON_INVENTORY", str(inventory))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))
    return tmp_path


@pytest.fixture
def configured_lab(configured, monkeypatch):
    (configured / "devices.toml").write_text(
        '[devices.quasar]\nplatform = "openwrt"\nhost = "192.0.2.1"\n'
        'user = "root"\nprofile = "lab"\nlab = true\n'
    )
    return configured


def _manifest(tmp_path, text):
    path = tmp_path / "manifest.toml"
    path.write_text(text)
    return path


def plan_output(
    *,
    diff="dhcp.skilltest='host'",
    approval="not-required",
    extra_sections: tuple[str, ...] = (),
) -> str:
    return (
        "BACKUP /tmp/fake.tar.gz (2 config files)\n"
        f"STAGED session={SID}\n"
        f"BASEHASH {BASE_HASH}\n"
        f"PROBES 1 {PROBES_SHA}\n"
        "PROFILE lab\n"
        "SECTION dhcp cfg01 dnsmasq dnsmasq\n"
        + "".join(f"SECTION {s}\n" for s in extra_sections)
        + "LEASH wan-rule firewall.wan_rule\n"
        f"APPROVAL {approval}\n"
        f"PLANDIGEST {DIGEST}\n"
        "----- diff -----\n"
        f"{diff}\n"
        "----------------\n"
    )


def _fake_script(
    calls,
    outputs: list[str] | None = None,
    extra_env: dict[str, str] | None = None,
):
    """Build a fake ``NewtonService.run_script``.

    Each call appends ``(args, kwargs, modes, probe_bytes_or_None)`` to
    ``calls``. ``outputs[i]`` (or the last one, or plan_output()) is
    returned as ``CompletedProcess.stdout``. While the script is "running"
    the probe file is still on disk, so we read it.
    """
    outputs = outputs or []

    def fake_run(self, device, *args, **kwargs):
        modes = []
        for part in args:
            if isinstance(part, str) and part.startswith("/tmp/newton-"):
                try:
                    modes.append(stat.S_IMODE(os.stat(part).st_mode))
                except OSError:
                    modes.append(None)
        probe_bytes: bytes | None = None
        if len(args) >= 5 and isinstance(args[4], str) and args[4].startswith("/tmp/newton-probes-"):
            try:
                with open(args[4], "rb") as fh:
                    probe_bytes = fh.read()
            except OSError:
                probe_bytes = None
        calls.append((args, kwargs, tuple(modes), probe_bytes))
        idx = len(calls) - 1
        if outputs:
            out = outputs[idx] if idx < len(outputs) else outputs[-1]
        else:
            out = plan_output()
        return subprocess.CompletedProcess(list(args), 0, out, "")
    return fake_run


def _read_probe_bytes(probe_bytes: bytes | None) -> list[list[str]]:
    if not probe_bytes:
        return []
    return [
        line.split("\t") for line in probe_bytes.decode("utf-8").splitlines() if line
    ]


# ---- touched.py: pure -------------------------------------------------------


# ---- touched.py: the requirement-based match rule (defect A fix) ------------


def test_touched_entries_matches_same_name_same_value():
    """A staged `set` with the same cfg/section/option/VALUE satisfies the
    control's matching requirement (the bare-name bug is gone)."""
    controls = [
        {"id": "A", "batch": ["set system.x.foo='1'"],
         "probes": [["fail"]]},
    ]
    assert touched.touched_entries(
        controls, "set system.x.foo='1'") == [0]


def test_touched_entries_value_mismatch_does_not_match():
    """Defect A: a setting on the same option with a DIFFERENT value
    (e.g. ``dnssec='0'`` when the control requires ``dnssec='1'``) must
    NOT seal the control's probes (no false rollback of a legitimate
    change)."""
    controls = [
        {"id": "OW-DNS-04", "batch": ["set dhcp.@dnsmasq[0].dnssec='1'"],
         "probes": [["conf-has", "dnsmasq", "line", "present", "dnssec"]]},
    ]
    # ``dnssec='0'`` (a legitimate user choice) does NOT match the
    # ``dnssec='1'`` requirement -> empty list (no entry index).
    assert touched.touched_entries(
        controls, "set dhcp.@dnsmasq[0].dnssec='0'") == []
    # ``dnssec='1'`` does match.
    assert touched.touched_entries(
        controls, "set dhcp.@dnsmasq[0].dnssec='1'") == [0]


def test_touched_entries_partial_two_line_control_no_match():
    """A control whose batch has TWO ``set`` lines (every requirement must
    be satisfied) is matched only when EVERY line is staged."""
    controls = [
        {"id": "TWO-LINE",
         "batch": [
             "set dropbear.@dropbear[0].PasswordAuth='0'",
             "set dropbear.@dropbear[0].RootPasswordAuth='0'",
         ],
         "probes": [["fail"]]},
    ]
    # only PasswordAuth staged -> req RootPasswordAuth='0' unmet -> no match
    assert touched.touched_entries(
        controls, "set dropbear.@dropbear[0].PasswordAuth='0'") == []
    # both lines staged -> match
    assert touched.touched_entries(
        controls,
        "set dropbear.@dropbear[0].PasswordAuth='0'\n"
        "set dropbear.@dropbear[0].RootPasswordAuth='0'\n",
    ) == [0]


def test_touched_entries_set_and_add_list_are_different_kinds():
    """A ``set`` requirement is satisfied by a ``set`` fact with the
    same value; an ``add_list`` fact does NOT satisfy it (the kinds are
    distinct, even when the option+value match)."""
    controls = [
        {"id": "SET-CTRL", "batch": ["set dhcp.@dnsmasq[0].server='1.1.1.1'"],
         "probes": [["fail"]]},
        {"id": "ADD-CTRL",
         "batch": ["add_list dhcp.@dnsmasq[0].server='1.1.1.1'"],
         "probes": [["fail"]]},
    ]
    # ``set ...='1.1.1.1'`` satisfies the set requirement, not the
    # add_list one.
    assert touched.touched_entries(
        controls, "set dhcp.@dnsmasq[0].server='1.1.1.1'") == [0]
    # ``add_list ...='1.1.1.1'`` satisfies the add_list requirement, not
    # the set one.
    assert touched.touched_entries(
        controls, "add_list dhcp.@dnsmasq[0].server='1.1.1.1'") == [1]


def test_touched_entries_duplicate_id_siblings_match_by_value():
    """Two manifest entries with the SAME id but different values are
    distinct entries.  Each entry matches only its own value; staging
    BOTH values seals only the LAST one (defect 2: batch facts are
    LAST-WINS in batch order; the router commits the later value)."""
    controls = [
        {"id": "OW-FW-06",
         "batch": ["set upnpd.config.enabled='0'"],
         "probes": [["ping", "192.0.2.1"]]},
        {"id": "OW-FW-06",
         "batch": ["set upnpd.config.enabled='1'"],
         "probes": [["ping", "192.0.2.2"]]},
    ]
    # stage only ``0`` -> entry 0 matches, entry 1 does not.
    assert touched.touched_entries(
        controls, "set upnpd.config.enabled='0'") == [0]
    # stage only ``1`` -> entry 1 matches, entry 0 does not.
    assert touched.touched_entries(
        controls, "set upnpd.config.enabled='1'") == [1]
    # staging BOTH values: only the later one survives (LAST-WINS),
    # so only entry 1 matches.
    assert touched.touched_entries(
        controls,
        "set upnpd.config.enabled='0'\n"
        "set upnpd.config.enabled='1'\n",
    ) == [1]
    # the deduped-id view collapses the duplicate id.
    assert touched.touched_control_ids(
        controls,
        "set upnpd.config.enabled='0'\n"
        "set upnpd.config.enabled='1'\n",
    ) == ["OW-FW-06"]


def test_touched_entries_placeholder_in_batch_never_matches():
    """A control with ANY ``{placeholder}`` in its batch is NEVER matched
    (lab-bound; not convertible on the host)."""
    controls = [
        {"id": "WITH-PH",
         "batch": [
             "set dropbear.@dropbear[0].Interface='lan'",
             "set firewall.{fw_wan_zone}.input='DROP'",
         ],
         "probes": [["fail"]]},
    ]
    # even when every other line is staged with the same value, the
    # placeholder line keeps the control unconvertible -> no match.
    assert touched.touched_entries(
        controls,
        "set dropbear.@dropbear[0].Interface='lan'\n"
        "set firewall.{fw_wan_zone}.input='DROP'\n",
    ) == []


def test_touched_entries_delete_lines_in_batch_do_not_block_match():
    """``delete`` / ``del_list`` in a control's batch are IGNORED for
    matching.  A control with a ``delete`` line and a ``set`` line
    matches when the ``set`` line's value is staged (the delete does
    not contribute a requirement)."""
    controls = [
        {"id": "DEL-OK",
         "batch": [
             "delete dhcp.skilltest",
             "set dhcp.skilltest.foo='1'",
         ],
         "probes": [["fail"]]},
        {"id": "DEL-ONLY",
         "batch": ["delete dhcp.skilltest"],
         "probes": [["fail"]]},
    ]
    # the set line is staged -> DEL-OK matches (the delete is ignored);
    # DEL-ONLY has no set/add_list lines so it never matches (no reqs).
    assert touched.touched_entries(
        controls, "set dhcp.skilltest.foo='1'") == [0]
    # staging a delete still doesn't satisfy anyone (delete never
    # produces a fact).
    assert touched.touched_entries(
        controls, "delete dhcp.skilltest") == []


def test_touched_entries_diff_only_value_match_through_section_lines():
    """A diff line whose SECTION fact resolves to a type matches a
    control batched at the typed section, even when the control's
    anonymous index (``@dnsmasq[0]``) and the diff's widened wildcard
    (``@dnsmasq[*]``) differ; the value must still match."""
    controls = [
        {"id": "DNSSEC",
         "batch": ["set dhcp.@dnsmasq[0].dnssec='1'"],
         "probes": [["fail"]]},
    ]
    assert touched.touched_entries(
        controls, "",
        diff="dhcp.cfg01411c.dnssec='1'\n",
        section_lines=("dhcp cfg01411c dnsmasq dnsmasq",),
    ) == [0]
    # the diff value differs -> no match.
    assert touched.touched_entries(
        controls, "",
        diff="dhcp.cfg01411c.dnssec='0'\n",
        section_lines=("dhcp cfg01411c dnsmasq dnsmasq",),
    ) == []


def test_touched_entries_diff_minus_lines_do_not_satisfy():
    """A diff ``-`` (removal) line never satisfies a requirement; only
    op ``""`` or ``+`` with a value count.  Same applies to ``@``
    (rename) and ``^`` (reorder)."""
    controls = [
        {"id": "REMOVED",
         "batch": ["set dhcp.@dnsmasq[0].dnssec='1'"],
         "probes": [["fail"]]},
    ]
    # the diff is a removal of the option; no satisfying fact is emitted.
    assert touched.touched_entries(
        controls, "",
        diff="-dhcp.cfg01411c.dnssec='1'\n",
        section_lines=("dhcp cfg01411c dnsmasq dnsmasq",),
    ) == []
    # ``@`` rename and ``^`` reorder also do not satisfy.
    assert touched.touched_entries(
        controls, "",
        diff="@dhcp.cfg01411c=newname\n",
        section_lines=("dhcp cfg01411c dnsmasq dnsmasq",),
    ) == []


def test_touched_entries_add_list_requirement_via_two_diff_lines():
    """An ``add_list`` requirement is satisfied by diff ``+`` (add_list)
    lines; each list item is its own fact.  A two-line control matches
    when the diff surfaces BOTH values."""
    controls = [
        {"id": "TWO-ADDLIST",
         "batch": [
             "add_list firewall.@rule[3].src_ip='10.0.0.0/8'",
             "add_list firewall.@rule[3].src_ip='192.168.0.0/16'",
         ],
         "probes": [["fail"]]},
    ]
    diff = (
        "firewall.@rule[3].src_ip+='10.0.0.0/8'\n"
        "firewall.@rule[3].src_ip+='192.168.0.0/16'\n"
    )
    assert touched.touched_entries(controls, "", diff=diff) == [0]
    # only one of the two add_list values -> no match (every req needed).
    assert touched.touched_entries(
        controls, "",
        diff="firewall.@rule[3].src_ip+='10.0.0.0/8'\n",
    ) == []


def test_touched_entries_anonymous_exact_index_against_batch():
    """Batch anonymous ``@type[i]`` must match the exact index on the
    other side (a specific index does not widen).  Same value too."""
    controls = [
        {"id": "A", "batch": ["set dhcp.@dnsmasq[0].x='1'"],
         "probes": [["fail"]]},
    ]
    assert touched.touched_entries(
        controls, "set dhcp.@dnsmasq[0].x='1'") == [0]
    assert touched.touched_entries(
        controls, "set dhcp.@dnsmasq[1].x='1'") == []
    assert touched.touched_entries(
        controls, "set dhcp.@other[0].x='1'") == []


def test_touched_entries_named_section_with_type_fact_matches_both_forms():
    """A diff on a named section that the SECTION fact resolves to a
    type matches BOTH a control batched as `set network.lan.ipaddr=...`
    and a control batched as `set network.@interface[0].ipaddr=...`,
    PROVIDED the values match.  An unrelated-type control does not
    match."""
    controls = [
        {"id": "NAMED-EXACT",
         "batch": ["set network.lan.ipaddr='x'"],
         "probes": [["fail"]]},
        {"id": "TYPED-INTERFACE",
         "batch": ["set network.@interface[0].ipaddr='x'"],
         "probes": [["fail"]]},
        {"id": "UNRELATED-TYPE",
         "batch": ["set network.@other[0].ipaddr='x'"],
         "probes": [["fail"]]},
    ]
    # same value on the diff -> NAMED-EXACT and TYPED-INTERFACE match,
    # UNRELATED-TYPE does not.
    matched = touched.touched_entries(
        controls, "",
        diff="network.lan.ipaddr='x'\n",
        section_lines=("network lan interface lan",),
    )
    assert 0 in matched
    assert 1 in matched
    assert 2 not in matched
    # different value on the diff -> none match.
    assert touched.touched_entries(
        controls, "",
        diff="network.lan.ipaddr='10.0.0.1/24'\n",
        section_lines=("network lan interface lan",),
    ) == []


def test_touched_entries_two_controls_same_target_once_each():
    """Two controls with the same requirement each fire once."""
    controls = [
        {"id": "A", "batch": ["set dhcp.@dnsmasq[0].x='1'"],
         "probes": [["fail"]]},
        {"id": "B", "batch": ["set dhcp.@dnsmasq[0].x='1'"],
         "probes": [["fail"]]},
    ]
    assert touched.touched_entries(
        controls, "set dhcp.@dnsmasq[0].x='1'") == [0, 1]


def test_touched_entries_caller_id_and_auto_id_dedup_in_id_view():
    """The id view dedupes; both entries contribute to the sealed
    probe list (see ``seal_manifest_ids`` for the full behaviour)."""
    controls = [
        {"id": "A", "batch": ["set dhcp.@dnsmasq[0].x='1'"],
         "probes": [["fail"]]},
    ]
    assert touched.touched_control_ids(
        controls, "set dhcp.@dnsmasq[0].x='1'") == ["A"]


def test_touched_entries_ignores_controls_without_probes_key():
    """Unconverted controls (no ``probes`` key) are silently skipped."""
    controls = [
        {"id": "OLD", "batch": ["set dhcp.@dnsmasq[0].x='1'"],
         "check": "echo ok"},
        {"id": "NEW", "batch": ["set dhcp.@dnsmasq[0].x='1'"],
         "probes": [["fail"]]},
    ]
    assert touched.touched_entries(
        controls, "set dhcp.@dnsmasq[0].x='1'") == [1]


def test_touched_entries_named_section_starting_with_cfg_matches_by_name():
    """A named section whose name happens to start with ``cfg`` (e.g.
    ``foo.cfgmain``) is a real UCI named section, NOT an anonymous raw
    id.  ``_section_kind`` must NOT classify it as ``cfgxxx`` just
    because the string starts with ``cfg``; only the ``cfg`` + six hex
    chars raw anonymous id form counts.  A control batched at the same
    named path matches when the staged batch sets the same option to
    the same value."""
    controls = [
        {"id": "NAMED-CFG",
         "batch": ["set foo.cfgmain.opt='1'"],
         "probes": [["fail"]]},
    ]
    assert touched.touched_entries(
        controls, "set foo.cfgmain.opt='1'") == [0]


def test_touched_entries_empty_batch_never_matches():
    controls = [{"id": "EMPTY", "batch": [], "probes": [["fail"]]}]
    assert touched.touched_entries(
        controls, "set dhcp.@dnsmasq[0].x='1'") == []


def test_touched_entries_junk_batch_lines_never_match():
    """Junk lines in a control's batch never become requirements; a
    real ``set`` line alone matches when the staged fact has the same
    value."""
    controls = [
        {"id": "JUNK",
         "batch": [
             "set ",                    # no path
             "set bogus=value",         # bogus cfg
             "set dhcp..x=1",           # empty section
             "set dhcp.@invalid[99999].y=z",   # out-of-cap index
             "set dhcp.bad!section.x=1",   # '!' not in section name regex
             "# set dhcp.@dnsmasq[0].dnssec='1'",   # comment
             "set dhcp.@dnsmasq[0].dnssec='1'",   # the one good line
         ],
         "probes": [["fail"]]},
    ]
    assert touched.touched_entries(
        controls, "set dhcp.@dnsmasq[0].dnssec='1'") == [0]


def test_touched_entries_set_minus_marker_is_not_a_fact():
    """``set cfg.sec.opt-='v'`` is UCI sugar for del_list (REMOVES ``v``);
    it must NEVER produce a fact (and never become a requirement).  A
    batch that uses the ``-`` marker does not satisfy any requirement
    and is not satisfied by any staged fact (it is not a fact at all)."""
    controls = [
        {"id": "OW-FW-06",
         "batch": ["set upnpd.config.enabled='1'"],
         "probes": [["fail"]]},
    ]
    # ``set upnpd.config.enabled-='1'`` is del_list sugar; it does NOT
    # emit a satisfying fact for the enabled='1' requirement.
    assert touched.touched_entries(
        controls, "set upnpd.config.enabled-='1'") == []
    # same value via the plain ``set`` marker DOES match.
    assert touched.touched_entries(
        controls, "set upnpd.config.enabled='1'") == [0]


def test_touched_entries_minus_marker_in_control_batch_does_not_match():
    """The ``-`` marker in a control's batch line is also UCI sugar for
    del_list (it REMOVES the value).  A control batch line with a ``-``
    marker must never produce a requirement (no false rollback of a
    legitimate removal)."""
    controls = [
        {"id": "DEL-CTRL",
         "batch": ["set upnpd.config.enabled-='1'"],
         "probes": [["fail"]]},
        {"id": "SET-CTRL",
         "batch": ["set upnpd.config.enabled='1'"],
         "probes": [["fail"]]},
    ]
    # the staging does not satisfy the DEL-CTRL (no requirement was
    # emitted) and does satisfy SET-CTRL.
    assert touched.touched_entries(
        controls, "set upnpd.config.enabled='1'") == [1]


def test_touched_entries_section_create_dropped_when_options_present():
    """A control whose batch has BOTH a section-create line (``set
    firewall.block_dot=rule``) AND option lines has its section-level
    requirement dropped when at least one option-level requirement
    exists, so re-applying only the option lines onto an existing
    section still matches (the diff never shows the section-create
    line then).  A control whose ONLY requirement is section-level
    keeps it."""
    option_lines = [
        "set firewall.block_dot.name='Block-DoT'",
        "set firewall.block_dot.src='lab'",
        "set firewall.block_dot.dest='wan'",
        "set firewall.block_dot.proto='tcp'",
        "set firewall.block_dot.dest_port='853'",
        "set firewall.block_dot.target='REJECT'",
    ]
    full_batch = ["set firewall.block_dot=rule"] + option_lines

    controls_with = [
        {"id": "OW-DNS-07", "batch": full_batch, "probes": [["fail"]]},
    ]
    controls_without = [
        {"id": "OW-DNS-07", "batch": option_lines, "probes": [["fail"]]},
    ]
    # the option lines alone match (the section-create line is dropped
    # because the control has at least one option-level requirement).
    assert touched.touched_entries(
        controls_without, "\n".join(option_lines)) == [0]
    # the full batch also matches.
    assert touched.touched_entries(
        controls_with, "\n".join(full_batch)) == [0]

    # a control whose ONLY requirement is section-level keeps it:
    # re-applying just the create line onto an existing section does
    # not match (the diff then has no section-create line).
    section_only = [
        {"id": "CREATE-ONLY",
         "batch": ["set firewall.block_dot=rule"],
         "probes": [["fail"]]},
    ]
    assert touched.touched_entries(section_only, "") == []
    # staging the create line itself does match.
    assert touched.touched_entries(
        section_only, "set firewall.block_dot=rule") == [0]


def test_needs_restage_no_miss_returns_empty():
    assert touched.needs_restage(
        [0, 1], [1]) == (False, [])


def test_needs_restage_misses_listed_stably_and_deduped():
    needs, miss = touched.needs_restage(
        [0], [1, 0, 1, 2])
    assert needs is True
    assert miss == [1, 2]


def test_needs_restage_uses_indexes_not_ids():
    """``needs_restage`` compares entry INDEXES; ids are only for
    messages and the record.  A duplicate-id sibling is a distinct
    index from its sibling."""
    needs, miss = touched.needs_restage(
        [0, 2], [0, 1, 3])
    assert needs is True
    assert miss == [1, 3]


def test_seal_manifest_ids_duplicate_id_sibling_seals_both():
    """A duplicate-id sibling in the auto path is fine: each entry
    contributes its own probes.  The id appears ONCE in the sealed id
    list; the manifest_probes carry both entries' probes."""
    controls = [
        {"id": "OW-FW-06",
         "batch": ["set upnpd.config.enabled='0'"],
         "probes": [["ping", "192.0.2.1"], ["ping", "192.0.2.3"]]},
        {"id": "OW-FW-06",
         "batch": ["set upnpd.config.enabled='1'"],
         "probes": [["ping", "192.0.2.2"], ["ping", "192.0.2.4"]]},
    ]
    sealed_entries, manifest_probes = touched.seal_manifest_ids(
        [], [0, 1], controls=controls,
    )
    assert sealed_entries == [0, 1]
    # both entries' probes are sealed (probe lines of one id twice are
    # fine).
    assert manifest_probes == [
        ["ping", "192.0.2.1"], ["ping", "192.0.2.3"],
        ["ping", "192.0.2.2"], ["ping", "192.0.2.4"],
    ]
    # the id view dedupes.
    assert touched.entry_ids(controls, sealed_entries) == ["OW-FW-06"]


def test_seal_manifest_ids_caller_id_ambiguous_refused():
    """Caller id that names more than one entry stays REFUSED (matches
    the existing ``expand_manifest_checks`` refusal).  The auto path
    accepts the same ambiguity."""
    controls = [
        {"id": "OW-FW-06",
         "batch": ["set upnpd.config.enabled='0'"],
         "probes": [["ping", "192.0.2.1"]]},
        {"id": "OW-FW-06",
         "batch": ["set upnpd.config.enabled='1'"],
         "probes": [["ping", "192.0.2.2"]]},
    ]
    with pytest.raises(ValueError, match="more than one"):
        touched.seal_manifest_ids(
            ["OW-FW-06"], [], controls=controls,
        )
    # auto entries by index: accepted (fine).
    sealed_entries, _ = touched.seal_manifest_ids(
        [], [0, 1], controls=controls,
    )
    assert sealed_entries == [0, 1]


# ---- server.py: integration with a fake manifest ----------------------------


MANIFEST_OK = """
[[control]]
id = 'MADE-UP-01'
tier = 'standard'
check_host = 'router'
batch = [ "set dhcp.@dnsmasq[0].dnssec='1'" ]
probes = [["conf-has", "dnsmasq", "line", "present", "dnssec"]]

[[control]]
id = 'MADE-UP-02'
tier = 'standard'
check_host = 'router'
batch = [ "set system.x.foo='1'" ]
probes = [["ping", "192.0.2.1"]]

[[control]]
id = 'MADE-UP-03'
tier = 'standard'
check_host = 'router'
batch = [ "set system.y.foo='1'" ]
probes = [["ping", "192.0.2.2"]]
"""


def test_dnssec_value_zero_adds_no_dnssec_probe(
    configured_lab, tmp_path, monkeypatch
):
    """``dnssec='0'`` is a legitimate user choice; the plan must not
    seal the dnssec-line probe (no false rollback)."""
    monkeypatch.setenv("NEWTON_MANIFEST", str(_manifest(tmp_path, MANIFEST_OK)))
    calls: list[Any] = []
    monkeypatch.setattr(server.NewtonService, "run_script", _fake_script(calls))
    planned = server.newton_plan_change(
        "quasar", "set dhcp.@dnsmasq[0].dnssec='0'", **explained("set dhcp.@dnsmasq[0].dnssec='0'"),
    )
    assert "error" not in planned
    # no probe was sealed: the router saw an empty probe file.
    probe_bytes = calls[0][3]
    fields = _read_probe_bytes(probe_bytes)
    assert ["conf-has", "dnsmasq", "line", "present", "dnssec"] not in fields
    record = json.loads(
        (configured_lab / "state" / "plans" / f"{SID}.json").read_text())
    assert "manifest_checks_auto" not in record


def test_dnssec_value_one_adds_dnssec_probe(
    configured_lab, tmp_path, monkeypatch
):
    """``dnssec='1'`` matches the control's requirement; the plan seals
    the dnssec-line probe and records ``manifest_checks_auto``."""
    monkeypatch.setenv("NEWTON_MANIFEST", str(_manifest(tmp_path, MANIFEST_OK)))
    calls: list[Any] = []
    monkeypatch.setattr(server.NewtonService, "run_script", _fake_script(calls))
    planned = server.newton_plan_change(
        "quasar", "set dhcp.@dnsmasq[0].dnssec='1'", **explained("set dhcp.@dnsmasq[0].dnssec='1'"),
    )
    assert "error" not in planned
    probe_bytes = calls[0][3]
    fields = _read_probe_bytes(probe_bytes)
    assert ["conf-has", "dnsmasq", "line", "present", "dnssec"] in fields
    record = json.loads(
        (configured_lab / "state" / "plans" / f"{SID}.json").read_text())
    assert record["manifest_checks_auto"] == ["MADE-UP-01"]
    assert record["manifest_checks"] == []
    assert record["probes"] == fields


def test_two_line_control_partial_batch_adds_no_auto_ids(
    configured_lab, tmp_path, monkeypatch
):
    """A control with TWO ``set`` lines is matched only when BOTH are
    staged.  Staging only one is a legitimate user choice and must
    NOT seal the control's probes."""
    manifest = """
[[control]]
id = 'TWO-LINE'
tier = 'standard'
check_host = 'router'
batch = [
  "set dropbear.@dropbear[0].PasswordAuth='0'",
  "set dropbear.@dropbear[0].RootPasswordAuth='0'",
]
probes = [["fail"]]
"""
    monkeypatch.setenv("NEWTON_MANIFEST", str(_manifest(tmp_path, manifest)))
    calls: list[Any] = []
    monkeypatch.setattr(server.NewtonService, "run_script", _fake_script(calls))
    planned = server.newton_plan_change(
        "quasar", "set dropbear.@dropbear[0].PasswordAuth='0'", **explained("set dropbear.@dropbear[0].PasswordAuth='0'"),
    )
    assert "error" not in planned
    record = json.loads(
        (configured_lab / "state" / "plans" / f"{SID}.json").read_text())
    assert "manifest_checks_auto" not in record


def test_two_line_control_all_lines_staged_adds_auto_ids(
    configured_lab, tmp_path, monkeypatch
):
    """Staging BOTH lines of a two-line control seals its probes and
    records ``manifest_checks_auto``."""
    manifest = """
[[control]]
id = 'TWO-LINE'
tier = 'standard'
check_host = 'router'
batch = [
  "set dropbear.@dropbear[0].PasswordAuth='0'",
  "set dropbear.@dropbear[0].RootPasswordAuth='0'",
]
probes = [["fail"]]
"""
    monkeypatch.setenv("NEWTON_MANIFEST", str(_manifest(tmp_path, manifest)))
    calls: list[Any] = []
    monkeypatch.setattr(server.NewtonService, "run_script", _fake_script(calls))
    planned = server.newton_plan_change(
        "quasar",
        "set dropbear.@dropbear[0].PasswordAuth='0'\n"
        "set dropbear.@dropbear[0].RootPasswordAuth='0'\n", **explained("set dropbear.@dropbear[0].PasswordAuth='0'\n"
        "set dropbear.@dropbear[0].RootPasswordAuth='0'\n"),
    )
    assert "error" not in planned
    record = json.loads(
        (configured_lab / "state" / "plans" / f"{SID}.json").read_text())
    assert record["manifest_checks_auto"] == ["TWO-LINE"]


def test_placeholder_in_batch_never_seals(configured_lab, tmp_path, monkeypatch):
    """A control with a ``{placeholder}`` in its batch is NEVER sealed;
    even when the other non-placeholder lines are staged, the
    placeholder keeps the control unconvertible."""
    manifest = """
[[control]]
id = 'PLACEHOLDER-CTRL'
tier = 'standard'
check_host = 'router'
batch = [
  "set dropbear.@dropbear[0].Interface='lan'",
  "set firewall.{fw_wan_zone}.input='DROP'",
]
probes = [["fail"]]
"""
    monkeypatch.setenv("NEWTON_MANIFEST", str(_manifest(tmp_path, manifest)))
    calls: list[Any] = []
    monkeypatch.setattr(server.NewtonService, "run_script", _fake_script(calls))
    planned = server.newton_plan_change(
        "quasar", "set dropbear.@dropbear[0].Interface='lan'", **explained("set dropbear.@dropbear[0].Interface='lan'"),
    )
    assert "error" not in planned
    record = json.loads(
        (configured_lab / "state" / "plans" / f"{SID}.json").read_text())
    assert "manifest_checks_auto" not in record


def test_delete_lines_in_control_batch_do_not_block_match(
    configured_lab, tmp_path, monkeypatch
):
    """A control with a ``delete`` line and a ``set`` line matches when
    the ``set`` line's value is staged; the ``delete`` is IGNORED for
    matching (no requirement, no false rollback)."""
    manifest = """
[[control]]
id = 'MIXED-DEL-SET'
tier = 'standard'
check_host = 'router'
batch = [
  "delete dhcp.skilltest",
  "set dhcp.skilltest.foo='1'",
]
probes = [["fail"]]
"""
    monkeypatch.setenv("NEWTON_MANIFEST", str(_manifest(tmp_path, manifest)))
    calls: list[Any] = []
    monkeypatch.setattr(server.NewtonService, "run_script", _fake_script(calls))
    planned = server.newton_plan_change(
        "quasar", "set dhcp.skilltest.foo='1'", **explained("set dhcp.skilltest.foo='1'"),
    )
    assert "error" not in planned
    record = json.loads(
        (configured_lab / "state" / "plans" / f"{SID}.json").read_text())
    assert record["manifest_checks_auto"] == ["MIXED-DEL-SET"]


def test_add_list_kind_match(configured_lab, tmp_path, monkeypatch):
    """An ``add_list`` requirement is satisfied by an ``add_list`` fact
    with the same value; a ``set`` fact does NOT satisfy it."""
    manifest = """
[[control]]
id = 'LIST-CTRL'
tier = 'standard'
check_host = 'router'
batch = [ "add_list dhcp.@dnsmasq[0].server='1.1.1.1'" ]
probes = [["fail"]]
"""
    monkeypatch.setenv("NEWTON_MANIFEST", str(_manifest(tmp_path, manifest)))
    calls: list[Any] = []
    monkeypatch.setattr(server.NewtonService, "run_script", _fake_script(calls))
    # a set with the same option+value does NOT match (different kind).
    planned = server.newton_plan_change(
        "quasar", "set dhcp.@dnsmasq[0].server='1.1.1.1'", **explained("set dhcp.@dnsmasq[0].server='1.1.1.1'"),
    )
    assert "error" not in planned
    record = json.loads(
        (configured_lab / "state" / "plans" / f"{SID}.json").read_text())
    assert "manifest_checks_auto" not in record
    # an add_list with the same option+value matches.
    planned = server.newton_plan_change(
        "quasar", "add_list dhcp.@dnsmasq[0].server='1.1.1.1'", **explained("add_list dhcp.@dnsmasq[0].server='1.1.1.1'"),
    )
    assert "error" not in planned
    record = json.loads(
        (configured_lab / "state" / "plans" / f"{SID}.json").read_text())
    assert record["manifest_checks_auto"] == ["LIST-CTRL"]


def test_duplicate_id_siblings_seal_both_and_id_once_in_record(
    configured_lab, tmp_path, monkeypatch
):
    """Two manifest entries with the same id but different values are
    distinct entries; staging both values seals only the LAST one
    (defect 2: batch facts are LAST-WINS; the router commits the later
    value).  The record carries the id ONCE."""
    manifest = """
[[control]]
id = 'OW-FW-06'
tier = 'standard'
check_host = 'router'
batch = [ "set upnpd.config.enabled='0'" ]
probes = [["ping", "192.0.2.1"]]

[[control]]
id = 'OW-FW-06'
tier = 'standard'
check_host = 'router'
batch = [ "set upnpd.config.enabled='1'" ]
probes = [["ping", "192.0.2.2"]]
"""
    monkeypatch.setenv("NEWTON_MANIFEST", str(_manifest(tmp_path, manifest)))
    calls: list[Any] = []
    monkeypatch.setattr(server.NewtonService, "run_script", _fake_script(calls))
    planned = server.newton_plan_change(
        "quasar",
        "set upnpd.config.enabled='0'\n"
        "set upnpd.config.enabled='1'\n", **explained("set upnpd.config.enabled='0'\n"
        "set upnpd.config.enabled='1'\n"),
    )
    assert "error" not in planned
    probe_bytes = calls[0][3]
    fields = _read_probe_bytes(probe_bytes)
    # only the LAST entry's probes are sealed (LAST-WINS).
    assert ["ping", "192.0.2.2"] in fields
    assert ["ping", "192.0.2.1"] not in fields
    record = json.loads(
        (configured_lab / "state" / "plans" / f"{SID}.json").read_text())
    # the record carries the id ONCE (manifest_checks_auto is deduped).
    assert record["manifest_checks_auto"] == ["OW-FW-06"]


def test_named_section_batch(configured_lab, tmp_path, monkeypatch):
    """A ``set system.x.foo='1'`` batch matches a control whose batch
    sets the same option to the same value.  The old section-level
    match is gone: a ``set system.x=anything`` (which has option=None
    and value 'anything') does NOT seal a control that requires
    ``set system.x.foo='1'``."""
    monkeypatch.setenv("NEWTON_MANIFEST", str(_manifest(tmp_path, MANIFEST_OK)))
    calls: list[Any] = []
    monkeypatch.setattr(server.NewtonService, "run_script", _fake_script(calls))
    planned = server.newton_plan_change(
        "quasar", "set system.x.foo='1'", **explained("set system.x.foo='1'"),
    )
    assert "error" not in planned
    record = json.loads(
        (configured_lab / "state" / "plans" / f"{SID}.json").read_text())
    assert record["manifest_checks_auto"] == ["MADE-UP-02"]


def test_unrelated_batch_adds_no_auto_ids(configured_lab, tmp_path, monkeypatch):
    monkeypatch.setenv("NEWTON_MANIFEST", str(_manifest(tmp_path, MANIFEST_OK)))
    calls: list[Any] = []
    monkeypatch.setattr(server.NewtonService, "run_script", _fake_script(calls))
    planned = server.newton_plan_change(
        "quasar", "set firewall.@defaults[0].x='1'", probes=[["fail"]], **explained("set firewall.@defaults[0].x='1'"),
    )
    assert "error" not in planned
    record = json.loads(
        (configured_lab / "state" / "plans" / f"{SID}.json").read_text())
    assert "manifest_checks_auto" not in record  # none added: key absent


def test_caller_id_and_auto_id_appear_once(configured_lab, tmp_path, monkeypatch):
    """If the caller already asked for an id the auto-derivation adds, the
    plan records it once and the expansion does not refuse duplicates."""
    monkeypatch.setenv("NEWTON_MANIFEST", str(_manifest(tmp_path, MANIFEST_OK)))
    calls: list[Any] = []
    monkeypatch.setattr(server.NewtonService, "run_script", _fake_script(calls))
    planned = server.newton_plan_change(
        "quasar", "set dhcp.@dnsmasq[0].dnssec='1'",
        manifest_checks=["MADE-UP-01"], **explained("set dhcp.@dnsmasq[0].dnssec='1'"),
    )
    assert "error" not in planned
    record = json.loads(
        (configured_lab / "state" / "plans" / f"{SID}.json").read_text())
    assert record["manifest_checks"] == ["MADE-UP-01"]
    assert record["manifest_checks_auto"] == ["MADE-UP-01"]
    # dedupe before expand_manifest_checks: a duplicate id would refuse
    fields = _read_probe_bytes(calls[0][3])
    assert ["conf-has", "dnsmasq", "line", "present", "dnssec"] in fields
    assert fields.count(["conf-has", "dnsmasq", "line", "present", "dnssec"]) == 1


def test_overflow_32_probe_lines_refuses_naming_the_ids(configured_lab, tmp_path, monkeypatch):
    """Adding the touched ids pushes the probe file past the 32-line cap
    -> the plan is refused with a NewtonError that names the offending ids."""
    manifest = """
[[control]]
id = 'OVERFLOW-CTRL'
tier = 'standard'
check_host = 'router'
batch = [ "set dhcp.@dnsmasq[0].dnssec='1'" ]
probes = """ + repr([["fail"]] * (probes.MAX_PROBE_LINES + 1)) + """
"""
    monkeypatch.setenv("NEWTON_MANIFEST", str(_manifest(tmp_path, manifest)))
    calls: list[Any] = []
    monkeypatch.setattr(server.NewtonService, "run_script", _fake_script(calls))
    result = server.newton_plan_change(
        "quasar", "set dhcp.@dnsmasq[0].dnssec='1'", **explained("set dhcp.@dnsmasq[0].dnssec='1'"),
    )
    # the plan refused: no script call, error mentions OVERFLOW-CTRL
    assert calls == []
    assert "OVERFLOW-CTRL" in (result.get("error") or "")


def test_diff_only_match_aborts_and_replans(configured_lab, tmp_path, monkeypatch):
    """A diff that adds an entry NOT in the batch-derived sealed set
    -> the plan aborts the first session and re-stages once with the
    union."""
    manifest = """
[[control]]
id = 'DNSSEC-ONLY'
tier = 'standard'
check_host = 'router'
batch = [ "set dhcp.@dnsmasq[0].dnssec='1'" ]
probes = [["conf-has", "dnsmasq", "line", "present", "dnssec"]]
"""
    monkeypatch.setenv("NEWTON_MANIFEST", str(_manifest(tmp_path, manifest)))
    first_diff = (
        "system.x='whatever'\n"
        "dhcp.cfg01411c.dnssec='1'\n"
    )
    sections = ("dhcp cfg01411c dnsmasq dnsmasq",)
    calls: list[Any] = []
    out1 = plan_output(diff=first_diff, extra_sections=sections)
    monkeypatch.setattr(
        server.NewtonService, "run_script",
        _fake_script(calls, [out1, out1]),
    )
    server.newton_plan_change(
        "quasar", "set system.x=whatever", **explained("set system.x=whatever"),
    )
    argv = [c[0][0] for c in calls]
    assert argv[0] == "plan"
    assert argv[1] == "abort"
    assert argv[2] == "plan"
    fields2 = _read_probe_bytes(calls[2][3])
    assert ["conf-has", "dnsmasq", "line", "present", "dnssec"] in fields2
    record = json.loads(
        (configured_lab / "state" / "plans" / f"{SID}.json").read_text())
    sealed = record["manifest_checks"] + record.get(
        "manifest_checks_auto", []
    )
    assert "DNSSEC-ONLY" in sealed


def test_restage_that_still_disagrees_aborts_and_raises(
    configured_lab, tmp_path, monkeypatch
):
    """The union restage STILL reveals entries outside its own sealed
    set -> abort and NewtonError naming the missing CONTROL ID (not the
    entry index)."""
    manifest = """
[[control]]
id = 'A'
tier = 'standard'
check_host = 'router'
batch = [ "set dhcp.@dnsmasq[0].a='1'" ]
probes = [["fail"]]

[[control]]
id = 'B'
tier = 'standard'
check_host = 'router'
batch = [ "set dhcp.@dnsmasq[0].b='1'" ]
probes = [["fail"]]

[[control]]
id = 'C'
tier = 'standard'
check_host = 'router'
batch = [ "set dhcp.@host[3].x='1'" ]
probes = [["fail"]]
"""
    monkeypatch.setenv("NEWTON_MANIFEST", str(_manifest(tmp_path, manifest)))
    first_diff = (
        "dhcp.cfg01411c.a='1'\n"
        "dhcp.cfg01411c.b='1'\n"
    )
    second_diff = "dhcp.cfg02222.x='1'\n"
    out1 = plan_output(diff=first_diff,
                       extra_sections=("dhcp cfg01411c dnsmasq dnsmasq",))
    out2 = plan_output(diff=second_diff,
                       extra_sections=("dhcp cfg02222 host somehost",))
    calls: list[Any] = []
    monkeypatch.setattr(
        server.NewtonService, "run_script",
        _fake_script(calls, [out1, out1, out2, out2]),
    )
    result = server.newton_plan_change(
        "quasar", "set dhcp.@dnsmasq[0].a='1'", **explained("set dhcp.@dnsmasq[0].a='1'"),
    )
    assert "error" in result
    argv = [c[0][0] for c in calls]
    # sequence: plan, abort, plan, abort -> abort shows up at indices 1, 3
    assert argv.count("abort") == 2
    # the missing CONTROL ID is in the message (the third entry's id is
    # 'C', not the positional index '2').
    assert "missing" in result["error"]
    assert "C" in result["error"]
    # no plan record left behind after the second abort
    assert list((configured_lab / "state" / "plans").glob("*.json")) == []


def test_junk_batch_lines_never_raise(configured_lab, tmp_path, monkeypatch):
    monkeypatch.setenv("NEWTON_MANIFEST", str(_manifest(tmp_path, MANIFEST_OK)))
    calls: list[Any] = []
    monkeypatch.setattr(server.NewtonService, "run_script", _fake_script(calls))
    # Lines whose first word is a staging verb but whose path part is junk:
    # the touched parser must skip them and only the good line contributes
    # a fact, so the plan adds MADE-UP-01 (the dnssec control).
    junk = (
        "set \n"
        "set bogus=value\n"
        "set dhcp..x=1\n"
        "set dhcp.@invalid[99999].y=z\n"
        "set dhcp.cfg01234c.option+='list'\n"
        "# set dhcp.@dnsmasq[0].dnssec='1'\n"
        "set dhcp.@dnsmasq[0].dnssec='1'\n"
    )
    planned = server.newton_plan_change("quasar", junk, **explained(junk))
    assert "error" not in planned
    record = json.loads(
        (configured_lab / "state" / "plans" / f"{SID}.json").read_text())
    assert record["manifest_checks_auto"] == ["MADE-UP-01"]


def test_caller_probes_plus_touched_overflow_names_the_ids(
    configured_lab, tmp_path, monkeypatch
):
    """Caller-supplied probes + the touched control's probes exceed the
    32-line cap -> the plan is refused with a NewtonError that names the
    offending ids and no script is run."""
    manifest = """
[[control]]
id = 'OW-DNS-04'
tier = 'standard'
check_host = 'router'
batch = [ "set dhcp.@dnsmasq[0].dnssec='1'" ]
probes = """ + repr([["fail"]] * 3) + """
"""
    monkeypatch.setenv("NEWTON_MANIFEST", str(_manifest(tmp_path, manifest)))
    calls: list[Any] = []
    monkeypatch.setattr(server.NewtonService, "run_script", _fake_script(calls))
    caller_probes: list[list[str]] = [["fail"]] * 30
    result = server.newton_plan_change(
        "quasar", "set dhcp.@dnsmasq[0].dnssec='1'",
        probes=caller_probes, **explained("set dhcp.@dnsmasq[0].dnssec='1'"),
    )
    # refused before any router call
    assert calls == []
    err = result.get("error") or ""
    assert "OW-DNS-04" in err, err
    # the message also names the totals so the operator sees the cause
    assert "32" in err or "line" in err or "byte" in err, err


def test_caller_probes_bytes_cap_names_the_ids(
    configured_lab, tmp_path, monkeypatch
):
    """Bytes-cap overflow caused by the caller's own probes still names
    the manifest control id being added (the 32-line cap passes; the
    4096-byte cap fires)."""
    big_a = "a" * 127
    big_b = "b" * 127
    manifest = f"""
[[control]]
id = 'BIG-BYTE-CTRL'
tier = 'standard'
check_host = 'router'
batch = [ "set dhcp.@dnsmasq[0].dnssec='1'" ]
probes = [["ping", "{big_a}"], ["ping", "{big_b}"]]
"""
    monkeypatch.setenv("NEWTON_MANIFEST", str(_manifest(tmp_path, manifest)))
    calls: list[Any] = []
    monkeypatch.setattr(server.NewtonService, "run_script", _fake_script(calls))
    caller_probes: list[list[str]] = [["ping", "x" * 127]] * 30
    result = server.newton_plan_change(
        "quasar", "set dhcp.@dnsmasq[0].dnssec='1'",
        probes=caller_probes, **explained("set dhcp.@dnsmasq[0].dnssec='1'"),
    )
    assert calls == []
    err = result.get("error") or ""
    assert "BIG-BYTE-CTRL" in err, err


# ---- hyphens in named sections (defect 1) ----------------


def test_named_section_with_hyphen_yields_a_fact():
    """``firewall.drop-bogon`` is a real UCI named section (the router
    itself uses hyphens).  The named-section regex ``_NAMED_SEC_RE``
    must accept hyphens, the same way ``policy.SECTION_NAME_RE`` does,
    so ``set firewall.drop-bogon.target='DROP'`` becomes a fact that
    satisfies a control batched at the same section."""
    facts = touched._parse_batch_facts(
        "set firewall.drop-bogon.target='DROP'\n"
    )
    assert facts == {
        touched._Requirement(
            "set", "firewall", "drop-bogon", "target", "DROP",
        ),
    }


def test_named_section_with_hyphen_matches_a_control():
    """End-to-end: a control batched at ``firewall.drop-bogon`` matches
    when the staged batch uses the same path; the touched parser used to
    reject the hyphen and the control would never have matched."""
    controls = [
        {"id": "WITH-HYPHEN",
         "batch": ["set firewall.drop-bogon.target='DROP'"],
         "probes": [["fail"]]},
    ]
    assert touched.touched_entries(
        controls, "set firewall.drop-bogon.target='DROP'") == [0]


# ---- LAST-WINS batch facts (defect 2) ---------------------


def test_parse_batch_facts_last_set_wins_for_same_option():
    """When the staged batch sets the same ``(cfg, section, option)``
    twice, the LATER value wins (the earlier fact is dropped).  Without
    this fix, both facts coexist; a control batched at the earlier value
    would seal even though the router is about to commit the later
    value -> probe failure -> false rollback."""
    facts = touched._parse_batch_facts(
        "set dhcp.@dnsmasq[0].dnssec='1'\n"
        "set dhcp.@dnsmasq[0].dnssec='0'\n"
    )
    assert facts == {
        touched._Requirement(
            "set", "dhcp", "@dnsmasq[0]", "dnssec", "0",
        ),
    }


def test_last_set_wins_prevents_false_dnssec_match():
    """``set ...dnssec='1'`` then ``set ...dnssec='0'`` must NOT match a
    control whose requirement is ``dnssec='1'``: only the final staged
    value is the fact set, and ``'1'`` is no longer there."""
    controls = [
        {"id": "OW-DNS-04",
         "batch": ["set dhcp.@dnsmasq[0].dnssec='1'"],
         "probes": [["fail"]]},
    ]
    assert touched.touched_entries(
        controls,
        "set dhcp.@dnsmasq[0].dnssec='1'\n"
        "set dhcp.@dnsmasq[0].dnssec='0'\n",
    ) == []
    # the reverse order DOES match.
    assert touched.touched_entries(
        controls,
        "set dhcp.@dnsmasq[0].dnssec='0'\n"
        "set dhcp.@dnsmasq[0].dnssec='1'\n",
    ) == [0]


def test_delete_after_set_removes_the_set_fact():
    """``delete cfg.sec.opt`` after a ``set cfg.sec.opt='v'`` removes the
    earlier set fact; nothing about ``opt`` is in the fact set anymore.
    The router is committing the deletion, so the value is gone; a
    control whose requirement is the value must not match."""
    controls = [
        {"id": "CTRL",
         "batch": ["set firewall.drop-bogon.target='DROP'"],
         "probes": [["fail"]]},
    ]
    assert touched.touched_entries(
        controls,
        "set firewall.drop-bogon.target='DROP'\n"
        "delete firewall.drop-bogon.target\n",
    ) == []


def test_delete_section_removes_every_fact_of_that_section():
    """``delete cfg.sec`` removes all earlier facts of that section
    (any option, and the section-level fact if any).  A control with two
    option-level requirements on the section must not match when the
    whole section is deleted afterwards."""
    controls = [
        {"id": "TWO-OPTS",
         "batch": [
             "set firewall.drop-bogon.target='DROP'",
             "set firewall.drop-bogon.proto='all'",
         ],
         "probes": [["fail"]]},
    ]
    assert touched.touched_entries(
        controls,
        "set firewall.drop-bogon.target='DROP'\n"
        "set firewall.drop-bogon.proto='all'\n"
        "delete firewall.drop-bogon\n",
    ) == []


def test_del_list_removes_matching_add_list_fact():
    """``add_list opt='a'``, ``add_list opt='b'``, ``del_list opt='a'``
    leaves only ``'b'``.  The router's commit shows the list as just
    ``'b'``; a control requiring ``add_list' opt='a'`` must NOT match."""
    controls = [
        {"id": "LIST-CTRL-A",
         "batch": ["add_list firewall.bogon_wan.src_ip='10.0.0.0/8'"],
         "probes": [["fail"]]},
        {"id": "LIST-CTRL-B",
         "batch": ["add_list firewall.bogon_wan.src_ip='172.16.0.0/12'"],
         "probes": [["fail"]]},
    ]
    assert touched.touched_entries(
        controls,
        "add_list firewall.bogon_wan.src_ip='10.0.0.0/8'\n"
        "add_list firewall.bogon_wan.src_ip='172.16.0.0/12'\n"
        "del_list firewall.bogon_wan.src_ip='10.0.0.0/8'\n",
    ) == [1]


def test_set_minus_marker_removes_matching_add_list_fact():
    """``set cfg.sec.opt-='v'`` is UCI sugar for del_list; it removes the
    matching earlier add_list fact.  The router commits only the items
    still in the list; an add_list requirement for the removed value
    must not match."""
    controls = [
        {"id": "A",
         "batch": ["add_list firewall.bogon_wan.src_ip='10.0.0.0/8'"],
         "probes": [["fail"]]},
        {"id": "B",
         "batch": ["add_list firewall.bogon_wan.src_ip='172.16.0.0/12'"],
         "probes": [["fail"]]},
    ]
    assert touched.touched_entries(
        controls,
        "add_list firewall.bogon_wan.src_ip='10.0.0.0/8'\n"
        "add_list firewall.bogon_wan.src_ip='172.16.0.0/12'\n"
        "set firewall.bogon_wan.src_ip-='10.0.0.0/8'\n",
    ) == [1]


# ---- error messages name control ids (defect 3) -----------


def test_restage_that_still_disagrees_aborts_and_names_ids(
    configured_lab, tmp_path, monkeypatch
):
    """The union restage STILL reveals entries outside its own sealed
    set -> abort and the error message names the MISSING CONTROL IDS,
    not the entry INDEXES (operators reading the log recognise ``OW-XX``
    ids, not positional indexes)."""
    manifest = """
[[control]]
id = 'A'
tier = 'standard'
check_host = 'router'
batch = [ "set dhcp.@dnsmasq[0].a='1'" ]
probes = [["fail"]]

[[control]]
id = 'B'
tier = 'standard'
check_host = 'router'
batch = [ "set dhcp.@dnsmasq[0].b='1'" ]
probes = [["fail"]]

[[control]]
id = 'C'
tier = 'standard'
check_host = 'router'
batch = [ "set dhcp.@host[3].x='1'" ]
probes = [["fail"]]
"""
    monkeypatch.setenv("NEWTON_MANIFEST", str(_manifest(tmp_path, manifest)))
    first_diff = (
        "dhcp.cfg01411c.a='1'\n"
        "dhcp.cfg01411c.b='1'\n"
    )
    second_diff = "dhcp.cfg02222.x='1'\n"
    out1 = plan_output(diff=first_diff,
                       extra_sections=("dhcp cfg01411c dnsmasq dnsmasq",))
    out2 = plan_output(diff=second_diff,
                       extra_sections=("dhcp cfg02222 host somehost",))
    calls: list[Any] = []
    monkeypatch.setattr(
        server.NewtonService, "run_script",
        _fake_script(calls, [out1, out1, out2, out2]),
    )
    result = server.newton_plan_change(
        "quasar", "set dhcp.@dnsmasq[0].a='1'", **explained("set dhcp.@dnsmasq[0].a='1'"),
    )
    assert "error" in result
    argv = [c[0][0] for c in calls]
    # sequence: plan, abort, plan, abort -> abort shows up at indices 1, 3
    assert argv.count("abort") == 2
    # the missing entry's CONTROL ID is in the message (not the index).
    err = result["error"]
    assert "C" in err, err
    # no plan record left behind after the second abort
    assert list((configured_lab / "state" / "plans").glob("*.json")) == []

# ---- a section set keeps the facts of the section's options ----


def test_a_section_set_keeps_the_add_list_facts_of_the_section():
    """A section-level set replaces the section's own fact only.

    ``uci set dhcp.h1=host`` changes the type of the section; the
    options that are on it stay on it.  The add_list fact of an option
    of that section therefore survives the later section set, and only
    a ``delete dhcp.h1`` takes it away.
    """
    facts = touched._parse_batch_facts(
        "add_list dhcp.h1.dhcp_script='/tmp/evil.sh'\n"
        "set dhcp.h1=host\n"
    )

    assert facts == {
        touched._Requirement(
            "add_list", "dhcp", "h1", "dhcp_script", "/tmp/evil.sh",
        ),
        touched._Requirement("set", "dhcp", "h1", None, "host"),
    }


def test_a_delete_of_the_section_takes_the_add_list_facts_away():
    """A whole-section delete is what drops the facts of the section."""
    facts = touched._parse_batch_facts(
        "add_list dhcp.h1.dhcp_script='/tmp/evil.sh'\n"
        "set dhcp.h1=host\n"
        "delete dhcp.h1\n"
    )

    assert facts == set()
