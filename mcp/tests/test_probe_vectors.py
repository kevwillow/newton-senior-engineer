"""The MCP side of the shared probe vectors: every case in
device/openwrt/newton-router/tests/probe_cases.json must get the same
verdict from validate_probes that the real router program gives it (checked
by the router test test_probe_vectors.py), so the table in probes.py
(design 3.6/4.3) cannot drift from the program.  The reason must match too.

Host-only rules (no router counterpart) live in test_probes_host.py."""

import json
import re
from pathlib import Path

import pytest

import newton_mcp.probes as probes
from newton_mcp.server import NewtonError


CASES = json.loads(
    (Path(__file__).resolve().parents[2]
     / "device/openwrt/newton-router/tests/probe_cases.json").read_text()
)

REASON_RE = re.compile(r"^probe (\d+): (\S+)$")


def _ids(entries):
    return [" ".join(f for f in e["probe"] if " " not in f)[:60] for e in entries]


@pytest.mark.parametrize(
    "fields", CASES["accepted"],
    ids=[" ".join(f for f in fields if " " not in f)[:60] for fields in CASES["accepted"]],
)
def test_vector_accepted_and_normalized_by_validate_probes(fields):
    assert probes.validate_probes([fields]) == [list(fields)]


def test_validate_probes_returns_every_line_and_normalizes_copies():
    first = CASES["accepted"][0]
    second = CASES["accepted"][1]
    source = [list(first), list(second)]
    result = probes.validate_probes(source)
    assert result == source
    assert result is not source
    assert result[0] is not source[0]


@pytest.mark.parametrize("entry", CASES["refused"], ids=_ids(CASES["refused"]))
def test_vector_refused_with_the_same_reason_and_probe_number(entry):
    with pytest.raises(NewtonError) as excinfo:
        probes.validate_probes([entry["probe"]])
    match = REASON_RE.match(str(excinfo.value))
    assert match, str(excinfo.value)
    assert match.group(1) == "1"
    assert match.group(2) == entry["reason"], str(excinfo.value)


@pytest.mark.parametrize(
    "entry", CASES["refused_multi"], ids=[e["reason"] for e in CASES["refused_multi"]]
)
def test_multi_line_vector_refused(entry):
    with pytest.raises(NewtonError) as excinfo:
        probes.validate_probes(entry["probes"])
    match = REASON_RE.match(str(excinfo.value))
    assert match, str(excinfo.value)
    assert match.group(1) == str(len(entry["probes"]))
    assert match.group(2) == entry["reason"]


def test_the_probe_number_in_the_message_is_one_based():
    vectors = [CASES["accepted"][0], CASES["refused"][0]["probe"], CASES["accepted"][1]]
    with pytest.raises(NewtonError) as excinfo:
        probes.validate_probes(vectors)
    assert REASON_RE.match(str(excinfo.value)).group(1) == "2"
