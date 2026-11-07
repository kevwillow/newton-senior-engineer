"""The shared probe vectors (design 3.6/4.3): every case in probe_cases.json
run through the REAL program's `probe` subcommand in test mode (and `seal`
for the multi-line limits).  A refused vector must give
`error bad-probe 1 <reason>` with exit 2 and the SAME reason the json names;
an accepted vector must NOT be refused as bad-probe (the probe itself may
run, pass or fail - only the grammar verdict counts).  The MCP side of the
same vectors is mcp/tests/test_probe_vectors.py running them through
newton_mcp.probes.validate_probes."""

import json
import re
from pathlib import Path

import pytest

from conftest import SID


CASES = json.loads((Path(__file__).parent / "probe_cases.json").read_text())


def _probe_bytes(fields):
    return ("\t".join(fields) + "\n").encode("utf-8", "surrogateescape")


def _ids(entries):
    return [" ".join(f for f in e["probe"] if " " not in f)[:60] for e in entries]


def _staged(router):
    router.use_stub_helper()
    router.write("control/diff.txt", b"dhcp.cfg01.domain='lan'\n")
    result = router.stage()
    assert (result.rc, result.out, result.err) == (0, SID + "\n", "")
    return router.txn(SID)


@pytest.mark.parametrize(
    "fields", CASES["accepted"],
    ids=[" ".join(f for f in fields if " " not in f)[:60] for fields in CASES["accepted"]],
)
def test_vector_accepted_by_the_programs_grammar(router, fields):
    res = router.probe(stdin=_probe_bytes(fields))
    name = re.escape(fields[0])
    assert res.err == "", (fields, res.err)
    assert re.fullmatch(rf"probe {name} (ok|fail)( [!-~]+)?", res.out.rstrip("\n")), (
        fields, res.out
    )
    assert res.rc in (0, 1), (fields, res.rc, res.out)


@pytest.mark.parametrize("entry", CASES["refused"], ids=_ids(CASES["refused"]))
def test_vector_refused_with_the_same_reason(router, entry):
    res = router.probe(stdin=_probe_bytes(entry["probe"]))
    assert (res.rc, res.out, res.err) == (
        2, "", f"error bad-probe 1 {entry['reason']}\n"
    ), entry


@pytest.mark.parametrize(
    "entry", CASES["refused_multi"], ids=[e["reason"] for e in CASES["refused_multi"]]
)
def test_multi_line_vector_refused_at_seal(router, entry):
    # the `probe` subcommand reads ONE line, so the whole-set limits are
    # checked by `seal` against a staged transaction (design 3.6)
    txn = _staged(router)
    data = b"".join(_probe_bytes(fields) for fields in entry["probes"])
    res = router.seal(SID, 90, data)
    line = len(entry["probes"])
    assert (res.rc, res.out, res.err) == (
        2, "", f"error bad-probe {line} {entry['reason']}\n"
    ), entry
    assert not (txn / "sealed").exists()
