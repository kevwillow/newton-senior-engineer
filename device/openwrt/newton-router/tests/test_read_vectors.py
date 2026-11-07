"""The shared read vectors (design 3.8/3.3): every command in read_cases.json
run through the REAL program in forced mode, role read.  The verdict must
equal the json: accepted = exit 0 and the fake tool ran (cat is served by
the program itself), refused = exit 2 with `error bad-arg`/`arg-count`/
`bad-character`/`too-many-tokens` and nothing executed.  The MCP side of
the same vectors is mcp/tests/test_read_vectors.py."""

import json
import re
from pathlib import Path

import pytest

from test_read import ERR_RE, make_read_root

CASES = json.loads((Path(__file__).parent / "read_cases.json").read_text())


@pytest.fixture
def rd(tmp_path):
    r = make_read_root(tmp_path)
    # the boundary case `cat /etc/config/<32 c's>` needs its regular file
    r.write("etc/config/" + "c" * 32, b"config\n")
    return r


def _ids(values):
    return [v.replace(" ", "-") for v in values]


@pytest.mark.parametrize("command", CASES["accepted"], ids=_ids(CASES["accepted"]))
def test_vector_accepted_by_the_program(rd, command):
    res = rd.forced("read " + command, role="read", timeout=15)
    assert res.rc == 0, (command, res.err)
    if command.startswith("cat "):
        assert res.out != "", command
        assert rd.calls() == [], command
    else:
        assert rd.calls() != [], command


@pytest.mark.parametrize("command", CASES["refused"], ids=_ids(CASES["refused"]))
def test_vector_refused_by_the_program(rd, command):
    res = rd.forced("read " + command, role="read", timeout=15)
    assert res.rc == 2, (command, res.rc, res.out)
    assert res.out == "", command
    assert ERR_RE.match(res.err.rstrip("\n")), (command, res.err)
    assert rd.calls() == [], command
