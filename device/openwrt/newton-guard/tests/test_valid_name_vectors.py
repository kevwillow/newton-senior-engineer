"""The shared valid_name vectors (valid_name_vectors.json), proven through
the guard's own behaviour: every valid name is protected (present in the
arm manifest), every invalid name is skipped (named in `status`'s skipped
line, except dot entries the shell glob never enumerates)."""

import json
import os

from conftest import HERE, arm, run_guard
from test_guard import manifest_ok


VECTORS = HERE / "tests" / "valid_name_vectors.json"


def escape(name):
    out = []
    for char in name:
        if char.isascii() and (char.isalnum() or char in "._-"):
            out.append(char)
        else:
            out.append("\\x%02x" % ord(char))
    return "".join(out)


def write_config(cfg, name, data=b"vector\n"):
    path = os.path.join(os.fsencode(str(cfg)), name.encode())
    with open(path, "wb") as handle:
        handle.write(data)


def test_vector_file_names_pass_guard_valid_name():
    vectors = json.loads(VECTORS.read_text())
    assert set(vectors) == {"valid", "invalid"}
    assert vectors["valid"] and vectors["invalid"]
    for name in vectors["valid"] + vectors["invalid"]:
        assert all(0x20 <= ord(char) <= 0x7E for char in name), name


def test_vectors_through_guard_arm_and_status(router):
    vectors = json.loads(VECTORS.read_text())
    cfg = router / "etc/config"
    for name in vectors["valid"] + vectors["invalid"]:
        write_config(cfg, name)
    result = arm(router)
    assert result.stdout == "armed txn-0001 161 60\n"
    manifest = manifest_ok(router, "txn-0001")
    for name in vectors["valid"]:
        assert name in manifest
    for name in vectors["invalid"]:
        assert name not in manifest
        lkg = router / "etc/newton/lkg/txn-0001"
        assert not os.path.exists(os.path.join(os.fsencode(str(lkg)), name.encode()))
    # Dot entries are invisible to the guard's "$CFG"/* glob, so .hidden is
    # neither protected nor listed as skipped; every other invalid name is.
    listed = [n for n in vectors["invalid"] if not n.startswith(".")]
    expected = "skipped " + " ".join(escape(n) for n in sorted(listed))
    status = run_guard(router, "status")
    lines = status.stdout.splitlines()
    assert lines[0] == "pending txn-0001 61"
    assert lines[1:] == [expected]
    assert all(char == "\n" or 0x20 <= ord(char) <= 0x7E for char in status.stdout)
