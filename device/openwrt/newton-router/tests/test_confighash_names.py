"""The shared valid_name vectors (device/openwrt/newton-guard/tests/
valid_name_vectors.json) applied to the program's confighash rule: every
valid name is hashed into the confighash output and the sealed base; every
invalid name is skipped and never makes seal fail. One extra test parses
valid_name out of the guard source and checks the vector file against the
guard's own case pattern run through sh."""

import hashlib
import json
import re
import subprocess
from pathlib import Path

from conftest import BUSYBOX, GUARD, SID
from test_seal import lock_is_free, sha, staged


VECTORS = (
    Path(__file__).resolve().parents[2] / "newton-guard" / "tests" / "valid_name_vectors.json"
)


def vectors():
    return json.loads(VECTORS.read_text())


def write_all(router, names):
    cfg = router.root / "etc/config"
    for name in names:
        path = cfg / name
        path.write_bytes(f"config {name}\n".encode())
        path.chmod(0o644)


def test_vector_names_in_confighash_output(router):
    """Every valid vector name appears in `confighash` with its md5; every
    invalid name is absent (including names like `-lead` the program's old
    pattern refused, and `foo.bak` it used to accept)."""
    data = vectors()
    write_all(router, data["valid"] + data["invalid"])
    res = router.forced("confighash", role="read", timeout=30)
    assert (res.rc, res.err) == (0, "")
    names = {line.split(" ", 1)[1] for line in res.out.splitlines()}
    assert names == set(data["valid"]) | {"system", "network", "firewall", "dhcp", "wireless"}
    for line in res.out.splitlines():
        digest, name = line.split(" ", 1)
        assert digest == hashlib.md5((router.root / "etc/config" / name).read_bytes()).hexdigest()


def test_invalid_vector_names_skipped_from_sealed_base(router):
    """Seal succeeds with every invalid vector name present, and the base
    hash equals the confighash of the valid names alone (the same hash as
    with all the invalid files absent)."""
    data = vectors()
    cfg = router.root / "etc/config"
    write_all(router, data["invalid"])
    staged(router)
    result = router.seal(SID, 90)
    assert result.rc == 0
    assert result.err == ""
    base = next(line.split()[1] for line in result.out.splitlines()
                if line.startswith("base "))
    text_with = router.confighash_text()
    for name in data["invalid"]:
        (cfg / name).unlink()
    text_without = router.confighash_text()
    assert text_with == text_without
    assert base == sha(text_without.encode())
    assert lock_is_free(router)


def test_guard_source_valid_name_matches_vector_file():
    """The vector file is checked against the guard's own valid_name case
    pattern, extracted from the guard source and run through sh, so a
    future edit to the guard rule without the vectors fails here."""
    source = GUARD.read_text()
    match = re.search(
        r"valid_name\(\)\s*\{\s*\n(\s*case \"\$1\" in\n.*?\n\s*esac\n)\s*return 0\n\}",
        source,
        re.S,
    )
    assert match, "cannot find valid_name() case pattern in the guard source"
    snippet = (
        "valid_name() {\n"
        + match.group(1)
        + "\treturn 0\n"
        "}\n"
        'if valid_name "$1"; then printf ok; else printf bad; fi\n'
    )
    data = vectors()
    for name in data["valid"]:
        proc = subprocess.run(
            [BUSYBOX, "sh", "-c", snippet, "sh", name],
            capture_output=True, text=True, timeout=10,
        )
        assert (proc.stdout, name) == ("ok", name)
    for name in data["invalid"]:
        proc = subprocess.run(
            [BUSYBOX, "sh", "-c", snippet, "sh", name],
            capture_output=True, text=True, timeout=10,
        )
        assert (proc.stdout, name) == ("bad", name)
