"""Smoke tests for tests/protocol/bootstrap_harness.py."""
from __future__ import annotations

import pytest

from tests.protocol.bootstrap_harness import (
    FakeRoot,
    SCRIPT,
    userns_ok,
)


pytestmark = pytest.mark.skipif(
    not userns_ok(), reason="user namespaces unavailable in this environment"
)


def test_root_dirs_uid_and_mode(tmp_path):
    fr = FakeRoot(tmp_path)
    rc, out, err = fr.run(
        ["stat", "-c", "%u %a", "/", "/usr", "/usr/local/sbin", "/root"]
    )
    assert rc == 0, err
    parsed = []
    for ln in out.splitlines():
        ln = ln.strip()
        if not ln:
            continue
        uid_s, mode = ln.split()
        parsed.append((uid_s, mode))
    assert parsed == [("0", "755"), ("0", "755"), ("0", "755"), ("0", "700")]


def test_id_is_root(tmp_path):
    fr = FakeRoot(tmp_path)
    rc, out, err = fr.run(["id", "-u"])
    assert rc == 0, err
    assert out.strip() == "0"


def test_tty_input_round_trip(tmp_path):
    fr = FakeRoot(tmp_path)
    rc, out, err = fr.run(
        ["bash", "-c", "[[ -t 0 ]] && read -r l && echo got:$l"],
        tty_input="hello\n",
    )
    assert rc == 0, err
    assert out.strip() == "got:hello"


def test_no_tty_short_circuits(tmp_path):
    fr = FakeRoot(tmp_path)
    rc, _, err = fr.run(
        ["bash", "-c", "[[ -t 0 ]] && read -r l && echo got:$l"],
    )
    assert rc != 0, err


def test_env_dict_applied_inside(tmp_path):
    fr = FakeRoot(tmp_path)
    rc, out, err = fr.run(["bash", "-c", "echo $FOO"], env={"FOO": "bar"})
    assert rc == 0, err
    assert out.strip() == "bar"


def test_env_none_value_unsets(tmp_path):
    fr = FakeRoot(tmp_path)
    rc, out, err = fr.run(["env"], env={"HOME": None})
    assert rc == 0, err
    keys = {line.split("=", 1)[0] for line in out.splitlines() if "=" in line}
    assert "HOME" not in keys


def test_outer_env_is_clean(tmp_path):
    fr = FakeRoot(tmp_path)
    rc, out, err = fr.run(["env"])
    assert rc == 0, err
    keys = {line.split("=", 1)[0] for line in out.splitlines() if "=" in line}
    allowed = {"PATH", "HOME", "LANG", "PWD", "SHLVL", "_", "OLDPWD"}
    assert {"PATH", "HOME", "LANG"}.issubset(keys)
    assert keys.issubset(allowed), sorted(keys - allowed)


def test_staged_bootstrap_executable(tmp_path):
    fr = FakeRoot(tmp_path)
    in_root = fr.install_bootstrap()
    rc, out, err = fr.run(["stat", "-c", "%a %u", in_root])
    assert rc == 0, err
    assert out.strip() == "755 0"


def test_sbin_mode_overrides(tmp_path):
    fr = FakeRoot(tmp_path)
    fr.install_bootstrap()
    rc, out, err = fr.run(["stat", "-c", "%a", "/usr/local/sbin"], sbin_mode="777")
    assert rc == 0, err
    assert out.strip() == "777"


def test_run_plain_unmapped_parent(tmp_path):
    fr = FakeRoot(tmp_path)
    rc, out, err = fr.run_plain(["stat", "-c", "%u", str(tmp_path)])
    assert rc == 0, err
    assert out.strip() in ("0", "65534"), out


def test_run_nonroot_id_not_zero(tmp_path):
    fr = FakeRoot(tmp_path)
    rc, out, err = fr.run_nonroot(["id", "-u"])
    assert rc == 0, err
    assert out.strip() != "0"


def test_harness_references_script(tmp_path):
    assert SCRIPT.name == "newton-bootstrap"
    assert SCRIPT.exists(), SCRIPT