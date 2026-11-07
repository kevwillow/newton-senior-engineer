"""Host side: `owrt-change.sh plan` and the staged-config check (SC-06..SC-10).

The plan asks the router program for `check-staged <SID>` only when the router's hello
`version=` is 1.3.0 or newer (the program that carries the verb). An older program reports
`STAGEDCHECK fw4 not-checked router-program-has-no-check`: never a pass. The repo's program
is 1.3.0 and has the verb (tests in device/openwrt/newton-router/tests/test_check_staged.py);
here a fake ssh wrapper answers `check-staged` with canned lines, or rewrites the hello version
to play an older router, while every other call goes to the real program as in
test_owrt_change_e2e.py.
"""
from __future__ import annotations

import re
import textwrap

import pytest

from test_owrt_change_e2e import _prep_plannable, _sid_from_staged, e2e  # noqa: F401  (e2e is a fixture)


WRAPPER = textwrap.dedent(
    """\
    #!/usr/bin/env python3
    import os
    import subprocess
    import sys

    args = sys.argv[1:]
    dest = next(i for i, a in enumerate(args) if "@" in a)
    cmd = " ".join(args[dest + 1:])
    stdin_bytes = sys.stdin.buffer.read()
    real = os.environ["FAKE_SSH_REAL"]
    log = os.environ.get("FAKE_CHECK_LOG")
    if " check-staged " in cmd:
        if log:
            with open(log, "a") as f:
                f.write(cmd + "\\n")
        sys.stdout.write(os.environ.get("FAKE_CHECK_OUT", ""))
        sys.stderr.write(os.environ.get("FAKE_CHECK_ERR", ""))
        sys.exit(int(os.environ.get("FAKE_CHECK_RC", "0")))
    proc = subprocess.run([real, *args], input=stdin_bytes, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out = proc.stdout
    if " hello " in cmd and os.environ.get("FAKE_HELLO_VERSION"):
        out = out.replace(b"version=1.3.0", ("version=" + os.environ["FAKE_HELLO_VERSION"]).encode())
    sys.stdout.buffer.write(out)
    sys.stderr.buffer.write(proc.stderr)
    sys.exit(proc.returncode)
    """
)


@pytest.fixture
def router13(e2e, tmp_path):  # noqa: F811
    """The e2e fixture with the fake ssh wrapped so the router answers as program 1.3.0."""
    bindir = tmp_path / "bin"
    real = bindir / "ssh.real"
    (bindir / "ssh").rename(real)
    wrapper = bindir / "ssh"
    wrapper.write_text(WRAPPER)
    wrapper.chmod(0o755)
    e2e.env["FAKE_SSH_REAL"] = str(real)
    e2e.env["FAKE_CHECK_LOG"] = str(tmp_path / "check-calls.log")
    e2e.check_log = tmp_path / "check-calls.log"
    return e2e


def _plan(e2e, extra_env):
    _prep_plannable(e2e)
    changes = e2e.root / "changes.uci"
    changes.write_text("set dhcp.cfg01.domain=lan\n")
    return e2e.run_plan(changes=changes, timeout=90, extra_env=extra_env)


def _stagedcheck_lines(stdout):
    return [l for l in stdout.splitlines() if l.startswith("STAGEDCHECK ")]


# SC-06: a router program without the verb is reported as not-checked, never as a pass.
def test_sc06_old_router_program_is_not_checked(router13):
    # the repo's program is 1.3.0 (it has the verb); the fake ssh makes hello say 1.2.0
    res = _plan(router13, {"FAKE_HELLO_VERSION": "1.2.0"})
    assert not router13.check_log.exists() or "check-staged" not in router13.check_log.read_text()
    assert res.returncode == 0, res.stdout
    assert _stagedcheck_lines(res.stdout) == ["STAGEDCHECK fw4 not-checked router-program-has-no-check"]
    assert "fw4=not-checked" in router13.audit.read_text()


@pytest.mark.parametrize(("out", "expected"), [
    ("fw4 pass\n", "STAGEDCHECK fw4 pass"),
    ("fw4 skipped-untouched\n", "STAGEDCHECK fw4 skipped-untouched"),
    ("fw4 not-checked network-live-state\n", "STAGEDCHECK fw4 not-checked network-live-state"),
    ("fw4 not-checked session-gone\n", "STAGEDCHECK fw4 not-checked session-gone"),
])
def test_sc07_router_13_statuses_pass_through(router13, out, expected):
    res = _plan(router13, {"FAKE_HELLO_VERSION": "1.3.0", "FAKE_CHECK_OUT": out})
    assert res.returncode == 0, res.stdout
    assert _stagedcheck_lines(res.stdout) == [expected]
    assert router13.check_log.read_text().count("check-staged") == 1
    sid = _sid_from_staged(next(l for l in res.stdout.splitlines() if l.startswith("STAGED ")))
    assert f"check-staged {sid}" in router13.check_log.read_text()


# SC-08: a failed staged check aborts the plan and discards the staged session.
@pytest.mark.parametrize(("out", "words"), [
    ("fw4 fail Error: Could not resolve protocol name\n", "staged firewall config fails fw4 check"),
    ("fw4 running-fails Could not resolve protocol name\n", "already fails fw4 check before the change"),
])
def test_sc08_failed_check_refuses_the_plan(router13, out, words):
    res = _plan(router13, {"FAKE_HELLO_VERSION": "1.3.0", "FAKE_CHECK_OUT": out, "FAKE_CHECK_RC": "1"})
    assert res.returncode != 0
    assert words in res.stdout
    assert "Could not resolve protocol name" in res.stdout
    assert "STAGEDCHECK" not in res.stdout
    assert not any(l.startswith("PLANDIGEST") for l in res.stdout.splitlines())
    leftovers = list((router13.router.root / "tmp/owrt-safe-apply.lock").glob("*.txn")) if (router13.router.root / "tmp/owrt-safe-apply.lock").exists() else []
    assert leftovers == [] or all(not (p / "sealed").exists() for p in leftovers)


# SC-09: a check that could not run, or answered in a shape we do not know, is not-checked.
@pytest.mark.parametrize(("out", "rc", "expected"), [
    ("", 0, "STAGEDCHECK fw4 not-checked check-error"),
    ("garbage\n", 0, "STAGEDCHECK fw4 not-checked check-error"),
    ("fw4 pass; reboot\n", 0, "STAGEDCHECK fw4 not-checked check-error"),
    ("fw4 maybe\n", 0, "STAGEDCHECK fw4 not-checked check-error"),
    ("fw4 not-checked Bad Reason With Spaces\n", 0, "STAGEDCHECK fw4 not-checked check-error"),
    ("", 1, "STAGEDCHECK fw4 not-checked check-error"),
    ("fw4 pass\n", 1, "STAGEDCHECK fw4 not-checked check-error"),
    ("fw4 skipped-untouched\n", 2, "STAGEDCHECK fw4 not-checked check-error"),
    ("fw4 not-checked session-gone\n", 1, "STAGEDCHECK fw4 not-checked check-error"),
])
def test_sc09_unusable_answer_is_not_a_pass(router13, out, rc, expected):
    res = _plan(router13, {"FAKE_HELLO_VERSION": "1.3.0", "FAKE_CHECK_OUT": out, "FAKE_CHECK_RC": str(rc)})
    assert res.returncode == 0, res.stdout
    assert _stagedcheck_lines(res.stdout) == [expected]


# SC-10: router text in a fail detail is masked and single-lined before it reaches the log.
def test_sc10_fail_detail_is_masked(router13):
    out = "fw4 fail key=PlantedKey8812 and more\n"
    res = _plan(router13, {"FAKE_HELLO_VERSION": "1.3.0", "FAKE_CHECK_OUT": out, "FAKE_CHECK_RC": "1"})
    assert res.returncode != 0
    assert "PlantedKey8812" not in res.stdout
    assert "PlantedKey8812" not in router13.audit.read_text()
    assert re.search(r"fails fw4 check", res.stdout)


def test_sc08b_fail_without_detail_still_refuses(router13):
    res = _plan(router13, {"FAKE_HELLO_VERSION": "1.3.0", "FAKE_CHECK_OUT": "fw4 fail\n", "FAKE_CHECK_RC": "1"})
    assert res.returncode != 0
    assert "staged firewall config fails fw4 check" in res.stdout


# SC-23: the real program and helper answer the verb in the e2e fake root (no canned line).
def test_sc23_real_verb_runs_in_the_e2e_root(e2e):  # noqa: F811
    res = _plan(e2e, {})
    assert res.returncode == 0, res.stdout
    lines = _stagedcheck_lines(res.stdout)
    assert len(lines) == 1 and re.fullmatch(
        r"STAGEDCHECK fw4 (pass|skipped-untouched|not-checked [a-z0-9-]{1,40})", lines[0]
    ), lines
    assert "router-program-has-no-check" not in lines[0]
