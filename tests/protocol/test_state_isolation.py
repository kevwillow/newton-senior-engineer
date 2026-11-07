"""Self-tests for the autouse state-dir isolation (conftest.py).

These tests prove the autouse fixtures in tests/protocol/conftest.py do
three things:

1. An inner test that writes into the guarded `approval-fp` subtree of
   the real home is reported as failed (the guard fires).
2. An inner test that writes into the guarded
   `wan-health-restart-pending` subtree is reported as failed.
3. An inner test that touches an unrelated subtree (e.g. `plans`) is
   NOT reported as failed (the guard only watches the two named
   subtrees).

The inner tests run in a subprocess pytest session whose own conftest
is a copy of tests/protocol/conftest.py; the inner test
monkeypatches `conftest.GUARDED_HOME_FOR_TESTS` to point at a fake
home tree under tmp_path so the guard is effective without touching
the real user state.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def _run_isolated_inner(inner_code, tmp_path):
    """Spawn a fresh pytest process whose only test body is `inner_code`
    and whose conftest is a copy of tests/protocol/conftest.py.  The
    inner conftest's autouse fixtures do not need any test framework
    beyond `pytest`.  Return the subprocess CompletedProcess."""
    inner_dir = tmp_path / "inner_pkg"
    inner_dir.mkdir(parents=True, exist_ok=True)
    conftest_src = (REPO / "tests" / "protocol" / "conftest.py").read_text()
    (inner_dir / "conftest.py").write_text(conftest_src)
    (inner_dir / "test_inner.py").write_text(inner_code)
    return subprocess.run(
        [
            sys.executable, "-m", "pytest",
            "-p", "no:cacheprovider",
            "-q", "--rootdir", str(inner_dir),
            str(inner_dir / "test_inner.py"),
        ],
        capture_output=True, text=True, timeout=120,
        cwd=str(inner_dir),
    )


def test_inner_subprocess_that_writes_into_fake_approval_fp_is_caught(tmp_path):
    fake_home = tmp_path / "fake_home"
    real_root = fake_home / ".local" / "state" / "newton"
    real_root.mkdir(parents=True, exist_ok=True)
    inner_code = textwrap.dedent("""\
        from pathlib import Path

        import conftest as _conftest
        _conftest.GUARDED_HOME_FOR_TESTS = r\"\"\"{fake_home}\"\"\"

        def test_inner_writes_into_fake_approval_fp(tmp_path):
            real_root = Path(r\"\"\"{real_root}\"\"\")
            fp_dir = real_root / \"approval-fp\"
            fp_dir.mkdir(parents=True, exist_ok=True)
            (fp_dir / \"r1\").write_text(\"v1 abc\\n\")
            assert (fp_dir / \"r1\").exists()
        """).format(fake_home=str(fake_home), real_root=str(real_root))
    proc = _run_isolated_inner(inner_code, tmp_path)
    assert proc.returncode != 0, (
        "inner pytest session must FAIL when the test writes into the "
        "guarded approval-fp subtree; got rc=0; stdout=%s stderr=%s"
        % (proc.stdout, proc.stderr)
    )
    assert "wrote into the real user state dir" in proc.stdout, proc.stdout
    assert "approval-fp" in proc.stdout, proc.stdout


def test_inner_subprocess_that_writes_into_fake_wan_health_is_caught(tmp_path):
    fake_home = tmp_path / "fake_home"
    real_root = fake_home / ".local" / "state" / "newton"
    real_root.mkdir(parents=True, exist_ok=True)
    inner_code = textwrap.dedent("""\
        from pathlib import Path

        import conftest as _conftest
        _conftest.GUARDED_HOME_FOR_TESTS = r\"\"\"{fake_home}\"\"\"

        def test_inner_writes_into_fake_wan_health(tmp_path):
            real_root = Path(r\"\"\"{real_root}\"\"\")
            d = real_root / \"wan-health-restart-pending\"
            d.mkdir(parents=True, exist_ok=True)
            # the real leak: marker written then cleared, empty dir left
            (d / \"r1\").write_text(\"v1\\n\")
            (d / \"r1\").unlink()
        """).format(fake_home=str(fake_home), real_root=str(real_root))
    proc = _run_isolated_inner(inner_code, tmp_path)
    assert proc.returncode != 0, (
        "inner pytest session must FAIL when the test writes into the "
        "wan-health subtree; got rc=0; stdout=%s stderr=%s"
        % (proc.stdout, proc.stderr)
    )
    assert "wan-health-restart-pending" in proc.stdout, proc.stdout


def test_inner_subprocess_clean_run_passes(tmp_path):
    fake_home = tmp_path / "fake_home"
    real_root = fake_home / ".local" / "state" / "newton"
    real_root.mkdir(parents=True, exist_ok=True)
    inner_code = textwrap.dedent("""\
        from pathlib import Path

        import conftest as _conftest
        _conftest.GUARDED_HOME_FOR_TESTS = r\"\"\"{fake_home}\"\"\"

        def test_inner_clean_run_passes(tmp_path):
            # Touch a file inside the inner test's own tmp_path only.
            (tmp_path / \"scribble.txt\").write_text(\"hello\\n\")
            assert (tmp_path / \"scribble.txt\").exists()
        """).format(fake_home=str(fake_home), real_root=str(real_root))
    proc = _run_isolated_inner(inner_code, tmp_path)
    assert proc.returncode == 0, (
        "inner pytest session must PASS when no guarded subtree is "
        "touched; got rc=%d; stdout=%s stderr=%s"
        % (proc.returncode, proc.stdout, proc.stderr)
    )


def test_guard_only_watches_named_subtrees(tmp_path):
    fake_home = tmp_path / "fake_home"
    real_root = fake_home / ".local" / "state" / "newton"
    real_root.mkdir(parents=True, exist_ok=True)
    inner_code = textwrap.dedent("""\
        from pathlib import Path

        import conftest as _conftest
        _conftest.GUARDED_HOME_FOR_TESTS = r\"\"\"{fake_home}\"\"\"

        def test_inner_writes_unrelated_subtree(tmp_path):
            real_root = Path(r\"\"\"{real_root}\"\"\")
            # `plans` is a real newton state dir the MCP server uses;
            # the guard must NOT trip on it.
            plans = real_root / \"plans\"
            plans.mkdir(parents=True, exist_ok=True)
            (plans / \"abc.json\").write_text(\"x\\n\")
            assert (plans / \"abc.json\").exists()
        """).format(fake_home=str(fake_home), real_root=str(real_root))
    proc = _run_isolated_inner(inner_code, tmp_path)
    assert proc.returncode == 0, (
        "inner pytest session must PASS when an unrelated subtree is "
        "touched; got rc=%d; stdout=%s stderr=%s"
        % (proc.returncode, proc.stdout, proc.stderr)
    )
