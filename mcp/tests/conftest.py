"""Shared pytest fixtures for the newton-mcp test suite.

The current text behavior (E2): ``test_secrets_redacted`` (and any other test
that touches the redactor without setting ``NEWTON_STATE_DIR``) would write a
random HMAC key to the real ``~/.local/state/newton/redact.key`` on first
use.  We make the state dir per-test by default so that every test gets an
isolated, throwaway directory and tests that set their own state dir keep
working — their fixtures run later and override ours.
"""

from __future__ import annotations

import os
import subprocess

import pytest

import newton_mcp.redact as _redact
import newton_mcp.server as _server


@pytest.fixture(autouse=True)
def _isolate_state_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))
    _redact.reset_key_cache()
    yield
    _redact.reset_key_cache()


@pytest.fixture(autouse=True)
def _clear_ssh_path_cache():
    """Drop the ssh_path resolve cache between tests.

    ``resolve_ssh`` is a ``functools.cache``-decorated function and the
    module-level cache survives across tests in the same process.  A test
    that asserts what ``resolve_ssh`` returns must start from an empty
    cache, and a test that monkeypatches ``SSH_CANDIDATES`` must not be
    poisoned by whatever the previous test cached.
    """
    from newton_mcp import ssh_path as _ssh_path
    _ssh_path.reset_cache()
    yield
    _ssh_path.reset_cache()


@pytest.fixture(autouse=True)
def _restrict_default_umask():
    """Force a 022 default umask for the test's duration so inventory files
    written with ``Path.write_text`` end up mode 0644 (not 0664) and pass
    the loaders' "must not be group- or world-writable" rule.  Restored
    on teardown so later tests or processes see the original mask."""
    old = os.umask(0o022)
    try:
        yield
    finally:
        os.umask(old)


@pytest.fixture(autouse=True)
def _block_real_ssh(monkeypatch):
    """Fail closed if a test reaches the host's ssh executable."""
    original_run = subprocess.run

    def guarded_run(argv, *args, **kwargs):
        if (
            isinstance(argv, (list, tuple))
            and argv
            and os.path.basename(os.fspath(argv[0])) == "ssh"
        ):
            raise AssertionError("test attempted a real ssh call")
        return original_run(argv, *args, **kwargs)

    monkeypatch.setattr(subprocess, "run", guarded_run)


@pytest.fixture(autouse=True)
def _stub_fw4_precheck(request, monkeypatch):
    """Replace ``NewtonService._refuse_failing_fw4`` with a no-op so the
    rest of the plan tests never need to fake ``read('fw4 check')`` results.
    Tests that exercise the real precheck opt out with the
    ``real_fw4_precheck`` marker.  The method is added in the same change
    that introduced this fixture, so before that lands the attribute is
    absent and we leave it alone (the rest of the suite is unaffected)."""
    if "real_fw4_precheck" in request.keywords:
        return
    if not hasattr(_server.NewtonService, "_refuse_failing_fw4"):
        return
    monkeypatch.setattr(_server.NewtonService, "_refuse_failing_fw4", lambda self, device_name: None)


@pytest.fixture
def configured_newton(tmp_path, monkeypatch):
    inventory = tmp_path / "devices.toml"
    inventory.write_text(
        '[devices.quasar]\nplatform = "openwrt"\nhost = "192.0.2.1"\nuser = "root"\n'
    )
    inventory.chmod(0o644)
    monkeypatch.setenv("NEWTON_INVENTORY", str(inventory))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))
    _redact.reset_key_cache()
    return tmp_path
