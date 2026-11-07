import importlib.util
import sys
import tempfile
from pathlib import Path

import pytest

LAB_DIR = Path(__file__).resolve().parent.parent
MODULE_PATH = LAB_DIR / "newton-lab-test.py"

# The driver file is named `newton-lab-test.py`, which Python
# can't import directly because of the hyphen. Load it as `newton_lab_test`
# for the tests.
_spec = importlib.util.spec_from_file_location("newton_lab_test", MODULE_PATH)
_mod = importlib.util.module_from_spec(_spec)
sys.modules["newton_lab_test"] = _mod
_spec.loader.exec_module(_mod)


def lab_toml_path():
    """The lab file the tests read: the maintainer's live lab/lab.toml when it
    exists, else lab/lab.example.toml (same tables and keys, synthetic values;
    test_lab_example.py keeps the two in step).  The example names its files
    under /home/user/; the copy the tests read says ~/ instead, so they resolve
    under the synthetic $HOME the fixtures below set up."""
    live = LAB_DIR / "lab.toml"
    if live.is_file():
        return live
    global _EXAMPLE_COPY
    if _EXAMPLE_COPY is None:
        text = (LAB_DIR / "lab.example.toml").read_text(encoding="utf-8")
        d = Path(tempfile.mkdtemp(prefix="newton-lab-example-"))
        _EXAMPLE_COPY = d / "lab.toml"
        _EXAMPLE_COPY.write_text(text.replace("/home/user/", "~/"), encoding="utf-8")
    return _EXAMPLE_COPY


_EXAMPLE_COPY = None


# The real lab.toml points PVE token/pin at ~/.config/pve/apollo.{token,pin},
# and some test labs use ~/.config/pve/{token,pin}. The runner reads those
# files when calling curl. They don't exist on a test host. Provide fake ones
# under a synthetic $HOME for the test session.
@pytest.fixture(scope="session")
def _fake_pve_home(tmp_path_factory):
    fake_home = tmp_path_factory.mktemp("home")
    pve = fake_home / ".config" / "pve"
    pve.mkdir(parents=True)
    pin_payload = "sha256/BvQeK8Wq0kQpZb4eYrZQzXmHVw5xqh1VR9aWPzHhQ50="
    tok_payload = "PVEAPIToken=kevlab@pve!test=00000000-0000-0000-0000-000000000000"
    for name in ("apollo.token", "apollo.pin", "token", "pin"):
        (pve / name).write_text(tok_payload if name.endswith("token") else pin_payload)
    return fake_home


# The HOME swap is per test, not per session: a session-scoped HOME is in
# place for the WHOLE session, and the MCP suite's non-editable install
# test (mcp/tests/test_installed_layout.py) installs offline from the uv
# cache -- a cache that lives under the real $HOME.  With the swap in place
# for the session, `pytest mcp/tests lab/tests` could not resolve the
# package's dependencies and the six install tests errored.  The fake home
# itself is still made once.
@pytest.fixture(autouse=True)
def _fake_pve_secrets(_fake_pve_home, monkeypatch):
    monkeypatch.setenv("HOME", str(_fake_pve_home))


# Speed up the polling loops in tests that exercise reset / ssh readiness.
@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr("newton_lab_test.time.sleep", lambda *_a, **_k: None)


# `nl.main([...])` without --lab falls back to DEFAULT_LAB; point it at the
# file the tests use so a tree without lab/lab.toml still runs.
@pytest.fixture(autouse=True)
def _default_lab_file(monkeypatch):
    monkeypatch.setattr("newton_lab_test.DEFAULT_LAB", lab_toml_path())
