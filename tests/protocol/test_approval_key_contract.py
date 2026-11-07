"""Contract test (round ap1): the host-side approval key K in
newton_mcp.approve.derive_k equals the setup tool's derive_k in
scripts/newton-router-setup for the same passphrase bytes and device, and
the passphrase-file reading strips exactly one trailing LF like setup does
(the reading is inline in approval_key_run, not a function, so the test
reproduces setup's exact cat/printf/%x/%$'\\n' snippet after sourcing the
real script).  Every passphrase here is a made-up value created by the
test itself."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "scripts" / "newton-router-setup"

sys.path.insert(0, str(REPO / "mcp"))
import newton_mcp.approve as approve  # noqa: E402


def _bash_env(tmp_path=None):
    env = {k: v for k, v in os.environ.items() if not k.startswith("NEWTON_")}
    env["TOOL"] = str(TOOL)
    # State-dir isolation: even though derive_k itself does not write, the
    # tool script's init() runs home_dir() via getent passwd, and any
    # future caller that reaches approval_fingerprint_write would write
    # into the real home without these env vars.  When tmp_path is given,
    # use a per-call tmp dir (mode 0700); otherwise fall back to a shared
    # /tmp scratch dir that is writable in CI containers.
    state_root = tmp_path if tmp_path is not None else Path("/tmp/newh-state")
    state_root.mkdir(parents=True, exist_ok=True)
    os.chmod(state_root, 0o700)
    env["NEWTON_STATE_DIR"] = str(state_root / "state")
    env["HOME"] = str(state_root / "home")
    return env


def setup_derive_k(passphrase: bytes, device: str, tmp_path=None) -> str:
    """The REAL derive_k from scripts/newton-router-setup, sourced from bash
    with the passphrase bytes on stdin (its documented contract)."""
    result = subprocess.run(
        ["bash", "-c", '. "${TOOL:?}"; derive_k "$1"', "derive_k", device],
        input=passphrase,
        capture_output=True,
        env=_bash_env(tmp_path),
        timeout=120,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.decode("ascii").strip()


def setup_read_and_derive(path: Path, device: str, tmp_path=None) -> str:
    """Reproduce setup's passphrase-file reading (approval_key_run, not a
    function): cat + printf x, strip the x, strip ONE trailing LF, then the
    real sourced derive_k on the resulting bytes."""
    result = subprocess.run(
        ["bash", "-c",
         '. "${TOOL:?}"; f="$1"; dev="$2"; '
         "pp=$(cat -- \"$f\" && printf 'x'); "
         "pp=${pp%x}; "
         "pp=${pp%$'\\n'}; "
         'printf \'%s\' "$pp" | derive_k "$dev"',
         "read_and_derive", str(path), device],
        capture_output=True,
        env=_bash_env(),
        timeout=120,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.decode("ascii").strip()


# (a) at least six pairs: ASCII, UTF-8 multibyte, spaces, a 200-byte
# passphrase, two device names, and a passphrase ending in a newline byte.
PAIRS = [
    (b"correct horse battery staple", "quasar"),
    ("haendler-passphrase-\xe9-\u2603".encode("utf-8"), "quasar"),
    (b"with  two   spaces inside", "quasar"),
    (b"q" * 200, "quasar"),
    (b"shared-made-up-pass", "pulsar"),
    (b"ends-with-newline\n", "quasar"),
    (b"carriage-return-pass\r", "quasar"),
]


@pytest.mark.parametrize("pp,device", PAIRS)
def test_derive_k_equals_setup_derive_k(pp, device, tmp_path):
    assert approve.derive_k(pp, device) == setup_derive_k(pp, device, tmp_path)


def test_derive_k_device_salt_separates_keys():
    pp = b"shared-made-up-pass"
    assert approve.derive_k(pp, "quasar") != approve.derive_k(pp, "pulsar")


# (c) the one-trailing-LF rule of read_passphrase_file matches setup's reading.


@pytest.mark.parametrize("content", [b"made-up-file-pass", b"made-up-file-pass\n"])
def test_read_passphrase_file_matches_setup_reading(content, tmp_path):
    f = tmp_path / "pp"
    f.write_bytes(content)
    assert approve.derive_k(approve.read_passphrase_file(f), "quasar") == (
        setup_read_and_derive(f, "quasar", tmp_path)
    )


def test_two_trailing_lfs_give_a_different_k(tmp_path):
    one = tmp_path / "one"
    one.write_bytes(b"made-up-file-pass\n")
    two = tmp_path / "two"
    two.write_bytes(b"made-up-file-pass\n\n")
    k_one = approve.derive_k(approve.read_passphrase_file(one), "quasar")
    k_two = approve.derive_k(approve.read_passphrase_file(two), "quasar")
    assert k_one != k_two
    assert k_one == setup_read_and_derive(one, "quasar", tmp_path)
    assert k_two == setup_read_and_derive(two, "quasar", tmp_path)


def test_crlf_keeps_the_cr(tmp_path):
    f = tmp_path / "crlf"
    f.write_bytes(b"made-up-file-pass\r\n")
    assert approve.read_passphrase_file(f) == b"made-up-file-pass\r"
    assert approve.derive_k(approve.read_passphrase_file(f), "quasar") == (
        setup_read_and_derive(f, "quasar", tmp_path)
    )
