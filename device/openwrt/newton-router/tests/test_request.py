"""Design 9.2 group 3 (request corpus, modes) and 2.5 (mode detection)."""

import subprocess

import pytest

from conftest import INSTALL_PATH

SPECIALS = list(';|&\'"\\,=%*?$`(){}<>!#~^')
BAD_BYTES = [b for b in range(0x01, 0x20)] + [b for b in range(0x7F, 0x100)]


def refused(router, res, code):
    """Every refusal: exit 2, one stderr error line, no stdout, no calls."""
    assert res.rc == 2, (res.rc, res.err)
    assert res.err == f"error {code}\n", res.err
    assert res.out == ""
    assert not router.canary.exists()
    assert router.calls() == []


def forced_bytes(router, request, role="change"):
    return router.forced(request, role=role, timeout=15)


# ---- forced-mode request corpus (design 3.2, 9.2 group 3) ----------------


def test_request_unset(router):
    refused(router, router.forced(None, timeout=15), "empty-request")


def test_request_empty(router):
    refused(router, forced_bytes(router, ""), "empty-request")


def test_request_1024_bytes_passes_length(router):
    # 1024 passes the length check, then fails as an unknown subcommand
    res = forced_bytes(router, "a" * 1024)
    assert res.rc == 2
    assert res.err == "error unknown-subcommand\n"
    assert res.out == ""


def test_request_1025_bytes(router):
    refused(router, forced_bytes(router, "a" * 1025), "request-too-long")


@pytest.mark.parametrize(
    "byte", BAD_BYTES, ids=[f"byte-{b:02x}" for b in BAD_BYTES]
)
def test_request_control_and_high_bytes(router, byte):
    request = b"hostname" + bytes([byte]) + b"x"
    res = router.forced(request, role="read", timeout=15)
    assert res.rc == 2
    assert res.err == "error bad-character\n"
    assert res.out == ""
    assert router.calls() == []


@pytest.mark.parametrize("ch", SPECIALS, ids=[hex(ord(c)) for c in SPECIALS])
def test_request_shell_metacharacters(router, ch):
    refused(router, forced_bytes(router, "hostname x" + ch + "y"), "bad-character")


def test_request_command_substitution_canary(router):
    request = f"hostname $(touch {router.canary})"
    refused(router, forced_bytes(router, request), "bad-character")


def test_request_backtick_canary(router):
    request = f"hostname `touch {router.canary}`"
    refused(router, forced_bytes(router, request), "bad-character")


def test_request_tab(router):
    refused(router, forced_bytes(router, "hostname\tx"), "bad-character")


def test_request_lf(router):
    refused(router, forced_bytes(router, "hostname\nx"), "bad-character")


def test_request_double_space(router):
    refused(router, forced_bytes(router, "hostname  x"), "bad-spacing")


def test_request_leading_space(router):
    refused(router, forced_bytes(router, " hostname"), "bad-spacing")


def test_request_trailing_space(router):
    refused(router, forced_bytes(router, "hostname "), "bad-spacing")


def test_request_16_tokens(router):
    res = forced_bytes(router, " ".join(["a"] * 16))
    assert res.rc == 2
    assert res.err == "error unknown-subcommand\n"


def test_request_17_tokens(router):
    refused(router, forced_bytes(router, " ".join(["a"] * 17)), "too-many-tokens")


def test_request_install_path_once(router):
    router.set_fake("uci", out="newton-test\n")
    res = forced_bytes(router, f"{INSTALL_PATH} hostname")
    assert (res.rc, res.out, res.err) == (0, "newton-test\n", "")
    assert router.calls() == ["uci -q get system.@system[0].hostname"]


def test_request_install_path_twice(router):
    refused(
        router,
        forced_bytes(router, f"{INSTALL_PATH} {INSTALL_PATH} hostname"),
        "unknown-subcommand",
    )


# ---- modes (design 2.5) ---------------------------------------------------


@pytest.mark.parametrize(
    "argv",
    [
        ["--caller=agent-one"],
        ["--role=read"],
        ["--role=read", "--caller=agent-one"],
        ["--caller=Agent-one", "--role=change"],
        ["--caller=agent-one", "--role=admin"],
        ["--caller=agent-one", "--role=change", "extra"],
        ["--caller=agent-one", "--caller=agent-one"],
        ["--caller=ab", "--role=change", "--role=read"],
    ],
    ids=["caller-only", "role-only", "swapped", "bad-label", "bad-role", "third-word", "repeated", "double-role"],
)
def test_bad_key_line(router, argv):
    res = router.direct(*argv, env={"SSH_ORIGINAL_COMMAND": "hostname"}, timeout=15)
    assert (res.rc, res.err, res.out) == (2, "error bad-key-line\n", "")


def test_rpcd_door_not_built(router):
    res = router.direct("--rpcd", timeout=15)
    assert (res.rc, res.err, res.out) == (2, "error door-not-built\n", "")


def test_forced_mode_never_falls_back_to_argv(router):
    # exact forced pair, but no SSH_ORIGINAL_COMMAND: empty-request, not argv
    res = router.forced(None, role="read", timeout=15)
    refused(router, res, "empty-request")


def test_forced_pair_with_extra_word_is_bad_key_line(router):
    res = router.direct(
        "--caller=agent-one", "--role=read", "hostname",
        env={"SSH_ORIGINAL_COMMAND": None}, timeout=15,
    )
    assert (res.rc, res.err, res.out) == (2, "error bad-key-line\n", "")


@pytest.mark.parametrize(
    "root_value", [None, "tmp/nothere", "relative", "/nonexistent-root-xyz"],
    ids=["unset", "relative", "bare", "missing-abs"],
)
def test_bad_root(router, root_value):
    res = router.direct(
        "hostname", env={"NEWTON_ROUTER_ROOT": root_value}, timeout=15
    )
    assert (res.rc, res.err, res.out) == (2, "error bad-root\n", "")


# ---- direct-mode limits (design 3.2) --------------------------------------


def test_direct_no_argument(router):
    refused(router, router.direct(timeout=15), "empty-request")


def test_direct_empty_token(router):
    refused(router, router.direct("hostname", "", timeout=15), "bad-spacing")


def test_direct_token_with_space(router):
    refused(router, router.direct("hostname", "a b", timeout=15), "bad-character")


def test_direct_16_tokens(router):
    res = router.direct(*(["a"] * 16), timeout=15)
    assert (res.rc, res.err) == (2, "error unknown-subcommand\n")


def test_direct_17_tokens(router):
    refused(router, router.direct(*(["a"] * 17), timeout=15), "too-many-tokens")


def test_direct_token_too_long(router):
    refused(router, router.direct("a" * 256, timeout=15), "request-too-long")


def test_direct_joined_too_long(router):
    refused(
        router, router.direct(*(["a" * 250] * 5), timeout=15), "request-too-long"
    )


# ---- globbing must stay off (planted defect M2: set -f removed) -----------


@pytest.mark.parametrize(
    "req", ["fwrestart [1]", "status [a]", "hello [ab]"],
)
def test_glob_characters_stay_literal(router, tmp_path, req):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    for name in ("1", "a", "ab"):
        (scratch / name).write_text("x")
    res = router.forced(req, role="change", cwd=scratch, timeout=15)
    assert (res.rc, res.err, res.out) == (2, "error bad-arg 1\n", "")
    assert router.calls() == []
