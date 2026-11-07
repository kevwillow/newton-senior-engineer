"""Design 2.4: forced-key caller labels use the complete label grammar."""

import pytest


BAD_LABELS = [
    pytest.param("ab!bad", id="bang"),
    pytest.param("ab;x", id="semicolon"),
    pytest.param("a b", id="space"),
    pytest.param("aB", id="uppercase"),
    pytest.param("a_b", id="underscore"),
    pytest.param("a.b", id="dot"),
    pytest.param("ab/c", id="slash"),
    pytest.param("a", id="too-short"),
    pytest.param("1ab", id="digit-first"),
    pytest.param("-ab", id="dash-first"),
    pytest.param("a" * 33, id="too-long"),
    pytest.param("ab\tbad", id="tab"),
    pytest.param("ab\x01bad", id="control-byte"),
    pytest.param("root", id="root"),
]


@pytest.mark.parametrize("label", BAD_LABELS)
def test_invalid_caller_label_is_refused(router, label):
    res = router.direct(
        f"--caller={label}",
        "--role=read",
        env={"SSH_ORIGINAL_COMMAND": "hostname"},
        timeout=15,
    )
    assert (res.rc, res.out, res.err) == (2, "", "error bad-key-line\n")


@pytest.mark.parametrize(
    "label",
    ["ab", "agent-one", "a1", pytest.param("a" * 32, id="max-length")],
)
def test_valid_caller_label_is_accepted(router, label):
    router.set_fake("uci", out="router-one\n", rc=0)
    res = router.direct(
        f"--caller={label}",
        "--role=read",
        env={"SSH_ORIGINAL_COMMAND": "hostname"},
        timeout=15,
    )
    assert (res.rc, res.out, res.err) == (0, "router-one\n", "")
