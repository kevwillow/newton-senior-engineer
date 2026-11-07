"""The MCP side of the shared read vectors: every command in
device/openwrt/newton-router/tests/read_cases.json must get the same verdict
from validate_read that the real router program gives it (checked by the
router test test_read_vectors.py), so the table in server.py (design 3.8/3.3)
cannot drift from the program."""

import json
from pathlib import Path

import pytest

import newton_mcp.server as server

CASES = json.loads(
    (Path(__file__).resolve().parents[2]
     / "device/openwrt/newton-router/tests/read_cases.json").read_text()
)


def _ids(values):
    return [v.replace(" ", "-") for v in values]


@pytest.mark.parametrize("command", CASES["accepted"], ids=_ids(CASES["accepted"]))
def test_vector_accepted_by_validate_read(command):
    tokens = server.validate_read(command)
    assert tokens == __import__("shlex").split(command)


@pytest.mark.parametrize("command", CASES["refused"], ids=_ids(CASES["refused"]))
def test_vector_refused_by_validate_read(command):
    with pytest.raises(server.NewtonError):
        server.validate_read(command)


# The wifiscan verb has its own section in the shared file (the router's
# own test drives the program with them).  The host knows the verb now, so
# the same verdicts are pinned here.
WIFISCAN_CASES = CASES.get("wifiscan", {"accepted": [], "refused": []})


@pytest.mark.parametrize(
    "command",
    WIFISCAN_CASES["accepted"],
    ids=_ids(WIFISCAN_CASES["accepted"]),
)
def test_wifiscan_vector_accepted_by_validate_read(command):
    tokens = server.validate_read(command)
    assert tokens == __import__("shlex").split(command)


@pytest.mark.parametrize(
    "command",
    WIFISCAN_CASES["refused"],
    ids=_ids(WIFISCAN_CASES["refused"]),
)
def test_wifiscan_vector_refused_by_validate_read(command):
    with pytest.raises(server.NewtonError):
        server.validate_read(command)


def test_every_token_stays_in_the_router_charset():
    """The last line of defence: a token shlex can produce but the router's
    request filter would refuse (quotes surviving into a token) is refused."""
    with pytest.raises(server.NewtonError):
        server.validate_read("uci show 'net\"work'")
