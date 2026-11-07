"""The fixed NEWTON RESULT notice."""

from __future__ import annotations

import pytest

from newton_mcp import notice


DEVICE = "quasar"
SESSION_ID = "0123456789abcdef0123456789abcdef"
SUMMARY = "Reserves a fixed address for a device."


@pytest.mark.parametrize(
    ("result", "word"),
    [
        ({"result": "confirmed"}, "CONFIRMED"),
        ({"result": "rolled_back"}, "ROLLED BACK"),
        ({"result": "unknown"}, "UNKNOWN"),
        ({"result": "error"}, "NOT APPLIED"),
        ({"error": "apply failed"}, "NOT APPLIED"),
        ({}, "NOT APPLIED"),
    ],
)
def test_result_line_uses_the_fixed_outcome_words(result, word):
    line = notice.result_line(result, DEVICE, SESSION_ID, SUMMARY)

    assert line.startswith(f"NEWTON RESULT: {word}  {DEVICE}  {SESSION_ID[:8]}  ")


def test_an_error_key_wins_over_a_result_word():
    line = notice.result_line(
        {"result": "confirmed", "error": "apply failed"},
        DEVICE,
        SESSION_ID,
        SUMMARY,
    )

    assert "NEWTON RESULT: NOT APPLIED" in line


def test_a_rollback_tells_the_owner_to_check_the_router():
    line = notice.result_line(
        {"result": "rolled_back"}, DEVICE, SESSION_ID, SUMMARY
    )

    assert line.endswith("  Check the router before doing anything else.")


def test_an_unknown_result_tells_the_owner_to_check_the_router():
    line = notice.result_line({"result": "unknown"}, DEVICE, SESSION_ID, SUMMARY)

    assert line.endswith("  Check the router before doing anything else.")


def test_a_confirmed_result_has_no_router_warning():
    line = notice.result_line({"result": "confirmed"}, DEVICE, SESSION_ID, SUMMARY)

    assert "Check the router" not in line


def test_the_grant_notice_is_in_parentheses():
    line = notice.result_line(
        {"result": "confirmed"},
        DEVICE,
        SESSION_ID,
        SUMMARY,
        "EASY GRANT: DHCP reservations until 16:40",
    )

    assert line == (
        "NEWTON RESULT: CONFIRMED  quasar  01234567  "
        "Reserves a fixed address for a device.  "
        "(EASY GRANT: DHCP reservations until 16:40)"
    )


def test_a_grant_notice_comes_before_the_router_warning():
    line = notice.result_line(
        {"result": "unknown"},
        DEVICE,
        SESSION_ID,
        SUMMARY,
        "EASY GRANT: DNS settings until 16:40",
    )

    assert line.endswith("  Check the router before doing anything else.")
    assert "(EASY GRANT: DNS settings until 16:40)" in line


def test_only_the_first_line_of_the_summary_is_used():
    line = notice.result_line(
        {"result": "confirmed"},
        DEVICE,
        SESSION_ID,
        "First summary line.\nSecond summary line.",
    )

    assert line.endswith("First summary line.")
    assert "Second summary line." not in line
