"""Scoped grants on disk: open, read, cover, narrow and revoke.

Every value here is synthetic: the approval key and the plan id are
literals in this file, and no device is contacted.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

import newton_mcp.approve as approve
from newton_mcp import change_classes, grants


DEVICE = "pulsar"
OTHER_DEVICE = "quasar"
K_HEX = "ab" * 32
OTHER_K_HEX = "cd" * 32
PLAN_ID = "0123456789abcdef0123456789abcdef"
OTHER_PLAN_ID = "fedcba9876543210fedcba9876543210"
NOW = 1_700_000_000


def _grant_file(device: str = DEVICE) -> Path:
    return approve.state_dir() / "grants" / f"{device}.json"


def _write_raw(device: str, text: str) -> Path:
    directory = approve.state_dir() / "grants"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(directory, 0o700)
    path = directory / f"{device}.json"
    path.write_text(text, encoding="utf-8")
    return path


def _classification(
    classes: frozenset[str],
    grantable: bool = True,
    high: bool = False,
) -> change_classes.Classification:
    return change_classes.Classification(
        classes=frozenset(classes),
        grantable=grantable,
        high=high,
        high_reasons=("internet-exposure",) if high else (),
    )


# --- opening and reading -----------------------------------------------------


def test_open_and_load_round_trip():
    grants.open_grant(
        DEVICE, ["dns", "dhcp-reservations"], 4, K_HEX, PLAN_ID, now=NOW
    )

    record = grants.load_live_grant(DEVICE, now=NOW)

    assert record is not None
    assert record["classes"] == ["dhcp-reservations", "dns"]
    assert record["granted_at"] == float(NOW)
    assert record["until"] == float(NOW) + 4 * 3600
    assert record["granted_by_plan"] == PLAN_ID
    assert record["k"] == K_HEX


def test_the_grant_file_is_private():
    grants.open_grant(DEVICE, ["dns"], 1, K_HEX, PLAN_ID, now=NOW)

    path = _grant_file()
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700


def test_there_is_no_grant_before_one_is_opened():
    assert grants.load_live_grant(DEVICE, now=NOW) is None
    assert grants.grant_summary(DEVICE, now=NOW) is None
    assert grants.covers(DEVICE, _classification({"dns"}), now=NOW) is None


def test_opening_a_grant_replaces_the_one_before_it():
    grants.open_grant(DEVICE, ["dns"], 1, K_HEX, PLAN_ID, now=NOW)
    grants.open_grant(
        DEVICE, ["hostname"], 8, OTHER_K_HEX, OTHER_PLAN_ID, now=NOW
    )

    record = grants.load_live_grant(DEVICE, now=NOW)

    assert record is not None
    assert record["classes"] == ["hostname"]
    assert record["k"] == OTHER_K_HEX
    assert record["until"] == float(NOW) + 8 * 3600


def test_an_expired_grant_is_deleted_and_reads_as_no_grant():
    grants.open_grant(DEVICE, ["dns"], 1, K_HEX, PLAN_ID, now=NOW)

    assert grants.load_live_grant(DEVICE, now=NOW + 3599) is not None
    assert grants.load_live_grant(DEVICE, now=NOW + 3600) is None
    assert not _grant_file().exists()


def test_a_malformed_grant_file_reads_as_no_grant_and_is_removed():
    path = _write_raw(DEVICE, "this is not json")

    assert grants.load_live_grant(DEVICE, now=NOW) is None
    assert not path.exists()


def test_a_grant_file_with_a_bad_shape_reads_as_no_grant():
    path = _write_raw(
        DEVICE,
        json.dumps(
            {
                "classes": ["not-a-class"],
                "granted_at": NOW,
                "until": NOW + 3600,
                "granted_by_plan": PLAN_ID,
                "k": K_HEX,
            }
        ),
    )

    assert grants.load_live_grant(DEVICE, now=NOW) is None
    assert not path.exists()


# --- opening refuses bad input -----------------------------------------------


@pytest.mark.parametrize("hours", [0, 2, 3, 24, -1, None, True, "4"])
def test_open_refuses_hours_outside_the_list(hours):
    with pytest.raises(ValueError):
        grants.open_grant(DEVICE, ["dns"], hours, K_HEX, PLAN_ID, now=NOW)


@pytest.mark.parametrize(
    "classes",
    [[], (), None, "dns", ["nope"], ["dns", "nope"], [1]],
)
def test_open_refuses_classes_outside_the_grantable_list(classes):
    with pytest.raises(ValueError):
        grants.open_grant(DEVICE, classes, 1, K_HEX, PLAN_ID, now=NOW)


@pytest.mark.parametrize(
    "k_hex",
    ["", "abc", "AB" * 32, "ab" * 31, "ab" * 33, "zz" * 32, None],
)
def test_open_refuses_a_bad_approval_key(k_hex):
    with pytest.raises(ValueError):
        grants.open_grant(DEVICE, ["dns"], 1, k_hex, PLAN_ID, now=NOW)


@pytest.mark.parametrize("plan_id", ["", "abc", "AB" * 16, None])
def test_open_refuses_a_bad_plan_id(plan_id):
    with pytest.raises(ValueError):
        grants.open_grant(DEVICE, ["dns"], 1, K_HEX, plan_id, now=NOW)


@pytest.mark.parametrize(
    "device",
    ["../etc/passwd", "..", "/etc/passwd", "Pulsar", "", "a/b", "a" * 33],
)
def test_a_device_name_that_tries_to_escape_is_refused(device):
    with pytest.raises(ValueError):
        grants.open_grant(device, ["dns"], 1, K_HEX, PLAN_ID, now=NOW)
    with pytest.raises(ValueError):
        grants.load_live_grant(device, now=NOW)
    with pytest.raises(ValueError):
        grants.grant_summary(device, now=NOW)
    with pytest.raises(ValueError):
        grants.revoke_grant(device)


# --- the display summary -----------------------------------------------------


def test_the_summary_has_no_key():
    grants.open_grant(DEVICE, ["dns"], 4, K_HEX, PLAN_ID, now=NOW)

    summary = grants.grant_summary(DEVICE, now=NOW)

    assert summary is not None
    assert set(summary) == {"classes", "until", "granted_at"}
    assert "k" not in summary
    assert summary["classes"] == ["dns"]
    assert summary["until"] == "2023-11-15T02:13:20Z"
    assert summary["granted_at"] == float(NOW)


def test_the_summary_is_none_without_a_live_grant():
    grants.open_grant(DEVICE, ["dns"], 1, K_HEX, PLAN_ID, now=NOW)

    assert grants.grant_summary(DEVICE, now=NOW + 3600) is None


# --- covering a change -------------------------------------------------------


def test_covers_a_change_inside_the_grant():
    grants.open_grant(
        DEVICE, ["dhcp-reservations", "dns"], 4, K_HEX, PLAN_ID, now=NOW
    )

    covered = grants.covers(DEVICE, _classification({"dns"}), now=NOW)

    assert covered == K_HEX


def test_covers_refuses_a_change_that_is_not_a_subset():
    grants.open_grant(DEVICE, ["dns"], 4, K_HEX, PLAN_ID, now=NOW)

    assert (
        grants.covers(
            DEVICE, _classification({"dns", "hostname"}), now=NOW
        )
        is None
    )


def test_covers_refuses_an_expired_grant():
    grants.open_grant(DEVICE, ["dns"], 1, K_HEX, PLAN_ID, now=NOW)

    assert grants.covers(DEVICE, _classification({"dns"}), now=NOW + 3600) is None


def test_covers_refuses_a_high_change():
    grants.open_grant(DEVICE, ["dns"], 4, K_HEX, PLAN_ID, now=NOW)

    covered = grants.covers(
        DEVICE, _classification({"dns"}, high=True), now=NOW
    )

    assert covered is None


def test_covers_refuses_a_change_that_is_not_grantable():
    grants.open_grant(DEVICE, ["dns"], 4, K_HEX, PLAN_ID, now=NOW)

    covered = grants.covers(
        DEVICE, _classification({"dns"}, grantable=False), now=NOW
    )

    assert covered is None


def test_covers_refuses_an_empty_classification():
    grants.open_grant(DEVICE, ["dns"], 4, K_HEX, PLAN_ID, now=NOW)

    assert grants.covers(DEVICE, _classification(frozenset()), now=NOW) is None


def test_a_grant_does_not_cover_another_device():
    grants.open_grant(DEVICE, ["dns"], 4, K_HEX, PLAN_ID, now=NOW)

    assert (
        grants.covers(OTHER_DEVICE, _classification({"dns"}), now=NOW) is None
    )


# --- narrowing and revoking --------------------------------------------------
#
# These open the grant against the real clock: narrowing reads the live
# grant, and a grant opened in the past is already over.


def test_narrow_keeps_only_the_kept_classes():
    grants.open_grant(DEVICE, ["dhcp-reservations", "dns"], 4, K_HEX, PLAN_ID)

    assert grants.narrow_grant(DEVICE, ["dns"]) is True

    record = grants.load_live_grant(DEVICE)
    assert record is not None
    assert record["classes"] == ["dns"]


def test_narrow_never_widens_the_grant():
    grants.open_grant(DEVICE, ["dns"], 4, K_HEX, PLAN_ID)

    assert grants.narrow_grant(DEVICE, ["dns", "hostname"]) is True

    record = grants.load_live_grant(DEVICE)
    assert record is not None
    assert record["classes"] == ["dns"]


def test_narrow_never_extends_the_deadline():
    grants.open_grant(DEVICE, ["dns"], 1, K_HEX, PLAN_ID)

    before = grants.load_live_grant(DEVICE)
    assert before is not None
    grants.narrow_grant(DEVICE, ["dns"])

    record = grants.load_live_grant(DEVICE)
    assert record is not None
    assert record["until"] == before["until"]
    assert record["granted_at"] == before["granted_at"]
    assert record["k"] == before["k"]


def test_narrow_to_nothing_revokes_the_grant():
    grants.open_grant(DEVICE, ["dns"], 4, K_HEX, PLAN_ID)

    assert grants.narrow_grant(DEVICE, []) is True
    assert grants.load_live_grant(DEVICE) is None
    assert not _grant_file().exists()


def test_narrow_to_a_class_the_grant_does_not_hold_revokes_it():
    grants.open_grant(DEVICE, ["dns"], 4, K_HEX, PLAN_ID)

    assert grants.narrow_grant(DEVICE, ["hostname"]) is True
    assert grants.load_live_grant(DEVICE) is None


def test_narrow_without_a_grant_reports_nothing_to_do():
    assert grants.narrow_grant(DEVICE, ["dns"]) is False


def test_revoke_removes_the_grant():
    grants.open_grant(DEVICE, ["dns"], 4, K_HEX, PLAN_ID)

    assert grants.revoke_grant(DEVICE) is True
    assert grants.load_live_grant(DEVICE) is None
    assert not _grant_file().exists()


def test_revoke_without_a_grant_reports_nothing_to_do():
    assert grants.revoke_grant(DEVICE) is False


def test_the_grant_hours_are_the_three_offered_lengths():
    assert grants.GRANT_HOURS == (1, 4, 8)
