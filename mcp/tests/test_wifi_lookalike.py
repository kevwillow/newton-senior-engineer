"""Wi-Fi scan, host side: the pure Wi-Fi summary and the look-alike rules.

Test IDs: P9-WIFI-LOOK-01..06, P9-WIFI-SUM-01..10, P9-WIFI-UCI-01..04.

Every input is a literal: no device, no network, no state directory.  The
module under test is ``newton_mcp.wifiscan``; it never touches a router.

Two properties hold everywhere and are asserted here:

* a BSSID never leaves the module, and
* a neighbour SSID only ever leaves it inside a look-alike finding, where
  it sits inside the untrusted envelope.
"""

from __future__ import annotations

import json

import pytest

import newton_mcp.envelope as envelope
import newton_mcp.wifiscan as wifiscan


OWN_BSSID = "aa:bb:cc:dd:ee:ff"
NEIGHBOUR_BSSID = "02:00:00:00:00:01"
KNOWN_BSSIDS = frozenset({OWN_BSSID})


def _rows(*rows: tuple) -> list[tuple]:
    """Fill the two BSSID columns of the look-alike table."""
    filled = []
    for row in rows:
        seen, own, expected = row[0], row[1], row[2]
        own_bssids = row[3] if len(row) > 3 else KNOWN_BSSIDS
        seen_bssid = row[4] if len(row) > 4 else NEIGHBOUR_BSSID
        filled.append((seen, own, expected, own_bssids, seen_bssid))
    return filled


# P9-WIFI-LOOK-01: the look-alike table.  One row per rule, with the
# boundaries the rules turn on:
#
#   * (a) homoglyph: the folds are equal and the raw names differ.
#   * (b) typo: the own name's fold is at least 6 characters and the
#     Damerau-Levenshtein distance is 1 (2 from 12 characters).
#   * (c) same_ssid_other_ap: the names are byte-identical and the BSSID
#     is not the router's own.
#   * (d) mixed_script: the seen name mixes scripts and its Latin-only
#     skeleton matches the own name.
#
# The whitespace rows are the false positives the rules must not report:
# a difference of plain ASCII spaces alone is the same name, not a clone.
LOOKALIKE_TABLE = _rows(
    # --- (a) homoglyph: same fold, different bytes -----------------------
    ("Virgin", "virgin", "homoglyph"),
    ("VIRGIN", "virgin", "homoglyph"),
    ("\uff36irgin", "virgin", "homoglyph"),
    ("rnoon", "moon", "homoglyph"),
    ("vvifi", "wifi", "homoglyph"),
    ("5chool", "school", "homoglyph"),
    ("b1ah", "blah", "homoglyph"),
    ("b|ah", "blah", "homoglyph"),
    ("n1ce", "nice", "homoglyph"),
    ("home", "h0me", "homoglyph"),
    ("school", "5chool", "homoglyph"),
    ("schoo1", "school", "homoglyph"),
    ("schooI", "school", "homoglyph"),
    ("my-network", "my-netw0rk", "homoglyph"),
    ("virgln", "virgin", "homoglyph"),
    ("vir\u200bgin", "virgin", "homoglyph"),
    # --- (a) homoglyph: the names differ only by invisible characters ---
    # a tab (Cc), a no-break space (Zs) and a zero-width space (Cf) all
    # fold away, so the clone reads as the own name on a phone
    ("vir\tgin", "virgin", "homoglyph"),
    ("vir\u00a0gin", "virgin", "homoglyph"),
    ("\u200bvirgin", "virgin", "homoglyph"),
    # --- (a) must NOT fire: the names differ only in whitespace ----------
    ("virgin", "virgin ", None),
    (" virgin ", "virgin", None),
    ("wifi ", "wifi", None),
    ("virgin ", "virgin", None),
    ("V irgin", "virgin", None),
    # --- (b) typo ---------------------------------------------------------
    ("virgn", "virgin", "typo"),
    ("virgi", "virgin", "typo"),
    ("virgins", "virgin", "typo"),
    ("virgin", "virgins", "typo"),
    ("abcdfe", "abcdef", "typo"),
    ("abcdeX", "abcdef", "typo"),
    ("abcdefghiXk", "abcdefghijk", "typo"),
    ("abcdeXghjXlm", "abcdefghjklm", "typo"),
    # --- (b) must NOT fire: too short, or too far -----------------------
    ("abcdeX", "abcde", None),
    ("abcdeXhijX", "abcdefghijk", None),
    ("abcdeXghjXlN", "abcdefghjklm", None),
    ("abcdeXghXkl", "abcdefghjkl", None),
    ("abcXgY", "abcdef", None),
    ("virgin", "virginss", None),
    # --- (c) same name, another AP ---------------------------------------
    ("virgin", "virgin", "same_ssid_other_ap", KNOWN_BSSIDS, NEIGHBOUR_BSSID),
    ("virgin", "virgin", None, KNOWN_BSSIDS, OWN_BSSID),
    ("virgin", "virgin", None, frozenset(), NEIGHBOUR_BSSID),
    # --- (d) mixed script ------------------------------------------------
    ("h\u043eme", "home", "mixed_script"),
    ("t\u0430st", "test", None),
    ("t\u0435st", "test", "mixed_script"),
    ("\u03c4est", "test", "mixed_script"),
    ("n\u0435twork", "network", "mixed_script"),
    ("n\u0435tworkx", "network", "mixed_script"),
    ("\u0430c", "ab", None),
    ("\u0430b", "ab", "mixed_script"),
    ("\u0431bcde", "network", None),
    # --- a non-Latin own name: the byte and the typo rules still apply --
    # (the Latin-skeleton rule does not: the own name has no Latin
    # letters, so there is nothing for the skeleton to imitate)
    ("\u0442\u0435\u0441\u0442", "\u0442\u0435\u0441\u0442",
     "same_ssid_other_ap", KNOWN_BSSIDS, NEIGHBOUR_BSSID),
    ("\u0434\u043e\u043c\u0430\u0448\u043d\u0438\u044f", "\u0434\u043e\u043c\u0430\u0448\u043d\u044f\u044f",
     "typo"),
    # a clone of an own name with non-Latin letters is out of scope: such
    # an own name is compared byte and fold only
    ("h\u043em\u0435", "h\u043eme", None),
    # --- an accented Latin letter is not a script mix --------------------
    ("caf\u00e9", "cafe", None),
)


@pytest.mark.parametrize(
    ("seen", "own", "expected", "own_bssids", "seen_bssid"),
    LOOKALIKE_TABLE,
)
def test_wifi_lookalike_table(
    seen, own, expected, own_bssids, seen_bssid
):
    """P9-WIFI-LOOK-01: one row per rule and per boundary."""
    rule = wifiscan.classify_lookalike(
        seen_ssid=seen,
        seen_bssid=seen_bssid,
        own_ssid=own,
        own_bssids=own_bssids,
    )
    assert rule == expected


def test_wifi_lookalike_table_has_at_least_forty_rows():
    """P9-WIFI-LOOK-02: the table covers every rule and every boundary."""
    assert len(LOOKALIKE_TABLE) >= 40
    rules = {row[2] for row in LOOKALIKE_TABLE}
    assert {
        "homoglyph",
        "typo",
        "same_ssid_other_ap",
        "mixed_script",
        None,
    } == rules


def test_wifi_fold_applies_the_confusables_in_a_fixed_order():
    """P9-WIFI-LOOK-03: the confusable table is fixed and multi-char first.

    The order is part of the contract: a multi-character rule runs before
    the single-character ones, so ``rn`` becomes ``m`` and not ``r`` plus
    ``n``.  ``RN`` also folds to ``m``, which only holds when the case
    fold happens before the confusables.
    """
    assert wifiscan.CONFUSABLES[0] == ("rn", "m")
    assert wifiscan.CONFUSABLES[1] == ("vv", "w")
    assert wifiscan.fold("|rn") == "lm"
    assert wifiscan.fold("vvi") == "wl"
    assert wifiscan.fold("RN") == "m"
    assert wifiscan.fold("rnoon") == "moon"
    assert wifiscan.fold("vvifi") == "wlfl"


def test_wifi_fold_drops_invisible_characters_and_keeps_whitespace():
    """P9-WIFI-LOOK-04: zero-width and control characters go, spaces stay."""
    assert wifiscan.fold("vir\u200bgin") == wifiscan.fold("virgin")
    assert wifiscan.fold("vir\u0007gin") == wifiscan.fold("virgin")
    # the whitespace stays, so the two names stay apart
    assert wifiscan.fold("V irgin") == "v lrgln"
    assert wifiscan.fold("V irgin") != wifiscan.fold("virgin")
    assert wifiscan.fold("a b") == "a b"
    assert wifiscan.fold_without_spaces("V irgin") == "vlrgln"


def test_wifi_damerau_distance_counts_a_transposition_as_one_edit():
    """P9-WIFI-LOOK-05: the typo rule uses the Damerau distance."""
    assert wifiscan.damerau_distance("abcdfe", "abcdef") == 1
    assert wifiscan.damerau_distance("abcdeX", "abcdef") == 1
    assert wifiscan.damerau_distance("abcXgY", "abcdef") == 3
    assert wifiscan.damerau_distance("", "abc") == 3


def test_wifi_latin_skeleton_maps_cyrillic_and_greek_look_alikes():
    """P9-WIFI-LOOK-06: the skeleton of a mixed-script name is Latin."""
    assert wifiscan.latin_skeleton("t\u0430st") == "tast"
    assert wifiscan.latin_skeleton("\u03c4est") == "test"
    assert wifiscan.latin_skeleton("caf\u00e9") == "caf\u00e9"


def _networks(*rows: tuple) -> list[dict]:
    """Build a result list from (ssid, bssid, channel, signal) tuples."""
    return [
        {"ssid": ssid, "bssid": bssid, "channel": channel, "signal": signal}
        for ssid, bssid, channel, signal in rows
    ]


def test_wifi_summary_counts_per_channel_and_the_strongest_signal():
    """P9-WIFI-SUM-01: per-channel counts and the strongest signal."""
    results = _networks(
        ("alpha", "02:00:00:00:00:01", 1, -70),
        ("beta", "02:00:00:00:00:02", 1, -55),
        ("gamma", "02:00:00:00:00:03", 1, -40),
        ("delta", "02:00:00:00:00:04", 6, -60),
        ("epsilon", "02:00:00:00:00:05", 6, -45),
        ("zeta", "02:00:00:00:00:06", 11, -80),
    )
    summary = wifiscan.summarise(
        radio="radio0",
        results=results,
        own_ssids=["virgin"],
        own_channel=6,
        own_bssids=KNOWN_BSSIDS,
        source="router:wifi-scan",
    )
    assert summary["bands"] == [
        {
            "radio": "radio0",
            "band": "2.4 GHz",
            "networks": 6,
            "channels": [
                {"channel": 1, "networks": 3, "strongest_dbm": -40},
                {"channel": 6, "networks": 2, "strongest_dbm": -45},
                {"channel": 11, "networks": 1, "strongest_dbm": -80},
            ],
        }
    ]
    assert summary["networks"] == 6
    assert summary["channels"] == 3


def test_wifi_summary_keeps_the_two_bands_apart():
    """P9-WIFI-SUM-02: a 5 GHz network is a band of its own."""
    results = _networks(
        ("alpha", "02:00:00:00:00:01", 1, -70),
        ("beta", "02:00:00:00:00:02", 36, -55),
    )
    summary = wifiscan.summarise(
        radio="radio0",
        results=results,
        own_ssids=[],
        own_channel=None,
        own_bssids=set(),
        source="router:wifi-scan",
    )
    assert [band["band"] for band in summary["bands"]] == ["2.4 GHz", "5 GHz"]
    assert summary["bands"][1]["channels"] == [
        {"channel": 36, "networks": 1, "strongest_dbm": -55}
    ]


def test_wifi_channel_crowded_counts_the_24ghz_window():
    """P9-WIFI-SUM-03: 2.4 GHz counts the channels within four of our own."""
    results = _networks(
        ("a", "02:00:00:00:00:01", 2, -70),
        ("b", "02:00:00:00:00:02", 3, -70),
        ("c", "02:00:00:00:00:03", 5, -70),
        ("d", "02:00:00:00:00:04", 7, -70),
        ("e", "02:00:00:00:00:05", 9, -70),
        ("f", "02:00:00:00:00:06", 11, -70),
        ("g", "02:00:00:00:00:07", 1, -70),
    )
    summary = wifiscan.summarise(
        radio="radio0",
        results=results,
        own_ssids=[],
        own_channel=6,
        own_bssids=set(),
        source="router:wifi-scan",
    )
    crowded = [f for f in summary["findings"] if f["finding"] == "channel_crowded"]
    assert len(crowded) == 1
    # channels 2..10 hold five neighbours; 11 and 1 are outside the window
    assert crowded[0]["networks"] == 5
    assert crowded[0]["channel"] == 6
    assert crowded[0]["band"] == "2.4 GHz"
    assert crowded[0]["window"] == "2-10"


def test_wifi_channel_crowded_counts_only_our_own_channel_on_5ghz():
    """P9-WIFI-SUM-04: 5 GHz counts the primary channel only."""
    results = _networks(
        ("a", "02:00:00:00:00:01", 36, -70),
        ("b", "02:00:00:00:00:02", 36, -70),
        ("c", "02:00:00:00:00:03", 36, -70),
        ("d", "02:00:00:00:00:04", 36, -70),
        ("e", "02:00:00:00:00:05", 40, -70),
        ("f", "02:00:00:00:00:06", 44, -70),
    )
    summary = wifiscan.summarise(
        radio="radio1",
        results=results,
        own_ssids=[],
        own_channel=36,
        own_bssids=set(),
        source="router:wifi-scan",
    )
    crowded = [f for f in summary["findings"] if f["finding"] == "channel_crowded"]
    assert len(crowded) == 1
    assert crowded[0]["networks"] == 4
    assert crowded[0]["band"] == "5 GHz"
    assert crowded[0]["window"] == "36-36"


def test_wifi_channel_crowded_needs_four_other_networks():
    """P9-WIFI-SUM-05: three neighbours on the window are not crowded."""
    results = _networks(
        ("a", "02:00:00:00:00:01", 6, -70),
        ("b", "02:00:00:00:00:02", 6, -70),
        ("c", "02:00:00:00:00:03", 6, -70),
    )
    summary = wifiscan.summarise(
        radio="radio0",
        results=results,
        own_ssids=[],
        own_channel=6,
        own_bssids=set(),
        source="router:wifi-scan",
    )
    assert [f for f in summary["findings"] if f["finding"] == "channel_crowded"] == []


def test_wifi_channel_crowded_excludes_our_own_ap():
    """P9-WIFI-SUM-06: our own AP is not a neighbour."""
    results = _networks(
        ("virgin", OWN_BSSID, 6, -40),
        ("a", "02:00:00:00:00:02", 6, -70),
        ("b", "02:00:00:00:00:03", 6, -70),
        ("c", "02:00:00:00:00:04", 6, -70),
    )
    summary = wifiscan.summarise(
        radio="radio0",
        results=results,
        own_ssids=["virgin"],
        own_channel=6,
        own_bssids=KNOWN_BSSIDS,
        source="router:wifi-scan",
    )
    assert [f for f in summary["findings"] if f["finding"] == "channel_crowded"] == []


def test_wifi_lookalike_findings_are_capped_at_ten_and_strongest_first():
    """P9-WIFI-SUM-07: at most ten findings, the strongest first."""
    # "abcdeX" is one edit away from the own name "abcdef": twelve
    # look-alikes, each a typo of the same own SSID.
    results = _networks(
        *[
            (
                f"abcde{chr(ord('g') + index)}",
                f"02:00:00:00:00:{index:02x}",
                6,
                -40 - index,
            )
            for index in range(12)
        ]
    )
    summary = wifiscan.summarise(
        radio="radio0",
        results=results,
        own_ssids=["abcdef"],
        own_channel=6,
        own_bssids=set(),
        source="router:wifi-scan",
    )
    lookalikes = [f for f in summary["findings"] if f["finding"] == "lookalike_ssid"]
    assert len(lookalikes) == 10
    assert [f["signal"] for f in lookalikes] == [
        -40, -41, -42, -43, -44, -45, -46, -47, -48, -49
    ]
    assert lookalikes[0]["seen_ssid"]["text"] == "abcdeg"
    assert lookalikes[0]["rule"] == "typo"


def test_wifi_summary_wraps_every_ssid_and_never_carries_a_bssid():
    """P9-WIFI-SUM-08: the SSIDs are enveloped, the BSSIDs are gone."""
    results = _networks(
        ("Virgin", "02:00:00:00:00:01", 6, -40),
        ("other", "02:00:00:00:00:02", 6, -50),
    )
    summary = wifiscan.summarise(
        radio="radio0",
        results=results,
        own_ssids=["virgin"],
        own_channel=6,
        own_bssids=KNOWN_BSSIDS,
        source="router:wifi-scan",
    )
    lookalikes = [f for f in summary["findings"] if f["finding"] == "lookalike_ssid"]
    assert len(lookalikes) == 1
    finding = lookalikes[0]
    assert finding["rule"] == "homoglyph"
    assert envelope.is_envelope(finding["own_ssid"])
    assert envelope.is_envelope(finding["seen_ssid"])
    assert finding["own_ssid"]["text"] == "virgin"
    assert finding["seen_ssid"]["text"] == "Virgin"
    assert finding["channel"] == 6
    assert finding["signal"] == -40
    serialised = json.dumps(summary)
    assert "02:00:00:00:00:01" not in serialised
    assert "02:00:00:00:00:02" not in serialised
    assert "aa:bb:cc:dd:ee:ff" not in serialised


def test_wifi_summary_says_when_the_same_name_check_cannot_run():
    """P9-WIFI-SUM-09: without the router's own BSSID rule (c) is skipped."""
    results = _networks(("virgin", "02:00:00:00:00:01", 6, -40))
    summary = wifiscan.summarise(
        radio="radio0",
        results=results,
        own_ssids=["virgin"],
        own_channel=6,
        own_bssids=set(),
        source="router:wifi-scan",
    )
    assert summary["same_name_check"] == (
        "same-name-other-AP check unavailable while the radio is off"
    )
    assert summary["findings"] == []


def test_wifi_summary_says_the_same_name_check_ran():
    """P9-WIFI-SUM-10: with the router's own BSSID rule (c) runs."""
    results = _networks(("virgin", "02:00:00:00:00:01", 6, -40))
    summary = wifiscan.summarise(
        radio="radio0",
        results=results,
        own_ssids=["virgin"],
        own_channel=6,
        own_bssids=KNOWN_BSSIDS,
        source="router:wifi-scan",
    )
    assert summary["same_name_check"] == "same-name-other-AP check ran"
    assert [f["rule"] for f in summary["findings"]] == ["same_ssid_other_ap"]


WIRELESS_UCI = "\n".join(
    [
        "wireless.radio0=radio0",
        "wireless.radio0.channel='6'",
        "wireless.radio0.band='2g'",
        "wireless.radio0.macaddr='AA:BB:CC:DD:EE:FF'",
        "wireless.@wifi-iface[0]=wifi-iface",
        "wireless.@wifi-iface[0].device='radio0'",
        "wireless.@wifi-iface[0].mode='ap'",
        "wireless.@wifi-iface[0].ssid='virgin'",
        "wireless.@wifi-iface[0].ifname='wlan0'",
        "wireless.@wifi-iface[1]=wifi-iface",
        "wireless.@wifi-iface[1].device='radio0'",
        "wireless.@wifi-iface[1].mode='ap'",
        "wireless.@wifi-iface[1].ssid='virgin-guest'",
        "wireless.@wifi-iface[1].disabled='1'",
        "wireless.@wifi-iface[2]=wifi-iface",
        "wireless.@wifi-iface[2].device='radio1'",
        "wireless.@wifi-iface[2].mode='ap'",
        "wireless.@wifi-iface[2].ssid='other-radio'",
        "wireless.@wifi-iface[3]=wifi-iface",
        "wireless.@wifi-iface[3].device='radio0'",
        "wireless.@wifi-iface[3].mode='sta'",
        "wireless.@wifi-iface[3].ssid='upstream-network'",
    ]
)


def test_wifi_uci_gives_the_radio_channel_own_ssids_and_bssids():
    """P9-WIFI-UCI-01: the radio's own facts come from `uci show wireless`."""
    assert wifiscan.has_radio(WIRELESS_UCI, "radio0") is True
    assert wifiscan.has_radio(WIRELESS_UCI, "radio9") is False
    assert wifiscan.own_channel(WIRELESS_UCI, "radio0") == 6
    assert wifiscan.own_channel(WIRELESS_UCI, "radio9") is None
    assert wifiscan.own_ssids(WIRELESS_UCI, "radio0") == ["virgin"]
    assert wifiscan.own_bssids_from_uci(WIRELESS_UCI, "radio0") == {
        "aa:bb:cc:dd:ee:ff"
    }
    assert wifiscan.up_ap_ifnames(WIRELESS_UCI, "radio0") == ["wlan0"]


def test_wifi_uci_takes_the_bssid_from_an_up_ap_interface():
    """P9-WIFI-UCI-02: `read iwinfo <iface> info` gives the AP's BSSID."""
    info = (
        "wlan0\t\tIEEE 802.11ax\n"
        "\tMode: IEEE 802.11ax\n"
        "\tChannel: 6\n"
        "\tAccess Point: 12:34:56:78:9a:bc\n"
    )
    assert wifiscan.bssids_from_iwinfo(info) == {"12:34:56:78:9a:bc"}
    assert wifiscan.bssids_from_iwinfo("wlan0: Device not found\n") == set()


def test_wifi_uci_scopes_bssids_to_the_scanned_radio():
    """P9-WIFI-UCI-04: another radio's macaddr is not this radio's BSSID."""
    text = "\n".join(
        [
            "wireless.radio0=radio0",
            "wireless.radio0.macaddr='aa:bb:cc:dd:ee:ff'",
            "wireless.radio1=radio1",
            "wireless.radio1.macaddr='11:22:33:44:55:66'",
            "wireless.@wifi-iface[0]=wifi-iface",
            "wireless.@wifi-iface[0].device='radio0'",
            "wireless.@wifi-iface[0].macaddr='12:34:56:78:9a:bc'",
            "wireless.@wifi-iface[1]=wifi-iface",
            "wireless.@wifi-iface[1].device='radio1'",
            "wireless.@wifi-iface[1].macaddr='21:32:43:54:65:76'",
        ]
    )

    assert wifiscan.own_bssids_from_uci(text, "radio0") == {
        "aa:bb:cc:dd:ee:ff",
        "12:34:56:78:9a:bc",
    }
    assert wifiscan.own_bssids_from_uci(text, "radio1") == {
        "11:22:33:44:55:66",
        "21:32:43:54:65:76",
    }


def test_wifi_uci_ignores_a_macaddr_that_is_not_a_mac():
    """P9-WIFI-UCI-03: a malformed macaddr is not a BSSID."""
    assert wifiscan.normalise_mac("not-a-mac") == ""
    assert wifiscan.normalise_mac("12:34:56:78:9a:bc") == "12:34:56:78:9a:bc"
    assert wifiscan.normalise_mac("12-34-56-78-9a-bc") == "12:34:56:78:9a:bc"
