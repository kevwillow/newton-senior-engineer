"""Planted defects for the host side of the Wi-Fi scan.

Used by tests/planted/runner.py with the wifi tests: each defect must turn
a named test red.  The `old` text of every defect is a piece of the code as
it stands after the implementation, so the file goes stale the moment
that code changes (test_planted_defects_current.py guards that).

Each defect is a tuple:

    (id, description, path, old, new, [pytest args])

`path` is the file the defect lives in, relative to the repo root.
"""

W = "mcp/newton_mcp/wifiscan.py"
S = "mcp/newton_mcp/scans.py"

LOOKALIKE = "mcp/tests/test_wifi_lookalike.py"
SCAN = "mcp/tests/test_wifi_scan.py"

MUTANTS = [
    (
        "P1",
        "the BSSID is kept in the look-alike finding",
        W,
        '                    "channel": result["channel"],\n'
        '                    "signal": result["signal"],\n',
        '                    "bssid": result["bssid"],\n'
        '                    "channel": result["channel"],\n'
        '                    "signal": result["signal"],\n',
        [f"{LOOKALIKE}::test_wifi_summary_wraps_every_ssid_and_never_carries_a_bssid"],
    ),
    (
        "P2",
        "the look-alike SSID is returned without the untrusted envelope",
        W,
        "    return envelope_module.envelope(\n"
        "        source, envelope_module.escape_delimiters(text)\n"
        "    )\n",
        '    return {"text": text}\n',
        [f"{LOOKALIKE}::test_wifi_summary_wraps_every_ssid_and_never_carries_a_bssid"],
    ),
    (
        "P3",
        "the strongest signal is the weakest one",
        W,
        '                        "strongest_dbm": max(channels[channel]),\n',
        '                        "strongest_dbm": min(channels[channel]),\n',
        [f"{LOOKALIKE}::test_wifi_summary_counts_per_channel_and_the_strongest_signal"],
    ),
    (
        "P4",
        "the typo rule needs more than six characters",
        W,
        "    if len(own_compact) >= TYPO_MIN_LENGTH:\n",
        "    if len(own_compact) > TYPO_MIN_LENGTH:\n",
        [f"{LOOKALIKE}::test_wifi_lookalike_table"],
    ),
    (
        "P5",
        "the confusables run before the case fold",
        W,
        "    normalised = unicodedata.normalize(\"NFKC\", text)\n"
        "    folded = normalised.casefold()\n"
        "    visible = \"\".join(\n"
        "        character\n"
        "        for character in folded\n"
        "        if unicodedata.category(character) not in (\"Cc\", \"Cf\")\n"
        "    )\n"
        "    for pattern, replacement in CONFUSABLES:\n"
        "        visible = visible.replace(pattern, replacement)\n"
        "    return visible\n",
        "    normalised = unicodedata.normalize(\"NFKC\", text)\n"
        "    visible = \"\".join(\n"
        "        character\n"
        "        for character in normalised\n"
        "        if unicodedata.category(character) not in (\"Cc\", \"Cf\")\n"
        "    )\n"
        "    for pattern, replacement in CONFUSABLES:\n"
        "        visible = visible.replace(pattern, replacement)\n"
        "    return visible.casefold()\n",
        [f"{LOOKALIKE}::test_wifi_fold_applies_the_confusables_in_a_fixed_order"],
    ),
    (
        "P6",
        "the wifi branch runs after the IP parse",
        S,
        "    if value.get(\"kind\") == WIFI_KIND:\n"
        "        _validate_wifi_request_fields(value)\n"
        "        return\n",
        "    if value.get(\"kind\") == WIFI_KIND:\n"
        "        try:\n"
        "            ipaddress.ip_address(str(value[\"target\"]))\n"
        "        except ValueError:\n"
        "            raise ScanError(\n"
        "                \"scan request was modified or is invalid; plan it again\"\n"
        "            ) from None\n"
        "        _validate_wifi_request_fields(value)\n"
        "        return\n",
        [f"{SCAN}::test_wifi_request_validation_runs_before_the_ip_parse"],
    ),
    (
        "P7",
        "the nmap retention statement changed",
        S,
        'KEPT = "addresses and open TCP ports only"\n',
        'KEPT = "addresses and open TCP ports and hostnames"\n',
        [f"{SCAN}::test_nmap_request_written_by_the_old_code_still_loads"],
    ),
]
