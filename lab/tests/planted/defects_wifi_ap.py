"""Planted defects for the AP subcommand of lab/wifi/newton-wifi.py.

Used by lab/tests/planted/runner.py: every defect must turn a named test in
lab/tests/test_wifi_helper.py red.  The `old` text of every defect is a piece
of the helper as it stands after the implementation, so the file goes stale
the moment that code changes (lab/tests/test_planted_defects_current.py
guards that).
"""
H = "lab/wifi/newton-wifi.py"
T = "lab/tests/test_wifi_helper.py"

MUTANTS = [
    ("A1", "ap: a name that is not the lab's own is accepted", H,
     '    if not name.startswith(AP_SSID_PREFIX):\n'
     '        raise ApRefused("the ssid must start with newton-test")\n',
     '    if False:\n'
     '        raise ApRefused("the ssid must start with newton-test")\n',
     [T + "::test_the_ap_refuses_a_name_that_is_not_the_labs_own"]),
    ("A2", "ap: a DFS channel is accepted", H,
     '    if freq not in AP_FREQS:\n'
     '        raise ApRefused("%d MHz is not one of the non-DFS 5 GHz channels"\n'
     '                        % freq)\n',
     '    if False:\n'
     '        raise ApRefused("%d MHz is not one of the non-DFS 5 GHz channels"\n'
     '                        % freq)\n',
     [T + "::test_the_ap_refuses_a_dfs_frequency"]),
    ("A3", "ap: the stop is not idempotent", H,
     '    try:\n'
     '        pid = int(_read(AP_PIDFILE))\n'
     '    except (OSError, ValueError):\n'
     '        return 0\n',
     '    pid = int(_read(AP_PIDFILE))\n',
     [T + "::test_ap_stop_is_idempotent"]),
]
