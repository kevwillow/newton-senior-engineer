"""Planted defects for the wifiscan verb.

Used by tests/planted/runner.py with test_wifiscan.py and test_lint.py: each
defect must turn a named test red. The `old` text of every defect is a
piece of the program as it stands after the implementation, so the file
goes stale the moment that code changes (test_planted_defects_current.py
guards that).
"""
W = "device/openwrt/newton-router/tests/test_wifiscan.py"
L = "device/openwrt/newton-router/tests/test_lint.py"

MUTANTS = [
    ("W1", "wifiscan: the rate-limit gate is gone",
     "\tlock_take 10\n\tuptime_stamp\n\tws_gate_check \"$radio\" \"$UP_STAMP\"\n",
     "\tlock_take 10\n\tuptime_stamp\n", [W]),
    ("W2", "wifiscan: the size cap is gone",
     "\tnbytes=$(wc -c < \"$OUT\")\n\tif [ \"$nbytes\" -gt 131072 ]; then\n\t\tfail scan-too-large 1\n\tfi\n",
     "\tnbytes=$(wc -c < \"$OUT\")\n", [W]),
    ("W3", "wifiscan: the radio name is interpolated into a shell string",
     "\tjson=$(printf '{\"section\":\"%s\"}' \"$radio\")\n",
     "\tjson=$(printf '{\"section\":\"%s\"}' \"$(sh -c \"echo $radio\")\")\n", [W, L]),
    ("W4", "wifiscan: a phy name is accepted as the radio",
     "\tcase \"$radio\" in\n\t\tradio[0-9]|radio[0-9][0-9]) ;;\n\t\t*) refuse bad-arg 2 2 ;;\n\tesac\n",
     "\tcase \"$radio\" in\n\t\tradio[0-9]|radio[0-9][0-9]|phy[0-9]|phy[0-9][0-9]) ;;\n\t\t*) refuse bad-arg 2 2 ;;\n\tesac\n", [W]),
    ("W5", "wifiscan: the stamp is written after the scan",
     "\tws_stamp_write \"$radio\" \"$UP_STAMP\"\n\texec 8>&-\n\tjson=$(printf '{\"device\":\"%s\"}' \"$phy\")\n\trun_bounded 25 \"$UBUS\" call iwinfo scan \"$json\"\n",
     "\texec 8>&-\n\tjson=$(printf '{\"device\":\"%s\"}' \"$phy\")\n\trun_bounded 25 \"$UBUS\" call iwinfo scan \"$json\"\n\tws_stamp_write \"$radio\" \"$UP_STAMP\"\n", [W]),
    ("W6", "wifiscan: the stamp is keyed by the phy, not by the radio",
     "\tws_stamp_write \"$radio\" \"$UP_STAMP\"\n",
     "\tws_stamp_write \"$phy\" \"$UP_STAMP\"\n", [W]),
    ("W7", "wifiscan: a broken /proc/uptime falls back to 0",
     "\t[ -n \"$UP_STAMP\" ] || fail internal 1 uptime\n",
     "\t[ -n \"$UP_STAMP\" ] || UP_STAMP=0\n", [W]),
    ("W8", "wifiscan: the check and the write are not one critical section",
     "\tlock_take 10\n\tuptime_stamp\n\tws_gate_check \"$radio\" \"$UP_STAMP\"\n",
     "\tws_gate_check \"$radio\" \"$UP_STAMP\"\n", [W]),
    ("W9", "wifiscan: the program lock is held across the phyname call",
     "\tjson=$(printf '{\"section\":\"%s\"}' \"$radio\")\n\tubus_capture \"$UBUS\" call iwinfo phyname \"$json\"\n",
     "\tlock_take 10\n\tjson=$(printf '{\"section\":\"%s\"}' \"$radio\")\n\tubus_capture \"$UBUS\" call iwinfo phyname \"$json\"\n", [W]),
]
