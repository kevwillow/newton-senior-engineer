"""Planted defects for the five repairs (mgmt-interface rename, caller label, abort hash equality, uci exits, jsonfilter exits)."""
B = "device/openwrt/newton-router/tests"
MUTANTS = [
    ('X1', 'H2: mgmt-interface ignores the committed name (a rename of the mgmt interface passes)', '(st_name[key] == mgif || cm_name[key] == mgif)', '(st_name[key] == mgif)', ['device/openwrt/newton-router/tests/test_leash.py']),
    ('X2', 'H2: the caller label glob accepts anything after the second byte', '[!a-z]*|*[!a-z0-9-]*) return 1 ;;', '[!a-z]*) return 1 ;;', ['device/openwrt/newton-router/tests/test_label.py']),
    ('X3', 'H2: uci-unset passes on every non-zero exit', '\t[ "$rc" -eq 1 ] && return 0\n\tif [ "$rc" -ne 0 ]; then\n\t\tPB_REASON=error\n\t\treturn 1\n\tfi\n\tPB_REASON=present', '\t[ "$rc" -ne 0 ] && return 0\n\tPB_REASON=present', ['device/openwrt/newton-router/tests/test_probes_exit.py', 'device/openwrt/newton-router/tests/test_probes_match.py']),
    ('X4', 'H2: service-running ignores a failing jsonfilter', '\tif [ "$rc" -ne 0 ] && [ "$rc" -ne 1 ]; then\n\t\tPB_REASON=error\n\t\treturn 1\n\tfi\n\tfound=0\n\tif grep -q \'^true$\' "$OUT"; then', '\tfound=0\n\tif grep -q \'^true$\' "$OUT"; then', ['device/openwrt/newton-router/tests/test_probes_exit.py']),
    ('X5', 'H2: abort compares the post hash by prefix', '[ "$post_c" = "$post_sha" ] && fail already-confirmed 1', 'case "$post_c" in "$post_sha"*) fail already-confirmed 1 ;; esac', ['device/openwrt/newton-router/tests/test_abort_exact.py']),
    ('X6', 'H2: uci-equals takes every non-zero exit as unset', '\tif [ "$rc" -eq 1 ]; then\n\t\tPB_REASON=\'unset\'\n\t\treturn 1\n\tfi\n\t[ "$rc" -eq 0 ] || { PB_REASON=error; return 1; }', '\t[ "$rc" -eq 0 ] || { PB_REASON=\'unset\'; return 1; }', ['device/openwrt/newton-router/tests/test_probes_exit.py', 'device/openwrt/newton-router/tests/test_probes_match.py']),
]
