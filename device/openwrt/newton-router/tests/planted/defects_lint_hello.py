"""Planted defects for hello/logging/simple/lint (the T1b group). Used by tests/planted/runner.py with test_hello.py, test_logging.py, test_simple.py, test_lint.py."""
B = "device/openwrt/newton-router/tests"
T = [f"{B}/test_hello.py", f"{B}/test_logging.py", f"{B}/test_simple.py", f"{B}/test_lint.py"]

MUTANTS = [
    ("M19", "seams honoured at the install path", 'if [ "$0" = /usr/libexec/newton/newton-router ]; then\n\tPROD=1', 'if false; then\n\tPROD=1', T),
    ("M20-unset", "NEWTON_LOCK dropped from the production unset list", 'unset NEWTON_LOCK NEWTON_CONFIG_DIR', 'unset NEWTON_CONFIG_DIR', T),
    ("M40", "fw-loaded echoes nft output", 'if "$NFT" list table inet fw4 >/dev/null 2>&1; then\n\t\techo 1', 'if "$NFT" list table inet fw4 2>&1; then\n\t\techo 1', T),
    ("M42", "refused request text written to syslog", 'line="caller=$CALLER door=$DOOR cmd=- rejected=$REJ len=$REQ_LEN from=$FROM_ADDR"',
     'line="caller=$CALLER door=$DOOR cmd=- rejected=$REJ len=$REQ_LEN from=$FROM_ADDR req=${SSH_ORIGINAL_COMMAND-}"', T),
    ("M44", "backup archive holds more than etc/config", '"$TAR" -czf - -C "$R/" etc/config </dev/null', '"$TAR" -czf - -C "$R/" etc </dev/null', T),
    ("H1", "hello exits 0 with a missing code file", '[ "$HELLO_MISSING" -eq 0 ] || return 1', ':', T),
    ("H2", "hello log keeps 65 lines", 'tail -n 64 "$R/tmp/newton/hello"', 'tail -n 65 "$R/tmp/newton/hello"', T),
    ("H2b", "hello log never trimmed", '[ "$nlines" -le 64 ] && return 0', 'return 0', T),
    ("H3", "direct mode writes the hello log", 'if [ "$DOOR" = ssh ]; then\n\t\thello_record "$nonce"', 'if true; then\n\t\thello_record "$nonce"', T),
    ("H4", "approval key present for 63 hex", 'if [ "${#kline}" -eq 64 ]; then', 'if [ "${#kline}" -ge 63 ]; then', T),
    ("H5", "junk profile means lab", 'prod) PROFILE_OUT=prod ;;\n\t\tesac', 'prod) PROFILE_OUT=prod ;;\n\t\t\t*) PROFILE_OUT=lab ;;\n\t\tesac', T),
    ("H6", "from= accepts junk", "''|*[!0-9a-fA-F.:]*) return 0 ;;", "'') return 0 ;;", T),
    ("H7", "log shows the full SID", "LOG_SID=$(printf '%s' \"$1\" | cut -c 1-8)", "LOG_SID=$(printf '%s' \"$1\" | cut -c 1-32)", T),
    ("H8", "mode field always prod", "MODE_STR='test'\n", "MODE_STR='prod'\n", T),
    ("H9", "agent always 0", "\t\t'') agentv=0 ;;\n\t\t*) agentv=1 ;;", "\t\t'') agentv=0 ;;\n\t\t*) agentv=0 ;;", T),
    ("H10", "tty always 0", "ttyv=$STDIN_TTY", "ttyv=0", T),
    ("H11", "hostname ignores uci failure", '"$UCI" -q get \'system.@system[0].hostname\' </dev/null', '"$UCI" -q get \'system.@system[0].hostname\' </dev/null || true', T),
    ("H12", "logd-pid waits only twice", 'while ! "$PIDOF" logd && [ "$i" -lt 5 ]; do', 'while ! "$PIDOF" logd && [ "$i" -lt 2 ]; do', T),
    ("H13", "hello device read from profile file", '\tIFS= read -r device 2>/dev/null < "$R/etc/newton/device-id" || :', '\tIFS= read -r device 2>/dev/null < "$R/etc/newton/profile" || :', T),
    ("H14", "syslog line missing rc", 'cmd=$CMD_NAME sid=$LOG_SID rc=$RC from=$FROM_ADDR"', 'cmd=$CMD_NAME sid=$LOG_SID from=$FROM_ADDR"', T),
    ("H15", "hello nonce echo wrong", "printf 'hello %s api=1 version=1.3.0", "printf 'hello x%s api=1 version=1.3.0", T),
    ("H16", "forbidden construct: backtick comment", "PROG_PID=$$\n", "PROG_PID=$$\n# `x`\n", T),
    ("H17", "forbidden call timeout in code", "PROG_PID=$$\n", "PROG_PID=$$\ntimeout 1 true\n", T),
]
