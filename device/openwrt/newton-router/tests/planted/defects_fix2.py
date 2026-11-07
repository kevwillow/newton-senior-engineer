"""Planted defects for the fix round after the second review (findings F-A to F-E): seal write checks and the fail-closed apply, the reserved label root, the locked hello update, signal traps and the scratch sweep, the index-shift fail-safe of the leash."""
B = "device/openwrt/newton-router/tests"
SW = B + "/test_seal_writes.py"
MUTANTS = [
    # ---- F-B: seal checks every durable write; apply fails closed on a missing leash copy
    ('FB1', 'F-B: a failed write of the leash copy does not stop seal', '{ cat "$leashf" > "$LOCK/$sid.txn/leash"; } 2>/dev/null || seal_write_fail "$sid"', '{ cat "$leashf" > "$LOCK/$sid.txn/leash"; } 2>/dev/null', [SW]),
    ('FB2', 'F-B: a failed write of the sealed marker does not stop seal', '{ printf \'\' > "$LOCK/$sid.txn/sealed"; } 2>/dev/null || seal_write_fail "$sid"', '{ printf \'\' > "$LOCK/$sid.txn/sealed"; } 2>/dev/null', [SW]),
    ('FB3', 'F-B: seal_write_fail refuses nothing', '\trm -f "$LOCK/$1.txn/sealed"\n\tfail internal 1 write\n}', '\trm -f "$LOCK/$1.txn/sealed"\n\treturn 0\n}', [SW]),
    ('FB4', 'F-B: apply takes a missing leash copy as not required', 'if [ "$profile" = prod ] || [ "$lrc" -ne 1 ]; then\n\t\trequired=1\n\tfi\n\tif [ "$required" -eq 1 ]; then\n\t\tcodes=', 'if [ "$profile" = prod ] || [ "$lrc" -eq 0 ]; then\n\t\trequired=1\n\tfi\n\tif [ "$required" -eq 1 ]; then\n\t\tcodes=', [SW]),
    ('FB5', 'F-B: apply does not name the leash-unreadable code', 'codes=${codes:+$codes,}leash-unreadable', ':', [SW]),
    ('FB6', 'F-B: apply reads the leash copy even when it cannot be read (shell error on stderr)', '\t\tif [ "$lrc" -le 1 ]; then\n\t\t\twhile IFS= read -r line; do', '\t\tif true; then\n\t\t\twhile IFS= read -r line; do', [SW]),
    # ---- F-C: the label root is reserved
    ('FC1', 'F-C: the caller label root is accepted in a key line', 'root|[!a-z]*|*[!a-z0-9-]*) return 1 ;;', '[!a-z]*|*[!a-z0-9-]*) return 1 ;;', [B + "/test_label.py"]),
    # ---- F-E: hello appends and trims under one lock
    ('FE1', 'F-E: hello never takes the directory lock', 'if "$FLOCK" -n 6; then', 'if true; then', [B + "/test_hello_lock.py"]),
    ('FE2', 'F-E: hello trims even when it did not get the lock', 'if [ "$got" -eq 1 ]; then\n\t\t\ttrim_hello\n\t\tfi', 'trim_hello', [B + "/test_hello_lock.py"]),
    ('FE3', 'F-E: hello does not wait for the lock', '[ "$waited" -lt 10 ] || break', '[ "$waited" -lt 0 ] || break', [B + "/test_hello_lock.py"]),
    # ---- F-A: signals end the call through the EXIT trap; scratch files carry the pid; the sweep
    ('FA1', 'F-A: SIGTERM is not trapped (the EXIT trap does not run)', "trap 'sig_exit 143' TERM\n", '', [B + "/test_scratch_signals.py"]),
    ('FA2', 'F-A: a signal exit leaves RC at 0 (the syslog line says rc=0)', 'sig_exit() {\n\tRC=$1\n\texit "$1"\n}', 'sig_exit() {\n\texit "$1"\n}', [B + "/test_scratch_signals.py"]),
    ('FA3', 'F-A: the sweep also removes the files of live calls', '\t\tkill -0 "$pid" 2>/dev/null && continue\n', '', [B + "/test_scratch_signals.py"]),
    ('FA4', 'F-A: the sweep removes any pid-shaped name, not only the scratch prefixes', '\t\t\trd.*|re.*|hl.*|in.*|st.*|dg.*|ls.*|lc.*|lp.*|lo.*|lu.*|ch.*|df.*|le.*|pb.*) ;;\n\t\t\t*) continue ;;', '\t\t\t*) ;;', [B + "/test_scratch_signals.py"]),
    ('FA5', 'F-A: the runner capture file has no pid in its name', 'OUT=$(mktemp "$R/tmp/newton/rd.$PROG_PID.XXXXXX")', 'OUT=$(mktemp "$R/tmp/newton/rd.XXXXXX")', [B + "/test_scratch_signals.py"]),
    ('FA6', 'F-A: the sweep is never called', '\tlocal rc\n\tsweep_scratch\n\tcompute_from', '\tlocal rc\n\tcompute_from', [B + "/test_scratch_signals.py"]),
    # ---- F-D: the index-shift fail-safe of the leash
    ('FD1', 'F-D: one selector line alone is enough to fire', 'fd_tot[fd_ck] >= 2', 'fd_tot[fd_ck] >= 1', [B + "/test_leash_index_shift.py"]),
    ('FD2', 'F-D: a structural line is not needed to fire', 'if (fd_nstr[fd_ck] > 0 && fd_tot[fd_ck] >= 2) fire(', 'if (fd_tot[fd_ck] >= 2) fire(', [B + "/test_leash_index_shift.py"]),
    ('FD3', 'F-D: a structural line addressed by name is not counted', 'if (c_selt[fd_i] != "" || c_str[fd_i]) fd_tot[fd_ck]++', 'if (c_selt[fd_i] != "") fd_tot[fd_ck]++', [B + "/test_leash_index_shift.py"]),
    ('FD4', 'F-D: the add of a section is not a structural line', 'P_OP == "@" || P_OP == "")) ? 1 : 0', 'P_OP == "@")) ? 1 : 0', [B + "/test_leash_index_shift.py"]),
]
