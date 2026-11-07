"""Planted defects for stage and seal (design 3.5a, 3.5b, 3.6, 5.4). Used by tests/planted/runner.py with test_stage.py and test_seal.py."""
B = "device/openwrt/newton-router/tests"
S = [f"{B}/test_stage.py", f"{B}/test_seal.py"]
MUTANTS = [
    ("M13a", "stage size limit off by one", '[ "$n" -le 30720 ] || fail stdin-too-large 2', '[ "$n" -le 30721 ] || fail stdin-too-large 2', S),
    ("M13b", "stage bad byte check removed", '[ "$n" -eq 0 ] || fail stdin-bad-byte 2', ':', S),
    ("M13c", "stage line count 1001", '[ "$n" -le 1000 ] || fail stdin-too-many-lines 2', '[ "$n" -le 1001 ] || fail stdin-too-many-lines 2', S),
    ("M13d", "stage line length 1025", 'length($0) > 1024', 'length($0) > 1025', S),
    ("S1", "busy shows the full SID to everyone", 'if [ "$CALLER" = root ] || [ "$owner" = "$CALLER" ]; then', 'if true; then', S),
    ("S2", "busy hides the SID from root and the owner", 'if [ "$CALLER" = root ] || [ "$owner" = "$CALLER" ]; then', 'if false; then', S),
    ("S3", "guard pending does not block stage", '\tcase "$G_LINE" in failed*|pending*) fail guard 3 "$G_LINE" ;; esac', '\tcase "$G_LINE" in failed*) fail guard 3 "$G_LINE" ;; esac', S),
    ("S4", "stage accepts a two line helper answer", '[ "$(wc -l < "$f")" -eq 1 ] || fail internal 1 stage-output', ':', S),
    ("S5", "stage-up records zero", 'printf \'%s\\n\' "$UP_NOW" > "$LOCK/$sid.txn/stage-up"', 'printf \'%s\\n\' 0 > "$LOCK/$sid.txn/stage-up"', S),
    ("S6", "seal allowed twice", '[ ! -e "$LOCK/$sid.txn/sealed" ] || fail already-sealed 3', ':', S),
    ("S7", "seal after apply started allowed", '[ ! -e "$LOCK/$sid.txn/applying" ] || fail already-applied 1', ':', S),
    ("S8", "33 probe lines allowed", '[ "$nl" -le 32 ]', '[ "$nl" -le 33 ]', S),
    ("S9", "513 byte probe line allowed", 'length($0) > 512', 'length($0) > 513', S),
    ("M34a", "digest leaves out T", "printf 'newton-plan-v1\\n%s\\n%s\\n%s\\n%s\\n%s\\n%s\\n' \"$dev\" \"$sid\" \"$base\" \"$diff\" \"$psha\" \"$t\"", "printf 'newton-plan-v1\\n%s\\n%s\\n%s\\n%s\\n%s\\n' \"$dev\" \"$sid\" \"$base\" \"$diff\" \"$psha\"", S),
    ("M34b", "digest leaves out the device", "printf 'newton-plan-v1\\n%s\\n%s\\n%s\\n%s\\n%s\\n%s\\n' \"$dev\" \"$sid\" \"$base\" \"$diff\" \"$psha\" \"$t\"", "printf 'newton-plan-v1\\n%s\\n%s\\n%s\\n%s\\n%s\\n%s\\n' x \"$sid\" \"$base\" \"$diff\" \"$psha\" \"$t\"", S),
    ("M34c", "digest leaves out the SID", "printf 'newton-plan-v1\\n%s\\n%s\\n%s\\n%s\\n%s\\n%s\\n' \"$dev\" \"$sid\" \"$base\" \"$diff\" \"$psha\" \"$t\"", "printf 'newton-plan-v1\\n%s\\n%s\\n%s\\n%s\\n%s\\n%s\\n' \"$dev\" x \"$base\" \"$diff\" \"$psha\" \"$t\"", S),
    ("M34d", "digest leaves out the base", "printf 'newton-plan-v1\\n%s\\n%s\\n%s\\n%s\\n%s\\n%s\\n' \"$dev\" \"$sid\" \"$base\" \"$diff\" \"$psha\" \"$t\"", "printf 'newton-plan-v1\\n%s\\n%s\\n%s\\n%s\\n%s\\n%s\\n' \"$dev\" \"$sid\" x \"$diff\" \"$psha\" \"$t\"", S),
    ("M34e", "digest leaves out the probes", "printf 'newton-plan-v1\\n%s\\n%s\\n%s\\n%s\\n%s\\n%s\\n' \"$dev\" \"$sid\" \"$base\" \"$diff\" \"$psha\" \"$t\"", "printf 'newton-plan-v1\\n%s\\n%s\\n%s\\n%s\\n%s\\n%s\\n' \"$dev\" \"$sid\" \"$base\" \"$diff\" x \"$t\"", S),
    ("M32", "a missing profile file means lab", "PROFILE_OUT='prod'", "PROFILE_OUT='lab'", S),
    ("S10", "session gone not refused", '\t[ -d "$LOCK/$sid.txn" ] || fail no-such-txn 3\n\tsession_live "$sid" || fail session-gone 3', '\t[ -d "$LOCK/$sid.txn" ] || fail no-such-txn 3\n\t:', S),
    ("S11", "seal ignores the leash file for required", 'grep -q \'^leash \' "$leashf" 2>/dev/null', 'grep -q NEVERMATCH "$leashf" 2>/dev/null', S),
    ("S12", "sealed written before base", '{ printf \'\' > "$LOCK/$sid.txn/sealed"; } 2>/dev/null || seal_write_fail "$sid"\n\tcrash_point\n\tprintf \'base %s\\n\' "$base"', 'printf \'base %s\\n\' "$base"', S),
]
