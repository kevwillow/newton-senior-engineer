"""Planted defects for the check-staged verb.

Used by tests/planted/runner.py with test_check_staged.py: each defect must turn a named test red.
The `old` text of every defect is a piece of the program as it stands after the implementation
(test_planted_defects_current.py guards that). The helper half (scripts/owrt-safe-apply.sh) is not
in the program file, so its defects are planted by hand and logged.
"""
T = "device/openwrt/newton-router/tests/test_check_staged.py"

MUTANTS = [
    ("CS-M1", "check-staged: an unknown helper line is passed through as it is",
     "\tprintf 'fw4 not-checked bad-helper-output\\n'\n\treturn 0\n}",
     "\tprintf '%s\\n' \"$first\"\n\treturn 0\n}", [T]),
    ("CS-M2", "check-staged: an empty helper answer reads as a pass",
     "\t\tprintf 'fw4 not-checked no-answer\\n'\n",
     "\t\tprintf 'fw4 pass\\n'\n", [T]),
    ("CS-M3", "check-staged: control characters stay in the line",
     "first=$(printf '%s' \"$first\" | LC_ALL=C tr -d '\\000-\\037\\177' | LC_ALL=C cut -c1-320)",
     "first=$(printf '%s' \"$first\" | LC_ALL=C cut -c1-320)", [T]),
    ("CS-M4", "check-staged: the detail is not cut",
     "printf 'fw4 %s %s\\n' \"$word\" \"$(printf '%s' \"$rest\" | LC_ALL=C cut -c1-300)\"",
     "printf 'fw4 %s %s\\n' \"$word\" \"$rest\"", [T]),
    ("CS-M5", "check-staged: a not-checked reason with upper case or underscores is accepted",
     "\t\t\t\t''|*[!a-z0-9-]*) ;;\n",
     "\t\t\t\t'') ;;\n", [T]),
    ("CS-M6", "check-staged: any role may ask (the row is read, not change)",
     "check-staged) SPEC_MIN=1; SPEC_MAX=1; SPEC_CLASSES='sid'; SPEC_ROLE=change; SPEC_OWNER=owner ;;",
     "check-staged) SPEC_MIN=1; SPEC_MAX=1; SPEC_CLASSES='sid'; SPEC_ROLE=read; SPEC_OWNER=owner ;;", [T]),
]
