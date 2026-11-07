"""mask_secrets must scan the WHOLE line for NAME=VALUE assignments
(triage #4/#6 confirmed leak). scripts/owrt-change.sh lines 111-163.

Before this fix, mask_secrets only inspected the part of a line before
the FIRST '='.  A line such as
    uci: foo=bar password='S3cr3tValue'
reached the audit log with the secret in clear (the first '=' was
`foo=bar`, the harmless pair).  After the fix, mask_secrets keeps the
existing first-'=' behaviour AND scans every `NAME[ \t]*[+^-]?[ \t]*=`
on the line; the first assignment whose stripped NAME (the part after
its last '.', any trailing + - ^ removed, lower-cased) matches the
catalog becomes the masked output, and the REST OF THE LINE is dropped
(so a value with spaces or quotes cannot leak).
"""

from __future__ import annotations

import re
import subprocess
import time
from pathlib import Path

import pytest

from tests.protocol.test_secret_catalog import (
    BASH_FUNCTIONS,
    CATALOG,
    REPO,
    SECRET_VALUE,
    SCRIPT,
    _extract_functions,
    bash_mask,
    shlex_quote,
)


SECRET = "S3cr3tValue"


# ---- 1. the four lines from the spec ---------------------------------------


@pytest.mark.parametrize(
    "line, kept_prefix",
    [
        (
            "uci: /tmp/uci.uci:1: parse error at line 1 set foo.bar=1 password='S3cr3tValue'",
            "uci: /tmp/uci.uci:1: parse error at line 1 set foo.bar=1 password=",
        ),
        (
            "uci: foo=bar password='S3cr3tValue'",
            "uci: foo=bar password=",
        ),
        (
            "uci error: bad quoting at set foo.bar=1 password='S3cr3tValue'",
            "uci error: bad quoting at set foo.bar=1 password=",
        ),
        (
            "uci: parse set foo.bar=1 passwd = S3cr3tValue",
            "uci: parse set foo.bar=1 passwd =",
        ),
    ],
    ids=["p-error", "two-eq", "q-error", "spaced-eq"],
)
def test_midline_secret_is_masked_and_harmless_prefix_kept(line, kept_prefix, tmp_path):
    (out,) = bash_mask([line], tmp_path)
    assert SECRET not in out, repr(out)
    assert kept_prefix in out, repr(out)
    assert out.endswith("='<masked>'")


# ---- 2. contains-form: x_credentials needs `contains credential` ---------


def test_contains_only_credential_is_masked(tmp_path):
    line = f"pkg.a.x_credentials='{SECRET}'"
    (out,) = bash_mask([line], tmp_path)
    assert SECRET not in out
    assert out == "pkg.a.x_credentials='<masked>'"


def test_catalog_has_contains_credential():
    rules = []
    for raw in CATALOG.read_text().splitlines():
        s = raw.strip()
        if s.startswith("#") or not s:
            continue
        rules.append(tuple(s.split(" ", 1)))
    assert ("contains", "credential") in rules


# ---- 3. two secret assignments on one line: first match wins, rest dropped


def test_two_secret_assignments_first_match_drops_rest(tmp_path):
    line = f"password='{SECRET}' token='OtherValue'"
    (out,) = bash_mask([line], tmp_path)
    assert SECRET not in out
    assert "OtherValue" not in out
    assert out.startswith("password=")
    assert out.endswith("='<masked>'")


# ---- 4. harmless line with several '=' stays unchanged (oneline still trims)


def test_harmless_several_eq_passes_through(tmp_path):
    line = "uci add dhcp dnsmasq && uci set dhcp.@dnsmasq[0].local='/lan/' && uci commit dhcp"
    (out,) = bash_mask([line], tmp_path)
    # exact-equal pass-through: oneline cuts to 120 chars (line is shorter).
    assert out == line


def test_harmless_multi_eq_long_unrelated_line(tmp_path):
    line = "a=1 b=2 c=3 d=4 e=5"
    (out,) = bash_mask([line], tmp_path)
    assert out == line


# ---- 5. catalog names r0kh, r1kh, authkey, apikey in SECOND position ------


@pytest.mark.parametrize(
    "name",
    ["r0kh", "r1kh", "authkey", "apikey"],
)
def test_triage4_name_masked_only_when_in_second_position(tmp_path, name):
    line = f"foo=bar {name}='{SECRET}'"
    (out,) = bash_mask([line], tmp_path)
    assert SECRET not in out
    assert out == f"foo=bar {name}='<masked>'"


# ---- 6. spaces around '=' --------------------------------------------------


def test_spaces_around_eq_masked(tmp_path):
    line = f"password = {SECRET}"
    (out,) = bash_mask([line], tmp_path)
    assert SECRET not in out
    assert out.startswith("password =")
    assert out.endswith("='<masked>'")


def test_space_before_eq_only(tmp_path):
    line = f"password ='{SECRET}'"
    (out,) = bash_mask([line], tmp_path)
    assert SECRET not in out
    assert out.startswith("password =")
    assert out.endswith("='<masked>'")


# ---- 7. quotes -------------------------------------------------------------


def test_single_quotes_around_value(tmp_path):
    line = f"password='{SECRET}'"
    (out,) = bash_mask([line], tmp_path)
    assert SECRET not in out
    assert out == "password='<masked>'"


def test_double_quotes_around_value(tmp_path):
    line = f'password="{SECRET}"'
    (out,) = bash_mask([line], tmp_path)
    assert SECRET not in out
    assert out == "password='<masked>'"


def test_unquoted_value_with_spaces_still_masked(tmp_path):
    line = f"password={SECRET} more tail that must not leak"
    (out,) = bash_mask([line], tmp_path)
    assert SECRET not in out
    assert "more tail" not in out
    assert out == "password='<masked>'"


# ---- 8. linear time --------------------------------------------------------


def _time_one_line(line: str, tmp_path: Path) -> float:
    """Run mask_secrets on one input line and return wall time in seconds."""
    audit = tmp_path / "audit.log"
    harness = tmp_path / "mask-timing.sh"
    harness.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        f"ROUTER=timing\nAUDIT={shlex_quote(str(audit))}\n"
        f"SECRET_CATALOG={shlex_quote(str(CATALOG))}\n"
        + _extract_functions(SCRIPT.read_text(), BASH_FUNCTIONS)
        + "\nload_secret_catalog\nIFS= read -r line || [[ -n $line ]] && mask_secrets \"$line\"\n"
    )
    start = time.perf_counter()
    result = subprocess.run(
        ["/usr/bin/env", "bash", str(harness)],
        input=line + "\n",
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
    )
    elapsed = time.perf_counter() - start
    assert result.returncode == 0, result.stderr
    return elapsed


def test_linear_time_pairs(tmp_path):
    pair = "a=1 "
    line = pair * 5000  # 20_000 chars, 5_000 pairs, 5_000 '='
    elapsed = _time_one_line(line, tmp_path)
    assert elapsed < 2.0, f"mask_secrets took {elapsed:.2f}s on 20k chars of pairs"


def test_linear_time_equals(tmp_path):
    line = "=" * 20000  # 20_000 '=' chars, no NAME: hits 64-eq ceiling
    elapsed = _time_one_line(line, tmp_path)
    assert elapsed < 2.0, f"mask_secrets took {elapsed:.2f}s on 20k '='"


# ---- 9. too-many-assignments marker (fail closed) --------------------------


def test_too_many_assignments_marker(tmp_path):
    # 70 '=' chars with no preceding NAME -> no inner match is ever found,
    # so we reach n_eq=65 and the rest of the line is dropped.
    # Keep the line short (under ~88 chars before the marker) so the marker
    # survives oneline's 120-char cut.
    line = "=" * 70  # 70 '=' chars; the 65th sits at index 64
    (out,) = bash_mask([line], tmp_path)
    assert "<masked: too many assignments>" in out
    assert SECRET_VALUE not in out


def test_exactly_at_limit_no_marker(tmp_path):
    # exactly 64 '=' -> every '=' is examined and none matches; the marker
    # does NOT appear and the line passes through (possibly cut by oneline).
    line = "=" * 64
    (out,) = bash_mask([line], tmp_path)
    assert "<masked: too many assignments>" not in out


def test_too_many_assignments_when_secret_would_have_been_after_64th(tmp_path):
    # A secret-looking assignment placed AFTER the 64th '=' is never reached;
    # the fail-closed marker wins, so the secret value never enters the log.
    # Build the line so the 65th '=' sits <= 88 chars from the start; the
    # 32-char marker then fits inside oneline's 120-char cut.
    line = "=" * 64 + f"={SECRET}"  # 65 '=' total, 65th at index 64
    assert len(line) <= 88, len(line)
    (out,) = bash_mask([line], tmp_path)
    assert SECRET not in out
    assert "<masked: too many assignments>" in out


# ---- 10. mask_secrets must walk the WHOLE argument even when the caller's
#         loop variable is not named `line` (scripts/owrt-change.sh:111-113) --


def bash_mask_via_args(loops, lines, tmp_path, catalog=CATALOG):
    """Run mask_secrets in a bash subprocess where the caller's loop variable
    is `loops` (e.g. ``arg``) instead of ``line``. Used to demonstrate the
    truth that scripts/owrt-change.sh:112 `local line=$1 i=0 len=${#line}`
    expanded `${#line}` BEFORE the local `line` was bound, so the inner length
    shadowed the outer one (or crashed under `set -u` when no outer
    ``line`` existed at all)."""
    harness = tmp_path / f"mask-loops-{loops}.sh"
    audit = tmp_path / "audit.log"
    harness.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        f"ROUTER=catalog-test\nAUDIT={shlex_quote(str(audit))}\n"
        f"SECRET_CATALOG={shlex_quote(str(catalog))}\n"
        + _extract_functions(SCRIPT.read_text(), BASH_FUNCTIONS)
        + f"\nload_secret_catalog\nfor {loops} in \"$@\"; do mask_secrets \"${loops}\"; done\n"
    )
    result = subprocess.run(
        ["/usr/bin/env", "bash", str(harness), *lines],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
    )
    assert result.returncode == 0, f"rc={result.returncode}: {result.stderr!r}\nstdout={result.stdout!r}"
    return result.stdout.splitlines()


def bash_mask_with_outer_line(lines, tmp_path, outer="OUTER", catalog=CATALOG):
    """Same as ``bash_mask_via_args`` but with an outer shell variable
    ``line`` set to a different value before calling mask_secrets. The
    outer value is shorter than the inputs so the wrong length reaches the
    function; the old `local line=$1 len=${#line}` shadowed it with the
    outer's."""
    harness = tmp_path / "mask-outer-line.sh"
    audit = tmp_path / "audit.log"
    harness.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        f"line={shlex_quote(outer)}\n"
        f"ROUTER=catalog-test\nAUDIT={shlex_quote(str(audit))}\n"
        f"SECRET_CATALOG={shlex_quote(str(catalog))}\n"
        + _extract_functions(SCRIPT.read_text(), BASH_FUNCTIONS)
        + "\nload_secret_catalog\n"
        "for arg in \"$@\"; do mask_secrets \"$arg\"; done\n"
    )
    result = subprocess.run(
        ["/usr/bin/env", "bash", str(harness), *lines],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
    )
    assert result.returncode == 0, f"rc={result.returncode}: {result.stderr!r}\nstdout={result.stdout!r}"
    return result.stdout.splitlines()


@pytest.mark.parametrize(
    "line",
    [
        "uci: foo=bar password='S3cr3tValue'",
        "uci: parse set foo.bar=1 passwd = S3cr3tValue",
    ],
)
def test_midline_secret_is_masked_when_caller_has_no_outer_line(line, tmp_path):
    out = bash_mask_via_args("arg", [line], tmp_path)
    assert len(out) == 1, out
    assert SECRET not in out[0], out


@pytest.mark.parametrize(
    "line",
    [
        "uci: foo=bar password='S3cr3tValue'",
        "uci: parse set foo.bar=1 passwd = S3cr3tValue",
    ],
)
def test_midline_secret_is_masked_when_caller_has_different_outer_line(line, tmp_path):
    out = bash_mask_with_outer_line([line], tmp_path)
    assert len(out) == 1, out
    assert SECRET not in out[0], out
