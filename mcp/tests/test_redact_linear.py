"""Linear-time pins for the redactor's line-start rule.

The line-start rules (dotted, kv, colon, option/list file form) must cost
linear time in the line length: the prefix is parsed with a bounded regex and
the rest of the line is taken as the value.  The old lazy ``.*?`` plus a
trailing ``\\s*$`` re-scan backtracked quadratically over long whitespace runs
(``a.b.key=`` + 50,000 spaces + ``x`` took ~16 s).  Every test here fails if
that shape comes back, while also pinning that the whole rest of the line is
still redacted.
"""

from __future__ import annotations

import time

import pytest

from newton_mcp import redact


N = 50_000


def _timed(text: str) -> tuple[str, float]:
    start = time.perf_counter()
    out = redact.redact_text(text)
    return out, time.perf_counter() - start


def test_dotted_long_space_value_is_linear_and_redacted():
    out, dt = _timed("a.b.key=" + " " * N + "x")
    assert dt < 2.0, f"redact_text took {dt:.2f}s (quadratic line-start rule is back)"
    assert "x" not in out
    assert out.count("<redacted:") == 1
    assert out.startswith("a.b.key=")
    i = out.find("<redacted:")
    assert out[:i].rstrip(" ") == "a.b.key="


@pytest.mark.parametrize(
    "line",
    [
        "key=" + " " * N + "x",
        "key:" + " " * N + "x",
        "option key" + " " * N + "x",
        "a.b.key=" + "\t" * N + "x",
        "a.b.key=" + " " * N + "'",
        "a.b.key='" + " " * N + "x'",
    ],
    ids=["kv-spaces", "colon-spaces", "option-spaces", "dotted-tabs", "spaces-then-quote", "quoted-spaces"],
)
def test_shared_line_start_rule_is_linear_and_redacted(line):
    out, dt = _timed(line)
    assert dt < 2.0, f"redact_text took {dt:.2f}s on {line[:24]!r}"
    assert "x" not in out, f"value leaked for {line[:24]!r}: {out[:60]!r}"
    assert out.count("<redacted:") == 1


def test_doubling_input_less_than_triples_cost():
    def best(n: int) -> float:
        return _min_run("a.b.key=" + " " * n + "x")

    t20 = best(20_000)
    t40 = best(40_000)
    assert t40 / t20 < 3.0, f"cost ratio {t40 / t20:.2f} at n=20k->40k (quadratic is ~4)"


def _min_run(text: str) -> float:
    times = []
    for _ in range(5):
        start = time.perf_counter()
        redact.redact_text(text)
        times.append(time.perf_counter() - start)
    return min(times)
