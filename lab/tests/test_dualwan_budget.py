"""Failover / failback time budget for the dualwan lab scenarios.

The router-resident health script (`scripts/newton-wan-health.sh`) needs up
to `N*(interval+K*timeout)+interval` seconds to demote a dead WAN, and the
same bound with `up_after` for restoration. K is the probe target count:
`probe_iface` pings each target in turn with `-W timeout` and stops at the
first answer, so a dead round costs K*timeout for K targets. The bound
assumes the other WANs in the same round answer promptly (do_round probes
every WAN in turn; each one that is also dead adds up to K*timeout to that
round). At the defaults (interval=5, timeout=2, K=1, down_after=3) the
failover budget is 26 s; with K=2 it is 32 s. The three scenarios that
measure the cut-to-route-change path (`dw-01-failover`, `dw-02-failback`,
`dw-05-failover-ifdown`) stage WH_INTERVAL / WH_TIMEOUT / WH_DOWN_AFTER /
WH_UP_AFTER / WH_TARGETS by hand at the top of the effect cmd; the lab
test `test_dualwan_scenario_effect_sets_wh_vars_from_batch` fails if they
differ from the same scenario's `batch`. The budget is then computed from
those WH_* values via `wh_budget`, so the budget matches the UCI settings
the health script actually runs with as long as the WH_* copy is kept in
sync. The three scenarios are ported to Pulsar (`p-dw-01-failover`,
`p-dw-02-failback`, `p-dw-05-failover-ifdown` in lab/scenarios-pulsar) and
every scenario test below runs over both copies.

The test pins:

* `lab/dualwan-lib.sh` exports `wh_budget N INTERVAL TIMEOUT TARGETS` and
  the formula is `N*(INTERVAL+TARGETS*TIMEOUT)+INTERVAL` (POSIX sh
  integer arithmetic; no `local`, no `[[`, no process substitution). It
  returns 26 for defaults (5/2/3/1), 32 for defaults with 2 targets, 15
  for the lab's interval=3 timeout=1 down_after=3 targets=1, and 11 for
  the lab's up_after=2.
* For each of dw-01, dw-02, dw-05 and its Pulsar port the effect cmd sets
  WH_INTERVAL, WH_TIMEOUT, WH_DOWN_AFTER, WH_UP_AFTER, WH_TARGETS at the
  top, and the test pins that those values come from the same scenario's
  `batch` (so the budget is computed from the scenario's own UCI settings,
  not hard-coded).
* The budget check after `wait_via` fails the effect when the measured
  seconds exceed the budget, with "failover over budget" / "failback
  over budget" on stderr. With `wait_via` stubbed to print a chosen
  seconds=N, the effect passes at N=budget and fails at N=budget+1;
  the dw-02 failover leg and failback leg are pinned separately.
"""
from __future__ import annotations

import os
import re
import subprocess
import tempfile
import tomllib
from pathlib import Path

import pytest

LAB_DIR = Path(__file__).resolve().parent.parent
LIB = LAB_DIR / "dualwan-lib.sh"
DUALWAN_DIR = LAB_DIR / "scenarios" / "dualwan"
PULSAR_DIR = LAB_DIR / "scenarios-pulsar"

BUDGETED = {
    "dw-01-failover",
    "dw-02-failback",
    "dw-05-failover-ifdown",
}


def _copies(*names: str) -> list:
    """(directory, name) params for each scenario and its Pulsar port.

    Every budgeted scenario is ported to lab/scenarios-pulsar with a `p-`
    prefix, and the port must obey the same budget, so every test runs
    over both copies.
    """
    return ([pytest.param(DUALWAN_DIR, n, id=f"dualwan/{n}") for n in names]
            + [pytest.param(PULSAR_DIR, f"p-{n}", id=f"scenarios-pulsar/p-{n}")
               for n in names])


BUDGETED_COPIES = _copies(*sorted(BUDGETED))
FAILOVER_COPIES = _copies("dw-01-failover", "dw-05-failover-ifdown")
FAILBACK_COPIES = _copies("dw-02-failback")

# Lab settings: interval=3, timeout=1, down_after=3, up_after=2, K=1 target.
LAB_INTERVAL = 3
LAB_TIMEOUT = 1
LAB_TARGETS = 1
WH_BUDGET_FAILOVER = 3 * (LAB_INTERVAL + LAB_TARGETS * LAB_TIMEOUT) + LAB_INTERVAL
WH_BUDGET_FAILBACK = 2 * (LAB_INTERVAL + LAB_TARGETS * LAB_TIMEOUT) + LAB_INTERVAL


def _wh_budget_function() -> str:
    """Return the `wh_budget` function text from `lab/dualwan-lib.sh`.

    The lib is bash-only (it uses `local` and process substitution in
    `wait_via`), so `sh -c '. lab/dualwan-lib.sh; ...'` is a syntax
    error. The function itself is POSIX-sh integer arithmetic, so we
    extract it and test the text in isolation the way the lib allows
    (no network, no ssh, no other helpers needed).
    """
    text = LIB.read_text()
    m = re.search(
        r"^wh_budget\(\)\s*\{(?:[^{}]|\{[^{}]*\})*^\}",
        text, re.MULTILINE | re.DOTALL,
    )
    assert m, "wh_budget() { ... } not found in lab/dualwan-lib.sh"
    return m.group(0)


@pytest.fixture(scope="module")
def wh_budget_fn() -> str:
    return _wh_budget_function()


def _sh_budget(fn_text: str, args: str) -> str:
    """Run `fn_text` under POSIX `sh` with `wh_budget <args>` and return stdout."""
    script = f"{fn_text}\necho $(wh_budget {args})\n"
    r = subprocess.run(
        ["sh", "-c", script],
        capture_output=True, text=True, timeout=10,
    )
    assert r.returncode == 0, (
        f"sh failed (rc={r.returncode}): {r.stderr!r}")
    return r.stdout.strip()


def _parse_batch_setting(batch: str, key: str) -> str:
    """Pull `set newton_wanhealth.main.<key>='<value>'` out of a batch string."""
    m = re.search(
        rf"set newton_wanhealth\.main\.{re.escape(key)}='(\d+)'", batch)
    assert m, (
        f"batch missing newton_wanhealth.main.{key}; got: {batch!r}")
    return m.group(1)


def _count_targets_in_batch(batch: str) -> int:
    """Count `add_list newton_wanhealth.main.target=...` lines in a batch string."""
    return len(re.findall(r"add_list newton_wanhealth\.main\.target=", batch))


def _read_wh_from_effect(cmd: str, key: str) -> str:
    """Pull `WH_<KEY>=<value>` (no quotes) from an effect cmd string."""
    m = re.search(rf"^\s*{key}=(\d+)\s*$", cmd, re.MULTILINE)
    assert m, f"effect cmd missing {key}=<int>; cmd was:\n{cmd}"
    return m.group(1)


# ---- wh_budget formula ------------------------------------------------------


def test_wh_budget_formula_with_K_parameter(wh_budget_fn: str):
    """wh_budget takes 4 args (N INTERVAL TIMEOUT TARGETS) and computes
    `N*(INTERVAL+TARGETS*TIMEOUT)+INTERVAL`. Defaults (5/2/3/1) give 26
    s; defaults with 2 targets give 32 s; lab failover (3/3/1/1) gives
    15 s; lab failback (2/3/1/1) gives 11 s."""
    assert _sh_budget(wh_budget_fn, "3 5 2 1") == "26", (
        "wh_budget 3 5 2 1 (defaults interval=5 timeout=2 down_after=3 "
        "targets=1) must equal 26 s")
    assert _sh_budget(wh_budget_fn, "3 5 2 2") == "32", (
        "wh_budget 3 5 2 2 (defaults interval=5 timeout=2 down_after=3 "
        "targets=2) must equal 32 s")
    assert _sh_budget(wh_budget_fn, "3 3 1 1") == "15", (
        "wh_budget 3 3 1 1 (lab interval=3 timeout=1 down_after=3 "
        "targets=1) must equal 15 s")
    assert _sh_budget(wh_budget_fn, "2 3 1 1") == "11", (
        "wh_budget 2 3 1 1 (lab interval=3 timeout=1 up_after=2 "
        "targets=1) must equal 11 s")


def test_wh_budget_is_posix_sh(wh_budget_fn: str):
    """The function must run under plain POSIX `sh` (dash on Debian) with
    no bash-isms: no `local`, no `[[`, no process substitution. This is
    what makes it usable from any sh-compatible shell the effect cmd
    might run under."""
    bad = ("local ", "[[", "]]", "<(", ">(", "declare ", "typeset ")
    for token in bad:
        assert token not in wh_budget_fn, (
            f"wh_budget must be POSIX sh; found bash-only {token!r} "
            f"in:\n{wh_budget_fn}")


def test_wh_budget_present_in_lib():
    """The helper is declared in lab/dualwan-lib.sh with a short comment."""
    text = LIB.read_text()
    assert re.search(r"^wh_budget\(\)\s*\{", text, re.MULTILINE), (
        "wh_budget() { ... } must be declared in lab/dualwan-lib.sh")


# ---- each dualwan scenario carries the WH_* vars ----------------------------


def _effect_for(directory: Path, name: str) -> tuple[str, str]:
    """Return (cmd, batch) for the first effect of the named dualwan scenario."""
    path = directory / f"{name}.toml"
    assert path.exists(), f"missing scenario file {path}"
    data = tomllib.loads(path.read_text())
    effects = data.get("effect", [])
    assert effects, f"{name}: no [[effect]] in {path}"
    return str(effects[0]["cmd"]), str(data.get("batch", ""))


@pytest.mark.parametrize("directory,name", BUDGETED_COPIES)
def test_dualwan_scenario_effect_sets_wh_vars_from_batch(
        directory: Path, name: str):
    """The effect cmd sets WH_INTERVAL / WH_TIMEOUT / WH_DOWN_AFTER /
    WH_UP_AFTER / WH_TARGETS at the top. The WH_* values are copied by
    hand from the scenario's `batch` (the UCI settings the health
    script will run with); if they differ the budget computed by
    `wh_budget` would not match what the script enforces, so this test
    fails on any drift."""
    cmd, batch = _effect_for(directory, name)

    expected = {
        "WH_INTERVAL": _parse_batch_setting(batch, "interval"),
        "WH_TIMEOUT": _parse_batch_setting(batch, "timeout"),
        "WH_DOWN_AFTER": _parse_batch_setting(batch, "down_after"),
        "WH_UP_AFTER": _parse_batch_setting(batch, "up_after"),
        "WH_TARGETS": str(_count_targets_in_batch(batch)),
    }
    got = {k: _read_wh_from_effect(cmd, k) for k in expected}
    assert got == expected, (
        f"{name}: WH_* values {got!r} must equal the batch's UCI "
        f"settings {expected!r} so the budget is computed from the "
        f"scenario's own settings")


# ---- budget enforcement: execute each effect under bash with stubs ----------


def _make_overrides(seconds_per_call: list[int], counter_path: str) -> str:
    """Build bash stubs for `wait_via` and the host-touching helpers.

    `wait_via` prints `via=WANT seconds=N` for each successive call,
    where N is taken from `seconds_per_call` in order (1-indexed). The
    real `nwcut_on/off` and `nwdown_on/off` become no-ops so the EXIT
    trap can run without touching the lab network.

    `counter_path` is a file the subshells spawned by `$(wait_via ...)`
    write to; the parent counter would be lost across command
    substitutions, so the stub persists it via the file (the lab runner
    runs each effect via `bash -c <cmd>` from the repo root, which is the
    same shape we mirror here).
    """
    seq = ",".join(str(s) for s in seconds_per_call)
    return f"""
WAIT_VIA_COUNTER_FILE='{counter_path}'
WAIT_VIA_SEQ='{seq}'
wait_via() {{
    local want=$1
    local idx=$(($(cat "$WAIT_VIA_COUNTER_FILE") + 1))
    echo $idx > "$WAIT_VIA_COUNTER_FILE"
    local secs
    secs=$(echo "$WAIT_VIA_SEQ" | cut -d, -f$idx)
    [ -z "$secs" ] && secs=0
    printf 'via=%s seconds=%d\\n' "$want" "$secs"
    return 0
}}
nwcut_on() {{ :; }}
nwcut_off() {{ :; }}
nwdown_on() {{ :; }}
nwdown_off() {{ :; }}
"""


def _effect_cmd_with_stubs(directory: Path, name: str,
                           seconds_per_call: list[int],
                           counter_path: str) -> str:
    """Build a bash script that runs `name`'s effect cmd with wait_via /
    nwcut_* / nwdown_* stubbed. The lab runner runs each effect via
    `bash -c <cmd>` with cwd=repo-root so the script must source
    `lab/dualwan-lib.sh` relative to that cwd; overrides are spliced in
    AFTER the source line so the lib's helpers are re-defined (the
    lib's `wait_via` calls ssh, which the test must not)."""
    cmd, _batch = _effect_for(directory, name)
    lines = cmd.split("\n")
    src_idx = next(
        (i for i, ln in enumerate(lines)
         if ln.strip() == ". lab/dualwan-lib.sh"),
        None,
    )
    assert src_idx is not None, (
        f"{name}: effect cmd must source lab/dualwan-lib.sh; got:\n{cmd}")
    pre = lines[:src_idx + 1]
    post = lines[src_idx + 1:]
    overrides = _make_overrides(seconds_per_call, counter_path)
    return "\n".join(pre + ["", overrides, ""] + post)


def _run(directory: Path, name: str,
         seconds_per_call: list[int]) -> subprocess.CompletedProcess:
    """Run the effect cmd for `name` with wait_via stubbed to return
    `seconds_per_call[i]` for the i-th call (1-indexed). cwd=repo-root
    so the lib's `. lab/dualwan-lib.sh` resolves."""
    fd, counter_path = tempfile.mkstemp(prefix="wh_budget_", suffix=".counter")
    try:
        with os.fdopen(fd, "w") as f:
            f.write("0")
        script = _effect_cmd_with_stubs(directory, name, seconds_per_call,
                                        counter_path)
        return subprocess.run(
            ["bash", "-c", script],
            capture_output=True, text=True, timeout=30,
            cwd=str(LAB_DIR.parent),  # the lab runner uses cwd=repo-root
        )
    finally:
        Path(counter_path).unlink(missing_ok=True)


# dw-01-failover and dw-05-failover-ifdown: one baseline A call, one B call.
_FAILOVER_CALLS_AT_BUDGET = [1, WH_BUDGET_FAILOVER]
_FAILOVER_CALLS_OVER_BUDGET = [1, WH_BUDGET_FAILOVER + 1]


@pytest.mark.parametrize("directory,name", FAILOVER_COPIES)
def test_dualwan_failover_effect_at_budget_passes(
        directory: Path, name: str):
    """When wait_via B reports exactly the budget, the effect exits 0
    and prints `failover_seconds=<budget>` on stdout."""
    r = _run(directory, name, _FAILOVER_CALLS_AT_BUDGET)
    assert r.returncode == 0, (
        f"{name}: rc={r.returncode}, stderr={r.stderr!r}, "
        f"stdout={r.stdout!r}")
    assert f"failover_seconds={WH_BUDGET_FAILOVER}" in r.stdout, (
        f"{name}: stdout must include `failover_seconds="
        f"{WH_BUDGET_FAILOVER}`; got: {r.stdout!r}")
    assert f"budget_seconds={WH_BUDGET_FAILOVER}" in r.stdout, (
        f"{name}: stdout must include `budget_seconds="
        f"{WH_BUDGET_FAILOVER}`; got: {r.stdout!r}")


@pytest.mark.parametrize("directory,name", FAILOVER_COPIES)
def test_dualwan_failover_effect_over_budget_fails(
        directory: Path, name: str):
    """When wait_via B reports one second over the budget, the effect
    exits non-zero with `failover over budget` on stderr."""
    r = _run(directory, name, _FAILOVER_CALLS_OVER_BUDGET)
    assert r.returncode != 0, (
        f"{name}: expected non-zero rc on budget overrun; got rc=0, "
        f"stdout={r.stdout!r}")
    assert "failover over budget" in r.stderr, (
        f"{name}: stderr must include `failover over budget` on "
        f"overrun; got: {r.stderr!r}")


# dw-02-failback: baseline A, failover B, failback A.
_DW02_FAILOVER_LEG_AT_BUDGET = [1, WH_BUDGET_FAILOVER, 1]
_DW02_FAILOVER_LEG_OVER_BUDGET = [1, WH_BUDGET_FAILOVER + 1, 1]
_DW02_FAILBACK_LEG_AT_BUDGET = [1, 1, WH_BUDGET_FAILBACK]
_DW02_FAILBACK_LEG_OVER_BUDGET = [1, 1, WH_BUDGET_FAILBACK + 1]


@pytest.mark.parametrize("directory,name", FAILBACK_COPIES)
def test_dualwan_failback_effect_failover_leg_at_budget_passes(
        directory: Path, name: str):
    r = _run(directory, name, _DW02_FAILOVER_LEG_AT_BUDGET)
    assert r.returncode == 0, (
        f"dw-02 failover leg: rc={r.returncode}, stderr={r.stderr!r}, "
        f"stdout={r.stdout!r}")
    assert f"failover_seconds={WH_BUDGET_FAILOVER}" in r.stdout, (
        f"dw-02 failover leg: stdout must include "
        f"`failover_seconds={WH_BUDGET_FAILOVER}`; got: {r.stdout!r}")


@pytest.mark.parametrize("directory,name", FAILBACK_COPIES)
def test_dualwan_failback_effect_failover_leg_over_budget_fails(
        directory: Path, name: str):
    r = _run(directory, name, _DW02_FAILOVER_LEG_OVER_BUDGET)
    assert r.returncode != 0, (
        f"dw-02 failover leg: expected non-zero rc on overrun; "
        f"got rc=0, stdout={r.stdout!r}")
    assert "failover over budget" in r.stderr, (
        f"dw-02 failover leg: stderr must include `failover over "
        f"budget` on overrun; got: {r.stderr!r}")


@pytest.mark.parametrize("directory,name", FAILBACK_COPIES)
def test_dualwan_failback_effect_failback_leg_at_budget_passes(
        directory: Path, name: str):
    r = _run(directory, name, _DW02_FAILBACK_LEG_AT_BUDGET)
    assert r.returncode == 0, (
        f"dw-02 failback leg: rc={r.returncode}, stderr={r.stderr!r}, "
        f"stdout={r.stdout!r}")
    assert f"failback_seconds={WH_BUDGET_FAILBACK}" in r.stdout, (
        f"dw-02 failback leg: stdout must include "
        f"`failback_seconds={WH_BUDGET_FAILBACK}`; got: {r.stdout!r}")


@pytest.mark.parametrize("directory,name", FAILBACK_COPIES)
def test_dualwan_failback_effect_failback_leg_over_budget_fails(
        directory: Path, name: str):
    r = _run(directory, name, _DW02_FAILBACK_LEG_OVER_BUDGET)
    assert r.returncode != 0, (
        f"dw-02 failback leg: expected non-zero rc on overrun; "
        f"got rc=0, stdout={r.stdout!r}")
    assert "failback over budget" in r.stderr, (
        f"dw-02 failback leg: stderr must include `failback over "
        f"budget` on overrun; got: {r.stderr!r}")
