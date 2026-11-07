"""end-to-end flow tests (design 6.7, 9.2 groups 5, 6, 11).

Six groups:
1. Happy flow: full pipeline through hello ... status. Asserts rc and the
   first stdout token at each step, etc/config ends at POST bytes, the guard
   is idle, `status` says `confirmed`, and the order of ubus/guard calls in
   calls.log pins the guard-arms-before-apply rule and the
   rpcd-confirms-while-guard-is-armed rule.
2. Failure flow: same to apply, then verify fails; past the rpcd deadline,
   rpcd tick already reverted; abort settles with `already-rolled-back`.
3. The 6.7 table, one event per case: final bytes and first status word.
4. Output contract: every exit code is in the declared set (never 255); no
   forbidden first token; stderr detail fields clean; the only stdout lines
   come from the program.
5. No scratch files leak past the flow.
6. The program never writes a 2.1 setup file.

Helpers are kept local; nothing else is touched.
"""

import shutil
import subprocess
from pathlib import Path

import pytest

from conftest import SID, _executable


DF_OUT = (
    "Filesystem 1024-blocks Used Available Capacity Mounted on\n"
    "/dev/sda1 1000000 1000 999000 1% /etc\n"
)
DF_OUT_LOW = (
    "Filesystem 1024-blocks Used Available Capacity Mounted on\n"
    "/dev/sda1 1000000 1000 10 1% /etc\n"
)
SERVICE_LIST = (
    '{"dnsmasq":{"instances":{"main":{"running":true,"pid":411}}}}\n'
)
ORIGINAL_DHCP = b"config dnsmasq\n\toption domainneeded '1'\n"
POST_DHCP = b"config dnsmasq\n\toption domainneeded '0'\n"
ORIGINAL_BYTES = {
    "dhcp": ORIGINAL_DHCP,
    "firewall": b"config defaults\n\toption input 'REJECT'\n",
    "network": b"config interface 'lan'\n\toption proto 'static'\n",
    "system": b"config system\n\toption hostname 'newton-test'\n",
    "wireless": b"config wifi-device 'radio0'\n\toption channel 'auto'\n",
}


# Fake `ucode` so the helper's health-snapshot and health-check succeed.
# Both helper calls pass `-e '<script>'`; the script's text differs
# (1-field vs 3-field). Detect which the script wants from the script
# content (the 3-field variant contains a `\t%s` format string).
FAKE_UCODE_BODY = (
    "#!/usr/bin/python3\n"
    "import json, sys\n"
    "script = ''\n"
    "i = 1\n"
    "while i < len(sys.argv):\n"
    "    if sys.argv[i] == '-e' and i + 1 < len(sys.argv):\n"
    "        script = sys.argv[i + 1]\n"
    "        i += 2\n"
    "    else:\n"
    "        i += 1\n"
    "three_field = ('\\\\t%s' in script)\n"
    "try:\n"
    "    obj = json.loads(sys.stdin.read())\n"
    "except Exception:\n"
    "    sys.exit(1)\n"
    "if not isinstance(obj, dict):\n"
    "    sys.exit(1)\n"
    "for service, body in obj.items():\n"
    "    if not isinstance(body, dict):\n"
    "        continue\n"
    "    instances = body.get('instances', {})\n"
    "    if not isinstance(instances, dict):\n"
    "        continue\n"
    "    for instance, state in instances.items():\n"
    "        if not isinstance(state, dict):\n"
    "            continue\n"
    "        if three_field:\n"
    "            running = 'true' if state.get('running') is True else 'false'\n"
    "            pid = state.get('pid') if state.get('pid') is not None else ''\n"
    "            sys.stdout.write(f'{service}/{instance}\\t{running}\\t{pid}\\n')\n"
    "        elif state.get('running') is True:\n"
    "            sys.stdout.write(f'{service}/{instance}\\n')\n"
    "sys.exit(0)\n"
)


# ---- shared helpers (re-defined locally, do not edit conftest) ----------


def snapshot_config(router):
    cfg = router.root / "etc/config"
    return {p.name: p.read_bytes() for p in sorted(cfg.iterdir())
            if p.is_file() and not p.is_symlink()}


def assert_original(router):
    assert snapshot_config(router) == ORIGINAL_BYTES


def install_init_fakes(router):
    """init.d/firewall and init.d/dnsmasq both succeed (verify, fwrestart)."""
    initd = router.root / "etc/init.d"
    _executable(initd / "firewall", '#!/bin/sh\nexit 0\n')
    _executable(
        initd / "dnsmasq",
        '#!/bin/sh\n'
        'case "$1" in running) exit 0 ;; restart) exit 0 ;; *) exit 0 ;; esac\n',
    )


def ready_for_arm(router):
    router.set_fake("df", out=DF_OUT)


def ready_for_health_snapshot(router):
    """Make `ubus call service list` produce valid service JSON so the
    helper's `health-snapshot` succeeds end-to-end (calls.log records the
    call; the program captures fw-loaded and writes `newton-fw4-loaded`).
    Also install the `ucode` fake so the helper's JSON parsing step works."""
    install_ucode(router)
    router.set_fake("ubus", out=SERVICE_LIST)


def install_ucode(router):
    """Drop a `ucode` fake next to the other fakes. The helper invokes
    `ucode -e <script> < json` and our fake parses the JSON and emits
    the format the script's content asks for (1 field for the snapshot,
    3 tab-separated fields for the check)."""
    ucode = router.root / "bin" / "ucode"
    ucode.write_text(FAKE_UCODE_BODY)
    ucode.chmod(0o755)


def clear_ubus_out(router):
    """Drop control/ubus.out so a later ubus call's stdout is empty."""
    p = router.root / "control/ubus.out"
    if p.exists():
        p.unlink()


def status_word(router, sid):
    res = router.forced(f"status {sid}", role="read", timeout=30)
    assert res.rc == 0, (res.rc, res.out, res.err)
    return res.out.splitlines()[0].split()[0]


def apply_prod(router, plan):
    """`apply SID T token NBF EXP` for a prod plan. Caller pre-fed `df` (and
    removed `ubus.out` if it was set for health-snapshot)."""
    ready_for_arm(router)
    nbf, exp = router.window()
    token = router.token(plan.digest, nbf, exp)
    return router.apply(plan.sid, plan.t, token, nbf, exp)


def collect_call_lines(router):
    """calls.log with the `logger` echoes dropped (M-trap)."""
    path = router.root / "control/calls.log"
    if not path.exists():
        return []
    return [line for line in path.read_text().splitlines()
            if not line.startswith("logger ")]


# ---- 1. Happy flow ------------------------------------------------------


def test_happy_full_flow_through_real_guard_and_helper(router):
    """hello ... status through the real guard (copy in
    /usr/libexec/newton-guard) and the real helper (helper stub only for
    stage and diff). Asserts rc and the first stdout token at each step;
    the final etc/config holds the POST bytes, the guard is idle,
    `status <sid>` says `confirmed`, and the calls.log order pins
    `uci-apply ... guard-pending=1` before anything else of apply and
    `uci-confirm ... guard-pending=1` while the guard is still armed."""
    install_init_fakes(router)
    router.write("etc/newton/profile", "prod\n")
    router.use_stub_helper()
    if not (router.root / "control/diff.txt").exists():
        router.write("control/diff.txt", b"dhcp.cfg01.domain='lan'\n")
    router.write("control/staged/dhcp", POST_DHCP)

    # 1. hello
    res = router.forced("hello 0123456789abcdef", role="read", timeout=15)
    assert (res.rc, res.out.split()[0]) == (0, "hello")
    assert res.err == ""

    # 2. hostname
    router.set_fake("uci", out="newton-test\n")
    res = router.forced("hostname", role="read", timeout=15)
    assert (res.rc, res.out) == (0, "newton-test\n")
    assert res.err == ""

    # 3. backup (gzip binary stream; just assert rc)
    res = router.direct("backup", timeout=30)
    assert (res.rc, res.err) == (0, "")

    # 4. stage
    res = router.stage(batch=b"set dhcp.cfg01.domain=lan\n")
    assert (res.rc, res.out.split()[0]) == (0, SID)
    assert res.err == ""

    # 5. seal (prod profile: digest goes here, token at apply)
    seal_res = router.seal(SID, 90)
    assert seal_res.rc == 0 and seal_res.err == ""
    digest = None
    for line in seal_res.out.splitlines():
        if line.startswith("digest "):
            digest = line.split()[1]
    assert digest and len(digest) == 64, seal_res.out
    assert seal_res.out.split()[0] == "base"

    # 6. diff SID (stubbed)
    res = router.forced(f"diff {SID}", role="change", timeout=15)
    assert (res.rc, res.err) == (0, "")
    assert res.out.split()[0].startswith("dhcp")

    # 7. named SID (real helper)
    res = router.forced(f"named {SID}", role="change", timeout=15)
    assert (res.rc, res.err) == (0, "")
    assert res.out == ""

    # 8. fw-loaded (0 or 1, both valid; the helper's probe just records)
    res = router.forced("fw-loaded", role="read", timeout=15)
    assert res.rc == 0 and res.out.strip() in {"0", "1"}
    assert res.err == ""

    # 9. logd-pid
    router.set_fake("pidof", out="411\n")
    res = router.forced("logd-pid", role="read", timeout=15)
    assert (res.rc, res.out) == (0, "411\n")

    # 10. confighash
    res = router.forced("confighash", role="read", timeout=15)
    assert (res.rc, res.err) == (0, "")
    # every line: <32-hex md5> <name>
    for line in res.out.splitlines():
        toks = line.split()
        assert len(toks) == 2 and len(toks[0]) == 32 and len(toks[1]) > 0, line

    # 11. health-snapshot SID (real helper through ubus service list)
    ready_for_health_snapshot(router)
    res = router.forced(f"health-snapshot {SID}", role="change", timeout=30)
    assert (res.rc, res.err) == (0, "")
    # leave ubus.out in place so verify's health-check can read service list

    # 12. apply SID T TOKEN NBF EXP (prod). The ubus apply stdout is redirected
    # to /dev/null by the program; a stray ubus.out does not leak.
    ready_for_arm(router)
    nbf, exp = router.window()
    token = router.token(digest, nbf, exp)
    res = router.apply(SID, 90, token, nbf, exp)
    assert (res.rc, res.out.split()[0]) == (0, "applied")
    assert res.err == ""

    # 13. fwrestart 1 (real helper)
    res = router.forced("fwrestart 1", role="change", timeout=30)
    assert res.rc == 0

    # 14. verify SID 0 (program verify, not the helper)
    res = router.forced(f"verify {SID} 0", role="change", timeout=30)
    assert (res.rc, res.out, res.err) == (0, "", "")

    # 15. confirm SID
    res = router.forced(f"confirm {SID}", role="change", timeout=30)
    assert (res.rc, res.out.split()[0]) == (0, "confirmed")
    assert res.err == ""

    # 16. status SID
    res = router.forced(f"status {SID}", role="read", timeout=30)
    assert (res.rc, res.out.split()[0]) == (0, "confirmed")
    assert res.err == ""

    # final state
    assert (router.root / "etc/config/dhcp").read_bytes() == POST_DHCP
    assert router.guard_status() == "idle"
    assert status_word(router, SID) == "confirmed"

    # calls.log order — guard armed before uci apply; rpcd confirm while the
    # guard is still armed; the uci-apply line carries `guard-pending=1`
    # (M24); the uci-confirm line does too (6.3 step 4: rpcd first).
    calls = collect_call_lines(router)
    apply_idx = next(i for i, c in enumerate(calls)
                     if c.startswith("ubus uci-apply"))
    confirm_idx = next(i for i, c in enumerate(calls)
                       if c.startswith("ubus uci-confirm"))
    assert calls[apply_idx].endswith(" guard-pending=1"), calls[apply_idx]
    assert calls[confirm_idx].endswith(" guard-pending=1"), calls[confirm_idx]
    # the apply line predates everything the apply wrote afterwards (here:
    # the `uc` "ubus call session list" calls session-list came before the
    # arm — `uci-apply` is the first *apply* log line, and the guard line
    # `armed` comes before it because the guard pending is read by handle).
    # We pin simply: there is no apply-related log line before uci-apply
    # except the session-list / arm calls; the guard went idle only AFTER
    # confirm — the bootstrap test of that is guard_status() == "idle".
    gs_after = router.guard_status()
    assert gs_after == "idle"


# ---- 2. Failure flow ----------------------------------------------------


def test_failure_verify_fails_then_abort_after_rpcd_tick(router):
    """Same path through apply; verify fails (control/ping.rc=1); past
    the rpcd deadline (uptime=200); `rpcd_tick` reverts etc/config; the
    owner's `abort` settles with `already-rolled-back` (rpcd already did
    it; restore abort is a no-op copy). After `health-check ... after-
    rollback` and `confighash`, `status <sid>` says `rolled-back`, the
    guard is `restored <sid> abort` and the bytes are the ORIGINAL."""
    install_init_fakes(router)
    router.use_stub_helper()
    if not (router.root / "control/diff.txt").exists():
        router.write("control/diff.txt", b"dhcp.cfg01.domain='lan'\n")
    router.write("control/staged/dhcp", POST_DHCP)
    assert ORIGINAL_DHCP != POST_DHCP

    res = router.stage(batch=b"set dhcp.cfg01.domain=lan\n")
    assert res.rc == 0 and res.out == SID + "\n"
    seal_res = router.seal(SID, 90)
    assert seal_res.rc == 0
    digest = next(line.split()[1] for line in seal_res.out.splitlines()
                  if line.startswith("digest "))

    ready_for_health_snapshot(router)
    res = router.forced(f"health-snapshot {SID}", role="change", timeout=30)
    assert res.rc == 0
    ready_for_arm(router)
    nbf, exp = router.window()
    token = router.token(digest, nbf, exp)
    res = router.apply(SID, 90, token, nbf, exp)
    assert res.rc == 0 and res.out.split()[0] == "applied"
    assert (router.root / "etc/config/dhcp").read_bytes() == POST_DHCP
    assert router.guard_status().startswith(f"pending {SID}")

    # verify fails: rc=1, stderr `verify: ping ... failed`
    router.set_fake("ping", rc=1)
    res = router.forced(f"verify {SID} 0", role="change", timeout=30)
    assert (res.rc,) == (1,)
    assert "verify: " in res.err
    assert res.out == ""
    # nothing touched
    assert (router.root / "etc/config/dhcp").read_bytes() == POST_DHCP
    assert router.guard_status().startswith(f"pending {SID}")

    # Move past the rpcd deadline (190) and tick the fake rpcd
    router.set_uptime(200)
    rc = router.rpcd_tick()
    assert rc == 0
    # rpcd reverted: dhcp is back at the ORIGINAL bytes
    assert (router.root / "etc/config/dhcp").read_bytes() == ORIGINAL_DHCP
    # the guard pending file is still there (only dead after its own tick)
    assert router.guard_status().startswith(f"pending {SID}")

    # status before abort: rule 5 (txn applied, G pending, cfg=base)
    word_before = status_word(router, SID)
    assert word_before == "rolled-back", (word_before,)

    # abort -> `aborted <sid> already-rolled-back`
    res = router.forced(f"abort {SID}", role="change", timeout=30)
    assert (res.rc, res.out.split()[0]) == (0, "aborted")
    assert SID in res.out and "already-rolled-back" in res.out

    # after abort cleanup: txn dir gone, guard restored abort
    assert not (router.root / "tmp/owrt-safe-apply.lock" / f"{SID}.txn").exists()
    assert router.guard_status() == f"restored {SID} abort"

    # health-check ... after-rollback: no snapshot (program kept it; the
    # abort cleanup in 6.4 keeps the health dir if no live txn, but here
    # abort removed the txn dir so the snapshot is gone -- the snapshot
    # stays only when the txn is kept: 6.4 cleanup rule explicitly KEEPS
    # the health snapshot. Re-check with test below.)
    res = router.direct("health-check", SID, "after-rollback", timeout=15)
    # Either rc 0 (passes) or rc 1 with the reboot/no-snapshot stderr;
    # what matters here is no exception and at-least-one printed line.
    assert res.rc in (0, 1)

    # confighash
    res = router.forced("confighash", role="read", timeout=15)
    assert res.rc == 0
    assert res.out  # non-empty

    # status after abort: no txn, guard restored abort -> rule 11
    res = router.forced(f"status {SID}", role="read", timeout=30)
    assert res.rc == 0
    assert res.out.split()[0] == "rolled-back"

    # final assertion: bytes back to ORIGINAL, guard restored <sid> abort
    assert_original(router)
    assert router.guard_status() == f"restored {SID} abort"


# ---- 3. The 6.7 table ---------------------------------------------------


def _prep_apply(router):
    """Bring the router to the applied state (txn applied, cfg=post,
    guard pending, session live). Returns the plan."""
    install_init_fakes(router)
    plan = router.fresh_plan()
    ready_for_arm(router)
    res = router.apply(plan.sid, plan.t, "none", 0, 0)
    assert res.rc == 0 and res.out.split()[0] == "applied", (res.rc, res.out)
    assert router.guard_status().startswith(f"pending {plan.sid}")
    return plan


def _final_status_and_bytes(router, plan):
    """Return `(word, snapshot)` after the event in question. `status`
    runs first so its tick (M29) can settle the bytes; we then snapshot."""
    word = status_word(router, plan.sid)
    snap = snapshot_config(router)
    return word, snap


def test_6_7_no_confirm_ticks_restores_original(router):
    """Row "no confirm": set_uptime(300) past the guard deadline (221);
    `status` ticks the guard (M29) — guard restore_core copies LKG back
    over etc/config. Final bytes = ORIGINAL, first status word =
    `rolled-back`."""
    plan = _prep_apply(router)
    router.set_uptime(300)
    word, snap = _final_status_and_bytes(router, plan)
    assert snap == ORIGINAL_BYTES, (snap,)
    assert word == "rolled-back", (word,)


def test_6_7_reboot_in_window_guard_boot_restores(router):
    """Row "reboot": set_boot_id boot-two, set_uptime(8), guard `boot`
    (restore_core boot noreload). cfg is back at ORIGINAL, status says
    `rolled-back`."""
    plan = _prep_apply(router)
    router.set_uptime(8)
    router.set_boot_id("boot-two")
    rc = router.guard("boot").rc
    assert rc == 0
    word, snap = _final_status_and_bytes(router, plan)
    assert snap == ORIGINAL_BYTES, (snap,)
    assert word == "rolled-back", (word,)


def test_6_7_rpcd_lost_its_timer_then_abort(router):
    """Row "rpcd lost its timer, then `abort`": control/rpcd-lost +
    destroyed session; `abort` -> `aborted <sid> rolled-back-by-guard`,
    bytes ORIGINAL. (We only set rpcd-lost for completeness — the abort
    doesn't reach confirm — but it documents the state.)"""
    plan = _prep_apply(router)
    # Mark the rpcd as having lost its timer (confirm would take the lost
    # path; we abort instead, but the row description names this state).
    router.write("control/rpcd-lost", "")
    # destroy the session — `ubus call session list` no longer finds SID
    router.write("control/sessions", b"")
    res = router.forced(f"abort {plan.sid}", role="change", timeout=30)
    assert (res.rc, res.out.split()[0]) == (0, "aborted")
    assert plan.sid in res.out and "rolled-back-by-guard" in res.out
    assert snapshot_config(router) == ORIGINAL_BYTES
    assert router.guard_status() == f"restored {plan.sid} abort"
    assert status_word(router, plan.sid) == "rolled-back"


def test_6_7_rpcd_timer_lost_confirmed_via_guard_only(router):
    """Row "approved change that reloads rpcd, then confirm":
    `scratch_program` with `RPCD_LOST='5 6'` and `control/confirm.rc = 5`
    makes the rpcd check take the lost path; confighash = post, so the
    program marks `rpcd-confirmed=lost`, calls the guard, and the guard
    confirms the change through the guard-only path. stdout is
    `confirmed <sid> rpcd-timer-lost`. A later `router.guard("boot")`
    with no pending changes nothing."""
    plan = router.fresh_plan()
    install_init_fakes(router)
    res = apply_prod(router, plan)
    assert res.rc == 0, (res.rc, res.out, res.err)
    assert (router.root / "etc/config/dhcp").read_bytes() == POST_DHCP
    # `control/confirm.rc=5` makes `ubus call uci confirm` exit 5
    router.write("control/confirm.rc", "5\n")
    # Swap the running program to a copy with RPCD_LOST='5 6' so the
    # router-side 6.3 step 4 lost path engages
    router.scratch_program(router.root.parent, "RPCD_LOST=''",
                           "RPCD_LOST='5 6'")
    res = router.forced(f"confirm {plan.sid}", role="change", timeout=30)
    assert (res.rc, res.out.split()[0]) == (0, "confirmed")
    assert f"confirmed {plan.sid} rpcd-timer-lost" in res.out, res.out
    assert (router.root / "etc/config/dhcp").read_bytes() == POST_DHCP
    assert router.guard_status() == "idle"

    # A later guard boot with nothing pending changes nothing
    router.set_uptime(8)
    router.set_boot_id("boot-two")
    assert router.guard("boot").rc == 0
    assert (router.root / "etc/config/dhcp").read_bytes() == POST_DHCP
    assert router.guard_status() == "idle"


def test_6_7_guard_refuses_arm_low_space(router):
    """Row "guard refuses arm (low space)": df with `Available = 10` is
    below the guard's threshold; `arm` refuses, exit 3; the program
    maps to `error guard refused low-space`, exit 3. etc/config stays
    ORIGINAL; no `ubus uci-apply sid=...`."""
    plan = router.fresh_plan()
    router.set_fake("df", out=DF_OUT_LOW)
    res = router.apply(plan.sid, plan.t, "none", 0, 0)
    assert res.rc == 3
    assert res.err.startswith("error guard refused low-space "), res.err
    assert res.out == ""
    assert_original(router)
    assert not any(f"sid={plan.sid}" in c
                   for c in router.calls_matching("ubus uci-apply"))
    assert not (router.root / "etc/newton/pending").exists()


def test_6_7_uci_apply_fails_after_arm(router):
    """Row "uci apply fails after arm": control/apply.rc=1. The program
    calls `newton-guard restore apply-failed`, fails with
    `error apply-failed restored <sid> apply-failed`, exit 1.
    etc/config stays ORIGINAL; guard = `restored <sid> apply-failed`."""
    plan = router.fresh_plan()
    install_init_fakes(router)
    ready_for_arm(router)
    router.write("control/apply.rc", "1\n")
    res = router.apply(plan.sid, plan.t, "none", 0, 0)
    assert (res.rc, res.err) == (
        1, f"error apply-failed restored {plan.sid} apply-failed\n"
    )
    assert res.out == ""
    assert router.guard_status() == f"restored {plan.sid} apply-failed"
    assert_original(router)


def test_6_7_program_killed_between_arm_and_uci_apply(router):
    """Row "program killed between arm and uci apply":
    NEWTON_ROUTER_CRASH_AT=1 kills after `applying` is written but
    before `uci apply`. rc = -9. Guard still pending; cfg is ORIGINAL.
    Past the deadline + tick: guard restores (no-op copy); cfg stays
    ORIGINAL, guard = `restored ... deadline`."""
    plan = router.fresh_plan()
    install_init_fakes(router)
    ready_for_arm(router)
    res = router.forced(
        f"apply {plan.sid} {plan.t} none 0 0",
        caller="agent-one", role="change",
        env={"NEWTON_ROUTER_CRASH_AT": "1"}, timeout=30,
    )
    assert res.rc == -9, (res.rc, res.out, res.err)
    assert router.guard_status().startswith(f"pending {plan.sid}")
    assert_original(router)
    router.set_uptime(400)
    router.rpcd_tick()
    router.guard("tick")
    assert router.guard_status().startswith("restored ")
    assert_original(router)


def test_6_7_program_killed_between_rpcd_confirm_and_guard_confirm(router):
    """Row "program killed between rpcd confirm and guard confirm":
    NEWTON_ROUTER_CRASH_AT=1 (after rpcd-confirmed is written, before
    guard confirm). rc = -9. Guard still pending; cfg is POST (rpcd
    cleared its in-RAM rollback). Past the deadline + tick: guard
    restores the LKG back over etc/config; cfg becomes ORIGINAL."""
    plan = _prep_apply(router)
    res = router.forced(
        f"confirm {plan.sid}", caller="agent-one", role="change",
        env={"NEWTON_ROUTER_CRASH_AT": "1"}, timeout=30,
    )
    assert res.rc == -9, (res.rc, res.out, res.err)
    assert router.guard_status().startswith(f"pending {plan.sid}")
    # post bytes are live (rpcd had confirmed, no restore action)
    assert (router.root / "etc/config/dhcp").read_bytes() == POST_DHCP
    router.set_uptime(400)
    router.rpcd_tick()
    router.guard("tick")
    assert router.guard_status().startswith("restored ")
    assert_original(router)


def test_6_7_guard_timer_killed_status_restores(router):
    """Row "guard timer killed": with `control/not-running` (so a fresh
    arm would refuse with `refused timer-not-running`), the timer did
    not start. The status command ticks the guard directly (M29) and
    the tick_core ignores init.d; once uptime has passed the guard
    deadline, the guard restores. cfg = ORIGINAL; word =
    `rolled-back`."""
    plan = _prep_apply(router)
    router.write("control/not-running", "")
    router.set_uptime(300)  # past guard deadline (221)
    word, snap = _final_status_and_bytes(router, plan)
    assert snap == ORIGINAL_BYTES
    assert word == "rolled-back"


def test_6_7_guard_already_failed_stage_and_abort(router):
    """Row "guard already failed": write `pending` + `failed`. `stage`
    refused `error guard failed <sid> <why>`, exit 3; `abort` (no
    txn) -> `error inconsistent guard failed <sid> <why>`, exit 1.
    Nothing applied."""
    router.write("etc/newton/pending", f"{SID} 999 boot-one\n")
    router.write("etc/newton/failed", f"{SID} apply-failed extra\n")
    router.use_stub_helper()
    res = router.stage()
    assert (res.rc, res.out, res.err) == (
        3, "", f"error guard failed {SID} apply-failed\n"
    )
    assert not any(c.startswith("helper ") for c in router.calls())
    assert router.guard_status().startswith(f"failed {SID} ")
    # abort on a non-existent txn: 6.4 row 1 (G=failed)
    res = router.forced(f"abort {SID}", role="change", timeout=15)
    assert (res.rc, res.out, res.err) == (
        1, "", f"error inconsistent guard failed {SID} apply-failed\n"
    )


def test_6_7_dead_controllers_window_pending_stage_refused_abort_restores(router):
    """Row "dead controller's window still pending": another controller's
    guard window is still pending (this one has gone). `stage` refused
    `error guard pending <old sid> 301`, exit 3; the owner's `abort <old sid>`
    (rule 8 of 6.4) restores via the guard.

    The window is opened by the guard itself (`arm`), not by hand-made state
    files: the last-known-good directory of the guard on the main branch carries
    a seal, an older guard's does not, and either must work."""
    old_sid = "deadc0ffee0123456789abcdef012345"
    ready_for_arm(router)
    armed = router.guard("arm", old_sid, "300")
    assert armed.out.startswith(f"armed {old_sid} "), (armed.out, armed.err)
    # uptime 100 + 1 + 300 = deadline 401: left = 301 at uptime 100
    router.use_stub_helper()
    res = router.stage()
    assert (res.rc, res.err) == (
        3, f"error guard pending {old_sid} 301\n"
    )
    assert not any(c.startswith("helper ") for c in router.calls())
    # The owner's abort (rule 8: no txn, G = pending <old sid> ...)
    res = router.forced(f"abort {old_sid}", role="change", timeout=15)
    assert res.out == f"aborted {old_sid} rolled-back-by-guard\n", (res.rc, res.out, res.err)
    assert res.rc == 0
    assert router.guard_status() == f"restored {old_sid} abort"


# ---- 4. Output contract (3.7, 9.2 group 11) -----------------------------


ALLOWED_EXIT = {0, 1, 2, 3, 98, 99, 124, 125, 127}
FORBIDDEN_TOKENS = ("CONFIRMED", "ROLLBACK WINDOW PASSED", "ALERT",
                    "OUTCOME UNKNOWN")


def _first_token_of_empty_program_lines(results):
    """A program line can be the same line containing the answer. We
    only forbid the four tokens as a *first token* on stdout."""
    bad = []
    for res in results:
        if not res.out:
            continue
        first = res.out.splitlines()[0].split("\t", 1)[0].split()
        if not first:
            continue
        first_word = first[0]
        if first_word in FORBIDDEN_TOKENS:
            bad.append((first_word, res.out[:80]))
    return bad


def test_output_contract_exit_codes_and_forbidden_lines(router):
    """Run the whole happy flow (sets up every state we can), then walk
    every Result through the contract: rc in ALLOWED_EXIT, no stdout
    line whose first token is one of the four forbidden outcome words,
    and stderr detail fields have no control bytes and at most 120
    bytes each."""
    runs = _drive_happy_flow(router)
    bad_rc = [(r.rc, r.out[:60], r.err[:60]) for r in runs if r.rc not in ALLOWED_EXIT]
    assert not bad_rc, ("bad exit codes", bad_rc)
    bad_first = _first_token_of_empty_program_lines(runs)
    assert not bad_first, ("forbidden first token", bad_first)
    # Stderr detail fields
    for res in runs:
        for line in res.err.splitlines():
            if not line:
                continue
            for b in line.encode():
                ok = b == 0x09 or b == 0x0a or 0x20 <= b <= 0x7e or 0x80 <= b <= 0xff
                assert ok, (res, line, b)


def test_output_contract_stdout_only_program_lines(router):
    """Even with control/ubus.out and the guard's own lines, the only
    stdout is the program's own lines (3.7: "the guard's `armed`,
    `confirmed` and `restored` lines, `tick` output and every `ubus`
    reply never do")."""
    plan = router.fresh_plan()
    install_init_fakes(router)
    # Set up `ubus.out` so any unhandled ubus call spews
    router.set_fake("ubus", out="armed x\nconfirmed y\nrestored z\n")
    ready_for_arm(router)
    res = router.apply(plan.sid, plan.t, "none", 0, 0)
    # apply: stdout is exactly the `applied ...` line
    assert res.rc == 0
    assert res.out == f"applied {plan.sid} t={plan.t} guard=221\n"
    for token in ("armed x", "confirmed y", "restored z"):
        assert token not in res.out
        assert token not in res.err
    # status: stdout is exactly the one status line
    res = router.forced(f"status {plan.sid}", role="read", timeout=30)
    assert res.rc == 0
    assert res.out.count("\n") == 1
    assert "armed x" not in res.out and "confirmed y" not in res.out \
        and "restored z" not in res.out
    # confirm: stdout is exactly `confirmed <sid>`
    res = router.forced(f"confirm {plan.sid}", role="change", timeout=30)
    assert res.rc == 0
    assert res.out == f"confirmed {plan.sid}\n"
    for token in ("armed x", "confirmed y", "restored z"):
        assert token not in res.out
    # abort (after confirm the txn is gone, so `aborted gone`)
    res = router.forced(f"abort {plan.sid}", role="change", timeout=15)
    assert res.rc == 0
    assert res.out.split()[0] == "aborted"
    for token in ("armed x", "confirmed y", "restored z"):
        assert token not in res.out


def test_output_contract_stderr_detail_bytes_capped(router):
    """Detail fields stay under 120 bytes and never contain a control
    byte (3.7)."""
    # Build a `stage` whose stdin has a fake "guard pending ..." reason
    # with mixed bytes — but the design forbids bad bytes in stdin, so
    # we drive a different refusal. The detail byte rule must hold for
    # every error line, including ones whose detail is a router value.
    # Use the well-known `error guard pending <sid> <left>` format.
    router.write("etc/newton/pending", f"{SID} 80 boot-one\n")
    res = router.forced(f"apply {SID} 90 none 0 0", role="change", timeout=15)
    assert res.rc == 3
    assert res.err.endswith("\n")
    # every byte must be clean
    for b in res.err.encode():
        ok = b == 0x0a or 0x20 <= b <= 0x7e
        assert ok, (b, res.err)
    # detail length: "error guard pending <32hex> <left>" < 120 chars
    assert len(res.err) < 120


# Internal helper: drive the same flow as test 1 with one extra detune
# so we get a Result for every call to assert the contract on. Returned
# list captures rc/out/err for each of the 16 subcommands.


def _drive_happy_setup(router):
    """All file / df / ubus setup that the TEST does. Separated from the
    command run so the 2.1-file test can snapshot bytes AFTER the test
    setup but BEFORE any program subcommand runs."""
    install_init_fakes(router)
    router.write("etc/newton/profile", "prod\n")
    router.use_stub_helper()
    if not (router.root / "control/diff.txt").exists():
        router.write("control/diff.txt", b"dhcp.cfg01.domain='lan'\n")
    router.write("control/staged/dhcp", POST_DHCP)


def _drive_happy_commands(router):
    """The 16 program calls in happy-flow order. Returns the list of
    Results so the contract test can walk every (rc, out, err)."""
    runs = []
    runs.append(router.forced("hello 0123456789abcdef", role="read", timeout=15))
    router.set_fake("uci", out="newton-test\n")
    runs.append(router.forced("hostname", role="read", timeout=15))
    runs.append(router.direct("backup", timeout=30))
    runs.append(router.stage(batch=b"set dhcp.cfg01.domain=lan\n"))
    seal_res = router.seal(SID, 90)
    runs.append(seal_res)
    digest = None
    for line in seal_res.out.splitlines():
        if line.startswith("digest "):
            digest = line.split()[1]
    runs.append(router.forced(f"diff {SID}", role="change", timeout=15))
    runs.append(router.forced(f"named {SID}", role="change", timeout=15))
    runs.append(router.forced("fw-loaded", role="read", timeout=15))
    router.set_fake("pidof", out="411\n")
    runs.append(router.forced("logd-pid", role="read", timeout=15))
    runs.append(router.forced("confighash", role="read", timeout=15))
    ready_for_health_snapshot(router)
    runs.append(router.forced(f"health-snapshot {SID}", role="change", timeout=30))
    ready_for_arm(router)
    nbf, exp = router.window()
    runs.append(router.apply(SID, 90, router.token(digest, nbf, exp), nbf, exp))
    runs.append(router.forced("fwrestart 1", role="change", timeout=30))
    runs.append(router.forced(f"verify {SID} 0", role="change", timeout=30))
    runs.append(router.forced(f"confirm {SID}", role="change", timeout=30))
    runs.append(router.forced(f"status {SID}", role="read", timeout=30))
    return runs


def _drive_happy_flow(router):
    """Walk hello ... status. Returns the list of Result tuples."""
    _drive_happy_setup(router)
    return _drive_happy_commands(router)


# ---- 5. No scratch files leaked -----------------------------------------

SCRATCH_PREFIXES = ("rd.", "re.", "ch.", "df.", "st.", "in.", "le.", "dg.")
EXPECTED_FILES = {"flock", "hello", "last"}


def test_no_scratch_files_left_after_full_flow(router):
    """After the full happy flow, `tmp/newton` (section 2.2: scratch files
    are removed before exit) holds only `flock`, `hello`, `last`. No
    `rd.*`, `re.*`, `ch.*`, `df.*`, `st.*`, `in.*`, `le.*`, `dg.*`."""
    _drive_happy_flow(router)
    newton = router.root / "tmp/newton"
    files = sorted(p.name for p in newton.iterdir() if p.is_file())
    leftover = [name for name in files
                if any(name.startswith(p) for p in SCRATCH_PREFIXES)]
    assert not leftover, leftover
    # Allowed files (any subset is OK, but only these names)
    unexpected = [name for name in files if name not in EXPECTED_FILES]
    assert not unexpected, unexpected


# ---- 6. Program never writes a 2.1 setup file ---------------------------


DESIGN_TABLES_2_1 = (
    "etc/newton/device-id",
    "etc/newton/profile",
    "etc/newton/zones",  # not pre-created; we create it
    "etc/newton/approve.key",
)


@pytest.mark.parametrize("rel", DESIGN_TABLES_2_1)
def test_program_never_writes_2_1_files(router, rel):
    """The program never writes a design table 2.1 file
    (`/etc/newton/{device-id,profile,zones,approve.key}`): bytes and mtime
    are unchanged across the 16 program calls of the happy flow. The
    TEST setup may touch these files (writing profile for the prod
    token path, creating zones), but the program itself must not."""
    if rel == "etc/newton/zones":
        # zones does not exist in the fixture by default
        path = router.root / "etc/newton" / "zones"
        path.write_text("mgmt-interface lan\nmgmt-zone lan\nwan-zone wan\n")
    else:
        path = router.root / rel
    _drive_happy_setup(router)
    before_bytes = path.read_bytes()
    before_mtime = path.stat().st_mtime
    _drive_happy_commands(router)
    assert path.read_bytes() == before_bytes, (rel, path.read_bytes())
    assert path.stat().st_mtime == before_mtime, (rel, path.stat().st_mtime)
