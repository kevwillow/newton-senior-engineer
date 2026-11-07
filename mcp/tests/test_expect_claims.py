"""the agent's expect claims run as post-apply verify probes.

Design: explanation rule 4 and ADR-018 point 3.  The claims join
the SAME sealed probe list the router verifies from a fresh session (no second
mechanism): sealed order is Newton's own probes, then the caller's, then the
claims.  A claim only ever adds a probe; a failed one means no confirm, so the
armed rollback restores the router, and the apply result names the claim.  The
router is faked at ``run_script``; nothing here reaches a device.
"""

from __future__ import annotations

import copy
import json
import re
import subprocess
from pathlib import Path

import pytest

import newton_mcp.server as server
from exhelp import explained, make_explanation
from newton_mcp import explanation as ex
from newton_mcp.plan import compute_plan_hash

SID = "0123456789abcdef0123456789abcdef"
BASE = "b" * 64
DIGEST = "d" * 64
BATCH = "set dhcp.skilltest=host\nset dhcp.skilltest.name='skilltest'"
INVENTORY = """\
[devices.lab1]
platform = "openwrt"
host = "192.0.2.3"
user = "root"
profile = "lab"
lab = true
"""

C_UCI = {"kind": "uci_equals", "path": "dhcp.skilltest.name", "equals": "skilltest"}
C_UCI2 = {"kind": "uci_equals", "path": "firewall.fwd_8443.dest_port", "equals": "8443"}
C_PROBE = {"kind": "probe", "probe": ["iface-absent", "guestx"]}


def plan_output():
    return (
        "BACKUP /tmp/fake.tar.gz (2 config files)\n"
        f"STAGED session={SID}\n"
        f"BASEHASH {BASE}\n"
        f"PROBES 0 {'a' * 64}\n"
        "PROFILE lab\n"
        "SECTION dhcp skilltest host skilltest\n"
        "APPROVAL not-required\n"
        f"PLANDIGEST {DIGEST}\n"
        "----- diff -----\n"
        "dhcp.skilltest='host'\n"
        "dhcp.skilltest.name='skilltest'\n"
        "----------------\n"
    )


@pytest.fixture
def env(tmp_path, monkeypatch):
    inventory = tmp_path / "devices.toml"
    inventory.write_text(INVENTORY)
    monkeypatch.setenv("NEWTON_INVENTORY", str(inventory))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))
    calls: list[tuple] = []
    sealed: list[list[list[str]]] = []
    apply_out = {"rc": 0, "stdout": f"APPLYING session={SID}\nCONFIRMED session={SID}\n"}

    def fake(self, device, *args, **kwargs):
        calls.append(args)
        if args[0] == "plan":
            lines = open(args[-1], encoding="utf-8").read().splitlines() if len(args) > 4 else []
            sealed.append([line.split("\t") for line in lines])
            return subprocess.CompletedProcess(args, 0, plan_output(), "")
        return subprocess.CompletedProcess(args, apply_out["rc"], apply_out["stdout"], "")

    monkeypatch.setattr(server.NewtonService, "run_script", fake)
    return tmp_path, calls, sealed, apply_out


def plan_call(batch=BATCH, **kw):
    return server.newton_plan_change("lab1", batch, **kw)


def stored(tmp_path):
    return json.loads((tmp_path / "state" / "plans" / f"{SID}.json").read_text())


def rollback_stdout(n: int, name: str, reason: str) -> str:
    return (
        f"APPLYING session={SID}\n"
        f"APPLIED session={SID} rollback=60s\n"
        f"VERIFY FAILED session={SID} - not confirming; waiting for automatic rollback\n"
        f"VERIFY DETAIL session={SID} round=3 exit=1 stage=router-verify (last failed round; stderr and stdout follow, each last 20 lines, at most 2 KB)\n"
        f"VERIFY STDERR session={SID}: verify: probe {n} failed: {name} {reason}\n"
        f"ROLLBACK WINDOW PASSED session={SID} rolled back by the guard\n"
    )


# ---- pure helpers -------------------------------------------------------------


def test_claim_probes_in_order_from_the_stored_explanation():
    expl = ex.parse_explanation(make_explanation(BATCH, expect=[C_UCI, C_PROBE]), change_lines=2)
    assert ex.claim_probes(expl) == [
        ["uci-equals", "dhcp.skilltest.name", "skilltest"],
        ["iface-absent", "guestx"],
    ]


def test_describe_claim_is_plain_words():
    assert ex.describe_claim(C_UCI2) == "uci firewall.fwd_8443.dest_port == 8443"
    assert ex.describe_claim(C_PROBE) == "probe iface-absent guestx"


def test_failed_claim_names_the_claim_and_why():
    expl = ex.parse_explanation(make_explanation(BATCH, expect=[C_UCI, C_UCI2]), change_lines=2)
    probes = [["fail"]] + ex.claim_probes(expl)  # one Newton/caller probe, then two claims
    out = ex.failed_claim(rollback_stdout(3, "uci-equals", "mismatch"), SID, probes, expl["expect"])
    assert out == {
        "claim": 2,
        "text": "expect claim 2 failed: uci firewall.fwd_8443.dest_port != 8443 (mismatch)",
    }


def test_a_failing_newton_probe_is_not_called_a_claim():
    expl = ex.parse_explanation(make_explanation(BATCH, expect=[C_UCI]), change_lines=2)
    probes = [["fail"]] + ex.claim_probes(expl)
    assert ex.failed_claim(rollback_stdout(1, "fail", "failed"), SID, probes, expl["expect"]) is None


def test_failed_claim_ignores_lines_that_are_not_the_routers_verify_line_for_this_session():
    expl = ex.parse_explanation(make_explanation(BATCH, expect=[C_UCI]), change_lines=2)
    probes = ex.claim_probes(expl)
    spoof = [
        f"VERIFY STDERR session={'f' * 32}: verify: probe 1 failed: uci-equals mismatch\n",
        f"hostname verify: probe 1 failed: uci-equals mismatch\n",
        f"VERIFY STDERR session={SID}: verify: probe 1 failed: ping mismatch\n",  # name disagrees with probe 1
        f"VERIFY STDERR session={SID}: verify: probe 9 failed: uci-equals mismatch\n",  # out of range
        f"VERIFY STDERR session={SID}: verify: probe 1 failed: uci-equals mis match\n",
    ]
    for line in spoof:
        assert ex.failed_claim(line, SID, probes, expl["expect"]) is None, line


# ---- plan: the claims join the sealed probe list -----------------------------------


def test_claims_are_sealed_after_newton_and_caller_probes_and_stored_in_the_record(env):
    tmp, calls, sealed, _ = env
    result = plan_call(probes=[["fail"]], **explained(BATCH, expect=[C_UCI, C_PROBE]))
    assert "error" not in result, result
    tail = [["uci-equals", "dhcp.skilltest.name", "skilltest"], ["iface-absent", "guestx"]]
    assert sealed[0] == [["fail"]] + tail
    record = stored(tmp)
    assert record["probes"] == [["fail"]] + tail
    assert record["plan_hash"] == compute_plan_hash(record)


def test_claims_are_in_the_hash_through_probes_and_explanation(env):
    tmp, *_ = env
    assert "error" not in plan_call(**explained(BATCH, expect=[C_UCI, C_PROBE]))
    record = stored(tmp)
    dropped = copy.deepcopy(record)
    dropped["probes"] = dropped["probes"][:-1]
    assert compute_plan_hash(dropped) != record["plan_hash"]
    swapped = copy.deepcopy(record)
    swapped["probes"][-1] = ["iface-absent", "guesty"]
    assert compute_plan_hash(swapped) != record["plan_hash"]


def test_a_duplicate_of_a_caller_probe_is_sealed_again_so_the_claim_keeps_its_own_line(env):
    tmp, _, sealed, _ = env
    dup = ["uci-equals", "dhcp.skilltest.name", "skilltest"]
    assert "error" not in plan_call(probes=[dup], **explained(BATCH, expect=[C_UCI]))
    assert sealed[0] == [dup, dup]
    assert stored(tmp)["probes"] == [dup, dup]


def test_a_claim_cannot_remove_or_replace_a_newton_probe(env):
    """Newton's manifest probes for the touched sections stay, in place, with
    the claims added after them; claims naming the same probe change nothing."""
    tmp, _, sealed, _ = env
    batch = "set dhcp.@dnsmasq[0].dnssec='1'"
    baseline = plan_call(batch, **explained(batch, expect=[C_PROBE]))
    assert "error" not in baseline, baseline
    with_claim = sealed[0]
    sealed.clear()
    assert with_claim[-1] == ["iface-absent", "guestx"]
    newton_only = with_claim[:-1]
    assert newton_only, "this batch touches a manifest control, so Newton seals its own probes"
    # claiming the same lines again leaves Newton's lines first and untouched
    claims = [{"kind": "probe", "probe": list(p)} for p in newton_only[:3]]
    assert "error" not in plan_call(batch, **explained(batch, expect=claims))
    assert sealed[0][: len(newton_only)] == newton_only
    assert sealed[0][len(newton_only):] == [list(p) for p in newton_only[:3]]


def test_claims_count_toward_the_probe_cap_and_are_never_dropped_to_fit(env):
    tmp, calls, sealed, _ = env
    result = plan_call(probes=[["fail"]] * 30, **explained(BATCH, expect=[C_UCI, C_UCI2, C_PROBE]))
    assert "error" in result
    assert "claim" in result["error"].lower()
    assert calls == []
    assert not (tmp / "state" / "plans").exists() or not list((tmp / "state" / "plans").glob("*.json"))


def test_tier_plans_also_seal_the_claims(env, monkeypatch):
    """plan_tier goes through the same plan path, so its claims are sealed too."""
    from exhelp import tier_explained

    values = {"fw_wan_zone": "wan", "fw_allow_ping": "Allow-Ping"}
    monkeypatch.setattr(
        server.NewtonService, "read",
        lambda self, d, c: {"exit_code": 1, "stdout": "", "stderr": "", "truncated": False},
    )
    kw = tier_explained("hardened", 0, values)
    kw["explanation"] = dict(kw["explanation"], expect=[C_UCI])
    result = server.newton_plan_tier("lab1", "hardened", 0, values, **kw)
    assert "error" not in result, result
    assert env[2][0][-1] == ["uci-equals", "dhcp.skilltest.name", "skilltest"]


# ---- apply: true confirms, false rolls back and names the claim -----------------------


def test_true_claim_confirms_and_result_has_no_failed_claim(env):
    tmp, calls, sealed, apply_out = env
    assert "error" not in plan_call(**explained(BATCH, expect=[C_UCI]))
    result = server.newton_apply_change("lab1", SID)
    assert result["result"] == "confirmed"
    assert "failed_claim" not in result


def test_false_claim_rolls_back_and_the_result_names_the_claim(env):
    tmp, calls, sealed, apply_out = env
    assert "error" not in plan_call(probes=[["fail"]], **explained(BATCH, expect=[C_UCI, C_UCI2]))
    apply_out.update(rc=1, stdout=rollback_stdout(3, "uci-equals", "mismatch"))
    result = server.newton_apply_change("lab1", SID)
    assert result["result"] == "rolled_back"
    assert result["failed_claim"] == {
        "claim": 2,
        "text": "expect claim 2 failed: uci firewall.fwd_8443.dest_port != 8443 (mismatch)",
    }


def test_rollback_from_a_newton_probe_names_no_claim(env):
    tmp, calls, sealed, apply_out = env
    assert "error" not in plan_call(probes=[["fail"]], **explained(BATCH, expect=[C_UCI]))
    apply_out.update(rc=1, stdout=rollback_stdout(1, "fail", "failed"))
    result = server.newton_apply_change("lab1", SID)
    assert result["result"] == "rolled_back"
    assert "failed_claim" not in result


def test_apply_refuses_a_record_whose_probes_lack_the_claims_even_with_a_matching_hash(env):
    tmp, calls, sealed, apply_out = env
    assert "error" not in plan_call(**explained(BATCH, expect=[C_UCI, C_PROBE]))
    record = stored(tmp)
    record["probes"] = []  # a self-consistent record that sealed none of the claims
    record["plan_hash"] = compute_plan_hash(record)
    (tmp / "state" / "plans" / f"{SID}.json").write_text(json.dumps(record))
    calls.clear()
    result = server.newton_apply_change("lab1", SID)
    assert "claim" in result["error"].lower()
    assert calls == []


# ---- r1: B1 every reason the router emits, N1 the router's own line, N3 wording ------------

ROUTER_SOURCE = Path(__file__).resolve().parents[2] / "device/openwrt/newton-router/newton-router"


def router_reasons() -> set[str]:
    """Every PB_REASON the router program can set, one concrete instance each.

    Read from the router source so a new reason there fails here until the host
    accepts it.  Templated reasons get a concrete instance.
    """
    raw = re.findall(r"""PB_REASON=("[^"]*"|'[^']*'|[^\s;}]*)""", ROUTER_SOURCE.read_text())
    found = {r.strip("\"'") for r in raw} - {""}
    concrete = {
        "count=$2": "count=2",
        "class=$cls": "class=LOCKED",
        "bad-arg-$i": "bad-arg-3",
    }
    return {concrete.get(r, r) for r in found}


def log_with(sid: str, header: str, stderr: list[str], stdout: list[str] = ()) -> str:
    lines = [f"APPLYING session={sid}", f"VERIFY FAILED session={sid} - not confirming; waiting for automatic rollback", header]
    lines += [f"VERIFY STDERR session={sid}: {s}" for s in stderr]
    lines += [f"VERIFY STDOUT session={sid}: {s}" for s in stdout]
    lines.append(f"ROLLBACK WINDOW PASSED session={sid} rolled back by the guard")
    return "\n".join(lines) + "\n"


def round_header(sid: str = SID, exit_code: int = 1, stage: str = "router-verify") -> str:
    return f"VERIFY DETAIL session={sid} round=3 exit={exit_code} stage={stage} (last failed round; stderr and stdout follow, each last 20 lines, at most 2 KB)"


def test_every_reason_the_router_emits_attributes_the_claim():
    reasons = router_reasons()
    assert {"count=2", "mismatch", "unset", "timeout", "absent", "present", "error", "budget"} <= reasons
    expl = ex.parse_explanation(make_explanation(BATCH, expect=[C_UCI]), change_lines=2)
    probes = ex.claim_probes(expl)
    for reason in sorted(reasons):
        out = ex.failed_claim(rollback_stdout(1, "uci-equals", reason), SID, probes, expl["expect"])
        assert out is not None and out["claim"] == 1, reason
        assert f"({reason})" in out["text"], (reason, out)


@pytest.mark.parametrize(
    "reason",
    ["count=", "count=x", "count=1234567", "count=-1", "class=lower", "class=LOCKED2", "bad-arg-", "bad-arg-123",
     "Mismatch", "mis match", "mismatch2", "x" * 40, "count=1 count=2", "ok", "failed"],
)
def test_a_reason_outside_the_routers_grammar_names_no_claim(reason):
    expl = ex.parse_explanation(make_explanation(BATCH, expect=[C_UCI]), change_lines=2)
    probes = ex.claim_probes(expl)
    assert ex.failed_claim(rollback_stdout(1, "uci-equals", reason), SID, probes, expl["expect"]) is None


def test_only_the_last_stderr_line_of_the_failed_round_block_counts():
    expl = ex.parse_explanation(make_explanation(BATCH, expect=[C_UCI]), change_lines=2)
    probes, expect = ex.claim_probes(expl), expl["expect"]
    forged = "verify: probe 1 failed: uci-equals mismatch"
    real = "verify: probe 1 failed: uci-equals unset"
    # device text earlier in the same stderr (an ssh banner, an echo) is not the verdict
    assert ex.failed_claim(log_with(SID, round_header(), [forged, "Connection closed"]), SID, probes, expect) is None
    # the router's own line is last: attributed from it, even after a forged one
    got = ex.failed_claim(log_with(SID, round_header(), [forged, "banner", real]), SID, probes, expect)
    assert got is not None and "(unset)" in got["text"]
    # a forged line in the stdout half, in the firewall-restart excerpt, after a local-check failure,
    # or under a round that did not exit 1 is not a verify-probe verdict
    assert ex.failed_claim(log_with(SID, round_header(), ["x"], [forged]), SID, probes, expect) is None
    fw = f"VERIFY DETAIL session={SID} firewall restart exit=1 (the change cannot be made live; its output follows, last 20 lines, at most 2 KB)"
    assert ex.failed_claim(log_with(SID, fw, [forged]), SID, probes, expect) is None
    assert ex.failed_claim(log_with(SID, round_header(stage="local-check"), ["local check exited 1", forged]), SID, probes, expect) is None
    assert ex.failed_claim(log_with(SID, round_header(stage="logd"), [forged]), SID, probes, expect) is None
    # a header without a stage word (the old shape) is not trusted either
    old = round_header().replace(" stage=router-verify", "")
    assert ex.failed_claim(log_with(SID, old, [forged]), SID, probes, expect) is None
    # no failed-round header at all
    bare = f"VERIFY STDERR session={SID}: {forged}\n"
    assert ex.failed_claim(bare, SID, probes, expect) is None
    # a header for another session
    other = "f" * 32
    assert ex.failed_claim(log_with(other, round_header(other), [forged]), SID, probes, expect) is None


def test_describe_claim_follows_the_reason():
    uci = C_UCI2
    path = "firewall.fwd_8443.dest_port"
    assert ex.describe_failed_claim(uci, "mismatch") == f"uci {path} != 8443"
    assert ex.describe_failed_claim(uci, "unset") == f"uci {path} is unset (claimed 8443)"
    assert "timed out" in ex.describe_failed_claim(uci, "timeout")
    assert "!=" not in ex.describe_failed_claim(uci, "timeout")
    assert "!=" not in ex.describe_failed_claim(uci, "error")
    assert "time budget" in ex.describe_failed_claim(uci, "budget")
    assert ex.describe_failed_claim(C_PROBE, "present") == "probe iface-absent guestx: found present, not as claimed"
    assert ex.describe_failed_claim(C_PROBE, "count=2") == "probe iface-absent guestx: matched 2 times, not as claimed"
    assert ex.describe_failed_claim(C_PROBE, "count=1") == "probe iface-absent guestx: matched 1 time, not as claimed"
    assert ex.describe_failed_claim(C_PROBE, "timeout").endswith("timed out")


def test_a_count_reason_failure_names_the_claim_in_the_apply_result(env):
    tmp, calls, sealed, apply_out = env
    nft = {"kind": "probe", "probe": ["nft-rule", "inet", "fw4", "input", "present", "jump syn_flood"]}
    assert "error" not in plan_call(**explained(BATCH, expect=[nft]))
    apply_out.update(rc=1, stdout=rollback_stdout(1, "nft-rule", "count=0"))
    result = server.newton_apply_change("lab1", SID)
    assert result["result"] == "rolled_back"
    assert result["failed_claim"]["claim"] == 1
    assert "matched 0 times" in result["failed_claim"]["text"]


def test_every_tier_batch_plans_with_the_most_claims_of_the_longest_length(env, monkeypatch):
    """B2: no tier batch may be refused for room once the explanation has MAX_CLAIMS claims."""
    from exhelp import tier_explained
    from newton_mcp import tiers

    monkeypatch.setattr(
        server.NewtonService, "read",
        lambda self, d, c: {"exit_code": 1, "stdout": "", "stderr": "", "truncated": False},
    )
    values = {"fw_wan_zone": "wan", "fw_allow_ping": "Allow-Ping"}
    longest = [
        {"kind": "uci_equals", "path": f"{'c' * 32}.{'s' * 64}.{'o' * 30}", "equals": "v" * 120 + f"{i:08d}"}
        for i in range(ex.MAX_CLAIMS)
    ]
    assert len({c["path"] + c["equals"] for c in longest}) == ex.MAX_CLAIMS
    assert [len("\t".join(["uci-equals", c["path"], c["equals"]])) for c in longest] == [
        10 + 128 + 128 + 2
    ] * ex.MAX_CLAIMS
    for tier in tiers.TIER_NAMES:
        count = len(tiers.split_tier(tier)["batches"])
        for index in range(count):
            names = {n for b in tiers.split_tier(tier)["batches"] for n in b["placeholders"]}
            tier_values = {k: v for k, v in values.items() if k in names}
            kw = tier_explained(tier, index, tier_values)
            kw["explanation"] = dict(kw["explanation"], expect=longest)
            result = server.newton_plan_tier("lab1", tier, index, tier_values, **kw)
            assert "error" not in result, (tier, index, result)
            assert len(env[2][-1]) <= 32 and sum(len("\t".join(p)) + 1 for p in env[2][-1]) <= 4096
            assert env[2][-1][-ex.MAX_CLAIMS:] == [["uci-equals", c["path"], c["equals"]] for c in longest]


def test_tier_batch_counts_with_room_for_the_claims():
    from newton_mcp import tiers

    counts = {t: len(tiers.split_tier(t)["batches"]) for t in tiers.TIER_NAMES}
    assert counts == {"standard": 1, "hardened": 2, "lockdown": 2}


# ---- newton-approve shows them -----------------------------------------------------------


def test_newton_approve_says_the_claims_will_be_checked_after_apply(tmp_path, monkeypatch, capsys):
    from test_approve_explanation import record, run

    _, out, _ = run(tmp_path, monkeypatch, capsys, record())
    note = next(r for r in out.splitlines() if "will be checked after apply" in r)
    assert not note.lstrip().startswith("|")  # Newton's own line, not agent text
    assert "rolls" in note
    assert out.index(note) < out.index("Expected after apply:")
    assert out.index("Agent's explanation (unchecked claims)") < out.index(note)


# ---- the vendor claims join the same sealed probe list ---------------------

VENDOR = "vyos"
V_LINE = "set interfaces ethernet eth0 mtu 1500"
C_CONFIG = {"kind": "config_has", "line": V_LINE}
C_PING = {"kind": "ping", "host": "192.0.2.10"}


def vendor_expl(expect):
    return ex.parse_explanation(
        make_explanation(BATCH, expect=expect), change_lines=2, platform=VENDOR
    )


def test_the_vendor_claims_keep_their_order():
    expl = vendor_expl([C_PING, C_CONFIG])
    assert ex.claim_probes(expl) == [
        ["ping", "192.0.2.10"],
        ["config_has", V_LINE],
    ]


def test_the_vendor_claims_match_the_sealed_probes():
    expl = vendor_expl([C_CONFIG, C_PING])
    probes = ex.claim_probes(expl)
    assert ex.claims_match_probes(probes, expl) is True
    assert ex.claims_match_probes([["fail"]] + probes, expl) is True
    assert ex.claims_match_probes(probes[:1], expl) is False
    assert ex.claims_match_probes([["config_has", "set something else"]] + probes[1:], expl) is False


def test_the_vendor_probes_are_the_shape_the_driver_runs():
    """The claim's probe line is what the vendor driver runs after apply."""
    from newton_mcp import vendor_change

    expl = vendor_expl([C_CONFIG, C_PING])
    probes = ex.claim_probes(expl)
    assert vendor_change._effective_probes({"probes": []}, probes) == probes
