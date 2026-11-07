"""Seal-time UCI reads fail closed unless the target is exactly missing."""

import json

import pytest

from conftest import SID
from leash_corpus import base_config
from leash_model import Scenario, Sec


SID2 = "fedcba9876543210fedcba9876543210"
PARSE_ERROR = "uci: Parse error (EOF with unterminated ') at line 2, byte 24\n"
READS = (
    ("staged-section", "network.lan", "staged"),
    ("committed-section", "network.lan", "committed"),
    ("committed-firewall", "firewall", "committed"),
)


def scenario_for(read_name):
    if read_name == "committed-firewall":
        section = Sec(
            "zone", None, name="iot", network=["iot"], input="REJECT",
            output="ACCEPT", forward="REJECT",
        )
        ops = [("newsec", "firewall", section, "iot")]
    else:
        ops = [("set", "network", "lan", "ipaddr", "192.168.9.1")]
    return Scenario(base_config(), ops, mode="id")


def prepare_scenario(router, scenario, faults, sid=SID):
    real_seal = router.seal
    router.seal = lambda *_args, **_kwargs: None
    try:
        router.sealed_scenario(scenario, sid=sid)
    finally:
        router.seal = real_seal
    control = router.root / "control/uci.json"
    data = json.loads(control.read_text())
    data["show_fail"] = faults
    router.write("control/uci.json", json.dumps(data))


def assert_nothing_sealed(router, sid=SID):
    txn = router.txn(sid)
    for name in (
        "sealed", "t", "base", "diff", "probes", "probes-sha", "profile",
        "leash", "digest",
    ):
        assert not (txn / name).exists(), name


def assert_uci_show_failure(router, read_name, target, scope, rc, stderr):
    router.use_leash_uci()
    fault = {"target": target, "scope": scope, "rc": rc, "stderr": stderr}
    prepare_scenario(router, scenario_for(read_name), [fault])
    result = router.seal(SID, 90)
    assert (result.rc, result.out, result.err) == (
        1, "", "error internal uci-show\n",
    )
    assert_nothing_sealed(router)


@pytest.mark.parametrize("read_name,target,scope", READS, ids=[r[0] for r in READS])
def test_parse_error_fails_closed(router, read_name, target, scope):
    assert_uci_show_failure(router, read_name, target, scope, 1, PARSE_ERROR)


@pytest.mark.parametrize("read_name,target,scope", READS, ids=[r[0] for r in READS])
def test_signal_exit_fails_closed(router, read_name, target, scope):
    assert_uci_show_failure(router, read_name, target, scope, 137, "")


def test_entry_not_found_with_extra_line_fails_closed(router):
    assert_uci_show_failure(
        router,
        "committed-section",
        "network.lan",
        "committed",
        1,
        "uci: Entry not found\nunexpected detail\n",
    )


def test_exact_entry_not_found_preserves_missing_section_result(router):
    router.use_leash_uci()
    scenario = scenario_for("committed-firewall")
    baseline = router.sealed_scenario(scenario)
    assert (baseline.rc, baseline.err) == (0, "")

    fault = {
        "target": "firewall.iot",
        "scope": "committed",
        "rc": 1,
        "stderr": "uci: Entry not found\n",
    }
    prepare_scenario(router, scenario, [fault], sid=SID2)
    result = router.seal(SID2, 90)
    assert (result.rc, result.err) == (baseline.rc, baseline.err)

    def leash_output(output):
        return [
            line for line in output.splitlines()
            if line.startswith(("section ", "leash ", "approval "))
        ]

    assert leash_output(result.out) == leash_output(baseline.out)

