"""Design 4.2: only documented exit codes may supply probe answers."""

import pytest


@pytest.mark.parametrize(
    "probe,args,rc,want",
    [
        pytest.param("uci-equals", ("network.lan.proto", "static"), 1,
                     (1, "probe uci-equals fail unset\n"), id="equals-exit1"),
        pytest.param("uci-equals", ("network.lan.proto", "static"), 2,
                     (1, "probe uci-equals fail error\n"), id="equals-exit2"),
        pytest.param("uci-equals", ("network.lan.proto", "static"), 255,
                     (1, "probe uci-equals fail error\n"), id="equals-exit255"),
        pytest.param("uci-unset", ("network.lan.proto",), 1,
                     (0, "probe uci-unset ok\n"), id="unset-exit1"),
        pytest.param("uci-unset", ("network.lan.proto",), 2,
                     (1, "probe uci-unset fail error\n"), id="unset-exit2"),
        pytest.param("uci-unset", ("network.lan.proto",), 255,
                     (1, "probe uci-unset fail error\n"), id="unset-exit255"),
    ],
)
def test_uci_probe_exit_codes(router, probe, args, rc, want):
    router.set_fake("uci", out="", rc=rc)
    res = router.probe(probe, *args)
    assert (res.rc, res.out, res.err) == (want[0], want[1], "")


@pytest.mark.parametrize(
    "state,rc,out,want",
    [
        pytest.param("absent", 2, "", (1, "probe service-running fail error\n"),
                     id="absent-json-error"),
        pytest.param("present", 2, "", (1, "probe service-running fail error\n"),
                     id="present-json-error"),
        pytest.param("absent", 1, "", (0, "probe service-running ok\n"),
                     id="absent-no-match"),
        pytest.param("present", 1, "", (1, "probe service-running fail absent\n"),
                     id="present-no-match"),
        pytest.param("present", 0, "true\n", (0, "probe service-running ok\n"),
                     id="present-true"),
    ],
)
def test_service_running_jsonfilter_exit_codes(router, state, rc, out, want):
    router.set_fake("ubus", out='{"dropbear":{"instances":{}}}\n', rc=0)
    router.set_fake("jsonfilter", out=out, rc=rc)
    res = router.probe("service-running", "dropbear", "any", state)
    assert (res.rc, res.out, res.err) == (want[0], want[1], "")
