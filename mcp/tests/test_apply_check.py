"""The plan input surface after the check -> probes change (round m2):
probes that fail the shared grammar, and the host-only secret-option rule,
are refused before anything is staged or run; valid probes reach the script
as a 0600 probe file whose content is exactly probe_file_bytes."""

from __future__ import annotations

import json
import os
import stat
import subprocess

import pytest

from exhelp import explained

from newton_mcp import server


SID = "0123456789abcdef0123456789abcdef"
BASE_HASH = "b" * 64


def _plan_output():
    return (
        "BACKUP /tmp/fake.tar.gz (2 config files)\n"
        f"STAGED session={SID}\n"
        f"BASEHASH {BASE_HASH}\n"
        f"PROBES 0 {'a' * 64}\n"
        "PROFILE lab\n"
        f"APPROVAL not-required\n"
        f"PLANDIGEST {'d' * 64}\n"
        "----- diff -----\n"
        "dhcp.skilltest='host'\n"
        "dhcp.skilltest.name='skilltest'\n"
        "----------------\n"
    )


@pytest.mark.parametrize(
    "probes,message",
    [
        ([["uci-equals", "network.lan.proto", "1; cat /etc/shadow"]], None),
        ([["fail"], ["no-such-probe", "x"]], "probe 2: unknown-probe"),
        ([["ping", "192.0.2.1", "9"]], "probe 1: bad-arg-2"),
        ([["uci-equals", "network.lan.proto", "x" * 129]], "probe 1: too-long"),
        ([["uci-equals", "network.lan.proto", "bad\\host"]], "probe 1: syntax"),
        ([["uci-unset", "wireless.ap.key"]], "probe 1: secret-option"),
        ([["uci-equals", "wireless.ap.key", "never-display-this"]], "probe 1: secret-option"),
        ([["fail"]] * 33, "probe 33: too-many"),
        ("fail", "probes must be a list of probe field lists"),
    ],
)
def test_refused_plan_probes_never_stage_or_run_script(
    configured_newton, monkeypatch, probes, message
):
    if message is None:
        # a TEXT field may hold any printable bytes: it is matched as a fixed
        # string, never executed, so the grammar accepts it and it stages
        monkeypatch.setattr(
            server.NewtonService,
            "run_script",
            lambda self, device, *a, **k: subprocess.CompletedProcess(a, 0, _plan_output(), ""),
        )
        assert server.newton_plan_change(
            "quasar", "set dhcp.skilltest=host", probes=probes, **explained("set dhcp.skilltest=host"),
        )["session_id"] == SID
        return
    monkeypatch.setattr(
        server.NewtonService, "run_script", lambda *a, **k: pytest.fail("script must not run")
    )
    result = server.newton_plan_change("quasar", "set dhcp.skilltest=host", probes=probes, **explained("set dhcp.skilltest=host"))
    assert message in result["error"], result
    assert "never-display-this" not in result["error"]
    assert not any((configured_newton / "state" / "plans").glob("*.json"))


def test_bad_manifest_checks_never_stage_or_run_script(configured_newton, monkeypatch):
    monkeypatch.setattr(
        server.NewtonService, "run_script", lambda *a, **k: pytest.fail("script must not run")
    )
    for manifest_checks in (["no such id"], ["OW-FW-01", "OW-FW-01"], ["x" * 65]):
        result = server.newton_plan_change(
            "quasar", "set dhcp.skilltest=host", manifest_checks=manifest_checks, **explained("set dhcp.skilltest=host"),
        )
        assert "error" in result
        assert not any((configured_newton / "state" / "plans").glob("*.json"))


def test_valid_probes_reach_the_script_as_a_probe_file(configured_newton, monkeypatch):
    calls = []

    def fake_run(self, device, *args, **kwargs):
        modes = tuple(
            stat.S_IMODE(os.stat(part).st_mode)
            for part in args if isinstance(part, str) and part.startswith("/tmp/newton-")
        )
        with open(args[-1], "rb") as stream:
            calls.append((args, stream.read(), modes))
        return subprocess.CompletedProcess(args, 0, _plan_output(), "")

    monkeypatch.setattr(server.NewtonService, "run_script", fake_run)
    probes = [["fail"], ["log-has", "present", "made-up-marker"]]
    assert server.newton_plan_change(
        "quasar", "set dhcp.skilltest=host", probes=probes, **explained("set dhcp.skilltest=host"),
    )["session_id"] == SID
    args, content, modes = calls[0]
    probe_path = args[-1]
    assert os.path.basename(probe_path).startswith("newton-probes-")
    assert modes == (0o600, 0o600)
    from newton_mcp import probes as probes_mod

    # the caller's probes, then the explanation's claim (the helper's default claim)
    assert content == probes_mod.probe_file_bytes(probes + [["iface-absent", "guestx"]])
    # the caller's probe file is gone once plan returns
    assert not os.path.exists(probe_path)


def test_default_no_probes_reaches_script_with_an_empty_file(configured_newton, monkeypatch):
    calls = []

    def fake_run(self, device, *args, **kwargs):
        calls.append((args, open(args[-1], "rb").read()))
        return subprocess.CompletedProcess(args, 0, _plan_output(), "")

    monkeypatch.setattr(server.NewtonService, "run_script", fake_run)
    assert server.newton_plan_change("quasar", "set dhcp.skilltest=host", **explained("set dhcp.skilltest=host"))["session_id"] == SID
    args, content = calls[0]
    # only the explanation's claim (the helper's default) is sealed
    assert content == b"iface-absent\tguestx\n"
