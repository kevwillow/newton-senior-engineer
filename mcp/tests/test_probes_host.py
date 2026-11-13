"""Host-only probe behaviour (no router counterpart) and the manifest
checks of design 4.8: the secret-option refusal, the probe file, the
whole-set limits, and the manifest expansion through a temp manifest with
made-up controls.  Plus the plan/apply plumbing this round adds."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import tempfile
import time
import tracemalloc

import pytest

from exhelp import explained, record_fields, record_fields_display

import newton_mcp.probes as probes
import newton_mcp.server as server
from newton_mcp.plan import compute_plan_hash
from newton_mcp.server import NewtonError


SID = "0123456789abcdef0123456789abcdef"
BASE_HASH = "b" * 64
DIGEST = "d" * 64
PROBES_SHA = "a" * 64


@pytest.fixture
def configured(tmp_path, monkeypatch):
    inventory = tmp_path / "devices.toml"
    inventory.write_text(
        '[devices.quasar]\nplatform = "openwrt"\nhost = "192.0.2.1"\nuser = "root"\n'
    )
    monkeypatch.setenv("NEWTON_INVENTORY", str(inventory))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))
    return tmp_path


@pytest.fixture
def configured_lab(configured, monkeypatch):
    monkeypatch.setenv(
        "NEWTON_INVENTORY",
        str(
            configured / "devices.toml"
        ),
    )
    (configured / "devices.toml").write_text(
        '[devices.quasar]\nplatform = "openwrt"\nhost = "192.0.2.1"\nuser = "root"\nprofile = "lab"\nlab = true\n'
    )
    return configured


def plan_output(*, approval="not-required", diff="dhcp.skilltest='host'"):
    return (
        "BACKUP /tmp/fake.tar.gz (2 config files)\n"
        f"STAGED session={SID}\n"
        f"BASEHASH {BASE_HASH}\n"
        f"PROBES 1 {PROBES_SHA}\n"
        "PROFILE lab\n"
        "SECTION dhcp cfg01 dnsmasq dnsmasq\n"
        "LEASH wan-rule firewall.wan_rule\n"
        f"APPROVAL {approval}\n"
        f"PLANDIGEST {DIGEST}\n"
        "----- diff -----\n"
        f"{diff}\n"
        "----------------\n"
    )


# ---- the host-only secret-option refusal -------------------------------------


@pytest.mark.parametrize("fields", [
    ["uci-equals", "wireless.ap.key", "hunter2"],
    ["uci-equals", "system.x.root_password", "x"],
    ["uci-equals", "rpcd.@login[0].password", "x"],
    ["uci-equals", "network.wg0.private_key", "x"],
    ["uci-equals", "dhcp.cfg.peap_pass", "x"],
])
def test_uci_equals_on_a_secret_option_is_refused(fields):
    with pytest.raises(NewtonError, match=r"probe 1: secret-option"):
        probes.validate_probes([fields])


def test_uci_unset_on_a_secret_option_is_refused_but_plain_path_is_not():
    with pytest.raises(NewtonError, match=r"probe 1: secret-option"):
        probes.validate_probes([["uci-unset", "wireless.ap.key"]])
    # no option part: nothing the agent could read as an oracle
    assert probes.validate_probes([["uci-unset", "wireless.lan"]]) == [["uci-unset", "wireless.lan"]]
    # a non-secret option is fine
    assert probes.validate_probes([["uci-equals", "wireless.ap.mode", "ap"]])


def test_secret_option_refusal_names_the_probe_number():
    with pytest.raises(NewtonError) as excinfo:
        probes.validate_probes([["fail"], ["uci-equals", "wireless.ap.key", "x"]])
    assert str(excinfo.value) == "probe 2: secret-option"


# ---- the probe file -----------------------------------------------------------


def test_probe_file_bytes_join_fields_with_one_tab_and_end_lines_with_lf():
    data = probes.probe_file_bytes([["fail"], ["ping", "192.0.2.1", "3"]])
    assert data == b"fail\nping\t192.0.2.1\t3\n"


def test_probe_file_bytes_of_an_empty_probe_list_is_empty():
    assert probes.probe_file_bytes([]) == b""


def test_write_probe_file_is_mode_0600_and_round_trips():
    lines = [["fail"], ["log-has", "present", "x"]]
    path = probes.write_probe_file(lines)
    try:
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
        with open(path, "rb") as stream:
            assert stream.read() == probes.probe_file_bytes(lines)
    finally:
        os.unlink(path)


def test_plan_deletes_both_temp_files_when_the_script_fails(configured_lab, monkeypatch, tmp_path):
    scratch = tmp_path / "scratch"  # tmp_path also holds the fixture's own files
    scratch.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(scratch))
    during = []

    def fake_run(self, device, *args, **kwargs):
        during.append(set(os.listdir(scratch)))
        return subprocess.CompletedProcess(list(args), 1, "ERROR: made-up failure", "")

    monkeypatch.setattr(server.NewtonService, "run_script", fake_run)
    result = server.newton_plan_change(
        "quasar", "set dhcp.skilltest=host", probes=[["fail"]], timeout_s=60, **explained("set dhcp.skilltest=host"),
    )
    assert "error" in result
    # both temp files existed while the script ran, so the empty dir below proves cleanup
    assert during, "run_script was never called"
    assert any(n.startswith("newton-uci-") for n in during[0])
    assert any(n.startswith("newton-probes-") for n in during[0])
    assert os.listdir(scratch) == []


# ---- the whole-set limits (design 3.6) ----------------------------------------


def test_thirty_two_lines_are_accepted():
    assert len(probes.validate_probes([["fail"]] * 32)) == 32


def test_the_4096_byte_limit_is_enforced_with_the_router_line_number():
    def line(total):
        return ["uci-equals", "network.lan.proto", "x" * (total - 29)]

    assert probes.validate_probes([line(128)] * 31 + [line(96)])[-1] == line(96)
    # one byte more anywhere crosses 4096 total bytes on line 32
    with pytest.raises(NewtonError) as excinfo:
        probes.validate_probes([line(128)] * 31 + [line(97)])
    assert str(excinfo.value) == "probe 32: too-long"
    with pytest.raises(NewtonError) as excinfo:
        probes.validate_probes([["fail"]] * 33)
    assert str(excinfo.value) == "probe 33: too-many"


def test_probes_must_be_a_list_of_lists_of_strings():
    for bad in ("fail", [["fail"], "ping"], [["fail"], [1]], 7, {"a": 1}):
        with pytest.raises(NewtonError):
            probes.validate_probes(bad)


# ---- the manifest checks (design 4.8) -----------------------------------------


def _manifest(tmp_path, text):
    path = tmp_path / "manifest.toml"
    path.write_text(text)
    return path


MANIFEST_OK = """
[[control]]
id = 'MADE-UP-01'
tier = 'standard'
check_host = 'router'
probes = [["fail"], ["log-has", "present", "made-up-marker"]]

[[control]]
id = 'MADE-UP-02'
tier = 'standard'
check_host = ''
probes = [["ping", "192.0.2.1"]]
"""


def test_manifest_ids_expand_before_the_callers_probes(tmp_path, monkeypatch):
    monkeypatch.setenv("NEWTON_MANIFEST", str(_manifest(tmp_path, MANIFEST_OK)))
    expanded = probes.expand_manifest_checks(["MADE-UP-01", "MADE-UP-02"])
    assert expanded == [["fail"], ["log-has", "present", "made-up-marker"], ["ping", "192.0.2.1"]]
    assert probes.expand_manifest_checks([]) == []


def test_manifest_without_probes_key_is_refused_with_the_host_reason(tmp_path, monkeypatch):
    monkeypatch.setenv(
        "NEWTON_MANIFEST",
        str(_manifest(tmp_path, "[[control]]\nid = 'MADE-UP-03'\ncheck_host = 'lab'\n")),
    )
    with pytest.raises(NewtonError) as excinfo:
        probes.expand_manifest_checks(["MADE-UP-03"])
    message = str(excinfo.value)
    assert "MADE-UP-03" in message
    assert "no probe form yet" in message
    assert "check_host lab" in message


def test_unknown_manifest_id_is_refused(tmp_path, monkeypatch):
    monkeypatch.setenv("NEWTON_MANIFEST", str(_manifest(tmp_path, MANIFEST_OK)))
    with pytest.raises(NewtonError, match="unknown manifest check id: MADE-UP-99"):
        probes.expand_manifest_checks(["MADE-UP-99"])


def test_missing_manifest_is_refused(tmp_path, monkeypatch):
    monkeypatch.setenv("NEWTON_MANIFEST", str(tmp_path / "gone.toml"))
    with pytest.raises(NewtonError, match="manifest not found"):
        probes.expand_manifest_checks(["MADE-UP-01"])


def test_the_same_id_twice_is_refused(tmp_path, monkeypatch):
    monkeypatch.setenv("NEWTON_MANIFEST", str(_manifest(tmp_path, MANIFEST_OK)))
    with pytest.raises(NewtonError, match="given twice"):
        probes.expand_manifest_checks(["MADE-UP-01", "MADE-UP-01"])


@pytest.mark.parametrize("bad_id", ["", "bad id", "bad/id", "x" * 65, 5, None])
def test_a_bad_id_shape_is_refused_before_anything_else(tmp_path, monkeypatch, bad_id):
    monkeypatch.setenv("NEWTON_MANIFEST", str(_manifest(tmp_path, MANIFEST_OK)))
    with pytest.raises(NewtonError, match="invalid manifest check id"):
        probes.expand_manifest_checks([bad_id])


def test_every_id_in_the_real_manifest_is_refused_today(tmp_path, monkeypatch):
    # ADR-010: a control that has been converted (``probes`` key) expands
    # directly.  The remaining unconverted ids of the real manifest are
    # still refused with the clear "no probe form yet" error; this test
    # now skips the converted ids so it keeps pinning the refusal shape.
    monkeypatch.delenv("NEWTON_MANIFEST", raising=False)
    unconverted_ids = []
    import tomllib

    real = probes.manifest_path()
    if not real.is_file():
        pytest.skip("real manifest not present")
    seen: set[str] = set()
    for control in tomllib.loads(real.read_text())["control"]:
        if "probes" in control or control["id"] in seen:
            continue
        seen.add(control["id"])
        unconverted_ids.append(control["id"])
    assert unconverted_ids
    for control_id in unconverted_ids[:3]:
        with pytest.raises(NewtonError, match="no probe form yet|more than one control"):
            probes.expand_manifest_checks([control_id])


def test_duplicate_id_across_manifest_entries_is_refused(tmp_path, monkeypatch):
    monkeypatch.setenv(
        "NEWTON_MANIFEST",
        str(_manifest(tmp_path, MANIFEST_OK + MANIFEST_OK.replace("MADE-UP-01", "MADE-UP-04"))),
    )
    with pytest.raises(NewtonError, match="more than one control"):
        probes.expand_manifest_checks(["MADE-UP-02"])


# ---- plan/apply plumbing this round adds --------------------------------------


def _fake_script(calls, output=None):
    def fake_run(self, device, *args, **kwargs):
        modes = tuple(
            stat.S_IMODE(os.stat(part).st_mode) for part in args if isinstance(part, str) and part.startswith("/tmp/newton-")
        )
        calls.append((args, kwargs, modes))
        return subprocess.CompletedProcess(list(args), 0, output or plan_output(), "")
    return fake_run


def test_plan_runs_the_probes_file_and_stores_the_record_fields(configured_lab, monkeypatch):
    calls = []
    monkeypatch.setattr(server.NewtonService, "run_script", _fake_script(calls))
    result = server.newton_plan_change(
        "quasar", "set dhcp.skilltest=host", timeout_s=120, probes=[["fail"]], **explained("set dhcp.skilltest=host"),
    )
    args = calls[0][0]
    assert args[0] == "plan"
    assert args[1] == "root@192.0.2.1"
    assert args[3] == "120"
    assert os.path.basename(args[4]).startswith("newton-probes-")
    assert not os.path.exists(args[4])
    assert calls[0][2] == (0o600, 0o600)
    record = json.loads(
        (configured_lab / "state" / "plans" / f"{SID}.json").read_text()
    )
    assert record["probes"] == [["fail"], ["iface-absent", "guestx"]]
    assert record["manifest_checks"] == []
    assert record["router_digest"] == DIGEST
    assert record["router_profile"] == "lab"
    assert record["router_leash"] == ["wan-rule firewall.wan_rule"]
    assert record["router_requires_approval"] is False
    assert result["router_requires_approval"] is False


def test_manifest_probes_come_before_the_callers_probes(configured_lab, tmp_path, monkeypatch):
    monkeypatch.setenv("NEWTON_MANIFEST", str(_manifest(tmp_path, MANIFEST_OK)))
    calls = []
    monkeypatch.setattr(
        server.NewtonService, "run_script", _fake_script(calls)
    )
    server.newton_plan_change(
        "quasar", "set dhcp.skilltest=host", probes=[["ping", "192.0.2.9"]],
        manifest_checks=["MADE-UP-01"], **explained("set dhcp.skilltest=host"),
    )
    record = json.loads(
        (configured_lab / "state" / "plans" / f"{SID}.json").read_text()
    )
    assert record["probes"] == [["fail"], ["log-has", "present", "made-up-marker"], ["ping", "192.0.2.9"], ["iface-absent", "guestx"]]
    assert record["manifest_checks"] == ["MADE-UP-01"]


def test_router_approval_forces_approval_even_when_the_host_policy_does_not(
    configured_lab, monkeypatch
):
    calls = []
    monkeypatch.setattr(
        server.NewtonService, "run_script", _fake_script(calls, plan_output(approval="required"))
    )
    planned = server.newton_plan_change("quasar", "set dhcp.skilltest=host", **explained("set dhcp.skilltest=host"))
    assert planned["requires_approval"] is True
    assert planned["router_requires_approval"] is True
    assert planned["approval_reasons"] == []
    record = json.loads(
        (configured_lab / "state" / "plans" / f"{SID}.json").read_text()
    )
    assert record["requires_approval"] is True
    assert record["router_requires_approval"] is True


@pytest.mark.parametrize("mangle", [
    lambda out: out.replace(f"PLANDIGEST {DIGEST}\n", ""),
    lambda out: out.replace(f"PLANDIGEST {DIGEST}", "PLANDIGEST nothex"),
    lambda out: out.replace("APPROVAL not-required", "APPROVAL maybe"),
    lambda out: out.replace("APPROVAL not-required\n", ""),
    lambda out: out.replace(f"PROBES 1 {PROBES_SHA}\n", ""),
    lambda out: out.replace(f"PROBES 1 {PROBES_SHA}", "PROBES x y"),
    lambda out: out.replace("PROFILE lab\n", ""),
    lambda out: out.replace("PROFILE lab", "PROFILE staging"),
    lambda out: out.replace(f"BASEHASH {BASE_HASH}\n", ""),
])
def test_a_missing_or_malformed_plan_line_is_an_error_not_a_guess(
    configured_lab, monkeypatch, mangle
):
    monkeypatch.setattr(
        server.NewtonService, "run_script", _fake_script([], mangle(plan_output()))
    )
    result = server.newton_plan_change("quasar", "set dhcp.skilltest=host", **explained("set dhcp.skilltest=host"))
    assert set(result) == {"error"}
    assert not any((configured_lab / "state" / "plans").glob("*.json"))


def test_diff_text_cannot_forge_the_router_fact_lines(configured_lab, monkeypatch):
    out = plan_output(diff="dhcp.x='y'\ndhcp.z='LEASH wan-rule forged'\ndhcp.w='APPROVAL required'")
    monkeypatch.setattr(server.NewtonService, "run_script", _fake_script([], out))
    planned = server.newton_plan_change("quasar", "set dhcp.skilltest=host", **explained("set dhcp.skilltest=host"))
    assert planned["requires_approval"] is False
    record = json.loads(
        (configured_lab / "state" / "plans" / f"{SID}.json").read_text()
    )
    assert record["router_leash"] == ["wan-rule firewall.wan_rule"]
    assert record["router_requires_approval"] is False


def _record(**updates):
    record = {
        "device": "quasar",
        "host": "192.0.2.1",
        "session_id": SID,
        "uci_batch": "set dhcp.skilltest=host",
        "diff": "dhcp.skilltest='host'",
        "probes": [["fail"], ["iface-absent", "guestx"]],
        "timeout_s": 90,
        "base_hash": BASE_HASH,
        "requires_approval": False,
        "router_digest": DIGEST,
        **record_fields("set dhcp.skilltest=host"),
        **record_fields_display(),
        "created_at": "2026-10-07T12:00:00+00:00",
        "staged_at": "2026-10-07T12:00:00+00:00",
    }
    record.update(updates)
    record["plan_hash"] = compute_plan_hash(record)
    return record


def test_plan_hash_changes_with_probes_and_router_digest():
    base = compute_plan_hash(_record())
    assert compute_plan_hash(_record(probes=[["fail"], ["fail"]])) != base
    assert compute_plan_hash(_record(router_digest="e" * 64)) != base
    assert compute_plan_hash(_record()) == base


def test_apply_passes_the_token_and_uses_timeout_plus_300(configured, monkeypatch):
    state = configured / "state" / "plans"
    state.mkdir(parents=True)
    record = _record(requires_approval=True)
    (state / f"{SID}.json").write_text(json.dumps(record))
    approvals = state.parent / "approvals"
    approvals.mkdir()
    token = "f" * 64
    (approvals / f"{SID}.json").write_text(json.dumps({
        "plan_id": SID,
        "plan_hash": record["plan_hash"],
        "device": "quasar",
        "base_hash": BASE_HASH,
        "approved_by": "operator",
        "created_at": "2099-01-01T00:00:00+00:00",
        "expires_at": "2099-01-01T00:30:00+00:00",
        "not_before": 4070908800,
        "not_after": 4070910600,
        "token": token,
    }))
    calls = []
    monkeypatch.setattr(
        server.NewtonService, "run_script",
        _fake_script(calls, f"CONFIRMED session={SID}"),
    )
    assert server.newton_apply_change("quasar", SID)["result"] == "confirmed"
    args, kwargs, _ = calls[0]
    assert args == ("apply", "root@192.0.2.1", SID, "90")
    assert kwargs["timeout"] == 390
    # SW2 Item 2: the window the v2 token binds travels with the token
    assert kwargs["extra_env"] == {
        "OWRT_EXPECT_BASE": BASE_HASH,
        "OWRT_APPROVAL_TOKEN": token,
        "OWRT_APPROVAL_NBF": "4070908800",
        "OWRT_APPROVAL_EXP": "4070910600",
    }


def test_apply_without_required_approval_passes_token_none(configured_lab, monkeypatch):
    state = configured_lab / "state" / "plans"
    state.mkdir(parents=True)
    record = _record()
    (state / f"{SID}.json").write_text(json.dumps(record))
    calls = []
    monkeypatch.setattr(
        server.NewtonService, "run_script",
        _fake_script(calls, f"CONFIRMED session={SID}"),
    )
    assert server.newton_apply_change("quasar", SID)["result"] == "confirmed"
    assert calls[0][1]["extra_env"]["OWRT_APPROVAL_TOKEN"] == "none"


@pytest.mark.parametrize("token", [None, "nothex", "F" * 64, "f" * 63, 5])
def test_a_required_approval_with_a_bad_token_is_refused_not_silently_none(
    configured, monkeypatch, token
):
    state = configured / "state" / "plans"
    state.mkdir(parents=True)
    record = _record(requires_approval=True)
    (state / f"{SID}.json").write_text(json.dumps(record))
    approvals = state.parent / "approvals"
    approvals.mkdir()
    (approvals / f"{SID}.json").write_text(json.dumps({
        "plan_id": SID,
        "plan_hash": record["plan_hash"],
        "device": "quasar",
        "base_hash": BASE_HASH,
        "approved_by": "operator",
        "created_at": "2099-01-01T00:00:00+00:00",
        "expires_at": "2099-01-01T00:30:00+00:00",
        "not_before": 4070908800,
        "not_after": 4070910600,
        "token": token,
    }))
    monkeypatch.setattr(
        server.NewtonService, "run_script",
        lambda *a, **k: pytest.fail("a bad token must never reach the script"),
    )
    result = server.newton_apply_change("quasar", SID)
    assert "approval record is invalid; ask the user to approve the plan again" in result["error"]
    # the broken approval is NOT consumed
    assert (approvals / f"{SID}.json").exists()
    assert not (approvals / f"{SID}.used").exists()


def test_an_old_check_record_cannot_apply(configured, monkeypatch):
    state = configured / "state" / "plans"
    state.mkdir(parents=True)
    record = _record()
    del record["probes"]
    del record["router_digest"]
    record["plan_hash"] = compute_plan_hash(
        {**record, "probes": [], "router_digest": DIGEST}
    )
    (state / f"{SID}.json").write_text(json.dumps(record))
    monkeypatch.setattr(
        server.NewtonService, "run_script",
        lambda *a, **k: pytest.fail("must not run"),
    )
    result = server.newton_apply_change("quasar", SID)
    assert "plan record was modified or is invalid" in result["error"]


# ---- still no probe surface anywhere -------------------------------------------


def test_newton_read_has_no_probe_verb():
    with pytest.raises(server.NewtonError):
        server.validate_read("probe ping 192.0.2.1")


def test_no_tool_is_named_probe_or_takes_a_check():
    assert "probe" not in server.TOOL_NAMES
    assert "newton_probe" not in server.TOOL_NAMES
    assert len(server.TOOL_NAMES) == 23


# ---- R2 review: bounded input, iterative _spec_ok, manifest cap ---------------


def test_validate_probes_refuses_one_million_entries_fast_and_under_5mb():
    """The list-length cap fires before any copy or per-element inspection,
    so a 1M-entry list is refused in well under a second and never allocates
    the 100MB the old implementation could."""
    huge = [["fail"]] * 1_000_000
    tracemalloc.start()
    started = time.monotonic()
    try:
        with pytest.raises(NewtonError, match=r"probe 33: too-many"):
            probes.validate_probes(huge)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        elapsed = time.monotonic() - started
        tracemalloc.stop()
    assert elapsed < 1.0, f"refusal took {elapsed:.2f}s, expected < 1s"
    assert peak < 5_000_000, f"tracemalloc peak was {peak} bytes, expected < 5MB"


def test_validate_probes_refuses_a_10mb_field_under_5mb():
    """A single 10MB field fails the per-field cap before the joined line is
    ever built, so no 100MB allocation occurs."""
    huge_field = ["x" * 10_000_000]
    tracemalloc.start()
    try:
        with pytest.raises(NewtonError, match=r"probe 1: too-long"):
            probes.validate_probes([huge_field])
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 5_000_000, f"tracemalloc peak was {peak} bytes, expected < 5MB"


def test_spec_ok_is_iterative_and_handles_a_100k_negation_chain():
    """`_spec_ok` must be iterative; the recursive version hit Python's
    recursion limit on a long leading-'!' chain."""
    value = "!" * 100_000 + "foo"
    assert probes._spec_ok(value) is True


def test_spec_ok_rejects_only_bangs_or_too_many_elements_iteratively():
    assert probes._spec_ok("") is False
    assert probes._spec_ok("!") is False
    assert probes._spec_ok("!" * 100_000) is False
    assert probes._spec_ok("a b c d e") is False  # 5 elements > 4
    # double negation still matches a single element
    assert probes._spec_ok("!!foo") is True
    assert probes._spec_ok("~regex") is True
    assert probes._spec_ok("!~regex") is True


def test_manifest_expansion_refuses_a_control_with_more_than_the_cap(tmp_path, monkeypatch):
    """The same cap that bounds validate_probes bounds expand_manifest_checks:
    a single control whose probes list is over the cap refuses fast."""
    manifest_text = (
        "[[control]]\nid = 'MADE-UP-01'\ncheck_host = 'lab'\n"
        "probes = " + repr([["fail"]] * (probes.MAX_PROBE_LINES + 1)) + "\n"
    )
    monkeypatch.setenv("NEWTON_MANIFEST", str(_manifest(tmp_path, manifest_text)))
    with pytest.raises(NewtonError, match="exceeds the " + str(probes.MAX_PROBE_LINES) + "-probe cap"):
        probes.expand_manifest_checks(["MADE-UP-01"])
