"""field receipts. One local line per getter run; no device output stored."""

from __future__ import annotations

import json
import os
import stat
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

import newton_mcp.server as server
from newton_mcp import receipts
from newton_mcp.adapters.getters import GetterError

from test_get_state import fake_clock_runner, lab, records  # noqa: F401
from test_getters import base_row, load_one

TOKEN = "LEAKTOKEN_91abZZ"

# Writes $NEWTON_FAKE_BODY verbatim; exit code from $NEWTON_FAKE_EXIT.
BODY_SSH = r'''#!/usr/bin/env python3
import os, sys
with open(os.environ["NEWTON_FAKE_RECORD"], "a") as f:
    f.write("{}\n")
sys.stdout.write(os.environ.get("NEWTON_FAKE_BODY", ""))
raise SystemExit(int(os.environ.get("NEWTON_FAKE_EXIT", "0")))
'''


@pytest.fixture
def rig(lab, monkeypatch):  # noqa: F811
    lab["fake"].write_text(BODY_SSH, encoding="utf-8")
    runner, clock = fake_clock_runner(lab)
    monkeypatch.setattr(server, "_ssh_runner", lambda: runner)
    monkeypatch.setattr(server, "_LEARNED_VERSIONS", {})
    monkeypatch.setattr(receipts, "_today", lambda: "2026-10-18")
    monkeypatch.delenv("NEWTON_FIELD_RECEIPTS", raising=False)

    def run(device: str, getter: str, body: str, exit_code: int = 0) -> dict[str, Any]:
        monkeypatch.setenv("NEWTON_FAKE_BODY", body)
        monkeypatch.setenv("NEWTON_FAKE_EXIT", str(exit_code))
        clock[0] += 10.0
        return server.newton_get_state(device=device, getter=getter)

    lab["run"] = run
    lab["file"] = lab["state"] / receipts.RECEIPT_FILE
    return lab


def lines(path: Path) -> list[dict[str, Any]]:
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines()]


def test_one_exact_receipt_per_run(rig) -> None:
    """platform, os, getter, status, shape, date; nothing else."""
    rig["run"]("jx1", "version", "Junos: 23.4R1\nModel: vjunos\n")
    rig["run"]("jx1", "interfaces", f"Synthetic {TOKEN}\n")
    rig["run"]("jx1", "interfaces", "something else entirely\n")
    rig["run"]("jx1", "interfaces", "boom\n", exit_code=1)
    rig["run"]("jx2", "interfaces", f"Synthetic {TOKEN}\n")  # version never asked
    base = {"v": 1, "date": "2026-10-18", "platform": "junos"}
    assert lines(rig["file"]) == [
        {**base, "os": "23.4R1", "getter": "version", "status": "ok", "shape": "matched"},
        {**base, "os": "23.4R1", "getter": "interfaces", "status": "ok", "shape": "matched"},
        {**base, "os": "23.4R1", "getter": "interfaces", "status": "ok", "shape": "mismatch"},
        {**base, "os": "23.4R1", "getter": "interfaces", "status": "device_error", "shape": "not_checked"},
        {**base, "os": "unknown", "getter": "interfaces", "status": "ok", "shape": "matched"},
    ]


def test_file_mode_and_no_device_data(rig) -> None:
    """0600 file, and no output text, device name or address inside."""
    rig["run"]("jx1", "version", f"Junos: 23.4R1\n{TOKEN}\n")
    rig["run"]("jx1", "interfaces", f"Synthetic {TOKEN} jx1 192.0.2.20\n")
    assert stat.S_IMODE(rig["file"].stat().st_mode) == 0o600
    text = "".join(
        p.read_text(encoding="utf-8")
        for p in rig["state"].iterdir()
        if p.name.startswith("field-receipts")
    )
    for forbidden in (TOKEN, "jx1", "192.0.2.20", "vjunos", "Synthetic"):
        assert forbidden not in text
    assert "newton" not in text


HOSTILE = [
    "Junos: 1.0\x1b[31mred",
    "Junos: " + "9" * 500,
    "Junos: 1.0;rm",
    "Junos: $(id)",
    'Junos: 1.0"},{"v":1',
    "Junos: １２.0",
    "Junos: 1.0‮",
    "Junos: ../../etc",
]


@pytest.mark.parametrize("body", HOSTILE)
def test_hostile_version_is_sanitized(rig, body: str) -> None:
    """an unsafe version string never reaches the file; os becomes unknown."""
    rig["run"]("jx1", "version", body + "\n")
    rig["run"]("jx1", "interfaces", "Synthetic\n")
    recs = lines(rig["file"])  # every line is still valid JSON, exactly 2 lines
    assert len(recs) == 2
    assert [r["os"] for r in recs] == ["unknown", "unknown"]
    assert set(recs[0]) == {"v", "date", "platform", "os", "getter", "status", "shape"}


def test_sanitize_version_unit() -> None:
    """bounded length and safe charset, else unknown."""
    assert receipts.sanitize_version("23.4R1") == "23.4R1"
    assert receipts.sanitize_version("17.12.04") == "17.12.04"
    assert receipts.sanitize_version("2026.10.01-0035-rolling") == "2026.10.01-0035-rolling"
    assert receipts.sanitize_version("7.24.5") == "7.24.5"
    assert receipts.sanitize_version("a" * 41) == "unknown"
    assert receipts.sanitize_version("1." + "0" * 38) == "unknown"
    assert receipts.sanitize_version("1." + "0" * 39) == "unknown"
    for bad in ("", "x y", "a\nb", "a\x00", "é", "a;b", "-1", None, 5):
        assert receipts.sanitize_version(bad) == "unknown"


def test_version_learned_from_version_getter_without_extra_call(rig) -> None:
    """no device call is added; unknown until `version` has run."""
    rig["run"]("jx1", "interfaces", "Synthetic\n")
    assert lines(rig["file"])[-1]["os"] == "unknown"
    before = len(records(rig["record"]))
    rig["run"]("jx1", "version", "Junos: 23.4R1\n")
    assert len(records(rig["record"])) == before + 1  # one run, one ssh call
    rig["run"]("jx1", "interfaces", "Synthetic\n")
    assert len(records(rig["record"])) == before + 2
    assert lines(rig["file"])[-1]["os"] == "23.4R1"
    # a version run that no longer parses drops the stale value
    rig["run"]("jx1", "version", "Junos: 1.0;x\n")
    rig["run"]("jx1", "interfaces", "Synthetic\n")
    assert lines(rig["file"])[-1]["os"] == "unknown"


@pytest.mark.parametrize(
    "platform,body,want",
    [
        ("vyos", "Version:          VyOS 2026.10.01-0035-rolling\nBuilt by: x\n", "2026.10.01-0035-rolling"),
        ("junos", "Hostname: x\nJunos: 26.2R1.7\n", "26.2R1.7"),
        ("iosxe", "Cisco IOS XE Software, Version 17.12.04\n", "17.12.04"),
        ("eos", "Software image version: 4.31.2F\n", "4.31.2F"),
        ("fortios", "Version: FortiGate-VM64 v7.4.3,build2573,240101 (GA.F)\n", "7.4.3"),
        ("routeros", "uptime: 1d\n  version: 7.24.5 (stable)\n", "7.24.5"),
    ],
)
def test_extract_version_per_platform(platform: str, body: str, want: str) -> None:
    """each vendor's documented version line yields its version."""
    assert receipts.extract_version(platform, body) == want
    assert receipts.extract_version(platform, "nothing useful\n") == "unknown"


def test_unwritable_state_dir_still_returns_the_read(rig) -> None:
    """a receipt failure adds a note; the read result is unchanged."""
    good = rig["run"]("jx1", "interfaces", "Synthetic\n")
    assert "receipt_note" not in good
    for p in rig["state"].glob("field-receipts*"):
        p.unlink()
    if os.geteuid() == 0:
        pytest.skip("root ignores directory permissions")
    rig["state"].chmod(0o500)
    try:
        res = rig["run"]("jx1", "interfaces", "Synthetic\n")
    finally:
        rig["state"].chmod(0o700)
    assert res["status"] == "ok" and res["shape"] == "matched"
    assert res["receipt_note"] == "field receipt not recorded"
    assert {k: v for k, v in res.items() if k != "receipt_note"}.keys() == good.keys()


def test_receipt_path_is_a_directory(rig) -> None:
    """any OS error on the file (here EISDIR) is contained."""
    rig["file"].mkdir(parents=True)
    res = rig["run"]("jx1", "interfaces", "Synthetic\n")
    assert res["status"] == "ok"
    assert res["receipt_note"] == "field receipt not recorded"


def test_symlink_receipt_file_is_refused(rig, tmp_path: Path) -> None:
    """a planted symlink is not followed."""
    target = tmp_path / "victim"
    rig["state"].mkdir(parents=True, exist_ok=True)
    rig["file"].symlink_to(target)
    res = rig["run"]("jx1", "interfaces", "Synthetic\n")
    assert res["receipt_note"] == "field receipt not recorded"
    assert not target.exists()


def test_size_is_bounded_by_rotation(rig, monkeypatch) -> None:
    """file never exceeds the cap; one rotated copy; total bounded."""
    monkeypatch.setattr(receipts, "MAX_BYTES", 1000)
    for _ in range(60):
        assert receipts.record(rig["state"], "junos", "interfaces", "ok", "matched", "1.0")
    main = rig["file"]
    old = rig["state"] / (receipts.RECEIPT_FILE + ".1")
    assert main.stat().st_size <= 1000
    assert old.stat().st_size <= 1000
    assert stat.S_IMODE(old.stat().st_mode) == 0o600
    names = sorted(p.name for p in rig["state"].glob("field-receipts*"))
    assert names == sorted(
        [receipts.RECEIPT_FILE, receipts.RECEIPT_FILE + ".1", receipts.LOCK_FILE]
    )
    for rec in lines(main) + lines(old):
        assert rec["getter"] == "interfaces"  # no torn lines


def test_concurrent_appends_do_not_tear_or_lose_lines(rig, monkeypatch) -> None:
    """threads appending (with rotation off the table) lose nothing."""
    def work() -> None:
        for _ in range(25):
            receipts.record(rig["state"], "vyos", "version", "ok", "matched", "1.4")

    threads = [threading.Thread(target=work) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(lines(rig["file"])) == 200


def test_concurrent_appends_with_rotation_stay_valid(rig, monkeypatch) -> None:
    """rotation under contention never tears a line or exceeds the cap."""
    monkeypatch.setattr(receipts, "MAX_BYTES", 2000)

    def work() -> None:
        for _ in range(40):
            receipts.record(rig["state"], "vyos", "version", "ok", "matched", "1.4")

    threads = [threading.Thread(target=work) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    for p in rig["state"].glob("field-receipts.jsonl*"):
        assert p.stat().st_size <= 2000
        lines(p)


def test_off_switch_writes_nothing(rig, monkeypatch) -> None:
    """NEWTON_FIELD_RECEIPTS=0 writes nothing and adds no note."""
    monkeypatch.setenv("NEWTON_FIELD_RECEIPTS", "0")
    res = rig["run"]("jx1", "interfaces", "Synthetic\n")
    assert "receipt_note" not in res
    assert not list(rig["state"].glob("field-receipts*"))
    listed = server.newton_list_getters(device="jx1")
    assert listed["field_evidence"]["enabled"] is False


def test_list_getters_counts_by_os(rig) -> None:
    """per-getter counts per os version, labelled as not verification."""
    rig["run"]("jx1", "version", "Junos: 23.4R1\n")
    rig["run"]("jx1", "interfaces", "Synthetic\n")
    rig["run"]("jx1", "interfaces", "Synthetic\n")
    rig["run"]("jx1", "interfaces", "nope\n")
    rig["run"]("jx2", "interfaces", "Synthetic\n")  # unknown os
    listed = server.newton_list_getters(device="jx1")
    ev = listed["field_evidence"]
    assert ev["enabled"] is True
    assert "not verification" in ev["note"]
    by_id = {g["id"]: g for g in listed["getters"]}
    zero = {"matched": 0, "mismatch": 0, "not_checked": 0}
    assert by_id["interfaces"]["field_evidence"] == {
        "23.4R1": {**zero, "matched": 2, "mismatch": 1, "last_date": "2026-10-18"},
        "unknown": {**zero, "matched": 1, "last_date": "2026-10-18"},
    }
    assert by_id["version"]["field_evidence"] == {
        "23.4R1": {**zero, "matched": 1, "last_date": "2026-10-18"},
    }
    assert by_id["routes"]["field_evidence"] == {}
    # promotion is unchanged: evidence does not touch `verified`
    assert by_id["interfaces"]["verified"] == "unverified"


def test_counts_are_per_platform_and_ignore_forged_lines(rig) -> None:
    """other platforms and malformed or out-of-range lines are skipped."""
    rig["run"]("jx1", "interfaces", "Synthetic\n")
    good = {"v": 1, "date": "2026-10-18", "platform": "junos", "os": "9.9",
            "getter": "interfaces", "status": "ok", "shape": "matched"}
    junk = [
        json.dumps({**good, "platform": "vyos", "os": "1.4"}),
        json.dumps({**good, "os": "bad os"}),
        json.dumps({**good, "shape": "matched\n"}),
        json.dumps({**good, "getter": "nosuch"}),
        json.dumps({**good, "extra": 1}),
        json.dumps({**good, "v": 2}),
        json.dumps({**good, "date": "yesterday"}),
        "not json",
        "[1]",
        "",
    ]
    with rig["file"].open("a", encoding="utf-8") as f:
        f.write("\n".join(junk) + "\n")
    ev = server.newton_list_getters(device="jx1")["getters"]
    interfaces = next(g for g in ev if g["id"] == "interfaces")
    assert list(interfaces["field_evidence"]) == ["unknown"]
    assert interfaces["field_evidence"]["unknown"]["matched"] == 1


def test_unreadable_receipts_do_not_fail_list_getters(rig) -> None:
    """a directory where the file should be yields empty evidence."""
    rig["file"].mkdir(parents=True)
    listed = server.newton_list_getters(device="jx1")
    assert listed["result"] == "ok"
    assert all(g["field_evidence"] == {} for g in listed["getters"])


def test_many_os_versions_are_capped_with_a_count(rig) -> None:
    """the per-getter view is capped and says how many it dropped."""
    for i in range(15):
        receipts.record(rig["state"], "junos", "interfaces", "ok", "matched", f"1.{i}")
    listed = server.newton_list_getters(device="jx1")
    g = next(g for g in listed["getters"] if g["id"] == "interfaces")
    assert len(g["field_evidence"]) == receipts.MAX_OS_SHOWN
    assert g["field_evidence_omitted_os"] == 15 - receipts.MAX_OS_SHOWN


def test_expect_alternative_count_is_capped(tmp_path: Path) -> None:
    """at most 12 `||` alternatives per entry."""
    twelve = " || ".join(f"aa{i:02d}" for i in range(12))
    thirteen = " || ".join(f"aa{i:02d}" for i in range(13))
    load_one(tmp_path, base_row(expect=[twelve]))
    with pytest.raises(GetterError):
        load_one(tmp_path, base_row(expect=[thirteen]))


# ---------------------------------------------------------------- r1 fixes

GOOD_VERSIONS = ["7.24.5", "2026.10.01-0035-rolling", "26.2R1.7", "17.12.04", "7.4.7", "4.30.3F"]
BAD_VERSIONS = [
    "192.168.1.1", "10.0.0.1", "myrouter.lan", "lab-home-gw",
    "lab-sw1.corp.example.com", "aa-bb-cc-dd-ee-ff", "00-11-22-33-44-55",
    "00:11:22:33:44:55", "00.11.22.33.44.55", "0011.2233.4455", "3com.example.com",
    "1host.lan", "7", "12", "router", "1.0.router", "1.2.3.4",
    # addresses split by other separators, long digit runs, MAC-ish with a letter
    "192.168.1-1", "192-168-1-1.0", "192.168.1~1", "192.168.1+1", "192_168_1_1.0",
    "4111111111111111.1", "123-45-6789.1", "20261234567890123456.1", "0011223344a5.1",
    "1.2.34.5", "10.0.0.1a", "1.2.3.4.5", "3com.lan", "3c.lan",
]
EXTRA_GOOD_VERSIONS = ["23.4R1", "21.4R3-S5.4", "17.9.4a", "7.16rc2", "1.4.0", "7.15beta3"]


@pytest.mark.parametrize("value", EXTRA_GOOD_VERSIONS)
def test_r2_b1_release_shapes_are_kept(value: str) -> None:
    """common vendor release shapes still pass the allow-list."""
    assert receipts.sanitize_version(value) == value


@pytest.mark.parametrize("value", GOOD_VERSIONS)
def test_r1_b1_real_versions_are_kept(value: str) -> None:
    """all six real or synthetic versions pass."""
    assert receipts.sanitize_version(value) == value


@pytest.mark.parametrize("value", BAD_VERSIONS)
def test_r1_b1_hosts_addresses_and_words_are_refused(value: str) -> None:
    """hostnames, FQDNs, IPv4, MAC-shaped tokens never pass as a version."""
    assert receipts.sanitize_version(value) == "unknown"


@pytest.mark.parametrize(
    "platform,body",
    [
        ("vyos", "Version: VyOS 192.168.1.1\n"),
        ("junos", "Junos: myrouter.lan\n"),
        ("vyos", "Version: VyOS lab-home-gw\n"),
        ("eos", "Software image version: lab-sw1.corp.example.com\n"),
        ("vyos", "Version: VyOS aa-bb-cc-dd-ee-ff\n"),
    ],
)
def test_r1_b1_extract_refuses_report_examples(platform: str, body: str) -> None:
    assert receipts.extract_version(platform, body) == "unknown"


def test_r1_b1_record_and_summarise_refuse_forged_host_os(rig) -> None:
    """record() writes unknown, and a forged line with a host is not shown."""
    assert receipts.record(rig["state"], "junos", "interfaces", "ok", "matched", "myrouter.lan")
    assert lines(rig["file"])[-1]["os"] == "unknown"
    forged = {"v": 1, "date": "2026-10-18", "platform": "junos", "os": "192.168.1.1",
              "getter": "interfaces", "status": "ok", "shape": "matched"}
    with rig["file"].open("a", encoding="utf-8") as f:
        f.write(json.dumps(forged) + "\n")
    got = receipts.summarise(rig["state"], "junos")["interfaces"]["by_os"]
    assert list(got) == ["unknown"]


def test_r1_b2_deeply_nested_line_does_not_crash_summarise(rig) -> None:
    """RecursionError-sized line is skipped; later good lines count."""
    rig["state"].mkdir(parents=True, exist_ok=True)
    rig["file"].write_text("[" * 200000 + "\n", encoding="utf-8")
    assert receipts.record(rig["state"], "junos", "interfaces", "ok", "matched", "1.0")
    out = receipts.summarise(rig["state"], "junos")
    assert out["interfaces"]["by_os"]["1.0"]["matched"] == 1
    listed = server.newton_list_getters(device="jx1")
    assert listed["result"] == "ok"


def test_r1_b2_overlong_line_is_skipped_before_parse(rig) -> None:
    good = {"v": 1, "date": "2026-10-18", "platform": "junos", "os": "1.0",
            "getter": "interfaces", "status": "ok", "shape": "matched"}
    rig["state"].mkdir(parents=True, exist_ok=True)
    pad = json.dumps({**good, "status": "ok"}) + " " * 600
    rig["file"].write_text(pad + "\n" + json.dumps(good) + "\n", encoding="utf-8")
    assert receipts.summarise(rig["state"], "junos")["interfaces"]["by_os"]["1.0"]["matched"] == 1


def test_r1_b2_any_exception_per_line_is_contained(rig, monkeypatch) -> None:
    rig["state"].mkdir(parents=True, exist_ok=True)
    rig["file"].write_text("{}\n{}\n", encoding="utf-8")

    def boom(_raw: str) -> Any:
        raise RuntimeError("x")

    monkeypatch.setattr(receipts.json, "loads", boom)
    assert receipts.summarise(rig["state"], "junos") == {}


def test_r1_b2_list_getters_survives_summarise_failure(rig, monkeypatch) -> None:
    """a broken receipts layer yields an error note, not a failed tool."""
    def boom(*_a: Any, **_k: Any) -> Any:
        raise RuntimeError("broken")

    monkeypatch.setattr(receipts, "summarise", boom)
    listed = server.newton_list_getters(device="jx1")
    assert listed["result"] == "ok"
    assert "error" in listed["field_evidence"]["note"].lower()
    assert all(g["field_evidence"] == {} for g in listed["getters"])


# --- learned version lifecycle

def _dev(name: str = "d1", platform: str = "junos", host: str = "h1") -> server.Device:
    return server.Device(name=name, platform=platform, host=host, user="u")


@pytest.fixture
def svc(rig, monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(server, "_learned_now", lambda: clock[0])
    service = object.__new__(server.NewtonService)

    def go(dev, getter, status, shape, stdout=""):
        assert service._field_receipt(dev, getter, status, shape, stdout) is True
        return lines(rig["file"])[-1]["os"]

    go.clock = clock
    return go


def test_r1_b3_only_ok_and_matched_version_teaches(svc) -> None:
    d = _dev()
    assert svc(d, "version", "ok", "mismatch", "Junos: 23.4R1\n") == "unknown"
    assert svc(d, "interfaces", "ok", "matched") == "unknown"
    assert svc(d, "version", "ok", "not_checked", "Junos: 23.4R1\n") == "unknown"
    assert svc(d, "interfaces", "ok", "matched") == "unknown"
    assert svc(d, "version", "ok", "matched", "Junos: 23.4R1\n") == "23.4R1"
    assert svc(d, "interfaces", "ok", "matched") == "23.4R1"


@pytest.mark.parametrize(
    "status,shape,stdout",
    [
        ("device_error", "not_checked", "boom"),
        ("timeout", "not_checked", ""),
        ("ok", "mismatch", "Junos: 24.1R1\n"),
        ("ok", "matched", "Junos: myrouter.lan\n"),  # unparseable -> unknown
        ("ok", "matched", "no version line\n"),
    ],
)
def test_r1_b3_any_other_version_run_clears(svc, status, shape, stdout) -> None:
    d = _dev()
    assert svc(d, "version", "ok", "matched", "Junos: 23.4R1\n") == "23.4R1"
    svc(d, "version", status, shape, stdout)
    assert svc(d, "interfaces", "ok", "matched") == "unknown"


def test_r1_b3_repointed_name_drops_the_value(svc) -> None:
    assert svc(_dev(), "version", "ok", "matched", "Junos: 23.4R1\n") == "23.4R1"
    assert svc(_dev(host="other"), "interfaces", "ok", "matched") == "unknown"
    assert svc(_dev(platform="vyos"), "interfaces", "ok", "matched") == "unknown"
    assert svc(_dev(), "interfaces", "ok", "matched") == "23.4R1"
    assert svc(_dev(name="d2"), "interfaces", "ok", "matched") == "unknown"


def test_r1_b3_learned_value_expires_after_15_minutes(svc) -> None:
    d = _dev()
    svc(d, "version", "ok", "matched", "Junos: 23.4R1\n")
    svc.clock[0] += 15 * 60 - 1
    assert svc(d, "interfaces", "ok", "matched") == "23.4R1"
    svc.clock[0] += 2
    assert svc(d, "interfaces", "ok", "matched") == "unknown"


def test_r2_n1_version_run_while_off_still_clears(svc, monkeypatch) -> None:
    """a failed version run with receipts off still drops the learned value."""
    d = _dev()
    assert svc(d, "version", "ok", "matched", "Junos: 23.4R1\n") == "23.4R1"
    monkeypatch.setenv("NEWTON_FIELD_RECEIPTS", "0")
    svc(d, "version", "device_error", "not_checked", "boom")
    monkeypatch.setenv("NEWTON_FIELD_RECEIPTS", "1")
    assert svc(d, "interfaces", "ok", "matched") == "unknown"


def test_r1_b3_skill_documents_the_window() -> None:
    skill = (Path(__file__).resolve().parents[2] / "SKILL.md").read_text(encoding="utf-8")
    assert "last 15 minutes" in skill


# --- N1..N4

def test_r1_n1_fifo_receipt_file_does_not_hang(rig) -> None:
    """a planted FIFO is refused at once by record and summarise."""
    import time
    rig["state"].mkdir(parents=True, exist_ok=True)
    os.mkfifo(rig["file"])
    os.mkfifo(rig["state"] / (receipts.RECEIPT_FILE + ".1"))
    t0 = time.monotonic()
    assert receipts.record(rig["state"], "junos", "interfaces", "ok", "matched", "1.0") is False
    assert receipts.summarise(rig["state"], "junos") == {}
    assert time.monotonic() - t0 < 3


def test_r1_n1_fifo_lock_file_does_not_hang(rig) -> None:
    import time
    rig["state"].mkdir(parents=True, exist_ok=True)
    os.mkfifo(rig["state"] / receipts.LOCK_FILE)
    t0 = time.monotonic()
    assert receipts.record(rig["state"], "junos", "interfaces", "ok", "matched", "1.0") is False
    assert time.monotonic() - t0 < 3


def test_r1_n1_fifo_rotated_file_does_not_hang_rotation(rig, monkeypatch) -> None:
    import time
    monkeypatch.setattr(receipts, "MAX_BYTES", 300)
    for _ in range(3):
        receipts.record(rig["state"], "junos", "interfaces", "ok", "matched", "1.0")
    old = rig["state"] / (receipts.RECEIPT_FILE + ".1")
    old.unlink(missing_ok=True)
    os.mkfifo(old)
    t0 = time.monotonic()
    for _ in range(10):
        receipts.record(rig["state"], "junos", "interfaces", "ok", "matched", "1.0")
    receipts.summarise(rig["state"], "junos")
    assert time.monotonic() - t0 < 3


def test_r1_n2_existing_loose_modes_are_tightened(rig) -> None:
    """pre-existing 0644 receipt, lock and rotated files become 0600."""
    rig["state"].mkdir(parents=True, exist_ok=True)
    for name in (receipts.RECEIPT_FILE, receipts.LOCK_FILE):
        p = rig["state"] / name
        p.write_text("", encoding="utf-8")
        p.chmod(0o644)
    assert receipts.record(rig["state"], "junos", "interfaces", "ok", "matched", "1.0")
    for name in (receipts.RECEIPT_FILE, receipts.LOCK_FILE):
        assert stat.S_IMODE((rig["state"] / name).stat().st_mode) == 0o600


def test_r1_n2_rotated_copy_is_0600_even_from_a_loose_file(rig, monkeypatch) -> None:
    monkeypatch.setattr(receipts, "MAX_BYTES", 300)
    rig["state"].mkdir(parents=True, exist_ok=True)
    rig["file"].write_text("x" * 290 + "\n", encoding="utf-8")
    rig["file"].chmod(0o644)
    assert receipts.record(rig["state"], "junos", "interfaces", "ok", "matched", "1.0")
    old = rig["state"] / (receipts.RECEIPT_FILE + ".1")
    assert old.exists() and stat.S_IMODE(old.stat().st_mode) == 0o600


def test_r1_n3_short_writes_are_completed(rig, monkeypatch) -> None:
    """os.write returning short counts still lands the whole line."""
    real = os.write

    def short(fd: int, data: bytes) -> int:
        return real(fd, data[:7])

    monkeypatch.setattr(receipts.os, "write", short)
    assert receipts.record(rig["state"], "junos", "interfaces", "ok", "matched", "1.0")
    monkeypatch.undo()
    assert len(lines(rig["file"])) == 1


def test_r1_n3_zero_progress_write_fails_cleanly(rig, monkeypatch) -> None:
    monkeypatch.setattr(receipts.os, "write", lambda fd, data: 0)
    assert receipts.record(rig["state"], "junos", "interfaces", "ok", "matched", "1.0") is False


@pytest.mark.parametrize("v", [True, 1.0, "1", None, [1]])
def test_r1_n4_v_must_be_the_int_one(rig, v: Any) -> None:
    good = {"v": 1, "date": "2026-10-18", "platform": "junos", "os": "1.0",
            "getter": "interfaces", "status": "ok", "shape": "matched"}
    rig["state"].mkdir(parents=True, exist_ok=True)
    rig["file"].write_text(
        json.dumps({**good, "v": v}) + "\n" + json.dumps(good) + "\n", encoding="utf-8"
    )
    assert receipts.summarise(rig["state"], "junos")["interfaces"]["by_os"]["1.0"]["matched"] == 1


# --- mutants that survived r0

def test_r1_n5_flock_serialises_processes(rig, tmp_path: Path) -> None:
    """a real second process blocks on the held lock, then proceeds."""
    import subprocess
    import sys
    import time

    rig["state"].mkdir(parents=True, exist_ok=True)
    code = (
        "import sys; sys.path.insert(0, %r); from pathlib import Path; "
        "from newton_mcp import receipts; "
        "sys.exit(0 if receipts.record(Path(sys.argv[1]), 'junos','interfaces','ok','matched','1.0') else 1)"
    ) % str(Path(receipts.__file__).resolve().parents[1])
    import fcntl
    lock_fd = os.open(str(rig["state"] / receipts.LOCK_FILE), os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(lock_fd, fcntl.LOCK_EX)
    try:
        proc = subprocess.Popen([sys.executable, "-c", code, str(rig["state"])])
        time.sleep(1.0)
        assert proc.poll() is None  # blocked on our lock
        assert not rig["file"].exists() or rig["file"].stat().st_size == 0
    finally:
        os.close(lock_fd)
    assert proc.wait(timeout=10) == 0
    assert len(lines(rig["file"])) == 1


def test_r1_n5_many_processes_lose_no_line(rig) -> None:
    import subprocess
    import sys

    code = (
        "import sys; sys.path.insert(0, %r); from pathlib import Path; "
        "from newton_mcp import receipts; "
        "[receipts.record(Path(sys.argv[1]),'vyos','version','ok','matched','1.4') for _ in range(50)]"
    ) % str(Path(receipts.__file__).resolve().parents[1])
    procs = [subprocess.Popen([sys.executable, "-c", code, str(rig["state"])]) for _ in range(6)]
    assert all(p.wait(timeout=60) == 0 for p in procs)
    assert len(lines(rig["file"])) == 300


def test_r1_n5_os_cap_is_exactly_eight() -> None:
    assert receipts.MAX_OS_SHOWN == 8


def test_r1_n5_valid_rejects_bad_getter_and_accepts_good(rig) -> None:
    good = {"v": 1, "date": "2026-10-18", "platform": "junos", "os": "unknown",
            "getter": "interfaces", "status": "ok", "shape": "matched"}
    assert receipts._valid(json.dumps(good), "junos") == good
    assert receipts._valid(json.dumps({**good, "getter": "nosuch"}), "junos") is None


def test_r1_n5_open_regular_refuses_non_regular(tmp_path: Path) -> None:
    with pytest.raises(OSError):
        receipts._open_regular(tmp_path, os.O_RDONLY)
    if Path("/dev/null").exists():
        with pytest.raises(OSError):
            receipts._open_regular(Path("/dev/null"), os.O_RDONLY)


@pytest.mark.parametrize("word", ["0", "off", "false", "no", "OFF", " False "])
def test_r1_n5_enabled_words(monkeypatch, word: str) -> None:
    monkeypatch.setenv("NEWTON_FIELD_RECEIPTS", word)
    assert receipts.enabled() is False
    for on in ("1", "on", "yes", "true", ""):
        monkeypatch.setenv("NEWTON_FIELD_RECEIPTS", on)
        assert receipts.enabled() is True


@pytest.mark.parametrize(
    "args",
    [("nosuch", "interfaces", "ok", "matched"), ("junos", "nosuch", "ok", "matched"),
     ("junos", "interfaces", "ok", "bogus"), ("junos", "interfaces", "OK\n", "matched"),
     ("junos", "interfaces", "", "matched")],
)
def test_r1_n5_record_validates_every_field(rig, args) -> None:
    assert receipts.record(rig["state"], args[0], args[1], args[2], args[3], "1.0") is False
    assert not rig["file"].exists()


def test_r1_n5_record_swallows_oserror(tmp_path: Path) -> None:
    blocker = tmp_path / "file"
    blocker.write_text("x", encoding="utf-8")
    assert receipts.record(blocker / "sub", "junos", "interfaces", "ok", "matched", "1.0") is False


def test_r1_n5_server_wrapper_swallows_exceptions(rig, monkeypatch) -> None:
    """The wrapper's own except Exception: record() itself raising must not escape."""
    def boom(*_a: Any, **_k: Any) -> bool:
        raise RuntimeError("x")

    monkeypatch.setattr(receipts, "record", boom)
    service = object.__new__(server.NewtonService)
    assert service._field_receipt(_dev(), "interfaces", "ok", "matched", "") is False
